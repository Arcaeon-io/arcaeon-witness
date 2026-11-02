// _pin_ratelimit.js — the per key limit on POST /api/pin: RATE_LIMIT pins per
// key per clock hour. Underscore prefix = not routed as a serverless function.
//
// Two modes, chosen by the same switch as the meter (lib/_usage_store.js):
//
//   WITNESS_USAGE_STORE unset or github
//       The old Stage-0 limiter, unchanged in shape: a Map in module scope.
//       Each warm instance counts on its own and a cold start forgets, so with
//       N warm instances a key can make up to N x RATE_LIMIT pins in an hour.
//       It stops one hot loop on one instance; it is not a global cap.
//
//   WITNESS_USAGE_STORE=postgres
//       One count per key per clock hour in the account database, shared by
//       every instance. The increment is one database function call
//       (pin_rate_hit, supabase/migrations/2026_10_31_pin_rate.sql): an
//       INSERT ... ON CONFLICT DO UPDATE SET hits = hits + 1 RETURNING hits,
//       which Postgres runs atomically per row, so two instances can never
//       both read 59 and both admit the 60th. If the database cannot be
//       reached the pin is refused (503, reason rate_limit_store_unreachable):
//       the meter, which needs the same database, would refuse it a step later
//       anyway, and a limiter that admits on error limits nothing.
//
// Windows are clock hours in UTC, so every instance agrees on which window a
// pin falls in without coordinating. A key can therefore make 60 pins at
// 10:59 and 60 more at 11:00; the limit is per window, as before.
//
// What counts: every request that passed auth and the namespace prefix check,
// whatever happens to it next, the same as the old limiter. Only the sha256 of
// the key is sent to the database, never the key.

"use strict";

const crypto = require("crypto");
const usageStore = require("./_usage_store.js");

const RATE_LIMIT = 60; // pins per key per clock hour
const WINDOW_MS = 3600_000;

const buckets = new Map(); // key -> {windowStart, count}

function windowStart(nowMs) {
  return Math.floor(nowMs / WINDOW_MS) * WINDOW_MS;
}

function retryAfter(nowMs) {
  return Math.max(1, Math.ceil((windowStart(nowMs) + WINDOW_MS - nowMs) / 1000));
}

function localHit(key, nowMs) {
  const start = windowStart(nowMs);
  let b = buckets.get(key);
  if (!b || b.windowStart !== start) {
    // Starting a new window is also when old buckets go: bounded by the keys
    // that pinned in the last hour.
    for (const [k, v] of buckets) if (v.windowStart !== start) buckets.delete(k);
    b = { windowStart: start, count: 0 };
    buckets.set(key, b);
  }
  b.count += 1;
  return b.count;
}

// check(key) -> {limited:false, hits, limit, shared}
//             | {limited:true, hits, limit, shared, retryAfterSeconds}
//             | {error:true, reason:"rate_limit_store_unreachable"}
async function check(key, { now = Date.now() } = {}) {
  let shared;
  try {
    shared = usageStore.onPostgres();
  } catch (_e) {
    return { error: true, reason: "rate_limit_store_unreachable" };
  }
  let hits;
  if (shared) {
    try {
      const out = await usageStore.rpc("pin_rate_hit", {
        p_key_hash: crypto.createHash("sha256").update(key, "utf8").digest("hex"),
        p_window_start: new Date(windowStart(now)).toISOString(),
      }, "ratelimit");
      hits = Array.isArray(out) ? out[0] : out;
    } catch (_e) {
      return { error: true, reason: "rate_limit_store_unreachable" };
    }
    if (!Number.isSafeInteger(hits) || hits < 1) {
      // A count we cannot read is not a count under the limit.
      return { error: true, reason: "rate_limit_store_unreachable" };
    }
  } else {
    hits = localHit(key, now);
  }
  const base = { hits, limit: RATE_LIMIT, shared };
  if (hits > RATE_LIMIT) return { limited: true, ...base, retryAfterSeconds: retryAfter(now) };
  return { limited: false, ...base };
}

module.exports = { check, RATE_LIMIT, WINDOW_MS, windowStart, _buckets: buckets };
