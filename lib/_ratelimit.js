// _ratelimit.js — naive per-IP fixed-window limiter for PUBLIC, UNAUTHENTICATED
// read endpoints. Underscore prefix = not routed as a serverless function.
//
// Same shape as api/pin.js's per-key rateLimited() (naive, per-instance,
// resets on cold start — see that file's comment for why this shape was
// already accepted as good enough for Stage-0). The difference here is the
// bucket key: /api/verify has no auth by design (board item 20 made it a
// no-key funnel — that's the point, a stranger shouldn't need a key just to
// ask "does this exist?"), so there is no caller key to bucket on. IP is the
// only identity available, and it is only as trustworthy as the header the
// edge network hands us.
//
// Honest limitation (documented, not hidden — same discipline as every
// other Stage-0 note in this repo): Vercel serverless functions are
// stateless per invocation, but a warm instance's module scope survives
// between invocations ON THAT INSTANCE. Under concurrent traffic Vercel
// routes requests for the same IP across MULTIPLE warm instances, each
// holding its own independent Map — so this is real protection against one
// hot loop hammering a single instance, and a real but imperfect slowdown
// against a distributed burst. It is NOT a guaranteed global cap.
// checkShared below is the cross instance count, in the account database,
// when WITNESS_USAGE_STORE=postgres; every endpoint calls that. This costs nothing extra and blocks something; it does
// not block everything.

"use strict";

const WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const LIMIT = 30; // calls per IP per window, per warm instance

const buckets = new Map(); // ip -> {windowStart, count}

// Bounded cleanup: sweep expired buckets at most once per SWEEP_INTERVAL_MS,
// driven off real request traffic (no timer, nothing runs when nothing is
// calling in) — so a long-lived warm instance under broad IP traffic
// doesn't grow this Map forever.
const SWEEP_INTERVAL_MS = 5 * 60 * 1000;
let lastSweep = 0;
function sweep(now) {
  if (now - lastSweep < SWEEP_INTERVAL_MS) return;
  lastSweep = now;
  for (const [key, b] of buckets) {
    if (now - b.windowStart > WINDOW_MS) buckets.delete(key);
  }
}

// Best-effort caller IP. x-forwarded-for's leftmost entry is what Vercel's
// edge network reports as the original client. Unset/unparseable falls back
// to the raw socket address; if even that is unavailable, every such caller
// collapses onto one shared "unknown" bucket — degraded, but it fails
// toward MORE blocking (they all share one 30/10min budget), never toward
// silently unlimited.
function callerIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim()) {
    return xff.split(",")[0].trim();
  }
  const addr = req.socket && req.socket.remoteAddress;
  return addr || "unknown";
}

// check(req, cost=1) -> {limited:false} | {limited:true, retryAfterSeconds, limit, windowSeconds}
//
// `cost` lets one call consume more than one unit of the SAME per-IP budget
// other callers spend one unit at a time from (added for the bulk-verify
// weighting, 2026-09-20 — see api/verify.js's handleBulk). A plain call
// (cost omitted) behaves exactly as before: one unit. The bucket is unified
// on purpose — a caller mixing single verifies and bulk verifies from one
// IP draws down one shared budget, not two independent ones, which is the
// whole point of weighting rather than giving bulk mode its own bucket (see
// BULK_VERIFY_DESIGN.md's "Rate limiting" section for the fuller reasoning).
function check(req, cost = 1) {
  const now = Date.now();
  sweep(now);
  const key = callerIp(req);
  let b = buckets.get(key);
  if (!b || now - b.windowStart > WINDOW_MS) {
    b = { windowStart: now, count: 0 };
    buckets.set(key, b);
  }
  // Always spend the cost, even on the call that crosses the line — matches
  // the pre-weighting behavior (a blocked call still incremented count by
  // 1), and keeps this a single code path instead of a branch per outcome.
  // A single call whose OWN cost exceeds LIMIT can never succeed in any
  // window; it is still charged (so it doesn't dodge the budget by costing
  // "too much to count"), and blocked immediately rather than admitted.
  b.count += cost;
  if (b.count > LIMIT) {
    const retryAfterSeconds = Math.max(1, Math.ceil((b.windowStart + WINDOW_MS - now) / 1000));
    return { limited: true, retryAfterSeconds, limit: LIMIT, windowSeconds: WINDOW_MS / 1000 };
  }
  return { limited: false };
}

// ---- the shared count (owner job 16) ----
//
// checkShared(req, cost) is check() with one count per IP per window shared by
// every warm instance, when WITNESS_USAGE_STORE=postgres (the same switch and
// the same account database as the meter and the per key pin limit,
// lib/_usage_store.js and lib/_pin_ratelimit.js). The increment is one call
// to the database function ip_rate_hit (supabase/migrations/
// 2026_10_31_ip_rate.sql): INSERT ... ON CONFLICT DO UPDATE SET hits = hits +
// cost RETURNING hits, atomic per row. Windows are fixed 10 minute slots of
// the clock, so every instance agrees on the window. Only the sha256 of the
// IP is sent, and rows older than a day are cleared by the same call.
//
// With the store off it is check(), unchanged. If the database cannot be
// reached, it falls back to check() for that call and logs it: a public read
// keeps a per instance limit rather than going down with the database, and
// never runs with no limit at all.
let usageStore = null;
function store() {
  if (!usageStore) usageStore = require("./_usage_store.js");
  return usageStore;
}

function slotStart(now) {
  return Math.floor(now / WINDOW_MS) * WINDOW_MS;
}

async function checkShared(req, cost = 1, { now = Date.now() } = {}) {
  let shared = false;
  try {
    shared = store().onPostgres();
  } catch (_e) {
    shared = false;
  }
  if (!shared) return check(req, cost);
  const ipHash = require("crypto").createHash("sha256").update(`ip-rate:v1\n${callerIp(req)}`, "utf8").digest("hex");
  const start = slotStart(now);
  let hits;
  try {
    const out = await store().rpc("ip_rate_hit", {
      p_ip_hash: ipHash, p_window_start: new Date(start).toISOString(), p_cost: cost,
    }, "ratelimit");
    hits = Array.isArray(out) ? out[0] : out;
  } catch (_e) {
    hits = null;
  }
  if (!Number.isSafeInteger(hits) || hits < 1) {
    console.error("[ratelimit] shared count unreadable; this call is limited per instance");
    return { ...check(req, cost), shared: false };
  }
  if (hits > LIMIT) {
    const retryAfterSeconds = Math.max(1, Math.ceil((start + WINDOW_MS - now) / 1000));
    return { limited: true, retryAfterSeconds, limit: LIMIT, windowSeconds: WINDOW_MS / 1000, shared: true };
  }
  return { limited: false, shared: true };
}

module.exports = { check, checkShared, callerIp, LIMIT, WINDOW_MS };
