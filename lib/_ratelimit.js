// _ratelimit.js: per-IP fixed-window limiter for PUBLIC, UNAUTHENTICATED
// read endpoints. Underscore prefix = not routed as a serverless function.
//
// The bucket key is the caller IP: /api/verify has no auth by design (board
// item 20 made it a no-key funnel, so a stranger does not need a key just to
// ask "does this exist?"), so there is no caller key to bucket on. IP is the
// only identity available, and it is only as trustworthy as the header the
// edge network hands us.
//
// WHERE THE COUNT LIVES (B079, 2026-09-25). This used to be one Map in module
// scope, so every warm Vercel instance kept its own count and a burst spread
// across N instances got N times the budget. The count now lives in a SHARED
// STORE that every instance increments:
//
//   - kvStore(): a Redis-compatible REST store (Vercel KV or Upstash), used
//     when KV_REST_API_URL + KV_REST_API_TOKEN (or the UPSTASH_REDIS_REST_*
//     pair) are set. One pipelined INCRBY + PEXPIRE per call, on a key named
//     for the IP and the clock-aligned window, so the increment is atomic
//     across instances and the key expires on its own.
//   - memoryStore(): the in-process Map. It is the stub every test uses, and
//     the fallback when no shared store is configured.
//
// Honest limits, stated rather than hidden:
//   - With no shared store configured, this is still per instance, exactly as
//     before. Turning the shared count on is an env change, not a code change.
//   - If the shared store errors or times out, the call is counted in this
//     instance's memory store instead. It degrades to the old per-instance
//     count, never to unlimited, and never to refusing everyone because the
//     store is down.

"use strict";

const WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const LIMIT = 30; // calls per IP per window, across every instance sharing the store
const KV_TIMEOUT_MS = 800;

// ---- stores: hit(key, cost, now) -> Promise<{count, windowStart}> ----

// In-process store. Same semantics the module always had: a bucket's window
// starts at its first hit and lasts windowMs.
function memoryStore({ windowMs = WINDOW_MS } = {}) {
  const buckets = new Map(); // key -> {windowStart, count}
  // Bounded cleanup: sweep expired buckets at most once per sweepMs, driven
  // off real traffic (no timer), so a long-lived warm instance under broad IP
  // traffic does not grow this Map forever.
  const sweepMs = 5 * 60 * 1000;
  let lastSweep = 0;
  function sweep(now) {
    if (now - lastSweep < sweepMs) return;
    lastSweep = now;
    for (const [key, b] of buckets) {
      if (now - b.windowStart > windowMs) buckets.delete(key);
    }
  }
  return {
    kind: "memory",
    async hit(key, cost, now) {
      sweep(now);
      let b = buckets.get(key);
      if (!b || now - b.windowStart > windowMs) {
        b = { windowStart: now, count: 0 };
        buckets.set(key, b);
      }
      b.count += cost;
      return { count: b.count, windowStart: b.windowStart };
    },
  };
}

// Shared Redis-compatible REST store (Vercel KV / Upstash). Windows are
// aligned to the clock (floor(now / windowMs)) so every instance agrees which
// window a call belongs to without coordinating.
function kvStore({ url, token, windowMs = WINDOW_MS, fetchImpl = globalThis.fetch, timeoutMs = KV_TIMEOUT_MS }) {
  const base = String(url).replace(/\/+$/, "");
  return {
    kind: "kv",
    async hit(key, cost, now) {
      const windowStart = Math.floor(now / windowMs) * windowMs;
      const k = `rl:${key}:${windowStart}`;
      const ctl = typeof AbortController === "function" ? new AbortController() : null;
      const timer = ctl ? setTimeout(() => ctl.abort(), timeoutMs) : null;
      try {
        const r = await fetchImpl(`${base}/pipeline`, {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify([["INCRBY", k, String(cost)], ["PEXPIRE", k, String(windowMs * 2)]]),
          signal: ctl ? ctl.signal : undefined,
        });
        if (!r.ok) throw new Error(`kv pipeline -> ${r.status}`);
        const out = await r.json();
        const first = Array.isArray(out) ? out[0] : null;
        if (!first || first.error || !Number.isFinite(Number(first.result))) {
          throw new Error("kv INCRBY returned no count");
        }
        return { count: Number(first.result), windowStart };
      } finally {
        if (timer) clearTimeout(timer);
      }
    },
  };
}

function storeFromEnv(env = process.env) {
  const url = env.KV_REST_API_URL || env.UPSTASH_REDIS_REST_URL;
  const token = env.KV_REST_API_TOKEN || env.UPSTASH_REDIS_REST_TOKEN;
  return url && token ? kvStore({ url, token }) : null;
}

// Best-effort caller IP. x-forwarded-for's leftmost entry is what Vercel's
// edge network reports as the original client. Unset/unparseable falls back
// to the raw socket address; if even that is unavailable, every such caller
// collapses onto one shared "unknown" bucket: degraded, but it fails toward
// MORE blocking (they all share one budget), never toward silently unlimited.
function callerIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim()) {
    return xff.split(",")[0].trim();
  }
  const addr = req.socket && req.socket.remoteAddress;
  return addr || "unknown";
}

// createLimiter({store, fallback}) -> {check(req, cost=1)}. One limiter per
// instance; limiters that share a store share one budget per IP.
function createLimiter({ store = null, fallback = memoryStore(), limit = LIMIT, windowMs = WINDOW_MS, now = Date.now, onStoreError = null } = {}) {
  // check(req, cost=1) -> Promise<{limited:false} | {limited:true, retryAfterSeconds, limit, windowSeconds}>
  //
  // `cost` lets one call consume more than one unit of the SAME per-IP budget
  // other callers spend one unit at a time from (bulk-verify weighting,
  // 2026-09-20; see api/verify.js's handleBulk). The bucket is unified on
  // purpose: single and bulk verifies from one IP draw down one budget. The
  // cost is always spent, even on the call that crosses the line, and a call
  // whose own cost exceeds the limit is charged and blocked, never admitted.
  async function check(req, cost = 1) {
    const t = now();
    const key = callerIp(req);
    let hit;
    if (store) {
      try {
        hit = await store.hit(key, cost, t);
      } catch (err) {
        if (onStoreError) onStoreError(err);
        hit = await fallback.hit(key, cost, t);
      }
    } else {
      hit = await fallback.hit(key, cost, t);
    }
    if (hit.count > limit) {
      const retryAfterSeconds = Math.max(1, Math.ceil((hit.windowStart + windowMs - t) / 1000));
      return { limited: true, retryAfterSeconds, limit, windowSeconds: windowMs / 1000 };
    }
    return { limited: false };
  }
  return { check, store, fallback };
}

// The process-wide limiter every endpoint uses. setStore() swaps the shared
// store (tests pass a memory stub; null means per-instance memory only).
let current = createLimiter({ store: storeFromEnv() });

function check(req, cost = 1) {
  return current.check(req, cost);
}

function setStore(store) {
  current = createLimiter({ store });
  return current;
}

function storeKind() {
  return current.store ? current.store.kind : "memory (per instance)";
}

module.exports = {
  check,
  callerIp,
  createLimiter,
  memoryStore,
  kvStore,
  storeFromEnv,
  setStore,
  storeKind,
  LIMIT,
  WINDOW_MS,
};
