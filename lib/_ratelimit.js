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
// checkShared below adds the cross instance count, in the account database,
// when WITNESS_USAGE_STORE=postgres and WITNESS_IP_RATE_SECRET are set; every
// endpoint calls that. The local check always runs first, so this costs
// nothing extra and blocks something; it does not block everything.

"use strict";

const WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const LIMIT = 30; // calls per IP per window, per warm instance

const buckets = new Map(); // ip -> {windowStart, count}

// Hard cap on the Map, whatever the traffic between sweeps. At MAX_BUCKETS a
// new IP evicts the oldest bucket first. Insertion order is window start
// order (a bucket is re-inserted when its window restarts), so the one evicted
// is the bucket nearest its own natural reset: the least budget handed back.
// Positive integer override WITNESS_IP_RATE_MAX_BUCKETS, read once per instance.
const MAX_BUCKETS = envInt("WITNESS_IP_RATE_MAX_BUCKETS", 10000);
function putBucket(key, b) {
  buckets.delete(key);
  while (buckets.size >= MAX_BUCKETS) buckets.delete(buckets.keys().next().value);
  buckets.set(key, b);
}

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
// edge network reports as the original client. Unset, unparseable (not an
// IPv4 or IPv6 address once normalised) or longer than MAX_IP_LEN falls back
// to the raw socket address, checked the same way; if even that is unusable,
// every such caller
// collapses onto one shared "unknown" bucket — degraded, but it fails
// toward MORE blocking (they all share one 30/10min budget), never toward
// silently unlimited.
//
// IPv6 is grouped by /64: one subscriber is routinely handed a whole /64, so
// keying on the full address would give one caller 2^64 separate budgets. An
// IPv6 address is normalised to its first four hextets ("2001:db8:0:1::/64"),
// with :: compression, brackets, a port after brackets and a zone id handled.
// An IPv4 mapped address (::ffff:a.b.c.d, or its hex form) is the IPv4
// address. IPv4 is unchanged (a ":port" after it is dropped). Anything that
// does not parse is returned as is by normaliseIp; parseIp returns null.
const MAX_IP_LEN = 64;
function normaliseIp(raw) {
  let s = String(raw).trim();
  const br = /^\[([^\]]+)\](?::\d+)?$/.exec(s);
  if (br) s = br[1];
  const pct = s.indexOf("%");
  if (pct > 0) s = s.slice(0, pct);
  const net = require("net");
  const v4port = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(s);
  if (v4port && net.isIPv4(v4port[1])) return v4port[1];
  if (net.isIPv4(s)) return s;
  if (!net.isIPv6(s)) return String(raw).trim();
  s = s.toLowerCase();
  const halves = s.split("::");
  const toHextets = (part) => {
    if (!part) return [];
    const out = [];
    for (const piece of part.split(":")) {
      if (piece.includes(".")) {
        const o = piece.split(".").map(Number);
        out.push(((o[0] << 8) | o[1]).toString(16), ((o[2] << 8) | o[3]).toString(16));
      } else {
        out.push(piece);
      }
    }
    return out;
  };
  const head = toHextets(halves[0]);
  const tail = halves.length > 1 ? toHextets(halves[1]) : [];
  const fill = halves.length > 1 ? new Array(8 - head.length - tail.length).fill("0") : [];
  const h = [...head, ...fill, ...tail].map((x) => parseInt(x, 16));
  if (h.length !== 8 || h.some((x) => !Number.isInteger(x) || x < 0 || x > 0xffff)) return String(raw).trim();
  // ::ffff:a.b.c.d (IPv4 mapped) is the IPv4 caller.
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0xffff) {
    return `${h[6] >> 8}.${h[6] & 0xff}.${h[7] >> 8}.${h[7] & 0xff}`;
  }
  return `${h.slice(0, 4).map((x) => x.toString(16)).join(":")}::/64`;
}

// -> the bucket key ("a.b.c.d" or "<first four hextets>::/64") | null
function parseIp(raw) {
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  if (!s || s.length > MAX_IP_LEN) return null;
  const n = normaliseIp(s);
  const net = require("net");
  if (net.isIPv4(n)) return n;
  if (n.endsWith("::/64") && net.isIPv6(n.slice(0, -3))) return n;
  return null;
}

function callerIp(req) {
  const xff = (req.headers || {})["x-forwarded-for"];
  if (typeof xff === "string") {
    // Only the head of the header is read, so a huge header costs nothing. A
    // leftmost entry with no comma inside the cap is overlong: refused, never
    // cut down to something that happens to parse.
    const head = xff.slice(0, MAX_IP_LEN + 1);
    const comma = head.indexOf(",");
    const entry = comma >= 0 ? head.slice(0, comma) : (xff.length > MAX_IP_LEN ? null : head);
    const first = parseIp(entry);
    if (first) return first;
  }
  const addr = parseIp(req.socket && req.socket.remoteAddress);
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
//
// `aligned` (used by checkShared) makes the window the 10 minute clock slot
// the shared count uses, so the local pre-check and the shared count reset
// together; plain check() keeps the window from the IP's first call.
function check(req, cost = 1, { now = Date.now(), aligned = false } = {}) {
  sweep(now);
  const key = callerIp(req);
  let b = buckets.get(key);
  const slot = aligned ? slotStart(now) : null;
  const stale = !b || (aligned ? b.windowStart < slot : now - b.windowStart > WINDOW_MS);
  if (stale) {
    b = { windowStart: aligned ? slot : now, count: 0 };
    putBucket(key, b);
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
// checkShared(req, cost) adds one count per IP per 10 minute clock slot shared
// by every warm instance, when BOTH WITNESS_USAGE_STORE=postgres AND
// WITNESS_IP_RATE_SECRET are set. Order matters, because the database it
// counts in is the same one the per key pin limit fails closed on (503
// rate_limit_store_unreachable), and a read flood must not be able to turn
// paying pins into 503s:
//
//   1. The local per instance check() runs first. A caller already over the
//      local limit is refused right there and the database is never touched.
//      A flood from one IP costs at most LIMIT database calls per instance per
//      window, not one per request.
//   2. Only a caller under the local limit asks the shared count: one call to
//      ip_rate_hit (supabase/migrations/2026_10_31_ip_rate.sql), an atomic
//      INSERT ... ON CONFLICT DO UPDATE SET hits = hits + cost. It does no
//      cleanup; old rows are cleared by the scheduled ip_rate_sweep(), never
//      per request.
//   3. That call has a deadline of SHARED_TIMEOUT_MS. On timeout or any
//      failure the answer is the local count already taken in step 1 (fail to
//      local, never open), and it is logged once per window.
//   4. A circuit breaker and a per instance cap (in flight, per second) sit in
//      front of that call, so a flood from many IPs under their own local
//      limits cannot turn into one database call per request (see "the
//      database budget" below). Over either, the local count decides.
//
// What reaches the database: HMAC-SHA256 of the IP under the server secret
// WITNESS_IP_RATE_SECRET (never the IP, never an unsalted hash, which over
// IPv4 is as good as the IP), the window start, and the hit count. Without
// the secret the limiter stays local only and writes nothing about IPs to the
// database at all.
const SHARED_TIMEOUT_MS = 250;
const SECRET_ENV = "WITNESS_IP_RATE_SECRET";
const MIN_SECRET_LEN = 32;

let usageStore = null;
function store() {
  if (!usageStore) usageStore = require("./_usage_store.js");
  return usageStore;
}

function slotStart(now) {
  return Math.floor(now / WINDOW_MS) * WINDOW_MS;
}

let warnedSecret = false;
function ipSecret() {
  const v = process.env[SECRET_ENV];
  if (typeof v === "string" && v.length >= MIN_SECRET_LEN) return v;
  if (!warnedSecret) {
    warnedSecret = true;
    console.error(`[ratelimit] ${SECRET_ENV} unset or shorter than ${MIN_SECRET_LEN}; the per IP limit stays per instance and no IP data goes to the database`);
  }
  return null;
}

function ipKey(ip, secret) {
  return require("crypto").createHmac("sha256", secret).update(`ip-rate:v2\n${ip}`, "utf8").digest("hex");
}

// ---- the database budget: a breaker and a per instance cap ----
//
// The local check bounds what ONE IP can cost; it does not bound a flood from
// many IPs (or many /64s), where every request is under its own local limit.
// Two guards stand between that and the database, and both answer with the
// local count already taken (the same answer as the failure path: limited per
// instance, never unlimited):
//
//   - Circuit breaker. BREAKER_FAILURES failures or timeouts within
//     BREAKER_WINDOW_MS open it; while open no shared call is made for
//     BREAKER_OPEN_MS. Then exactly one probe call is let through: success
//     closes it, failure opens it again for another BREAKER_OPEN_MS.
//   - Cap. At most MAX_IN_FLIGHT shared calls outstanding at once, and at most
//     MAX_PER_SECOND started per clock second, per instance. A call that never
//     settles holds its slot until RELEASE_AFTER_MS at most.
//
// Each is a positive integer env override (WITNESS_IP_RATE_*), read once per
// instance; an unset or invalid value keeps the default.
function envInt(name, dflt) {
  const v = Number(process.env[name]);
  return Number.isSafeInteger(v) && v > 0 ? v : dflt;
}
const BREAKER_FAILURES = envInt("WITNESS_IP_RATE_BREAKER_FAILURES", 5);
const BREAKER_WINDOW_MS = envInt("WITNESS_IP_RATE_BREAKER_WINDOW_MS", 30 * 1000);
const BREAKER_OPEN_MS = envInt("WITNESS_IP_RATE_BREAKER_OPEN_MS", 30 * 1000);
const MAX_IN_FLIGHT = envInt("WITNESS_IP_RATE_MAX_IN_FLIGHT", 8);
const MAX_PER_SECOND = envInt("WITNESS_IP_RATE_MAX_PER_SECOND", 50);
const RELEASE_AFTER_MS = 2000;

const breaker = { failures: [], openUntil: 0, probing: false };
let inFlight = 0;
let secSlot = -1;
let secCount = 0;

// The outage line is logged at most once per WINDOW_MS slot, not per request.
let lastOutageLog = -1;
function logOutage(now, why) {
  const slot = slotStart(now);
  if (slot === lastOutageLog) return;
  lastOutageLog = slot;
  console.error(`[ratelimit] shared count ${why}; calls are limited per instance (logged once per ${WINDOW_MS / 60000} minute window)`);
}

// -> "closed" | "probe" | "open"
function breakerGate(now) {
  if (breaker.openUntil === 0) return "closed";
  if (now < breaker.openUntil || breaker.probing) return "open";
  breaker.probing = true;
  return "probe";
}
function breakerResult(ok, now, wasProbe) {
  if (wasProbe) breaker.probing = false;
  if (ok) {
    if (wasProbe) { breaker.openUntil = 0; breaker.failures = []; }
    return;
  }
  if (wasProbe) { breaker.openUntil = now + BREAKER_OPEN_MS; return; }
  breaker.failures = breaker.failures.filter((t) => now - t < BREAKER_WINDOW_MS);
  breaker.failures.push(now);
  if (breaker.failures.length >= BREAKER_FAILURES && breaker.openUntil === 0) {
    breaker.openUntil = now + BREAKER_OPEN_MS;
    breaker.failures = [];
    logOutage(now, `failed ${BREAKER_FAILURES} times in ${BREAKER_WINDOW_MS / 1000}s, breaker open for ${BREAKER_OPEN_MS / 1000}s`);
  }
}
// Takes a slot under the cap, or returns false (over the cap).
function takeSlot(now) {
  const sec = Math.floor(now / 1000);
  if (sec !== secSlot) { secSlot = sec; secCount = 0; }
  if (inFlight >= MAX_IN_FLIGHT || secCount >= MAX_PER_SECOND) return false;
  inFlight += 1;
  secCount += 1;
  return true;
}

// Resolves to the RPC's answer, or rejects on failure or after timeoutMs.
// The abort also cancels the real fetch; the race covers a call that ignores
// it. The in flight slot is released when the real call settles (so the cap
// counts what the database is actually doing), or after RELEASE_AFTER_MS.
function rpcWithDeadline(fn, args, timeoutMs) {
  const ac = typeof AbortController === "function" ? new AbortController() : null;
  let released = false;
  const release = () => { if (!released) { released = true; inFlight -= 1; } };
  const hard = setTimeout(release, Math.max(RELEASE_AFTER_MS, timeoutMs * 4));
  if (hard && typeof hard.unref === "function") hard.unref();
  let timer;
  const deadline = new Promise((_resolve, reject) => {
    timer = setTimeout(() => {
      if (ac) ac.abort();
      reject(new Error("timeout"));
    }, timeoutMs);
    if (timer && typeof timer.unref === "function") timer.unref();
  });
  const call = Promise.resolve().then(() => store().rpc(fn, args, "ratelimit", ac ? { signal: ac.signal } : {}));
  call.then(() => {}, () => {}).finally(() => { clearTimeout(hard); release(); });
  return Promise.race([call, deadline]).finally(() => clearTimeout(timer));
}

async function checkShared(req, cost = 1, { now = Date.now(), timeoutMs = SHARED_TIMEOUT_MS } = {}) {
  const local = check(req, cost, { now, aligned: true });
  if (local.limited) return { ...local, shared: false };

  let onPg = false;
  try {
    onPg = store().onPostgres();
  } catch (_e) {
    onPg = false;
  }
  if (!onPg) return local;
  const secret = ipSecret();
  if (!secret) return { ...local, shared: false };

  const gate = breakerGate(now);
  if (gate === "open") return { ...local, shared: false };
  if (!takeSlot(now)) {
    if (gate === "probe") breaker.probing = false;
    return { ...local, shared: false };
  }

  const start = slotStart(now);
  let hits;
  try {
    const out = await rpcWithDeadline("ip_rate_hit", {
      p_ip_hash: ipKey(callerIp(req), secret), p_window_start: new Date(start).toISOString(), p_cost: cost,
    }, timeoutMs);
    hits = Array.isArray(out) ? out[0] : out;
  } catch (_e) {
    hits = null;
  }
  if (!Number.isSafeInteger(hits) || hits < 1) {
    breakerResult(false, now, gate === "probe");
    logOutage(now, "unreadable or slow");
    return { ...local, shared: false };
  }
  breakerResult(true, now, gate === "probe");
  if (hits > LIMIT) {
    const retryAfterSeconds = Math.max(1, Math.ceil((start + WINDOW_MS - now) / 1000));
    return { limited: true, retryAfterSeconds, limit: LIMIT, windowSeconds: WINDOW_MS / 1000, shared: true };
  }
  return { limited: false, shared: true };
}

// For tests: the breaker and cap state of this instance.
function _sharedState() {
  return { inFlight, breakerOpenUntil: breaker.openUntil, probing: breaker.probing, recentFailures: breaker.failures.length,
    buckets: buckets.size };
}

module.exports = {
  check, checkShared, callerIp, normaliseIp, parseIp, ipKey, LIMIT, MAX_IP_LEN, MAX_BUCKETS, RELEASE_AFTER_MS, WINDOW_MS, SHARED_TIMEOUT_MS, SECRET_ENV,
  BREAKER_FAILURES, BREAKER_WINDOW_MS, BREAKER_OPEN_MS, MAX_IN_FLIGHT, MAX_PER_SECOND, _sharedState,
};
