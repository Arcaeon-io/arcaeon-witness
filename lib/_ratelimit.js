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
// against a distributed burst. It is NOT a guaranteed global cap. A precise
// cross-instance limiter needs shared state (Vercel KV / Upstash) and is
// not built here. This costs nothing extra and blocks something; it does
// not block everything.

"use strict";

const WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const LIMIT = 30; // calls per IP per window, per warm instance

const buckets = new Map(); // "<scope>|<ip>" or "<ip>" -> {windowStart, count}

// Hard cap on the Map, whatever the traffic between sweeps (red hunt
// 2026-11-02: a flood of distinct addresses used to add one entry each for up
// to five minutes with no ceiling). At MAX_BUCKETS a new key evicts the oldest
// bucket first. Insertion order is window start order (a bucket is re-inserted
// when its window restarts), so the one evicted is the bucket nearest its own
// natural reset: the least budget handed back. Positive integer override
// WITNESS_IP_RATE_MAX_BUCKETS, read once per instance.
function envInt(name, dflt) {
  const v = Number(process.env[name]);
  return Number.isSafeInteger(v) && v > 0 ? v : dflt;
}
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
// every such caller collapses onto one shared "unknown" bucket: degraded,
// but it fails toward MORE blocking (they all share one 30/10min budget),
// never toward silently unlimited.
//
// IPv6 is grouped by /64 (red hunt 2026-11-02): one subscriber is routinely
// handed a whole /64, so keying on the full address would give one caller
// 2^64 separate budgets. An IPv6 address is normalised to its first four
// hextets ("2001:db8:0:1::/64"), with :: compression, brackets, a port after
// brackets and a zone id handled. An IPv4 mapped address (::ffff:a.b.c.d, or
// its hex form) is the IPv4 address. IPv4 is unchanged (a ":port" after it is
// dropped). Anything that does not parse is returned as is by normaliseIp;
// parseIp returns null.
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
  // A client address never carries a prefix length. Without this, a header
  // value already written as "2001:DB8::/64" skipped normalisation and became
  // its own non canonical bucket beside "2001:db8:0:0::/64" (review, round 2).
  if (s.includes("/")) return null;
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

// check(req, cost=1, {scope}) -> {limited:false} | {limited:true, retryAfterSeconds, limit, windowSeconds}
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
// `scope` (red hunt 2026-11-02) names a SEPARATE budget for one endpoint, the
// same LIMIT per window but its own bucket per IP, for a path whose callers
// must not be starved by the public read budget: /api/fulfill's buyer, whose
// own picker form spends the default bucket on live prefix checks, must still
// be able to mint. Omitted or empty keeps the one shared read bucket.
function check(req, cost = 1, { now = Date.now(), scope = "" } = {}) {
  sweep(now);
  const ip = callerIp(req);
  const key = scope ? `${scope}|${ip}` : ip;
  let b = buckets.get(key);
  if (!b || now - b.windowStart > WINDOW_MS) {
    b = { windowStart: now, count: 0 };
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

// For tests only: a suite that drives one handler from one fake address many
// times across its cases must be able to start each case with an empty Map.
function _resetForTests() {
  buckets.clear();
  lastSweep = 0;
}

function _bucketCount() {
  return buckets.size;
}

module.exports = { check, callerIp, normaliseIp, parseIp, LIMIT, WINDOW_MS, MAX_IP_LEN, MAX_BUCKETS, _resetForTests, _bucketCount };
