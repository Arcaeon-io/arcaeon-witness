// _prefix_check.js — the namespace-prefix AVAILABILITY check behind
// `GET /api/prefix-available?prefix=<p>`. Underscore prefix = not routed as a
// serverless function by Vercel.
//
// WHY THIS EXISTS (2026-08-30, board item I-daniel-01 — Daniel 12288/12291:
// "shouldnt we let our users pick a prefix that isnt selected"). Rev-2 gave
// the buyer a prefix FIELD; it did not give them a way to know whether their
// pick was free before they committed. The only feedback was a rejected form
// POST after the fact. This is the pre-flight answer.
//
// WHERE IT IS ROUTED, AND WHY IT IS NOT ITS OWN api/ FILE. `api/` sits at
// Vercel Hobby's 12-function hard cap (see CHANGELOG 2026-08-17 and
// lib/_page.js's header) — a 13th file breaks the deploy. So the public URL
// `/api/prefix-available` is a vercel.json REWRITE onto the existing
// `/api/fulfill` function carrying `?op=prefix-available`, which fulfill.js
// dispatches here before anything else. That is the same trick already in
// vercel.json for `/api/status.json` -> `/api/status?format=json`, and the
// same reasoning that put the balance page on the balance function.
//
// ==== BOUNDARY — THIS FILE MINTS NOTHING ====================================
// This endpoint issues no key, writes no file, touches no money, and needs no
// auth. It reads the existing prefix list and answers yes/no. Key MINTING is
// not part of the prefix picker and never becomes part of it: it stays behind
// api/fulfill.js's server-side Stripe session verification (self-serve path),
// or the operator's hands per projects/online_business/FULFILLMENT_RUNBOOK.md
// (manual path). A "the prefix is free" answer here is ADVISORY — advice, not
// a reservation. The authoritative check is the un-cached keys.listPrefixes()
// + keys.prefixConflicts() pair inside fulfill.js's mint path, which runs
// again at mint time and is the only one that can refuse a key.
// ===========================================================================
//
// PRIVACY (2026-11-22): the answer is taken or free, nothing more. It used to
// return three "free instead" alternatives built from the asked stem and
// checked against every existing prefix, which handed a caller with no auth
// names shaped by other customers' prefixes and told them which neighbours
// of a taken prefix were free. Those are gone, and so is the code that built
// them. Checks are limited per address in their own bucket (scope
// "prefix-check", see handle below).
//
// No CORS on purpose: the only caller is the picker form on
// /api/fulfill, same origin. Leaving cross-origin off keeps prefix
// enumeration first-party rather than handing anyone a scriptable oracle over
// customer prefixes. (Namespaces themselves are public by design in the pin
// repo; a prefix with no pins yet is not, so this stays narrow.)

"use strict";

const keys = require("./_keys.js");
const ratelimit = require("./_ratelimit.js");

// Matches lib/_keys.js PREFIX_RE's ceiling: 48 chars total, leaving >=16
// chars of namespace room under _store.NS_RE's 64.
const MAX_PREFIX_LEN = 48;

// The limiter bucket this endpoint counts in, per address.
const PREFIX_CHECK_SCOPE = "prefix-check";

// ---- existing-prefix list, briefly cached ----
// keys.listPrefixes() is a directory listing plus one GitHub read per issued
// key. A debounced picker asks this once per typing pause, so an uncached
// call per keystroke-pause would fan out that read set every time. TTL is
// short and the cache is per-warm-instance (same honest limitation as
// _ratelimit.js's buckets). The cache lives HERE and nowhere else — the mint
// path in fulfill.js calls keys.listPrefixes() directly and never sees it, so
// a stale entry can only ever make this endpoint's ADVICE briefly wrong, and
// can never widen what an actual mint will accept.
const CACHE_TTL_MS = 20 * 1000;
let cache = { at: 0, prefixes: null };

async function existingPrefixes() {
  const now = Date.now();
  if (cache.prefixes && now - cache.at < CACHE_TTL_MS) return cache.prefixes;
  const list = await keys.listPrefixes();
  cache = { at: now, prefixes: list };
  return list;
}

// Exported for tests (each test stubs a different prefix universe).
function _resetCache() {
  cache = { at: 0, prefixes: null };
}

// The pure decision, separated from the HTTP shell so tests can drive it
// directly and so fulfill.js could reuse it if the picker ever moves.
// Returns {status, body}.
async function decide(rawPrefix) {
  if (rawPrefix === undefined || rawPrefix === null || String(rawPrefix).trim() === "") {
    return {
      status: 400,
      body: {
        available: false,
        reason: "empty",
        detail: "pass ?prefix=<your-prefix>",
      },
    };
  }
  // Normalized exactly as api/fulfill.js normalizes an explicit pick (H3:
  // trim + lowercase). If these two ever diverge, this endpoint starts
  // answering about a different string than the one that gets minted.
  const prefix = String(rawPrefix).trim().toLowerCase();

  const v = keys.validatePrefix(prefix);
  if (!v.ok) {
    return {
      status: 400,
      body: { available: false, prefix, reason: v.reason, detail: v.detail },
    };
  }

  let existing;
  try {
    existing = await existingPrefixes();
  } catch (err) {
    // Fail CLOSED as "unknown", never as "available" — a store hiccup must
    // not talk a buyer into a pick the mint path will refuse. 503 so the UI
    // can say "could not check" rather than "free".
    console.error(`[prefix-available] store read failed: ${err.message}`);
    return {
      status: 503,
      body: {
        available: null,
        prefix,
        reason: "store_unavailable",
        detail:
          "could not read the prefix list just now — your pick is still validated when the key is minted",
      },
    };
  }

  if (!keys.prefixConflicts(prefix, existing)) {
    return {
      status: 200,
      body: {
        available: true,
        prefix,
        example: `${prefix}main`,
        note: "advisory — the binding check runs again at mint time",
      },
    };
  }

  // Which prefix collided is NEVER echoed: it belongs to another customer
  // (same discipline as api/fulfill.js's 409). No alternatives either: any
  // name built against the existing list says something about it.
  return {
    status: 200,
    body: {
      available: false,
      prefix,
      reason: "taken",
      detail:
        "that prefix is taken — it matches, contains, or is contained by an existing prefix",
    },
  };
}

// ---- HTTP shell ----
async function handle(req, res) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.setHeader("allow", "GET, HEAD");
    return res.status(405).json({ error: "GET or HEAD only" });
  }
  res.setHeader("cache-control", "no-store");

  // Per-address limiter (per-IP, IPv6 by /64, per-warm-instance — see
  // _ratelimit.js for exactly what that does and does not buy), in its OWN
  // bucket: before 2026-11-22 it shared the public read bucket with
  // /api/verify, so its budget for this endpoint was whatever reads had left.
  // A user who trips it mid-purchase gets 429 here. That is survivable
  // BECAUSE the check is advisory: the picker degrades to "could not check"
  // and the submit path still works. Nothing on the revenue path depends on
  // a 200.
  const rl = ratelimit.check(req, 1, { scope: PREFIX_CHECK_SCOPE });
  if (rl.limited) {
    res.setHeader("retry-after", String(rl.retryAfterSeconds));
    return res.status(429).json({
      available: null,
      reason: "rate_limited",
      detail: `too many availability checks (${rl.limit} per ${rl.windowSeconds}s); the prefix is validated at mint time regardless`,
      retry_after_seconds: rl.retryAfterSeconds,
    });
  }

  const q = req.query || {};
  const { status, body } = await decide(q.prefix);
  return res.status(status).json(body);
}

module.exports = {
  handle,
  decide,
  existingPrefixes,
  MAX_PREFIX_LEN,
  PREFIX_CHECK_SCOPE,
  CACHE_TTL_MS,
  _resetCache,
};
