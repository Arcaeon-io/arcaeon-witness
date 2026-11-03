// _keys.js — DYNAMICALLY ISSUED witness keys + Stripe-fulfillment bindings.
// Underscore prefix = not routed as a serverless function by Vercel.
//
// WHY THIS EXISTS (2026-08-17, board item 25 — instant fulfillment): until
// now every witness key lived in the WITNESS_KEYS env var, hand-provisioned.
// An env var cannot be appended to by a serverless function at runtime, so
// self-serve purchase ("pay Stripe, get a key on the receipt page") requires
// a real key store. This is that store — the MINIMAL one, deliberately built
// on the exact same primitive every other stateful module here already uses:
// JSON files in the PRIVATE usage repo (dan8433-user/arcaeon-witness-usage),
// GitHub contents API, create-only / compare-and-swap writes. Nothing new to
// operate, same GITHUB_PIN_TOKEN, same audit-by-git-history property as
// _meter.js and _balance.js.
//
// Files this module owns (all in the PRIVATE usage repo — never the public
// pin repo; a raw key or a billing hash must never land in public git):
//
//   keys/<sha256(key)>.json          issued-key record: namespace prefix the
//                                    key may pin under, plan, org, pool_id.
//                                    api/pin.js + api/balance.js consult this
//                                    AFTER the WITNESS_KEYS env lookup misses,
//                                    so env-provisioned keys are untouched.
//   fulfillments/<session_id>.json   Stripe Checkout session -> key binding.
//                                    CREATE-ONLY: this file is the idempotency
//                                    gate that guarantees one session never
//                                    mints two keys. It stores the RAW key on
//                                    purpose — the whole point of the receipt
//                                    page is that revisiting it re-shows the
//                                    same key (Stripe's receipt email links
//                                    back to it), and you cannot re-show what
//                                    you only kept a hash of. The session URL
//                                    is already a bearer of the key by design,
//                                    so a private-repo copy adds no new
//                                    exposure class beyond what the product
//                                    promise itself requires.
//   pools/<pool_id>.json             credit-pool record (org/team schema,
//                                    baked in now, UI later — see below).
//
// ORG / POOL SCHEMA (schema now, UI later): every issued key carries
// `org` (nullable) and `pool_id`. Credits conceptually live on the POOL.
// For a solo purchase — the only flow wired today — the pool is a
// single-key pool whose `credit_account` IS the key's own sha256 hash, so
// the pool's balance file is exactly the balance/<key_hash>.json that
// api/_balance.js already reads and decrements: no change to the live
// billing path. TEAM FLOW (future): N issued-key records share one
// pool_id; the pool's credit_account becomes a pool-scoped identifier and
// api/pin.js's charge path resolves key -> issued-key record -> pool_id ->
// credit_account before calling decrementCredit, so N keys draw down one
// shared balance. That resolution hop is NOT built (solo pools don't need
// it); the fields exist now so no schema migration is needed when it is.

"use strict";

const crypto = require("crypto");

const USAGE_REPO = process.env.GITHUB_USAGE_REPO || "dan8433-user/arcaeon-witness-usage";
const USAGE_BRANCH = process.env.GITHUB_USAGE_BRANCH || "main";
const API = "https://api.github.com";

// Stripe Checkout session ids are `cs_test_...` / `cs_live_...`, alphanumeric.
// Anchored + charset-limited so a session id is path-safe by construction —
// this is what lets fulfillments/<session_id>.json use the id verbatim with
// zero traversal risk, and it doubles as the first "faked URL" rejection.
const SESSION_ID_RE = /^cs_(test|live)_[A-Za-z0-9]{8,240}$/;

function ghHeaders() {
  const h = {
    accept: "application/vnd.github+json",
    "user-agent": "arcaeon-witness-keys",
    "x-github-api-version": "2022-11-28",
  };
  const tok = process.env.GITHUB_PIN_TOKEN;
  if (tok) h.authorization = `Bearer ${tok}`;
  return h;
}

// Same gh get/put pair as _meter.js/_balance.js. Duplicated rather than
// imported on purpose — each stateful module here carries its own copy so its
// error redaction and logging tag stay legible by inspection (the established
// house pattern; see _balance.js which did the same next to _meter.js).
async function getFile(path) {
  const r = await fetch(
    `${API}/repos/${USAGE_REPO}/contents/${path}?ref=${USAGE_BRANCH}`,
    { headers: ghHeaders() }
  );
  if (r.status === 404) return null;
  if (!r.ok) {
    // Path redacted from thrown messages (2026-08-14 audit discipline):
    // callers interpolate err.message into response bodies, and these paths
    // name key hashes / session ids in a PRIVATE repo.
    console.error(`[keys] GET ${path} -> ${r.status}`);
    throw new Error(`key store read failed (${r.status})`);
  }
  const body = await r.json();
  const text = Buffer.from(body.content, "base64").toString("utf-8");
  return { json: JSON.parse(text), sha: body.sha };
}

async function putFile(path, obj, message, sha) {
  const payload = {
    message,
    branch: USAGE_BRANCH,
    content: Buffer.from(JSON.stringify(obj, null, 2) + "\n").toString("base64"),
  };
  if (sha) payload.sha = sha;
  const r = await fetch(`${API}/repos/${USAGE_REPO}/contents/${path}`, {
    method: "PUT",
    headers: { ...ghHeaders(), "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (r.status === 409) {
    console.error(`[keys] PUT ${path} -> 409 sha conflict`);
    const err = new Error("key store write conflict (concurrent writer)");
    err.conflict = true;
    throw err;
  }
  if (!r.ok) {
    const detail = await r.text().catch(() => "");
    // GitHub's create-race shape (two writers both tried to CREATE the same
    // not-yet-existing file) — same tagging idiom as _store/_meter/_balance.
    const isCreateRace = r.status === 422 && /sha.*wasn't supplied/i.test(detail);
    console.error(`[keys] PUT ${path} -> ${r.status}: ${detail.slice(0, 400)}`);
    const err = new Error(`key store write failed (${r.status})`);
    if (isCreateRace) err.conflict = true;
    throw err;
  }
  return r.json();
}

// ---- minting ----
// wk_ prefix so an issued key is recognizable in support conversations
// without revealing anything; 24 random bytes = 192 bits, hex-encoded.
function mintKey() {
  return "wk_" + crypto.randomBytes(24).toString("hex");
}

// The namespace prefix an issued key may pin under. Random and DERIVED FROM
// NOTHING — deliberately not a slice of the key hash: sha256(key) is the
// billing identifier (client_reference_id, balance file names) and the public
// pin repo must never carry any recognizable piece of it (_store.js's
// OWNER_ID_DOMAIN comment states the rule). Matches _store.NS_RE by
// construction ([a-z0-9-], well under 64 chars, leaving the buyer room for a
// suffix like "prod" or "agent-7").
function mintNamespacePrefix() {
  return `wk-${crypto.randomBytes(6).toString("hex")}-`;
}

function mintPoolId() {
  return `pool_${crypto.randomBytes(8).toString("hex")}`;
}

// ---- prefix picking (rev-2, board item 27) ----
// A buyer may now CHOOSE the namespace prefix at mint time instead of taking
// the random wk-… one. The prefix is an AUTHORIZATION boundary — a key pins
// every namespace starting with its prefix — so two rules are load-bearing:
//
//   1. FORMAT: lowercase [a-z0-9-], starts alphanumeric, ends in '-', ≤48
//      chars total (leaves ≥16 chars of namespace room under _store.NS_RE's
//      64). The trailing dash is required so "acme-" can never accidentally
//      startsWith-match an unrelated namespace like "acmecorp-main".
//   2. NO TWO-WAY OVERLAP with any existing prefix: a new prefix must neither
//      BE a prefix of an existing one nor HAVE an existing one as its prefix
//      ("acme-" vs "acme-labs-" is rejected in BOTH directions). Overlapping
//      prefixes would let two different customers' keys pin into each other's
//      namespaces — that is the harm this check exists to prevent.
//
// "wk-" is RESERVED for auto-minted prefixes: a customer who claimed "wk-"
// (or any wk-… stem) could otherwise sit upstream of every random mint that
// follows, so the whole stem is refused to custom pickers outright.
const PREFIX_RE = /^[a-z0-9][a-z0-9-]{0,46}-$/;

// RESERVED_BRAND_STEMS — the operator's own brand namespaces (2026-09-20,
// second-model review). Before this, a customer could claim "velouria-x" or
// "arcaeon-x" (only "wk-" was reserved), which did two bad things at once:
// (a) lib/_status_data.js's isReferenceNamespace() tags any "velouria-"/
// "arcaeon-" namespace as "our own log" on the PUBLIC status page, so a
// paying customer's row would be mislabelled as the operator's; and (b) it
// let a customer squat the operator's brand stem outright, same class of
// harm as an unreserved "wk-" would have been.
//
// SINGLE SOURCE OF TRUTH: this array is the only place these stems are
// spelled out. lib/_status_data.js's REFERENCE_PREFIXES is DERIVED from it
// (never a separate literal) so the claim-time refusal and the status
// page's "reference" tag can never drift apart — a stem reserved here is
// always a stem the page calls ours, and vice versa.
//
// Matching mirrors the "wk-" check exactly: a bare stem or the stem plus a
// trailing dash plus anything ("velouria-", "velouria-x", …) is refused; a
// stem merely APPEARING inside a longer, differently-rooted prefix
// ("acme-velouria-mirror-", "myarcaeon-x-") is not — same startsWith
// discipline PREFIX overlap already uses elsewhere in this file.
const RESERVED_BRAND_STEMS = ["velouria", "arcaeon"];

function validatePrefix(p) {
  if (typeof p !== "string" || p.length === 0) {
    return { ok: false, reason: "empty", detail: "prefix is empty" };
  }
  if (!PREFIX_RE.test(p)) {
    return {
      ok: false,
      reason: "format",
      detail:
        "prefix must be lowercase [a-z0-9-], start with a letter or digit, " +
        "end in '-', and be at most 48 characters",
    };
  }
  if (p.startsWith("wk-")) {
    return {
      ok: false,
      reason: "reserved",
      detail: "the wk- stem is reserved for auto-minted prefixes",
    };
  }
  for (const stem of RESERVED_BRAND_STEMS) {
    if (p.startsWith(`${stem}-`)) {
      return {
        ok: false,
        reason: "reserved",
        detail: `the ${stem}- stem is reserved for the operator's own namespaces`,
      };
    }
  }
  return { ok: true };
}

// Two-way overlap check. Returns true if the candidate collides with ANY
// existing prefix (equal, contains, or is contained by). The caller never
// echoes WHICH prefix collided — existing prefixes belong to other customers.
function prefixConflicts(candidate, existingPrefixes) {
  for (const ex of existingPrefixes || []) {
    if (!ex) continue;
    if (candidate.startsWith(ex) || ex.startsWith(candidate)) return true;
  }
  return false;
}

// Pre-suggest a prefix from what Stripe already knows about the buyer: the
// email local part first ("jane.doe@acme.com" -> "jane-doe-"), else the
// customer name/company. Returns a VALID prefix string or null — a suggestion
// that fails validatePrefix (e.g. sanitizes to nothing, or lands on the
// reserved wk- stem) is dropped rather than repaired into surprise.
function suggestPrefix(email, name) {
  const candidates = [];
  if (email && typeof email === "string" && email.includes("@")) {
    candidates.push(email.split("@")[0]);
  }
  if (name && typeof name === "string") candidates.push(name);
  for (const raw of candidates) {
    const base = String(raw)
      .toLowerCase()
      .replace(/[^a-z0-9-]+/g, "-")
      .replace(/-{2,}/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 24)
      .replace(/-+$/g, "");
    if (!base) continue;
    const p = `${base}-`;
    if (validatePrefix(p).ok) return p;
  }
  return null;
}

// Prefixes already bound in the WITNESS_KEYS env var ("key:prefix" pairs,
// comma-separated — same format _store.keyPrefixFor consumes). Env keys are
// hand-provisioned, but their prefixes are just as much authorization
// boundaries as issued-store ones, so the overlap check must see them.
function envKeyPrefixes() {
  const raw = process.env.WITNESS_KEYS || "";
  const out = [];
  for (const pair of raw.split(",")) {
    const i = pair.indexOf(":");
    if (i < 1) continue;
    const prefix = pair.slice(i + 1).trim();
    if (prefix) out.push(prefix);
  }
  return out;
}

// GitHub contents API directory listing (array of entries; 404 = no dir yet,
// which is simply "no issued keys yet" -> empty). NOTE the API caps a
// directory listing at 1000 entries; combined with the one-read-per-key fan
// out below, this listing approach is deliberately the CHEAP version for the
// current scale (self-serve keys number in the tens). When key volume ever
// approaches that cap, replace with a maintained prefix-index file — do NOT
// silently validate against a truncated list.
async function listDir(path) {
  const r = await fetch(
    `${API}/repos/${USAGE_REPO}/contents/${path}?ref=${USAGE_BRANCH}`,
    { headers: ghHeaders() }
  );
  if (r.status === 404) return [];
  if (!r.ok) {
    console.error(`[keys] LIST ${path} -> ${r.status}`);
    throw new Error(`key store list failed (${r.status})`);
  }
  const body = await r.json();
  // [] only via the 404 above: a 200 that is not a listing must not read as
  // "no prefixes are spoken for" (lib/_verdict.js).
  return require("./_verdict.js").requireListing(body, `key store list ${path}`).map((e) => e.name);
}

// Every prefix currently spoken for: env WITNESS_KEYS bindings + every
// issued-key record in the store. Revoked keys KEEP their prefix reserved —
// a revoked key may be un-revoked, and freeing its prefix would let a new
// customer sit on top of its historical pins.
async function listPrefixes() {
  const out = new Set(envKeyPrefixes());
  const names = await listDir("keys");
  const reads = names
    .filter((n) => n.endsWith(".json"))
    .map((n) => getFile(`keys/${n}`));
  for (const rec of await Promise.all(reads)) {
    const p =
      rec && rec.json && typeof rec.json.namespace_prefix === "string"
        ? rec.json.namespace_prefix.trim()
        : "";
    if (p) out.add(p);
  }
  return [...out];
}

function keyHash(secret) {
  return crypto.createHash("sha256").update(secret, "utf8").digest("hex");
}

// ---- paths ----
function issuedKeyPath(hash) {
  return `keys/${hash}.json`;
}
function poolPath(poolId) {
  return `pools/${poolId}.json`;
}
function fulfillmentPath(sessionId) {
  return `fulfillments/${sessionId}.json`;
}

// ---- issued-key auth resolution ----
// The dynamic half of what _store.keyPrefixFor does for env keys. Returns the
// key's namespace prefix (string) or null for an unknown/revoked key. Callers
// (pin.js, balance.js) try the env lookup FIRST — it's free and covers every
// hand-provisioned key — and only reach here on a miss, so env-key requests
// cost zero extra store reads. Fails CLOSED on a malformed record: a key file
// without a usable prefix authorizes nothing.
async function issuedKeyPrefix(secret) {
  if (!secret) return null;
  const rec = await getFile(issuedKeyPath(keyHash(secret)));
  if (!rec) return null;
  if (rec.json && rec.json.revoked === true) return null;
  const prefix = rec.json && typeof rec.json.namespace_prefix === "string"
    ? rec.json.namespace_prefix.trim()
    : "";
  // Same empty-prefix refusal as _store.keyPrefixFor: "" would startsWith-match
  // every namespace, and a malformed record must never widen authorization.
  return prefix ? prefix : null;
}

// ---- unknown-key lookups are limited per address (red hunt 2026-11-02, round 2) ----
//
// issuedKeyPrefix above is one GitHub read per key that is not in WITNESS_KEYS.
// Before this, ANY bearer value reached it, before any rate limit: a stranger
// sending `Authorization: Bearer x1`, `x2`, ... emptied the hour's quota on
// GITHUB_PIN_TOKEN, the one token every paid pin, meter increment and credit
// debit also use, and paying customers answered 502 until it refilled. No key
// was needed. The per key limiter in api/pin.js runs AFTER auth, so it never
// saw the flood.
//
// Round 1 refused the whole address once it had missed MISS_LIMIT times, which
// locked every self-serve key behind a shared NAT out of pin, balance and
// stamp for ten minutes the moment one agent retried a mistyped key twenty
// times. Round 2 (reviewer's blocker) is built so a VALID key always gets
// through and a REPEATED bad key costs one read:
//
//   known    sha256(key) -> {prefix, until}   positive cache, checked BEFORE the
//                                             cap: a key this instance has seen
//                                             valid in the last CACHE_TTL_MS is
//                                             served without a read whatever its
//                                             address has done. (Revocation
//                                             therefore lags by up to that TTL
//                                             on a warm instance.)
//   unknown  sha256(key) -> until             negative cache: a repeated bad key
//                                             is answered without a read and is
//                                             counted once, not once per retry.
//   bucket   address -> {windowStart, hashes, graceAt}
//                                             the cap counts DISTINCT unknown
//                                             hashes per address per window.
//                                             The hash is added BEFORE the store
//                                             read (the slot is reserved, so
//                                             concurrent guesses cannot all slip
//                                             under the count) and removed again
//                                             if the key turns out valid or the
//                                             store failed (our outage never
//                                             counts against the caller).
//   grace    an address over the cap still gets ONE store read per
//            GRACE_READ_MS, so the holder of a valid key this instance has
//            never seen waits at most a minute, not the whole window. A valid
//            key never seen by this instance, from an address over the cap,
//            inside that minute, IS refused: that is the protection, and the
//            body says so in words meant for the holder of a good key.
//   global   at most GLOBAL_READS_PER_MIN unknown-key store reads per instance
//            per minute, whatever the addresses (a routed /56 is 256 /64s; a
//            flood of distinct addresses must not add up to the token quota).
//            A read that found a valid key gives its slot back; a read that
//            failed does NOT (it still cost a GitHub call, and a 5xx from
//            GitHub is exactly when to stop asking).
//   eviction the bucket Map is capped; an expired bucket is evicted first,
//            then one under the cap, and an over-cap bucket only when nothing
//            else is left, so a flood of fresh addresses cannot wash out the
//            counts that are doing the work.
//
// Everything here is per warm instance and in memory, the same honest
// limitation as lib/_ratelimit.js: it bounds what one instance will spend,
// it does not stop a flood spread across many instances or across instance
// churn (each cold start begins with empty caches and counts). The cross
// instance count is PR 15's job. A key shape gate was considered and
// rejected: the live store carries hand written records with no `source`, so
// their raw keys cannot be assumed to match mintKey()'s `wk_` + 48 hex. Only
// an OVERLONG value is refused without a read: no issued key is anywhere near
// MAX_KEY_LEN. Only hashes are ever held here, never a bearer value.
const MAX_KEY_LEN = 256;
const MISS_LIMIT = 20; // distinct unknown keys per address per window
const MISS_WINDOW_MS = 10 * 60 * 1000;
const GRACE_READ_MS = 60 * 1000; // one store read per over-cap address per minute
const CACHE_TTL_MS = 60 * 1000; // positive and negative caches
// A valid key stays SERVABLE for this long after its fresh TTL, as last seen
// valid: when the instance's read budget is gone under a flood, a key it has
// seen valid in the last ten minutes is served from this memory instead of
// 429, so a flood cannot take every issued key on the instance down with it
// (review, round 3). Only real keys can reach this path, bounded by the
// customer count. The cost: a revocation can lag by up to this long, and only
// during a flood (with budget to spare the key is re-read as usual).
const STALE_KEEP_MS = 10 * 60 * 1000;
const CACHE_MAX = 10000;
// 15, not 60, until PR 15's cross instance limiter ships: this cap is per
// warm instance, and 60 a minute times the instances Vercel can run at once
// adds up past the token's 5,000 an hour. 15 x 60 = 900 an hour per instance.
const GLOBAL_READS_PER_MIN = 15; // unknown-key store reads per instance per minute
let globalReadsPerMin = GLOBAL_READS_PER_MIN;
let missMaxBuckets = 10000;

const clock = { now: () => Date.now() };
const missBuckets = new Map(); // ip -> {windowStart, hashes:Set<hash>, graceAt}
const known = new Map(); // hash -> {prefix, until, staleUntil}
const unknown = new Map(); // hash -> until
let globalMinute = -1;
let globalReads = 0;

function cacheGet(map, hash, now) {
  const e = map.get(hash);
  if (e === undefined) return undefined;
  const until = typeof e === "number" ? e : e.until;
  if (until <= now) {
    map.delete(hash);
    return undefined;
  }
  return e;
}

function cachePut(map, hash, value) {
  map.delete(hash);
  while (map.size >= CACHE_MAX) map.delete(map.keys().next().value);
  map.set(hash, value);
}

// knownGet(hash, now) -> {prefix, fresh:true}   seen valid inside CACHE_TTL_MS
//                      | {prefix, fresh:false}  seen valid inside STALE_KEEP_MS
//                      | undefined
function knownGet(hash, now) {
  const e = known.get(hash);
  if (e === undefined) return undefined;
  if (e.staleUntil <= now) {
    known.delete(hash);
    return undefined;
  }
  return { prefix: e.prefix, fresh: e.until > now };
}

// Insertion order is window start order (a bucket is re-created when its
// window turns), so the first entry is the oldest. An expired oldest goes
// first; otherwise the first under-cap bucket, found and stopped at; an
// over-cap bucket only when every bucket is over the cap.
function evictOneBucket(now) {
  const first = missBuckets.entries().next().value;
  if (!first) return;
  const [oldestKey, oldest] = first;
  if (now - oldest.windowStart > MISS_WINDOW_MS) {
    missBuckets.delete(oldestKey);
    return;
  }
  for (const [k, b] of missBuckets) {
    if (b.hashes.size < MISS_LIMIT) {
      missBuckets.delete(k);
      return;
    }
  }
  missBuckets.delete(oldestKey);
}

function bucketFor(ip, now, create) {
  let b = missBuckets.get(ip);
  if (b && now - b.windowStart > MISS_WINDOW_MS) {
    missBuckets.delete(ip);
    b = undefined;
  }
  if (!b && create) {
    if (missBuckets.size >= missMaxBuckets) evictOneBucket(now);
    b = { windowStart: now, hashes: new Set(), graceAt: 0 };
    missBuckets.set(ip, b);
  }
  return b || null;
}

function overCap(b, hash) {
  return b.hashes.size >= MISS_LIMIT && !b.hashes.has(hash);
}

function addressLimited(b, now) {
  const retryAfterSeconds = Math.max(1, Math.ceil((b.windowStart + MISS_WINDOW_MS - now) / 1000));
  return { prefix: null, limited: true, scope: "address", retryAfterSeconds };
}

// The grace refusal: the next read for this address opens when its grace
// minute turns, NOT at the end of the ten minute window, and Retry-After says
// so (review, round 3). addressLimited above keeps the window end for the one
// path where that is true (a repeated bad key no bucket of ours counted).
function graceLimited(b, now) {
  const retryAfterSeconds = Math.max(1, Math.ceil((b.graceAt + GRACE_READ_MS - now) / 1000));
  return { prefix: null, limited: true, scope: "grace", retryAfterSeconds };
}

function globalTake(now) {
  const m = Math.floor(now / 60000);
  if (m !== globalMinute) {
    globalMinute = m;
    globalReads = 0;
  }
  if (globalReads >= globalReadsPerMin) return false;
  globalReads += 1;
  return true;
}

function globalLimited(now) {
  const retryAfterSeconds = Math.max(1, Math.ceil(((globalMinute + 1) * 60000 - now) / 1000));
  return { prefix: null, limited: true, scope: "instance", retryAfterSeconds };
}

// lookupIssuedPrefix(req, key) -> {prefix}                      found
//                              | {prefix:null}                  unknown
//                              | {prefix:null, limited:true, scope, retryAfterSeconds}
// Throws on a store failure, exactly as issuedKeyPrefix does; callers map that
// to 502 ("we could not check" is never "your key is invalid").
async function lookupIssuedPrefix(req, key) {
  if (!key) return { prefix: null };
  if (key.length > MAX_KEY_LEN) return { prefix: null };
  const now = clock.now();
  const hash = keyHash(key);

  const seen = knownGet(hash, now);
  if (seen && seen.fresh) return { prefix: seen.prefix };
  // Past its fresh TTL but seen valid inside STALE_KEEP_MS: served only where
  // a refusal below would otherwise land on a real key (see STALE_KEEP_MS).
  // With budget to spare the key falls through and is re-read as usual.
  const stale = seen ? { prefix: seen.prefix, stale: true } : null;

  const { callerIp } = require("./_ratelimit.js");
  const ip = callerIp(req);

  if (cacheGet(unknown, hash, now) !== undefined) {
    // A repeated bad key: no read. Every read that found nothing added its
    // hash to the address bucket, grace reads included, so a retry of the
    // same wrong key stays a plain 401. Refused as limited only when the
    // bucket is over the cap and this hash is not one it counted (it was
    // first seen from another address); Retry-After is then the window end.
    const b = bucketFor(ip, now, false);
    if (b && overCap(b, hash)) return addressLimited(b, now);
    return { prefix: null };
  }

  const b = bucketFor(ip, now, true);
  const grace = overCap(b, hash);
  if (grace && now - b.graceAt < GRACE_READ_MS) return stale || graceLimited(b, now);
  if (!globalTake(now)) return stale || globalLimited(now);
  if (grace) b.graceAt = now; // spent only once the read is really made

  // Reserve the address slot BEFORE the await. A grace read reserves too: if
  // it finds nothing, the hash stays counted so its retry is a 401, not 429.
  const reserved = !b.hashes.has(hash);
  if (reserved) b.hashes.add(hash);

  let prefix;
  try {
    prefix = await issuedKeyPrefix(key);
  } catch (err) {
    // Our outage never counts against the ADDRESS. The instance read slot is
    // NOT given back: the call was made, and during a store outage that means
    // the (globalReadsPerMin + 1)th unknown lookup in a minute answers 429
    // (instance scope), not 502, until the minute turns. That is the right
    // way round: a failing store is the moment to stop asking it. Keys this
    // instance has seen valid are still served from memory meanwhile.
    if (reserved) b.hashes.delete(hash);
    throw err;
  }
  if (prefix === null) {
    cachePut(unknown, hash, now + CACHE_TTL_MS);
    return { prefix: null };
  }
  if (reserved) b.hashes.delete(hash);
  if (globalReads > 0) globalReads -= 1;
  cachePut(known, hash, { prefix, until: now + CACHE_TTL_MS, staleUntil: now + STALE_KEEP_MS });
  return { prefix };
}

// The one 429 body every caller sends. Worded for the holder of a GOOD key,
// who is the one person it can wrongly reach.
function missLimitedBody(looked) {
  if (looked.scope === "grace") {
    return {
      error:
        "too many unrecognized keys came from your network address in the last 10 minutes; " +
        "if your key is valid, retry in about a minute, or send from another address",
      reason: "unknown_key_rate_limited",
      retry_after_seconds: looked.retryAfterSeconds,
    };
  }
  if (looked.scope === "instance") {
    return {
      error:
        "this service is looking up more unrecognized keys than it allows right now; " +
        "if your key is valid, wait a minute and retry",
      reason: "unknown_key_lookups_exhausted",
      retry_after_seconds: looked.retryAfterSeconds,
    };
  }
  return {
    error:
      "too many unrecognized keys came from your network address in the last 10 minutes; " +
      "if your key is valid, wait and retry, or send from another address",
    reason: "unknown_key_rate_limited",
    retry_after_seconds: looked.retryAfterSeconds,
  };
}

function _resetMissLimiterForTests() {
  missBuckets.clear();
  known.clear();
  unknown.clear();
  globalMinute = -1;
  globalReads = 0;
  globalReadsPerMin = GLOBAL_READS_PER_MIN;
  missMaxBuckets = 10000;
}

function _setMissMaxBucketsForTests(n) {
  missMaxBuckets = n;
}

function _setGlobalReadsPerMinForTests(n) {
  globalReadsPerMin = n;
}

function _missStateForTests() {
  return { buckets: missBuckets.size, known: known.size, unknown: unknown.size, globalReads };
}

// ---- fulfillment binding (the session -> key idempotency record) ----
async function readFulfillment(sessionId) {
  return getFile(fulfillmentPath(sessionId));
}

// Create-only. Returns {created:true, record} if this call won the slot, or
// {created:false, record} with the WINNER's record if a concurrent visit (or a
// prior one) already bound this session — the caller must then serve the
// winner's key and throw its own freshly-minted one away (never minted twice
// for one session, even under a race: the create-only CAS is the guarantee).
async function createFulfillment(sessionId, record) {
  try {
    await putFile(
      fulfillmentPath(sessionId),
      record,
      `fulfill ${sessionId.slice(0, 24)} pack=${record.pack}`
    );
    return { created: true, record };
  } catch (err) {
    if (!err.conflict) throw err;
    const cur = await getFile(fulfillmentPath(sessionId));
    if (!cur) throw err; // conflict but nothing readable — surface the error
    return { created: false, record: cur.json };
  }
}

// Small CAS update loop for mutating an existing fulfillment record (consent
// capture). Best-effort semantics decided by the caller; this just does the
// read-modify-write honestly. Returns the updated record.
async function updateFulfillment(sessionId, mutate) {
  let lastErr = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    const cur = await getFile(fulfillmentPath(sessionId));
    if (!cur) return null;
    const next = mutate({ ...cur.json });
    try {
      await putFile(
        fulfillmentPath(sessionId),
        next,
        `fulfill update ${sessionId.slice(0, 24)}`,
        cur.sha
      );
      return next;
    } catch (err) {
      if (err.conflict && attempt === 0) {
        lastErr = err;
        continue;
      }
      throw err;
    }
  }
  throw lastErr || new Error("key store: exhausted CAS retries on fulfillment update");
}

// Create-only writes for the key + pool records. A conflict here means a
// concurrent request for the SAME session already wrote them (both derive from
// the same fulfillment record), so it is idempotent success, not an error.
async function writeIssuedKey(record) {
  try {
    await putFile(
      issuedKeyPath(record.key_hash),
      record,
      `issue key ${record.key_hash.slice(0, 12)} (${record.source})`
    );
  } catch (err) {
    if (!err.conflict) throw err;
  }
}

async function writePool(record) {
  try {
    await putFile(poolPath(record.pool_id), record, `pool ${record.pool_id}`);
  } catch (err) {
    if (!err.conflict) throw err;
  }
}

module.exports = {
  SESSION_ID_RE,
  PREFIX_RE,
  RESERVED_BRAND_STEMS,
  mintKey,
  mintNamespacePrefix,
  mintPoolId,
  validatePrefix,
  prefixConflicts,
  suggestPrefix,
  envKeyPrefixes,
  listPrefixes,
  keyHash,
  issuedKeyPath,
  poolPath,
  fulfillmentPath,
  issuedKeyPrefix,
  lookupIssuedPrefix,
  missLimitedBody,
  MAX_KEY_LEN,
  MISS_LIMIT,
  MISS_WINDOW_MS,
  GRACE_READ_MS,
  CACHE_TTL_MS,
  GLOBAL_READS_PER_MIN,
  STALE_KEEP_MS,
  _resetMissLimiterForTests,
  _setMissMaxBucketsForTests,
  _setGlobalReadsPerMinForTests,
  _missStateForTests,
  _clock: clock,
  readFulfillment,
  createFulfillment,
  updateFulfillment,
  writeIssuedKey,
  writePool,
  USAGE_REPO,
  USAGE_BRANCH,
  // exported for tests:
  getFile,
};
