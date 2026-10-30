// _account_api.js — the Arcaeon account, phase 1: agent sign-up by keypair
// challenge-response, and the device registry. Underscore prefix = not
// routed as a serverless function.
//
// Public paths (vercel.json rewrites):
//   POST /api/account/challenge -> /api/balance?op=account-challenge
//   POST /api/account/verify    -> /api/balance?op=account-verify
//   GET|POST /api/account/devices -> /api/balance?op=account-devices
//   GET /api/account/pins       -> /api/balance?op=account-pins   (phase 2)
//   POST /api/account/checkout  -> /api/balance?op=account-checkout (phase 3)
// They ride api/balance.js because api/ is at the Vercel Hobby 12-function
// cap (same reason /api/stamp rides api/verify.js and /api/prefix-available
// rides api/fulfill.js). balance.js dispatches on ?op= before anything else.
//
// The flow (docs/ACCOUNT_V1.md has it in plain words):
//   1. challenge {public_key}: base64url of a raw 32-byte Ed25519 public key.
//      Returns {nonce, expires_at, pow:{difficulty, alg}}. Nonce lives 5 min.
//   2. verify {public_key, nonce, signature, pow_solution}:
//      signature = Ed25519 over the bytes of "arcaeon-account-v1\n" + nonce,
//      pow: sha256(nonce + pow_solution) has `difficulty` leading zero bits.
//      The challenge is taken single use; then agent (+ account if none) is
//      created and an API key is returned ONCE.
//   3. devices: bearer API key. GET lists, POST {name, public_key} registers.
//
// Order inside verify, on purpose: the signature is checked BEFORE the
// challenge is taken, so someone who only saw a nonce cannot burn it. Every
// verify that passes the signature check consumes the nonce, whatever happens
// after (expired, short proof of work): one challenge, one attempt.

"use strict";

const crypto = require("crypto");
const ratelimit = require("./_ratelimit.js");
const accountdb = require("./_accountdb.js");
const checkoutImpl = require("./_account_checkout.js");

const DOMAIN = "arcaeon-account-v1\n";
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_POW_BITS = 20;
const POW_ALG = "sha256(nonce+solution), leading zero bits";
const MAX_DEVICES = 50;
const B64URL = /^[A-Za-z0-9_-]+$/;
// Raw Ed25519 public key as an SPKI DER: this fixed 12-byte header + 32 bytes.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// ACCOUNT_POW_BITS: an integer 1..32. Anything else (unset, 0, junk) is the
// default 20: proof of work can be made cheaper by config, never switched off.
function powBits(env = process.env) {
  const raw = env.ACCOUNT_POW_BITS;
  if (raw === undefined || raw === "") return DEFAULT_POW_BITS;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 && n <= 32 ? n : DEFAULT_POW_BITS;
}

// Strict, canonical base64url of exactly `len` bytes. Canonical (re-encodes
// to the same string) so one key has exactly one spelling, one agent id.
function decodeB64url(s, len) {
  if (typeof s !== "string" || !B64URL.test(s)) return null;
  const buf = Buffer.from(s, "base64url");
  if (buf.length !== len || buf.toString("base64url") !== s) return null;
  return buf;
}

function publicKeyObject(raw32) {
  try {
    return crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw32]),
      format: "der",
      type: "spki",
    });
  } catch (_e) {
    return null;
  }
}

function signedMessage(nonce) {
  return Buffer.from(DOMAIN + nonce, "utf8");
}

function leadingZeroBits(buf) {
  let n = 0;
  for (const byte of buf) {
    if (byte === 0) { n += 8; continue; }
    return n + Math.clz32(byte) - 24;
  }
  return n;
}

function powOk(nonce, solution, bits) {
  const h = crypto.createHash("sha256").update(nonce + solution, "utf8").digest();
  return leadingZeroBits(h) >= bits;
}

// For clients and tests: find a solution by counting up.
function solvePow(nonce, bits) {
  for (let i = 0; ; i++) {
    const s = i.toString(36);
    if (powOk(nonce, s, bits)) return s;
  }
}

function readBody(req) {
  const b = req.body;
  if (b && typeof b === "object" && !Buffer.isBuffer(b)) return b;
  if (typeof b === "string" || Buffer.isBuffer(b)) {
    try {
      const j = JSON.parse(String(b));
      return j && typeof j === "object" ? j : null;
    } catch (_e) {
      return null;
    }
  }
  return null;
}

function refuse(res, status, reason, error, extra) {
  res.setHeader("cache-control", "no-store");
  return res.status(status).json({ ok: false, reason, error, ...(extra || {}) });
}

function bearer(req) {
  const auth = String((req.headers && req.headers.authorization) || "");
  return auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
}

// createAccountApi({getStore, now, env, fetchImpl}) -> {challenge, verify, devices, pins, checkout}
// getStore() returns a store or null; now() returns epoch ms; fetchImpl is
// what talks to Stripe (checkout only). Tests inject all of them; production
// uses the env-backed store, the real clock and fetch.
function createAccountApi({ getStore = () => accountdb.fromEnv(), now = () => Date.now(), env = process.env,
  fetchImpl = (u, o) => fetch(u, o) } = {}) {
  function storeOr503(res) {
    const store = getStore();
    if (!store) {
      refuse(res, 503, "account_store_not_configured",
        "the account store is not configured on this deployment (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY unset)");
      return null;
    }
    return store;
  }

  function storeFailed(res, err) {
    // err.message names the step and HTTP status only; never a key.
    return refuse(res, 502, "account_store_error", err && err.storeError ? err.message : "account store failed");
  }

  async function challenge(req, res) {
    if (req.method !== "POST") {
      res.setHeader("allow", "POST");
      return refuse(res, 405, "method_not_allowed", "POST only");
    }
    const rl = ratelimit.check(req);
    if (rl.limited) {
      res.setHeader("retry-after", String(rl.retryAfterSeconds));
      return refuse(res, 429, "rate_limited", "rate limit exceeded", {
        note: `naive per-instance, per-IP limiter (Stage-0): ~${rl.limit} calls per IP per ${Math.round(rl.windowSeconds / 60)} minutes`,
        retry_after_seconds: rl.retryAfterSeconds,
      });
    }
    const body = readBody(req);
    if (!body) return refuse(res, 400, "bad_body", "body must be a JSON object");
    const raw = decodeB64url(body.public_key, 32);
    if (!raw || !publicKeyObject(raw)) {
      return refuse(res, 400, "bad_public_key", "public_key must be base64url (no padding) of a raw 32-byte Ed25519 public key");
    }
    const store = storeOr503(res);
    if (!store) return;
    const nonce = crypto.randomBytes(32).toString("base64url");
    const difficulty = powBits(env);
    const expires_at = new Date(now() + CHALLENGE_TTL_MS).toISOString();
    try {
      await store.createChallenge({ nonce, public_key: body.public_key, pow_bits: difficulty, expires_at });
    } catch (err) {
      return storeFailed(res, err);
    }
    res.setHeader("cache-control", "no-store");
    return res.status(201).json({
      nonce,
      expires_at,
      pow: { difficulty, alg: POW_ALG },
      sign: { alg: "Ed25519", message: "the UTF-8 bytes of \"arcaeon-account-v1\\n\" followed by the nonce" },
    });
  }

  async function verify(req, res) {
    if (req.method !== "POST") {
      res.setHeader("allow", "POST");
      return refuse(res, 405, "method_not_allowed", "POST only");
    }
    const body = readBody(req);
    if (!body) return refuse(res, 400, "bad_body", "body must be a JSON object");
    const { public_key, nonce, signature, pow_solution } = body;
    const raw = decodeB64url(public_key, 32);
    const keyObj = raw && publicKeyObject(raw);
    if (!keyObj) {
      return refuse(res, 400, "bad_public_key", "public_key must be base64url (no padding) of a raw 32-byte Ed25519 public key");
    }
    if (!decodeB64url(nonce, 32)) return refuse(res, 400, "bad_nonce", "nonce must be the 43-character value /challenge returned");
    const sig = decodeB64url(signature, 64);
    if (!sig) return refuse(res, 400, "bad_signature_encoding", "signature must be base64url (no padding) of a 64-byte Ed25519 signature");
    if (typeof pow_solution !== "string" || pow_solution.length < 1 || pow_solution.length > 64) {
      return refuse(res, 400, "bad_pow_solution", "pow_solution must be a string of 1 to 64 characters");
    }

    let sigOk = false;
    try {
      sigOk = crypto.verify(null, signedMessage(nonce), keyObj, sig);
    } catch (_e) {
      sigOk = false;
    }
    if (!sigOk) {
      return refuse(res, 401, "signature_invalid",
        "the signature does not verify over \"arcaeon-account-v1\\n\" + nonce with this public key");
    }

    const store = storeOr503(res);
    if (!store) return;

    let taken;
    try {
      taken = await store.takeChallenge(nonce, public_key, now());
    } catch (err) {
      return storeFailed(res, err);
    }
    if (!taken.ok && taken.reason === "expired") {
      return refuse(res, 410, "challenge_expired", "this nonce expired; ask /api/account/challenge for a new one");
    }
    if (!taken.ok) {
      return refuse(res, 409, "challenge_not_found_or_used",
        "no open challenge for this nonce and public key: never issued, issued to another key, or already used");
    }
    if (!powOk(nonce, pow_solution, taken.challenge.pow_bits)) {
      return refuse(res, 400, "pow_insufficient",
        `sha256(nonce + pow_solution) needs ${taken.challenge.pow_bits} leading zero bits; this challenge is now used, ask for a new one`);
    }

    let agent, key;
    try {
      agent = await store.createAgentWithAccount(public_key);
      key = await store.issueApiKey({ account_id: agent.account_id, agent_public_key: public_key });
    } catch (err) {
      return storeFailed(res, err);
    }
    res.setHeader("cache-control", "no-store");
    return res.status(agent.created ? 201 : 200).json({
      ok: true,
      account_id: agent.account_id,
      agent_id: agent.agent_id,
      created: agent.created,
      api_key: key.api_key,
      api_key_note: "shown once; only its sha256 is stored, so it cannot be shown again",
    });
  }

  async function devices(req, res) {
    if (req.method !== "GET" && req.method !== "POST") {
      res.setHeader("allow", "GET, POST");
      return refuse(res, 405, "method_not_allowed", "GET or POST only");
    }
    const raw = bearer(req);
    if (!raw) return refuse(res, 401, "missing_api_key", "Authorization: Bearer <account api key> required");
    const store = storeOr503(res);
    if (!store) return;
    let who;
    try {
      who = await store.resolveApiKey(raw);
    } catch (err) {
      return storeFailed(res, err);
    }
    if (!who) return refuse(res, 401, "unknown_api_key", "this api key is not recognized or was revoked");

    if (req.method === "GET") {
      try {
        const list = await store.listDevices(who.account_id);
        res.setHeader("cache-control", "no-store");
        return res.status(200).json({ ok: true, account_id: who.account_id, devices: list });
      } catch (err) {
        return storeFailed(res, err);
      }
    }

    const body = readBody(req);
    if (!body) return refuse(res, 400, "bad_body", "body must be a JSON object");
    const name = typeof body.name === "string" ? body.name.trim() : "";
    // Printable, no control characters, 1..64 characters.
    if (!name || [...name].length > 64 || /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(name)) {
      return refuse(res, 400, "bad_name", "name must be 1 to 64 printable characters");
    }
    const dk = decodeB64url(body.public_key, 32);
    if (!dk || !publicKeyObject(dk)) {
      return refuse(res, 400, "bad_public_key", "public_key must be base64url (no padding) of a raw 32-byte Ed25519 public key");
    }
    let r;
    try {
      r = await store.registerDevice({ account_id: who.account_id, name, public_key: body.public_key, max: MAX_DEVICES });
    } catch (err) {
      return storeFailed(res, err);
    }
    if (!r.ok && r.reason === "device_exists") return refuse(res, 409, "device_exists", "this public key is already registered on this account");
    if (!r.ok && r.reason === "device_limit") return refuse(res, 409, "device_limit", `an account holds at most ${MAX_DEVICES} devices`);
    if (!r.ok) return refuse(res, 401, r.reason, "the account behind this api key was not found");
    res.setHeader("cache-control", "no-store");
    return res.status(201).json({ ok: true, device: r.device });
  }

  // Phase 2: the account's own pin allowance, read only. Bearer API key.
  // Rolls the monthly window first if it has passed (so a read after the
  // anniversary shows the fresh 3,000), and nothing else.
  async function pins(req, res) {
    if (req.method !== "GET") {
      res.setHeader("allow", "GET");
      return refuse(res, 405, "method_not_allowed", "GET only");
    }
    const raw = bearer(req);
    if (!raw) return refuse(res, 401, "missing_api_key", "Authorization: Bearer <account api key> required");
    const store = storeOr503(res);
    if (!store) return;
    let who, view;
    try {
      who = await store.resolveApiKey(raw);
      if (!who) return refuse(res, 401, "unknown_api_key", "this api key is not recognized or was revoked");
      view = await store.pinStatus({ account_id: who.account_id, now: now() });
    } catch (err) {
      return storeFailed(res, err);
    }
    if (!view) return refuse(res, 401, "unknown_account", "the account behind this api key was not found");
    res.setHeader("cache-control", "no-store");
    return res.status(200).json({ ok: true, account_id: who.account_id, ...view });
  }

  // Phase 3: the server makes the Stripe Checkout Session for the bearer's
  // account, on the account's own Stripe customer (lib/_account_checkout.js).
  // Bearer API key; body {plan: monthly|yearly} or {pack: pins_200|pins_1000}.
  // Shares the per-IP limiter: every call makes a Stripe object.
  async function checkout(req, res) {
    if (req.method !== "POST") {
      res.setHeader("allow", "POST");
      return refuse(res, 405, "method_not_allowed", "POST only");
    }
    const raw = bearer(req);
    if (!raw) return refuse(res, 401, "missing_api_key", "Authorization: Bearer <account api key> required");
    const rl = ratelimit.check(req);
    if (rl.limited) {
      res.setHeader("retry-after", String(rl.retryAfterSeconds));
      return refuse(res, 429, "rate_limited", "rate limit exceeded", { retry_after_seconds: rl.retryAfterSeconds });
    }
    const store = storeOr503(res);
    if (!store) return;
    let who;
    try {
      who = await store.resolveApiKey(raw);
    } catch (err) {
      return storeFailed(res, err);
    }
    if (!who) return refuse(res, 401, "unknown_api_key", "this api key is not recognized or was revoked");
    let r;
    try {
      r = await checkoutImpl.createCheckout({ store, account_id: who.account_id, body: readBody(req), now: now(), env, fetchImpl });
    } catch (err) {
      if (err && err.storeError) return storeFailed(res, err);
      // err.message names the Stripe step and status; never the key or Stripe's text.
      return refuse(res, 502, "stripe_error", err && err.stripeError ? err.message : "stripe call failed");
    }
    if (!r.ok) return refuse(res, r.status, r.reason, r.error);
    res.setHeader("cache-control", "no-store");
    const { status: _s, ...body } = r;
    return res.status(201).json({ ...body, account_id: who.account_id,
      note: "pay at url within 2 hours; whoever pays it pays for this account on its own Stripe customer" });
  }

  return { challenge, verify, devices, pins, checkout };
}

const OPS = {
  "account-challenge": "challenge", "account-verify": "verify", "account-devices": "devices",
  "account-pins": "pins", "account-checkout": "checkout",
};
const defaultApi = createAccountApi();

// Used by api/balance.js: returns true if ?op= named an account route (and it
// was handled), false otherwise.
async function dispatch(req, res, api = defaultApi) {
  const op = String((req.query || {}).op || "");
  const fn = OPS[op];
  if (!fn) return false;
  await api[fn](req, res);
  return true;
}

module.exports = {
  createAccountApi,
  dispatch,
  powBits,
  powOk,
  solvePow,
  leadingZeroBits,
  decodeB64url,
  signedMessage,
  DOMAIN,
  CHALLENGE_TTL_MS,
  DEFAULT_POW_BITS,
  MAX_DEVICES,
};
