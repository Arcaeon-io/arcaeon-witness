// lib/_move.js: POST /api/v1/move, the seller's half of moving a bought pin
// pack to the signing witness.
//
// The signing witness (origin arcaeon.io/witness/v1) sends this host one
// signed question, a move ask, the first time a pin arrives there with a pack
// key it does not hold. This host checks the ask, marks the key moved in its
// usage store, freezes the bought balance, and answers signed with its own
// Ed25519 answer key. vercel.json rewrites /api/v1/move to
// /api/credit?op=move, because api/ is at the host's limit of 12 functions.
//
// Both bodies are canonical JSON (canonicalBytes below): UTF-8, object keys
// sorted by code point at every depth, no white space, whole numbers only, no
// null. It gives the same bytes as Python's
//   json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
// for every value it accepts, and refuses the values that line would encode
// in some other way (floats, null, lone surrogates). A signature is Ed25519
// over the canonical bytes of the object without `sig`, as 128 lower case
// hex. A key_id is the lower case hex SHA-256 of a 32 byte public key.
//
// Settings:
//   ASKER (below, in code)      the signing witness's origin, public key and
//                               key_id. Public values, pinned here, never
//                               read from an ask.
//   WITNESS_MOVE_ANSWER_KEY     this host's answer key: the 32 byte Ed25519
//                               private seed as 64 lower case hex. Missing or
//                               malformed, every ask is answered 503 and
//                               nothing is marked.
//
// Every refusal is a status other than 200 with an unsigned JSON body
// {error, field}, and marks nothing.

"use strict";

const crypto = require("crypto");
const balance = require("./_balance.js");

// ---- the signing witness, pinned ----
// The two key values are published at
// https://arcaeon.io/.well-known/arcaeon-witness.json (fields key_id and
// public_key). Until both are written here, every ask is refused with 503
// and nothing is marked.
const ASKER = Object.freeze({
  origin: "arcaeon.io/witness/v1",
  public_key: "",
  key_id: "",
});

const ANSWER_KEY_ENV = "WITNESS_MOVE_ANSWER_KEY";
const MAX_SKEW_SECONDS = 300;
const MAX_ANSWER_BYTES = 16384;
const MAX_SALES = 20;
const ASK_FIELDS = ["asked_at", "key_hash", "key_id", "kind", "nonce", "sig", "to", "v"];
const TIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const CHECKOUT_RE = /^[A-Za-z0-9_-]{1,200}$/;
// Grants that are purchases: the two checkout paths. Admin grants
// (internal-admin) and pin refunds are not sales.
const SALE_SOURCES = new Set(["stripe-webhook", "stripe-fulfill", "stripe-fulfill-topup"]);

// ---- canonical JSON ----

function byCodePoint(a, b) {
  const A = Array.from(a);
  const B = Array.from(b);
  const n = Math.min(A.length, B.length);
  for (let i = 0; i < n; i++) {
    const x = A[i].codePointAt(0);
    const y = B[i].codePointAt(0);
    if (x !== y) return x - y;
  }
  return A.length - B.length;
}

function wellFormed(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function canonicalText(v) {
  if (v === null || v === undefined) throw new TypeError("canonical JSON: no field may be null");
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || Object.is(v, -0)) throw new TypeError("canonical JSON: whole numbers only");
    return String(v);
  }
  if (typeof v === "string") {
    if (!wellFormed(v)) throw new TypeError("canonical JSON: text holds a lone surrogate");
    // JSON.stringify escapes exactly what Python's encoder escapes with
    // ensure_ascii=False: the quote, the backslash, \b \f \n \r \t, and the
    // other characters below U+0020 as \u00xx in lower case hex.
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    const parts = [];
    for (let i = 0; i < v.length; i++) parts.push(canonicalText(v[i]));
    return `[${parts.join(",")}]`;
  }
  if (typeof v === "object") {
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) throw new TypeError("canonical JSON: plain objects only");
    const keys = Object.keys(v).sort(byCodePoint);
    return `{${keys.map((k) => `${canonicalText(k)}:${canonicalText(v[k])}`).join(",")}}`;
  }
  throw new TypeError(`canonical JSON: cannot encode a ${typeof v}`);
}

function canonicalBytes(v) {
  return Buffer.from(canonicalText(v), "utf8");
}

function withoutSig(obj) {
  const out = {};
  for (const k of Object.keys(obj)) if (k !== "sig") out[k] = obj[k];
  return out;
}

// ---- keys ----
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function privateKeyFromSeedHex(hex) {
  return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(hex, "hex")]), format: "der", type: "pkcs8" });
}
function publicKeyFromHex(hex) {
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(hex, "hex")]), format: "der", type: "spki" });
}
function rawPublicHex(privateKey) {
  return crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(SPKI_PREFIX.length).toString("hex");
}
function keyIdOf(publicHex) {
  return crypto.createHash("sha256").update(Buffer.from(publicHex, "hex")).digest("hex");
}

// A throwaway key pair, for tests and for an operator making the answer key.
// Nothing is written anywhere.
function generateKeyHex() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(PKCS8_PREFIX.length).toString("hex");
  const pub = rawPublicHex(privateKey);
  return { seed, public_key: pub, key_id: keyIdOf(pub) };
}

function signObject(obj, privateKey) {
  return crypto.sign(null, canonicalBytes(withoutSig(obj)), privateKey).toString("hex");
}

function verifyObject(obj, publicKey) {
  if (typeof obj.sig !== "string" || !HEX128.test(obj.sig)) return false;
  try {
    return crypto.verify(null, canonicalBytes(withoutSig(obj)), publicKey, Buffer.from(obj.sig, "hex"));
  } catch {
    return false;
  }
}

// The answer key from the environment, or a reason it cannot be used. The
// value is never logged or echoed.
function loadAnswerKey(env = process.env) {
  const raw = env[ANSWER_KEY_ENV];
  if (typeof raw !== "string" || raw === "") return { ok: false, reason: `${ANSWER_KEY_ENV} is not set` };
  if (!HEX64.test(raw)) return { ok: false, reason: `${ANSWER_KEY_ENV} is not 64 lower case hex` };
  try {
    const privateKey = privateKeyFromSeedHex(raw);
    const pub = rawPublicHex(privateKey);
    return { ok: true, privateKey, public_key: pub, key_id: keyIdOf(pub) };
  } catch {
    return { ok: false, reason: `${ANSWER_KEY_ENV} is not an Ed25519 seed` };
  }
}

// The pinned asker is usable only when its key_id is the SHA-256 of its key.
function askerReady(asker) {
  return !!asker && typeof asker.origin === "string" && asker.origin !== "" &&
    typeof asker.public_key === "string" && HEX64.test(asker.public_key) &&
    typeof asker.key_id === "string" && asker.key_id === keyIdOf(asker.public_key);
}

// ---- time ----
function formatTime(ms) {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}
function parseTime(s) {
  const m = typeof s === "string" ? TIME_RE.exec(s) : null;
  if (!m) return null;
  const ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  return formatTime(ms) === s ? ms : null; // refuses 2026-02-30 and the like
}

// ---- the ask ----
// checkAsk(body, asker, nowMs) -> { ok: true } | { ok: false, status, field, error }
function checkAsk(body, asker, nowMs) {
  const bad = (status, field, error) => ({ ok: false, status, field, error });
  if (!body || typeof body !== "object" || Array.isArray(body)) return bad(400, "body", "the ask is not a JSON object");
  const keys = Object.keys(body).sort();
  if (keys.length !== ASK_FIELDS.length || keys.some((k, i) => k !== ASK_FIELDS[i])) {
    return bad(400, "body", `the ask must hold exactly these fields: ${ASK_FIELDS.join(", ")}`);
  }
  if (body.kind !== "move_ask") return bad(400, "kind", "kind is not move_ask");
  if (body.v !== 1) return bad(400, "v", "v is not 1");
  if (typeof body.key_hash !== "string" || !HEX64.test(body.key_hash)) return bad(400, "key_hash", "key_hash is not 64 lower case hex");
  if (typeof body.nonce !== "string" || !HEX32.test(body.nonce)) return bad(400, "nonce", "nonce is not 32 lower case hex");
  if (typeof body.to !== "string" || typeof body.asked_at !== "string" || typeof body.key_id !== "string") {
    return bad(400, "body", "to, asked_at and key_id must be text");
  }
  if (body.key_id !== asker.key_id) return bad(401, "key_id", "the asking key is not the one this host trusts");
  if (!verifyObject(body, publicKeyFromHex(asker.public_key))) return bad(401, "sig", "the signature does not verify");
  if (body.to !== asker.origin) return bad(403, "to", "to is not the origin this host expects");
  const t = parseTime(body.asked_at);
  if (t === null) return bad(400, "asked_at", "asked_at is not YYYY-MM-DDTHH:MM:SSZ");
  if (Math.abs(nowMs - t) > MAX_SKEW_SECONDS * 1000) return bad(401, "asked_at", "asked_at is more than 300 seconds from this host's clock");
  return { ok: true };
}

// ---- the answer ----
function answerObject({ status, keyHash, to, nonce, mark, sellerKeyId }) {
  const obj = { key_hash: keyHash, key_id: sellerKeyId, kind: "move_answer", nonce, status, to, v: 1 };
  if (status === "moved") {
    obj.credits = mark.credits;
    obj.moved_at = mark.moved_at;
    obj.sales = mark.sales.map((s) => ({ checkout: s.checkout, credits: s.credits, pack: s.pack }));
  }
  return obj;
}

function signedAnswer(fields, answerKey) {
  const obj = answerObject({ ...fields, sellerKeyId: answerKey.key_id });
  obj.sig = signObject(obj, answerKey.privateKey);
  return canonicalBytes(obj);
}

// A stored mark is answered only when it is still a well formed one.
function markIsAnswerable(mark) {
  if (!mark || !Number.isSafeInteger(mark.credits) || mark.credits < 0) return false;
  if (parseTime(mark.moved_at) === null) return false;
  if (!Array.isArray(mark.sales) || mark.sales.length < 1 || mark.sales.length > MAX_SALES) return false;
  let sum = 0;
  for (const s of mark.sales) {
    if (!s || typeof s.checkout !== "string" || !CHECKOUT_RE.test(s.checkout)) return false;
    if (typeof s.pack !== "string" || !Number.isSafeInteger(s.credits) || s.credits < 1) return false;
    sum += s.credits;
  }
  return mark.credits <= sum;
}

// ---- deciding the mark ----
// The sales are read from the balance file's applied_events (the checkout
// ids every grant records, oldest first) and each grant's ledger record. A
// grant whose record is missing cannot be told apart from a sale, so the
// ask is refused rather than answered with a list that may be short.
function decider(hash, to, nowMs, askerKeyId, answerKey) {
  return async (json, bal) => {
    const refuse = (reason, detail) => ({ refuse: { reason, detail } });
    const events = Array.isArray(json.applied_events) ? json.applied_events.filter((e) => typeof e === "string") : [];
    const candidates = events.filter((e) => !e.startsWith("refund-"));
    const records = await Promise.all(candidates.map((e) => balance.getFile(balance.ledgerGrantPath(hash, e))));
    const sales = [];
    const seen = new Set();
    for (let i = 0; i < candidates.length; i++) {
      const rec = records[i] && records[i].json;
      if (!rec || typeof rec !== "object") {
        return refuse("sale_record_missing", "a grant on this key has no readable ledger record");
      }
      if (!SALE_SOURCES.has(rec.source)) continue;
      const checkout = String(rec.event_id || candidates[i]);
      if (seen.has(checkout)) continue;
      seen.add(checkout);
      sales.push({ checkout, credits: Number(rec.pins), pack: String(rec.pack) });
    }
    if (sales.length === 0) return { not_sold: true };
    for (const s of sales) {
      const on = Object.prototype.hasOwnProperty.call(balance.PACKS, s.pack) ? balance.PACKS[s.pack] : null;
      if (!CHECKOUT_RE.test(s.checkout) || !on || on.pins !== s.credits) {
        return refuse("sale_not_movable", "a purchase on this key is not a pack size on sale today");
      }
    }
    if (sales.length > MAX_SALES) return refuse("too_many_sales", `more than ${MAX_SALES} purchases on this key`);
    // Whole pins only. A stamp costs a fraction of a pin, so a balance can
    // hold a part of one; that part is not moved (it stays in balance_at_mark).
    const credits = Math.floor(bal);
    if (!Number.isSafeInteger(credits) || credits < 0) return refuse("balance_unreadable", "the balance is not a number from 0");
    const sum = sales.reduce((a, s) => a + s.credits, 0);
    if (credits > sum) return refuse("credits_exceed_sales", "the balance is more than the purchases on this key");
    const mark = { to, moved_at: formatTime(nowMs), credits, sales, balance_at_mark: bal, asked_by: askerKeyId };
    // The answer must fit before anything is marked.
    const probe = signedAnswer({ status: "moved", keyHash: hash, to, nonce: "0".repeat(32), mark }, answerKey);
    if (probe.length > MAX_ANSWER_BYTES) return refuse("answer_too_large", "the answer would be over 16384 bytes");
    return { mark };
  };
}

function refuseJson(res, status, field, error) {
  res.setHeader("cache-control", "no-store");
  return res.status(status).json({ error, field });
}

function readBody(req) {
  const b = req.body;
  if (b && typeof b === "object" && !Buffer.isBuffer(b)) return b;
  const text = Buffer.isBuffer(b) ? b.toString("utf8") : typeof b === "string" ? b : null;
  if (text === null) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// ---- the route ----
// opts.asker and opts.now exist for tests; the route itself passes neither.
async function handle(req, res, opts = {}) {
  const asker = opts.asker || ASKER;
  const env = opts.env || process.env;
  const nowMs = opts.now ? opts.now() : Date.now();
  if (req.method !== "POST") {
    res.setHeader("allow", "POST");
    return refuseJson(res, 405, "method", "POST only");
  }
  const answerKey = loadAnswerKey(env);
  if (!answerKey.ok) {
    console.error(`[move] ask refused, answer key unusable: ${answerKey.reason}`);
    return refuseJson(res, 503, "answer_key", "this host has no answer key set");
  }
  if (!askerReady(asker)) {
    console.error("[move] ask refused, the signing witness's public key is not pinned in lib/_move.js");
    return refuseJson(res, 503, "key_id", "this host has no signing witness key pinned");
  }
  const body = readBody(req);
  const v = checkAsk(body, asker, nowMs);
  if (!v.ok) return refuseJson(res, v.status, v.field, v.error);

  const hash = body.key_hash;
  let r;
  try {
    r = await balance.markMoved(hash, body.to, decider(hash, body.to, nowMs, asker.key_id, answerKey));
  } catch (err) {
    console.error(`[move] store error for ${hash.slice(0, 12)}: ${err.message}`);
    return refuseJson(res, 502, "store", "the usage store could not be read or written; nothing was marked");
  }
  if (r.status === "refused") {
    console.error(`[move] ask refused for ${hash.slice(0, 12)}, nothing marked: ${r.reason}: ${r.detail}`);
    return refuseJson(res, 409, "key_hash", `this key cannot be moved automatically (${r.reason}); nothing was marked`);
  }
  if (r.status === "moved" && !markIsAnswerable(r.mark)) {
    console.error(`[move] the move mark on ${hash.slice(0, 12)} is not well formed; not answered`);
    return refuseJson(res, 503, "key_hash", "the move mark on this key cannot be read");
  }
  const bytes = signedAnswer({ status: r.status, keyHash: hash, to: body.to, nonce: body.nonce, mark: r.mark }, answerKey);
  if (r.status === "moved") {
    console.error(`[move] ${r.first ? "marked" : "answered again"} ${hash.slice(0, 12)} to=${body.to} credits=${r.mark.credits}`);
  }
  res.setHeader("cache-control", "no-store");
  res.setHeader("content-type", "application/json");
  return res.status(200).send(bytes);
}

module.exports = {
  ASKER,
  ANSWER_KEY_ENV,
  MAX_SKEW_SECONDS,
  MAX_ANSWER_BYTES,
  MAX_SALES,
  SALE_SOURCES,
  canonicalText,
  canonicalBytes,
  signObject,
  verifyObject,
  keyIdOf,
  generateKeyHex,
  privateKeyFromSeedHex,
  publicKeyFromHex,
  loadAnswerKey,
  askerReady,
  checkAsk,
  formatTime,
  parseTime,
  handle,
};
