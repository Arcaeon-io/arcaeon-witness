// lib/_contract.js: the traveling objects of the contract (docs/CONTRACT.md
// version 2, in the sandbox repositories), as the join reads and writes
// them: canonical bytes, the Ed25519 signature, the pin reader, the
// receipt, the stored row and the signed rows answer.
//
// It is held byte for byte to test/vectors/contract_vectors.json (copied
// from the seal repository) and to test/vectors/join_reference.json (made by
// the reference witness). Every reader fails closed and names the first
// field it cannot read. Nothing here reads a setting or the clock.
"use strict";

const crypto = require("crypto");

const MAX_INT = Number.MAX_SAFE_INTEGER; // 2^53 minus 1
const MAX_OBJECT_BYTES = 4096;
const ZERO_HEAD_CHAIN = "0".repeat(64);
const ZERO_ROW_CHAIN = "0".repeat(32);

const HEAD_FIELDS = ["chain", "kind", "n", "v"];
const PIN_FIELDS = ["head", "issued_at", "key_id", "kind", "namespace", "sig", "v"];
const PIN_OPTIONAL = ["root", "root_n"];
const STATEMENT_FIELDS = ["key_id", "kind", "public_key", "sig", "started_at", "v"];

const NAMESPACE_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const HEX128_RE = /^[0-9a-f]{128}$/;
const TIME_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;

// Fixed DER wrappings of a raw Ed25519 key, so the runtime's own crypto
// module can load one. No package is needed.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

class ContractError extends Error {
  constructor(field, reason) {
    super(`${field}: ${reason}`);
    this.field = field;
    this.reason = reason;
  }
}

// ---- canonical bytes ----

function compareUtf16(a, b) {
  // JavaScript strings are UTF-16, and < compares code units.
  return a < b ? -1 : a > b ? 1 : 0;
}

function writeString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const code = s.charCodeAt(i);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (code < 0x20) {
      if (ch === "\b") out += "\\b";
      else if (ch === "\f") out += "\\f";
      else if (ch === "\n") out += "\\n";
      else if (ch === "\r") out += "\\r";
      else if (ch === "\t") out += "\\t";
      else out += "\\u" + code.toString(16).padStart(4, "0");
    } else out += ch;
  }
  return out + '"';
}

function writeValue(value, field) {
  if (value === null || value === undefined) {
    throw new ContractError(field || "value", "is null, which is never written; an absent value is an absent field");
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    if (!value.isWellFormed()) throw new ContractError(field || "value", "holds a lone surrogate");
    return writeString(value);
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new ContractError(field || "value", "is a number with a fraction or exponent; only integers are written");
    }
    if (value > MAX_INT || value < -MAX_INT) {
      throw new ContractError(field || "value", "is an integer outside plus or minus 2^53 minus 1");
    }
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v, i) => writeValue(v, field ? `${field}.${i}` : String(i))).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort(compareUtf16);
    return "{" + keys.map((k) => writeString(k) + ":" + writeValue(value[k], field ? `${field}.${k}` : k)).join(",") + "}";
  }
  throw new ContractError(field || "value", `is a value of type ${typeof value}, which has no JSON form`);
}

function canonical(value) {
  return Buffer.from(writeValue(value, ""), "utf8");
}

// ---- strict parsing ----

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// Strict JSON from bytes: at most MAX_OBJECT_BYTES, UTF-8 with no byte
// order mark, valid JSON. A duplicated key, a number with a fraction, or
// any other form the canonical writer would not give, is caught by the
// byte for byte check every caller makes after reading the shape.
function parse(raw, what = "object") {
  if (!Buffer.isBuffer(raw)) throw new ContractError(what, "must be bytes");
  if (raw.length > MAX_OBJECT_BYTES) throw new ContractError(what, `is larger than ${MAX_OBJECT_BYTES} bytes`);
  if (raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) {
    throw new ContractError(what, "starts with a byte order mark");
  }
  let text;
  try {
    text = UTF8.decode(raw);
  } catch {
    throw new ContractError(what, "is not valid UTF-8");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new ContractError(what, "is not valid JSON");
  }
}

// ---- readers ----

function typeName(x) {
  if (x === null) return "null";
  if (Array.isArray(x)) return "an array";
  if (typeof x === "number") return Number.isInteger(x) ? "an integer" : "a number with a fraction or exponent";
  if (typeof x === "object") return "an object";
  return `a ${typeof x}`;
}

function isObject(x) {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}

function readObject(obj, name, kind, fields, optional = [], prefix = "") {
  if (!isObject(obj)) throw new ContractError(name, `must be a JSON object, got ${typeName(obj)}`);
  if (!("kind" in obj)) throw new ContractError(prefix + "kind", "the field is missing; every traveling object names its kind");
  if (obj.kind !== kind) throw new ContractError(prefix + "kind", `must be ${kind}`);
  if (!("v" in obj)) throw new ContractError(prefix + "v", "the field is missing");
  if (obj.v !== 1) throw new ContractError(prefix + "v", "must be the integer 1");
  const allowed = new Set([...fields, ...optional]);
  for (const k of Object.keys(obj).sort(compareUtf16)) {
    if (!allowed.has(k)) {
      throw new ContractError(prefix + k, `is not a field of a version 1 ${kind}; an unknown field is refused`);
    }
  }
  for (const k of fields) {
    if (!(k in obj)) throw new ContractError(prefix + k, "the field is missing");
  }
}

function readInt(x, field, low) {
  if (!Number.isInteger(x)) throw new ContractError(field, `must be an integer, got ${typeName(x)}`);
  if (x < low || x > MAX_INT) throw new ContractError(field, `must be an integer from ${low} to ${MAX_INT}`);
}

function readHex64(x, field) {
  if (typeof x !== "string" || !HEX64_RE.test(x)) {
    throw new ContractError(field, "must be exactly 64 lower case hex characters");
  }
}

function isNamespace(x) {
  return typeof x === "string" && NAMESPACE_RE.test(x);
}

function readNamespace(x) {
  if (!isNamespace(x)) {
    throw new ContractError("namespace",
      "must be 1 to 64 characters from a to z, 0 to 9, dot, underscore and hyphen, starting with a letter or digit");
  }
}

function isTime(text) {
  if (typeof text !== "string" || !TIME_RE.test(text)) return false;
  const y = +text.slice(0, 4), mo = +text.slice(5, 7), d = +text.slice(8, 10);
  const h = +text.slice(11, 13), mi = +text.slice(14, 16), s = +text.slice(17, 19);
  if (y < 1 || mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || s > 59) return false;
  const days = new Date(Date.UTC(2000, mo, 0)).getUTCDate(); // days in that month, leap year neutral
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const max = mo === 2 ? (leap ? 29 : 28) : days;
  return d <= max;
}

function readTime(x, field) {
  if (!isTime(x)) {
    throw new ContractError(field, 'must be exactly YYYY-MM-DDTHH:MM:SSZ in UTC, a real calendar date and time');
  }
}

function readSig(x) {
  if (typeof x !== "string" || !HEX128_RE.test(x)) {
    throw new ContractError("sig", "must be exactly 128 lower case hex characters, a 64 byte signature");
  }
}

function readHead(obj, where = "head") {
  const p = where ? `${where}.` : "";
  readObject(obj, where || "head", "head", HEAD_FIELDS, [], p);
  readHex64(obj.chain, p + "chain");
  readInt(obj.n, p + "n", 0);
  if (obj.n === 0 && obj.chain !== ZERO_HEAD_CHAIN) {
    throw new ContractError(p + "chain", "must be 64 zeros for the empty ledger, n 0");
  }
  return obj;
}

// A pin's shape, without its signature, in the reference witness's order:
// kind, v, unknown fields, missing fields, then each value in canonical key
// order (head, issued_at, key_id, namespace, root, root_n, sig).
function readPin(obj) {
  readObject(obj, "pin", "pin", PIN_FIELDS, PIN_OPTIONAL);
  readHead(obj.head, "head");
  readTime(obj.issued_at, "issued_at");
  readHex64(obj.key_id, "key_id");
  readNamespace(obj.namespace);
  if ("root" in obj || "root_n" in obj) {
    if (!("root" in obj)) throw new ContractError("root", "the field is missing; root and root_n travel together");
    readHex64(obj.root, "root");
    if (!("root_n" in obj)) throw new ContractError("root_n", "the field is missing; root and root_n travel together");
    readInt(obj.root_n, "root_n", 0);
    if (obj.root_n !== obj.head.n) throw new ContractError("root_n", `must equal the head's n, ${obj.head.n}`);
  }
  readSig(obj.sig);
  return obj;
}

// A witness_statement, signature included: it carries its own key.
function readStatement(obj) {
  readObject(obj, "witness_statement", "witness_statement", STATEMENT_FIELDS);
  readHex64(obj.key_id, "key_id");
  readHex64(obj.public_key, "public_key");
  const pub = Buffer.from(obj.public_key, "hex");
  if (keyId(pub) !== obj.key_id) throw new ContractError("key_id", "is not the SHA-256 of public_key");
  readSig(obj.sig);
  readTime(obj.started_at, "started_at");
  if (!verify(obj, pub)) throw new ContractError("sig", "does not verify under public_key");
  return obj;
}

// ---- keys and signatures ----

function privateFromSeed(seedHex) {
  if (typeof seedHex !== "string" || !HEX64_RE.test(seedHex)) {
    throw new ContractError("key", "a seed is exactly 64 lower case hex characters");
  }
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedHex, "hex")]),
    format: "der",
    type: "pkcs8",
  });
}

function publicRaw(privateKey) {
  const der = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(der.length - 32));
}

function publicFromRaw(raw) {
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

function keyId(raw) {
  if (!Buffer.isBuffer(raw) || raw.length !== 32) throw new ContractError("public_key", "a public key is exactly 32 bytes");
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function withoutSig(obj) {
  const out = {};
  for (const k of Object.keys(obj)) if (k !== "sig") out[k] = obj[k];
  return out;
}

function signingBytes(obj) {
  return canonical(withoutSig(obj));
}

// A copy of obj with key_id and sig set by privateKey.
function sign(privateKey, obj) {
  const out = withoutSig(obj);
  out.key_id = keyId(publicRaw(privateKey));
  out.sig = crypto.sign(null, signingBytes(out), privateKey).toString("hex");
  return out;
}

// True only when key_id names raw and sig verifies under it.
function verify(obj, raw) {
  try {
    if (!isObject(obj) || obj.key_id !== keyId(raw)) return false;
    if (typeof obj.sig !== "string" || !HEX128_RE.test(obj.sig)) return false;
    return crypto.verify(null, signingBytes(obj), publicFromRaw(raw), Buffer.from(obj.sig, "hex"));
  } catch {
    return false;
  }
}

function formatTime(date) {
  return date.toISOString().slice(0, 19) + "Z";
}

// ---- rows, receipts and the rows answer, as the reference witness makes them ----

function rowChain(row) {
  const body = {};
  for (const k of Object.keys(row)) if (k !== "chain") body[k] = row[k];
  return crypto.createHash("sha256")
    .update(Buffer.concat([Buffer.from(String(row.prev), "ascii"), canonical(body)]))
    .digest("hex")
    .slice(0, 32);
}

function makeRow(seq, receivedAt, pin, prev, publicKey) {
  const row = { seq, received_at: receivedAt, pin, prev, public_key: publicKey };
  row.chain = rowChain(row);
  return row;
}

// The contract receipt of a stored row. The signature scheme is
// deterministic, so the same row always gives the same receipt bytes.
function makeReceipt(privateKey, row) {
  return sign(privateKey, {
    head: row.pin.head,
    kind: "receipt",
    namespace: row.pin.namespace,
    received_at: row.received_at,
    v: 1,
    witness_seq: row.seq,
  });
}

function rowDigest(row) {
  return crypto.createHash("sha256").update(canonical(row)).digest("hex");
}

// The signed rows answer for rows given newest first.
function makeAnswer(privateKey, namespace, rows, servedAt) {
  const envelope = sign(privateKey, {
    chain: rows[0].chain, kind: "witness_rows", namespace, rows: rows.length, served_at: servedAt, v: 1,
  });
  const sigs = rows.map((row) => sign(privateKey, {
    kind: "witness_row", namespace, row_digest: rowDigest(row), seq: row.seq, v: 1,
  }));
  return { envelope, rows, sigs };
}

// Whether a new pin names the same point as a held one: the same head,
// key_id, namespace, root and root_n. Only issued_at and sig may differ.
function samePoint(held, pin) {
  for (const k of ["key_id", "namespace", "root", "root_n"]) {
    if (held[k] !== pin[k]) return false;
  }
  return held.head.n === pin.head.n && held.head.chain === pin.head.chain;
}

module.exports = {
  MAX_OBJECT_BYTES,
  ZERO_HEAD_CHAIN,
  ZERO_ROW_CHAIN,
  ContractError,
  canonical,
  parse,
  readHead,
  readPin,
  readStatement,
  isNamespace,
  isTime,
  privateFromSeed,
  publicRaw,
  keyId,
  sign,
  verify,
  formatTime,
  rowChain,
  makeRow,
  makeReceipt,
  rowDigest,
  makeAnswer,
  samePoint,
};
