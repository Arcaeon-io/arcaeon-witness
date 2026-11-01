// _receipt.js: signed per pin receipts, in the shape of the contract between
// the seal, the witness and the checker (the reference witness's
// docs/CONTRACT.md, "Pins and receipts", and its witness/contract.py
// make_receipt). Underscore prefix = not routed as a serverless function.
//
// Why: a pin's public record (pins/<ns>/latest.json) is unsigned. Its
// authenticity rests on where it sits. A phone or a desktop that holds only
// what the witness answered cannot tell that answer from one anybody wrote.
// A receipt is the witness's signature on the one thing the pinner needs:
// "I took in this head, for this namespace, as my record number seq, at this
// time."
//
// THE SHAPE, exactly the contract's receipt (version 1):
//
//   {"head": {"chain": <64 hex>, "kind": "head", "n": <rows>, "v": 1},
//    "key_id": <sha256 of the raw 32 byte public key, 64 hex>,
//    "kind": "receipt", "namespace": <ns>,
//    "received_at": <the record's pinned_at, YYYY-MM-DDTHH:MM:SSZ>,
//    "sig": <Ed25519 over the canonical bytes of the rest, 128 hex>,
//    "v": 1, "witness_seq": <the record's seq>}
//
// Canonical bytes, as the contract writes them: keys sorted by UTF-16 code
// units, no whitespace, integers only, no null, strings escaped only for
// quote, backslash and control characters. JSON.stringify writes strings
// exactly that way, and sorts nothing, so canonical() sorts.
//
// A receipt is made only where the contract can carry it: a chain of exactly
// 64 hex characters (the contract's head chain is a SHA-256) and a namespace
// that starts with a letter or digit. Any other pin gets no receipt, and the
// answer says why (receipt_unavailable), never a receipt that a contract
// reader would refuse.
//
// THE KEY. Read from WITNESS_RECEIPT_KEY: the 32 byte Ed25519 seed as 64
// hex characters, put there by the owner's hand. Nothing here creates a key,
// writes one, logs one or puts one in an error. Tests use a throwaway key.
// Off unless WITNESS_RECEIPTS is on and the key reads.
//
// THE PUBLISHED KEY. GET /.well-known/arcaeon-witness-key (api/verify.js
// ?op=witness-key) answers {key_id, public_key, checkpoint_verifier_key}, and
// the receipt key adds its own signature line to every checkpoint
// tools/publish_checkpoint.js publishes (checkpointKeys below). And, when
// WITNESS_RECEIPT_STARTED_AT is set, the contract's witness_statement signed
// by the same key: a stable document that names the key every receipt is
// checked against.

"use strict";

const crypto = require("crypto");

const NS_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HEX64 = /^[0-9a-fA-F]{64}$/;
const TIME_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");

function enabled(env = process.env) {
  const v = String(env.WITNESS_RECEIPTS || "").toLowerCase();
  return v === "on" || v === "1" || v === "true" || v === "yes";
}

function canonical(value) {
  if (value === null || value === undefined) throw new TypeError("canonical: null is never written");
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("canonical: numbers are integers within 2^53 - 1");
    return String(value);
  }
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (typeof value === "object") {
    return "{" + Object.keys(value).sort().map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  throw new TypeError("canonical: unhandled value");
}

// -> {private, publicRaw, keyId} | null. Never throws, never logs the key.
function keyFromEnv(env = process.env) {
  const hex = String(env.WITNESS_RECEIPT_KEY || "").trim();
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  try {
    const priv = crypto.createPrivateKey({
      key: Buffer.concat([PKCS8_ED25519, Buffer.from(hex, "hex")]), format: "der", type: "pkcs8",
    });
    const spki = crypto.createPublicKey(priv).export({ format: "der", type: "spki" });
    const publicRaw = spki.subarray(spki.length - 32);
    return { private: priv, publicRaw, keyId: crypto.createHash("sha256").update(publicRaw).digest("hex") };
  } catch (_e) {
    return null;
  }
}

function sign(key, obj) {
  const body = { ...obj, key_id: key.keyId };
  delete body.sig;
  const sig = crypto.sign(null, Buffer.from(canonical(body), "utf8"), key.private).toString("hex");
  return { ...body, sig };
}

function wholeSeconds(iso) {
  if (typeof iso !== "string") return null;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return null;
  const out = new Date(Math.floor(t / 1000) * 1000).toISOString().replace(".000Z", "Z");
  return TIME_RE.test(out) ? out : null;
}

// For a stored pin record {namespace, rows, chain, seq, pinned_at}:
//   {receipt} | {receipt: null, receipt_unavailable: reason}  when receipts are on
//   {}                                                         when they are off
function forRecord(record, env = process.env) {
  if (!enabled(env)) return {};
  const key = keyFromEnv(env);
  if (!key) return { receipt: null, receipt_unavailable: "receipt_key_not_configured" };
  if (!record || typeof record !== "object") return { receipt: null, receipt_unavailable: "no_record" };
  if (typeof record.namespace !== "string" || !NS_RE.test(record.namespace)) {
    return { receipt: null, receipt_unavailable: "namespace_not_in_contract_form" };
  }
  if (typeof record.chain !== "string" || !HEX64.test(record.chain)) {
    return { receipt: null, receipt_unavailable: "chain_not_64_hex" };
  }
  if (!Number.isSafeInteger(record.rows) || record.rows < 1) return { receipt: null, receipt_unavailable: "rows" };
  if (!Number.isSafeInteger(record.seq) || record.seq < 1) return { receipt: null, receipt_unavailable: "seq" };
  const receivedAt = wholeSeconds(record.pinned_at);
  if (!receivedAt) return { receipt: null, receipt_unavailable: "pinned_at" };
  const receipt = sign(key, {
    head: { chain: record.chain.toLowerCase(), kind: "head", n: record.rows, v: 1 },
    kind: "receipt",
    namespace: record.namespace,
    received_at: receivedAt,
    v: 1,
    witness_seq: record.seq,
  });
  return { receipt };
}

// The same JSON, written the same way whatever the key order, so a pointer and
// a numbered row can be compared. Unlike canonical it takes nulls and any
// number, since stored records carry both.
function sameJson(a, b) {
  const norm = (v) => {
    if (Array.isArray(v)) return v.map(norm);
    if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, norm(v[k])]));
    return v;
  };
  return JSON.stringify(norm(a)) === JSON.stringify(norm(b));
}

// For a record read from the latest pointer (pins/<ns>/latest.json), which
// can be rewritten and is not in the checkpoint: a receipt only when the
// numbered row it names, pins/<ns>/<seq>.json, is there and holds the same
// record. Otherwise receipt_unavailable "pointer_not_backed_by_row", or
// "row_unreadable" when the row cannot be read. readRow(path) -> {json} | null.
// The write paths sign the record they just wrote and use forRecord.
async function forPointer(record, readRow, env = process.env) {
  if (!enabled(env)) return {};
  if (!record || typeof record !== "object" || !Number.isSafeInteger(record.seq) || record.seq < 1 ||
      typeof record.namespace !== "string" || !NS_RE.test(record.namespace)) {
    return forRecord(record, env);
  }
  let row;
  try {
    row = await readRow(`pins/${record.namespace}/${String(record.seq).padStart(8, "0")}.json`);
  } catch (_e) {
    return { receipt: null, receipt_unavailable: "row_unreadable" };
  }
  if (!row || !sameJson(row.json, record)) return { receipt: null, receipt_unavailable: "pointer_not_backed_by_row" };
  return forRecord(record, env);
}

// Check a receipt offline against a public key (raw 32 bytes): the shape
// above, key_id the hash of that key, the signature. -> {ok} | {ok:false, field}.
function verify(receipt, publicRaw) {
  const want = ["head", "key_id", "kind", "namespace", "received_at", "sig", "v", "witness_seq"];
  if (!receipt || typeof receipt !== "object" || Object.keys(receipt).sort().join() !== want.join()) {
    return { ok: false, field: "receipt" };
  }
  const h = receipt.head;
  if (!h || typeof h !== "object" || Object.keys(h).sort().join() !== "chain,kind,n,v" || h.kind !== "head" ||
      h.v !== 1 || !/^[0-9a-f]{64}$/.test(h.chain) || !Number.isSafeInteger(h.n) || h.n < 0) {
    return { ok: false, field: "head" };
  }
  if (receipt.kind !== "receipt" || receipt.v !== 1) return { ok: false, field: "kind" };
  if (typeof receipt.namespace !== "string" || !NS_RE.test(receipt.namespace)) return { ok: false, field: "namespace" };
  if (typeof receipt.received_at !== "string" || !TIME_RE.test(receipt.received_at)) return { ok: false, field: "received_at" };
  if (!Number.isSafeInteger(receipt.witness_seq) || receipt.witness_seq < 1) return { ok: false, field: "witness_seq" };
  const keyId = crypto.createHash("sha256").update(publicRaw).digest("hex");
  if (receipt.key_id !== keyId) return { ok: false, field: "key_id" };
  if (typeof receipt.sig !== "string" || !/^[0-9a-f]{128}$/.test(receipt.sig)) return { ok: false, field: "sig" };
  const body = { ...receipt };
  delete body.sig;
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicRaw]);
  const pub = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
  const ok = crypto.verify(null, Buffer.from(canonical(body), "utf8"), pub, Buffer.from(receipt.sig, "hex"));
  return ok ? { ok: true } : { ok: false, field: "sig" };
}

// The same key in the checkpoint's signed note form (lib/_checkpoint.js), so
// the receipt key also signs the published checkpoint: one more signature
// line, which every checker that does not know this key ignores, and which
// ties the key every receipt names to the log's own checkpoint.
const CHECKPOINT_KEY_NAME = "arcaeon.io/witness-pins/receipts";

function checkpointKeys(env = process.env) {
  const hex = String(env.WITNESS_RECEIPT_KEY || "").trim();
  const key = keyFromEnv(env);
  if (!key) return null;
  const { keyHash } = require("./_checkpoint.js");
  const h = keyHash(CHECKPOINT_KEY_NAME, key.publicRaw).toString("hex");
  return {
    signer: `PRIVATE+KEY+${CHECKPOINT_KEY_NAME}+${h}+${Buffer.concat([Buffer.from([1]), Buffer.from(hex, "hex")]).toString("base64")}`,
    verifier: `${CHECKPOINT_KEY_NAME}+${h}+${Buffer.concat([Buffer.from([1]), key.publicRaw]).toString("base64")}`,
  };
}

// The stable key document. -> {status, body}.
function keyDocument(env = process.env) {
  if (!enabled(env)) {
    return { status: 404, body: { error: "receipts are not enabled on this witness", reason: "not_enabled", field: "op" } };
  }
  const key = keyFromEnv(env);
  if (!key) {
    return { status: 503, body: { error: "the receipt key is not configured", reason: "receipt_key_not_configured",
      field: "WITNESS_RECEIPT_KEY" } };
  }
  const body = { key_id: key.keyId, public_key: key.publicRaw.toString("hex"), algorithm: "ed25519",
    checkpoint_verifier_key: checkpointKeys(env).verifier };
  const started = String(env.WITNESS_RECEIPT_STARTED_AT || "");
  if (TIME_RE.test(started)) {
    body.witness_statement = sign(key, { kind: "witness_statement", public_key: body.public_key, started_at: started, v: 1 });
  }
  return { status: 200, body };
}

module.exports = { enabled, canonical, keyFromEnv, forRecord, forPointer, sameJson, verify, keyDocument, wholeSeconds, checkpointKeys,
  CHECKPOINT_KEY_NAME };
