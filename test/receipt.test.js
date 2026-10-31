// test/receipt.test.js — signed per pin receipts in the contract's shape
// (lib/_receipt.js), owner job 10. The REFERENCE vectors below were made by
// the reference witness's own code (arcaeon-witness-sandbox
// witness/contract.py make_receipt and make_statement) with the throwaway seed
// 11 x 32; Ed25519 is deterministic, so this code must give the same bytes
// and the same signature, or a contract reader would not accept it.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_KEYS = "testkeyA:demo-";
delete process.env.WITNESS_PLANS;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const receipts = require("../lib/_receipt.js");
const pinHandler = require("../api/pin.js");
const latestHandler = require("../api/latest.js");
const verifyHandler = require("../api/verify.js");

const SEED = "11".repeat(32);
const REF_RECEIPT_BYTES = '{"head":{"chain":"abababababababababababababababababababababababababababababababab","kind":"head","n":42,"v":1},"key_id":"10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d","kind":"receipt","namespace":"demo-phone","received_at":"2026-10-31T10:11:12Z","sig":"ef754674c063e4c0dec860762685705b0536135ddb850319dc2c392cee968f668fbca332862efd46918ac5b91e8721640aa7f6b07a4c7e008455828eaee8d303","v":1,"witness_seq":7}';
const REF_STATEMENT = { kind: "witness_statement", public_key: "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
  started_at: "2026-10-31T00:00:00Z", v: 1, key_id: "10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d",
  sig: "f66fc802fb3f9e69be8ff5de7a494234db59407cb4ea3f17ea93b96cf0511b418312820af0101d5bb06fb0fba4ea5d5099d1e91dcf36f070c10e8dfca48d7902" };

let gh, restore, saved;
const realPutSleep = store._putRetry.sleep;
const ENV = ["WITNESS_RECEIPTS", "WITNESS_RECEIPT_KEY", "WITNESS_RECEIPT_STARTED_AT"];
function on() {
  process.env.WITNESS_RECEIPTS = "on";
  process.env.WITNESS_RECEIPT_KEY = SEED;
}
beforeEach(() => {
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  for (const k of ENV) delete process.env[k];
  gh = new MockGitHubStore();
  restore = install(gh);
  store._putRetry.sleep = async () => {};
});
afterEach(() => {
  store._putRetry.sleep = realPutSleep;
  restore();
  for (const k of ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
});

const CHAIN = "ab".repeat(32);
async function pin(body, key = "testkeyA") {
  const res = makeRes();
  await pinHandler(makeReq({ method: "POST", headers: { authorization: `Bearer ${key}` }, body }), res);
  return res;
}
const publicRaw = () => receipts.keyFromEnv().publicRaw;

test("REFERENCE: the same seed and record give byte for byte the reference witness's receipt", () => {
  on();
  const { receipt } = receipts.forRecord({ namespace: "demo-phone", rows: 42, chain: CHAIN, seq: 7,
    pinned_at: "2026-10-31T10:11:12.345Z" });
  assert.equal(receipts.canonical(receipt), REF_RECEIPT_BYTES);
  assert.deepEqual(receipts.verify(JSON.parse(REF_RECEIPT_BYTES), publicRaw()), { ok: true });
});

test("REFERENCE: the key document's statement is the reference witness's witness_statement", async () => {
  on();
  process.env.WITNESS_RECEIPT_STARTED_AT = "2026-10-31T00:00:00Z";
  const res = makeRes();
  await verifyHandler(makeReq({ method: "GET", query: { op: "witness-key" } }), res);
  assert.equal(res._status, 200);
  assert.equal(res._body.key_id, REF_STATEMENT.key_id);
  assert.equal(res._body.public_key, REF_STATEMENT.public_key);
  assert.equal(receipts.canonical(res._body.witness_statement), receipts.canonical(REF_STATEMENT));
});

test("PIN: a new pin, a renewal and the idempotent re-pin each carry a receipt that verifies", async () => {
  on();
  const first = await pin({ namespace: "demo-r", rows: 3, chain: CHAIN });
  assert.equal(first._status, 201);
  const r1 = first._body.receipt;
  assert.deepEqual(receipts.verify(r1, publicRaw()), { ok: true });
  assert.deepEqual(r1.head, { chain: CHAIN, kind: "head", n: 3, v: 1 });
  assert.equal(r1.witness_seq, first._body.pin.seq);
  assert.match(r1.received_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  const again = await pin({ namespace: "demo-r", rows: 3, chain: CHAIN });
  assert.equal(again._status, 200);
  assert.deepEqual(again._body.receipt, r1, "the same record gives the same receipt");
  const renew = await pin({ namespace: "demo-r", rows: 3, chain: CHAIN, intent: "renew" });
  assert.equal(renew._body.receipt.witness_seq, r1.witness_seq + 1, "witness_seq strictly increases");
  assert.deepEqual(receipts.verify(renew._body.receipt, publicRaw()), { ok: true });
});

test("LATEST: the latest record's receipt, only from a fresh read", async () => {
  on();
  await pin({ namespace: "demo-l", rows: 5, chain: CHAIN });
  const res = makeRes();
  await latestHandler(makeReq({ method: "GET", query: { ns: "demo-l", namespace: "demo-l" } }), res);
  assert.equal(res._status, 200, JSON.stringify(res._body));
  assert.deepEqual(receipts.verify(res._body.receipt, publicRaw()), { ok: true });
});

test("NOT IN CONTRACT FORM: a short chain gets no receipt, and the answer says why", async () => {
  on();
  const res = await pin({ namespace: "demo-short", rows: 3, chain: "abcdef12" });
  assert.equal(res._status, 201);
  assert.equal(res._body.receipt, null);
  assert.equal(res._body.receipt_unavailable, "chain_not_64_hex");
  assert.equal(receipts.forRecord({ namespace: "-lead", rows: 1, chain: CHAIN, seq: 1, pinned_at: "2026-10-31T00:00:00Z" })
    .receipt_unavailable, "namespace_not_in_contract_form");
});

test("FLAG OFF: no receipt field at all, no key document", async () => {
  process.env.WITNESS_RECEIPT_KEY = SEED;
  const res = await pin({ namespace: "demo-off", rows: 3, chain: CHAIN });
  assert.equal("receipt" in res._body, false);
  const doc = makeRes();
  await verifyHandler(makeReq({ method: "GET", query: { op: "witness-key" } }), doc);
  assert.equal(doc._status, 404);
});

test("KEY: missing or malformed key gives no receipt and is never printed", async () => {
  process.env.WITNESS_RECEIPTS = "on";
  for (const bad of [undefined, "zz".repeat(32), "11".repeat(31), "AA".repeat(32)]) {
    if (bad === undefined) delete process.env.WITNESS_RECEIPT_KEY; else process.env.WITNESS_RECEIPT_KEY = bad;
    const res = await pin({ namespace: `demo-k${Math.random().toString(16).slice(2, 8)}`, rows: 3, chain: CHAIN });
    assert.equal(res._status, 201);
    assert.equal(res._body.receipt_unavailable, "receipt_key_not_configured");
    if (bad) assert.ok(!JSON.stringify(res._body).includes(bad));
    const doc = makeRes();
    await verifyHandler(makeReq({ method: "GET", query: { op: "witness-key" } }), doc);
    assert.equal(doc._status, 503);
    assert.equal(doc._body.field, "WITNESS_RECEIPT_KEY");
  }
  on();
  const res = await pin({ namespace: "demo-k-good", rows: 3, chain: CHAIN });
  assert.ok(!JSON.stringify(res._body).includes(SEED), "the seed never appears");
});

test("VERIFY: every changed field is refused by name", () => {
  on();
  const { receipt } = receipts.forRecord({ namespace: "demo-v", rows: 9, chain: CHAIN, seq: 2, pinned_at: "2026-10-31T01:02:03Z" });
  const cases = [
    [{ ...receipt, witness_seq: 3 }, "sig"], [{ ...receipt, namespace: "demo-w" }, "sig"],
    [{ ...receipt, head: { ...receipt.head, n: 10 } }, "sig"], [{ ...receipt, received_at: "2026-10-31T01:02:04Z" }, "sig"],
    [{ ...receipt, key_id: "00".repeat(32) }, "key_id"], [{ ...receipt, extra: 1 }, "receipt"],
    [{ ...receipt, head: { ...receipt.head, root: "x" } }, "head"], [{ ...receipt, received_at: "2026-10-31T01:02:03.5Z" }, "received_at"],
    [{ ...receipt, sig: receipt.sig.toUpperCase() }, "sig"],
  ];
  for (const [r, field] of cases) assert.equal(receipts.verify(r, publicRaw()).field, field, JSON.stringify(r).slice(0, 80));
});

test("CANONICAL: sorted keys, integers only, no null", () => {
  assert.equal(receipts.canonical({ b: 1, a: [true, "x\"\n"] }), '{"a":[true,"x\\"\\n"],"b":1}');
  assert.throws(() => receipts.canonical({ a: 1.5 }));
  assert.throws(() => receipts.canonical({ a: null }));
  assert.equal(receipts.canonical({ "é": 1, z: 2 }), '{"z":2,"é":1}');
});

test("CHECKPOINT: the receipt key signs the checkpoint, and the key document's verifier key checks it", async () => {
  on();
  const checkpoint = require("../lib/_checkpoint.js");
  const keys = receipts.checkpointKeys();
  const text = checkpoint.formatCheckpoint({ size: 3, root: Buffer.alloc(32, 7) });
  const signed = checkpoint.signCheckpoint(text, keys.signer);
  const res = makeRes();
  await verifyHandler(makeReq({ method: "GET", query: { op: "witness-key" } }), res);
  const v = checkpoint.verifyCheckpointSignature(signed, res._body.checkpoint_verifier_key);
  assert.equal(v.ok, true, JSON.stringify(v));
  // The verifier key names the same raw public key the receipts use.
  const parsed = checkpoint.parseVerifierKey(res._body.checkpoint_verifier_key);
  assert.equal(Buffer.from(parsed.pub).toString("hex"), res._body.public_key);
  // A checkpoint signed by another key does not pass for this one.
  const other = checkpoint.generateKey("arcaeon.io/witness-pins/receipts");
  assert.equal(checkpoint.verifyCheckpointSignature(checkpoint.signCheckpoint(text, other.signer),
    res._body.checkpoint_verifier_key).ok, false);
});

test("LATEST: a record read from the lagging mirror gets no receipt, and the answer says why", async () => {
  on();
  await pin({ namespace: "demo-mirror", rows: 4, chain: CHAIN });
  const record = gh.read("test-owner/test-pins", "pins/demo-mirror/latest.json");
  const orig = global.fetch;
  global.fetch = async (url, opts) => {
    const u = new URL(String(url));
    if (u.hostname === "api.github.com") return { status: 502, ok: false, json: async () => ({}), text: async () => "" };
    if (u.hostname === "raw.githubusercontent.com") return { status: 200, ok: true, json: async () => record, text: async () => JSON.stringify(record) };
    return orig(url, opts);
  };
  try {
    const res = makeRes();
    await latestHandler(makeReq({ method: "GET", query: { ns: "demo-mirror", namespace: "demo-mirror" } }), res);
    assert.equal(res._status, 200, JSON.stringify(res._body));
    assert.equal(res._body.source, "raw.githubusercontent");
    assert.equal(res._body.receipt, null);
    assert.equal(res._body.receipt_unavailable, "read_from_lagging_mirror");
  } finally {
    global.fetch = orig;
  }
});

// --- job 13: GET /api/verify answers with the signed receipt ---

async function verifyGet(query) {
  const res = makeRes();
  await verifyHandler(makeReq({ method: "GET", query, headers: { "x-forwarded-for": `10.40.0.${Math.floor(Math.random() * 250)}` } }), res);
  return res;
}

test("VERIFY: a witnessed current head comes with the same receipt the pin was answered with", async () => {
  on();
  const p = await pin({ namespace: "demo-ver", rows: 6, chain: CHAIN });
  const res = await verifyGet({ ns: "demo-ver", rows: "6", chain: CHAIN });
  assert.equal(res._status, 200, JSON.stringify(res._body));
  assert.equal(res._body.witnessed, true);
  assert.deepEqual(res._body.receipt, p._body.receipt);
  assert.deepEqual(receipts.verify(res._body.receipt, publicRaw()), { ok: true });
});

test("VERIFY: a superseded head found in history comes with its own record's receipt", async () => {
  on();
  const first = await pin({ namespace: "demo-hist", rows: 6, chain: CHAIN });
  await pin({ namespace: "demo-hist", rows: 9, chain: "cd".repeat(32) });
  const res = await verifyGet({ ns: "demo-hist", rows: "6", chain: CHAIN });
  assert.equal(res._body.witnessed, true);
  assert.equal(res._body.is_current_head, false);
  assert.deepEqual(res._body.receipt, first._body.receipt);
  assert.equal(res._body.receipt.witness_seq, 1);
});

test("VERIFY: a head that was not witnessed has no receipt; flag off, no field", async () => {
  on();
  await pin({ namespace: "demo-nope", rows: 6, chain: CHAIN });
  const miss = await verifyGet({ ns: "demo-nope", rows: "6", chain: "ef".repeat(32) });
  assert.notEqual(miss._body.witnessed, true);
  assert.equal("receipt" in miss._body, false);
  delete process.env.WITNESS_RECEIPTS;
  const off = await verifyGet({ ns: "demo-nope", rows: "6", chain: CHAIN });
  assert.equal(off._body.witnessed, true);
  assert.equal("receipt" in off._body, false);
});

test("VERIFY: a short chain is witnessed, and says why it has no receipt", async () => {
  on();
  await pin({ namespace: "demo-shortv", rows: 2, chain: "abcdef12" });
  const res = await verifyGet({ ns: "demo-shortv", rows: "2", chain: "abcdef12" });
  assert.equal(res._body.witnessed, true);
  assert.equal(res._body.receipt, null);
  assert.equal(res._body.receipt_unavailable, "chain_not_64_hex");
});
