// test/reconcile_receipt.test.js — lib/_reconcile_receipt.js: what the signed
// receipt of a hosted completeness verdict binds, what it refuses to claim,
// and that it fails closed on every doctored copy.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const T = require("../lib/_reconcile_tapes.js");
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const fixtures = require("./fixtures/reconcile/cases.json");

const KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-09-23");
const OTHER = checkpoint.generateKey("arcaeon.io/someone-else/2026-09-23");

function pairNamed(re) {
  const c = fixtures.cases.find((x) => re.test(x.name) && x.python);
  assert.ok(c, String(re));
  return [Buffer.from(c.a_b64, "base64"), Buffer.from(c.b_b64, "base64")];
}
const [A, B] = pairNamed(/test_cross_repo_adapter_tape_a0: agent vs tool$/);

function signedFor(a, b, key = KEY, now = Date.UTC(2026, 8, 23, 12, 0, 0)) {
  const result = T.reconcileTapes(a, b);
  const r = receipts.buildReceipt({ bytesA: a, bytesB: b, result, now });
  const signer = receipts.loadSigner({ [receipts.SIGNER_ENV]: key.signer });
  return { result, receipt: receipts.signReceipt(r, signer) };
}

test("RECEIPT: binds the sha256 of each tape exactly as submitted, the verdict, the method and the time", () => {
  const { result, receipt } = signedFor(A, B);
  const sha = (b) => `sha256:raw-bytes:v1:${crypto.createHash("sha256").update(b).digest("hex")}`;
  assert.equal(receipt.kind, "arcaeon-reconcile-receipt");
  assert.deepEqual(receipt.tapes, { tape_a: { digest: sha(A), bytes: A.length }, tape_b: { digest: sha(B), bytes: B.length } });
  assert.equal(receipt.verdict.verdict, "MATCHED");
  assert.equal(receipt.verdict.matched, 5);
  assert.equal(receipt.verdict_digest, T.digestC14n(result));
  assert.equal(receipt.compared_at, "2026-09-23T12:00:00Z");
  assert.equal(receipt.method.reference.reconcile_sha256, T.REFERENCE.reconcile_sha256);
  assert.equal(receipt.method.impl, "js-port");
});

test("RECEIPT: claims only 'these two tapes, as submitted, compared like this at this time', and says what it does not claim", () => {
  const { receipt } = signedFor(A, B);
  assert.equal(receipt.claim, "These two tapes, as submitted, compared like this at this time.");
  const dnc = receipt.does_not_claim.join("\n");
  assert.match(dnc, /saw only the bytes submitted/);
  assert.match(dnc, /A tape the operator owns is not an outside witness/);
  assert.match(dnc, /No witness pin was checked/);
  assert.match(dnc, /It does not keep the tapes/);
  // and it holds no tape content: not one request or response digest from a row
  const text = JSON.stringify(receipt);
  for (const line of A.toString("utf-8").split("\n").filter((l) => l)) {
    const row = JSON.parse(line);
    assert.ok(!text.includes(row.req) && !(row.resp && text.includes(row.resp)), "a tape digest leaked into the receipt");
  }
});

test("RECEIPT: signs with the checkpoint key shape and verifies; the disclaimer is inside the signed bytes", () => {
  const { receipt } = signedFor(A, B);
  assert.equal(receipt.signer.verifier, KEY.verifier);
  const text = T.wireJson(receipt);
  assert.deepEqual(receipts.verifyReceiptText(text, KEY.verifier), { ok: true, reason: "signed", signer: KEY.verifier });
  const cut = JSON.parse(text);
  cut.does_not_claim = cut.does_not_claim.slice(0, 1);
  assert.equal(receipts.verifyReceiptText(JSON.stringify(cut), KEY.verifier).reason, "bad_signature");
});

test("RECEIPT FAILS CLOSED: a changed verdict, digest, time or tape size breaks the signature", () => {
  const { receipt } = signedFor(A, B);
  const base = T.wireJson(receipt);
  for (const [from, to] of [['"verdict":"MATCHED"', '"verdict":"MISSING"'], ['"matched":5', '"matched":6'],
    ["2026-09-23T12:00:00Z", "2026-09-23T12:00:01Z"], [`"bytes":${A.length}`, `"bytes":${A.length + 1}`],
    [receipt.tapes.tape_a.digest.slice(-6), "000000"]]) {
    const doctored = base.replace(from, to);
    assert.notEqual(doctored, base, from);
    assert.equal(receipts.verifyReceiptText(doctored, KEY.verifier).reason, "bad_signature", from);
  }
});

test("RECEIPT FAILS CLOSED: another key, no key, a garbled signature, and a non-receipt are refused by name", () => {
  const { receipt } = signedFor(A, B, OTHER);
  assert.equal(receipts.verifyReceiptText(T.wireJson(receipt), KEY.verifier).reason, "unknown_signer");
  const own = signedFor(A, B).receipt;
  const garbled = { ...JSON.parse(T.wireJson(own)), sig: "AAAA" };
  assert.equal(receipts.verifyReceiptText(JSON.stringify(garbled), KEY.verifier).reason, "malformed_signature");
  assert.equal(receipts.verifyReceiptText('{"kind":"check"}').reason, "not_a_reconcile_receipt");
  assert.equal(receipts.verifyReceiptText("not json").reason, "malformed_receipt");
});

test("RECEIPT WITHOUT A KEY: the verdict is unchanged and the receipt says it is unsigned, and why", () => {
  const result = T.reconcileTapes(A, B);
  const r = receipts.signReceipt(receipts.buildReceipt({ bytesA: A, bytesB: B, result }), receipts.loadSigner({}));
  assert.equal(r.sig, null);
  assert.equal(r.signer, null);
  assert.match(r.unsigned_reason, /WITNESS_RECONCILE_SIGNER_KEY is not set/);
  assert.equal(r.verdict.verdict, "MATCHED");
  assert.equal(receipts.verifyReceiptText(T.wireJson(r)).reason, "unsigned");
  const bad = receipts.loadSigner({ [receipts.SIGNER_ENV]: "PRIVATE+KEY+nope" });
  assert.equal(bad.ok, false);
  assert.ok(!JSON.stringify(bad).includes("PRIVATE+KEY+nope"), "a bad key is named, never echoed");
});

test("RECEIPT: never signs with the witness log's key", () => {
  const s = receipts.loadSigner({ WITNESS_LOG_SIGNER_KEY: KEY.signer });
  assert.equal(s.ok, false, "the log key is not a reconcile key");
});

test("RECEIPT: a verdict quoting a tape's lone surrogate still gets a signed receipt, with the digest gap named", () => {
  const c = fixtures.cases.find((x) => x.name === "lone_surrogate_in_req_altered");
  assert.ok(c);
  const a = Buffer.from(c.a_b64, "base64");
  const b = Buffer.from(c.b_b64, "base64");
  const { result, receipt } = signedFor(a, b);
  assert.equal(result.verdict, "ALTERED");
  assert.equal(receipt.verdict_digest, null);
  assert.match(receipt.verdict_digest_note, /lone surrogate/);
  assert.equal(receipts.verifyReceiptText(T.wireJson(receipt), KEY.verifier).ok, true);
});

// unit R-WIDE (C7): a receipt is held to a key the caller names, and a saved
// answer whose receipt binds no verdict text is partial, never ok
test("R-WIDE C7: verifyReceiptText with no verifier named answers unknown_signer, never ok", () => {
  const { receipt } = signedFor(A, B);
  assert.deepEqual(receipts.verifyReceiptText(T.wireJson(receipt)), { ok: false, reason: "unknown_signer" });
  assert.equal(receipts.verifyReceiptText(T.wireJson(receipt), KEY.verifier).ok, true, "control: the key named");
});

test("R-WIDE C7: a saved answer whose receipt has no verdict digest (a tape's lone surrogate) and carries a verdict is signed_partial, never ok", () => {
  const c = fixtures.cases.find((x) => x.name === "lone_surrogate_in_req_altered");
  const a = Buffer.from(c.a_b64, "base64");
  const b = Buffer.from(c.b_b64, "base64");
  const { result, receipt } = signedFor(a, b);
  assert.equal(receipt.verdict_digest, null, "fixture");
  const answer = T.wireJson({ ok: true, verdict: result, receipt });
  assert.deepEqual(receipts.verifyReceiptText(answer, KEY.verifier), { ok: false, reason: "signed_partial", signer: KEY.verifier });
  assert.equal(receipts.verifyReceiptText(T.wireJson(receipt), KEY.verifier).ok, true, "the receipt alone still verifies");
  // control: a saved answer whose receipt binds its verdict is ok
  const s = signedFor(A, B);
  assert.equal(receipts.verifyReceiptText(T.wireJson({ ok: true, verdict: s.result, receipt: s.receipt }), KEY.verifier).ok, true);
});
