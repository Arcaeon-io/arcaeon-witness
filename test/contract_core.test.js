// test/contract_core.test.js: lib/_contract.js, the contract's canonical
// bytes, its signatures and its readers, held to the shared vectors
// (test/vectors/contract_vectors.json, copied byte for byte from the seal
// repository) and to bytes the reference witness made
// (test/vectors/join_reference.json).
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const c = require("../lib/_contract.js");

const VECTORS_PATH = path.join(__dirname, "vectors", "contract_vectors.json");
const VECTORS = JSON.parse(fs.readFileSync(VECTORS_PATH, "utf8"));
const REF = JSON.parse(fs.readFileSync(path.join(__dirname, "vectors", "join_reference.json"), "utf8"));
const KEYS = VECTORS.test_keys;

test("the vectors file is the seal repository's, byte for byte", () => {
  const digest = crypto.createHash("sha256").update(fs.readFileSync(VECTORS_PATH)).digest("hex");
  assert.equal(digest, "3f6da76fff919f3b02e02a7ea65a0469e979e6ec7c34a5407ae42a61faf58d03");
});

test("every vector object is written as its expected canonical bytes, with its SHA-256", () => {
  assert.ok(VECTORS.objects.length >= 30);
  for (const o of VECTORS.objects) {
    const bytes = c.canonical(o.object);
    assert.equal(bytes.toString("hex"), o.canonical_hex, o.name);
    assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), o.sha256, o.name);
  }
});

test("every signed vector verifies under the TEST key its key_id names, and fails under another", () => {
  const byId = {};
  for (const k of Object.values(KEYS)) byId[k.key_id] = Buffer.from(k.public_key, "hex");
  let signed = 0;
  for (const o of VECTORS.objects) {
    if (typeof o.object.sig !== "string") continue;
    const pub = byId[o.object.key_id];
    assert.ok(pub, o.name);
    assert.equal(c.verify(o.object, pub), true, o.name);
    const other = Object.values(byId).find((p) => !p.equals(pub));
    assert.equal(c.verify(o.object, other), false, o.name);
    signed += 1;
  }
  assert.ok(signed >= 8);
});

test("key ids and public keys come from the TEST seeds as the vectors state them", () => {
  for (const k of Object.values(KEYS)) {
    const priv = c.privateFromSeed(k.seed);
    assert.equal(c.publicRaw(priv).toString("hex"), k.public_key);
    assert.equal(c.keyId(c.publicRaw(priv)), k.key_id);
  }
});

test("a pin signed here is the reference witness's pin, byte for byte", () => {
  const owner = c.privateFromSeed(KEYS.owner.seed);
  const p1 = JSON.parse(REF.pins[0]);
  const again = c.sign(owner, { head: p1.head, issued_at: p1.issued_at, kind: "pin", namespace: p1.namespace, v: 1 });
  assert.equal(c.canonical(again).toString(), REF.pins[0]);
});

test("rows, receipts and the signed rows answer are the reference witness's bytes", () => {
  const wit = c.privateFromSeed(KEYS.witness.seed);
  const pins = REF.pins.map((t) => JSON.parse(t));
  const r1 = c.makeRow(1, "2026-10-02T09:15:01Z", pins[0], c.ZERO_ROW_CHAIN, KEYS.owner.public_key);
  const r2 = c.makeRow(2, "2026-10-03T00:40:02Z", pins[1], r1.chain, KEYS.owner.public_key);
  assert.equal(c.canonical(r1).toString(), REF.rows[0]);
  assert.equal(c.canonical(r2).toString(), REF.rows[1]);
  assert.equal(c.canonical(c.makeReceipt(wit, r1)).toString(), REF.receipts[0]);
  assert.equal(c.canonical(c.makeReceipt(wit, r2)).toString(), REF.receipts[1]);
  const answer = c.makeAnswer(wit, "team-notes", [r2, r1], REF.answer_served_at);
  assert.equal(c.canonical(answer).toString(), REF.answer);
});

test("a stored row whose chain does not match its fields is caught", () => {
  const pins = REF.pins.map((t) => JSON.parse(t));
  const r1 = c.makeRow(1, "2026-10-02T09:15:01Z", pins[0], c.ZERO_ROW_CHAIN, KEYS.owner.public_key);
  assert.equal(c.rowChain(r1), r1.chain);
  const bent = { ...r1, received_at: "2026-10-02T09:15:02Z" };
  assert.notEqual(c.rowChain(bent), bent.chain);
});

test("canonical refuses what the contract never writes, naming the field", () => {
  assert.throws(() => c.canonical({ a: 1.5 }), (e) => e.field === "a");
  assert.throws(() => c.canonical({ a: null }), (e) => e.field === "a");
  assert.throws(() => c.canonical({ a: { b: 2 ** 53 } }), (e) => e.field === "a.b");
  assert.throws(() => c.canonical({ a: undefined }), (e) => e.field === "a");
});

function goodPin() {
  return JSON.parse(REF.pins[1]);
}

test("readPin names the first field at fault, in the reference order", () => {
  const cases = [
    [(p) => { delete p.kind; }, "kind"],
    [(p) => { p.kind = "receipt"; }, "kind"],
    [(p) => { p.v = 2; }, "v"],
    [(p) => { p.zzz = 1; }, "zzz"],
    [(p) => { delete p.sig; }, "sig"],
    [(p) => { delete p.issued_at; }, "issued_at"],
    [(p) => { p.head.n = -1; }, "head.n"],
    [(p) => { p.head.chain = "AB"; }, "head.chain"],
    [(p) => { p.head.extra = 1; }, "head.extra"],
    [(p) => { p.issued_at = "2026-02-30T00:00:00Z"; }, "issued_at"],
    [(p) => { p.issued_at = "2026-10-02T23:59:60Z"; }, "issued_at"],
    [(p) => { p.key_id = "x"; }, "key_id"],
    [(p) => { p.namespace = "-bad"; }, "namespace"],
    [(p) => { p.namespace = "Upper"; }, "namespace"],
    [(p) => { delete p.root; }, "root"],
    [(p) => { delete p.root_n; }, "root_n"],
    [(p) => { p.root_n = 6; }, "root_n"],
    [(p) => { p.sig = "00"; }, "sig"],
  ];
  for (const [bend, field] of cases) {
    const p = goodPin();
    bend(p);
    assert.throws(() => c.readPin(p), (e) => e instanceof c.ContractError && e.field === field, field);
  }
  assert.doesNotThrow(() => c.readPin(goodPin()));
});

test("parse refuses a body that is not strict JSON, naming pin", () => {
  for (const raw of [
    Buffer.from("\xef\xbb\xbf{}", "latin1"),
    Buffer.from([0x7b, 0xff, 0x7d]),
    Buffer.from("{not json"),
    Buffer.alloc(4097, 0x20),
  ]) {
    assert.throws(() => c.parse(raw, "pin"), (e) => e.field === "pin");
  }
});

test("the time form is whole seconds, UTC", () => {
  assert.equal(c.formatTime(new Date(Date.UTC(2026, 0, 2, 3, 4, 5, 999))), "2026-01-02T03:04:05Z");
});
