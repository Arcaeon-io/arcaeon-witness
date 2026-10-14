// test/case_rsig.test.js — unit R-SIG (2026-10-14): signed_under on every
// signed record; one reader; no unsigned records. Every record the service
// signs (the sealed case, the withdrawal record, the reference row, the
// refusal receipt) names the key document it was signed under, exactly
// {document_sha256, document_commit}, and one function reads all four,
// lib/_case_seal.js signedUnderReason: the named commit on the published
// branch, the document there the one named, signed_by active in its role
// there, the signature, and the current document's listing. With the
// architect's rulings: note_version must equal 4 (a row at version 3 keeps
// its own reading); case_signature_invalid is signature_invalid;
// withdrawal.reason is absent when not given; a registration file is the
// party's signature and the service's unsigned arrival note. The setup
// below is test/case_rrv.test.js's, with the writers deployed.
"use strict";


process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0171:case-test-";
for (const k of ["WITNESS_BATCH_SHADOW", "WITNESS_ADMIN_KEY", "WITNESS_CASE_OPERATOR_KEY", "WITNESS_CASE_SIGNER_KEY",
  "WITNESS_RECONCILE_SIGNER_KEY", "WITNESS_RECONCILE_VERIFIER", "WITNESS_LOG_SIGNER_KEY", "VERCEL_GIT_COMMIT_SHA", "KEY_DOCUMENT_BRANCH"]) {
  delete process.env[k];
}

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const REG = require("./helpers/case_registration.js");
const KD = require("./helpers/key_document.js");
const store = require("../lib/_store.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const S = require("../lib/_case_seal.js");
const RECONCILE = require("../lib/_reconcile_http.js");
const CP = require("../lib/_case_page.js");
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const stamp = require("../lib/_stamp.js");
const { canonicalBytes } = require("../lib/_check_record.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const PINS = process.env.GITHUB_PIN_REPO;
const USAGE = process.env.GITHUB_USAGE_REPO;
const STAMPS = process.env.STAMP_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z");
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-14rsig");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-14rsig");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-14rsig");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0171" });

function tapePair() {
  const c = reconcileFixtures.cases.find((x) => /^receipt-test_call_proxy_tape\/test_cross_repo_adapter_tape_a0: agent vs tool$/.test(x.name) && x.python);
  assert.ok(c, "the fixture tape pair");
  return [Buffer.from(c.a_b64, "base64"), Buffer.from(c.b_b64, "base64")];
}
const [AGENT_TAPE, TOOL_TAPE] = tapePair();

let gh;
let restore;
let realSleep;
beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
  realSleep = store._putRetry.sleep;
  store._putRetry.sleep = async () => {};
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  KD.serve(gh, DOC);
});
afterEach(() => {
  store._putRetry.sleep = realSleep;
  restore();
});

let ipSeq = 0;
const nextIp = () => {
  ipSeq += 1;
  return `10.94.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
};
function req(op, body, headers = {}) {
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": nextIp(), ...headers }, body });
}
function parsed(res) {
  return typeof res._body === "string" ? JSON.parse(res._body) : res._body;
}
function opening(scope) {
  return {
    protocol_version: "case/1",
    policy_version: C.SUPPORTED_POLICY_VERSION,
    scope_digest: sha(scope),
    party_a: { side: "agent", label: "agent-operator@example.com" },
    party_b: { side: "tool", label: "tool-operator@example.com" },
    opened_at: "2026-10-10T07:30:00Z",
    deadline: DEADLINE,
  };
}
function party(caseId, role, tape, key = undefined) {
  const salt = C.newSalt();
  const tape_sha256 = sha(tape);
  return { role, tape, tape_sha256, salt, key, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
}
async function openCase(scope) {
  const o = makeRes();
  await H.handleCaseOpen(req("case-open", opening(scope), OPEN_AUTH), o, { now: NOW });
  assert.equal(o._status, 201, JSON.stringify(o._body));
  return o._body.case_id;
}
function plantStamp(hash) {
  gh.seed(STAMPS, stamp.stampPath(hash), { kind: "file-stamp", v: 1, sha256: hash, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: "2026-10-10T07:45:00.123Z" });
}
// unit R-L (L3): the commit path signs a repair note before it removes
// anything, so it runs with a deployment's environment and key document
const deployedEnv = (env = KEYS) => KD.deployed(gh, env, DOC);
async function commit(id, p, now = NOW, extra = {}) {
  const res = makeRes();
  const body = REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 }, p.key);
  await H.handleCaseCommit(req("case-commit", body), res, { now, env: deployedEnv(), keyDocument: DOC, ...extra });
  return { status: res._status, body: parsed(res) };
}
async function register(id, p) {
  plantStamp(p.commitment_sha256);
  const r = await commit(id, p);
  assert.equal(r.status, 201, JSON.stringify(r.body));
}
async function withdraw(id, p, { now = NOW + 2000, env = KEYS, salt = p.salt, reason } = {}) {
  const res = makeRes();
  const body = { case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt, ...(reason === undefined ? {} : { reason }) };
  await H.handleCaseWithdraw(req("case-withdraw", body), res, { now, env: KD.deployed(gh, env, DOC), keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
async function committedCase(scope, keys = {}) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE, keys.a);
  const b = party(id, "b", TOOL_TAPE, keys.b);
  for (const p of [a, b]) await register(id, p);
  return { id, a, b };
}
function revealBody(id, a, b) {
  return {
    case_id: id,
    reveals: { a: { tape_sha256: a.tape_sha256, salt: a.salt }, b: { tape_sha256: b.tape_sha256, salt: b.salt } },
    tape_a_b64: a.tape.toString("base64"),
    tape_b_b64: b.tape.toString("base64"),
  };
}
// The requester's own refusal request (N3): its role named, and its own opening.
const ownOpening = (c, role) => ({ ...revealBody(c.id, c.a, c.b), role });
async function reveal(c, { now = REVEAL_AT, env = KEYS, keyDocument = DOC, body = revealBody(c.id, c.a, c.b) } = {}) {
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", body), res, { now, env: KD.deployed(gh, env, keyDocument), keyDocument });
  return { status: res._status, body: parsed(res) };
}
async function sealedCase(scope, keys = {}) {
  const c = await committedCase(scope, keys);
  const r = await reveal(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  return { ...c, r };
}
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0171", url: "https://second-operator.example/cases/0152" });
async function reference(c, { role = "a", env = KEYS, now = REVEAL_AT + 1800000, deploy = true } = {}) {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: XREF }),
    res, { now, env: deploy ? KD.deployed(gh, env, DOC) : env, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
// The operator's reference (no proof; the operator's bearer key).
const OPERATOR_KEY = "case-operator-key-0171-rsig";
async function operatorReference(c, { now = REVEAL_AT + 1800000 } = {}) {
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, cross_reference: { ...XREF, reference: "operator-ref" } },
    { authorization: `Bearer ${OPERATOR_KEY}` }), res, { now, env: KD.deployed(gh, { ...KEYS, [H.OPERATOR_KEY_ENV]: OPERATOR_KEY }, DOC), keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
async function casePage(id, now = REVEAL_AT + 3600000) {
  const res = makeRes();

  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": nextIp() } }), res,
    { now, keyDocument: DOC, env: {} });
  return { status: res._status, html: String(res._body) };
}
async function reconcileCall(tapeA, tapeB, { env = KEYS } = {}) {
  const res = makeRes();
  await RECONCILE.handleReconcile(makeReq({ method: "POST", query: { op: "reconcile" }, headers: { "content-type": "application/json", "x-forwarded-for": nextIp() },
    body: { agent_tape: tapeA.toString("utf-8"), tool_tape: tapeB.toString("utf-8") } }), res, { env, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
// Run `inner` when the first request matching `match` goes out, then let
// that request through.
async function during(match, inner, outer) {
  const viaMock = global.fetch;
  let got;
  let fired = false;
  global.fetch = async (url, o) => {
    if (!fired && match(String(url), (o && o.method) || "GET")) {
      fired = true;
      got = await inner();
    }
    return viaMock(url, o);
  };
  try {
    const out = await outer();
    return { out, inner: got, fired };
  } finally {
    global.fetch = viaMock;
  }
}
const storedCase = (id) => gh.read(PINS, C.casePath(id));
const lockOf = (id) => gh.read(USAGE, H._internal.caseLockPath(id));
const pinsPaths = () => [...gh._repoMap(PINS).keys()];
const esc = (s) => CP._internal.esc(s);
const sealerRun = (dt = 60000, env = deployedEnv()) => S.anchorPending({ now: REVEAL_AT + 3600000 + dt, keyDocument: DOC, env });
const read = (rel) => fs.readFileSync(path.join(__dirname, "..", rel), "utf8");
const README = () => read("README.md").replace(/\s+/g, " ");
function jsFiles(dir) {
  const out = [];
  for (const e of fs.readdirSync(path.join(__dirname, "..", dir), { withFileTypes: true })) {
    const rel = `${dir}/${e.name}`;
    if (e.isDirectory()) out.push(...jsFiles(rel));
    else if (/\.(js|mjs|cjs)$/.test(e.name)) out.push(rel);
  }
  return out;
}

// The registration file at `rpath` as the pins repository holds it: its
// bytes, and their sha256.
const pinFile = (id) => `pins/case/${id}/00000001.json`;
const pinTree = (id) => pinsPaths().filter((p) => p.startsWith(`pins/case/${id}/`)).sort();
// The pin read: pinState since this unit, anchorState before it.
const pinRead = (id, served) => (S.pinState || S.anchorState)(id, served);
// Every request this test's code sends, while `fn` runs: method, decoded
// URL and, for a PUT, whether it named a sha (an update, not a create).
async function spyRequests(fn) {
  const viaMock = global.fetch;
  const seen = [];
  global.fetch = async (url, o) => {
    const method = (o && o.method) || "GET";
    let update = false;
    if (method === "PUT") {
      try {
        update = !!JSON.parse(o.body).sha;
      } catch {
        update = false;
      }
    }
    const r = await viaMock(url, o);
    seen.push({ method, url: decodeURIComponent(String(url)), update, ok: r.ok });
    return r;
  };
  try {
    await fn();
  } finally {
    global.fetch = viaMock;
  }
  return seen;
}

const TAPES = require("../lib/_reconcile_tapes.js");
const rootSha = (id) => gh._repoMap(PINS).get(C.casePath(id)).sha;
const casePuts = (id) => gh.putLog.filter((p) => p.path === C.casePath(id) || p === C.casePath(id)).length;
const RULE_4 = "The case may not have been sealed. Nothing was pinned. Send the same reveal again: it seals the case, or answers that it is already sealed.";
const WITHDRAWN_TEXT = "The case was withdrawn before this reveal could seal it. Nothing was recorded, and this response carries no verdict.";
// The port, failing `n` times (Infinity: always) before it answers.
function portFails(t, n = Infinity) {
  const real = TAPES.reconcileTapes;
  let left = n;
  return t.mock.method(TAPES, "reconcileTapes", (...args) => {
    if (left > 0) {
      left -= 1;
      const e = new Error("the port broke");
      e.name = "PortBroke";
      throw e;
    }
    return real(...args);
  });
}
const noTapeDigest = (c, body) => {
  const text = JSON.stringify(body);
  return !text.includes(c.a.tape_sha256) && !text.includes(c.b.tape_sha256);
};

// =============================================================================
// UNIT R-SIG
// =============================================================================

const checkRecord = require("../lib/_check_record.js");
const LATER = checkpoint.generateKey("arcaeon.io/case-test/2026-10-14rsig-later");
// The current document lists a case key that the document a record names
// did not: one published only later.
const CURRENT = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.entry(LATER), KD.reconcileEntry(RECEIPT_KEY)));
const suOf = (doc) => ({ document_sha256: KD.sha256(canonicalBytes(doc)), document_commit: KD.serve(gh, doc) });
const laterSigner = () => {
  const signer = S.loadCaseSigner({ ...KEYS, [S.CASE_SIGNER_ENV]: LATER.signer }, { keyDocument: CURRENT });
  assert.equal(signer.ok, true, JSON.stringify(signer));
  return signer;
};
// A record signed by hand as the service signs one: signed_by, sig_reason
// null, and the signature over the record minus sig.
function signByHand(unsigned, signer) {
  const rec = { ...unsigned, signed_by: signer.keyId, sig_reason: null, sig: null };
  rec.sig = crypto.sign(null, checkRecord.preimage(rec), signer.privateKey).toString("base64");
  return rec;
}
function withoutSig(rec) {
  const { sig: _s, signed_by: _b, sig_reason: _r, ...rest } = rec; // eslint-disable-line no-unused-vars
  return rest;
}
const flipSig = (rec) => {
  const b = Buffer.from(rec.sig, "base64");
  b[10] ^= 1;
  return { ...rec, sig: b.toString("base64") };
};
async function pageUnder(id, doc, now = REVEAL_AT + 3600000) {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": nextIp() } }), res,
    { now, keyDocument: doc, env: {} });
  return { status: res._status, html: String(res._body) };
}
const cell = (html, name) => {
  const m = html.match(new RegExp(`<tr><th>${name}</th><td>(.*?)</td></tr>`));
  return m ? m[1] : null;
};
const RECEIPT_FIELDS_TWO = ["document_commit", "document_sha256"];
// One of each signed record kind, written by this service's own handlers.
async function fourRecords(scope) {
  const s = await sealedCase(`${scope} seal`);
  const ref = await reference(s);
  assert.equal(ref.status, 201, JSON.stringify(ref.body).slice(0, 300));
  const w = await committedCase(`${scope} withdrawal`);
  assert.equal((await withdraw(w.id, w.b)).status, 201);
  const r = await reveal(w, { body: ownOpening(w, "a") });
  assert.equal(r.status, 409, JSON.stringify(r.body).slice(0, 300));
  return { s, w, seal: storedCase(s.id), row: gh.read(PINS, C.referencePath(s.id, 1)), withdrawal: storedCase(w.id), receipt: r.body.refusal_receipt };
}

test("R-SIG 1: a reference row signed by a key published only later never verifies: its key is absent from the document the row names and active in the current one; the row is not counted, and the page says why", async () => {
  const c = await sealedCase("RSIG 1");
  const row = signByHand({
    kind: C.REFERENCE_KIND, v: 1, case_id: c.id, seq: 1, cross_reference: { ...XREF }, recorded_at: C.utcSeconds(REVEAL_AT + 60000),
    appended_by: "operator", anchor_note: C.REFERENCE_ANCHOR_NOTE, note_version: C.REFERENCE_NOTE_VERSION, signed_under: suOf(DOC),
  }, laterSigner());
  gh.seed(PINS, C.referencePath(c.id, 1), row);
  const live = await S.liveRecords(storedCase(c.id), { keyDocument: CURRENT });
  assert.equal(live.ok, true);
  assert.deepEqual(live.rows, []);
  assert.deepEqual(live.invalid.map((x) => [x.seq, x.reason, x.detail]), [[1, "signature_invalid", "signer_unpublished"]]);
  const p = await pageUnder(c.id, CURRENT);
  assert.equal(p.status, 200, p.html.slice(0, 300));
  assert.ok(p.html.includes("reference row 1 is not counted: signature_invalid (signer_unpublished)"), cell(p.html, "records"));
});

test("R-SIG 2: a withdrawal record signed by a key published only later never verifies: the withdrawn page says its signature does not verify, and why", async () => {
  const c = await committedCase("RSIG 2");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const planted = signByHand({ ...withoutSig(storedCase(c.id)), signed_under: suOf(DOC) }, laterSigner());
  assert.deepEqual(C.validateCase(planted), { ok: true }, "fixture: a valid record");
  gh.seed(PINS, C.casePath(c.id), planted);
  const a = await S.signedUnderReason(planted, "case", CURRENT);
  assert.deepEqual([a.code, a.reason], ["signature_invalid", "signer_unpublished"]);
  const p = await pageUnder(c.id, CURRENT);
  assert.match(p.html, /<h1>Case: WITHDRAWN<\/h1>/);
  const signed = cell(p.html, "signed by");
  assert.ok(signed && signed.includes("signature_invalid (signer_unpublished)"), signed);
  assert.doesNotMatch(signed, /verifies|verified/);
});

test("R-SIG 3: one tampered signature, one answer: a seal, a reference row, a withdrawal record and a refusal receipt, each with a signature byte flipped, read signature_invalid by every reader", async () => {
  const f = await fourRecords("RSIG 3");
  const readers = {
    seal: async (x) => (await S.sealedRecordReason(x, DOC)).code,
    row: async (x) => (await S.judgeReferenceRow({ json: x }, { path: C.referencePath(f.s.id, 1), caseId: f.s.id, seq: 1, sealed: f.seal, keyDocument: DOC })).reason,
    withdrawal: async (x) => (await S.signedUnderReason(x, "case", DOC)).code,
    receipt: async (x) => (await S.verifyRefusalReceipt(x, DOC)).reason,
  };
  const flipped = {};
  const held = {};
  for (const k of Object.keys(readers)) {
    flipped[k] = await readers[k](flipSig(f[k]));
    held[k] = await readers[k](f[k]);
  }
  assert.deepEqual(flipped, { seal: "signature_invalid", row: "signature_invalid", withdrawal: "signature_invalid", receipt: "signature_invalid" });
  assert.deepEqual(held, { seal: "valid_under_document", row: undefined, withdrawal: "valid_under_document", receipt: undefined }, "control: each holds");
  assert.equal((await S.verifyRefusalReceipt(f.receipt, DOC)).ok, true);
});

test("R-SIG 4: every signed record carries signed_under, exactly document_sha256 and document_commit; it is required, and retrieved_at is unknown_field", async () => {
  const f = await fourRecords("RSIG 4");
  for (const k of ["seal", "row", "withdrawal", "receipt"]) {
    assert.deepEqual(Object.keys(f[k].signed_under).sort(), RECEIPT_FIELDS_TWO, k);
  }
  const su = f.seal.signed_under;
  const plus = { ...su, retrieved_at: "2026-10-10T09:00:00Z" };
  const without = (x) => withoutSig({ ...x, signed_under: undefined });
  assert.deepEqual([C.validateCase({ ...f.seal, signed_under: plus }).code, C.validateCase({ ...f.withdrawal, signed_under: plus }).code,
    C.validateReferenceRow({ ...f.row, signed_under: plus }).code, S.refusalReceiptFormReason({ ...f.receipt, signed_under: plus })],
  ["unknown_field", "unknown_field", "unknown_field", "unknown_field"]);
  const drop = (x) => {
    const { signed_under: _u, ...rest } = x; // eslint-disable-line no-unused-vars
    return rest;
  };
  assert.deepEqual([C.validateCase(drop(f.seal)).code, C.validateCase(drop(f.withdrawal)).code, C.validateReferenceRow(drop(f.row)).code,
    S.refusalReceiptFormReason(drop(f.receipt))], ["missing_field", "missing_field", "missing_field", "missing_field"]);
  assert.equal(typeof without, "function");
  for (const file of ["lib/_case.js", "lib/_case_seal.js", "lib/_case_http.js", "lib/_case_page.js"]) {
    assert.doesNotMatch(read(file), /retrieved_at|document_unrecorded|service clock, unverified/, file);
  }
});

test("R-SIG 5: signRecord without a signer throws, and so does each builder of a signed record", async () => {
  for (const signer of [null, undefined, { ok: false, code: "case_key_unset", reason: "no key" }]) {
    assert.throws(() => S.signRecord({ kind: "x" }, signer), /signRecord: no signer/);
  }
  const c = await committedCase("RSIG 5");
  const su = suOf(DOC);
  assert.throws(() => S.withdrawnRecord(storedCase(c.id), { role: "b", at: C.utcSeconds(NOW + 2000), salt: c.b.salt, signedUnder: su }, null), /no signer/);
  assert.throws(() => S.referenceRow({ caseId: c.id, seq: 1, crossReference: XREF, recordedAt: C.utcSeconds(REVEAL_AT), appendedBy: "operator", signedUnder: su }, null),
    /no signer/);
  assert.throws(() => S.refusalReceipt({ caseId: c.id, at: C.utcSeconds(NOW), role: "a", commitmentSha256: c.a.commitment_sha256, signedUnder: su }, null), /no signer/);
});

test("R-SIG 6: sig null is malformed_field on a sealed case, a withdrawal record, a reference row and a refusal receipt", async () => {
  const f = await fourRecords("RSIG 6");
  const unsigned = (x) => ({ ...x, sig: null, signed_by: null, sig_reason: "unsigned in this test" });
  assert.deepEqual([C.validateCase(unsigned(f.seal)).code, C.validateCase(unsigned(f.withdrawal)).code, C.validateReferenceRow(unsigned(f.row)).code,
    S.refusalReceiptFormReason({ ...f.receipt, sig: null })], ["malformed_field", "malformed_field", "malformed_field", "malformed_field"]);
  for (const f2 of ["lib/_case.js", "lib/_case_seal.js", "lib/_case_page.js"]) assert.doesNotMatch(read(f2), /row_unsigned/, f2);
});

test("R-SIG 7 (ruled: note_version must equal 4): a row with no note_version, or 1, 2 or 5, is malformed_field; a row at version 3 keeps its own reading, row_note_v3", async () => {
  const f = await fourRecords("RSIG 7");
  const at = (v) => {
    const x = { ...f.row };
    if (v === undefined) delete x.note_version;
    else x.note_version = v;
    return C.validateReferenceRow(x);
  };
  assert.deepEqual([at(undefined).code, at(1).code, at(2).code, at(5).code, at(3).code], ["malformed_field", "malformed_field", "malformed_field", "malformed_field", "row_note_v3"]);
  assert.deepEqual(at(4), { ok: true });
  for (const file of ["lib/_case.js", "lib/_case_seal.js"]) assert.doesNotMatch(read(file), /row_note_v1|row_note_v2/, file);
});

test("R-SIG 8: a withdrawal that names no reason records none, and the page says \"No reason was given.\"; one that names a reason records it", async () => {
  const c = await committedCase("RSIG 8");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  assert.equal(has(storedCase(c.id).withdrawal, "reason"), false);
  assert.ok(cell((await casePage(c.id)).html, "reason").includes("No reason was given."));
  const d = await committedCase("RSIG 8 deadline");
  assert.equal((await withdraw(d.id, d.a, { reason: "deadline" })).status, 201);
  assert.equal(storedCase(d.id).withdrawal.reason, "deadline");
  assert.ok(cell((await casePage(d.id)).html, "reason").includes("<code>deadline</code>"));
  assert.equal(C.DEFAULT_WITHDRAWAL_REASON, undefined);
  for (const file of ["lib/_case.js", "lib/_case_seal.js", "lib/_case_page.js", "lib/_case_http.js"]) {
    assert.doesNotMatch(read(file), /DEFAULT_WITHDRAWAL_REASON|before Design N/, file);
  }
});

test("R-SIG 9: appended_by names what was presented: preimage:a for a role's proof, operator for the operator key; the page says so in words", async () => {
  const s = await sealedCase("RSIG 9");
  assert.equal((await reference(s)).status, 201);
  assert.equal((await operatorReference(s)).status, 201);
  assert.equal(gh.read(PINS, C.referencePath(s.id, 1)).appended_by, "preimage:a");
  assert.equal(gh.read(PINS, C.referencePath(s.id, 2)).appended_by, "operator");
  assert.deepEqual(C.APPENDED_BY, ["preimage:a", "preimage:b", "operator"]);
  const p = await casePage(s.id);
  assert.ok(p.html.includes(esc("appended on presentation of role a's commitment preimage")), cell(p.html, "reference row 1"));
  assert.ok(p.html.includes("appended with the operator key"), cell(p.html, "reference row 2"));
  assert.doesNotMatch(p.html, /appended by role:/);
});

test("R-SIG 10: the refusal receipt's reason is case_withdrawn", async () => {
  const f = await fourRecords("RSIG 10");
  assert.equal(f.receipt.reason, "case_withdrawn");
  assert.equal(S.REFUSAL_RECEIPT_REASON, "case_withdrawn");
  for (const file of jsFiles("lib").concat(jsFiles("tools"))) assert.doesNotMatch(read(file), /consent_not_jointly_held/, file);
});

test("R-SIG 11: checkStoredReceipt, publishedSignatureReason and receiptSignerReason are gone", () => {
  for (const name of ["checkStoredReceipt", "publishedSignatureReason", "receiptSignerReason", "RECEIPT_UNSIGNED_REASONS"]) assert.equal(S[name], undefined, name);
  for (const file of jsFiles("lib").concat(jsFiles("tools"))) {
    assert.doesNotMatch(read(file), /checkStoredReceipt|publishedSignatureReason|receiptSignerReason/, file);
  }
});

test("R-SIG 12: the withdrawal and the reference refuse 503 document_unavailable when the document they sign under cannot be confirmed, and write nothing", async () => {
  const s = await sealedCase("RSIG 12 reference");
  const c = await committedCase("RSIG 12 withdrawal");
  const root = rootSha(c.id);
  const puts = gh.putLog.length;
  S._internal.clearDocumentCache();
  gh.forceRawFailure(1000, 503);
  const w = await withdraw(c.id, c.b);
  assert.deepEqual([w.status, w.body.error_code], [503, "document_unavailable"], JSON.stringify(w.body).slice(0, 300));
  const r = await reference(s);
  assert.deepEqual([r.status, r.body.error_code], [503, "document_unavailable"], JSON.stringify(r.body).slice(0, 300));
  gh.forceRawFailure(0);
  assert.equal(gh.putLog.length, puts, "nothing written");
  assert.equal(rootSha(c.id), root);
  assert.equal(gh.has(PINS, C.referencePath(s.id, 1)), false);
});

test("R-SIG: one reader. signedUnderReason is the one function that checks a record's signature against a key document; sealedRecordReason, judgeReferenceRow, the withdrawn page, verifyRefusalReceipt and the refusal receipt tool call it", () => {
  assert.equal(typeof S.signedUnderReason, "function");
  const seal = read("lib/_case_seal.js");
  // signatureReason's one caller is signedUnderReason
  assert.equal((seal.match(/signatureReason\(/g) || []).length, 2, "the definition and its one call");
  for (const file of ["lib/_case_page.js", "lib/_case_http.js", "tools/check_refusal_receipt.js"]) {
    assert.doesNotMatch(read(file), /signatureReason\(|checkKeyDocument\(/, file);
  }
  assert.match(read("lib/_case_page.js"), /signedUnderReason\(/);
  assert.match(read("tools/check_refusal_receipt.js"), /signedUnderReason\(/);
});

test("R-SIG: one case-root judge, judgeCase(got, caseId), exported from lib/_case_seal.js and used by the handler, the sealer and the page", () => {
  assert.equal(typeof S.judgeCase, "function");
  const ok = S.judgeCase({ json: { not: "a case" } }, "0".repeat(64));
  assert.equal(ok.ok, false);
  for (const file of ["lib/_case_http.js", "lib/_case_page.js"]) {
    assert.doesNotMatch(read(file), /function judgeCase/, file);
    assert.match(read(file), /SEAL\.judgeCase\(/, file);
  }
  for (const file of ["lib/_case_http.js", "lib/_case_page.js", "lib/_case_seal.js"]) {
    assert.doesNotMatch(read(file), /judgeWith\(got, cpath, \(json\) => \{\s*const r = C\.validateCase\(json\);/, file);
  }
});

test("R-SIG: signature_invalid replaces case_signature_invalid everywhere", async () => {
  for (const file of jsFiles("lib").concat(jsFiles("tools"))) assert.doesNotMatch(read(file), /case_signature_invalid/, file);
  // a seal signed by a key its named document does not list: signature_invalid
  const s = await sealedCase("RSIG signature_invalid");
  const planted = signByHand(withoutSig(storedCase(s.id)), laterSigner());
  const a = await S.sealedRecordReason(planted, CURRENT);
  assert.deepEqual([a.code, a.reason], ["signature_invalid", "signer_unpublished"]);
});

test("R-SIG: a sealed case's stored reconcile receipt must be signed: sig null or unsigned_reason is malformed_field", async () => {
  const f = await fourRecords("RSIG stored receipt");
  const k = f.seal;
  assert.equal(C.validateCase({ ...k, verdict: { ...k.verdict, sig: null, signer: null, unsigned_reason: "no key" } }).code, "malformed_field");
  assert.equal(C.validateCase({ ...k, verdict: { ...k.verdict, unsigned_reason: "no key" } }).code, "malformed_field");
});

test("R-SIG: sig_reason is non-null only on an OPEN or COMMITTED root, and there it is UNSEALED_SIG_REASON", async () => {
  const f = await fourRecords("RSIG sig_reason");
  const id = await openCase("RSIG sig_reason open");
  const open = storedCase(id);
  assert.equal(open.sig_reason, C.UNSEALED_SIG_REASON);
  assert.equal(C.validateCase({ ...open, sig_reason: "another sentence" }).code, "malformed_field");
  for (const [what, rec, judge] of [["seal", f.seal, C.validateCase], ["withdrawal", f.withdrawal, C.validateCase], ["row", f.row, C.validateReferenceRow]]) {
    assert.equal(rec.sig_reason, null, what);
    assert.equal(judge({ ...rec, sig_reason: "a reason" }).code, "malformed_field", what);
  }
});

test("R-SIG rule 11 (ruled): the registration file sentence, on the page and in the README", async () => {
  const SENTENCE = "A registration file is signed by the registering party over the case, role and commitment; its registered_at, stamp_commit and " +
    "stamped_at are the service's unsigned arrival note until a seal copies them into signed bytes.";
  const c = await committedCase("RSIG rule 11");
  assert.ok((await casePage(c.id, NOW + 60000)).html.includes(esc(SENTENCE)));
  assert.ok(README().includes(SENTENCE));
});

test("R-SIG rule 12: the key document's description names every signed record and its key", () => {
  const d = S.PUBLISHED_KEYS.description;
  assert.ok(d.includes("Sealed cases, withdrawal records and reference rows are signed by a case key (role case, or no role). The reconcile key " +
    "(role reconcile) signs each sealed case's reconcile receipt and each refusal receipt. Each signed record names its key in signed_by and the " +
    "commit of this document it was signed under in signed_under."), d);
});

test("R-SIG: the page prints no 'unsigned:' cell; an open or committed case's signed-by row is the fixed sentence", async () => {
  const c = await committedCase("RSIG no unsigned cell");
  const p = await casePage(c.id, NOW + 60000);
  assert.equal(cell(p.html, "signed by"), esc(C.UNSEALED_SIG_REASON));
  assert.doesNotMatch(read("lib/_case_page.js"), /unsigned: \$\{/);
});

// =============================================================================
// R-SIG's must-fail gap tests: each fails with its planted defect
// =============================================================================

test("MUST-FAIL GAP (G07): a stored receipt with sig null alone, or an empty sig, is malformed_field at verdict.sig", async () => {
  const k = (await fourRecords("RSIG gap G07")).seal;
  for (const sig of [null, ""]) {
    const v = C.validateCase({ ...k, verdict: { ...k.verdict, sig } });
    assert.deepEqual([v.ok, v.code, v.field], [false, "malformed_field", "verdict.sig"], JSON.stringify(sig));
  }
});

test("MUST-FAIL GAP (T02): the exported receipt binding refuses a receipt with sig null: receipt_signature_unreadable", async () => {
  const k = (await fourRecords("RSIG gap T02")).seal;
  assert.equal(S.checkSealedReceipt(k), null, "control");
  assert.equal(S.checkSealedReceipt({ ...k, verdict: { ...k.verdict, sig: null } }), "receipt_signature_unreadable");
});

test("MUST-FAIL GAP (T24): a refusal receipt whose signed_under lacks a field is missing_field", async () => {
  const { receipt } = await fourRecords("RSIG gap T24");
  assert.equal(S.refusalReceiptFormReason(receipt), null, "control");
  for (const k of ["document_sha256", "document_commit"]) {
    const { [k]: _gone, ...su } = receipt.signed_under; // eslint-disable-line no-unused-vars
    assert.equal(S.refusalReceiptFormReason({ ...receipt, signed_under: su }), "missing_field", k);
  }
});

test("MUST-FAIL GAP (T29, T30): a reference row whose named document cannot be read is unreadable, not invalid, and the live count is not established", async () => {
  const s = await sealedCase("RSIG gap T29");
  assert.equal((await reference(s)).status, 201);
  const sealed = storedCase(s.id);
  assert.equal(sealed.cross_reference, null, "fixture: the seal carries no cross_reference");
  S._internal.clearDocumentCache();
  gh.forceRawFailure(1000, 503);
  let live;
  try {
    live = await S.liveRecords(sealed, { keyDocument: DOC });
  } finally {
    gh.forceRawFailure(0);
  }
  assert.deepEqual([live.ok, live.records, live.indeterminate, live.unreadable, live.invalid, live.rows.length],
    [true, null, true, [1], [], 0], JSON.stringify(live));
});

test("MUST-FAIL GAP (U08): a reference to a case whose seal signature does not verify is refused 409 signature_invalid in words", async () => {
  const s = await sealedCase("RSIG gap U08");
  gh.seed(PINS, C.casePath(s.id), flipSig(storedCase(s.id)));
  const r = await reference(s);
  assert.deepEqual([r.status, r.body.error_code], [409, "signature_invalid"], JSON.stringify(r.body).slice(0, 300));
  assert.ok(r.body.error.includes("its signature is not confirmed under the key document it names"), r.body.error);
});

test("MUST-FAIL GAP (U09): the refusal receipt's 409 says what was read, and nothing of consent", async () => {
  const w = await committedCase("RSIG gap U09");
  assert.equal((await withdraw(w.id, w.b)).status, 201);
  const r = await reveal(w, { body: ownOpening(w, "a") });
  assert.equal(r.status, 409);
  assert.ok(r.body.error.startsWith("the case was withdrawn, so this reveal is refused and its tapes are never decoded or hashed; nothing was compared, " +
    "and nothing about the tapes is kept."), r.body.error);
  assert.doesNotMatch(r.body.error, /consent/i);
});

test("MUST-FAIL GAP (V03, V10): the withdrawn page's signed-by cell names the commit it verified under, and says when the named document could not be read", async () => {
  const w = await committedCase("RSIG gap V03");
  assert.equal((await withdraw(w.id, w.b)).status, 201);
  const rec = storedCase(w.id);
  const ok = cell((await casePage(w.id)).html, "signed by");
  assert.ok(ok.startsWith(`<code>${esc(rec.signed_by)}</code>, the signature verified under the key document this record names, at commit `), ok);
  assert.ok(ok.includes(rec.signed_under.document_commit.slice(0, 12)), ok);
  S._internal.clearDocumentCache();
  gh.forceRawFailure(1000, 503);
  let html;
  try {
    html = (await casePage(w.id)).html;
  } finally {
    gh.forceRawFailure(0);
  }
  const no = cell(html, "signed by");
  assert.equal(no, `<code>${esc(rec.signed_by)}</code>: the key document this record names could not be read when this page was read (http_503), ` +
    "so its signature is not confirmed");
});

test("MUST-FAIL GAP (V09): the does-not-verify page names the failed check in words for signature_invalid", async () => {
  const s = await sealedCase("RSIG gap V09");
  gh.seed(PINS, C.casePath(s.id), flipSig(storedCase(s.id)));
  const p = await casePage(s.id);
  assert.ok(cell(p.html, "the check that failed").startsWith(
    esc("the case signature: it is not confirmed under the verifier its signed_by names in the key document the case names")), p.html.slice(0, 600));
});

test("MUST-FAIL GAP (R03): the README says the page reads \"No reason was given.\" when a withdrawal names none", () => {
  assert.ok(README().includes("otherwise it has none, and the case page says \"No reason was given.\""));
});

// =============================================================================
// UNIT R-RVf3 (the R-SIG reader's items)
// =============================================================================

// 2 (T12). One key id under two verifiers: a 32-bit birthday search, found
// once offline and kept with how it was found (test/fixtures/
// key_id_collision.js). The current document's entry must carry the same
// verifier as the named one's, not only the same id.
const COLLISION = require("./fixtures/key_id_collision.json");
const COLLISION_SEARCH = require("./fixtures/key_id_collision.js");

test("R-RVf3 2 (T12): two keys sharing one key id are told apart by the full verifier: a record the first signed, under a document listing it, is signer_unlisted when the current document lists the second under that id", async () => {
  const [k1, k2] = COLLISION.keys;
  for (const k of COLLISION.keys) {
    const again = COLLISION_SEARCH.keyOf(k.counter);
    assert.deepEqual([again.signer, again.verifier], [k.signer, k.verifier], "the fixture is the search's own output");
    assert.equal(checkpoint.parseVerifierKey(k.verifier).ok, true);
  }
  assert.equal(KD.keyIdOf(k1), COLLISION.key_id);
  assert.equal(KD.keyIdOf(k2), COLLISION.key_id, "one key id");
  assert.notEqual(k1.verifier, k2.verifier, "two verifiers");
  const first = KD.docWith(KD.entry(k1), KD.reconcileEntry(RECEIPT_KEY));
  const second = KD.docWith(KD.entry(k2), KD.reconcileEntry(RECEIPT_KEY));
  assert.equal(S.checkKeyDocument(first).ok, true);
  assert.equal(S.checkKeyDocument(second).ok, true);
  const f = await fourRecords("RRVf3 T12");
  const signerOf = (k) => {
    const p = checkpoint.parseSignerKey(k.signer);
    return { keyId: `${p.name}+${p.hash}`, privateKey: p.privateKey };
  };
  const by1 = signByHand({ ...withoutSig(f.row), signed_under: suOf(first) }, signerOf(k1));
  const by2 = signByHand({ ...withoutSig(f.row), signed_under: suOf(second) }, signerOf(k2));
  assert.equal(by1.signed_by, by2.signed_by);
  assert.equal((await S.signedUnderReason(by1, "case", first)).code, "valid_under_document", "control");
  assert.equal((await S.signedUnderReason(by2, "case", second)).code, "valid_under_document", "control");
  assert.deepEqual(await S.signedUnderReason(by1, "case", second), { code: "signer_unlisted", reason: "case_key_not_listed", key_id: COLLISION.key_id });
  assert.deepEqual(await S.signedUnderReason(by2, "case", first), { code: "signer_unlisted", reason: "case_key_not_listed", key_id: COLLISION.key_id });
});

// 5a. A WITHDRAWN ROOT IS ACTED ON ONLY WHEN IT VERIFIES (the architect's
// ruling: fail closed): before a refusal receipt is signed or a retried
// withdrawal is answered, the withdrawal record goes through the one reader.
const caseSigner = () => S.loadCaseSigner(KEYS, { keyDocument: DOC });
// The withdrawal record re-signed naming a document commit no one serves:
// its named document cannot be read (could-not-look).
const namingNoDocument = (w) => signByHand({ ...withoutSig(w), signed_under: { ...w.signed_under, document_commit: "0".repeat(40) } }, caseSigner());
async function withdrawnBy(scope, role) {
  const c = await committedCase(scope);
  assert.equal((await withdraw(c.id, c[role])).status, 201);
  return c;
}

test("R-RVf3 5a: a refusal receipt is signed only from a withdrawal record that verifies: one whose signature does not verify is 409 signature_invalid, one whose named document cannot be read is 503 document_unavailable; neither carries a receipt", async () => {
  const bad = await withdrawnBy("RRVf3 5a receipt invalid", "b");
  gh.seed(PINS, C.casePath(bad.id), flipSig(storedCase(bad.id)));
  const r = await reveal(bad, { body: ownOpening(bad, "a") });
  assert.deepEqual([r.status, r.body.error_code, r.body.status], [409, "signature_invalid", "WITHDRAWN"], JSON.stringify(r.body).slice(0, 400));
  assert.equal(has(r.body, "refusal_receipt"), false);
  const away = await withdrawnBy("RRVf3 5a receipt unavailable", "b");
  gh.seed(PINS, C.casePath(away.id), namingNoDocument(storedCase(away.id)));
  const u = await reveal(away, { body: ownOpening(away, "a") });
  assert.deepEqual([u.status, u.body.error_code], [503, "document_unavailable"], JSON.stringify(u.body).slice(0, 400));
  assert.equal(has(u.body, "refusal_receipt"), false);
  // control: the record as written gives the receipt
  const good = await withdrawnBy("RRVf3 5a receipt control", "b");
  const g = await reveal(good, { body: ownOpening(good, "a") });
  assert.deepEqual([g.status, g.body.error_code, has(g.body, "refusal_receipt")], [409, "case_withdrawn", true]);
});

test("R-RVf3 5a: a retried withdrawal is answered only from a withdrawal record that verifies: 409 signature_invalid, or 503 document_unavailable; no marker is written and no record is answered", async () => {
  for (const [scope, plant, status, code] of [["invalid", flipSig, 409, "signature_invalid"], ["unavailable", namingNoDocument, 503, "document_unavailable"]]) {
    const c = await withdrawnBy(`RRVf3 5a retried ${scope}`, "b");
    gh.seed(PINS, C.casePath(c.id), plant(storedCase(c.id)));
    // the marker taken away: a retried withdrawal that is answered writes it again
    gh._repoMap(PINS).delete(C.withdrawnMarkerPath(c.id));
    const puts = gh.putLog.length;
    const r = await withdraw(c.id, c.b);
    assert.deepEqual([r.status, r.body.error_code], [status, code], `${scope}: ${JSON.stringify(r.body).slice(0, 400)}`);
    assert.equal(has(r.body, "case"), false, scope);
    assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c.id)), false, `${scope}: no marker`);
    assert.equal(gh.putLog.length, puts, `${scope}: nothing written`);
  }
  // control: the record as written is answered 200, and the marker written again
  const ok = await withdrawnBy("RRVf3 5a retried control", "b");
  gh._repoMap(PINS).delete(C.withdrawnMarkerPath(ok.id));
  const again = await withdraw(ok.id, ok.b);
  assert.deepEqual([again.status, again.body.existing], [200, true]);
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(ok.id)), true);
});

// 5b. The reference's own judge of the row it built reads the row's named
// document; when that read cannot be made, the answer is the retry-safe 503
// with codes only, never the 500 that says the service built a bad row.
test("R-RVf3 5b: the reference's pre-write judge that cannot read the row's named document answers 503 document_unavailable, codes only; nothing is written", async () => {
  const s = await sealedCase("RRVf3 5b");
  const listing = (u, m) => m === "GET" && decodeURIComponent(u).includes(`/repos/${PINS}/contents/${C.referencesDir(s.id)}`);
  const puts = gh.putLog.length;
  let r;
  let fired;
  try {
    ({ out: r, fired } = await during(listing, async () => {
      S._internal.clearDocumentCache();
      gh.forceRawFailure(1000, 503);
    }, () => reference(s)));
  } finally {
    gh.forceRawFailure(0);
  }
  assert.equal(fired, true, "fixture: the document went away after the sealed check");
  assert.deepEqual([r.status, r.body.error_code], [503, "document_unavailable"], JSON.stringify(r.body).slice(0, 400));
  assert.equal(has(r.body, "error"), false, "codes only");
  assert.doesNotMatch(JSON.stringify(r.body), /its own judge refuses|internal_error/);
  assert.equal(gh.putLog.length, puts, "nothing written");
  assert.equal(gh.has(PINS, C.referencePath(s.id, 1)), false);
  // sent again with the document back, the row is written
  assert.equal((await reference(s)).status, 201);
});

// 5c. A ROW AT VERSION 3 (the architect's ruling): read with its own
// reading, row_note_v3, and its signature verified; one whose signature
// does not verify reads signature_invalid. Neither is counted.
const V3_ANCHOR_NOTE = "This row has no pin of its own. It is recorded by the pins-repository commit that writes it. A later pin of the case " +
  "may list that commit. This row is anchored only if a pin that lists it is, and no anchoring is asserted here.";

test("R-RVf3 5c: a row at note_version 3 reads row_note_v3 only when its signature verifies; one whose signature does not verify reads signature_invalid; neither is counted", async () => {
  const f = await fourRecords("RRVf3 5c");
  const v3 = signByHand({ ...withoutSig(f.row), note_version: 3, anchor_note: V3_ANCHOR_NOTE }, caseSigner());
  assert.equal(C.validateReferenceRow(v3).code, "row_note_v3");
  const at = C.referencePath(f.s.id, 1);
  for (const [row, reason] of [[v3, "row_note_v3"], [flipSig(v3), "signature_invalid"]]) {
    gh.seed(PINS, at, row);
    const live = await S.liveRecords(f.seal, { keyDocument: DOC });
    assert.deepEqual([live.records, live.invalid.map((x) => ({ seq: x.seq, reason: x.reason }))], [1, [{ seq: 1, reason }]], `${reason}: ${JSON.stringify(live)}`);
  }
});

// R-RVf3's must-fail gap tests: each fails with its planted defect
test("MUST-FAIL GAP (W11): the 5a refusals carry the reader's reason", async () => {
  const bad = await withdrawnBy("RRVf3 gap W11 invalid", "b");
  gh.seed(PINS, C.casePath(bad.id), flipSig(storedCase(bad.id)));
  assert.equal((await reveal(bad, { body: ownOpening(bad, "a") })).body.reason, "bad_signature");
  const away = await withdrawnBy("RRVf3 gap W11 unavailable", "b");
  gh.seed(PINS, C.casePath(away.id), namingNoDocument(storedCase(away.id)));
  assert.equal((await withdraw(away.id, away.b)).body.reason, "commit_not_on_branch");
});

test("MUST-FAIL GAP (B05): a pre-write judge refusal that is not a could-not-look stays 500 internal_error (a row dated before the seal); nothing is written", async () => {
  const s = await sealedCase("RRVf3 gap B05");
  const puts = gh.putLog.length;
  const r = await reference(s, { now: REVEAL_AT - 60000 });
  assert.deepEqual([r.status, r.body.error_code, r.body.reason], [500, "internal_error", "reference_before_seal"], JSON.stringify(r.body).slice(0, 300));
  assert.equal(gh.putLog.length, puts);
});

test("MUST-FAIL GAP (V01): a version-3 row whose other fields do not read as a row's reads by its form, never row_note_v3, and is not counted", async () => {
  const f = await fourRecords("RRVf3 gap V01");
  const v3 = signByHand({ ...withoutSig(f.row), note_version: 3, anchor_note: V3_ANCHOR_NOTE }, caseSigner());
  const { signed_under: _su, ...noDocument } = v3; // eslint-disable-line no-unused-vars
  assert.equal(C.validateReferenceRow(noDocument).code, "missing_field");
  gh.seed(PINS, C.referencePath(f.s.id, 1), noDocument);
  const live = await S.liveRecords(f.seal, { keyDocument: DOC });
  assert.deepEqual([live.records, live.invalid.map((x) => x.reason)], [1, ["reference_missing_field"]], JSON.stringify(live));
});
