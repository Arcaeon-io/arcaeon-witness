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
