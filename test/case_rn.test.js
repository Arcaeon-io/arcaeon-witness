// test/case_rn.test.js — unit R-N (2026-10-13): one signature rule
// everywhere, the refusal receipt made real, the reconcile bypass closed, and
// the withdrawal lease made honest. A second reader's pass over Design N and
// red-team fixes C, D and E found:
//
//   BLOCKER  an unsigned refusal receipt went out under a 409 that said it
//            was signed, and its sig_reason named environment variables to
//            an anonymous caller.
//   MAJOR    ?op=reconcile compared any two tapes, a withdrawn one included,
//            and returned a receipt signed by the reconcile key.
//   MAJOR    unsigned reference rows were counted as records, shown as "two
//            records", and written when the signer failed.
//   MAJOR    fix C: a failed DELETE left the file standing for good while the
//            answer said registration_recorded: false; a failed read after
//            the write left the registration standing on an assumption; the
//            lease clock was stale.
//   MINORS   publishedSignatureReason ignored key role; the refusal receipt
//            bound nothing; the race branch said the tapes were not read; a
//            retried withdrawal was 409; a failed marker was never
//            rewritten; fix E's trace lived only in git history; a reference
//            skipped the anchor-conflict check; the §2B todos asserted the
//            opposite of a closed decision.
//
// The binding decisions (N1-N4, C1-C3, E1, D1, T1) and the owner's four
// answers of 2026-10-13: C1 deletes only a registration whose creating
// commit comes after the withdrawal's; the lease race writes no log event;
// the refusal names the requester by a `role` field; the withdrawn tape is
// recorded at withdrawn_commitments/<sha256(tape_sha256)>.json.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0081:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rn");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rn");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rn");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0081" });

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
  return `10.93.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
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
function party(caseId, role, tape) {
  const salt = C.newSalt();
  const tape_sha256 = sha(tape);
  return { role, tape, tape_sha256, salt, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
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
async function commit(id, p, now = NOW, extra = {}) {
  const res = makeRes();
  await H.handleCaseCommit(req("case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 })), res, { now, ...extra });
  return { status: res._status, body: parsed(res) };
}
async function register(id, p) {
  plantStamp(p.commitment_sha256);
  const r = await commit(id, p);
  assert.equal(r.status, 201, JSON.stringify(r.body));
}
async function withdraw(id, p, { now = NOW + 2000, env = KEYS, salt = p.salt } = {}) {
  const res = makeRes();
  await H.handleCaseWithdraw(req("case-withdraw", { case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt }), res, { now, env, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
async function committedCase(scope) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
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
async function sealedCase(scope) {
  const c = await committedCase(scope);
  const r = await reveal(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  return c;
}
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0081", url: "https://second-operator.example/cases/0081" });
async function reference(c, { role = "a", env = KEYS, now = REVEAL_AT + 1800000 } = {}) {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: XREF }),
    res, { now, env, keyDocument: DOC });
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
// The race lost after the write (the commit's lease ran out and the
// withdrawal took it over), the removal refused when `deleteFails`.
async function lostRace(scope, { deleteFails = false } = {}) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const rpath = C.registrationPath(id, "b");
  const late = NOW + 1000 + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000;
  const viaMock = global.fetch;
  if (deleteFails) {
    global.fetch = async (url, o) => ((o && o.method) === "DELETE" ? { ok: false, status: 500, json: async () => ({}), text: async () => "" } : viaMock(url, o));
  }
  let r;
  try {
    r = await during(
      (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
      () => withdraw(id, a, { now: late }),
      () => commit(id, b, NOW + 1000),
    );
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body));
  assert.equal(r.out.body.error_code, "case_withdrawn", JSON.stringify(r.out.body));
  return { id, a, b, rpath, out: r.out.body };
}
const storedCase = (id) => gh.read(PINS, C.casePath(id));
const lockOf = (id) => gh.read(USAGE, H._internal.caseLockPath(id));
const logFiles = (id) => [...gh.repos.get(PINS).keys()].filter((p) => p.startsWith(`${C.caseLogDir(id)}/`)).sort();
const pinsText = () => [...gh.repos.get(PINS).values()].map((r) => r.content).join("\n");
const sealerRun = (dt = 60000) => S.anchorPending({ now: REVEAL_AT + 3600000 + dt, keyDocument: DOC });
// N2: the sha256 of the digest's 32 bytes, as a salt is kept (lib/_case.js saltSha256)
// The case key revoked (unit R-I): the current document, its marker, the tool.
const CASE_REVOKED = Object.freeze(KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11" }), KD.reconcileEntry(RECEIPT_KEY)));
const revokedDoc = () => CASE_REVOKED;
const TOOL = { recordRevocation: (...args) => require("../tools/record_key_revocation.js").recordRevocation(...args) };
const markerFor = (W) => ({ kind: "key-revocation", v: 1, key_id: KD.keyIdOf(CASE_KEY), key_fingerprint: S.keyFingerprint(CASE_KEY.verifier), revoked_in_commit: W });
async function revoke() {
  const W = KD.serve(gh, CASE_REVOKED);
  const out = await TOOL.recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: CASE_REVOKED, write: true });
  assert.equal(out.ok, true, JSON.stringify(out));
  return { W, R: out.commit, path: out.path };
}
const withdrawnCommitmentPath = (tapeSha256) => `withdrawn_commitments/${sha(Buffer.from(tapeSha256, "hex"))}.json`;

// =============================================================================
// N1: one signature rule everywhere; the refusal receipt is signed or not issued
// =============================================================================

test("R-N N1 (BLOCKER): with no reconcile signer the refusal is 503 signer_unavailable: no receipt, no 409 claiming one, and the body names no environment variable", async () => {
  const c = await committedCase("RN no signer");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const writes = gh.putLog.length;
  const cases = [
    ["no reconcile key set", { [S.CASE_SIGNER_ENV]: CASE_KEY.signer }, DOC],
    ["a reconcile key that does not parse", { ...KEYS, [receipts.SIGNER_ENV]: "not a key" }, DOC],
    ["a reconcile key the document carries does not list", KEYS, KD.docWith(KD.entry(CASE_KEY))],
  ];
  for (const [name, env, keyDocument] of cases) {
    const r = await reveal(c, { env, keyDocument, body: ownOpening(c, "a") });
    assert.deepEqual([r.status, r.body.error_code], [503, "signer_unavailable"], `${name}: ${JSON.stringify(r.body).slice(0, 300)}`);
    assert.equal(has(r.body, "refusal_receipt"), false, name);
    assert.doesNotMatch(JSON.stringify(r.body), /WITNESS_|_KEY\b|SIGNER_KEY|is not set/, `${name}: no environment variable named`);
  }
  assert.deepEqual(gh.putLog.slice(writes), [], "nothing written");
});

test("R-N N1, N3: a refusal on a withdrawn case with the requester's own valid opening carries a receipt signed by the reconcile key, naming the requester's role and commitment and signed_under; it verifies under the named document the way a seal does", async () => {
  const c = await committedCase("RN receipt");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const record = storedCase(c.id);
  const writes = gh.putLog.length;
  const r = await reveal(c, { body: ownOpening(c, "a") });
  assert.equal(r.status, 409, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.error_code, "case_withdrawn");
  const rr = r.body.refusal_receipt;
  assert.deepEqual(Object.keys(rr).sort(),
    ["at", "case_id", "commitment_sha256", "kind", "reason", "role", "sig", "sig_reason", "signed_by", "signed_under", "v"]);
  assert.deepEqual([rr.kind, rr.v, rr.case_id, rr.at, rr.reason, rr.role, rr.commitment_sha256, rr.sig_reason],
    ["comparison_refused", 1, c.id, C.utcSeconds(REVEAL_AT), "consent_not_jointly_held", "a", c.a.commitment_sha256, null]);
  assert.equal(rr.signed_by, KD.keyIdOf(RECEIPT_KEY), "the reconcile key");
  assert.deepEqual(rr.signed_under, { document_sha256: KD.sha256(canonicalBytes(DOC)), document_commit: KD.commitOf(DOC), retrieved_at: C.utcSeconds(REVEAL_AT) });
  assert.deepEqual(await S.verifyRefusalReceipt(rr, DOC), { ok: true });
  // bound: another role, another commitment, another time do not verify
  for (const forged of [{ ...rr, role: "b" }, { ...rr, commitment_sha256: c.b.commitment_sha256 }, { ...rr, at: C.utcSeconds(REVEAL_AT + 1000) }]) {
    assert.equal((await S.verifyRefusalReceipt(forged, DOC)).reason, "bad_signature");
  }
  // under the NAMED document: a commit off the published branch is not a document, and a sha256 that is not the commit's is not it
  const off = KD.serveOffBranch(gh, DOC, "4".repeat(40));
  assert.equal((await S.verifyRefusalReceipt({ ...rr, signed_under: { ...rr.signed_under, document_commit: off } }, DOC)).reason, "document_not_on_branch");
  assert.equal((await S.verifyRefusalReceipt({ ...rr, signed_under: { ...rr.signed_under, document_sha256: "e".repeat(64) } }, DOC)).reason, "document_sha256_mismatch");
  // a key the CURRENT document does not list in its role, or lists revoked, does not hold
  assert.equal((await S.verifyRefusalReceipt(rr, KD.docWith(KD.entry(CASE_KEY)))).reason, "signer_unlisted");
  assert.equal((await S.verifyRefusalReceipt(rr, KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY, { status: "revoked", revokedSince: "2026-10-11" })))).reason,
    "signer_revoked");
  // nothing changes anywhere
  assert.deepEqual(gh.putLog.slice(writes), []);
  assert.deepEqual(storedCase(c.id), record);
});

test("R-N N1: ONE SIGNATURE RULE: a case-role key never verifies a refusal receipt, and a reconcile-role key never verifies a reference row (publishedSignatureReason filters by role)", async () => {
  const at = C.utcSeconds(REVEAL_AT);
  const signedUnder = KD.signedUnder(gh, DOC, at);
  const byCase = S.refusalReceipt({ caseId: "c".repeat(64), at, role: "a", commitmentSha256: "d".repeat(64), signedUnder }, S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  assert.equal(byCase.signed_by, KD.keyIdOf(CASE_KEY));
  assert.equal((await S.verifyRefusalReceipt(byCase, DOC)).reason, "signer_unpublished", "a case key is not a reconcile key");
  const row = S.referenceRow({ caseId: "c".repeat(64), seq: 1, crossReference: XREF, recordedAt: at, appendedBy: "operator" },
    S.loadReconcileSigner(KEYS, { keyDocument: DOC }));
  assert.equal(row.signed_by, KD.keyIdOf(RECEIPT_KEY));
  assert.equal(S.publishedSignatureReason(row, DOC), "signer_unpublished", "a reconcile key is not a case key");
  assert.equal(S.publishedSignatureReason(row, DOC, "reconcile"), null, "control: in its own role it verifies");
  const p = C.referencePath("c".repeat(64), 1);
  assert.equal(S.judgeReferenceRow({ json: row }, { path: p, caseId: "c".repeat(64), seq: 1, sealed: null, keyDocument: DOC }).reason,
    "reference_signature_signer_unpublished");
});

test("R-N N1: an unsigned reference row is not a record: the reference refuses 503 signer_unavailable rather than write one (no row, no quota), and a stored unsigned row is not counted and not shown as a record", async () => {
  const c = await sealedCase("RN unsigned row");
  await sealerRun();
  const r = await reference(c, { env: { [receipts.SIGNER_ENV]: RECEIPT_KEY.signer } });
  assert.deepEqual([r.status, r.body.error_code], [503, "signer_unavailable"], JSON.stringify(r.body));
  assert.doesNotMatch(JSON.stringify(r.body), /WITNESS_|is not set/);
  assert.equal(gh.has(PINS, C.referencePath(c.id, 1)), false, "no row");
  assert.equal(gh.has(USAGE, H._internal.referenceQuotaPath(c.id, "a")), false, "no unit of the quota spent");
  // a row stored unsigned (planted: written by an earlier build)
  const unsigned = S.referenceRow({ caseId: c.id, seq: 1, crossReference: XREF, recordedAt: C.utcSeconds(REVEAL_AT + 1800000), appendedBy: "role:a" },
    S.loadCaseSigner({}, { keyDocument: DOC }));
  assert.equal(unsigned.sig, null, "fixture: unsigned");
  gh.seed(PINS, C.referencePath(c.id, 1), unsigned);
  const p = C.referencePath(c.id, 1);
  assert.equal(S.judgeReferenceRow({ json: unsigned }, { path: p, caseId: c.id, seq: 1, sealed: storedCase(c.id), keyDocument: DOC }).reason, "row_unsigned");
  const live = await S.liveRecords(storedCase(c.id), { keyDocument: DOC });
  assert.equal(live.records, 1, "not counted");
  assert.deepEqual(live.invalid, [{ seq: 1, reason: "row_unsigned" }]);
  const page = await casePage(c.id);
  assert.ok(!page.html.includes("two records"), "never two records for it");
  assert.match(page.html, /one record/);
});

test("R-N N1: ONE SIGNATURE RULE: a withdrawal is written signed or not at all: without a case key the document lists it is 503 signer_unavailable and nothing is withdrawn", async () => {
  const c = await committedCase("RN unsigned withdrawal");
  const before = storedCase(c.id);
  const w = await withdraw(c.id, c.b, { env: { [receipts.SIGNER_ENV]: RECEIPT_KEY.signer } });
  assert.deepEqual([w.status, w.body.error_code], [503, "signer_unavailable"], JSON.stringify(w.body));
  assert.doesNotMatch(JSON.stringify(w.body), /WITNESS_|is not set/);
  assert.deepEqual(storedCase(c.id), before);
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c.id)), false);
  assert.equal(gh.has(PINS, withdrawnCommitmentPath(c.b.tape_sha256)), false);
});

// =============================================================================
// N2: ?op=reconcile refuses a withdrawn tape
// =============================================================================

test("R-N N2: the withdrawal records the withdrawer's tape digest at withdrawn_commitments/<sha256(tape_sha256)>.json, holding only {withdrawn_at}; ?op=reconcile reads that path once per tape and refuses 409 consent_withdrawn for either tape, naming no case and issuing no receipt", async () => {
  const c = await committedCase("RN reconcile");
  const w = await withdraw(c.id, c.b);
  assert.equal(w.status, 201, JSON.stringify(w.body));
  const listed = withdrawnCommitmentPath(c.b.tape_sha256);
  assert.deepEqual(gh.read(PINS, listed), { listed_at: storedCase(c.id).withdrawal.at }, "unit R-N3 (N4): listed_at");
  assert.equal(w.body.withdrawn_commitment, "written");
  assert.equal(gh.has(PINS, withdrawnCommitmentPath(c.a.tape_sha256)), false, "only the withdrawer's digest is known");
  for (const [x, y] of [[AGENT_TAPE, TOOL_TAPE], [TOOL_TAPE, AGENT_TAPE]]) {
    const g0 = gh.getLog.length;
    const r = await reconcileCall(x, y);
    assert.deepEqual([r.status, r.body.error_code], [409, "consent_withdrawn"], JSON.stringify(r.body).slice(0, 300));
    assert.equal(has(r.body, "receipt") || has(r.body, "verdict"), false, "no receipt, no verdict");
    assert.ok(!JSON.stringify(r.body).includes(c.id), "names no case");
    const reads = gh.getLog.slice(g0).filter((p) => p.startsWith("withdrawn_commitments/"));
    assert.deepEqual(reads.sort(), [withdrawnCommitmentPath(sha(x)), withdrawnCommitmentPath(sha(y))].sort(), "one read per tape");
  }
  // control: two tapes neither withdrawn compare
  const ok = await reconcileCall(AGENT_TAPE, AGENT_TAPE);
  assert.equal(ok.status, 200, JSON.stringify(ok.body).slice(0, 300));
  assert.ok(ok.body.receipt);
  // a consent read that fails is not a yes: 503, nothing compared
  gh.forceGetFailure(PINS, withdrawnCommitmentPath(sha(AGENT_TAPE)), 1, 503);
  const u = await reconcileCall(AGENT_TAPE, AGENT_TAPE);
  assert.deepEqual([u.status, u.body.error_code], [503, "consent_unreadable"]);
  assert.equal(has(u.body, "receipt"), false);
});

// =============================================================================
// N3: the refusal reads one role's opening, the requester's own
// =============================================================================

test("R-N N3: without a valid own opening the refusal is 404 not_a_party, with no receipt and no change anywhere", async () => {
  const c = await committedCase("RN not a party");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const writes = gh.putLog.length;
  const base = revealBody(c.id, c.a, c.b);
  const bodies = [
    ["no role named", base],
    ["an unknown role", { ...base, role: "c" }],
    ["the other role's opening under its own name", { ...base, role: "a", reveals: { a: base.reveals.b, b: base.reveals.b } }],
    ["a salt that is not its own", { ...base, role: "a", reveals: { ...base.reveals, a: { ...base.reveals.a, salt: C.newSalt() } } }],
    ["no opening for the named role", { ...base, role: "a", reveals: { b: base.reveals.b } }],
    ["an opening that is not one", { ...base, role: "a", reveals: { a: "open sesame" } }],
    ["no reveals at all", { case_id: c.id, role: "a" }],
  ];
  for (const [name, body] of bodies) {
    const r = await reveal(c, { body });
    assert.deepEqual([r.status, r.body.error_code], [404, "not_a_party"], `${name}: ${JSON.stringify(r.body).slice(0, 300)}`);
    assert.equal(has(r.body, "refusal_receipt"), false, name);
  }
  assert.deepEqual(gh.putLog.slice(writes), [], "no change anywhere");
});

test("R-N N3: the counterparty's opening is never read or hashed: the hasher never sees its tape hash or salt, and a malformed counterparty entry changes nothing", async (t) => {
  const c = await committedCase("RN never hashed");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const hasher = t.mock.method(C, "commitmentSha256");
  const decode = t.mock.method(RECONCILE, "tapeFrom");
  const r = await reveal(c, { body: ownOpening(c, "a") });
  assert.equal(r.status, 409, JSON.stringify(r.body).slice(0, 300));
  assert.ok(r.body.refusal_receipt);
  const seen = JSON.stringify(hasher.mock.calls.map((x) => x.arguments));
  assert.ok(seen.includes(c.a.salt), "the requester's own opening is hashed");
  assert.ok(!seen.includes(c.b.salt) && !seen.includes(c.b.tape_sha256), "the counterparty's never is");
  assert.equal(decode.mock.callCount(), 0, "no tape is decoded");
  const body = { ...ownOpening(c, "a"), reveals: { a: { tape_sha256: c.a.tape_sha256, salt: c.a.salt }, b: { tape_sha256: "not hex", salt: 7, extra: true } } };
  const r2 = await reveal(c, { body });
  assert.equal(r2.status, 409, JSON.stringify(r2.body).slice(0, 300));
  assert.equal(r2.body.refusal_receipt.role, "a");
});

test("R-N N3, C1: a registration written after the withdrawal does not stand: its role is not a party to a refusal (404 not_a_party), while the role registered before it is", async () => {
  const x = await lostRace("RN post-withdrawal party", { deleteFails: true });
  assert.equal(gh.has(PINS, x.rpath), true, "fixture: the late registration file is there");
  const c = { id: x.id, a: x.a, b: x.b };
  const late = await reveal(c, { body: ownOpening(c, "b") });
  assert.deepEqual([late.status, late.body.error_code], [404, "not_a_party"], JSON.stringify(late.body).slice(0, 300));
  const early = await reveal(c, { body: ownOpening(c, "a") });
  assert.equal(early.status, 409, JSON.stringify(early.body).slice(0, 300));
  assert.equal(early.body.refusal_receipt.role, "a");
});

// =============================================================================
// N4: the lease race says what is true and writes no hash and no log
// =============================================================================

test("R-N N4: a withdrawal that lands after the reveal hashed its tapes, before its attempt: refused in true words, no hash written, and no receipt", async (t) => {
  const c = await committedCase("RN race");
  const compare = t.mock.method(RECONCILE, "compare");
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(c.id)}`),
    () => withdraw(c.id, c.b, { now: REVEAL_AT - 1000 }),
    () => reveal(c),
  );
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body));
  assert.deepEqual([r.out.status, r.out.body.error_code], [409, "case_withdrawn"], JSON.stringify(r.out.body).slice(0, 300));
  // unit R-N2 (m4): the words
  assert.equal(r.out.body.error, "Refused. A withdrawal landed while this reveal was in progress. Nothing computed from the tapes is kept.");
  assert.equal(has(r.out.body, "refusal_receipt"), false);
  assert.equal(compare.mock.callCount(), 0, "nothing compared");
  const input = C.revealInputSha256({ case_id: c.id, policy_version: C.SUPPORTED_POLICY_VERSION, tape_sha256: { a: c.a.tape_sha256, b: c.b.tape_sha256 } });
  const text = pinsText();
  for (const h of [c.a.tape_sha256, input]) assert.ok(!text.includes(h), "no hash written");
  assert.equal(storedCase(c.id).status, "WITHDRAWN");
});

test("R-N N4: the commit's lost race writes no case log event: the removal's commit, whose message names the reason, is the only trace", async () => {
  const x = await lostRace("RN no log");
  assert.deepEqual(logFiles(x.id), [], "no public entry on the withdrawn case");
  assert.equal(has(x.out, "log_event"), false);
  assert.equal(x.out.registration_removed, true);
  assert.match(gh.commitsFor(PINS, x.rpath)[0].message, /written after the withdrawal, removed/);
});

// =============================================================================
// C1, C2: a registration never stands after a withdrawal, nor on an assumption
// =============================================================================

test("R-N C1: a late registration whose removal fails: registration_recorded true while the file is there; the sealer's withdrawn path removes it (one compare read), keeps the registration from before the withdrawal, and says so", async () => {
  const x = await lostRace("RN repair", { deleteFails: true });
  assert.equal(x.out.registration_removed, false);
  assert.equal(x.out.registration_recorded, true, "the file's real state");
  assert.equal(gh.has(PINS, x.rpath), true);
  const page = await casePage(x.id);
  assert.match(page.html, /does not stand/, "the page says a registration under a withdrawn case does not stand");
  const c0 = gh.compareLog.length;
  const run = await sealerRun();
  assert.equal(gh.has(PINS, x.rpath), false, "removed by the sealer's repair");
  assert.equal(gh.has(PINS, C.registrationPath(x.id, "a")), true, "the registration from before the withdrawal stays");
  const entry = run.withdrawn_repaired.find((e) => e.case_id === x.id);
  assert.ok(entry, JSON.stringify(run.withdrawn_repaired));
  assert.deepEqual([entry.removed, entry.kept], [["b"], ["a"]]);
  assert.ok(gh.compareLog.slice(c0).filter((k) => k.startsWith(`${PINS}:`)).length >= 2, "one compare read per registration");
  assert.match(gh.commitsFor(PINS, x.rpath)[0].message, /written after the withdrawal, removed/);
  // a second run removes nothing more
  const again = await sealerRun(120000);
  const e2 = again.withdrawn_repaired.find((e) => e.case_id === x.id);
  assert.deepEqual(e2 ? e2.removed : [], []);
});

test("R-N C1: the sealer's withdrawn path rewrites a withdrawn marker that failed", async () => {
  const c = await committedCase("RN sealer marker");
  const mpath = C.withdrawnMarkerPath(c.id);
  gh.forceFailure(PINS, mpath, 1, 502);
  const w = await withdraw(c.id, c.b);
  assert.deepEqual([w.status, w.body.marker], [201, "failed"]);
  assert.equal(gh.has(PINS, mpath), false);
  const run = await sealerRun();
  assert.deepEqual(gh.read(PINS, mpath), { kind: "case-withdrawn-marker", v: 1, case_id: c.id, withdrawn_at: storedCase(c.id).withdrawal.at });
  const entry = run.withdrawn_repaired.find((e) => e.case_id === c.id);
  assert.equal(entry.marker, "written");
});

test("R-N C2: a case that cannot be read after the registration's write: the registration is unwound (removed) and the answer is 503; the same registration again registers", async () => {
  const id = await openCase("RN after read");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const rpath = C.registrationPath(id, "a");
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
    async () => gh.forceGetFailure(PINS, C.casePath(id), 1, 503),
    () => commit(id, a),
  );
  assert.deepEqual([r.out.status, r.out.body.error_code], [503, "registration_unconfirmed"], JSON.stringify(r.out.body));
  assert.equal(r.out.body.registration_recorded, false);
  assert.equal(r.out.body.registration_removed, true);
  assert.equal(gh.has(PINS, rpath), false, "never stands on an assumption");
  assert.equal(gh.commitsFor(PINS, rpath).length, 2, "written, then removed");
  assert.equal(lockOf(id).state, "released");
  const again = await commit(id, a);
  assert.equal(again.status, 201, JSON.stringify(again.body));
});

// =============================================================================
// C3: the lease clock; a retried withdrawal
// =============================================================================

test("R-N C3: the lease clock is read at acquisition and on each wait: a lease that runs out while the request waits is taken, not reported busy, and the new lease expires 30 s after its own acquisition", async () => {
  const id = await openCase("RN lease");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const T = NOW + 1000;
  gh.seed(USAGE, H._internal.caseLockPath(id), { kind: "case-lock", v: 1, case_id: id, holder: "someone-else", op: "commit",
    acquired_at: new Date(T - 28500).toISOString(), expires_at: new Date(T + 1500).toISOString(), state: "held" });
  let t = T;
  store._putRetry.sleep = async (ms) => { t += ms; };
  const r = await commit(id, a, T, { clock: () => t });
  assert.equal(r.status, 201, `an expired lease is not busy: ${JSON.stringify(r.body)}`);
  const lock = lockOf(id);
  assert.equal(lock.acquired_at, new Date(T + 2000).toISOString(), "acquired after two waits, by the clock then");
  assert.equal(Date.parse(lock.expires_at) - Date.parse(lock.acquired_at), H.CASE_LOCK_TTL_SECONDS * 1000);
  assert.equal(r.body.registration.registered_at, C.utcSeconds(T), "the registration keeps the request's time");
});

test("R-N C3: a retried withdrawal (the same role and preimage) is idempotent 200 and rewrites a marker that failed (since unit R-N2, B1, a listing that fails is 503 before the record, test/case_rn2.test.js); another role or another salt is still 409", async () => {
  const c = await committedCase("RN retry");
  const mpath = C.withdrawnMarkerPath(c.id);
  const lpath = withdrawnCommitmentPath(c.b.tape_sha256);
  gh.forceFailure(PINS, mpath, 1, 502);
  const w = await withdraw(c.id, c.b);
  assert.equal(w.status, 201, JSON.stringify(w.body));
  assert.deepEqual([w.body.marker, w.body.withdrawn_commitment], ["failed", "written"]);
  const record = storedCase(c.id);
  const again = await withdraw(c.id, c.b, { now: NOW + 5000 });
  assert.equal(again.status, 200, JSON.stringify(again.body));
  assert.equal(again.body.existing, true);
  assert.deepEqual([again.body.marker, again.body.withdrawn_commitment], ["written", "existing"]);
  assert.deepEqual(gh.read(PINS, lpath), { listed_at: record.withdrawal.at }, "first written with the withdrawal (unit R-N3, N4)");
  assert.deepEqual(storedCase(c.id), record, "the withdrawal record is not written again");
  const third = await withdraw(c.id, c.b, { now: NOW + 6000 });
  assert.deepEqual([third.status, third.body.marker, third.body.withdrawn_commitment], [200, "existing", "existing"]);
  const other = await withdraw(c.id, c.a, { now: NOW + 7000 });
  assert.deepEqual([other.status, other.body.error_code], [409, "case_withdrawn"]);
  const salted = await withdraw(c.id, c.b, { now: NOW + 8000, salt: C.newSalt() });
  assert.deepEqual([salted.status, salted.body.error_code], [409, "case_withdrawn"]);
});

// =============================================================================
// E1: reveal_attempts, append-only, in the sealed base
// =============================================================================

// A reveal whose seal write (the second PUT of the case file) fails.
async function revealSealFails(c, now) {
  let puts = 0;
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    if ((o && o.method) === "PUT" && String(url).includes(`/repos/${PINS}/contents/${C.casePath(c.id)}`) && ++puts === 2) gh.forceFailure(PINS, C.casePath(c.id), 1, 502);
    return viaMock(url, o);
  };
  try {
    return await reveal(c, { now });
  } finally {
    global.fetch = viaMock;
  }
}

test("R-N E1: reveal_attempts is append-only and part of the sealed base: two failed reveals then one that seals leave every attempt and every failure, in order, inside the sealed record's signature", async () => {
  const c = await committedCase("RN attempts");
  const T1 = REVEAL_AT;
  const T2 = REVEAL_AT + 60000;
  const T3 = REVEAL_AT + 120000;
  const policy = storedCase(c.id).policy_version;
  const attempt = (at) => ({ event: "attempt", commitments: { a: c.a.commitment_sha256, b: c.b.commitment_sha256 },
    input_sha256: C.revealInputSha256({ case_id: c.id, policy_version: policy, tape_sha256: { a: c.a.tape_sha256, b: c.b.tape_sha256 } }), at: C.utcSeconds(at) });
  const failure = (at) => ({ event: "failure", reason: "case_seal_failed", at: C.utcSeconds(at) });
  assert.equal((await revealSealFails(c, T1)).status, 503);
  assert.deepEqual(storedCase(c.id).reveal_attempts, [attempt(T1), failure(T1)]);
  assert.equal(has(storedCase(c.id), "reveal_attempt") || has(storedCase(c.id), "reveal_failure"), false, "the old single fields are gone");
  assert.equal((await revealSealFails(c, T2)).status, 503);
  assert.deepEqual(storedCase(c.id).reveal_attempts, [attempt(T1), failure(T1), attempt(T2), failure(T2)], "nothing replaced");
  const page = await casePage(c.id);
  assert.match(page.html, /2 joint reveal attempts/);
  const sealed = await reveal(c, { now: T3 });
  assert.equal(sealed.status, 201, JSON.stringify(sealed.body).slice(0, 300));
  const k = storedCase(c.id);
  assert.equal(k.status, "VERDICT");
  assert.deepEqual(k.reveal_attempts, [attempt(T1), failure(T1), attempt(T2), failure(T2), attempt(T3)]);
  assert.equal((await S.sealedRecordReason(k, DOC)).code, "valid_under_document");
  const trimmed = { ...k, reveal_attempts: k.reveal_attempts.slice(4) };
  assert.deepEqual(C.validateCase(trimmed), { ok: true }, "fixture: still a valid record");
  assert.deepEqual(await S.sealedRecordReason(trimmed, DOC), { code: "case_signature_invalid", reason: "bad_signature" }, "the attempts are signed");
});

test("R-N E1: the schema: reveal_attempts only on COMMITTED or VERDICT, entries an attempt or a failure, a failure only right after an attempt, an attempt's commitments the case's own, and a VERDICT's last entry the attempt that sealed it", async () => {
  const c = await committedCase("RN attempts schema");
  const k = storedCase(c.id);
  const att = { event: "attempt", commitments: { a: c.a.commitment_sha256, b: c.b.commitment_sha256 }, input_sha256: "e".repeat(64), at: "2026-10-10T09:00:00Z" };
  const fail = { event: "failure", reason: "case_seal_failed", at: "2026-10-10T09:00:00Z" };
  for (const list of [[att], [att, fail], [att, fail, att], [att, att]]) assert.deepEqual(C.validateCase({ ...k, reveal_attempts: list }), { ok: true });
  const bad = [
    [[], "malformed_field", "reveal_attempts"],
    [[fail], "status_inconsistent", "reveal_attempts.0"],
    [[att, fail, fail], "status_inconsistent", "reveal_attempts.2"],
    [[{ ...att, event: "retry" }], "malformed_field", "reveal_attempts.0.event"],
    [[{ ...att, commitments: { a: c.b.commitment_sha256, b: c.a.commitment_sha256 } }], "status_inconsistent", "reveal_attempts.0.commitments"],
    [[{ ...att, extra: 1 }], "unknown_field", "reveal_attempts.0.extra"],
    [[att, { ...fail, reason: "bad luck" }], "malformed_field", "reveal_attempts.1.reason"],
  ];
  for (const [list, code, field] of bad) {
    const v = C.validateCase({ ...k, reveal_attempts: list });
    assert.deepEqual([v.code, v.field], [code, field], JSON.stringify(v));
  }
  assert.equal(C.validateCase({ ...k, reveal_attempt: att }).code, "unknown_field", "the single field is gone");
  const open = await openCase("RN attempts schema open");
  assert.equal(C.validateCase({ ...storedCase(open), reveal_attempts: [att] }).code, "status_inconsistent");
});

// =============================================================================
// D1: the reference runs the anchor-conflict check
// =============================================================================

test("R-N D1: a reference row runs the anchor-conflict check before it takes a row: a daily anchor record whose head holds another chain for the pin is 409 anchor_conflict, with no row and no quota", async () => {
  const c = await sealedCase("RN anchor conflict");
  const { seq } = S.pinPaths(c.id);
  const ours = gh.read(PINS, seq);
  const set = (rec) => {
    gh._repoMap(PINS).get(seq).content = JSON.stringify(rec, null, 2) + "\n";
    return gh.addCommit(PINS, seq, "mock: the numbered pin record rewritten");
  };
  const other = set({ ...ours, chain: sha("another chain") });
  const day = gh.commitsFor(PINS, seq).slice(-1)[0].date.slice(0, 10);
  gh.seedText(PINS, `anchors/${day}-head.txt`, `${other} ${day}T03:15:00+00:00\n`);
  set(ours);
  const r = await reference(c);
  assert.deepEqual([r.status, r.body.error_code], [409, "anchor_conflict"], JSON.stringify(r.body).slice(0, 300));
  assert.equal(gh.has(PINS, C.referencePath(c.id, 1)), false);
  assert.equal(gh.has(USAGE, H._internal.referenceQuotaPath(c.id, "a")), false);
});

// =============================================================================
// T1: the §2B todos are plain assertions now
// =============================================================================

test("R-N T1: the §2B todos are plain passing assertions in test/case_redteam.test.js, and the §4 cost todo stays (since unit R-N2 beside the M2 open question)", () => {
  const text = fs.readFileSync(path.join(__dirname, "case_redteam.test.js"), "utf8");
  const todos = [...text.matchAll(/\{ todo: "([^"]*)"/g)].map((m) => m[1]);
  assert.equal(todos.length, 2, JSON.stringify(todos));
  assert.ok(todos.some((t) => /reads 20 rows/.test(t)), "the §4 cost todo");
  assert.ok(todos.some((t) => /a digest already published in a sealed case can still be listed by a stranger/.test(t)), "the M2 open question");
});

// =============================================================================
// UNIT R-N: the must-fail pass's gaps (each test kills a planted defect the
// tests above let through; the ids are the pass's)
// =============================================================================

test("MUST-FAIL GAP (F04): a read held to a sha256 never takes a document kept by its commit: it reads the commit again", async () => {
  const W = KD.serve(gh, KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.entry(LOG_KEY)));
  const at = `${S.KEY_DOCUMENT_REPO}@${W}:`;
  assert.equal((await S.fetchNamedDocument(W)).ok, true);
  const n = gh.rawLog.filter((k) => k.startsWith(at)).length;
  const held = await S.fetchNamedDocument(W, "e".repeat(64));
  assert.equal(held.ok, true);
  assert.equal(gh.rawLog.filter((k) => k.startsWith(at)).length, n + 1, "read again");
});

test("MUST-FAIL GAP (F11): an order the compare answers 404 is read again on the next request, never kept", async () => {
  const c = await sealedCase("RN gap order 404");
  const { R } = await revoke(c);
  S._internal.clearDocumentCache();
  gh.forceCompareFailure(1, 404, `${PINS}:${R}...`);
  assert.equal((await S.sealedRecordReason(storedCase(c.id), revokedDoc())).reason, "order_not_shown");
  assert.equal((await S.sealedRecordReason(storedCase(c.id), revokedDoc())).code, "signer_since_revoked", "read again, and now shown");
});

test("MUST-FAIL GAP (F16): the second reads count toward the bound: 150 commits that removed the marker, then a valid one, is more than 200 reads", async () => {
  const c = await sealedCase("RN gap second reads");
  const W = KD.serve(gh, revokedDoc());
  const mp = S.revocationMarkerPath(CASE_KEY.verifier);
  for (let i = 0; i < 150; i += 1) gh._recordCommit(PINS, mp, "mock: removed", null);
  gh.seed(PINS, mp, markerFor(W), { keepHistory: true });
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  const a = await S.sealedRecordReason(storedCase(c.id), revokedDoc());
  assert.deepEqual([a.code, a.reason], ["signer_revoked", "revocation_marker_unreadable"]);
});

test("MUST-FAIL GAP (F19): a candidate that is not JSON is a plain skip: a marker found after it is kept", async () => {
  const c = await sealedCase("RN gap not json");
  const W = KD.serve(gh, revokedDoc());
  const mp = S.revocationMarkerPath(CASE_KEY.verifier);
  gh.seedText(PINS, mp, "not json");
  gh.seed(PINS, mp, markerFor(W), { keepHistory: true });
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  assert.equal((await S.sealedRecordReason(storedCase(c.id), revokedDoc())).code, "signer_since_revoked");
  const n = gh.commitsLog.filter((p) => p === mp).length;
  await S.sealedRecordReason(storedCase(c.id), revokedDoc());
  assert.equal(gh.commitsLog.filter((p) => p === mp).length, n, "kept");
});

test("MUST-FAIL GAP (F23): a skipped candidate whose second read fails is unreadable, never passed over", async (t) => {
  const c = await sealedCase("RN gap second read fails");
  const { R, path: mp } = await revoke(c);
  gh.addCommit(PINS, mp);
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  const key = `/${PINS}/${R}/${mp}`;
  let reads = 0;
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    if (String(url).startsWith("https://raw.githubusercontent.com") && String(url).endsWith(key)) {
      reads += 1;
      const status = reads === 1 ? 404 : 503;
      return { status, ok: false, json: async () => ({}), text: async () => "" };
    }
    return viaMock(url, o);
  };
  t.after(() => { global.fetch = viaMock; });
  const a = await S.sealedRecordReason(storedCase(c.id), revokedDoc());
  assert.equal(reads, 2, "read twice");
  assert.deepEqual([a.code, a.reason], ["signer_revoked", "revocation_marker_unreadable"]);
});

test("MUST-FAIL GAP (F26, T02): a walk asks for the page the Link header names, not the one after the last", async (t) => {
  await sealedCase("RN gap link page");
  const W = KD.serve(gh, revokedDoc());
  const mp = S.revocationMarkerPath(CASE_KEY.verifier);
  gh.seed(PINS, mp, markerFor(W));
  const asked = { pins: [], doc: [] };
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    const u = new URL(String(url));
    if (!u.pathname.endsWith("/commits")) return viaMock(url, o);
    const which = u.searchParams.get("path") === mp ? "pins" : u.searchParams.get("path") === S.CASE_KEYS_FILE ? "doc" : null;
    const page = Number(u.searchParams.get("page") || 1);
    if (which) asked[which].push(page);
    const r = await viaMock(url, o);
    if (!which || page !== 1) return r;
    const next = new URL(u.href);
    next.searchParams.set("page", "3");
    return { ...r, headers: { get: (h) => (h.toLowerCase() === "link" ? `<${next.href}>; rel="next"` : null) } };
  };
  t.after(() => { global.fetch = viaMock; });
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  await S.sealedRecordReason(storedCase((await sealedCase("RN gap link page, read")).id), revokedDoc());
  assert.deepEqual(asked.pins, [1, 3]);
  await TOOL.recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: revokedDoc() });
  assert.deepEqual(asked.doc, [1, 3]);
});

test("MUST-FAIL GAP (R07): a case the tree shows withdrawn with no registration file is passed over by the withdrawn path, and the run does not fail", async () => {
  const id = await openCase("RN gap withdrawn no registrations");
  gh.seed(PINS, C.casePath(id), { v: 1, case_id: id, protocol_version: "case/1", status: "WITHDRAWN", opened_at: "2026-10-10T07:30:00Z",
    withdrawal: { by_role: "a", at: "2026-10-10T08:30:00Z", salt_sha256: sha("s"), reason: "party_choice" }, limits: C.LIMITS.slice(), signed_by: null, sig: null, sig_reason: "planted" },
  { keepHistory: true });
  gh.seed(PINS, C.withdrawnMarkerPath(id), { kind: "case-withdrawn-marker", v: 1, case_id: id, withdrawn_at: "2026-10-10T08:30:00Z" });
  const run = await sealerRun();
  assert.equal(run.ok, true);
  assert.deepEqual(run.withdrawn_repaired, []);
});

test("MUST-FAIL GAP (R14, R15, R16, R17): the withdrawal's commit is the oldest of the newest WITHDRAWN run, read at most five deep, and a read that fails says so", async () => {
  // many commits before the withdrawal are not read past the run
  const c = await committedCase("RN gap W deep");
  for (let i = 0; i < 5; i += 1) gh.addCommit(PINS, C.casePath(c.id));
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const W = gh.commitsFor(PINS, C.casePath(c.id))[0].sha;
  assert.deepEqual(await S.withdrawalCommitOf(c.id), { ok: true, commit: W });
  // a rewrite of the withdrawn root: W stays the first
  const W2 = gh.addCommit(PINS, C.casePath(c.id));
  S._internal.clearCommitFiles();
  assert.deepEqual(await S.withdrawalCommitOf(c.id), { ok: true, commit: W }, "not the rewrite");
  assert.notEqual(W, W2);
  // six WITHDRAWN commits are past the bound
  for (let i = 0; i < 4; i += 1) gh.addCommit(PINS, C.casePath(c.id));
  assert.deepEqual(await S.withdrawalCommitOf(c.id), { ok: false, reason: "withdrawal_commit_beyond_bound" });
  // a read that fails
  const d = await committedCase("RN gap W unread");
  assert.equal((await withdraw(d.id, d.b)).status, 201);
  const newest = gh.commitsFor(PINS, C.casePath(d.id))[0].sha;
  S._internal.clearCommitFiles();
  gh.forceRawFailure(1, 503, `${PINS}@${newest}:${C.casePath(d.id)}`);
  assert.deepEqual(await S.withdrawalCommitOf(d.id), { ok: false, reason: "case_at_commit_http_503" });
});

test("MUST-FAIL GAP (R18, H14): a role with no registration file on a withdrawn case is not a party (404), never could-not-look", async () => {
  const id = await openCase("RN gap unregistered role");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  assert.equal((await withdraw(id, a)).status, 201);
  const r = await reveal({ id, a, b }, { body: { ...revealBody(id, a, b), role: "b" } });
  assert.deepEqual([r.status, r.body.error_code], [404, "not_a_party"], JSON.stringify(r.body));
});

test("MUST-FAIL GAP (R19, R23, R24): the withdrawn path removes nothing it cannot order: an order neither before nor after, or a withdrawal commit it cannot read, is unknown; an absent file is passed over", async () => {
  const x = await lostRace("RN gap repair unknown", { deleteFails: true });
  // the first pins compare of the repair (role a's) answers 404
  gh.forceCompareFailure(1, 404, `${PINS}:`);
  const one = await S.repairWithdrawn(x.id, { roles: ["a", "b"] });
  assert.deepEqual(one.unknown, [{ role: "a", reason: "registration_order_not_found" }]);
  assert.deepEqual(one.removed, ["b"]);
  assert.equal(gh.has(PINS, C.registrationPath(x.id, "a")), true, "a registration it cannot order stays");
  // the withdrawal's commit cannot be read: every role unknown, by that reason
  gh.forceCommitsFailure(PINS, C.casePath(x.id), 1, 503);
  S._internal.clearCommitFiles();
  const two = await S.repairWithdrawn(x.id, { roles: ["a", "b"] });
  assert.deepEqual(two.unknown, [{ role: "a", reason: "commits_unreadable" }, { role: "b", reason: "commits_unreadable" }]);
  // b is gone now: passed over, not unknown
  const three = await S.repairWithdrawn(x.id, { roles: ["a", "b"] });
  assert.deepEqual([three.unknown, three.kept, three.removed], [[], ["a"], []]);
});

test("MUST-FAIL GAP (R32, R36): a receipt carrying a sig_reason, or signed by a reconcile key the named document lists as retired, does not verify", async () => {
  const at = C.utcSeconds(REVEAL_AT);
  const signer = S.loadReconcileSigner(KEYS, { keyDocument: DOC });
  const checkRecord = require("../lib/_check_record.js");
  const base = S.refusalReceipt({ caseId: "c".repeat(64), at, role: "a", commitmentSha256: "d".repeat(64), signedUnder: KD.signedUnder(gh, DOC, at) }, signer);
  const withReason = { ...base, sig_reason: "a reason", sig: null };
  withReason.sig = crypto.sign(null, checkRecord.preimage(withReason), signer.privateKey).toString("base64");
  assert.deepEqual(await S.verifyRefusalReceipt(withReason, DOC), { ok: false, reason: "malformed_field" });
  const retired = KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY, { status: "retired" }));
  const underRetired = S.refusalReceipt({ caseId: "c".repeat(64), at, role: "a", commitmentSha256: "d".repeat(64), signedUnder: KD.signedUnder(gh, retired, at) }, signer);
  assert.deepEqual(await S.verifyRefusalReceipt(underRetired, DOC), { ok: false, reason: "signer_not_active" });
});

test("MUST-FAIL GAP (C03, C04, C06): a refusal names role a or b and carries exactly its opening's two fields; a joint reveal's role is a or b", async () => {
  const c = await committedCase("RN gap opening forms");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const own = { tape_sha256: c.a.tape_sha256, salt: c.a.salt };
  for (const [name, body] of [
    ["role c with an opening under c", { ...revealBody(c.id, c.a, c.b), role: "c", reveals: { c: own } }],
    ["an opening with a field more", { ...revealBody(c.id, c.a, c.b), role: "a", reveals: { a: { ...own, note: "x" } } }],
  ]) {
    const r = await reveal(c, { body });
    assert.deepEqual([r.status, r.body.error_code], [404, "not_a_party"], `${name}: ${JSON.stringify(r.body).slice(0, 200)}`);
  }
  const live = await committedCase("RN gap live role");
  const r = await reveal(live, { body: { ...revealBody(live.id, live.a, live.b), role: "c" } });
  assert.deepEqual([r.status, r.body.error_code, r.body.field], [400, "bad_role", "role"]);
});

test("MUST-FAIL GAP (C13): a sealed case whose list ends in a failure is refused at that entry", async () => {
  const c = await sealedCase("RN gap sealed ends in failure");
  const k = storedCase(c.id);
  const v = C.validateCase({ ...k, reveal_attempts: [...k.reveal_attempts, { event: "failure", reason: "case_seal_failed", at: "2026-10-10T09:00:00Z" }] });
  assert.deepEqual([v.code, v.field], ["status_inconsistent", "reveal_attempts.1"]);
});

test("MUST-FAIL GAP (H04): the lease is released at the lease clock's time", async () => {
  const id = await openCase("RN gap released at");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  let t = NOW + 1000;
  const r = await commit(id, a, NOW + 1000, { clock: () => (t += 250) });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  const lock = lockOf(id);
  assert.ok(Date.parse(lock.released_at) > Date.parse(lock.acquired_at), JSON.stringify(lock));
  assert.ok(Date.parse(lock.released_at) <= t);
});

// A lost race whose DELETE answers `status` after doing `then` to the store.
async function lostRaceDelete(scope, status, then) {
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    if ((o && o.method) === "DELETE") {
      await then(String(url), o, viaMock);
      return { ok: false, status, json: async () => ({}), text: async () => "" };
    }
    return viaMock(url, o);
  };
  try {
    return await lostRace(scope);
  } finally {
    global.fetch = viaMock;
  }
}

test("MUST-FAIL GAP (H06, H07): registration_recorded is read back when the removal is not confirmed: a removal that landed but answered 500 is false; a read-back that fails says it may be there (true)", async () => {
  const landed = await lostRaceDelete("RN gap removal landed", 500, (url, o, viaMock) => viaMock(url, o));
  assert.equal(landed.out.registration_removed, false);
  assert.equal(gh.has(PINS, landed.rpath), false, "fixture: it is gone");
  assert.equal(landed.out.registration_recorded, false, "the file's real state");
  const unread = await lostRaceDelete("RN gap read-back fails", 500, async (url) => {
    const path = decodeURIComponent(new URL(url).pathname.replace(/^\/repos\/[^/]+\/[^/]+\/contents\//, ""));
    gh.forceGetFailure(PINS, path, 1, 503);
  });
  assert.equal(unread.out.registration_recorded, true);
});

test("MUST-FAIL GAP (H09, H10): the read-after-write unwind's removal names why, and a removal that fails is reported with the file's state", async (t) => {
  const run = async (scope) => {
    const id = await openCase(scope);
    const a = party(id, "a", AGENT_TAPE);
    plantStamp(a.commitment_sha256);
    const rpath = C.registrationPath(id, "a");
    const r = await during(
      (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
      async () => gh.forceGetFailure(PINS, C.casePath(id), 1, 503),
      () => commit(id, a),
    );
    return { rpath, out: r.out };
  };
  const x = await run("RN gap unwind message");
  assert.match(gh.commitsFor(PINS, x.rpath)[0].message, /commitment a unconfirmed after its write, removed/);
  const viaMock = global.fetch;
  global.fetch = async (url, o) => ((o && o.method) === "DELETE" ? { ok: false, status: 500, json: async () => ({}), text: async () => "" } : viaMock(url, o));
  t.after(() => { global.fetch = viaMock; });
  const y = await run("RN gap unwind refused");
  assert.deepEqual([y.out.status, y.out.body.registration_removed, y.out.body.registration_recorded], [503, false, true]);
});

test("MUST-FAIL GAP (H13, H17, H19): a refusal whose withdrawal commit cannot be read is 503 naming it; a registration file that does not read is no party's; a deployment whose document is not confirmed issues no receipt", async () => {
  const c = await committedCase("RN gap refusal reads");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  S._internal.clearCommitFiles();
  gh.forceCommitsFailure(PINS, C.casePath(c.id), 1, 503);
  const u = await reveal(c, { body: ownOpening(c, "a") });
  assert.deepEqual([u.status, u.body.error_code], [503, "store_unreachable"]);
  assert.match(u.body.error, /the withdrawal's commit could not be read/);
  // a deployment naming a commit the readers cannot confirm
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", ownOpening(c, "a")), res, { now: REVEAL_AT, env: { ...KEYS, [S.DEPLOY_COMMIT_ENV]: "9".repeat(40) }, keyDocument: DOC });
  assert.deepEqual([res._status, parsed(res).error_code], [503, "document_unavailable"], JSON.stringify(parsed(res)).slice(0, 200));
  assert.equal(has(parsed(res), "refusal_receipt"), false);
  // a registration file that does not read, written before the withdrawal
  const d = await committedCase("RN gap bad registration");
  const reg = gh.read(PINS, C.registrationPath(d.id, "a"));
  gh.seed(PINS, C.registrationPath(d.id, "a"), { ...reg, note: "not a registration field" }, { keepHistory: true });
  const rec = S.withdrawnRecord(storedCase(d.id), { role: "b", at: C.utcSeconds(NOW + 2000), salt: d.b.salt }, S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  gh.seed(PINS, C.casePath(d.id), rec, { keepHistory: true });
  const r = await reveal(d, { body: ownOpening(d, "a") });
  assert.deepEqual([r.status, r.body.error_code], [404, "not_a_party"], JSON.stringify(r.body).slice(0, 200));
});

test("MUST-FAIL GAP (H31): a retry with the withdrawer's salt and another tape hash is not the withdrawer's: 409, and nothing is recorded for that tape", async () => {
  const c = await committedCase("RN gap retry tape");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const res = makeRes();
  const other = sha("another tape");
  await H.handleCaseWithdraw(req("case-withdraw", { case_id: c.id, role: "b", tape_sha256: other, salt: c.b.salt }), res, { now: NOW + 5000, env: KEYS, keyDocument: DOC });
  assert.deepEqual([res._status, parsed(res).error_code], [409, "case_withdrawn"]);
  assert.equal(gh.has(PINS, withdrawnCommitmentPath(other)), false);
});

test("MUST-FAIL GAP (H40): a reference to an anchored case takes a row", async () => {
  const c = await sealedCase("RN gap anchored");
  await sealerRun();
  const { seq } = S.pinPaths(c.id);
  const day = gh.commitsFor(PINS, seq).slice(-1)[0].date.slice(0, 10);
  gh.seedText(PINS, `anchors/${day}-head.txt`, `${gh.headOf(PINS)} ${day}T03:15:00+00:00\n`);
  assert.equal((await S.anchorState(c.id, S.caseChain(storedCase(c.id)))).pin, "anchored", "fixture: anchored");
  const r = await reference(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
});

test("MUST-FAIL GAP (P04): the page names the latest attempt", async () => {
  const c = await committedCase("RN gap latest attempt");
  await revealSealFails(c, REVEAL_AT);
  await revealSealFails(c, REVEAL_AT + 60000);
  const page = await casePage(c.id);
  assert.match(page.html, /The latest: A joint reveal was attempted at 2026-10-10T09:01:00Z/);
});

test("MUST-FAIL GAP (S05): a next page that is not a page number is a list that cannot be read", async () => {
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    const r = await viaMock(url, o);
    if (!String(url).includes("/commits?")) return r;
    return { ...r, headers: { get: (h) => (h.toLowerCase() === "link" ? `<https://api.github.com/repos/${PINS}/commits?path=x&page=next>; rel="next"` : null) } };
  };
  try {
    await assert.rejects(store.listCommitsPage("x", { perPage: 100, page: 1 }), /next page/);
  } finally {
    global.fetch = viaMock;
  }
});
