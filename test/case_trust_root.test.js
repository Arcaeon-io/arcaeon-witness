// test/case_trust_root.test.js — unit R-I (2026-10-13): the key document's
// trust root, revocation by commit order, and the sealer reading what it
// names. A second-model review of Design I at 7041aa8:
//
//   B1. Revocation was decided on service-written dates (retrieved_at
//       against since / revoked_since), and any key the current document
//       marks revoked read signer_since_revoked, which holds. A signer
//       revoked BEFORE sealing could read as holding.
//   B2. The reveal never read the document it names: it hashed its bundled
//       copy and took VERCEL_GIT_COMMIT_SHA on faith.
//   M1. A key absent from the CURRENT document read valid_under_document,
//       and any 40-hex commit the raw host serves was a document a case
//       could name, on the published branch or not.
//   m1-m3. A fetched document was cached before its hash was compared; the
//       could-not-look page always said the NAMED document could not be
//       read; the revoking commit shown was the reader's own deployment.
//
// The binding decisions, with the owner's answers of 2026-10-13:
//   I1  retrieved_at is display only. A key the current document lists as
//       revoked is ordered against the case's pin by a REVOCATION MARKER in
//       the pins repository, revocations/<fingerprint>.json, written
//       create-only by tools/record_key_revocation.js and carrying the
//       key_id, the key's public-key fingerprint and the witness-repository
//       commit that revoked it. R is the commit that wrote the marker; P is
//       the case_commit of the case's pin (Design J). P strictly before R
//       (compare/<R>...<P> behind) is signer_since_revoked, which holds,
//       under a banner naming R and P; anything else (P at or after R, no
//       pin, no marker, a marker or an order that cannot be read) is
//       signer_revoked, which does not. A marker counts only beside the
//       current document's revocation; one without it is ignored and
//       reported as marker_without_revocation.
//   I2  the reveal reads the document at its own commit and refuses 503
//       document_unavailable when it differs from the bundled copy, cannot
//       be read, or the commit is not on the published branch.
//   I3  a signer absent from the current document is signer_unlisted.
//   ANCESTRY  a named document_commit must be on the published branch
//       (KEY_DOCUMENT_BRANCH, default main): commitOnBranch.
//   I5  a fetched document is cached only after its hash matches; the
//       could-not-look page names which document; the revoking commit shown
//       is R.
//   I4  the key document's prose, dedup by public key across roles, and the
//       case signer held apart from the document's reconcile keys.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0071:case-test-";
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
const STAMPS = process.env.STAMP_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z");
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13ri");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13ri");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13ri");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const revokedIn = (k, since, role) => (role === "reconcile" ? KD.reconcileEntry(k, { status: "revoked", revokedSince: since }) : KD.entry(k, { status: "revoked", revokedSince: since }));
// The current document after the case key is revoked, and after the reconcile key is.
const CASE_REVOKED = Object.freeze(KD.docWith(revokedIn(CASE_KEY, "2026-10-11"), KD.reconcileEntry(RECEIPT_KEY)));
const RECEIPT_REVOKED = Object.freeze(KD.docWith(KD.entry(CASE_KEY), revokedIn(RECEIPT_KEY, "2026-10-11", "reconcile")));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0071" });
// loaded when first used, so each test stands or falls on its own
const TOOL = { recordRevocation: (...args) => require("../tools/record_key_revocation.js").recordRevocation(...args) };

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
  // the published document's history: the key active first
  KD.serve(gh, DOC);
});
afterEach(() => {
  store._putRetry.sleep = realSleep;
  restore();
  delete process.env.KEY_DOCUMENT_BRANCH;
});

let ipSeq = 0;
function req(op, body, headers = {}) {
  ipSeq += 1;
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": `10.95.${(ipSeq >> 8) & 255}.${ipSeq & 255}`, ...headers }, body });
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
async function committedCase(scope) {
  const o = makeRes();
  await H.handleCaseOpen(req("case-open", opening(scope), OPEN_AUTH), o, { now: NOW });
  assert.equal(o._status, 201, JSON.stringify(o._body));
  const id = o._body.case_id;
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  for (const p of [a, b]) {
    gh.seed(STAMPS, stamp.stampPath(p.commitment_sha256), { kind: "file-stamp", v: 1, sha256: p.commitment_sha256, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: "2026-10-10T07:45:00.123Z" });
    const r = makeRes();
    await H.handleCaseCommit(req("case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 })), r, { now: NOW });
    assert.equal(r._status, 201, JSON.stringify(r._body));
  }
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
async function reveal(body, { env, keyDocument = DOC } = {}) {
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", body), res, { now: REVEAL_AT, env: env || KD.deployed(gh, KEYS, keyDocument), keyDocument });
  return { status: res._status, body: parsed(res) };
}
const storedCase = (id) => gh.read(PINS, C.casePath(id));
// A sealed case, pinned by the reveal unless `pinFails`.
async function sealedCase(scope, { pinFails = false } = {}) {
  const c = await committedCase(scope);
  if (pinFails) gh.forceFailure(PINS, S.pinPaths(c.id).seq, 1, 502);
  const r = await reveal(revealBody(c.id, c.a, c.b));
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  const k = storedCase(c.id);
  const pin = gh.read(PINS, S.pinPaths(c.id).latest);
  return { ...c, k, P: pin ? pin.case_commit : null };
}
async function referenceAs(id, p, keyDocument) {
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt: p.salt,
    cross_reference: { operator: "second-operator.example", reference: "r-1", url: "https://second-operator.example/r/1" } }), res,
  { now: REVEAL_AT + 3600000, env: KEYS, keyDocument });
  return { status: res._status, body: parsed(res) };
}
async function pageOf(id, keyDocument) {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": `10.94.0.${(ipSeq += 1) & 255}` } }), res,
    { now: REVEAL_AT + 3600000, keyDocument, env: {} });
  return { status: res._status, html: String(res._body) };
}
const verdictShown = (html) => html.includes("<h2>The verdict</h2>");

// The revocation, published: the current document served at a later commit
// of the published branch, then the marker written by the tool. -> {W, R}.
async function revoke(k, current) {
  const W = KD.serve(gh, current);
  const out = await TOOL.recordRevocation({ keyId: KD.keyIdOf(k), currentDocument: current, write: true });
  assert.equal(out.ok, true, JSON.stringify(out));
  return { W, R: out.commit, path: out.path, marker: out.marker };
}

// =============================================================================
// I1: revocation by commit order
// =============================================================================

test("I1: a signer revoked in commit R, the case pinned at P before R: signer_since_revoked, which holds; it names R and P, never a date; the page shows the verdict under the banner \"revoked in commit R, after this case was pinned in commit P\", both linked", async () => {
  const c = await sealedCase("I1 before");
  assert.match(c.P, /^[0-9a-f]{40}$/, "fixture: the case is pinned");
  const { W, R } = await revoke(CASE_KEY, CASE_REVOKED);
  const got = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.equal(got.code, "signer_since_revoked", JSON.stringify(got));
  assert.equal(S.sealHolds(got), true);
  assert.equal(got.case_commit, c.P);
  assert.deepEqual(got.revoked, [{ role: "case", key_id: KD.keyIdOf(CASE_KEY), revoked_since: "2026-10-11", revoking_commit: R, revoked_in_document_commit: W }]);
  assert.equal(Object.prototype.hasOwnProperty.call(got, "current_commit"), false, "never the reader's own deployment");
  const p = await pageOf(c.id, CASE_REVOKED);
  assert.equal(p.status, 200);
  assert.ok(verdictShown(p.html), "the verdict is shown");
  assert.ok(p.html.includes(`revoked in commit <a href="https://github.com/${store.REPO}/commit/${R}"`), "R, linked");
  assert.ok(p.html.includes(`after this case was pinned in commit <a href="https://github.com/${store.REPO}/commit/${c.P}"`), "P, linked");
  assert.ok(!p.html.includes("Revoked since this case was sealed"), "no date-based banner");
  // the reconcile key, the same way
  const d = await sealedCase("I1 before, reconcile");
  await revoke(RECEIPT_KEY, RECEIPT_REVOKED);
  const r = await S.sealedRecordReason(d.k, RECEIPT_REVOKED);
  assert.equal(r.code, "signer_since_revoked", JSON.stringify(r));
  assert.equal(r.revoked[0].role, "reconcile");
});

test("I1: the same with P not before R (the case pinned after the revoking commit): signer_revoked, which does not hold; no verdict, the sealer does not pin it, the reference refuses 409", async () => {
  // the revocation first
  await revoke(CASE_KEY, CASE_REVOKED);
  // then a case sealed with a bundle that still lists the key active (its
  // pin lands after R), and one whose pin did not land
  const late = await sealedCase("I1 after");
  const lateAnswer = await S.sealedRecordReason(late.k, CASE_REVOKED);
  assert.equal(lateAnswer.code, "signer_revoked", JSON.stringify(lateAnswer));
  assert.equal(lateAnswer.reason, "pinned_at_or_after_revocation");
  assert.equal(S.sealHolds(lateAnswer), false);
  const p = await pageOf(late.id, CASE_REVOKED);
  assert.match(p.html, /<h1>Case: SEALED RECORD DOES NOT VERIFY<\/h1>/);
  assert.equal(verdictShown(p.html), false);
  assert.deepEqual(await S.anchorCase(late.id, { now: REVEAL_AT + 60000, keyDocument: CASE_REVOKED }),
    { ok: false, code: "signer_revoked", reason: "pinned_at_or_after_revocation" });
  const ref = await referenceAs(late.id, late.a, CASE_REVOKED);
  assert.deepEqual([ref.status, ref.body.error_code], [409, "signer_revoked"]);
  const unpinned = await sealedCase("I1 after, unpinned", { pinFails: true });
  await S.anchorCase(unpinned.id, { now: REVEAL_AT + 60000, keyDocument: CASE_REVOKED });
  assert.equal(gh.has(PINS, S.pinPaths(unpinned.id).latest), false, "no pin");
});

test("I1: an unpinned case whose signer the current document lists as revoked is signer_revoked, even with the revocation recorded after it was sealed", async () => {
  const c = await sealedCase("I1 unpinned", { pinFails: true });
  assert.equal(c.P, null, "fixture: no pin");
  await revoke(CASE_KEY, CASE_REVOKED);
  const got = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.deepEqual([got.code, got.reason], ["signer_revoked", "case_not_pinned"]);
  assert.equal((await S.anchorCase(c.id, { now: REVEAL_AT + 60000, keyDocument: CASE_REVOKED })).code, "signer_revoked");
  assert.equal(gh.has(PINS, S.pinPaths(c.id).latest), false, "the sealer does not pin it");
});

test("I1: a key the current document lists as revoked with no marker is signer_revoked; a marker that cannot be read, or an order that cannot be read, is signer_revoked too", async () => {
  const c = await sealedCase("I1 no marker");
  KD.serve(gh, CASE_REVOKED);
  assert.deepEqual([(await S.sealedRecordReason(c.k, CASE_REVOKED)).code, (await S.sealedRecordReason(c.k, CASE_REVOKED)).reason],
    ["signer_revoked", "no_revocation_marker"]);
  const { path } = await revoke(CASE_KEY, CASE_REVOKED);
  S._internal.clearDocumentCache();
  gh.forceCommitsFailure(PINS, path, 1, 503);
  assert.deepEqual([(await S.sealedRecordReason(c.k, CASE_REVOKED)).code, (await S.sealedRecordReason(c.k, CASE_REVOKED)).code],
    ["signer_revoked", "signer_since_revoked"], "an unreadable marker is not remembered");
  S._internal.clearDocumentCache();
  gh.forceCompareFailure(1, 503, PINS);
  const unread = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.deepEqual([unread.code, unread.reason], ["signer_revoked", "revocation_order_unreadable"]);
});

test("I1: retrieved_at is display only: a seal whose retrieved_at is the day before revoked_since, pinned after the revoking commit, is signer_revoked; one whose retrieved_at is after revoked_since, pinned before it, holds", async () => {
  // an operator records revoked_since 2026-10-05 on a later day
  const honestRevoked = KD.docWith(revokedIn(CASE_KEY, "2026-10-05"), KD.reconcileEntry(RECEIPT_KEY));
  const honest = await sealedCase("I1 dates, honest");
  assert.equal(honest.k.signed_under.retrieved_at, "2026-10-10T09:00:00Z", "fixture: sealed after revoked_since's day");
  await revoke(CASE_KEY, honestRevoked);
  assert.equal((await S.sealedRecordReason(honest.k, honestRevoked)).code, "signer_since_revoked");
  // a case sealed after the revocation, its retrieved_at the day before revoked_since
  const attacker = KD.docWith(revokedIn(CASE_KEY, "2026-10-11"), KD.reconcileEntry(RECEIPT_KEY));
  const late = await sealedCase("I1 dates, after");
  assert.equal(late.k.signed_under.retrieved_at.slice(0, 10), "2026-10-10", "fixture: the day before revoked_since");
  assert.equal((await S.sealedRecordReason(late.k, attacker)).code, "signer_revoked");
});

// =============================================================================
// THE BOUNDS ON THE MARKER (2026-10-13)
// =============================================================================

test("MARKER: it carries key_id, the key's public-key fingerprint and the witness-repository commit that revoked it, at revocations/<fingerprint>.json; the tool finds that commit (the oldest on the branch at which the document lists the key revoked) and writes create-only", async () => {
  const W = KD.serve(gh, CASE_REVOKED);
  KD.serve(gh, KD.docWith(revokedIn(CASE_KEY, "2026-10-11"), KD.reconcileEntry(RECEIPT_KEY), KD.entry(LOG_KEY)));
  const fingerprint = sha(checkpoint.parseVerifierKey(CASE_KEY.verifier).pub);
  assert.equal(S.keyFingerprint(CASE_KEY.verifier), fingerprint);
  assert.equal(S.revocationMarkerPath(CASE_KEY.verifier), `revocations/${fingerprint}.json`);
  const dry = await TOOL.recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: CASE_REVOKED });
  assert.equal(dry.ok, true, JSON.stringify(dry));
  assert.equal(dry.written, false, "a dry run writes nothing");
  assert.deepEqual(dry.marker, { kind: "key-revocation", v: 1, key_id: KD.keyIdOf(CASE_KEY), key_fingerprint: fingerprint, revoked_in_commit: W });
  assert.equal(gh.has(PINS, dry.path), false);
  const out = await TOOL.recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: CASE_REVOKED, write: true });
  assert.equal(out.written, true);
  assert.deepEqual(gh.read(PINS, out.path), dry.marker);
  assert.equal(out.commit, gh.commitsFor(PINS, out.path)[0].sha);
  assert.deepEqual(S.validateRevocationMarker(dry.marker), { ok: true });
  // never overwritten
  const again = await TOOL.recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: CASE_REVOKED, write: true });
  assert.deepEqual([again.ok, again.code], [false, "marker_exists"]);
  assert.equal(gh.commitsFor(PINS, out.path).length, 1, "one write, ever");
  // the tool refuses a key the current document does not list as revoked
  const active = await TOOL.recordRevocation({ keyId: KD.keyIdOf(RECEIPT_KEY), currentDocument: CASE_REVOKED, write: true });
  assert.deepEqual([active.ok, active.code], [false, "not_revoked"]);
  // the schema
  for (const bad of [{ ...dry.marker, extra: 1 }, { ...dry.marker, v: 2 }, { ...dry.marker, key_fingerprint: "F".repeat(64) }, { ...dry.marker, revoked_in_commit: "x" }]) {
    assert.equal(S.validateRevocationMarker(bad).ok, false, JSON.stringify(bad));
  }
});

test("MARKER WITHOUT REVOCATION: a marker for a key the current document does not list as revoked is ignored (the case holds) and the sealer's run reports it as marker_without_revocation", async () => {
  const c = await sealedCase("marker alone");
  const marker = { kind: "key-revocation", v: 1, key_id: KD.keyIdOf(CASE_KEY), key_fingerprint: S.keyFingerprint(CASE_KEY.verifier), revoked_in_commit: KD.commitOf(DOC) };
  gh.seed(PINS, S.revocationMarkerPath(CASE_KEY.verifier), marker);
  assert.equal((await S.sealedRecordReason(c.k, DOC)).code, "valid_under_document", "the marker alone never revokes");
  const run = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.deepEqual(run.marker_without_revocation, [{ path: S.revocationMarkerPath(CASE_KEY.verifier), key_id: KD.keyIdOf(CASE_KEY) }]);
  // with the current document's revocation it counts
  const run2 = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: CASE_REVOKED });
  assert.deepEqual(run2.marker_without_revocation, []);
});

test("MARKER, READ AS IT NAMES: a marker whose fingerprint is not the key's, or whose revoking commit is not one at which the document lists the key revoked, does not count: signer_revoked", async () => {
  const c = await sealedCase("marker checked");
  KD.serve(gh, CASE_REVOKED);
  const fp = S.keyFingerprint(CASE_KEY.verifier);
  const good = { kind: "key-revocation", v: 1, key_id: KD.keyIdOf(CASE_KEY), key_fingerprint: fp, revoked_in_commit: KD.commitOf(CASE_REVOKED) };
  gh.seed(PINS, S.revocationMarkerPath(CASE_KEY.verifier), { ...good, revoked_in_commit: KD.commitOf(DOC) });
  assert.deepEqual([(await S.sealedRecordReason(c.k, CASE_REVOKED)).code, (await S.sealedRecordReason(c.k, CASE_REVOKED)).reason],
    ["signer_revoked", "revocation_marker_invalid"], "at that commit the key is active");
  S._internal.clearDocumentCache();
  gh.seed(PINS, S.revocationMarkerPath(CASE_KEY.verifier), { ...good, key_id: KD.keyIdOf(RECEIPT_KEY) });
  assert.equal((await S.sealedRecordReason(c.k, CASE_REVOKED)).reason, "revocation_marker_invalid");
});

// =============================================================================
// I2: the reveal reads the document at its own commit
// =============================================================================

test("I2: a reveal whose bundled document's sha256 differs from the document at its commit is 503 document_unavailable: no attempt, nothing compared; the mismatching read is not cached, and once the commit serves the bundle the reveal seals", async (t) => {
  const c = await committedCase("I2 differs");
  const other = KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.entry(LOG_KEY, { status: "retired" }));
  const commit = KD.serve(gh, other); // the deployment's commit serves another document
  const before = storedCase(c.id);
  const compare = t.mock.method(RECONCILE, "compare");
  const r = await reveal(revealBody(c.id, c.a, c.b), { env: { ...KEYS, [S.DEPLOY_COMMIT_ENV]: commit }, keyDocument: DOC });
  assert.equal(r.status, 503, JSON.stringify(r.body));
  assert.deepEqual([r.body.error_code, r.body.reason], ["document_unavailable", "bundled_document_differs"]);
  assert.deepEqual(storedCase(c.id), before, "no attempt written");
  assert.equal(compare.mock.callCount(), 0);
  compare.mock.restore();
  // the commit now serves the bundle: not cached, so read again, and sealed
  gh.seedRaw(S.KEY_DOCUMENT_REPO, commit, S.CASE_KEYS_FILE, JSON.stringify(DOC));
  const ok = await reveal(revealBody(c.id, c.a, c.b), { env: { ...KEYS, [S.DEPLOY_COMMIT_ENV]: commit }, keyDocument: DOC });
  assert.equal(ok.status, 201, JSON.stringify(ok.body).slice(0, 300));
});

test("I2: a reveal whose commit's document cannot be read, or whose commit is not on the published branch, is 503 document_unavailable with no attempt; KEY_DOCUMENT_BRANCH names the branch", async () => {
  const c = await committedCase("I2 unreadable");
  const before = storedCase(c.id);
  const commit = KD.serve(gh, DOC);
  gh.raw.delete(`${S.KEY_DOCUMENT_REPO}@${commit}:${S.CASE_KEYS_FILE}`);
  let r = await reveal(revealBody(c.id, c.a, c.b), { env: { ...KEYS, [S.DEPLOY_COMMIT_ENV]: commit } });
  assert.deepEqual([r.status, r.body.error_code, r.body.reason], [503, "document_unavailable", "document_at_commit_http_404"]);
  const side = "5".repeat(40);
  KD.serveOffBranch(gh, DOC, side);
  r = await reveal(revealBody(c.id, c.a, c.b), { env: { ...KEYS, [S.DEPLOY_COMMIT_ENV]: side } });
  assert.deepEqual([r.status, r.body.error_code, r.body.reason], [503, "document_unavailable", "commit_not_on_branch"]);
  assert.deepEqual(storedCase(c.id), before, "no attempt written");
  // a deployment of another branch names that branch
  gh.setBranch(S.KEY_DOCUMENT_REPO, "preview-branch");
  r = await reveal(revealBody(c.id, c.a, c.b), { env: { ...KEYS, [S.DEPLOY_COMMIT_ENV]: KD.serve(gh, DOC), [S.KEY_DOCUMENT_BRANCH_ENV]: "preview-branch" } });
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
});

// =============================================================================
// ANCESTRY: a named commit must be on the published branch
// =============================================================================

test("ANCESTRY: commitOnBranch is one compare read of compare/<branch>...<commit>: identical or behind is on (cached), ahead or diverged is not, a failed read is unknown (not cached)", async () => {
  const on = KD.serve(gh, KD.docWith(KD.entry(CASE_KEY)));
  const side = KD.serveOffBranch(gh, KD.docWith(KD.entry(LOG_KEY)));
  assert.deepEqual(await S.commitOnBranch(on), { on: true });
  const n = gh.compareLog.length;
  assert.deepEqual(await S.commitOnBranch(on), { on: true });
  assert.equal(gh.compareLog.length, n, "cached");
  assert.equal(gh.compareLog[n - 1], `${S.KEY_DOCUMENT_REPO}:main...${on}`);
  assert.equal((await S.commitOnBranch(side)).on, false);
  assert.equal((await S.commitOnBranch("6".repeat(40))).on, false, "a commit the repository does not have");
  gh.forceCompareFailure(1, 503);
  const fresh = KD.serve(gh, KD.docWith(KD.entry(RECEIPT_KEY)));
  assert.deepEqual(await S.commitOnBranch(fresh), { unknown: "compare_http_503" });
  assert.deepEqual(await S.commitOnBranch(fresh), { on: true }, "a failure is not remembered");
  // the pins repository, by name
  assert.deepEqual(await S.commitOnBranch(gh.headOf(PINS) || gh.seed(PINS, "x.json", {}), { repo: store.REPO, branch: store.BRANCH }), { on: true });
});

test("ANCESTRY: a sealed case naming a document commit that is not on the published branch (a side branch's, or a fork's the raw host serves) is document_unavailable, never valid; so is a branch read that fails", async () => {
  const c = await committedCase("ancestry");
  const compared = RECONCILE.compare(c.a.tape, c.b.tape, { env: KEYS, now: REVEAL_AT, keyDocument: DOC });
  const st = S.storableReceipt(compared.receipt);
  const named = KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.entry(LOG_KEY));
  const side = KD.serveOffBranch(gh, named, "7".repeat(40));
  const k = S.sealCase(storedCase(c.id), {
    reveals: { a: { tape_sha256: c.a.tape_sha256, salt: c.a.salt }, b: { tape_sha256: c.b.tape_sha256, salt: c.b.salt } },
    receipt: st.receipt, crossReference: null, revealedAt: C.utcSeconds(REVEAL_AT),
    signedUnder: { document_sha256: KD.sha256(canonicalBytes(named)), document_commit: side, retrieved_at: C.utcSeconds(REVEAL_AT) },
  }, S.loadCaseSigner(KEYS, { keyDocument: named }));
  const got = await S.sealedRecordReason(k, DOC);
  assert.deepEqual(got, { code: "document_unavailable", reason: "commit_not_on_branch", document: "named", document_commit: side });
  gh.seed(PINS, C.casePath(c.id), k);
  const p = await pageOf(c.id, DOC);
  assert.equal(p.status, 503);
  // a branch read that fails
  const s2 = await sealedCase("ancestry fails");
  S._internal.clearDocumentCache();
  gh.forceCompareFailure(1, 502, S.KEY_DOCUMENT_REPO);
  assert.deepEqual(await S.sealedRecordReason(s2.k, DOC),
    { code: "document_unavailable", reason: "compare_http_502", document: "named", document_commit: s2.k.signed_under.document_commit });
});

// =============================================================================
// I3: a signer absent from the current document
// =============================================================================

test("I3: a signer absent from the current document is signer_unlisted: no verdict, no pin, the reference refuses 409; the case key and the reconcile key alike", async () => {
  const c = await sealedCase("I3", { pinFails: true });
  const noCase = KD.docWith(KD.reconcileEntry(RECEIPT_KEY));
  const noReceipt = KD.docWith(KD.entry(CASE_KEY));
  assert.deepEqual(await S.sealedRecordReason(c.k, noCase), { code: "signer_unlisted", reason: "case_key_not_listed", key_id: KD.keyIdOf(CASE_KEY) });
  assert.deepEqual(await S.sealedRecordReason(c.k, noReceipt), { code: "signer_unlisted", reason: "reconcile_key_not_listed", key_id: KD.keyIdOf(RECEIPT_KEY) });
  // listed under the other role does not count
  const wrongRole = KD.docWith(KD.entry(CASE_KEY), KD.entry(RECEIPT_KEY));
  assert.equal((await S.sealedRecordReason(c.k, wrongRole)).code, "signer_unlisted");
  const p = await pageOf(c.id, noCase);
  assert.equal(verdictShown(p.html), false);
  assert.ok(p.html.includes("signer_unlisted"));
  assert.deepEqual(await S.anchorCase(c.id, { now: REVEAL_AT + 60000, keyDocument: noCase }),
    { ok: false, code: "signer_unlisted", reason: "case_key_not_listed" });
  assert.equal(gh.has(PINS, S.pinPaths(c.id).latest), false);
  const ref = await referenceAs(c.id, c.a, noReceipt);
  assert.deepEqual([ref.status, ref.body.error_code], [409, "signer_unlisted"]);
});

// =============================================================================
// I5: the cache, the could-not-look page
// =============================================================================

test("I5: a fetched document is cached only after its hash matches: other bytes at the named commit are case_signature_invalid, and once the commit serves the named bytes the case verifies", async () => {
  const c = await sealedCase("I5 cache");
  const commit = c.k.signed_under.document_commit;
  S._internal.clearDocumentCache(); // the reveal kept the matching read; start this instance afresh
  gh.seedRaw(S.KEY_DOCUMENT_REPO, commit, S.CASE_KEYS_FILE, JSON.stringify(KD.docWith(KD.entry(CASE_KEY))));
  assert.deepEqual(await S.sealedRecordReason(c.k, DOC), { code: "case_signature_invalid", reason: "document_sha256_mismatch" });
  gh.seedRaw(S.KEY_DOCUMENT_REPO, commit, S.CASE_KEYS_FILE, JSON.stringify(DOC));
  assert.equal((await S.sealedRecordReason(c.k, DOC)).code, "valid_under_document", "the mismatch was not cached");
  const reads = gh.rawLog.length;
  assert.equal((await S.sealedRecordReason(c.k, DOC)).code, "valid_under_document");
  assert.equal(gh.rawLog.length, reads, "the match is");
});

test("I5: the could-not-look page names which document could not be read: the one the case names, or the current one this reader carries", async () => {
  const c = await sealedCase("I5 page");
  const current = await pageOf(c.id, null);
  assert.equal(current.status, 503);
  assert.ok(current.html.includes("The current key document this reader carries could not be read"), "the current one");
  assert.ok(!current.html.includes("The key document this case names could not be read"));
  assert.deepEqual(await S.sealedRecordReason(c.k, null),
    { code: "document_unavailable", reason: "current_document_unreadable", document: "current", document_commit: c.k.signed_under.document_commit });
  S._internal.clearDocumentCache();
  gh.raw.delete(`${S.KEY_DOCUMENT_REPO}@${c.k.signed_under.document_commit}:${S.CASE_KEYS_FILE}`);
  const named = await pageOf(c.id, DOC);
  assert.equal(named.status, 503);
  assert.ok(named.html.includes("The key document this case names could not be read"), "the named one");
  assert.ok(!named.html.includes("The current key document this reader carries could not be read"));
});

// =============================================================================
// I4: the document's prose, dedup by public key, the signer's separation
// =============================================================================

test("I4: the key document's notes state the rules: revoked keeps the verdict of a case pinned before the revoking commit under a banner, and a case pinned at or after it does not verify; the reconcile key is listed here with role reconcile; no 'never provisioned' sentence; the shape still reads", () => {
  const text = fs.readFileSync(path.join(__dirname, "..", "public", ".well-known", "arcaeon", "case-signing-keys.json"), "utf8");
  const doc = JSON.parse(text);
  assert.equal(S.checkKeyDocument(doc).ok, true, "the shape the code parses");
  assert.match(doc.status_meaning.revoked, /cases pinned before the revoking commit keep their verdict under a banner/);
  assert.match(doc.status_meaning.revoked, /cases pinned at or after it do not verify/);
  assert.match(doc.rotation, /revocations\/<fingerprint>\.json/);
  assert.match(doc.description, /the reconcile key .* is listed in this document too, with role reconcile/);
  assert.ok(!/has been provisioned yet/.test(text), "the 'never provisioned' sentence is gone");
});

test("I4: the document is deduplicated by public key across roles: one key listed twice under two names, as case and reconcile, does not read", () => {
  // the same public key under another name: another key_id, the same bytes
  const vk = checkpoint.parseVerifierKey(CASE_KEY.verifier);
  const name = "arcaeon.io/another-name/2026-10-13ri";
  const hash = crypto.createHash("sha256").update(Buffer.concat([Buffer.from(name), Buffer.from([0x0a, 0x01]), vk.pub])).digest().subarray(0, 4).toString("hex");
  const verifier = `${name}+${hash}+${Buffer.concat([Buffer.from([0x01]), vk.pub]).toString("base64")}`;
  assert.equal(checkpoint.parseVerifierKey(verifier).ok, true, "fixture: a well-formed verifier for the same key under another name");
  const doc = KD.docWith(KD.entry(CASE_KEY), { key_id: `${name}+${hash}`, verifier, since: "2026-10-10", note: "the same key, again", status: "active", role: "reconcile" });
  assert.deepEqual(S.checkKeyDocument(doc), { ok: false, reason: "duplicate_public_key", at: "keys[1].verifier" });
});

test("I4: loadCaseSigner holds the case key apart from the document's reconcile keys as well as the environment's: a case key the document lists as a reconcile key is case_key_is_other_key", () => {
  const vk = checkpoint.parseVerifierKey(CASE_KEY.verifier);
  const name = "arcaeon.io/case-as-reconcile/2026-10-13ri";
  const hash = crypto.createHash("sha256").update(Buffer.concat([Buffer.from(name), Buffer.from([0x0a, 0x01]), vk.pub])).digest().subarray(0, 4).toString("hex");
  const verifier = `${name}+${hash}+${Buffer.concat([Buffer.from([0x01]), vk.pub]).toString("base64")}`;
  assert.equal(checkpoint.parseVerifierKey(verifier).ok, true, "fixture");
  const doc = KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY),
    { key_id: `${name}+${hash}`, verifier, since: "2026-10-10", note: "the case key's bytes, as a reconcile key", status: "active", role: "reconcile" });
  const loaded = S.loadCaseSigner(KEYS, { keyDocument: doc });
  assert.deepEqual([loaded.ok, loaded.code], [false, "case_key_is_other_key"]);
  assert.match(loaded.reason, /reconcile key the key document lists/);
  assert.equal(S.loadCaseSigner(KEYS, { keyDocument: DOC }).ok, true, "control");
});
