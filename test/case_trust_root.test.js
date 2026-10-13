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
  CP._internal.clearPageCache(); // unit R-J (J7): each view here reads afresh
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": `10.94.0.${(ipSeq += 1) & 255}` } }), res,
    { now: REVEAL_AT + 3600000, keyDocument, env: {} });
  return { status: res._status, html: String(res._body) };
}
const verdictShown = (html) => html.includes("<h2>The verdict</h2>");
// unit R-I2 (M2): the banner's sentence for a key, P, R and W linked as the page links them
const aTo = (href, sha) => `<a href="${href}" rel="nofollow noopener noreferrer">${sha.slice(0, 12)}</a>`;
const bannerSentence = (P, R, W) =>
  `The case file was written at commit ${aTo(`https://github.com/${store.REPO}/commit/${P}`, P)}, before this key's revocation was recorded in ` +
  `the pins repository at commit ${aTo(`https://github.com/${store.REPO}/commit/${R}`, R)}. The key document lists the key as revoked at ` +
  `its commit ${aTo(`https://github.com/${S.KEY_DOCUMENT_REPO}/blob/${W}/${S.CASE_KEYS_FILE}`, W)}.`;

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
  // unit R-I2 (M2): the banner says exactly what is proven, P, R and W each linked
  assert.ok(p.html.includes(bannerSentence(c.P, R, W)), "the banner, word for word");
  assert.ok(!/pinned before the revocation|revoked after this case was pinned/.test(p.html), "never more than is proven");
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
  // the order compare itself, compare/<R>...<P> (since unit R-J, J6, the case
  // commit's own branch read comes first, compare/main...<P>)
  const R = gh.commitsFor(PINS, path).slice(-1)[0].sha;
  gh.forceCompareFailure(1, 503, `${PINS}:${R}...`);
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

// =============================================================================
// THE MUST-FAIL PASS: tests for the planted defects the tests above let through
// =============================================================================

const markerPath = (k) => S.revocationMarkerPath(k.verifier);
const goodMarker = (k, W) => ({ kind: "key-revocation", v: 1, key_id: KD.keyIdOf(k), key_fingerprint: S.keyFingerprint(k.verifier), revoked_in_commit: W });
async function reasonOf(k, current) {
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  const a = await S.sealedRecordReason(k, current);
  return [a.code, a.reason];
}

test("MUST-FAIL GAP (ST03, B03, A09, A04, A05, A06, A07): commitOnBranch reads one compare per question: an answer with no known status is unknown, a branch name it cannot use is unknown without a read, a non-commit is off without a read; it keeps on per repository and branch; it sends the pin token; another repository's default is its own branch", async () => {
  const c = KD.serve(gh, KD.docWith(KD.entry(CASE_KEY)));
  // an answer that names no known status
  const viaMock = global.fetch;
  global.fetch = async (url, o) => (String(url).includes("/compare/")
    ? { ok: true, status: 200, json: async () => ({ status: "weird" }), text: async () => "{}" } : viaMock(url, o));
  try {
    assert.deepEqual(await S.commitOnBranch(c), { unknown: "compare_http_200" });
  } finally {
    global.fetch = viaMock;
  }
  const n = gh.compareLog.length;
  assert.deepEqual(await S.commitOnBranch(c, { branch: "a..b" }), { unknown: "branch_name_invalid" });
  assert.deepEqual(await S.commitOnBranch("not-a-commit"), { on: false });
  assert.equal(gh.compareLog.length, n, "neither is asked");
  // on main, and kept for main only
  assert.deepEqual(await S.commitOnBranch(c), { on: true });
  // another branch is asked, not taken from main's answer; one that does not
  // exist is not "off" (unit R-I2, m4)
  assert.deepEqual(await S.commitOnBranch(c, { branch: "other-branch" }), { unknown: "branch_unreadable" });
  // the read carries the pin token (rate limits)
  const heard = [];
  global.fetch = async (url, o) => {
    if (String(url).includes("/compare/")) heard.push((o && o.headers) || {});
    return viaMock(url, o);
  };
  try {
    await S.commitOnBranch(KD.serve(gh, KD.docWith(KD.entry(LOG_KEY))));
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(heard[0].authorization, "Bearer test-token");
  // the pins repository's default branch is the pins branch, whatever KEY_DOCUMENT_BRANCH says
  process.env.KEY_DOCUMENT_BRANCH = "release";
  const pinsHead = gh.seed(PINS, "x.json", {});
  assert.deepEqual(await S.commitOnBranch(pinsHead, { repo: store.REPO }), { on: true });
});

test("MUST-FAIL GAP (C02, C06): the reveal refuses a branch read that fails by its reason, and reads the document at its commit once per instance, after a match", async () => {
  const c = await committedCase("gap confirm");
  gh.forceCompareFailure(1, 502, S.KEY_DOCUMENT_REPO);
  const r = await reveal(revealBody(c.id, c.a, c.b));
  assert.deepEqual([r.status, r.body.error_code, r.body.reason], [503, "document_unavailable", "compare_http_502"]);
  const commit = KD.commitOf(DOC);
  const ok = await reveal(revealBody(c.id, c.a, c.b));
  assert.equal(ok.status, 201, JSON.stringify(ok.body).slice(0, 200));
  const reads = gh.rawLog.filter((x) => x.includes(commit)).length;
  const d = await committedCase("gap confirm, again");
  assert.equal((await reveal(revealBody(d.id, d.a, d.b))).status, 201);
  assert.equal(gh.rawLog.filter((x) => x.includes(commit)).length, reads, "the second reveal reads the kept document");
});

test("MUST-FAIL GAP (S08, R08, P02): a case key the current document lists only as a reconcile key is unlisted; a signer_revoked answer names the case's pin commit; the order read is kept", async () => {
  const c = await sealedCase("gap roles");
  assert.deepEqual(await S.sealedRecordReason(c.k, KD.docWith(KD.reconcileEntry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY))),
    { code: "signer_unlisted", reason: "case_key_not_listed", key_id: KD.keyIdOf(CASE_KEY) });
  await revoke(CASE_KEY, CASE_REVOKED);
  const late = await sealedCase("gap roles, after");
  const a = await S.sealedRecordReason(late.k, CASE_REVOKED);
  assert.deepEqual([a.code, a.case_commit], ["signer_revoked", late.P]);
  // the order of c (before) is read once
  assert.equal((await S.sealedRecordReason(c.k, CASE_REVOKED)).code, "signer_since_revoked");
  const n = gh.compareLog.filter((x) => x.startsWith(`${PINS}:`)).length;
  assert.equal((await S.sealedRecordReason(c.k, CASE_REVOKED)).code, "signer_since_revoked");
  assert.equal(gh.compareLog.filter((x) => x.startsWith(`${PINS}:`)).length, n, "kept");
});

test("MUST-FAIL GAP (P01): a case whose pin records the revoking commit itself (P equal to R) is pinned AT the revocation: signer_revoked", async () => {
  const c = await sealedCase("gap P equals R");
  const { R } = await revoke(CASE_KEY, CASE_REVOKED);
  const { seq, latest } = S.pinPaths(c.id);
  const pin = gh.read(PINS, seq);
  gh.seed(PINS, seq, { ...pin, case_commit: R });
  gh.seed(PINS, latest, { ...pin, case_commit: R });
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  const st = await S.anchorState(c.id, S.caseChain(c.k), { anchor: false });
  assert.deepEqual([st.pin, st.case_commit], ["pinned", R], "fixture: the pin records R, and the case file at R is this case");
  const a = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.deepEqual([a.code, a.reason], ["signer_revoked", "pinned_at_or_after_revocation"]);
});

test("MUST-FAIL GAP (K01, K02, K10; unit R-I2 M3, B1): R is the commit that wrote the first valid marker, whatever touched its path since, 101 and more later commits included; a case pinned between R and them is signer_revoked; a marker list that cannot be read is unreadable; a marker read is kept per key", async () => {
  const c = await sealedCase("gap marker commits");
  const { R, path: mp } = await revoke(CASE_KEY, CASE_REVOKED);
  const late = await sealedCase("gap marker commits, late");
  for (let i = 0; i < 105; i += 1) gh.addCommit(PINS, mp); // the same valid marker, rewritten
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  assert.equal((await S.sealedRecordReason(c.k, CASE_REVOKED)).revoked[0].revoking_commit, R, "the oldest commit, the one that wrote it");
  const lateAnswer = await S.sealedRecordReason(late.k, CASE_REVOKED);
  assert.deepEqual([lateAnswer.code, lateAnswer.reason], ["signer_revoked", "pinned_at_or_after_revocation"], "pinned after R, before the rewrites: never holds");
  const n = gh.commitsLog.filter((p) => p === mp).length;
  await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.equal(gh.commitsLog.filter((p) => p === mp).length, n, "kept for the instance");
  S._internal.clearDocumentCache();
  gh.forceCommitsFailure(PINS, mp, 1, 503);
  assert.deepEqual((await S.sealedRecordReason(c.k, CASE_REVOKED)).reason, "revocation_marker_unreadable");
});

test("MUST-FAIL GAP (K03, K05, K06, K07, K09, K11, K12): a marker that does not read as it names does not count: another version, another fingerprint, a revoking commit off the branch or whose document lists the key revoked only in another role, or a marker that is not JSON, is invalid; a revoking document or branch that cannot be read is unreadable", async () => {
  const c = await sealedCase("gap marker forms");
  const W = KD.serve(gh, CASE_REVOKED);
  const mp = markerPath(CASE_KEY);
  const plant = (m) => gh.seed(PINS, mp, m);
  plant({ ...goodMarker(CASE_KEY, W), v: 2 });
  assert.deepEqual(await reasonOf(c.k, CASE_REVOKED), ["signer_revoked", "revocation_marker_invalid"], "another version");
  plant({ ...goodMarker(CASE_KEY, W), key_fingerprint: "a".repeat(64) });
  assert.deepEqual(await reasonOf(c.k, CASE_REVOKED), ["signer_revoked", "revocation_marker_invalid"], "another fingerprint");
  const side = KD.serveOffBranch(gh, CASE_REVOKED, "9".repeat(40));
  plant(goodMarker(CASE_KEY, side));
  assert.deepEqual(await reasonOf(c.k, CASE_REVOKED), ["signer_revoked", "revocation_marker_invalid"], "off the branch");
  const otherRole = KD.serve(gh, KD.docWith(KD.reconcileEntry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11" }), KD.reconcileEntry(RECEIPT_KEY)));
  plant(goodMarker(CASE_KEY, otherRole));
  assert.deepEqual(await reasonOf(c.k, CASE_REVOKED), ["signer_revoked", "revocation_marker_invalid"], "revoked there in another role");
  gh.seedCommit(S.KEY_DOCUMENT_REPO, "8".repeat(40), S.CASE_KEYS_FILE);
  plant(goodMarker(CASE_KEY, "8".repeat(40)));
  assert.deepEqual(await reasonOf(c.k, CASE_REVOKED), ["signer_revoked", "revocation_marker_unreadable"], "the revoking document cannot be read");
  plant(goodMarker(CASE_KEY, W));
  S._internal.clearDocumentCache();
  gh.forceCompareFailure(1, 503, `...${W}`);
  const a = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.deepEqual([a.code, a.reason], ["signer_revoked", "revocation_marker_unreadable"], "its branch cannot be read");
  // a marker path whose only commit wrote text that is not JSON
  const list = gh.commits.get(PINS);
  for (let i = list.length - 1; i >= 0; i -= 1) if (list[i].path === mp) list.splice(i, 1);
  gh.seedText(PINS, mp, "not json");
  assert.deepEqual(await reasonOf(c.k, CASE_REVOKED), ["signer_revoked", "revocation_marker_invalid"], "not JSON");
});

test("MUST-FAIL GAP (M07, M08, M09): validateRevocationMarker names a missing field, refuses an empty key id, and refuses what is not an object", () => {
  const good = goodMarker(CASE_KEY, "1".repeat(40));
  const { key_id: _k, ...noKey } = good; // eslint-disable-line no-unused-vars
  assert.deepEqual(S.validateRevocationMarker(noKey), { ok: false, reason: "missing_field:key_id" });
  assert.equal(S.validateRevocationMarker({ ...good, key_id: "" }).ok, false);
  assert.deepEqual(S.validateRevocationMarker(null), { ok: false, reason: "not_an_object" });
});

test("MUST-FAIL GAP (W02, W03, W04, W05): the sealer's run reports a marker at a path that is not its key's, and an invalid one, with no key id; a marker it cannot read leaves markers_unread said", async () => {
  await sealedCase("gap run markers");
  const wrongPath = `revocations/${"b".repeat(64)}.json`;
  gh.seed(PINS, wrongPath, goodMarker(CASE_KEY, KD.commitOf(DOC)));
  const invalid = markerPath(RECEIPT_KEY);
  gh.seed(PINS, invalid, { ...goodMarker(RECEIPT_KEY, KD.commitOf(DOC)), v: 2 });
  const run = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: CASE_REVOKED });
  assert.deepEqual(run.marker_without_revocation.sort((x, y) => x.path.localeCompare(y.path)),
    [{ path: invalid, key_id: null }, { path: wrongPath, key_id: null }].sort((x, y) => x.path.localeCompare(y.path)));
  assert.equal(run.markers_unread, null);
  gh.forceGetFailure(PINS, wrongPath, 1, 503);
  const unread = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: CASE_REVOKED });
  assert.equal(unread.markers_unread, "revocations_unreadable");
});

test("MUST-FAIL GAP (H03, H04, G04, G05): the reference and the page say signer_unlisted and signer_revoked in words", async () => {
  const c = await sealedCase("gap words");
  const noCase = KD.docWith(KD.reconcileEntry(RECEIPT_KEY));
  const u = await referenceAs(c.id, c.a, noCase);
  assert.match(u.body.error, /a key that signed it is not listed in its role in the current key document/);
  assert.ok((await pageOf(c.id, noCase)).html.includes("the current key document: a key that signed it is not listed there in its role"));
  KD.serve(gh, CASE_REVOKED); // no marker: signer_revoked
  const r = await referenceAs(c.id, c.a, CASE_REVOKED);
  assert.match(r.body.error, /a key that signed it is revoked in the current key document, and the case file is not shown written before the revocation was recorded in the pins repository/);
  assert.ok((await pageOf(c.id, CASE_REVOKED)).html.includes("a key that signed it is revoked in the current key document, and this case&#39;s file is not shown written before the revocation was recorded in the pins repository"));
});

test("MUST-FAIL GAP (T02, T04, T10, T11, T12, T13, T14, T15): the tool refuses an existing marker even in a dry run, never writes over a marker another writer created mid-write, says a store error, an unlisted key, and each read it could not make", async () => {
  KD.serve(gh, CASE_REVOKED);
  const keyId = KD.keyIdOf(CASE_KEY);
  const mp = markerPath(CASE_KEY);
  assert.deepEqual((await TOOL.recordRevocation({ keyId: "nobody+00000000", currentDocument: CASE_REVOKED })).code, "not_listed");
  // a store error writing it
  gh.forceFailure(PINS, mp, 1, 502);
  assert.equal((await TOOL.recordRevocation({ keyId, currentDocument: CASE_REVOKED, write: true })).code, "store_error");
  // another writer creates it mid-write (a 409, the path found taken)
  const theirs = { ...goodMarker(CASE_KEY, KD.commitOf(CASE_REVOKED)) };
  const viaMock = global.fetch;
  let fired = false;
  global.fetch = async (url, o) => {
    if (!fired && (o && o.method) === "PUT" && String(url).includes(`/contents/${mp}`)) {
      fired = true;
      gh.seed(PINS, mp, theirs);
      gh.forceConflict(PINS, mp, 1);
    }
    return viaMock(url, o);
  };
  let raced;
  try {
    raced = await TOOL.recordRevocation({ keyId, currentDocument: CASE_REVOKED, write: true });
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(fired, true);
  assert.equal(raced.code, "marker_exists");
  assert.equal(gh.commitsFor(PINS, mp).length, 1, "theirs, never written over");
  // and a dry run is refused once it exists
  assert.equal((await TOOL.recordRevocation({ keyId, currentDocument: CASE_REVOKED })).code, "marker_exists");
  // the reads it could not make
  gh.repos.get(PINS).delete(mp);
  gh.forceGetFailure(PINS, mp, 1, 503);
  assert.equal((await TOOL.recordRevocation({ keyId, currentDocument: CASE_REVOKED })).code, "could_not_look", "the marker path");
  gh.forceCommitsFailure(S.KEY_DOCUMENT_REPO, S.CASE_KEYS_FILE, 1, 503);
  assert.equal((await TOOL.recordRevocation({ keyId, currentDocument: CASE_REVOKED })).code, "could_not_look", "the document's commits");
  // unit R-N (n4): a document read by its commit is kept, so the failure needs a fresh instance
  S._internal.clearDocumentCache();
  gh.forceRawFailure(1, 503, S.KEY_DOCUMENT_REPO);
  assert.equal((await TOOL.recordRevocation({ keyId, currentDocument: CASE_REVOKED })).code, "could_not_look", "a document on the way");
});

test("MUST-FAIL GAP (T06, ST01, T07): the tool walks every page of the document's history, oldest first, and counts a revocation only in the key's own role", async () => {
  // the key listed revoked as a reconcile key first, then as itself
  const asReconcile = KD.docWith(KD.reconcileEntry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11" }), KD.reconcileEntry(RECEIPT_KEY));
  KD.serve(gh, asReconcile);
  const first = KD.serve(gh, KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11", note: "revoked, 0" }), KD.reconcileEntry(RECEIPT_KEY)));
  for (let i = 1; i <= 100; i += 1) {
    KD.serve(gh, KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11", note: `revoked, ${i}` }), KD.reconcileEntry(RECEIPT_KEY)));
  }
  const out = await TOOL.recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: CASE_REVOKED });
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(out.marker.revoked_in_commit, first, "the oldest commit, past the first page, in its own role");
});

test("MUST-FAIL GAP (B01): KEY_DOCUMENT_BRANCH names the branch: a deployment of another branch seals when it names that branch, and is refused when it does not", async () => {
  gh.setBranch(S.KEY_DOCUMENT_REPO, "preview-branch");
  const doc = KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.entry(LOG_KEY, { status: "retired" }));
  const commit = KD.serve(gh, doc);
  const c = await committedCase("gap branch env");
  const unnamed = await reveal(revealBody(c.id, c.a, c.b), { env: { ...KEYS, [S.DEPLOY_COMMIT_ENV]: commit }, keyDocument: doc });
  assert.deepEqual([unnamed.status, unnamed.body.reason], [503, "branch_unreadable"], "main is not this repository's branch here (unit R-I2, m4: unknown, not off)");
  const named = await reveal(revealBody(c.id, c.a, c.b), { env: { ...KEYS, [S.DEPLOY_COMMIT_ENV]: commit, [S.KEY_DOCUMENT_BRANCH_ENV]: "preview-branch" }, keyDocument: doc });
  assert.equal(named.status, 201, JSON.stringify(named.body).slice(0, 200));
});

// =============================================================================
// UNIT R-I2 (2026-10-13): fixes from the second reader's pass over R-I
// =============================================================================

// A valid marker for `k` revoked in the document at W, written to its path
// as another write, keeping the path's history. -> the commit.
const writeMarker = (k, W, over = {}) => gh.seed(PINS, markerPath(k), { ...goodMarker(k, W), ...over }, { keepHistory: true });

test("R-I2 B1: R is found by walking every page of the marker path's commits; past the bound it is unreadable (signer_revoked), never a later commit", async () => {
  const c = await sealedCase("R-I2 bound");
  const { R, path: mp } = await revoke(CASE_KEY, CASE_REVOKED);
  for (let i = 0; i < S.COMMIT_LIST_PAGES * 100; i += 1) gh.addCommit(PINS, mp);
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  const a = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.deepEqual([a.code, a.reason], ["signer_revoked", "revocation_marker_unreadable"], "the oldest commit cannot be reached within the bound");
  // unit R-N (n7): the refusal names the key and no revoking commit at all, R or a later one
  assert.deepEqual(a.revoked, [{ role: "case", key_id: KD.keyIdOf(CASE_KEY), revoked_since: "2026-10-11" }]);
  assert.ok(!JSON.stringify(a).includes(R), "R is named nowhere in the answer");
});

test("R-I2 B1 (commitsOf): the commit that wrote a pin record is the oldest touching it, past the first page of its history", async () => {
  const c = await sealedCase("R-I2 commitsOf");
  const { seq } = S.pinPaths(c.id);
  const wrote = gh.commitsFor(PINS, seq);
  assert.equal(wrote.length, 1, "fixture: written once");
  for (let i = 0; i < 105; i += 1) gh.addCommit(PINS, seq);
  S._internal.clearCommitFiles();
  const st = await S.anchorState(c.id, S.caseChain(c.k), { anchor: false });
  assert.equal(st.pin, "pinned");
  assert.equal(st.pin_commit.sha, wrote[0].sha, "the commit that wrote it, not the 100th newest");
});

test("R-I2 M1: R is the oldest commit at which the path reads as a VALID marker for the key: a stray earlier write is skipped, not fatal; a later valid marker never moves R; with none valid it is revocation_marker_invalid", async () => {
  const c = await sealedCase("R-I2 first valid");
  const W = KD.serve(gh, CASE_REVOKED);
  // a stray first write: a marker naming a commit where the key is active
  gh.seed(PINS, markerPath(CASE_KEY), goodMarker(CASE_KEY, KD.commitOf(DOC)));
  assert.deepEqual(await reasonOf(c.k, CASE_REVOKED), ["signer_revoked", "revocation_marker_invalid"], "none valid yet");
  const R = writeMarker(CASE_KEY, W);
  S._internal.clearCommitFiles();
  const a = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.equal(a.code, "signer_since_revoked", JSON.stringify(a));
  assert.equal(a.revoked[0].revoking_commit, R, "the first valid one");
  // a later valid marker (another revoking document) never moves R
  const W2 = KD.serve(gh, KD.docWith(revokedIn(CASE_KEY, "2026-10-12"), KD.reconcileEntry(RECEIPT_KEY)));
  writeMarker(CASE_KEY, W2);
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  const b = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.deepEqual([b.revoked[0].revoking_commit, b.revoked[0].revoked_in_document_commit], [R, W]);
  // a read that fails before the first valid marker is found fails closed
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  const stray = gh.commitsFor(PINS, markerPath(CASE_KEY)).slice(-1)[0].sha;
  gh.forceRawFailure(1, 503, `${PINS}@${stray}`);
  const u = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.deepEqual([u.code, u.reason], ["signer_revoked", "revocation_marker_unreadable"]);
});

test("R-I2 m6: the marker is read at R, not at the path's head: a later write of other content does not change what R says", async () => {
  const c = await sealedCase("R-I2 at R");
  const { R, W, path: mp } = await revoke(CASE_KEY, CASE_REVOKED);
  gh.seed(PINS, mp, { not: "a marker" }, { keepHistory: true });
  assert.deepEqual(gh.read(PINS, mp), { not: "a marker" }, "fixture: the head differs");
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  const a = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.equal(a.code, "signer_since_revoked", JSON.stringify(a));
  assert.deepEqual([a.revoked[0].revoking_commit, a.revoked[0].revoked_in_document_commit], [R, W]);
});

test("R-I2 M1 (the tool): the tool runs the reader's check on the marker it would write, against the readers' published branch, and refuses one the reader would reject", async () => {
  // the operator walks a branch the readers do not use
  gh.setBranch(S.KEY_DOCUMENT_REPO, "release");
  KD.serve(gh, CASE_REVOKED);
  const out = await TOOL.recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: CASE_REVOKED, branch: "release", write: true });
  assert.deepEqual([out.ok, out.code], [false, "marker_rejected"], JSON.stringify(out));
  assert.match(out.reason, /revocation_marker_(invalid|unreadable)/);
  assert.equal(gh.has(PINS, markerPath(CASE_KEY)), false, "nothing written");
  // the readers' branch named: it passes, and is written
  process.env.KEY_DOCUMENT_BRANCH = "release";
  const ok = await TOOL.recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: CASE_REVOKED, write: true });
  assert.equal(ok.ok, true, JSON.stringify(ok));
});

test("R-I2 m2: a case under a revoked key whose pin is not pinned says why: case_not_pinned (no pin, or a legacy one with no case_commit), pin_commit_mismatch, or pin_unreadable:<reason>", async () => {
  const c = await sealedCase("R-I2 pin states");
  await revoke(CASE_KEY, CASE_REVOKED);
  const { latest, seq } = S.pinPaths(c.id);
  const pin = gh.read(PINS, latest);
  // the pin names the commit that opened the case: the file there is another case
  const opened = gh.commitsFor(PINS, C.casePath(c.id)).slice(-1)[0].sha;
  gh.seed(PINS, latest, { ...pin, case_commit: opened });
  assert.deepEqual(await reasonOf(c.k, CASE_REVOKED), ["signer_revoked", "pin_commit_mismatch"]);
  gh.seed(PINS, latest, pin);
  S._internal.clearDocumentCache();
  gh.forceGetFailure(PINS, latest, 1, 503);
  const u = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.deepEqual([u.code, u.reason], ["signer_revoked", "pin_unreadable:pin_pointer_unreadable"]);
  // a legacy pin with no case_commit
  const { case_commit: _cc, ...legacy } = pin; // eslint-disable-line no-unused-vars
  gh.seed(PINS, latest, legacy);
  gh.seed(PINS, seq, legacy);
  assert.deepEqual(await reasonOf(c.k, CASE_REVOKED), ["signer_revoked", "case_not_pinned"]);
});

test("R-I2 m3: the DOES NOT VERIFY notice says the current document's two rules, one sentence each", async () => {
  const c = await sealedCase("R-I2 notice");
  const unlisted = await pageOf(c.id, KD.docWith(KD.reconcileEntry(RECEIPT_KEY)));
  const revoked = await pageOf(c.id, (KD.serve(gh, CASE_REVOKED), CASE_REVOKED));
  for (const p of [unlisted, revoked]) {
    assert.match(p.html, /Each key that signed it must also be listed in its role in the current key document; a key that is not makes the record signer_unlisted\./);
    assert.match(p.html, /A key the current key document lists as revoked holds only for a case whose case file was written before the key&#39;s revocation was recorded in the pins repository|A key the current key document lists as revoked holds only for a case whose case file was written before the key's revocation was recorded in the pins repository/);
  }
});

test("R-I2 m4: a compare 404 is off only on a branch that exists: a branch that does not exist, or a branch read that fails, is unknown (branch_unreadable), and the branch read is kept; the page does not say 'try again' for a commit off the branch", async () => {
  // unit R-N (n1): off, and marked as a 404, so a walk that skips on it reads it again
  assert.deepEqual(await S.commitOnBranch("6".repeat(40)), { on: false, not_found: true }, "main exists: a commit it does not have is off");
  const n = gh.branchLog.length;
  assert.deepEqual(await S.commitOnBranch("6".repeat(40)), { on: false, not_found: true });
  assert.equal(gh.branchLog.length, n, "the branch read is kept");
  assert.deepEqual(await S.commitOnBranch("6".repeat(40), { branch: "no-such-branch" }), { unknown: "branch_unreadable" });
  S._internal.clearDocumentCache();
  gh.forceBranchFailure(1, 503);
  assert.deepEqual(await S.commitOnBranch("6".repeat(40)), { unknown: "branch_unreadable" });
  // the page, for a case naming a commit off the branch
  const c = await committedCase("R-I2 page off branch");
  const compared = RECONCILE.compare(c.a.tape, c.b.tape, { env: KEYS, now: REVEAL_AT, keyDocument: DOC });
  const named = KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.entry(LOG_KEY));
  const side = KD.serveOffBranch(gh, named, "3".repeat(40));
  const k = S.sealCase(storedCase(c.id), {
    reveals: { a: { tape_sha256: c.a.tape_sha256, salt: c.a.salt }, b: { tape_sha256: c.b.tape_sha256, salt: c.b.salt } },
    receipt: S.storableReceipt(compared.receipt).receipt, crossReference: null, revealedAt: C.utcSeconds(REVEAL_AT),
    signedUnder: { document_sha256: KD.sha256(canonicalBytes(named)), document_commit: side, retrieved_at: C.utcSeconds(REVEAL_AT) },
  }, S.loadCaseSigner(KEYS, { keyDocument: named }));
  gh.seed(PINS, C.casePath(c.id), k);
  const p = await pageOf(c.id, DOC);
  assert.equal(p.status, 503);
  assert.ok(p.html.includes("is not on the published branch"), "says what it is");
  assert.ok(!p.html.includes("try again"), "no retry will change it");
});

test("R-I2 m1, m7: the key document's notes say a retired key still verifies seals under a document where it was active with no commit order, that a key suspected of compromise must be revoked, not retired, and that a legacy pin with no case_commit under a revoked key reads case_not_pinned and cannot be upgraded", () => {
  const doc = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "public", ".well-known", "arcaeon", "case-signing-keys.json"), "utf8"));
  assert.equal(S.checkKeyDocument(doc).ok, true);
  const all = `${doc.description} ${JSON.stringify(doc.status_meaning)} ${doc.rotation}`;
  assert.match(doc.status_meaning.retired, /still verifies .* no commit order/);
  assert.match(all, /suspected of compromise must be revoked, not retired/);
  assert.match(all, /a legacy pin with no case_commit .* reads case_not_pinned and cannot be upgraded/);
});

test("R-I2 M2, m5: no reader, tool or note says more than is proven ('pinned before the revocation', 'revoked after this case was pinned'); KEY_DOCUMENT_BRANCH is documented in both tools' usage and in README.md", () => {
  const root = path.join(__dirname, "..");
  const files = ["lib/_case_page.js", "lib/_case_seal.js", "lib/_case_http.js", "public/.well-known/arcaeon/case-signing-keys.json", "tools/record_key_revocation.js"];
  for (const f of files) {
    assert.ok(!/pinned before the revocation|revoked after this case was pinned/.test(fs.readFileSync(path.join(root, f), "utf8")), f);
  }
  const usage = (f) => {
    const text = fs.readFileSync(path.join(root, f), "utf8");
    const at = text.search(/usage|USAGE|OPERATOR COMMAND/);
    return text.slice(at, at + 4000);
  };
  for (const f of ["tools/preview_dry_run.js", "tools/record_key_revocation.js"]) assert.match(usage(f), /KEY_DOCUMENT_BRANCH/, f);
  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
  assert.match(readme, /^#+ .*KEY_DOCUMENT_BRANCH/m, "a README section");
  assert.match(readme, /default `?main`?/);
  assert.match(readme, /steps \(e\) and \(f\)/);
});

// =============================================================================
// UNIT R-I2, THE MUST-FAIL PASS: tests for the planted defects the tests above let through
// =============================================================================

test("R-I2 GAP (P11, P13): the could-not-look page's heading says a commit off the branch is not on it, and a current document that does not read is named as the current one", async () => {
  const c = await sealedCase("R-I2 gap headings");
  const current = await pageOf(c.id, null);
  assert.ok(current.html.includes("The current one could not be read on this request"));
  const d = await committedCase("R-I2 gap headings, off branch");
  const compared = RECONCILE.compare(d.a.tape, d.b.tape, { env: KEYS, now: REVEAL_AT, keyDocument: DOC });
  const named = KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.entry(LOG_KEY, { status: "retired" }));
  const side = KD.serveOffBranch(gh, named, "2".repeat(40));
  gh.seed(PINS, C.casePath(d.id), S.sealCase(storedCase(d.id), {
    reveals: { a: { tape_sha256: d.a.tape_sha256, salt: d.a.salt }, b: { tape_sha256: d.b.tape_sha256, salt: d.b.salt } },
    receipt: S.storableReceipt(compared.receipt).receipt, crossReference: null, revealedAt: C.utcSeconds(REVEAL_AT),
    signedUnder: { document_sha256: KD.sha256(canonicalBytes(named)), document_commit: side, retrieved_at: C.utcSeconds(REVEAL_AT) },
  }, S.loadCaseSigner(KEYS, { keyDocument: named })));
  const off = await pageOf(d.id, DOC);
  assert.ok(off.html.includes("<h2>The key document this case names is not on the published branch</h2>"));
});

test("R-I2 GAP (S03): a case under a revoked key whose pin pointer does not read as a pin says pin_unreadable with the judge's reason", async () => {
  const c = await sealedCase("R-I2 gap pin unreadable");
  await revoke(CASE_KEY, CASE_REVOKED);
  gh.seed(PINS, S.pinPaths(c.id).latest, { not: "a pin" });
  const [code, reason] = await reasonOf(c.k, CASE_REVOKED);
  assert.equal(code, "signer_revoked");
  assert.match(reason, /^pin_unreadable:/);
  assert.notEqual(reason, "pin_unreadable:pin_pointer_unreadable");
});

test("R-I2 GAP (S11, L02): the branch read carries the pin token; a short history is walked in one commits read", async () => {
  const heard = [];
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    if (String(url).includes("/branches/")) heard.push((o && o.headers) || {});
    return viaMock(url, o);
  };
  try {
    await S.commitOnBranch("6".repeat(40));
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(heard.length, 1);
  assert.equal(heard[0].authorization, "Bearer test-token");
  const c = await sealedCase("R-I2 gap one read");
  const { path: mp } = await revoke(CASE_KEY, CASE_REVOKED);
  S._internal.clearDocumentCache();
  const n = gh.commitsLog.filter((p) => p === mp).length;
  assert.equal((await S.sealedRecordReason(c.k, CASE_REVOKED)).code, "signer_since_revoked");
  assert.equal(gh.commitsLog.filter((p) => p === mp).length - n, 1, "one page, one read");
});

test("R-I2 GAP (M03): a commit that removed the marker file reads as nothing there, not as a read that failed: a stray marker removed and a valid one written after it gives R at the valid one", async () => {
  const c = await sealedCase("R-I2 gap removed");
  const W = KD.serve(gh, CASE_REVOKED);
  const mp = markerPath(CASE_KEY);
  gh.seed(PINS, mp, goodMarker(CASE_KEY, KD.commitOf(DOC))); // a stray first write
  gh.repos.get(PINS).delete(mp);
  gh._recordCommit(PINS, mp, "mock: removed", null); // a commit that removed it
  writeMarker(CASE_KEY, W);
  const a = await (async () => {
    S._internal.clearDocumentCache();
    S._internal.clearCommitFiles();
    return S.sealedRecordReason(c.k, CASE_REVOKED);
  })();
  // unit R-N2 (m1): a commit that removed the file is nothing there on every
  // read, so it stays a soft skip older than the valid marker, and R is not
  // shown: unreadable (the raw host cannot tell a removal from a 404 it has
  // not caught up on)
  assert.deepEqual([a.code, a.reason], ["signer_revoked", "revocation_marker_unreadable"], JSON.stringify(a));
});

test("R-I2 GAP (K02): a pin pointer whose numbered record has no commit at all is a pin commit that could not be read, never a crash", async () => {
  const c = await sealedCase("R-I2 gap no record commits", { pinFails: true });
  const chain = S.caseChain(c.k);
  const caseCommit = gh.commitsFor(PINS, C.casePath(c.id))[0].sha;
  gh.seed(PINS, S.pinPaths(c.id).latest, S._internal.pinRecord(c.id, chain, REVEAL_AT, caseCommit));
  assert.equal(gh.commitsFor(PINS, S.pinPaths(c.id).seq).length, 0, "fixture: the numbered record was never written");
  const st = await S.anchorState(c.id, chain, { anchor: false });
  assert.deepEqual([st.pin, st.reason], ["could_not_look", "pin_commit_unreadable"]);
});

test("R-I2 GAP (T02, J04, J05): the tool's printed usage names KEY_DOCUMENT_BRANCH; the notes say what 'pinned before it' means and that no later write moves the revoking commit", () => {
  const { spawnSync } = require("node:child_process");
  const out = spawnSync(process.execPath, [path.join(__dirname, "..", "tools", "record_key_revocation.js")], { encoding: "utf8" });
  assert.equal(out.status, 1);
  assert.match(out.stdout, /KEY_DOCUMENT_BRANCH names the key document's published branch \(main unless set\)/);
  const doc = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "public", ".well-known", "arcaeon", "case-signing-keys.json"), "utf8"));
  assert.match(doc.status_meaning.revoked, /the case-file commit the case's pin records comes before the revoking commit in the pins repository; it says nothing of when this document's revocation was committed or deployed/);
  assert.match(doc.rotation, /the oldest commit at which the marker's path holds a valid marker for the key, so no later write moves it/);
});

// =============================================================================
// UNIT R-N, THE FOLLOW-UPS (n1 to n7) from the second reader's pass over R-I2
// at be26c37
// =============================================================================

const fresh = async (k, current) => {
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  return S.sealedRecordReason(k, current);
};
const commitsReads = (mp) => gh.commitsLog.filter((p) => p === mp).length;

test("R-N n1: a raw-host 404 at the real R, with a later rewrite that is valid, does not let the rewrite become R: the skipped commit is read once more, and unless it skips again the answer is revocation_marker_unreadable; a marker found after such a skip is not kept", async () => {
  const c = await sealedCase("R-N n1 raw");
  const { R, path: mp } = await revoke(CASE_KEY, CASE_REVOKED);
  // a case pinned after R, then a rewrite of the same valid marker after it
  const late = await sealedCase("R-N n1 raw, late");
  const R2 = gh.addCommit(PINS, mp);
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  gh.forceRawFailure(1, 404, `${PINS}@${R}:${mp}`);
  const a = await S.sealedRecordReason(late.k, CASE_REVOKED);
  assert.deepEqual([a.code, a.reason], ["signer_revoked", "revocation_marker_unreadable"], "R read again holds a marker: the rewrite is not R");
  // unit R-N2 (m1): the 404 holds on the second read: still skipped, so R is
  // not shown, and the answer is unreadable, never the rewrite
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  gh.forceRawFailure(2, 404, `${PINS}@${R}:${mp}`);
  const b = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.deepEqual([b.code, b.reason], ["signer_revoked", "revocation_marker_unreadable"], JSON.stringify(b));
  assert.notEqual(R2, R);
  assert.equal(gh.rawLog.filter((k) => k === `${PINS}@${R}:${mp}`).length >= 2, true, "read twice");
  const n = commitsReads(mp);
  const again = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.equal(commitsReads(mp), n + 1, "walked again: a marker found after a skip is never kept");
  assert.equal(again.revoked[0].revoking_commit, R, "and R, once it reads, is R");
  await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.equal(commitsReads(mp), n + 1, "a marker found with no skip is kept");
});

test("R-N n1: a compare 404 on the revoking commit of the real R (the branch known to exist) is the same: read again, unreadable unless it skips again", async () => {
  await sealedCase("R-N n1 compare");
  const { R, W, path: mp } = await revoke(CASE_KEY, CASE_REVOKED);
  const late = await sealedCase("R-N n1 compare, late");
  gh.addCommit(PINS, mp);
  const branchCompare = `${S.KEY_DOCUMENT_REPO}:${S.keyDocumentBranch()}...${W}`;
  // the branch is known to exist (kept), so the 404 alone reads as off
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  assert.deepEqual(await S.commitOnBranch("8".repeat(40)), { on: false, not_found: true }, "a 404 on a branch that exists");
  gh.forceCompareFailure(1, 404, branchCompare);
  S._internal.clearCommitFiles();
  const a = await S.sealedRecordReason(late.k, CASE_REVOKED);
  assert.deepEqual([a.code, a.reason], ["signer_revoked", "revocation_marker_unreadable"]);
  assert.ok(gh.compareLog.filter((k) => k === branchCompare).length >= 2, "the skipped candidate's order read again");
  // unit R-N2 (m1): a second 404 on the re-read is still a soft skip: unreadable, and nothing kept
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  gh.forceCompareFailure(2, 404, branchCompare);
  const b = await S.sealedRecordReason(late.k, CASE_REVOKED);
  assert.deepEqual([b.code, b.reason], ["signer_revoked", "revocation_marker_unreadable"]);
  assert.equal(b.revoked[0].revoking_commit, undefined, "no R");
  const n = commitsReads(mp);
  await S.sealedRecordReason(late.k, CASE_REVOKED);
  assert.equal(commitsReads(mp), n + 1, "not kept");
});

test("R-N n2: the walk of a path's commits follows the Link header's rel=\"next\": a short page with a next page is not the last, for the reader and for the tool", async () => {
  const c = await sealedCase("R-N n2");
  const { R, path: mp } = await revoke(CASE_KEY, CASE_REVOKED);
  const late = await sealedCase("R-N n2, late");
  for (let i = 0; i < 12; i += 1) gh.addCommit(PINS, mp);
  gh.commitsPageCap = 5; // the host answers five a page, and says there are more
  const a = await fresh(late.k, CASE_REVOKED);
  assert.deepEqual([a.code, a.reason], ["signer_revoked", "pinned_at_or_after_revocation"], "R is the oldest, past the short pages");
  assert.equal((await fresh(c.k, CASE_REVOKED)).revoked[0].revoking_commit, R);
  // the tool's walk of the key document's history, the same
  gh.commitsPageCap = 0;
  const RECEIPT_GONE = KD.docWith(KD.entry(CASE_KEY), revokedIn(RECEIPT_KEY, "2026-10-12", "reconcile"));
  const first = KD.serve(gh, RECEIPT_GONE);
  for (let i = 0; i < 7; i += 1) KD.serve(gh, KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY, { status: "revoked", revokedSince: "2026-10-12", note: `again ${i}` })));
  gh.commitsPageCap = 3;
  const out = await TOOL.recordRevocation({ keyId: KD.keyIdOf(RECEIPT_KEY), currentDocument: RECEIPT_GONE });
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(out.marker.revoked_in_commit, first, "the oldest, past the short pages");
});

test("R-N n2: a next page that does not move forward is a list that cannot be read, never a loop", async () => {
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    const r = await viaMock(url, o);
    if (!String(url).includes("/commits?")) return r;
    return { ...r, headers: { get: (h) => (h.toLowerCase() === "link" ? `<https://api.github.com/repos/${PINS}/commits?path=x&page=1>; rel="next"` : null) } };
  };
  try {
    await assert.rejects(store.listCommitsPage("x", { perPage: 100, page: 1 }), /next page/);
  } finally {
    global.fetch = viaMock;
  }
});

test("R-N n4: the walk reads at most 200 candidates per request, then answers revocation_marker_unreadable; a valid marker at the 200th is found", async () => {
  // the case key: 199 stray writes, then the valid marker (the 200th candidate)
  const c = await sealedCase("R-N n4 cap");
  const W = KD.serve(gh, KD.docWith(revokedIn(CASE_KEY, "2026-10-11"), revokedIn(RECEIPT_KEY, "2026-10-11", "reconcile")));
  const both = KD.docWith(revokedIn(CASE_KEY, "2026-10-11"), revokedIn(RECEIPT_KEY, "2026-10-11", "reconcile"));
  gh.seed(PINS, markerPath(CASE_KEY), { stray: 0 });
  for (let i = 1; i < 199; i += 1) gh.seed(PINS, markerPath(CASE_KEY), { stray: i }, { keepHistory: true });
  const R = writeMarker(CASE_KEY, W);
  // the reconcile key: 200 stray writes, then the valid marker (the 201st)
  gh.seed(PINS, markerPath(RECEIPT_KEY), { stray: 0 });
  for (let i = 1; i < 200; i += 1) gh.seed(PINS, markerPath(RECEIPT_KEY), { stray: i }, { keepHistory: true });
  writeMarker(RECEIPT_KEY, W);
  const a = await fresh(c.k, KD.docWith(revokedIn(CASE_KEY, "2026-10-11"), KD.reconcileEntry(RECEIPT_KEY)));
  assert.equal(a.code, "signer_since_revoked", JSON.stringify(a).slice(0, 300));
  assert.equal(a.revoked[0].revoking_commit, R);
  const b = await fresh(c.k, both);
  assert.deepEqual([b.code, b.reason], ["signer_revoked", "revocation_marker_unreadable"], "the 201st candidate is never read");
  assert.equal(S.MARKER_CANDIDATES_READ, 200);
});

test("R-N n4: a negative compare is kept for the instance (off the branch; not before), a 404 is read again, and a key document read by commit is kept", async () => {
  const side = gh.seedSideCommit(S.KEY_DOCUMENT_REPO, "5".repeat(40));
  assert.deepEqual(await S.commitOnBranch(side), { on: false });
  let n = gh.compareLog.length;
  assert.deepEqual(await S.commitOnBranch(side), { on: false });
  // unit R-N2 (m2): off can change (the branch moves), so it is read again
  assert.equal(gh.compareLog.length, n + 1, "an answer that is off is read again");
  const ghost = "7".repeat(40);
  await S.commitOnBranch(ghost);
  n = gh.compareLog.length;
  await S.commitOnBranch(ghost);
  assert.equal(gh.compareLog.length, n + 1, "a 404 is read again");
  // not before: the order of a case pinned after R, read once
  await revoke(CASE_KEY, CASE_REVOKED);
  const late = await sealedCase("R-N n4 order kept");
  assert.equal((await S.sealedRecordReason(late.k, CASE_REVOKED)).reason, "pinned_at_or_after_revocation");
  n = gh.compareLog.length;
  assert.equal((await S.sealedRecordReason(late.k, CASE_REVOKED)).reason, "pinned_at_or_after_revocation");
  assert.equal(gh.compareLog.length, n, "an order that is not before is kept");
  // the document at a commit, read with nothing to match, is kept
  const W = KD.serve(gh, KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.entry(LOG_KEY)));
  const at = `${S.KEY_DOCUMENT_REPO}@${W}:`;
  assert.equal((await S.fetchNamedDocument(W)).ok, true);
  const r = gh.rawLog.filter((k) => k.startsWith(at)).length;
  assert.equal((await S.fetchNamedDocument(W)).ok, true);
  assert.equal(gh.rawLog.filter((k) => k.startsWith(at)).length, r, "kept by its commit");
  // a failed read is not kept
  const W2 = KD.serve(gh, KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.entry(LOG_KEY, { status: "retired" })));
  gh.forceRawFailure(1, 503, W2);
  assert.equal((await S.fetchNamedDocument(W2)).ok, false);
  assert.equal((await S.fetchNamedDocument(W2)).ok, true);
});

test("R-N n5: the banner says the key document lists the key as revoked AT its commit W", async () => {
  const c = await sealedCase("R-N n5");
  const { W, R } = await revoke(CASE_KEY, CASE_REVOKED);
  const p = await pageOf(c.id, CASE_REVOKED);
  assert.ok(p.html.includes(bannerSentence(c.P, R, W)));
  assert.ok(p.html.includes("lists the key as revoked at its commit"));
  assert.ok(!p.html.includes("revoked from its commit"));
});

test("R-N n6: pinned_at_or_after_revocation is answered only when the compare shows that order; a compare that cannot show it (a 404, or diverged) is order_not_shown", async () => {
  const c = await sealedCase("R-N n6");
  const { R } = await revoke(CASE_KEY, CASE_REVOKED);
  S._internal.clearDocumentCache();
  gh.forceCompareFailure(1, 404, `${PINS}:${R}...${c.P}`);
  const nf = await S.sealedRecordReason(c.k, CASE_REVOKED);
  assert.deepEqual([nf.code, nf.reason], ["signer_revoked", "order_not_shown"]);
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    if (String(url).endsWith(`/compare/${R}...${c.P}`)) {
      return { status: 200, ok: true, json: async () => ({ status: "diverged", ahead_by: 1, behind_by: 1 }), text: async () => "{}" };
    }
    return viaMock(url, o);
  };
  try {
    S._internal.clearDocumentCache();
    const dv = await S.sealedRecordReason(c.k, CASE_REVOKED);
    assert.deepEqual([dv.code, dv.reason], ["signer_revoked", "order_not_shown"]);
  } finally {
    global.fetch = viaMock;
  }
  // ahead stays pinned_at_or_after_revocation (I1 above; identical: MUST-FAIL GAP P01)
  const late = await sealedCase("R-N n6 late");
  assert.equal((await fresh(late.k, CASE_REVOKED)).reason, "pinned_at_or_after_revocation");
});

test("R-N n6: the tool's notes and the change log say no more than the reason code does", () => {
  const root = path.join(__dirname, "..");
  const tool = fs.readFileSync(path.join(root, "tools", "record_key_revocation.js"), "utf8");
  assert.ok(!/pinned before the key was revoked/.test(tool), "the tool's comment");
  const log = fs.readFileSync(path.join(root, "CHANGELOG.md"), "utf8");
  assert.ok(!log.includes("\"Pinned before the revocation\" is gone from the page, the refusal words and the notes."), "the R-I2 line");
  assert.match(log, /`pinned_at_or_after_revocation`[^\n]*only when the compare shows that order[^\n]*`order_not_shown`/);
});

test("R-N: tools/preview_dry_run.js prints KEY_DOCUMENT_BRANCH in its usage (--help), not only in a comment", () => {
  const { spawnSync } = require("node:child_process");
  const out = spawnSync(process.execPath, [path.join(__dirname, "..", "tools", "preview_dry_run.js"), "--help"], { encoding: "utf8" });
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /KEY_DOCUMENT_BRANCH/);
  assert.match(out.stdout, /published/);
});

test("R-N n3: the README says a marker path forced past the walk's bound reads unreadable for good, accepted", () => {
  const readme = fs.readFileSync(path.join(__dirname, "..", "README.md"), "utf8");
  assert.match(readme, /5,000 commits or more[^.]*revocation_marker_unreadable[^.]*for good/);
});
