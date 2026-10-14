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
//   I1  retrieved_at is display only. Since unit R-REV (2026-10-14) a key
//       the current document lists as revoked is signer_revoked, whenever
//       it signed: no marker, pin or order is read (the revocation markers
//       and their tool are removed; test/case_rrev.test.js holds the rule).
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
// The current document after the case key is revoked.
const CASE_REVOKED = Object.freeze(KD.docWith(KD.entry(CASE_KEY, { status: "revoked" }), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0071" });

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
  const pin = gh.read(PINS, S.pinPaths(c.id).seq);
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

// =============================================================================
// I1: a revoked signer (since unit R-REV, no order is read)
// =============================================================================

test("I1 (since unit R-REV): a case whose signer the current document lists as revoked is signer_revoked, pinned or not: the sealer does not pin an unpinned one", async () => {
  const c = await sealedCase("I1 unpinned", { pinFails: true });
  assert.equal(c.P, null, "fixture: no pin");
  const pinned = await sealedCase("I1 pinned");
  assert.notEqual(pinned.P, null, "fixture: a pin");
  for (const k of [c.k, pinned.k]) {
    const got = await S.sealedRecordReason(k, CASE_REVOKED);
    assert.deepEqual([got.code, got.reason], ["signer_revoked", "key_revoked"]);
  }
  const anchored = await S.anchorCase(c.id, { now: REVEAL_AT + 60000, keyDocument: CASE_REVOKED });
  assert.deepEqual([anchored.code, anchored.reason], ["not_sealed", "signer_revoked"]);
  assert.equal(gh.has(PINS, S.pinPaths(c.id).seq), false, "the sealer does not pin it");
});

// =============================================================================
// I2: the reveal reads the document at its own commit
// =============================================================================

test("I2: a reveal whose bundled document's sha256 differs from the document at its commit is 503 document_unavailable: no attempt, nothing compared; the mismatching read is not cached, and once the commit serves the bundle the reveal seals", async (t) => {
  const c = await committedCase("I2 differs");
  const other = KD.docWith(KD.entry(CASE_KEY, { note: "another document" }), KD.reconcileEntry(RECEIPT_KEY));
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
  assert.equal(gh.has(PINS, S.pinPaths(c.id).seq), false);
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

test("MUST-FAIL GAP (S08): a case key the current document lists only as a reconcile key is unlisted", async () => {
  const c = await sealedCase("gap roles");
  assert.deepEqual(await S.sealedRecordReason(c.k, KD.docWith(KD.reconcileEntry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY))),
    { code: "signer_unlisted", reason: "case_key_not_listed", key_id: KD.keyIdOf(CASE_KEY) });
});

test("MUST-FAIL GAP (H03, H04, G04, G05): the reference and the page say signer_unlisted and signer_revoked in words", async () => {
  const c = await sealedCase("gap words");
  const noCase = KD.docWith(KD.reconcileEntry(RECEIPT_KEY));
  const u = await referenceAs(c.id, c.a, noCase);
  assert.match(u.body.error, /a key that signed it is not listed in its role in the current key document/);
  assert.ok((await pageOf(c.id, noCase)).html.includes("the current key document: a key that signed it is not listed there in its role"));
  // since unit R-REV: revoked, whenever it signed; the page's one sentence
  const r = await referenceAs(c.id, c.a, CASE_REVOKED);
  assert.deepEqual([r.status, r.body.error_code, r.body.reason, r.body.key_id], [409, "signer_revoked", "key_revoked", KD.keyIdOf(CASE_KEY)]);
  assert.match(r.body.error, /^One of the keys this case is signed with \(.+\) is listed as revoked in the key document this service carries \(commit not known to this deployment\), so this case takes no reference row, whenever it was signed; no row was written\.$/);
  assert.ok((await pageOf(c.id, CASE_REVOKED)).html.includes(`One of the keys this case is signed with (<code>${KD.keyIdOf(CASE_KEY)}</code>) is listed as revoked ` +
    "in the key document this service carries (commit not known to this deployment), so this page does not show its verdict, whenever it was signed."));
});

test("MUST-FAIL GAP (B01): KEY_DOCUMENT_BRANCH names the branch: a deployment of another branch seals when it names that branch, and is refused when it does not", async () => {
  gh.setBranch(S.KEY_DOCUMENT_REPO, "preview-branch");
  const doc = KD.docWith(KD.entry(CASE_KEY, { note: "another document" }), KD.reconcileEntry(RECEIPT_KEY));
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

test("R-I2 B1 (commitsOf): the commit that wrote a pin record is the oldest touching it, past the first page of its history", async () => {
  const c = await sealedCase("R-I2 commitsOf");
  const { seq } = S.pinPaths(c.id);
  const wrote = gh.commitsFor(PINS, seq);
  assert.equal(wrote.length, 1, "fixture: written once");
  for (let i = 0; i < 105; i += 1) gh.addCommit(PINS, seq);
  S._internal.clearCommitFiles();
  const st = await S.pinState(c.id, S.caseChain(c.k));
  assert.equal(st.pin, "pinned");
  assert.equal(st.pin_commit.sha, wrote[0].sha, "the commit that wrote it, not the 100th newest");
});

test("R-I2 m3 (since unit R-REV): the DOES NOT VERIFY notice says the current document's one rule; a revoked key's case is not that page", async () => {
  const c = await sealedCase("R-I2 notice");
  const unlisted = await pageOf(c.id, KD.docWith(KD.reconcileEntry(RECEIPT_KEY)));
  assert.match(unlisted.html, /Each key that signed it must also be listed in its role in the current key document; a key that is not makes the record signer_unlisted\./);
  assert.ok(!/revoked/.test(unlisted.html), "no revocation rule");
  const revoked = await pageOf(c.id, CASE_REVOKED);
  assert.ok(!revoked.html.includes("The sealed record does not verify"));
  assert.ok(revoked.html.includes("SIGNED BY A REVOKED KEY"));
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

test("R-I2 m5 (since unit R-REV, with no revocation tool): KEY_DOCUMENT_BRANCH is documented in the preview tool's usage and in README.md", () => {
  const root = path.join(__dirname, "..");
  const usage = (f) => {
    const text = fs.readFileSync(path.join(root, f), "utf8");
    const at = text.search(/usage|USAGE|OPERATOR COMMAND/);
    return text.slice(at, at + 4000);
  };
  assert.match(usage("tools/preview_dry_run.js"), /KEY_DOCUMENT_BRANCH/);
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
  assert.ok(current.html.includes("The current one could not be read when this page was read"));
  const d = await committedCase("R-I2 gap headings, off branch");
  const compared = RECONCILE.compare(d.a.tape, d.b.tape, { env: KEYS, now: REVEAL_AT, keyDocument: DOC });
  const named = KD.docWith(KD.entry(CASE_KEY, { note: "another document" }), KD.reconcileEntry(RECEIPT_KEY));
  const side = KD.serveOffBranch(gh, named, "2".repeat(40));
  gh.seed(PINS, C.casePath(d.id), S.sealCase(storedCase(d.id), {
    reveals: { a: { tape_sha256: d.a.tape_sha256, salt: d.a.salt }, b: { tape_sha256: d.b.tape_sha256, salt: d.b.salt } },
    receipt: S.storableReceipt(compared.receipt).receipt, crossReference: null, revealedAt: C.utcSeconds(REVEAL_AT),
    signedUnder: { document_sha256: KD.sha256(canonicalBytes(named)), document_commit: side, retrieved_at: C.utcSeconds(REVEAL_AT) },
  }, S.loadCaseSigner(KEYS, { keyDocument: named })));
  const off = await pageOf(d.id, DOC);
  assert.ok(off.html.includes("<h2>The key document this case names is not on the published branch</h2>"));
});

test("R-I2 GAP (S11): the branch read carries the pin token", async () => {
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
});

test("R-I2 GAP (K02): a pin file with no commit at all is could_not_look, never a crash; since unit R-L (g5) it says the repository lists no commit for it (pin_commits_none), not that a read failed", async () => {
  const c = await sealedCase("R-I2 gap no record commits", { pinFails: true });
  const chain = S.caseChain(c.k);
  const caseCommit = gh.commitsFor(PINS, C.casePath(c.id))[0].sha;
  // the file put in the mock's tree directly, with no commit (unit R-PIN: there is no pointer to plant)
  gh._repoMap(PINS).set(S.pinPaths(c.id).seq, { content: JSON.stringify(S._internal.pinRecord(c.id, chain, REVEAL_AT, caseCommit), null, 2) + "\n", sha: "f".repeat(40) });
  assert.equal(gh.commitsFor(PINS, S.pinPaths(c.id).seq).length, 0, "fixture: no commit wrote the pin file");
  const st = await S.pinState(c.id, chain);
  assert.deepEqual([st.pin, st.reason], ["could_not_look", "pin_commits_none"]);
});

// =============================================================================
// UNIT R-N, THE FOLLOW-UPS (n1 to n7) from the second reader's pass over R-I2
// at be26c37
// =============================================================================

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

test("R-N n4: a negative compare is read again (off the branch), a 404 is read again, and a key document read by commit is kept", async () => {
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
  // the document at a commit, read with nothing to match, is kept
  const W = KD.serve(gh, KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.entry(LOG_KEY)));
  const at = `${S.KEY_DOCUMENT_REPO}@${W}:`;
  assert.equal((await S.fetchNamedDocument(W)).ok, true);
  const r = gh.rawLog.filter((k) => k.startsWith(at)).length;
  assert.equal((await S.fetchNamedDocument(W)).ok, true);
  assert.equal(gh.rawLog.filter((k) => k.startsWith(at)).length, r, "kept by its commit");
  // a failed read is not kept
  const W2 = KD.serve(gh, KD.docWith(KD.entry(CASE_KEY, { note: "another document" }), KD.reconcileEntry(RECEIPT_KEY)));
  gh.forceRawFailure(1, 503, W2);
  assert.equal((await S.fetchNamedDocument(W2)).ok, false);
  assert.equal((await S.fetchNamedDocument(W2)).ok, true);
});

test("R-N: tools/preview_dry_run.js prints KEY_DOCUMENT_BRANCH in its usage (--help), not only in a comment", () => {
  const { spawnSync } = require("node:child_process");
  const out = spawnSync(process.execPath, [path.join(__dirname, "..", "tools", "preview_dry_run.js"), "--help"], { encoding: "utf8" });
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /KEY_DOCUMENT_BRANCH/);
  assert.match(out.stdout, /published/);
});
