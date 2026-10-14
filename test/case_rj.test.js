// test/case_rj.test.js — unit R-J (2026-10-13): the row sentence, what
// "anchored" claims, a wrong commit is a mismatch, and the case checked by
// bytes. A second-model review of Design J at 7041aa8 found:
//   BLOCKER 1  the reference row's signed anchor_note said the row is
//              anchored by the commit that writes it and the daily anchor of
//              the head; no reader computes that, and a commit alone never
//              anchors;
//   MAJOR 2    "anchored" checks no OpenTimestamps proof and no signature;
//   MAJOR 3    a forged or wrong case_commit read could_not_look, never
//              pin_commit_mismatch;
//   MAJOR 4    the case was compared by chain (minus sig), rows by bytes;
//   MINORS     non-JSON at a pin's oldest commit or an anchor head read
//              could_not_look; no ancestry check on Design J's commits; each
//              page view made many uncached reads; case_not_anchored meant
//              "not pinned".
// The binding decisions J1-J8 are in each test's name. The setup below is
// test/case_commits.test.js's.
// Unit R-PIN (2026-10-13) removed the anchor reader, the row commits and the
// page cache, and with them J2's test, J7's cache half, J8's refusal and the
// gap tests of that code; the rest read the one pin with pinState.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0061:case-test-";
for (const k of ["WITNESS_BATCH_SHADOW", "WITNESS_ADMIN_KEY", "WITNESS_CASE_OPERATOR_KEY", "WITNESS_CASE_SIGNER_KEY",
  "WITNESS_RECONCILE_SIGNER_KEY", "WITNESS_RECONCILE_VERIFIER", "WITNESS_LOG_SIGNER_KEY", "VERCEL_GIT_COMMIT_SHA"]) {
  delete process.env[k];
}

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const REG = require("./helpers/case_registration.js");
const KD = require("./helpers/key_document.js");
const store = require("../lib/_store.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const S = require("../lib/_case_seal.js");
const CP = require("../lib/_case_page.js");
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const stamp = require("../lib/_stamp.js");
const statusData = require("../lib/_status_data.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z");
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rj");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rj");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rj");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0061" });
const PINS_URL = `https://github.com/${PINS}`;

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
});
afterEach(() => {
  store._putRetry.sleep = realSleep;
  restore();
});

let ipSeq = 0;
function req(op, body, headers = {}) {
  ipSeq += 1;
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": `10.97.${(ipSeq >> 8) & 255}.${ipSeq & 255}`, ...headers }, body });
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
async function reveal(c) {
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", revealBody(c.id, c.a, c.b)), res, { now: REVEAL_AT, env: KD.deployed(gh, KEYS, DOC), keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
async function sealedCase(scope, { pinFails = false } = {}) {
  const c = await committedCase(scope);
  if (pinFails) gh.forceFailure(PINS, S.pinPaths(c.id).seq, 1, 502);
  const r = await reveal(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  return { ...c, r };
}
// A page view (unit R-PIN: no page cache, so every view reads).
async function casePage(id, { now = REVEAL_AT + 3600000, ip = null } = {}) {

  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": ip || `10.98.0.${(ipSeq += 1) & 255}` } }), res,
    { now, keyDocument: DOC, env: {} });
  return { status: res._status, html: String(res._body) };
}
const storedCase = (id) => gh.read(PINS, C.casePath(id));
const chainOf = (id) => S.caseChain(storedCase(id));
// The commit that wrote the sealed case file: the newest touching it.
const sealCommit = (id) => gh.commitsFor(PINS, C.casePath(id))[0].sha;
// Run `inner` when the first request whose URL includes `match` goes out,
// then let that request through.
function onFirstRequest(match, inner) {
  const viaMock = global.fetch;
  let fired = false;
  global.fetch = async (url, o) => {
    if (!fired && String(url).includes(match)) {
      fired = true;
      await inner();
    }
    return viaMock(url, o);
  };
  return () => { global.fetch = viaMock; };
}
// The case file rewritten in place, in its own commit (a swapped file).
function rewriteCase(id, rec) {
  const p = C.casePath(id);
  gh._repoMap(PINS).get(p).content = JSON.stringify(rec, null, 2) + "\n";
  return gh.addCommit(PINS, p, "mock: the case file rewritten");
}
// A pin for `chain` naming `caseCommit`, written over the case's one pin file.
function plantPin(id, chain, caseCommit) {
  const rec = { ...S._internal.pinRecord(id, chain, REVEAL_AT, caseCommit) };
  if (caseCommit === undefined) delete rec.case_commit;
  gh.seed(PINS, S.pinPaths(id).seq, rec);
  return rec;
}
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0051", url: "https://second-operator.example/cases/0051" });
async function reference(c, role = "a", ref = "row") {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: { ...XREF, reference: ref } }),
    res, { now: REVEAL_AT + 1800000, env: KEYS, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
const rowPath = (id, n) => C.referencePath(id, n);
// The row's line on the page, from its label to the end of its table row.
function rowLine(html, n) {
  const at = html.indexOf(`reference row ${n}`);
  assert.ok(at >= 0, `the page shows reference row ${n}`);
  return html.slice(at, html.indexOf("</tr>", at));
}
const caseText = (id) => gh._repoMap(PINS).get(C.casePath(id)).content;

// =============================================================================
// J1: the row's sentence (version 4 since unit R-PIN)
// =============================================================================

const V1_NOTE = "This row has no pin of its own. It is anchored by the pins-repository commit that writes it and by the daily anchor " +
  "of the repository head. It never changes the sealed case: the case's records field is the count at seal time, and a " +
  "reader counts this row as a second record only if the row is valid.";
// unit R-J2 (B2) to unit R-PIN: version 3, recorded since as never issued
const V3_NOTE = "This row has no pin of its own. It is recorded by the pins-repository commit that writes it. A later pin of the case may list " +
  "that commit. This row is anchored only if a pin that lists it is, and no anchoring is asserted here.";
// since unit R-PIN: version 4
const V4_NOTE = "This row has no pin of its own. It is recorded by the pins-repository commit that writes it, and no anchoring is asserted here.";

test("J1 (version 4 since unit R-PIN): REFERENCE_ANCHOR_NOTE is the current version and rows carry its note_version; the judge accepts it and rejects a v1 row with reason row_note_v1 and a v3 row with row_note_v3", async () => {
  assert.equal(C.REFERENCE_ANCHOR_NOTE, V4_NOTE);
  assert.ok(C.REFERENCE_FIELDS.includes("note_version"));
  const { id } = await sealedCase("RJ J1 judge");
  const signer = S.loadCaseSigner(KEYS, { keyDocument: DOC });
  const good = S.referenceRow({ caseId: id, seq: 1, crossReference: XREF, recordedAt: "2026-10-10T10:00:00Z", appendedBy: "operator" }, signer);
  assert.deepEqual([good.note_version, good.anchor_note], [4, V4_NOTE]);
  assert.equal(C.validateReferenceRow(good).ok, true);
  const { note_version: _v, ...v1 } = { ...good, anchor_note: V1_NOTE };
  assert.equal(C.validateReferenceRow(v1).code, "row_note_v1");
  assert.equal(C.validateReferenceRow({ ...good, anchor_note: V3_NOTE, note_version: 3 }).code, "row_note_v3");
  gh.seed(PINS, rowPath(id, 1), v1);
  const live = await S.liveRecords(storedCase(id), { keyDocument: DOC });
  assert.deepEqual([live.records, live.invalid], [1, [{ seq: 1, reason: "row_note_v1" }]]);
  gh.seed(PINS, rowPath(id, 1), good);
  assert.equal((await S.liveRecords(storedCase(id), { keyDocument: DOC })).records, 2, "the v4 row is a record");
});

test("J1: a row's 201 body: the row and the answer carry the v4 note, and the answer names no row commit (unit R-PIN)", async () => {
  const c = await sealedCase("RJ J1 body");
  const r = await reference(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.deepEqual([r.body.anchor_note, r.body.row.anchor_note, r.body.row.note_version], [V4_NOTE, V4_NOTE, 4]);
  for (const k of ["row_commit", "row_commit_note"]) assert.equal(Object.prototype.hasOwnProperty.call(r.body, k), false, k);
  assert.doesNotMatch(r.body.anchor_note, /anchored by|daily anchor of the repository head/);
});

// =============================================================================
// J2: "anchored" claims what is checked, and says the proof is not
// =============================================================================

// =============================================================================
// J3, J4: a wrong commit is a mismatch; the case is checked by its bytes
// =============================================================================

test("J3: a pin naming a commit that does not exist, or one at which the case file is absent, is pin_commit_mismatch (the commit's existence read once from the commits API); only a transport failure is could_not_look", async () => {
  const early = gh.seedText(PINS, "notes/before-the-case.txt", "a commit from before the case\n");
  const early2 = gh.seedText(PINS, "notes/also-before.txt", "another commit from before the case\n");
  const { id } = await sealedCase("RJ J3");
  const chain = chainOf(id);
  plantPin(id, chain, "f".repeat(40));
  assert.deepEqual(await S.pinState(id, storedCase(id)).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_commit_not_found"]);
  assert.ok(gh.commitLog.includes(`${PINS}:${"f".repeat(40)}`), "the commits API was asked");
  plantPin(id, chain, early);
  assert.deepEqual(await S.pinState(id, storedCase(id)).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_absent_at_commit"]);
  // transport failures: the raw read, and the existence read
  plantPin(id, chain, sealCommit(id));
  S._internal.clearCommitFiles();
  gh.forceRawFailure(1, 503, `:${C.casePath(id)}`);
  assert.deepEqual(await S.pinState(id, storedCase(id)), { pin: "could_not_look", reason: "case_at_commit_http_503", case_commit: sealCommit(id) }); // unit R-L (g3)
  plantPin(id, chain, early2);
  gh.forceCommitFailure(1, 503);
  assert.deepEqual(await S.pinState(id, storedCase(id)), { pin: "could_not_look", reason: "case_commit_exists_http_503", case_commit: early2 });
});

test("J4: the case is compared at case_commit byte for byte, sig included: a served case whose sig differs from the bytes at case_commit is pin_commit_mismatch; the case file link names case_commit", async () => {
  const { id } = await sealedCase("RJ J4");
  const stored = storedCase(id);
  const otherSig = { ...stored, sig: stored.sig.replace(/.$/, (ch) => (ch === "A" ? "B" : "A")) };
  assert.equal(S.caseChain(otherSig), chainOf(id), "fixture: the chain leaves sig out");
  assert.deepEqual(await S.pinState(id, otherSig).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_at_commit_differs"]);
  // served from the branch: the case file rewritten with that sig
  rewriteCase(id, otherSig);
  assert.deepEqual(await S.pinState(id, chainOf(id)).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_at_commit_differs"]);
  // the page's case file link, on a case that reads pinned
  const { id: id2 } = await sealedCase("RJ J4 link");
  const html = (await casePage(id2)).html;
  assert.ok(html.includes(`href="${PINS_URL}/blob/${sealCommit(id2)}/${C.casePath(id2)}"`), "the case file at case_commit");
  assert.ok(!html.includes(`href="${PINS_URL}/blob/${store.BRANCH}/${C.casePath(id2)}"`), "not the branch's");
});

// =============================================================================
// J5: non-JSON where a pin should be is a conflict
// =============================================================================

test("J5: non-JSON at the pin's oldest commit is conflict, never could_not_look", async () => {
  const { id } = await sealedCase("RJ J5 oldest");
  const { seq } = S.pinPaths(id);
  gh.commitsFor(PINS, seq).slice(-1)[0].content = "not json\n";
  S._internal.clearCommitFiles();
  assert.deepEqual(await S.pinState(id, storedCase(id)).then((s) => [s.pin, s.reason]), ["conflict", "pin_at_its_commit_not_json"]);
});

// =============================================================================
// J6: the case commit is held to the pins repository's branch
// =============================================================================

test("J6: case_commit goes through commitOnBranch: off the branch is pin_commit_mismatch; a branch read that fails is could_not_look", async () => {
  // case_commit off the branch, holding the case file byte for byte
  const { id } = await sealedCase("RJ J6 case");
  const side = gh.seedSideCommit(PINS, crypto.createHash("sha1").update("rj side case").digest("hex"));
  gh.seedRaw(PINS, side, C.casePath(id), caseText(id));
  plantPin(id, chainOf(id), side);
  assert.deepEqual(await S.pinState(id, storedCase(id)).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_commit_off_branch"]);
  // the branch read fails: no claim
  const { id: id2 } = await sealedCase("RJ J6 unknown");
  gh.forceCompareFailure(1, 503, sealCommit(id2));
  assert.deepEqual(await S.pinState(id2, storedCase(id2)), { pin: "could_not_look", reason: "case_commit_compare_http_503", case_commit: sealCommit(id2) }); // unit R-L (g3)
  assert.equal((await S.pinState(id2, storedCase(id2))).pin, "pinned", "control: read again");
});

// =============================================================================
// J7: the limiter covers the page route (unit R-PIN removed the page cache)
// =============================================================================

test("J7: the per-IP limiter covers the page route", async () => {
  const { id } = await sealedCase("RJ J7");
  const t0 = REVEAL_AT + 3600000;
  assert.equal((await casePage(id, { now: t0 })).status, 200);
  let last;
  for (let i = 0; i < 40 && (!last || last.status !== 429); i += 1) last = await casePage(id, { now: t0, ip: "10.251.0.1" });
  assert.equal(last.status, 429);
});

// =============================================================================
// J8: case_not_anchored was case_not_pinned, and unit R-PIN removed it
// =============================================================================

test("J8: case_not_anchored, and since unit R-PIN the error codes case_not_pinned and anchor_conflict, are gone from the code", async () => {
  const fs = require("node:fs");
  const path = require("node:path");
  const src = (f) => fs.readFileSync(path.join(__dirname, "..", "lib", f), "utf8");
  for (const f of ["_case.js", "_case_http.js", "_case_seal.js", "_case_page.js"]) assert.ok(!src(f).includes("case_not_anchored"), f);
  // the handlers answer neither code; case_not_pinned stays only as a
  // signer_revoked reason inside revocationOrder, which unit R-PIN leaves as it was
  for (const f of ["_case.js", "_case_http.js", "_case_page.js"]) {
    for (const code of ["case_not_pinned", "anchor_conflict"]) assert.ok(!src(f).includes(code), `${f}: ${code}`);
  }
  assert.ok(!src("_case_seal.js").includes("anchor_conflict"));
});

// =============================================================================
// MUST-FAIL GAP (unit R-J): the mutants the pass over the lines R-J changed
// left alive, each caught here
// =============================================================================

test("MUST-FAIL GAP (A03): a row whose note_version is not 4 is refused by name", async () => {
  const { id } = await sealedCase("RJ gap note version");
  const signer = S.loadCaseSigner(KEYS, { keyDocument: DOC });
  const good = S.referenceRow({ caseId: id, seq: 1, crossReference: XREF, recordedAt: "2026-10-10T10:00:00Z", appendedBy: "operator" }, signer);
  for (const v of [1, 5, "4"]) assert.equal(C.validateReferenceRow({ ...good, note_version: v }).code, "unknown_version", String(v));
});

test("MUST-FAIL GAP (B06, B07): a commit's existence is read once and kept", async () => {
  const early = gh.seedText(PINS, "notes/gap-early.txt", "before the case\n");
  const { id } = await sealedCase("RJ gap exists once");
  plantPin(id, chainOf(id), early);
  for (let i = 0; i < 2; i += 1) assert.equal((await S.pinState(id, storedCase(id))).reason, "case_absent_at_commit");
  assert.equal(gh.commitLog.filter((k) => k === `${PINS}:${early}`).length, 1);
});

test("MUST-FAIL GAP (B25, B26): given a chain, the case read from the branch is served only when it has that chain; a read that fails is could_not_look", async () => {
  const { id } = await sealedCase("RJ gap chain mode");
  const other = sha("a chain that is not this case's");
  plantPin(id, other, sealCommit(id));
  assert.deepEqual(await S.pinState(id, other).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_served_differs"]); // unit R-J2 (n5)
  plantPin(id, chainOf(id), sealCommit(id));
  gh.forceGetFailure(PINS, C.casePath(id), 1, 503);
  assert.deepEqual(await S.pinState(id, chainOf(id)), { pin: "could_not_look", reason: "case_unreadable" });
});

test("MUST-FAIL GAP (D04, D05, D06): the case commit row says the commit does not hold this case file byte for byte; a pinned page links the case file at case_commit; a page whose pin is not read links the branch's file", async () => {
  const { id } = await sealedCase("RJ gap links");
  const pinned = (await casePage(id)).html;
  assert.match(pinned, /Pinned at commit /, "fixture: pinned");
  assert.ok(pinned.includes(`href="${PINS_URL}/blob/${sealCommit(id)}/${C.casePath(id)}"`));
  const early = gh.seedText(PINS, "notes/gap-other.txt", "x\n");
  const { id: id2 } = await sealedCase("RJ gap mismatch page");
  plantPin(id2, chainOf(id2), early);
  const mismatch = (await casePage(id2)).html;
  assert.ok(mismatch.includes("the pins repository holds no case file at that commit (case_absent_at_commit), so the case is not shown as pinned."), "the pin line (unit R-J2, n6 and n7; unit R-J3, its reason)");
  assert.ok(mismatch.includes(`href="${PINS_URL}/blob/${store.BRANCH}/${C.casePath(id2)}"`), "the branch's file");
  assert.ok(!mismatch.includes(`/blob/${early}/`));
});

test("MUST-FAIL GAP (B29, C04, D07): a reader that holds the case it serves never reads the case file again: the page, a reference, and the sealed check under a revoked key", async () => {
  const caseReads = (id) => gh.getLog.filter((p) => p === C.casePath(id)).length;
  const c = await sealedCase("RJ gap served once");
  let r0 = caseReads(c.id);
  assert.equal((await casePage(c.id)).status, 200);
  assert.equal(caseReads(c.id) - r0, 1, "the page reads the case once");
  r0 = caseReads(c.id);
  assert.equal((await reference(c)).status, 201);
  assert.equal(caseReads(c.id) - r0, 1, "a reference reads the case once");
  const revoked = KD.docWith(KD.entry(CASE_KEY, { status: "revoked" }), KD.reconcileEntry(RECEIPT_KEY));
  r0 = caseReads(c.id);
  const answer = await S.sealedRecordReason(storedCase(c.id), revoked);
  assert.deepEqual([answer.code, answer.reason], ["signer_revoked", "case_key_revoked"]);
  assert.equal(caseReads(c.id) - r0, 0, "the sealed check reads no case file");
});
