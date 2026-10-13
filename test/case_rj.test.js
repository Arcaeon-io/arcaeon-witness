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
// J7: a page view is cached per case for sixty seconds; a view here reads
// afresh unless `cached` (the J7 test's own views)
async function casePage(id, { now = REVEAL_AT + 3600000, cached = false, ip = null } = {}) {
  if (!cached) CP._internal.clearPageCache();
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": ip || `10.98.0.${(ipSeq += 1) & 255}` } }), res,
    { now, keyDocument: DOC, env: {} });
  return { status: res._status, html: String(res._body) };
}
const storedCase = (id) => gh.read(PINS, C.casePath(id));
const chainOf = (id) => S.caseChain(storedCase(id));
// The commit that wrote a create-only file: the oldest touching it.
const wroteIt = (path) => gh.commitsFor(PINS, path).slice(-1)[0];
const DAY = 86400000;
const dayOf = (ms) => new Date(ms).toISOString().slice(0, 10);
// The pin's own day: the mock's commits carry this process's clock.
const pinDay = (id) => wroteIt(S.pinPaths(id).seq).date.slice(0, 10);
// A daily anchor record, as the operator's job writes one: the pins
// repository's head (by default, as it is now) and a time, at
// anchors/<day>-head.txt, in its own commit.
function dailyAnchor(day, head = gh.headOf(PINS)) {
  const path = `anchors/${day}-head.txt`;
  const claimedAt = `${day}T03:15:00+00:00`;
  const commit = gh.seedText(PINS, path, `${head} ${claimedAt}\n`);
  return { path, head, claimedAt, commit };
}
const commitLink = (sha) => `href="${PINS_URL}/commit/${sha}"`;
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
// A pin for `chain` naming `caseCommit`, written over the case's pin paths.
function plantPin(id, chain, caseCommit) {
  const rec = { ...S._internal.pinRecord(id, chain, REVEAL_AT, caseCommit) };
  if (caseCommit === undefined) delete rec.case_commit;
  gh.seed(PINS, S.pinPaths(id).seq, rec);
  gh.seed(PINS, S.pinPaths(id).latest, rec);
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
const rowCommit = (id, n) => gh.commitsFor(PINS, rowPath(id, n))[0].sha;
// The row's line on the page, from its label to the end of its table row.
function rowLine(html, n) {
  const at = html.indexOf(`reference row ${n}`);
  assert.ok(at >= 0, `the page shows reference row ${n}`);
  return html.slice(at, html.indexOf("</tr>", at));
}
const sealerRun = (dt = 60000) => S.anchorPending({ now: REVEAL_AT + 3600000 + dt, keyDocument: DOC });
const caseText = (id) => gh._repoMap(PINS).get(C.casePath(id)).content;
// Every read a page or a reader makes, counted across the mock's logs.
const reads = () => gh.getLog.length + gh.commitsLog.length + gh.rawLog.length + gh.compareLog.length + (gh.commitLog ? gh.commitLog.length : 0);

// =============================================================================
// J1: the row's sentence, version 2
// =============================================================================

const V1_NOTE = "This row has no pin of its own. It is anchored by the pins-repository commit that writes it and by the daily anchor " +
  "of the repository head. It never changes the sealed case: the case's records field is the count at seal time, and a " +
  "reader counts this row as a second record only if the row is valid.";
// since unit R-J2 (B2) the sentence is version 3; version 2 was never issued
const V2_NOTE = "This row has no pin of its own. It is recorded by the pins-repository commit that writes it. A later pin of the case may list " +
  "that commit. This row is anchored only if a pin that lists it is, and no anchoring is asserted here.";

test("J1 (version 3 since unit R-J2, B2): REFERENCE_ANCHOR_NOTE is the current version and rows carry its note_version; the judge accepts it and rejects a v1 row with reason row_note_v1", async () => {
  assert.equal(C.REFERENCE_ANCHOR_NOTE, V2_NOTE);
  assert.ok(C.REFERENCE_FIELDS.includes("note_version"));
  const { id } = await sealedCase("RJ J1 judge");
  const signer = S.loadCaseSigner(KEYS, { keyDocument: DOC });
  const good = S.referenceRow({ caseId: id, seq: 1, crossReference: XREF, recordedAt: "2026-10-10T10:00:00Z", appendedBy: "operator" }, signer);
  assert.deepEqual([good.note_version, good.anchor_note], [3, V2_NOTE]);
  assert.equal(C.validateReferenceRow(good).ok, true);
  const { note_version: _v, ...v1 } = { ...good, anchor_note: V1_NOTE };
  assert.equal(C.validateReferenceRow(v1).code, "row_note_v1");
  gh.seed(PINS, rowPath(id, 1), v1);
  const live = await S.liveRecords(storedCase(id), { keyDocument: DOC });
  assert.deepEqual([live.records, live.invalid], [1, [{ seq: 1, reason: "row_note_v1" }]]);
  gh.seed(PINS, rowPath(id, 1), good);
  assert.equal((await S.liveRecords(storedCase(id), { keyDocument: DOC })).records, 2, "the v2 row is a record");
});

test("J1: a row's 201 body: the row and the answer carry the v2 note, and the row_commit note agrees (the case's next pin lists the commit; neither note says the row is anchored by a commit)", async () => {
  const c = await sealedCase("RJ J1 body");
  const r = await reference(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.deepEqual([r.body.anchor_note, r.body.row.anchor_note, r.body.row.note_version], [V2_NOTE, V2_NOTE, 3]);
  assert.match(r.body.row_commit_note, /A later pin of the case may list that commit/);
  for (const note of [r.body.anchor_note, r.body.row_commit_note]) {
    assert.doesNotMatch(note, /anchored by|daily anchor of the repository head/);
  }
});

// =============================================================================
// J2: "anchored" claims what is checked, and says the proof is not
// =============================================================================

test("J2: an anchored state carries proof: unchecked; the page says a daily anchor record in this repository names a head that holds this pin and that it does not check the OpenTimestamps proof; ANCHOR_NOTE says the same", async () => {
  const { id } = await sealedCase("RJ J2");
  dailyAnchor(pinDay(id));
  const st = await S.anchorState(id, storedCase(id));
  assert.equal(st.pin, "anchored");
  assert.equal(st.anchor.proof, "unchecked");
  const html = (await casePage(id)).html;
  assert.ok(html.includes("anchored: a daily anchor record in this repository names a head that holds this pin; this page does not check the " +
    "OpenTimestamps proof."), html.slice(html.indexOf("anchored"), html.indexOf("anchored") + 300));
  assert.match(S.ANCHOR_NOTE, /a daily anchor record in this repository names a head that holds that pin/);
  assert.match(S.ANCHOR_NOTE, /does not check the OpenTimestamps proof/);
});

// =============================================================================
// J3, J4: a wrong commit is a mismatch; the case is checked by its bytes
// =============================================================================

test("J3: a pin naming a commit that does not exist, or one at which the case file is absent, is pin_commit_mismatch (the commit's existence read once from the commits API); only a transport failure is could_not_look", async () => {
  const early = gh.seedText(PINS, "notes/before-the-case.txt", "a commit from before the case\n");
  const early2 = gh.seedText(PINS, "notes/also-before.txt", "another commit from before the case\n");
  const { id } = await sealedCase("RJ J3");
  const chain = chainOf(id);
  plantPin(id, chain, "f".repeat(40));
  assert.deepEqual(await S.anchorState(id, storedCase(id)).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_commit_not_found"]);
  assert.ok(gh.commitLog.includes(`${PINS}:${"f".repeat(40)}`), "the commits API was asked");
  plantPin(id, chain, early);
  assert.deepEqual(await S.anchorState(id, storedCase(id)).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_absent_at_commit"]);
  // transport failures: the raw read, and the existence read
  plantPin(id, chain, sealCommit(id));
  S._internal.clearCommitFiles();
  gh.forceRawFailure(1, 503, `:${C.casePath(id)}`);
  assert.deepEqual(await S.anchorState(id, storedCase(id)), { pin: "could_not_look", reason: "case_at_commit_http_503", case_commit: sealCommit(id) }); // unit R-L (g3)
  plantPin(id, chain, early2);
  gh.forceCommitFailure(1, 503);
  assert.deepEqual(await S.anchorState(id, storedCase(id)), { pin: "could_not_look", reason: "case_commit_exists_http_503", case_commit: early2 });
});

test("J4: the case is compared at case_commit byte for byte, sig included: a served case whose sig differs from the bytes at case_commit is pin_commit_mismatch; the case file link names case_commit", async () => {
  const { id } = await sealedCase("RJ J4");
  const stored = storedCase(id);
  const otherSig = { ...stored, sig: stored.sig.replace(/.$/, (ch) => (ch === "A" ? "B" : "A")) };
  assert.equal(S.caseChain(otherSig), chainOf(id), "fixture: the chain leaves sig out");
  assert.deepEqual(await S.anchorState(id, otherSig).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_at_commit_differs"]);
  // served from the branch: the case file rewritten with that sig
  rewriteCase(id, otherSig);
  assert.deepEqual(await S.anchorState(id, chainOf(id)).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_at_commit_differs"]);
  // the page's case file link, on a case that reads pinned
  const { id: id2 } = await sealedCase("RJ J4 link");
  const html = (await casePage(id2)).html;
  assert.ok(html.includes(`href="${PINS_URL}/blob/${sealCommit(id2)}/${C.casePath(id2)}"`), "the case file at case_commit");
  assert.ok(!html.includes(`href="${PINS_URL}/blob/${store.BRANCH}/${C.casePath(id2)}"`), "not the branch's");
});

// =============================================================================
// J5: non-JSON where a pin should be is a conflict
// =============================================================================

test("J5: non-JSON at the pin's oldest commit, or at the head a daily anchor record names, is conflict, never could_not_look", async () => {
  const { id } = await sealedCase("RJ J5 oldest");
  const { seq } = S.pinPaths(id);
  gh.commitsFor(PINS, seq).slice(-1)[0].content = "not json\n";
  S._internal.clearCommitFiles();
  assert.deepEqual(await S.anchorState(id, storedCase(id)).then((s) => [s.pin, s.reason]), ["conflict", "pin_at_its_commit_not_json"]);

  const { id: id2 } = await sealedCase("RJ J5 head");
  const p2 = S.pinPaths(id2).seq;
  const good = gh._repoMap(PINS).get(p2).content;
  gh._repoMap(PINS).get(p2).content = "not json\n";
  const bad = gh.addCommit(PINS, p2, "mock: the numbered pin record rewritten as text");
  dailyAnchor(pinDay(id2), bad);
  gh._repoMap(PINS).get(p2).content = good;
  gh.addCommit(PINS, p2, "mock: the numbered pin record put back");
  const st = await S.anchorState(id2, storedCase(id2));
  assert.deepEqual([st.pin, st.reason, st.anchor && st.anchor.head_commit], ["conflict", "anchored_head_not_json", bad]);
});

// =============================================================================
// J6: Design J's commits are held to the pins repository's branch
// =============================================================================

test("J6: case_commit, anchor heads and row commits go through commitOnBranch: off the branch is pin_commit_mismatch (case, row) or an anchor conflict (head); a branch read that fails is could_not_look", async () => {
  // case_commit off the branch, holding the case file byte for byte
  const { id } = await sealedCase("RJ J6 case");
  const side = gh.seedSideCommit(PINS, crypto.createHash("sha1").update("rj side case").digest("hex"));
  gh.seedRaw(PINS, side, C.casePath(id), caseText(id));
  plantPin(id, chainOf(id), side);
  assert.deepEqual(await S.anchorState(id, storedCase(id)).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_commit_off_branch"]);
  // the branch read fails: no claim
  const { id: id2 } = await sealedCase("RJ J6 unknown");
  gh.forceCompareFailure(1, 503, sealCommit(id2));
  assert.deepEqual(await S.anchorState(id2, storedCase(id2)), { pin: "could_not_look", reason: "case_commit_compare_http_503", case_commit: sealCommit(id2) }); // unit R-L (g3)
  assert.equal((await S.anchorState(id2, storedCase(id2))).pin, "pinned", "control: read again");
  // an anchor head off the branch that holds the pin
  const { id: id3 } = await sealedCase("RJ J6 head");
  const p3 = S.pinPaths(id3).seq;
  const sideHead = gh.seedSideCommit(PINS, crypto.createHash("sha1").update("rj side head").digest("hex"));
  gh.seedRaw(PINS, sideHead, p3, gh._repoMap(PINS).get(p3).content);
  dailyAnchor(pinDay(id3), sideHead);
  const st3 = await S.anchorState(id3, storedCase(id3));
  assert.deepEqual([st3.pin, st3.reason, st3.anchor && st3.anchor.head_commit], ["conflict", "anchored_head_off_branch", sideHead]);
  // a row commit off the branch, holding the row byte for byte
  const c4 = await sealedCase("RJ J6 row");
  assert.equal((await reference(c4)).status, 201);
  await sealerRun();
  const latest = S.pinPaths(c4.id).latest;
  const sideRow = gh.seedSideCommit(PINS, crypto.createHash("sha1").update("rj side row").digest("hex"));
  gh.seedRaw(PINS, sideRow, rowPath(c4.id, 1), gh._repoMap(PINS).get(rowPath(c4.id, 1)).content);
  const pointer = gh.read(PINS, latest);
  assert.deepEqual(pointer.reference_commits.map((e) => e.seq), [1], "fixture: the next pin lists the row");
  gh.seed(PINS, latest, { ...pointer, reference_commits: [{ seq: 1, commit: sideRow }] });
  const st4 = await S.anchorState(c4.id, storedCase(c4.id));
  const live = await S.liveRecords(storedCase(c4.id), { keyDocument: DOC });
  const states = await S.referenceCommitStates(c4.id, chainOf(c4.id), st4, live.rows);
  assert.deepEqual([states.get(1).state, states.get(1).reason], ["pin_commit_mismatch", "reference_commit_off_branch"]);
});

// =============================================================================
// J7: page reads cached per case for sixty seconds; the limiter covers it
// =============================================================================

test("J7: a second view of a case page within sixty seconds reads nothing; after sixty seconds it reads again; the per-IP limiter covers the page route", async () => {
  const { id } = await sealedCase("RJ J7");
  dailyAnchor(pinDay(id));
  const t0 = REVEAL_AT + 3600000;
  const first = await casePage(id, { now: t0 });
  assert.equal(first.status, 200);
  const r1 = reads();
  const second = await casePage(id, { now: t0 + 59000, cached: true });
  assert.equal(reads(), r1 + 1, "within sixty seconds, only the root is read (since unit R-J2, M2)");
  assert.equal(second.html, first.html);
  await casePage(id, { now: t0 + 60000, cached: true });
  assert.ok(reads() > r1, "read again at sixty seconds");
  // one address, cached views included: the limiter answers 429
  let last;
  for (let i = 0; i < 40 && (!last || last.status !== 429); i += 1) last = await casePage(id, { now: t0 + 60000, cached: true, ip: "10.251.0.1" });
  assert.equal(last.status, 429);
});

// =============================================================================
// J8: case_not_anchored is case_not_pinned
// =============================================================================

test("J8: a reference to a sealed case whose pin did not land is 409 case_not_pinned; case_not_anchored is gone from the code", async () => {
  const c = await sealedCase("RJ J8", { pinFails: true });
  const r = await reference(c);
  assert.deepEqual([r.status, r.body.error_code, r.body.state], [409, "case_not_pinned", "commit_unrecorded"], JSON.stringify(r.body).slice(0, 300));
  const fs = require("node:fs");
  const path = require("node:path");
  for (const f of ["_case_http.js", "_case_seal.js", "_case_page.js"]) {
    assert.ok(!fs.readFileSync(path.join(__dirname, "..", "lib", f), "utf8").includes("case_not_anchored"), f);
  }
});

// =============================================================================
// MUST-FAIL GAP (unit R-J): the mutants the pass over the lines R-J changed
// left alive, each caught here
// =============================================================================

test("MUST-FAIL GAP (A03): a row whose note_version is not 2 is refused by name", async () => {
  const { id } = await sealedCase("RJ gap note version");
  const signer = S.loadCaseSigner(KEYS, { keyDocument: DOC });
  const good = S.referenceRow({ caseId: id, seq: 1, crossReference: XREF, recordedAt: "2026-10-10T10:00:00Z", appendedBy: "operator" }, signer);
  for (const v of [1, 4, "3"]) assert.equal(C.validateReferenceRow({ ...good, note_version: v }).code, "unknown_version", String(v));
});

test("MUST-FAIL GAP (B06, B07): a commit's existence is read once and kept", async () => {
  const early = gh.seedText(PINS, "notes/gap-early.txt", "before the case\n");
  const { id } = await sealedCase("RJ gap exists once");
  plantPin(id, chainOf(id), early);
  for (let i = 0; i < 2; i += 1) assert.equal((await S.anchorState(id, storedCase(id))).reason, "case_absent_at_commit");
  assert.equal(gh.commitLog.filter((k) => k === `${PINS}:${early}`).length, 1);
});

test("MUST-FAIL GAP (B23): a head whose branch read fails leaves the case pinned, its anchor could_not_look", async () => {
  const { id } = await sealedCase("RJ gap head unknown");
  const a = dailyAnchor(pinDay(id));
  gh.forceCompareFailure(1, 503, `...${a.head}`);
  const st = await S.anchorState(id, storedCase(id));
  assert.deepEqual([st.pin, st.anchor], ["pinned", { could_not_look: "anchor_head_compare_http_503" }]);
});

test("MUST-FAIL GAP (B25, B26): given a chain, the case read from the branch is served only when it has that chain; a read that fails is could_not_look", async () => {
  const { id } = await sealedCase("RJ gap chain mode");
  const other = sha("a chain that is not this case's");
  plantPin(id, other, sealCommit(id));
  assert.deepEqual(await S.anchorState(id, other).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_served_differs"]); // unit R-J2 (n5)
  plantPin(id, chainOf(id), sealCommit(id));
  gh.forceGetFailure(PINS, C.casePath(id), 1, 503);
  assert.deepEqual(await S.anchorState(id, chainOf(id)), { pin: "could_not_look", reason: "case_unreadable" });
});

test("MUST-FAIL GAP (C01): a reference to a case whose anchored head holds no JSON is 409 anchor_conflict", async () => {
  const c = await sealedCase("RJ gap reference head");
  const p = S.pinPaths(c.id).seq;
  const good = gh._repoMap(PINS).get(p).content;
  gh._repoMap(PINS).get(p).content = "not json\n";
  const bad = gh.addCommit(PINS, p, "mock: the numbered pin record rewritten as text");
  dailyAnchor(pinDay(c.id), bad);
  gh._repoMap(PINS).get(p).content = good;
  gh.addCommit(PINS, p, "mock: put back");
  const r = await reference(c);
  assert.deepEqual([r.status, r.body.error_code, r.body.reason], [409, "anchor_conflict", "anchored_head_not_json"], JSON.stringify(r.body).slice(0, 300));
});

test("MUST-FAIL GAP (D04, D05, D06): the case commit row says the commit does not hold this case file byte for byte; an anchored page links the case file at case_commit; a page whose pin is not read links the branch's file", async () => {
  const { id } = await sealedCase("RJ gap links");
  dailyAnchor(pinDay(id));
  const anchored = (await casePage(id)).html;
  assert.match(anchored, /anchored: a daily anchor record/, "fixture: anchored");
  assert.ok(anchored.includes(`href="${PINS_URL}/blob/${sealCommit(id)}/${C.casePath(id)}"`));
  const early = gh.seedText(PINS, "notes/gap-other.txt", "x\n");
  const { id: id2 } = await sealedCase("RJ gap mismatch page");
  plantPin(id2, chainOf(id2), early);
  const mismatch = (await casePage(id2)).html;
  assert.ok(mismatch.includes("the pins repository holds no case file at that commit (case_absent_at_commit)</td>"), "the case commit row (unit R-J2, n6 and n7; unit R-J3, its reason)");
  assert.ok(mismatch.includes(`href="${PINS_URL}/blob/${store.BRANCH}/${C.casePath(id2)}"`), "the branch's file");
  assert.ok(!mismatch.includes(`/blob/${early}/`));
});

test("MUST-FAIL GAP (D09, D10, D11): the cache answers only the same key document, never an earlier clock, and never a page that was not 200", async () => {
  const { id } = await sealedCase("RJ gap cache keys");
  const t0 = REVEAL_AT + 3600000;
  await casePage(id, { now: t0 });
  const view = async (now, keyDocument) => {
    const r0 = reads();
    const res = makeRes();
    await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": `10.252.0.${(ipSeq += 1) & 255}` } }), res,
      { now, keyDocument, env: {} });
    return { status: res._status, read: reads() - r0 > 1 }; // more than the root (unit R-J2, M2)
  };
  assert.deepEqual(await view(t0 + 1000, DOC), { status: 200, read: false }, "control: cached");
  assert.equal((await view(t0 + 2000, KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)))).read, true, "another key document");
  CP._internal.clearPageCache();
  await view(t0, DOC);
  assert.equal((await view(t0 - 1000, DOC)).read, true, "an earlier clock");
  // a page that was not 200 is never kept: the named document unreadable
  CP._internal.clearPageCache();
  S._internal.clearDocumentCache();
  const su = storedCase(id).signed_under;
  gh.forceRawFailure(2, 503, `@${su.document_commit}:`);
  const down = await view(t0 + 5000, DOC);
  assert.equal(down.status, 503, "fixture: the named document could not be read");
  assert.equal((await view(t0 + 6000, DOC)).read, true, "read again after a 503");
});

test("MUST-FAIL GAP (B18): a row whose read at its commit fails is could_not_look, never pin_commit_mismatch", async () => {
  const c = await sealedCase("RJ gap row read");
  assert.equal((await reference(c)).status, 201);
  await sealerRun();
  const st = await S.anchorState(c.id, storedCase(c.id));
  const live = await S.liveRecords(storedCase(c.id), { keyDocument: DOC });
  S._internal.clearCommitFiles();
  gh.forceRawFailure(1, 503, `:${rowPath(c.id, 1)}`);
  const states = await S.referenceCommitStates(c.id, chainOf(c.id), st, live.rows);
  assert.deepEqual([states.get(1).state, states.get(1).reason], ["could_not_look", "reference_at_commit_http_503"]);
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
  const revoked = KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11" }), KD.reconcileEntry(RECEIPT_KEY));
  r0 = caseReads(c.id);
  const answer = await S.sealedRecordReason(storedCase(c.id), revoked);
  assert.deepEqual([answer.code, answer.reason], ["signer_revoked", "no_revocation_marker"]);
  assert.equal(caseReads(c.id) - r0, 0, "the sealed check reads no case file");
});

test("MUST-FAIL GAP (D12): the page cache holds at most PAGE_CACHE_MAX (500) cases, dropping the oldest first", async () => {
  const usage = () => gh.repos.get(process.env.GITHUB_USAGE_REPO) || new Map();
  const ids = [];
  for (let i = 0; i < 501; i += 1) {
    // a fresh day's open quota and a fresh budget every fifteen opens
    if (i % 15 === 0) {
      for (const p of [...usage().keys()]) if (p.startsWith("case_opens/")) usage().delete(p);
      require("../lib/_ratelimit.js").setStore(null);
    }
    const o = makeRes();
    await H.handleCaseOpen(req("case-open", opening(`RJ gap cache bound ${i}`), OPEN_AUTH), o, { now: NOW });
    assert.equal(o._status, 201, JSON.stringify(o._body).slice(0, 200));
    ids.push(o._body.case_id);
  }
  require("../lib/_ratelimit.js").setStore(null);
  CP._internal.clearPageCache();
  const t0 = REVEAL_AT + 3600000;
  for (const id of ids) assert.equal((await casePage(id, { now: t0, cached: true })).status, 200);
  const r0 = reads();
  await casePage(ids[500], { now: t0 + 1000, cached: true });
  assert.equal(reads(), r0 + 1, "the newest is kept: only its root is read");
  await casePage(ids[0], { now: t0 + 1000, cached: true });
  assert.ok(reads() > r0, "the oldest was dropped");
});
