// test/case_commits.test.js — Design J (2026-10-12): every public write
// names its own commit, and "anchored" means what it says.
//
// The defects (three confirmed red-team claims, GPT-5.6 §3.2, §3.4 and §5):
// the commit that wrote a sealed case appeared neither in the case nor in
// its pin; the commit that wrote a reference row appeared neither in the row
// nor in the answer; and anchorState said "anchored" after reading
// pins/case/<id>/latest.json and nothing else, so "anchored" meant only "a
// pin file exists".
//
// STEP 1, here: the anchor words. A reader says exactly one of pinned (the
// pin holds this case's chain at the commit that wrote it, named), anchored
// (pinned, and a daily anchor record names a head of the pins repository
// that holds the pin; the record's own commit is named beside it) or
// could_not_look (a read failed: no claim). Every place that said anchored
// after reading only latest.json now says pinned.
//
// Unit R-PIN (2026-10-13): a case has one pin, pins/case/<case_id>/
// 00000001.json, written once; there is no pointer, no next pin, no row
// commit and no anchor reader. The tests of the daily anchor reader, the next
// pins and the row commits were removed with that code; those below read the
// one pin with pinState.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0051:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-12j");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-12j");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-12j");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0051" });

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
async function casePage(id) {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": `10.98.0.${(ipSeq += 1) & 255}` } }), res,
    { now: REVEAL_AT + 3600000, keyDocument: DOC, env: {} });
  return { status: res._status, html: String(res._body) };
}
const storedCase = (id) => gh.read(PINS, C.casePath(id));
const chainOf = (id) => S.caseChain(storedCase(id));
// The commit that wrote a create-only file: the oldest touching it.
const wroteIt = (path) => gh.commitsFor(PINS, path).slice(-1)[0];
// =============================================================================
// STEP 1: the pin words (since unit R-PIN: pinned, not_pinned, and each
// state that is neither; never anchored)
// =============================================================================

test("PINNED: a sealed case whose pin holds its chain reads pinned, naming the commit that wrote its pin, read at that commit", async () => {
  const { id } = await sealedCase("J pinned");
  const { seq } = S.pinPaths(id);
  const wrote = wroteIt(seq);
  const g0 = gh.getLog.length;
  const c0 = gh.commitsLog.length;
  const r0 = gh.rawLog.length;
  const st = await S.pinState(id, storedCase(id)); // unit R-J (J4): the case served, held to its bytes at case_commit
  assert.equal(st.pin, "pinned");
  assert.deepEqual(st.pin_commit, { sha: wrote.sha, date: wrote.date });
  assert.equal(st.record.chain, chainOf(id));
  assert.equal(Object.prototype.hasOwnProperty.call(st, "anchor"), false, "unit R-PIN: no anchor state");
  // what it read (unit R-PIN): the pin file, its commits, that record at the
  // commit that wrote it, and the case file at the commit the pin names
  assert.deepEqual(gh.getLog.slice(g0), [seq]);
  assert.deepEqual(gh.commitsLog.slice(c0), [seq]);
  assert.deepEqual(gh.rawLog.slice(r0), [`${PINS}@${wrote.sha}:${seq}`, `${PINS}@${st.case_commit}:${C.casePath(id)}`]);
});

test("COULD_NOT_LOOK: a read the pin's state needs that fails is no claim", async () => {
  const { id } = await sealedCase("J could not look");
  const chain = chainOf(id);
  const { seq } = S.pinPaths(id);
  const wrote = wroteIt(seq);
  const fresh = () => S._internal.clearCommitFiles();
  // the pin file
  gh.forceGetFailure(PINS, seq, 1, 503);
  assert.deepEqual(await S.pinState(id, chain), { pin: "could_not_look", reason: "pin_read_failed" });
  // the commits of the pin file
  gh.forceCommitsFailure(PINS, seq, 1, 503);
  assert.deepEqual(await S.pinState(id, chain), { pin: "could_not_look", reason: "pin_commit_unreadable" });
  // the pin record at the commit that wrote it
  fresh();
  gh.forceRawFailure(1, 503, `@${wrote.sha}:${seq}`);
  assert.deepEqual(await S.pinState(id, chain), { pin: "could_not_look", reason: "pin_at_commit_http_503" });
  fresh();
  gh.forceRawFailure(1, 0, `@${wrote.sha}:${seq}`);
  assert.deepEqual(await S.pinState(id, chain), { pin: "could_not_look", reason: "pin_at_commit_fetch_failed" });
  // the case file on the branch, read when the caller hands a chain
  fresh();
  gh.forceGetFailure(PINS, C.casePath(id), 1, 503);
  assert.deepEqual(await S.pinState(id, chain), { pin: "could_not_look", reason: "case_unreadable" });
  fresh();
  assert.equal((await S.pinState(id, chain)).pin, "pinned", "control: every read answered");
});

test("A PIN THAT HOLDS ANOTHER CHAIN, ON THE BRANCH OR AT ITS OWN COMMIT, IS A CONFLICT: never pinned", async () => {
  // the pin file on the branch holds another chain
  const { id } = await sealedCase("J conflict");
  const { seq } = S.pinPaths(id);
  gh.seed(PINS, seq, { ...gh.read(PINS, seq), chain: sha("another chain") }, { keepHistory: true });
  assert.deepEqual(await S.pinState(id, chainOf(id)), { pin: "conflict", reason: "pin_holds_another_chain" });

  // the pin record held another chain at the commit that wrote it (the oldest touching it)
  const { id: id2 } = await sealedCase("J conflict at its commit");
  const p2 = S.pinPaths(id2).seq;
  const mine = gh.read(PINS, p2);
  gh.seed(PINS, p2, { ...mine, chain: sha("yet another chain") });
  gh._repoMap(PINS).get(p2).content = JSON.stringify(mine, null, 2) + "\n";
  gh.addCommit(PINS, p2, "mock: the pin record rewritten to this case's chain");
  const st2 = await S.pinState(id2, chainOf(id2));
  assert.equal(st2.pin, "conflict");
  assert.equal(st2.reason, "pin_at_its_commit_holds_another_chain");
  assert.equal(st2.pin_commit, undefined, "no pin commit is named for a pin that is not this case's");
});

test("THE WRITERS SAY PINNED: the reveal's answer, pinChain, the sealer's report and the status row say pinned, and none of them says anchored", async () => {
  const { id, r } = await sealedCase("J writers");
  const { seq } = S.pinPaths(id);
  assert.equal(r.body.pin, "pinned");
  assert.equal(r.body.pin_commit, wroteIt(seq).sha, "the reveal names the commit that wrote its pin");
  assert.ok(!JSON.stringify(r.body).includes('"anchored"'));
  const again = await S.pinChain(id, chainOf(id), REVEAL_AT);
  assert.equal(again.pin, "pinned");
  assert.equal(again.existing, true);
  // unit R-PIN: a root with its pin file is no candidate, and is not read again
  const run = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.equal(run.candidates, 0);
  assert.equal(run.pinned, 1);
  assert.deepEqual(run.already, []);
  assert.deepEqual(run.newly_pinned, []);
  assert.equal(Object.prototype.hasOwnProperty.call(run, "anchored"), false);
  const p = await sealedCase("J writers pending", { pinFails: true });
  assert.equal(p.r.body.pin, "commit_unrecorded", "step 2: the pin is the second phase of the case write");
  const run2 = await S.anchorPending({ now: REVEAL_AT + 120000, keyDocument: DOC });
  assert.deepEqual(run2.newly_pinned, [p.id]);
  const tree = await store.getTree();
  const row = S.caseAnchorSummary(tree);
  assert.equal(row.pinned, 2);
  assert.equal(Object.prototype.hasOwnProperty.call(row, "anchored"), false);
  const data = await statusData.gatherStatusData();
  assert.equal(data.caseAnchors.pinned, 2);
});

// =============================================================================
// STEP 2: the case's two writes, the case file and then the pin that records
// the commit that wrote it
// =============================================================================

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

test("TWO WRITES: the reveal reads back the commit the pins repository assigned to the sealed case file and records it as case_commit in the pin; the answer names it too", async () => {
  const { id, r } = await sealedCase("J case commit");
  const commit = sealCommit(id);
  assert.match(gh.commitsFor(PINS, C.casePath(id))[0].message, /sealed/, "fixture: the newest commit of the case file is the seal");
  assert.equal(r.body.case_commit, commit);
  assert.equal(r.body.pin, "pinned");
  const { seq } = S.pinPaths(id);
  assert.equal(gh.read(PINS, seq).case_commit, commit);
  const st = await S.pinState(id, chainOf(id));
  assert.equal(st.pin, "pinned");
  assert.equal(st.case_commit, commit, "the reader names it, after reading the case file at it");
  assert.ok(gh.rawLog.includes(`${PINS}@${commit}:${C.casePath(id)}`));
  // the judge: case_commit is 40 lowercase hex
  const verdict = require("../lib/_verdict.js");
  const judge = (rec) => verdict.judgeCaseSeal({ json: rec }, { namespace: S.pinNamespace(id) });
  assert.equal(judge(gh.read(PINS, seq)).ok, true);
  for (const bad of [commit.toUpperCase(), commit.slice(1), null, 7]) {
    assert.equal(judge({ ...gh.read(PINS, seq), case_commit: bad }).reason, "case_seal_case_commit_unreadable", String(bad));
  }
});

test("THE VERIFIER NEVER TRUSTS case_commit AS AN ID: a pin naming a commit at which the case file is not the case served, byte for byte, is pin_commit_mismatch, never pinned; since unit R-J (J3) so is one naming a commit that does not exist; only a read that fails is could_not_look", async () => {
  const { id } = await sealedCase("J mismatch");
  const chain = chainOf(id);
  const opened = gh.commitsFor(PINS, C.casePath(id)).slice(-1)[0].sha; // the case file as opened, not as sealed
  plantPin(id, chain, opened);
  const st = await S.pinState(id, chain);
  assert.equal(st.pin, "pin_commit_mismatch");
  assert.equal(st.reason, "case_at_commit_differs");
  assert.equal(st.case_commit, opened);
  assert.ok(gh.rawLog.includes(`${PINS}@${opened}:${C.casePath(id)}`), "it read the case file at the commit the pin names");
  const page = (await casePage(id)).html;
  assert.match(page, /pin_commit_mismatch: its pin names commit <a [^>]+>[0-9a-f]{12}<\/a> for the case file, and the case file at that commit is not this case file in canonical form \(json-c14n:v1\) \(case_at_commit_differs\), so the case is not shown as pinned\./); // unit R-J3 (F2): no "never"
  assert.ok(!page.includes("Pinned at commit"));
  // unit R-J (J3), inverted: a commit the repository does not have is a
  // mismatch, never could_not_look (its existence read from the commits API)
  S._internal.clearCommitFiles();
  plantPin(id, chain, "f".repeat(40));
  const forged = await S.pinState(id, chain);
  assert.deepEqual([forged.pin, forged.reason, forged.case_commit], ["pin_commit_mismatch", "case_commit_not_found", "f".repeat(40)]);
  gh.forceRawFailure(1, 503, `:${C.casePath(id)}`);
  plantPin(id, chain, sealCommit(id));
  assert.deepEqual(await S.pinState(id, chain), { pin: "could_not_look", reason: "case_at_commit_http_503", case_commit: sealCommit(id) }); // unit R-L (g3): the commit it names
  assert.equal((await S.pinState(id, chain)).pin, "pinned", "control: the seal's own commit, read");
});

test("NOT PINNED, AND A PIN THAT NAMES NO CASE COMMIT: a sealed case with no pin file reads not_pinned, and a pin without case_commit unreadable (unit R-PIN: case_commit is required); neither is pinned", async () => {
  const p = await sealedCase("J unrecorded", { pinFails: true });
  assert.deepEqual(await S.pinState(p.id, chainOf(p.id)), { pin: "not_pinned" });
  const { id } = await sealedCase("J legacy pin");
  const chain = chainOf(id);
  plantPin(id, chain, undefined); // a pin from before Design J
  const st = await S.pinState(id, chain);
  assert.equal(st.pin, "unreadable");
  assert.equal(st.reason, "case_seal_missing_field");
  const page = (await casePage(id)).html;
  assert.match(page, /unreadable: a record is present at this case's pin path and cannot be read as a case seal record \(/);
  assert.ok(!page.includes("Pinned at commit"));
  assert.match((await casePage(p.id)).html, /Not pinned: no pin file is present under this case's namespace \(not_pinned\)\./);
});

test("CRASH BETWEEN THE PHASES: the case file written and its pin not; the answer names what it knows, the page says not pinned, the case file is never backfilled, and the sealer's next run records the commit, read back and checked, in the pin", async () => {
  // the pin write fails after the case file landed
  const { id, r } = await sealedCase("J crash pin", { pinFails: true });
  const cpath = C.casePath(id);
  assert.equal(r.body.pin, "commit_unrecorded");
  assert.equal(r.body.case_commit, sealCommit(id), "the answer still names the case file's commit");
  assert.equal(gh.has(PINS, S.pinPaths(id).seq), false);
  // the case's PUT answered without its commit: a process that died right after the write
  // (the reveal's attempt is the case file's first PUT since red-team fix E; the seal's is the second)
  const c = await committedCase("J crash answer");
  gh.dropCommitFromAnswer(PINS, C.casePath(c.id), 2);
  const lost = await reveal(c);
  assert.equal(lost.status, 201);
  assert.equal(lost.body.case_commit, null);
  assert.equal(lost.body.pin, "commit_unrecorded");
  assert.equal(gh.has(PINS, S.pinPaths(c.id).seq), false, "no pin without the commit it records");

  for (const x of [id, c.id]) assert.match((await casePage(x)).html, /Not pinned: no pin file is present/);
  const bytes = (x) => gh._repoMap(PINS).get(C.casePath(x)).content;
  const before = { [id]: [bytes(id), gh.commitsFor(PINS, cpath).length], [c.id]: [bytes(c.id), gh.commitsFor(PINS, C.casePath(c.id)).length] };
  const run = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.deepEqual(run.newly_pinned.sort(), [id, c.id].sort());
  // never backfilled silently: the case files are untouched, and each pin records the commit read back
  for (const x of [id, c.id]) {
    assert.equal(bytes(x), before[x][0], "the case file is byte for byte as written");
    assert.equal(gh.commitsFor(PINS, C.casePath(x)).length, before[x][1], "and was not written again");
    assert.equal(gh.read(PINS, S.pinPaths(x).seq).case_commit, sealCommit(x));
    assert.ok(gh.commitsLog.includes(C.casePath(x)), "the commit was read back");
    assert.ok(gh.rawLog.includes(`${PINS}@${sealCommit(x)}:${C.casePath(x)}`), "and the case file read at it");
  }
  for (const x of [id, c.id]) {
    const st = await S.pinState(x, chainOf(x));
    assert.equal(st.pin, "pinned");
    assert.equal(st.case_commit, sealCommit(x));
  }
});

test("SWAPPED FILE: a late retry that would pin a different commit of a swapped case file pins nothing and reports pin_commit_mismatch; a pin that did is pin_commit_mismatch to the reader and the page, and the sealer does not read it again", async () => {
  const { id } = await sealedCase("J swapped", { pinFails: true });
  const cpath = C.casePath(id);
  const original = storedCase(id);
  const chain = chainOf(id);
  const swapped = { ...original, deadline: "2026-10-10T21:00:00Z" };
  assert.notEqual(S.caseChain(swapped), chain, "fixture: another case");
  // the file is swapped while the sealer reads back its commit
  let swapCommit = null;
  const undo = onFirstRequest(`commits?path=${encodeURIComponent(cpath)}`, async () => { swapCommit = rewriteCase(id, swapped); });
  let run;
  try {
    run = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: DOC });
  } finally {
    undo();
  }
  assert.ok(swapCommit, "fixture: the swap happened during the read-back");
  assert.deepEqual(run.newly_pinned, []);
  assert.deepEqual(run.refused, [{ case_id: id, code: "pin_commit_mismatch", reason: "case_at_commit_differs" }]);
  assert.equal(gh.has(PINS, S.pinPaths(id).seq), false, "nothing pinned");

  // the original is put back, and a late retry that did not check pinned the swapped file's commit
  rewriteCase(id, original);
  plantPin(id, chain, swapCommit);
  const st = await S.pinState(id, chain);
  assert.equal(st.pin, "pin_commit_mismatch");
  assert.equal(st.case_commit, swapCommit);
  assert.match((await casePage(id)).html, /pin_commit_mismatch/);
  // unit R-PIN: a root with its pin file is no candidate
  const again = await S.anchorPending({ now: REVEAL_AT + 120000, keyDocument: DOC });
  assert.equal(again.candidates, 0);
  assert.deepEqual(again.already, [], "never read as pinned");
  assert.deepEqual(again.refused, []);
});

// =============================================================================
// STEP 3: a reference row, written with the case's one pin untouched
// =============================================================================

const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0051", url: "https://second-operator.example/cases/0051" });
async function reference(c, role = "a", ref = "row") {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: { ...XREF, reference: ref } }),
    res, { now: REVEAL_AT + 1800000, env: KEYS, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
// The row's line on the page, from its label to the end of its table row.
function rowLine(html, n) {
  const at = html.indexOf(`reference row ${n}`);
  assert.ok(at >= 0, `the page shows reference row ${n}`);
  return html.slice(at, html.indexOf("</tr>", at));
}

// =============================================================================
// STEP 4: every commit on the page is a link into the public repository
// =============================================================================

// Every 40-hex commit the page carries sits in an href into a public
// repository, never in the page's text; and every link to a commit shows it.
function commitsOnPage(html) {
  const hrefs = [...html.matchAll(/<a href="([^"]*)"[^>]*>([^<]*)<\/a>/g)].map((m) => ({ href: m[1], text: m[2] }));
  const text = html.replace(/<a href="[^"]*"[^>]*>[^<]*<\/a>/g, "");
  const bare = text.match(/\b[0-9a-f]{40}\b/g) || [];
  const linked = [];
  for (const h of hrefs) {
    const m = /^https:\/\/github\.com\/([^/]+\/[^/]+)\/(commit|blob)\/([0-9a-f]{40})(\/|$)/.exec(h.href);
    if (m) linked.push({ repo: m[1], kind: m[2], sha: m[3], text: h.text });
  }
  return { bare, linked };
}

test("EVERY COMMIT IS A LINK: on a sealed page, pinned and with a row recorded, and under a since-revoked key, every commit (the key document's, the stamps', the case file's, the pin's, the revoking document's) is a link into the public repository it is a commit of, and none is bare text", async () => {
  const c = await sealedCase("J every commit");
  const r = await reference(c, "a", "row-linked");
  assert.equal(r.status, 201);
  const k = storedCase(c.id);
  const current = "c".repeat(40);
  const render = async (keyDocument, env) => {
    const res = makeRes();
    await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: c.id }, headers: { "x-forwarded-for": `10.98.1.${(ipSeq += 1) & 255}` } }), res,
      { now: REVEAL_AT + 3600000, keyDocument, env });
    return String(res._body);
  };
  // the row shows under the document that lists its key active; the banner under one that revokes it since
  const page = await render(DOC, {});
  // unit R-I: a revocation counts by commit order: the document's
  // revocation on the branch (W), then the key's marker in the pins
  // repository (R), after this case's file was written
  const revoked = KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11" }), KD.reconcileEntry(RECEIPT_KEY));
  const W = KD.serve(gh, revoked);
  const marked = await require("../tools/record_key_revocation.js").recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: revoked, write: true });
  assert.equal(marked.ok, true, JSON.stringify(marked));
  const banner = await render(revoked, { [S.DEPLOY_COMMIT_ENV]: current });
  assert.match(page, /Pinned at commit <a /, "fixture: pinned");
  assert.match(rowLine(page, 1), /the row and the commit that wrote it/, "fixture: the row");
  assert.match(banner, /A key that signed this case is revoked\./, "fixture: the banner");
  const one = commitsOnPage(page);
  const two = commitsOnPage(banner);
  assert.deepEqual([...one.bare, ...two.bare], [], "no commit is bare text");
  const linked = [...one.linked, ...two.linked];
  const want = [
    [S.KEY_DOCUMENT_REPO, k.signed_under.document_commit, "the key document the case names"],
    [S.KEY_DOCUMENT_REPO, W, "the document's commit that lists the key revoked"],
    [PINS, marked.commit, "the revoking commit, the marker's"],
    [STAMPS, k.commitments.a.stamp_commit, "role a's stamp"],
    [STAMPS, k.commitments.b.stamp_commit, "role b's stamp"],
    [PINS, sealCommit(c.id), "the case file"],
    [PINS, wroteIt(S.pinPaths(c.id).seq).sha, "the pin"],
  ];
  for (const [repo, sha, what] of want) {
    assert.ok(linked.some((l) => l.repo === repo && l.sha === sha), `${what}: ${sha} linked into ${repo}`);
  }
  for (const l of linked) assert.ok([PINS, STAMPS, S.KEY_DOCUMENT_REPO].includes(l.repo), `a link into a repository the page names: ${l.repo}`);
});

test("EVERY COMMIT IS A LINK, ON THE OTHER PAGES THAT NAME ONE: pin_commit_mismatch (the commit the pin names), could_not_look on the key document, a case not yet pinned, and a case registered and not revealed", async () => {
  const pages = [];
  // pin_commit_mismatch
  const m = await sealedCase("J link mismatch");
  plantPin(m.id, chainOf(m.id), gh.commitsFor(PINS, C.casePath(m.id)).slice(-1)[0].sha);
  pages.push(["pin_commit_mismatch", (await casePage(m.id)).html]);
  // the key document the case names could not be read
  const d = await sealedCase("J link document");
  gh.forceRawFailure(1, 503, `:${S.CASE_KEYS_FILE}`);
  S._internal.clearDocumentCache();
  const dp = await casePage(d.id);
  assert.equal(dp.status, 503, "fixture: the could-not-look page");
  pages.push(["document could_not_look", dp.html]);
  // not pinned yet
  const p = await sealedCase("J link pending", { pinFails: true });
  pages.push(["not_pinned", (await casePage(p.id)).html]);
  // registered, not revealed: the stamp commits
  const k = await committedCase("J link committed");
  const kp = (await casePage(k.id)).html;
  assert.match(kp, /<h1>Case: COMMITTED<\/h1>/, "fixture: the committed page");
  for (const r of ["a", "b"]) {
    const sc = gh.read(PINS, C.casePath(k.id)).commitments[r].stamp_commit;
    assert.ok(kp.includes(`href="https://github.com/${STAMPS}/commit/${sc}"`), `role ${r}'s stamp commit, linked`);
  }
  pages.push(["committed", kp]);
  for (const [name, html] of pages) {
    const { bare, linked } = commitsOnPage(html);
    assert.deepEqual(bare, [], `${name}: no commit is bare text`);
    assert.ok(linked.length > 0, `${name}: it names a commit, linked`);
  }
  assert.match(pages[0][1], /pin_commit_mismatch: its pin names commit <a href="https:\/\/github\.com\/test-owner\/test-pins\/commit\/[0-9a-f]{40}"/);
});

// =============================================================================
// THE MUST-FAIL PASS OVER DESIGN J: the gaps it found
// =============================================================================
// 108 defects planted, one at a time, in the code Design J added or changed:
// lib/_case_seal.js (64), lib/_case_page.js (15), lib/_verdict.js (8),
// lib/_case_http.js (6), tools/preview_dry_run.js (5), lib/_status_json.js
// (1), api/status.js (2) and test/helpers/mock_store.js (7), the whole suite
// run against each. 83 were caught by steps 1 to 4. Of the 25 that survived,
// 24 are closed by the tests below (two of them, T03 and T05, in
// test/preview_dry_run.test.js) and one is equivalent:
//   - H06, lib/_case_http.js: the reveal logging a pinned seal as a failure,
//     a server log line no answer and no record carries.
// The test names carry the mutant ids. (Unit R-PIN removed the tests of the
// daily anchor reader, the next pins and the row commits, with that code.)

test("B03 (a commit whose case file is not JSON): a pin naming it is pin_commit_mismatch, not could_not_look", async () => {
  const { id } = await sealedCase("J not json");
  const p = C.casePath(id);
  const kept = gh._repoMap(PINS).get(p).content;
  gh._repoMap(PINS).get(p).content = "this is not a case file\n";
  const garbage = gh.addCommit(PINS, p, "mock: not JSON");
  gh._repoMap(PINS).get(p).content = kept;
  gh.addCommit(PINS, p, "mock: put back");
  plantPin(id, chainOf(id), garbage);
  const st = await S.pinState(id, chainOf(id));
  assert.equal(st.pin, "pin_commit_mismatch");
  assert.equal(st.reason, "case_at_commit_differs");
});

test("C01, C02 (the pin holds seq 1): the pin read at its commit with another seq is a conflict, and an orphan at seq 1 that says seq 2 is never adopted", async () => {
  const { id } = await sealedCase("J own seq");
  const { seq } = S.pinPaths(id);
  const mine = gh.read(PINS, seq);
  gh.seed(PINS, seq, { ...mine, seq: 2 });
  gh._repoMap(PINS).get(seq).content = JSON.stringify(mine, null, 2) + "\n";
  gh.addCommit(PINS, seq, "mock: put back to seq 1");
  const st = await S.pinState(id, chainOf(id));
  assert.equal(st.pin, "conflict");
  // unit R-J3 (BL2): another seq is not a pin record for this case; "another chain" is not said of it
  assert.equal(st.reason, "pin_at_its_commit_not_a_pin");

  const o = await sealedCase("J orphan seq", { pinFails: true });
  const op = S.pinPaths(o.id);
  gh.seed(PINS, op.seq, { ...S._internal.pinRecord(o.id, chainOf(o.id), REVEAL_AT, sealCommit(o.id)), seq: 2 });
  const r = await S.anchorCase(o.id, { now: REVEAL_AT + 60000, keyDocument: DOC });
  // unit R-PIN: the judge holds a case pin to seq 1, so the record is not read as a pin at all
  assert.equal(r.pin, "unreadable");
  assert.equal(gh.read(PINS, op.seq).seq, 2, "never written over");
});

test("S01, S02 (the status page's case row): the column says pinned and holds the pinned count", async () => {
  const statusHandler = require("../api/status.js");
  await sealedCase("J status one");
  await sealedCase("J status two");
  await sealedCase("J status pending", { pinFails: true });
  const res = makeRes();
  await statusHandler(makeReq({ method: "GET", headers: { "x-forwarded-for": "10.98.2.1" } }), res);
  const page = String(res._body);
  assert.match(page, /<th>where<\/th><th>case files<\/th><th>pinned<\/th><th>withdrawn<\/th>/);
  const row = /<td><code>pins\/case\/<\/code>[\s\S]*?<\/tr>/.exec(page);
  assert.ok(row, "the case row");
  assert.deepEqual([...row[0].matchAll(/<td>(\d+)<\/td>/g)].map((x) => Number(x[1])), [3, 2, 0]);
  // (since unit R-L4 no registration file is counted; since unit R-PIN no pending count)
  assert.match(page, /<em>Pinned<\/em> means the case has its pin file, by path alone/);
});
