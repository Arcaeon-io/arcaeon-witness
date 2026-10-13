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
async function casePage(id) {
  const res = makeRes();
  CP._internal.clearPageCache(); // unit R-J (J7): each view here reads afresh
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": `10.98.0.${(ipSeq += 1) & 255}` } }), res,
    { now: REVEAL_AT + 3600000, keyDocument: DOC, env: {} });
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

// =============================================================================
// STEP 1: the anchor words, pinned, anchored and could_not_look
// =============================================================================

test("PINNED: a sealed case whose pin holds its chain reads pinned, naming the commit that wrote its pin, read at that commit; with no daily anchor record holding it, it is never anchored", async () => {
  const { id } = await sealedCase("J pinned");
  const { seq, latest } = S.pinPaths(id);
  const wrote = wroteIt(seq);
  const g0 = gh.getLog.length;
  const c0 = gh.commitsLog.length;
  const r0 = gh.rawLog.length;
  const st = await S.anchorState(id, storedCase(id)); // unit R-J (J4): the case served, held to its bytes at case_commit
  assert.equal(st.pin, "pinned");
  assert.deepEqual(st.pin_commit, { sha: wrote.sha, date: wrote.date });
  assert.equal(st.anchor, null, "no daily anchor record holds it");
  assert.equal(st.record.chain, chainOf(id));
  // what it read: the pointer, the anchors listing, the numbered record's commits, that record at the commit that wrote it,
  // and (step 2) the case file at the commit the pin names
  assert.deepEqual(gh.getLog.slice(g0), [latest, "anchors"]);
  assert.deepEqual(gh.commitsLog.slice(c0), [seq]);
  assert.deepEqual(gh.rawLog.slice(r0), [`${PINS}@${wrote.sha}:${seq}`, `${PINS}@${st.case_commit}:${C.casePath(id)}`]);
});

test("ANCHORED: a daily anchor record whose head holds the pin reads anchored, naming the record, the commit that wrote it and the head it names", async () => {
  const { id } = await sealedCase("J anchored");
  const a = dailyAnchor(pinDay(id));
  const st = await S.anchorState(id, chainOf(id));
  assert.equal(st.pin, "anchored");
  const rc = gh.commitsFor(PINS, a.path)[0];
  assert.equal(rc.sha, a.commit);
  assert.deepEqual(st.anchor, { path: a.path, head_commit: a.head, claimed_at: a.claimedAt, record_commit: { sha: a.commit, date: rc.date }, proof: "unchecked" },
    "unit R-J (J2): the OpenTimestamps proof is not checked, and the state says so");
  assert.deepEqual(st.pin_commit.sha, wroteIt(S.pinPaths(id).seq).sha, "the pin's own commit is named too");
  // the pin was read at the head the record names, and the record at the commit that wrote it
  assert.ok(gh.rawLog.includes(`${PINS}@${a.head}:${S.pinPaths(id).seq}`));
  assert.ok(gh.rawLog.includes(`${PINS}@${a.commit}:${a.path}`));
});

test("ANCHORED ONLY BY A HEAD THAT HOLDS THE PIN: a record whose head predates the pin does not anchor it, a later one does, and at most ANCHOR_RECORD_READS records from the day before the pin are read", async () => {
  const c = await committedCase("J heads");
  const today = dayOf(Date.now());
  const early = dailyAnchor(today); // the head before the reveal: no pin there
  assert.equal((await reveal(c)).status, 201);
  const chain = chainOf(c.id);
  const before = await S.anchorState(c.id, chain);
  assert.equal(before.pin, "pinned", "a head that predates the pin anchors nothing");
  assert.equal(before.anchor, null);
  assert.ok(gh.rawLog.includes(`${PINS}@${early.head}:${S.pinPaths(c.id).seq}`), "that head was read and did not hold it");
  const later = dailyAnchor(dayOf(Date.now() + DAY));
  const after = await S.anchorState(c.id, chain);
  assert.equal(after.pin, "anchored");
  assert.equal(after.anchor.path, later.path);
  assert.equal(after.anchor.head_commit, later.head);

  // the bound: records older than the day before the pin are not read, and past the first ANCHOR_RECORD_READS the rest wait
  assert.equal(S.ANCHOR_RECORD_READS, 3);
  const d = await committedCase("J bound");
  const old = dailyAnchor(dayOf(Date.now() - 5 * DAY));
  for (let i = 0; i < S.ANCHOR_RECORD_READS; i += 1) dailyAnchor(dayOf(Date.now() + (10 + i) * DAY)); // heads before the pin
  assert.equal((await reveal(d)).status, 201);
  const holding = dailyAnchor(dayOf(Date.now() + 20 * DAY));
  const g0 = gh.getLog.length;
  const st = await S.anchorState(d.id, chainOf(d.id));
  assert.equal(st.pin, "pinned", "the record that holds it is past the bound");
  const reads = gh.getLog.slice(g0).filter((p) => p.startsWith("anchors/"));
  assert.ok(!reads.includes(old.path), "a record from before the pin's day is not read");
  assert.ok(!reads.includes(holding.path), "nor one past the bound");
  assert.ok(reads.includes(later.path), "the first records from the day before the pin on are read");
  assert.equal(reads.length, S.ANCHOR_RECORD_READS);
});

test("COULD_NOT_LOOK: a read the pin's state needs that fails is no claim; the pin, then the anchor, each say so", async () => {
  const { id } = await sealedCase("J could not look");
  const chain = chainOf(id);
  const { seq, latest } = S.pinPaths(id);
  const wrote = wroteIt(seq);
  const fresh = () => S._internal.clearCommitFiles();
  // the pointer
  gh.forceGetFailure(PINS, latest, 1, 503);
  assert.deepEqual(await S.anchorState(id, chain), { pin: "could_not_look", reason: "pin_pointer_unreadable" });
  // the commits of the numbered record
  gh.forceCommitsFailure(PINS, seq, 1, 503);
  assert.deepEqual(await S.anchorState(id, chain), { pin: "could_not_look", reason: "pin_commit_unreadable" });
  // the numbered record at the commit that wrote it
  fresh();
  gh.forceRawFailure(1, 503, `@${wrote.sha}:${seq}`);
  assert.deepEqual(await S.anchorState(id, chain), { pin: "could_not_look", reason: "pin_at_commit_http_503" });
  fresh();
  gh.forceRawFailure(1, 0, `@${wrote.sha}:${seq}`);
  assert.deepEqual(await S.anchorState(id, chain), { pin: "could_not_look", reason: "pin_at_commit_fetch_failed" });

  // the anchor: the pin was read, so it stays pinned, and the anchor could not be looked up
  const pinnedBut = async (why) => {
    fresh();
    const st = await S.anchorState(id, chain);
    assert.equal(st.pin, "pinned", why);
    assert.deepEqual(st.anchor, { could_not_look: why });
  };
  gh.forceGetFailure(PINS, "anchors", 1, 503);
  await pinnedBut("anchors_unreadable");
  const a = dailyAnchor(pinDay(id));
  gh.forceGetFailure(PINS, a.path, 1, 503);
  await pinnedBut("anchor_record_unreadable");
  gh.forceRawFailure(1, 503, `@${a.head}:${seq}`);
  await pinnedBut("pin_at_head_http_503");
  // anchored is never said without the record's own commit
  gh.forceCommitsFailure(PINS, a.path, 1, 503);
  await pinnedBut("anchor_record_commit_unreadable");
  gh.forceRawFailure(1, 503, `@${a.commit}:${a.path}`);
  await pinnedBut("anchor_record_at_commit_http_503");
  fresh();
  assert.equal((await S.anchorState(id, chain)).pin, "anchored", "control: every read answered");
});

test("A PIN THAT DIFFERS AT ITS OWN COMMIT, OR IN AN ANCHORED HEAD, IS A CONFLICT: never pinned, never anchored", async () => {
  const { id } = await sealedCase("J conflict");
  const chain = chainOf(id);
  const { seq } = S.pinPaths(id);
  const ours = gh.read(PINS, seq);
  const theirs = { ...ours, chain: sha("another chain") };
  const set = (rec) => {
    gh._repoMap(PINS).get(seq).content = JSON.stringify(rec, null, 2) + "\n";
    return gh.addCommit(PINS, seq, "mock: the numbered pin record rewritten");
  };
  // an anchored head holding another chain for the pin: the record was rewritten, anchored, and put back
  const other = set(theirs);
  const a = dailyAnchor(pinDay(id), other);
  set(ours);
  const st = await S.anchorState(id, chain);
  assert.equal(st.pin, "conflict");
  assert.equal(st.reason, "anchored_head_holds_another_chain");
  assert.equal(st.anchor.head_commit, a.head);

  // the numbered record held another chain at the commit that wrote it (the oldest touching it)
  const { id: id2 } = await sealedCase("J conflict at its commit");
  const p2 = S.pinPaths(id2).seq;
  const mine = gh.read(PINS, p2);
  gh.seed(PINS, p2, { ...mine, chain: sha("yet another chain") });
  gh._repoMap(PINS).get(p2).content = JSON.stringify(mine, null, 2) + "\n";
  gh.addCommit(PINS, p2, "mock: the numbered pin record rewritten to this case's chain");
  const st2 = await S.anchorState(id2, chainOf(id2));
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
  const run = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.deepEqual(run.already, [id]);
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

test("THE PAGE: pinned names the commit that wrote the pin and says no daily anchor record holds it yet; anchored names the record, its commit and the head, each a link; could_not_look claims neither", async () => {
  const { id } = await sealedCase("J page");
  const { seq, latest } = S.pinPaths(id);
  const wrote = wroteIt(seq);
  const pinned = (await casePage(id)).html;
  assert.ok(pinned.includes(`pinned at commit <a ${commitLink(wrote.sha)}`), "the pin's commit, linked");
  assert.match(pinned, /\(the pins repository&#39;s commit time\)/);
  assert.match(pinned, /pinned, not anchored yet: no daily anchor record held its pin when this page was read/); // unit R-J2 (M2)
  assert.ok(!pinned.includes("anchored: a daily anchor record in this repository names a head that holds this pin"));
  assert.ok(!pinned.includes("anchored: its pin"), "the old words are gone");

  const a = dailyAnchor(pinDay(id));
  const anchored = (await casePage(id)).html;
  // unit R-J (J2): what is checked, and that the proof is not
  assert.match(anchored, /anchored: a daily anchor record in this repository names a head that holds this pin; this page does not check the OpenTimestamps proof\./);
  assert.ok(anchored.includes(`href="${PINS_URL}/blob/${a.commit}/${a.path}"`), "the record, at the commit that wrote it");
  assert.ok(anchored.includes(`written at commit <a ${commitLink(a.commit)}`), "the record's own commit");
  assert.ok(anchored.includes(`names the head <a ${commitLink(a.head)}`), "the head of the pins repository it names");

  gh.forceGetFailure(PINS, latest, 1, 503);
  const cnl = (await casePage(id)).html;
  assert.match(cnl, /could_not_look: its pin could not be read when this page was read \(pin_pointer_unreadable\), so nothing is claimed about its pin or its anchor/);
  assert.ok(!cnl.includes("pinned at commit"));
  assert.ok(!cnl.includes("anchored: a daily"));
});

test("THE NOTE: a case is pinned by the commit that writes its pin and anchored only by a daily anchor record, named with that record's commit", () => {
  // unit R-J (J2): a daily anchor record in this repository, and the proof not checked
  assert.match(S.ANCHOR_NOTE, /^A case is pinned by the pins-repository commit that writes its pin, and anchored only when a daily anchor record in this repository names a head that holds that pin; this service does not check the OpenTimestamps proof\. The record's own commit is named beside the word\./);
  assert.match(S.ANCHOR_NOTE, /not as a log-tree leaf/);
  assert.ok(!/is anchored by the pins-repository commit/.test(S.ANCHOR_NOTE), "a commit alone never anchors");
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
// A pin for `chain` naming `caseCommit`, written over the case's pin paths.
function plantPin(id, chain, caseCommit) {
  const rec = { ...S._internal.pinRecord(id, chain, REVEAL_AT, caseCommit) };
  if (caseCommit === undefined) delete rec.case_commit;
  gh.seed(PINS, S.pinPaths(id).seq, rec);
  gh.seed(PINS, S.pinPaths(id).latest, rec);
  return rec;
}

test("TWO WRITES: the reveal reads back the commit the pins repository assigned to the sealed case file and records it as case_commit in the pin; the answer names it too", async () => {
  const { id, r } = await sealedCase("J case commit");
  const commit = sealCommit(id);
  assert.match(gh.commitsFor(PINS, C.casePath(id))[0].message, /sealed/, "fixture: the newest commit of the case file is the seal");
  assert.equal(r.body.case_commit, commit);
  assert.equal(r.body.pin, "pinned");
  const { seq, latest } = S.pinPaths(id);
  assert.equal(gh.read(PINS, seq).case_commit, commit);
  assert.equal(gh.read(PINS, latest).case_commit, commit);
  const st = await S.anchorState(id, chainOf(id));
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

test("THE VERIFIER NEVER TRUSTS case_commit AS AN ID: a pin naming a commit at which the case file is not the case served, byte for byte, is pin_commit_mismatch, never pinned and never anchored; since unit R-J (J3) so is one naming a commit that does not exist; only a read that fails is could_not_look", async () => {
  const { id } = await sealedCase("J mismatch");
  const chain = chainOf(id);
  const opened = gh.commitsFor(PINS, C.casePath(id)).slice(-1)[0].sha; // the case file as opened, not as sealed
  plantPin(id, chain, opened);
  const a = dailyAnchor(dayOf(Date.now() + DAY));
  const st = await S.anchorState(id, chain);
  assert.equal(st.pin, "pin_commit_mismatch");
  assert.equal(st.reason, "case_at_commit_differs");
  assert.equal(st.case_commit, opened);
  assert.ok(gh.rawLog.includes(`${PINS}@${opened}:${C.casePath(id)}`), "it read the case file at the commit the pin names");
  assert.ok(!gh.rawLog.some((k) => k.startsWith(`${PINS}@${a.head}:`)), "and looked no further: never anchored");
  const page = (await casePage(id)).html;
  assert.match(page, /pin_commit_mismatch: its pin names commit <a [^>]+>[0-9a-f]{12}<\/a> for the case file, and the case file at that commit is not this case file in canonical form \(json-c14n:v1\) \(case_at_commit_differs\)\. Never pinned, never anchored\./);
  assert.ok(!page.includes("pinned at commit"));
  // unit R-J (J3), inverted: a commit the repository does not have is a
  // mismatch, never could_not_look (its existence read from the commits API)
  S._internal.clearCommitFiles();
  plantPin(id, chain, "f".repeat(40));
  const forged = await S.anchorState(id, chain);
  assert.deepEqual([forged.pin, forged.reason, forged.case_commit], ["pin_commit_mismatch", "case_commit_not_found", "f".repeat(40)]);
  gh.forceRawFailure(1, 503, `:${C.casePath(id)}`);
  plantPin(id, chain, sealCommit(id));
  assert.deepEqual(await S.anchorState(id, chain), { pin: "could_not_look", reason: "case_at_commit_http_503" });
  dailyAnchor(dayOf(Date.now() + 2 * DAY)); // a head holding the pin as now planted (re-seeding drops a path's history in the mock)
  assert.equal((await S.anchorState(id, chain)).pin, "anchored", "control: the seal's own commit, read");
});

test("COMMIT_UNRECORDED: a sealed case with no pin, or a pin that names no case commit, reads commit_unrecorded, never pinned or anchored, as document_unrecorded reads", async () => {
  const p = await sealedCase("J unrecorded", { pinFails: true });
  assert.deepEqual(await S.anchorState(p.id, chainOf(p.id)), { pin: "commit_unrecorded", reason: "not_pinned" });
  const { id } = await sealedCase("J legacy pin");
  const chain = chainOf(id);
  plantPin(id, chain, undefined); // a pin from before Design J
  dailyAnchor(dayOf(Date.now() + DAY));
  const st = await S.anchorState(id, chain);
  assert.equal(st.pin, "commit_unrecorded");
  assert.equal(st.reason, "no_case_commit");
  const page = (await casePage(id)).html;
  assert.match(page, /commit_unrecorded: its pin names no commit for the case file/);
  assert.ok(!page.includes("anchored: a daily"));
  assert.ok(!page.includes("pinned at commit"));
  assert.match((await casePage(p.id)).html, /commit_unrecorded: the second of this case&#39;s two writes, the pin that records the commit that wrote the case file, has not completed/);
});

test("CRASH BETWEEN THE PHASES: the case file written and its pin not; the answer names what it knows, the page says commit_unrecorded, the case file is never backfilled, and the sealer's next run records the commit, read back and checked, in the pin", async () => {
  // the pin write fails after the case file landed
  const { id, r } = await sealedCase("J crash pin", { pinFails: true });
  const cpath = C.casePath(id);
  assert.equal(r.body.pin, "commit_unrecorded");
  assert.equal(r.body.case_commit, sealCommit(id), "the answer still names the case file's commit");
  assert.equal(gh.has(PINS, S.pinPaths(id).latest), false);
  // the case's PUT answered without its commit: a process that died right after the write
  // (the reveal's attempt is the case file's first PUT since red-team fix E; the seal's is the second)
  const c = await committedCase("J crash answer");
  gh.dropCommitFromAnswer(PINS, C.casePath(c.id), 2);
  const lost = await reveal(c);
  assert.equal(lost.status, 201);
  assert.equal(lost.body.case_commit, null);
  assert.equal(lost.body.pin, "commit_unrecorded");
  assert.equal(gh.has(PINS, S.pinPaths(c.id).seq), false, "no pin without the commit it records");

  for (const x of [id, c.id]) assert.match((await casePage(x)).html, /commit_unrecorded/);
  const bytes = (x) => gh._repoMap(PINS).get(C.casePath(x)).content;
  const before = { [id]: [bytes(id), gh.commitsFor(PINS, cpath).length], [c.id]: [bytes(c.id), gh.commitsFor(PINS, C.casePath(c.id)).length] };
  const run = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.deepEqual(run.newly_pinned.sort(), [id, c.id].sort());
  // never backfilled silently: the case files are untouched, and the run names each commit it recorded
  for (const x of [id, c.id]) {
    assert.equal(bytes(x), before[x][0], "the case file is byte for byte as written");
    assert.equal(gh.commitsFor(PINS, C.casePath(x)).length, before[x][1], "and was not written again");
    assert.equal(gh.read(PINS, S.pinPaths(x).latest).case_commit, sealCommit(x));
    assert.ok(gh.commitsLog.includes(C.casePath(x)), "the commit was read back");
    assert.ok(gh.rawLog.includes(`${PINS}@${sealCommit(x)}:${C.casePath(x)}`), "and the case file read at it");
  }
  assert.deepEqual(run.commits_recorded.map((x) => [x.case_id, x.pin_seq, x.case_commit]).sort(),
    [[id, 1, sealCommit(id)], [c.id, 1, sealCommit(c.id)]].sort());
  for (const x of [id, c.id]) {
    const st = await S.anchorState(x, chainOf(x));
    assert.equal(st.pin, "pinned");
    assert.equal(st.case_commit, sealCommit(x));
  }
});

test("SWAPPED FILE: a late retry that would pin a different commit of a swapped case file pins nothing and reports pin_commit_mismatch; a pin that did is pin_commit_mismatch to every reader, a daily anchor record notwithstanding", async () => {
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
  assert.equal(gh.has(PINS, S.pinPaths(id).latest), false);

  // the original is put back, and a late retry that did not check pinned the swapped file's commit
  rewriteCase(id, original);
  plantPin(id, chain, swapCommit);
  dailyAnchor(dayOf(Date.now() + DAY));
  const st = await S.anchorState(id, chain);
  assert.equal(st.pin, "pin_commit_mismatch");
  assert.equal(st.case_commit, swapCommit);
  assert.match((await casePage(id)).html, /pin_commit_mismatch/);
  const again = await S.anchorPending({ now: REVEAL_AT + 120000, keyDocument: DOC });
  assert.deepEqual(again.already, [], "never read as pinned");
  assert.deepEqual(again.refused, [{ case_id: id, code: "pin_commit_mismatch", reason: "case_at_commit_differs" }]);
});

// =============================================================================
// STEP 3: a reference row's two writes, the row and then the case's next pin,
// which lists its commit
// =============================================================================

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

test("ROW COMMIT: the row's answer names the commit that wrote it; the page shows it commit_unrecorded until the case's next pin lists it, then names it from that pin, read at that commit; a row read with its pin has its commit in two places", async () => {
  const c = await sealedCase("J row commit");
  const r = await reference(c, "a", "row-1");
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(r.body.row_commit, rowCommit(c.id, 1), "the answer names the commit the pins repository assigned to the row");
  assert.match(r.body.row_commit_note, /A later pin of the case may list that commit/); // unit R-J2 (B2): no future event stated as fact
  const before = rowLine((await casePage(c.id)).html, 1);
  assert.match(before, /commit_unrecorded: no pin of this case read when this page was read lists the commit that wrote this row/);

  const run = await sealerRun();
  assert.deepEqual(run.already, [c.id]);
  const two = S._internal.pinPath(c.id, 2);
  const pin2 = gh.read(PINS, two);
  assert.equal(pin2.seq, 2);
  assert.equal(pin2.chain, chainOf(c.id), "the case's chain, unchanged");
  assert.equal(pin2.case_commit, sealCommit(c.id));
  assert.deepEqual(pin2.reference_commits, [{ seq: 1, commit: r.body.row_commit }]);
  assert.deepEqual(gh.read(PINS, S.pinPaths(c.id).latest), pin2, "the pointer moved to the next pin");
  assert.deepEqual(run.commits_recorded, [{ case_id: c.id, pin_seq: 2, case_commit: sealCommit(c.id), reference_commits: [{ seq: 1, commit: r.body.row_commit }] }]);
  assert.ok(gh.rawLog.includes(`${PINS}@${r.body.row_commit}:${rowPath(c.id, 1)}`), "the row was read at its commit before it was listed");
  const after = rowLine((await casePage(c.id)).html, 1);
  assert.ok(after.includes(`recorded by commit <a ${commitLink(r.body.row_commit)}`), "the row's commit, linked"); // unit R-J2 (B2)
  assert.match(after, /listed by pin 2, read when this page was read/);
  const st = await S.anchorState(c.id, chainOf(c.id));
  assert.equal(st.pin, "pinned", "the case reads pinned through its next pin");
  assert.equal(st.pin_commit.sha, wroteIt(S.pinPaths(c.id).seq).sha, "and the pin it names is the seal's");

  // a second run with nothing new writes nothing; a later row goes in the pin after
  const writes = gh.putLog.length;
  assert.deepEqual((await sealerRun(120000)).commits_recorded, []);
  assert.equal(gh.putLog.length, writes);
  const r2 = await reference(c, "b", "row-2");
  assert.equal(r2.status, 201);
  await sealerRun(180000);
  assert.deepEqual(gh.read(PINS, S._internal.pinPath(c.id, 3)).reference_commits, [{ seq: 2, commit: r2.body.row_commit }], "only the rows since the last pin");
  const page = (await casePage(c.id)).html;
  assert.match(rowLine(page, 1), /listed by pin 2/);
  assert.match(rowLine(page, 2), /listed by pin 3/);
});

test("CRASH BETWEEN THE PHASES, FOR A ROW: the row's write answered without its commit; the answer says so, the page says commit_unrecorded, the row is never written again, and the next run lists the commit, read back and checked", async () => {
  const c = await sealedCase("J row crash");
  gh.dropCommitFromAnswer(PINS, rowPath(c.id, 1), 1);
  const r = await reference(c, "a", "row-lost");
  assert.equal(r.status, 201);
  assert.equal(r.body.row_commit, null);
  assert.match(rowLine((await casePage(c.id)).html, 1), /commit_unrecorded/);
  const bytes = gh._repoMap(PINS).get(rowPath(c.id, 1)).content;
  const run = await sealerRun();
  assert.deepEqual(run.commits_recorded.map((x) => x.reference_commits), [[{ seq: 1, commit: rowCommit(c.id, 1) }]]);
  assert.equal(gh._repoMap(PINS).get(rowPath(c.id, 1)).content, bytes, "the row is byte for byte as written");
  assert.equal(gh.commitsFor(PINS, rowPath(c.id, 1)).length, 1, "and was written once");
  assert.ok(rowLine((await casePage(c.id)).html, 1).includes(`recorded by commit <a ${commitLink(rowCommit(c.id, 1))}`));
});

test("A ROW SWAPPED WHILE THE SEALER READS ITS COMMIT BACK IS NOT LISTED; A PIN LISTING A COMMIT THAT HOLDS ANOTHER ROW IS pin_commit_mismatch FOR THAT ROW, NEVER ITS COMMIT", async () => {
  const c = await sealedCase("J row swapped");
  assert.equal((await reference(c, "a", "row-original")).status, 201);
  const p = rowPath(c.id, 1);
  const original = gh.read(PINS, p);
  let swapCommit = null;
  const undo = onFirstRequest(`commits?path=${encodeURIComponent(p)}`, async () => {
    gh._repoMap(PINS).get(p).content = JSON.stringify({ ...original, recorded_at: "2026-10-10T09:45:00Z" }, null, 2) + "\n";
    swapCommit = gh.addCommit(PINS, p, "mock: the row rewritten");
  });
  let run;
  try {
    run = await sealerRun();
  } finally {
    undo();
  }
  assert.ok(swapCommit, "fixture: the swap happened during the read-back");
  assert.deepEqual(run.rows_unrecorded, [{ case_id: c.id, seq: 1, code: "pin_commit_mismatch", reason: "reference_at_commit_differs" }]);
  assert.equal(gh.has(PINS, S._internal.pinPath(c.id, 2)), false, "no pin lists it");
  // the original put back, and a pin that lists the swapped row's commit for it
  gh._repoMap(PINS).get(p).content = JSON.stringify(original, null, 2) + "\n";
  gh.addCommit(PINS, p, "mock: the row put back");
  const latest = gh.read(PINS, S.pinPaths(c.id).latest);
  const bad = { ...latest, seq: 2, reference_commits: [{ seq: 1, commit: swapCommit }] };
  gh.seed(PINS, S._internal.pinPath(c.id, 2), bad);
  gh.seed(PINS, S.pinPaths(c.id).latest, bad);
  const line = rowLine((await casePage(c.id)).html, 1);
  assert.match(line, /pin_commit_mismatch: pin 2 names commit <a [^>]+>[0-9a-f]{12}<\/a> for this row, and the row at that commit is not this row in canonical form \(json-c14n:v1\) \(reference_at_commit_differs\)/);
  assert.ok(!line.includes("written at commit"));
});

test("A PIN FROM BEFORE, NAMING NO CASE COMMIT: the next run records the commit, read back and checked, in the case's next pin; until then commit_unrecorded", async () => {
  const { id } = await sealedCase("J legacy retry");
  const chain = chainOf(id);
  plantPin(id, chain, undefined);
  assert.equal((await S.anchorState(id, chain)).pin, "commit_unrecorded");
  const run = await sealerRun();
  assert.deepEqual(run.commits_recorded, [{ case_id: id, pin_seq: 2, case_commit: sealCommit(id), reference_commits: [] }]);
  const two = gh.read(PINS, S._internal.pinPath(id, 2));
  assert.equal(two.case_commit, sealCommit(id));
  assert.equal(Object.prototype.hasOwnProperty.call(two, "reference_commits"), false, "no rows to list");
  const st = await S.anchorState(id, chain);
  assert.equal(st.pin, "pinned");
  assert.equal(st.case_commit, sealCommit(id));
});

test("THE NEXT PIN'S RECORD: from seq 2 on a pin carries case_commit; reference_commits, when present, lists {seq, commit} in ascending seq; the judge refuses anything else by name", async () => {
  const { id } = await sealedCase("J next pin judge");
  const verdict = require("../lib/_verdict.js");
  const ns = S.pinNamespace(id);
  const judge = (rec) => verdict.judgeCaseSeal({ json: rec }, { namespace: ns });
  const base = { ...gh.read(PINS, S.pinPaths(id).latest), seq: 2, reference_commits: [{ seq: 1, commit: "a".repeat(40) }, { seq: 3, commit: "b".repeat(40) }] };
  assert.equal(judge(base).ok, true);
  const { case_commit: _drop, ...noCommit } = base; // eslint-disable-line no-unused-vars
  const bad = {
    case_seal_missing_field: [noCommit],
    case_seal_wrong_seq: [{ ...base, seq: 0 }, { ...base, seq: "2" }, { ...base, seq: 1.5 }, { ...base, seq: 100000000 }],
    case_seal_reference_commits_unreadable: [
      { ...base, reference_commits: [] },
      { ...base, reference_commits: {} },
      { ...base, reference_commits: [{ seq: 3, commit: "a".repeat(40) }, { seq: 1, commit: "b".repeat(40) }] },
      { ...base, reference_commits: [{ seq: 1, commit: "a".repeat(40) }, { seq: 1, commit: "b".repeat(40) }] },
      { ...base, reference_commits: [{ seq: 1, commit: "A".repeat(40) }] },
      { ...base, reference_commits: [{ seq: 0, commit: "a".repeat(40) }] },
      { ...base, reference_commits: [{ seq: 1, commit: "a".repeat(40), at: "x" }] },
      { ...base, reference_commits: [{ seq: 1 }] },
    ],
  };
  for (const [reason, recs] of Object.entries(bad)) {
    for (const rec of recs) assert.equal(judge(rec).reason, reason, `${reason}: ${JSON.stringify(rec.reference_commits)} ${rec.seq}`);
  }
});

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

test("EVERY COMMIT IS A LINK: on a sealed page, anchored and with a row recorded, and under a since-revoked key, every commit (the key document's, the stamps', the case file's, the pin's, the daily anchor record's and its head, the row's, the revoking document's) is a link into the public repository it is a commit of, and none is bare text", async () => {
  const c = await sealedCase("J every commit");
  const r = await reference(c, "a", "row-linked");
  assert.equal(r.status, 201);
  await sealerRun();
  const a = dailyAnchor(dayOf(Date.now() + DAY));
  const k = storedCase(c.id);
  const current = "c".repeat(40);
  const render = async (keyDocument, env) => {
    const res = makeRes();
    CP._internal.clearPageCache(); // unit R-J (J7): each view here reads afresh
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
  assert.match(page, /anchored: a daily anchor record in this repository names a head that holds this pin/, "fixture: anchored");
  assert.match(rowLine(page, 1), /recorded by commit/, "fixture: the row, recorded");
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
    [PINS, a.commit, "the daily anchor record"],
    [PINS, a.head, "the head it names"],
    [PINS, r.body.row_commit, "the row"],
  ];
  for (const [repo, sha, what] of want) {
    assert.ok(linked.some((l) => l.repo === repo && l.sha === sha), `${what}: ${sha} linked into ${repo}`);
  }
  for (const l of linked) assert.ok([PINS, STAMPS, S.KEY_DOCUMENT_REPO].includes(l.repo), `a link into a repository the page names: ${l.repo}`);
});

test("EVERY COMMIT IS A LINK, ON THE OTHER PAGES THAT NAME ONE: pin_commit_mismatch (the commit the pin names), a row's pin_commit_mismatch, could_not_look on the key document, a case not yet pinned, and a case registered and not revealed", async () => {
  const pages = [];
  // pin_commit_mismatch
  const m = await sealedCase("J link mismatch");
  plantPin(m.id, chainOf(m.id), gh.commitsFor(PINS, C.casePath(m.id)).slice(-1)[0].sha);
  pages.push(["pin_commit_mismatch", (await casePage(m.id)).html]);
  // a row whose listed commit holds another row
  const w = await sealedCase("J link row mismatch");
  assert.equal((await reference(w, "a", "row-w")).status, 201);
  await sealerRun();
  const rp = rowPath(w.id, 1);
  const row = gh.read(PINS, rp);
  gh._repoMap(PINS).get(rp).content = JSON.stringify({ ...row, recorded_at: "2026-10-10T09:45:00Z" }, null, 2) + "\n";
  const other = gh.addCommit(PINS, rp, "mock: another row at this path");
  gh._repoMap(PINS).get(rp).content = JSON.stringify(row, null, 2) + "\n";
  gh.addCommit(PINS, rp, "mock: the row put back");
  const latest = gh.read(PINS, S.pinPaths(w.id).latest);
  gh.seed(PINS, S.pinPaths(w.id).latest, { ...latest, reference_commits: [{ seq: 1, commit: other }] });
  pages.push(["row pin_commit_mismatch", (await casePage(w.id)).html]);
  // the key document the case names could not be read
  const d = await sealedCase("J link document");
  gh.forceRawFailure(1, 503, `:${S.CASE_KEYS_FILE}`);
  S._internal.clearDocumentCache();
  const dp = await casePage(d.id);
  assert.equal(dp.status, 503, "fixture: the could-not-look page");
  pages.push(["document could_not_look", dp.html]);
  // not pinned yet
  const p = await sealedCase("J link pending", { pinFails: true });
  pages.push(["commit_unrecorded", (await casePage(p.id)).html]);
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
  assert.match(pages[1][1], /pin_commit_mismatch: pin 2 names commit <a href="https:\/\/github\.com\/test-owner\/test-pins\/commit\/[0-9a-f]{40}"/);
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
// The test names carry the mutant ids.

test("A03 (the day before the pin): a daily anchor record named the day before the pin's commit, whose head holds the pin, anchors it", async () => {
  const { id } = await sealedCase("J day before");
  const before = dayOf(Date.parse(`${pinDay(id)}T00:00:00Z`) - DAY);
  const a = dailyAnchor(before);
  const st = await S.anchorState(id, chainOf(id));
  assert.equal(st.pin, "anchored");
  assert.equal(st.anchor.path, a.path);
});

test("A11, A12 (the record's own commit): it is the commit that wrote the text read, the newest touching it, and the record at that commit must name the same head", async () => {
  const { id } = await sealedCase("J record commit");
  const chain = chainOf(id);
  const day = pinDay(id);
  const path = `anchors/${day}-head.txt`;
  const head = gh.headOf(PINS);
  // written twice: the first text names a head that does not hold the pin, the second the head that does
  const first = gh.seedText(PINS, path, `${"0".repeat(40)} ${day}T03:15:00+00:00\n`);
  gh._repoMap(PINS).get(path).content = `${head} ${day}T03:15:00+00:00\n`;
  const second = gh.addCommit(PINS, path, "mock: the record rewritten");
  const st = await S.anchorState(id, chain);
  assert.equal(st.pin, "anchored");
  assert.equal(st.anchor.record_commit.sha, second, "the commit that wrote the text read");
  assert.notEqual(second, first);
  // the text now read names a head the record at its own commit does not: no claim
  S._internal.clearCommitFiles();
  gh.seedText(PINS, `anchors/${dayOf(Date.now() + 9 * DAY)}-head.txt`, "x"); // a new head, which holds the pin too
  gh._repoMap(PINS).get(path).content = `${gh.headOf(PINS)} ${day}T03:15:00+00:00\n`; // changed with no commit of its own
  const st2 = await S.anchorState(id, chain);
  assert.equal(st2.pin, "pinned");
  assert.deepEqual(st2.anchor, { could_not_look: "anchor_record_changed" });
});

test("B03 (a commit whose case file is not JSON): a pin naming it is pin_commit_mismatch, not could_not_look", async () => {
  const { id } = await sealedCase("J not json");
  const p = C.casePath(id);
  const kept = gh._repoMap(PINS).get(p).content;
  gh._repoMap(PINS).get(p).content = "this is not a case file\n";
  const garbage = gh.addCommit(PINS, p, "mock: not JSON");
  gh._repoMap(PINS).get(p).content = kept;
  gh.addCommit(PINS, p, "mock: put back");
  plantPin(id, chainOf(id), garbage);
  const st = await S.anchorState(id, chainOf(id));
  assert.equal(st.pin, "pin_commit_mismatch");
  assert.equal(st.reason, "case_at_commit_differs");
});

test("C01, C02 (a numbered record holds its own seq): the seal's record read at its commit with another seq is a conflict, and an orphan at seq 1 that says seq 2 is never adopted", async () => {
  const { id } = await sealedCase("J own seq");
  const { seq } = S.pinPaths(id);
  const mine = gh.read(PINS, seq);
  gh.seed(PINS, seq, { ...mine, seq: 2 });
  gh._repoMap(PINS).get(seq).content = JSON.stringify(mine, null, 2) + "\n";
  gh.addCommit(PINS, seq, "mock: put back to seq 1");
  const st = await S.anchorState(id, chainOf(id));
  assert.equal(st.pin, "conflict");
  assert.equal(st.reason, "pin_at_its_commit_holds_another_chain");

  const o = await sealedCase("J orphan seq", { pinFails: true });
  const op = S.pinPaths(o.id);
  gh.seed(PINS, op.seq, { ...S._internal.pinRecord(o.id, chainOf(o.id), REVEAL_AT, sealCommit(o.id)), seq: 2 });
  const r = await S.anchorCase(o.id, { now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.equal(r.pin, "conflict");
  assert.equal(gh.has(PINS, op.latest), false, "no pointer to it");
});

// Pins planted directly: the seal's at seq 1 and next pins up to `top`,
// `lists` mapping a pin seq to its reference_commits.
function plantPins(id, top, lists = {}) {
  const chain = chainOf(id);
  const base = gh.read(PINS, S.pinPaths(id).seq);
  let rec = base;
  for (let n = 2; n <= top; n += 1) {
    rec = { ...base, seq: n, ...(lists[n] ? { reference_commits: lists[n] } : {}) };
    gh.seed(PINS, S._internal.pinPath(id, n), rec);
  }
  gh.seed(PINS, S.pinPaths(id).latest, rec);
  return chain;
}

test("C03, C04 (the walk down the pins): a page reads no pin below the ones that list its rows, and reads at most PIN_WALK_READS below the pointer", async () => {
  assert.equal(S.PIN_WALK_READS, 20);
  const c = await sealedCase("J walk");
  assert.equal((await reference(c, "a", "walk-1")).status, 201);
  const commit = rowCommit(c.id, 1);
  // listed in pin 4, the pointer's: pins 3, 2 and 1 are not read
  plantPins(c.id, 4, { 4: [{ seq: 1, commit }] });
  const g0 = gh.getLog.length;
  assert.match(rowLine((await casePage(c.id)).html, 1), /listed by pin 4/);
  const read = gh.getLog.slice(g0);
  for (const n of [1, 2, 3]) assert.ok(!read.includes(S._internal.pinPath(c.id, n)), `pin ${n} is not read`);
  // listed in pin 2 under a pointer at 22: twenty reads reach it; at 23 they do not
  const top = S._internal.listedReferences;
  const chain = plantPins(c.id, 22, { 2: [{ seq: 1, commit }] });
  const at22 = await top(c.id, chain, gh.read(PINS, S.pinPaths(c.id).latest), new Set([1]));
  assert.equal(at22.ok, true);
  assert.deepEqual(at22.listed.get(1), { commit, pin_seq: 2 });
  plantPins(c.id, 23, { 2: [{ seq: 1, commit }] });
  const at23 = await top(c.id, chain, gh.read(PINS, S.pinPaths(c.id).latest), new Set([1]));
  assert.deepEqual([at23.ok, at23.reason], [false, "pins_not_read"]);
  assert.match(rowLine((await casePage(c.id)).html, 1), /could_not_look: its commit could not be read when this page was read \(pins_not_read\)/);
});

test("C05, C06 (which pins count): a pin below the pointer that is not this case's stops the walk, and a row two pins list is read from the newer", async () => {
  const c = await sealedCase("J which pins");
  assert.equal((await reference(c, "a", "which-1")).status, 201);
  const commit = rowCommit(c.id, 1);
  // pin 2 holds another chain: what it lists does not count
  plantPins(c.id, 3, {});
  gh.seed(PINS, S._internal.pinPath(c.id, 2), { ...gh.read(PINS, S._internal.pinPath(c.id, 2)), chain: sha("not this case"), reference_commits: [{ seq: 1, commit }] });
  assert.match(rowLine((await casePage(c.id)).html, 1), /could_not_look: its commit could not be read when this page was read \(pin_unreadable\)/);
  // row 1 listed in pin 3 at its commit and in pin 2 at another; row 2 only in pin 2, so the walk reads both:
  // the newer pin's listing of row 1 is the one read
  assert.equal((await reference(c, "b", "which-2")).status, 201);
  const commit2 = rowCommit(c.id, 2);
  plantPins(c.id, 3, { 2: [{ seq: 1, commit: sealCommit(c.id) }, { seq: 2, commit: commit2 }], 3: [{ seq: 1, commit }] });
  const page = (await casePage(c.id)).html;
  assert.match(rowLine(page, 1), /recorded by commit .*listed by pin 3/);
  assert.match(rowLine(page, 2), /recorded by commit .*listed by pin 2/, "fixture: the walk went on to pin 2");
});

test("C08 (at most REFERENCE_ROW_READS rows a run): twenty-one rows are listed over two runs, twenty and then one", async () => {
  const c = await sealedCase("J twenty-one");
  for (let i = 0; i < 21; i += 1) assert.equal((await reference(c, i < 20 ? "a" : "b", `bulk-${i}`)).status, 201);
  const one = await sealerRun();
  assert.equal(one.commits_recorded[0].reference_commits.length, S.REFERENCE_ROW_READS);
  const two = await sealerRun(120000);
  assert.deepEqual(two.commits_recorded[0].reference_commits.map((x) => x.seq), [21]);
});

test("C13 (the pointer moved from the record read): when another writer moves the pointer meanwhile, the next pin is not counted written, the run says so, and the next run adopts the record", async () => {
  const c = await sealedCase("J pointer moved");
  assert.equal((await reference(c, "a", "moved-1")).status, 201);
  const { latest } = S.pinPaths(c.id);
  // the pointer changes under the run, right before it is moved
  const viaMock = global.fetch;
  let moved = false;
  global.fetch = async (url, o) => {
    if (!moved && (o && o.method) === "PUT" && String(url).includes(`/contents/${latest}`)) {
      moved = true;
      const rec = gh._repoMap(PINS).get(latest);
      rec.content = rec.content.replace(/\n$/, " \n"); // the same record, written again: a new blob sha
      rec.sha = crypto.randomBytes(20).toString("hex");
    }
    return viaMock(url, o);
  };
  let run;
  try {
    run = await sealerRun();
  } finally {
    global.fetch = viaMock;
  }
  assert.ok(moved, "fixture: the pointer moved");
  assert.deepEqual(run.commits_recorded, [], "not counted written");
  assert.deepEqual(run.pending, [{ case_id: c.id, reason: "pin_pointer_moved" }]);
  assert.equal(gh.has(PINS, S._internal.pinPath(c.id, 2)), true, "the record landed");
  assert.equal(gh.read(PINS, latest).seq, 1, "the pointer did not move to it");
  const again = await sealerRun(120000);
  assert.deepEqual(again.pending, []);
  assert.equal(gh.read(PINS, latest).seq, 2, "the next run adopts it");
  assert.match(rowLine((await casePage(c.id)).html, 1), /listed by pin 2/);
});

test("C18 (a row of a case not pinned yet): its commit is commit_unrecorded, the case's own second phase not done, never could_not_look", async () => {
  const c = await sealedCase("J row unpinned", { pinFails: true });
  // a row on a case not pinned: since red-team fix D the handler refuses one, so it is planted, as a row written before would be
  assert.equal((await reference(c, "a", "early-row")).body.error_code, "case_not_pinned", "fixture: the handler refuses it now");
  const row = S.referenceRow({ caseId: c.id, seq: 1, crossReference: { ...XREF, reference: "early-row" }, recordedAt: C.utcSeconds(REVEAL_AT + 1800000),
    appendedBy: "role:a" }, S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  gh.seed(PINS, rowPath(c.id, 1), row);
  const line = rowLine((await casePage(c.id)).html, 1);
  assert.match(line, /commit_unrecorded: no pin of this case read when this page was read lists the commit that wrote this row/);
  assert.ok(!line.includes("could_not_look"));
});

test("C23 (a row whose commit holds no JSON there): the sealer does not list it and reports pin_commit_mismatch, not could_not_look", async () => {
  const c = await sealedCase("J row not json");
  assert.equal((await reference(c, "a", "row-x")).status, 201);
  const p = rowPath(c.id, 1);
  const kept = gh._repoMap(PINS).get(p).content;
  gh._repoMap(PINS).get(p).content = "not a row\n";
  gh.addCommit(PINS, p, "mock: not JSON at the newest commit");
  gh._repoMap(PINS).get(p).content = kept; // the file read now is the row; its newest commit holds no JSON
  const run = await sealerRun();
  assert.deepEqual(run.rows_unrecorded, [{ case_id: c.id, seq: 1, code: "pin_commit_mismatch", reason: "reference_at_commit_differs" }]);
  assert.deepEqual(run.commits_recorded, []);
});

test("P03, P07 (the page's words for a pin it read): an anchor it could not look up is said, and a case file commit that holds another case is never shown as the case's", async () => {
  const { id } = await sealedCase("J page words");
  gh.forceGetFailure(PINS, "anchors", 1, 503);
  const page = (await casePage(id)).html;
  assert.match(page, /pinned; whether a daily anchor record holds its pin could not be read when this page was read \(could_not_look: anchors_unreadable\), so no anchor is claimed\./);
  assert.ok(!page.includes("pinned, not anchored yet"));
  const opened = gh.commitsFor(PINS, C.casePath(id)).slice(-1)[0].sha;
  plantPin(id, chainOf(id), opened);
  const m = (await casePage(id)).html;
  assert.ok(m.includes(`not shown: its pin names <a ${commitLink(opened)}`), "the case commit row"); // unit R-J2 (n6, n7)
  assert.ok(!m.includes("written at commit"), "never shown as the commit that wrote the case");
});

test("S01, S02 (the status page's case row): the column says pinned and holds the pinned count", async () => {
  const statusHandler = require("../api/status.js");
  await sealedCase("J status one");
  await sealedCase("J status two");
  await sealedCase("J status pending", { pinFails: true });
  const res = makeRes();
  await statusHandler(makeReq({ method: "GET", headers: { "x-forwarded-for": "10.98.2.1" } }), res);
  const page = String(res._body);
  assert.match(page, /<th>where<\/th><th>case files<\/th><th>pinned<\/th><th>pending<\/th><th>withdrawn<\/th>/);
  const row = /<td><code>pins\/case\/<\/code>[\s\S]*?<\/tr>/.exec(page);
  assert.ok(row, "the case row");
  assert.deepEqual([...row[0].matchAll(/<td>(\d+)<\/td>/g)].map((x) => Number(x[1])), [3, 2, 1, 0]);
  assert.match(page, /<em>Pinned<\/em> means the case has both registration files and a pin pointer, by path alone/);
});
