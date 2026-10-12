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
  const st = await S.anchorState(id, chainOf(id));
  assert.equal(st.pin, "pinned");
  assert.deepEqual(st.pin_commit, { sha: wrote.sha, date: wrote.date });
  assert.equal(st.anchor, null, "no daily anchor record holds it");
  assert.equal(st.record.chain, chainOf(id));
  // what it read: the pointer, the anchors listing, the numbered record's commits, and that record at the commit that wrote it
  assert.deepEqual(gh.getLog.slice(g0), [latest, "anchors"]);
  assert.deepEqual(gh.commitsLog.slice(c0), [seq]);
  assert.deepEqual(gh.rawLog.slice(r0), [`${PINS}@${wrote.sha}:${seq}`]);
});

test("ANCHORED: a daily anchor record whose head holds the pin reads anchored, naming the record, the commit that wrote it and the head it names", async () => {
  const { id } = await sealedCase("J anchored");
  const a = dailyAnchor(pinDay(id));
  const st = await S.anchorState(id, chainOf(id));
  assert.equal(st.pin, "anchored");
  const rc = gh.commitsFor(PINS, a.path)[0];
  assert.equal(rc.sha, a.commit);
  assert.deepEqual(st.anchor, { path: a.path, head_commit: a.head, claimed_at: a.claimedAt, record_commit: { sha: a.commit, date: rc.date } });
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
  assert.equal(p.r.body.pin, "pending");
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
  assert.match(pinned, /pinned, not anchored yet: no daily anchor record read on this request holds its pin/);
  assert.ok(!pinned.includes("anchored: a daily anchor record holds its pin"));
  assert.ok(!pinned.includes("anchored: its pin"), "the old words are gone");

  const a = dailyAnchor(pinDay(id));
  const anchored = (await casePage(id)).html;
  assert.match(anchored, /anchored: a daily anchor record holds its pin/);
  assert.ok(anchored.includes(`href="${PINS_URL}/blob/${a.commit}/${a.path}"`), "the record, at the commit that wrote it");
  assert.ok(anchored.includes(`written at commit <a ${commitLink(a.commit)}`), "the record's own commit");
  assert.ok(anchored.includes(`names the head <a ${commitLink(a.head)}`), "the head of the pins repository it names");

  gh.forceGetFailure(PINS, latest, 1, 503);
  const cnl = (await casePage(id)).html;
  assert.match(cnl, /could_not_look: its pin could not be read on this request \(pin_pointer_unreadable\), so nothing is claimed about its pin or its anchor/);
  assert.ok(!cnl.includes("pinned at commit"));
  assert.ok(!cnl.includes("anchored: a daily"));
});

test("THE NOTE: a case is pinned by the commit that writes its pin and anchored only by a daily anchor record, named with that record's commit", () => {
  assert.match(S.ANCHOR_NOTE, /^A case is pinned by the pins-repository commit that writes its pin, and anchored only when a daily anchor record names a head of the pins repository that holds that pin; the record's own commit is named beside the word\./);
  assert.match(S.ANCHOR_NOTE, /not as a log-tree leaf/);
  assert.ok(!/is anchored by the pins-repository commit/.test(S.ANCHOR_NOTE), "a commit alone never anchors");
});
