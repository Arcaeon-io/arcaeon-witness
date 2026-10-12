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

test("THE VERIFIER NEVER TRUSTS case_commit AS AN ID: a pin naming a commit at which the case file is not the case its chain names is pin_commit_mismatch, never pinned and never anchored; a commit it cannot read it at is could_not_look", async () => {
  const { id } = await sealedCase("J mismatch");
  const chain = chainOf(id);
  const opened = gh.commitsFor(PINS, C.casePath(id)).slice(-1)[0].sha; // the case file as opened, not as sealed
  plantPin(id, chain, opened);
  const a = dailyAnchor(dayOf(Date.now() + DAY));
  const st = await S.anchorState(id, chain);
  assert.equal(st.pin, "pin_commit_mismatch");
  assert.equal(st.reason, "case_at_commit_is_another_case");
  assert.equal(st.case_commit, opened);
  assert.ok(gh.rawLog.includes(`${PINS}@${opened}:${C.casePath(id)}`), "it read the case file at the commit the pin names");
  assert.ok(!gh.rawLog.some((k) => k.startsWith(`${PINS}@${a.head}:`)), "and looked no further: never anchored");
  const page = (await casePage(id)).html;
  assert.match(page, /pin_commit_mismatch: its pin names commit <a [^>]+>[0-9a-f]{12}<\/a> for the case file, and the case file at that commit is not the case whose chain the pin holds\. Never pinned, never anchored\./);
  assert.ok(!page.includes("pinned at commit"));
  // a commit the raw host does not serve the file at: no claim
  S._internal.clearCommitFiles();
  plantPin(id, chain, "f".repeat(40));
  assert.deepEqual(await S.anchorState(id, chain), { pin: "could_not_look", reason: "case_at_commit_http_404" });
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
  const c = await committedCase("J crash answer");
  gh.dropCommitFromAnswer(PINS, C.casePath(c.id), 1);
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
  assert.deepEqual(run.refused, [{ case_id: id, code: "pin_commit_mismatch", reason: "case_at_commit_is_another_case" }]);
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
  assert.deepEqual(again.refused, [{ case_id: id, code: "pin_commit_mismatch", reason: "case_at_commit_is_another_case" }]);
});
