// test/case_rj2.test.js — unit R-J2 (2026-10-13): fixes from the second
// reader's pass over R-J at 64e6abf.
//   B2  the signed row sentence said the row is "listed by the case's next
//       pin", a future event stated as fact: version 3 claims only what the
//       row's commit records, and version 2 was never issued;
//   B1  every conflict was said to "hold another chain": worded by reason;
//   M1  a commit the host does not show yet read as off the branch;
//   M2  the page cache re-served "on this request" for sixty seconds;
//   n1-n8 the minor findings.
// The setup below is test/case_rj.test.js's (its header there).
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rj2");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rj2");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rj2");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0071" });
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

const fs = require("node:fs");
const path = require("node:path");
const utc = (ms) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.000Z$/, "Z");
const PAGE_SRC = () => fs.readFileSync(path.join(__dirname, "..", "lib", "_case_page.js"), "utf8");

// =============================================================================
// B2: the signed row sentence, version 3
// =============================================================================

const V3_NOTE = "This row has no pin of its own. It is recorded by the pins-repository commit that writes it. A later pin of the case may list " +
  "that commit. This row is anchored only if a pin that lists it is, and no anchoring is asserted here.";
const V2_NOTE = "This row has no pin of its own. It is recorded by the pins-repository commit that writes it and listed by the case's next " +
  "pin; it is anchored only when that pin is.";
const ROW_COMMIT_NOTE = "row_commit is the commit the pins repository assigned to this row's write (null when that write's answer named none). " +
  "The row cannot name it itself. A later pin of the case may list that commit; the case page says a pin lists it only after reading that pin.";

test("B2: the signed row carries the version-3 sentence and note_version 3, exactly; the 201 body's row_commit_note agrees; the README records version 2 as never issued", async () => {
  assert.equal(C.REFERENCE_ANCHOR_NOTE, V3_NOTE);
  assert.equal(C.REFERENCE_NOTE_VERSION, 3);
  const c = await sealedCase("RJ2 B2 row");
  const r = await reference(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  const stored = gh.read(PINS, rowPath(c.id, 1));
  assert.deepEqual([stored.anchor_note, stored.note_version], [V3_NOTE, 3]);
  assert.equal(S.publishedSignatureReason(stored, DOC), null, "the sentence is under the signature");
  assert.deepEqual([r.body.anchor_note, r.body.row_commit_note], [V3_NOTE, ROW_COMMIT_NOTE]);
  const readme = fs.readFileSync(path.join(__dirname, "..", "README.md"), "utf8").replace(/\s+/g, " ");
  assert.ok(readme.includes(V3_NOTE), "the README quotes the sentence");
  assert.ok(readme.includes("Version 2 of this sentence was never issued"));
});

test("B2: a row carrying version 2, or no version, reads as its own reason (row_note_v2, row_note_v1) and is not counted; the v1 reason names what the row lacks", async () => {
  const { id } = await sealedCase("RJ2 B2 versions");
  const signer = S.loadCaseSigner(KEYS, { keyDocument: DOC });
  const good = S.referenceRow({ caseId: id, seq: 1, crossReference: XREF, recordedAt: "2026-10-10T10:00:00Z", appendedBy: "operator" }, signer);
  const v2 = { ...good, note_version: 2, anchor_note: V2_NOTE };
  const { note_version: _n, ...none } = good;
  const v1 = C.validateReferenceRow(none);
  assert.equal(v1.code, "row_note_v1");
  assert.match(v1.error, /no note_version/);
  assert.doesNotMatch(v1.error, /first/);
  assert.equal(C.validateReferenceRow(v2).code, "row_note_v2");
  for (const [row, reason] of [[v2, "row_note_v2"], [none, "row_note_v1"]]) {
    gh.seed(PINS, rowPath(id, 1), row);
    const live = await S.liveRecords(storedCase(id), { keyDocument: DOC });
    assert.deepEqual([live.records, live.invalid], [1, [{ seq: 1, reason }]], reason);
  }
  gh.seed(PINS, rowPath(id, 1), good);
  assert.equal((await S.liveRecords(storedCase(id), { keyDocument: DOC })).records, 2, "control: version 3 counts");
});

test("B2, n1: beside a case that reads anchored, a listed row says recorded by commit X and listed by pin N (read when this page was read), its anchor state not computed, never 'anchored'; its link is the row at its commit", async () => {
  const c = await sealedCase("RJ2 B2 page");
  assert.equal((await reference(c)).status, 201);
  await sealerRun();
  dailyAnchor(pinDay(c.id));
  const html = (await casePage(c.id)).html;
  assert.match(html, /anchored: a daily anchor record/, "fixture: the case reads anchored");
  const line = rowLine(html, 1);
  const rc = rowCommit(c.id, 1);
  assert.ok(line.includes(`recorded by commit <a ${commitLink(rc)}`), line);
  assert.ok(line.includes("listed by pin 2, read when this page was read"), line);
  assert.ok(line.includes("anchor state: not computed"), line);
  assert.doesNotMatch(line, /anchored/);
  assert.ok(line.includes(`href="${PINS_URL}/blob/${rc}/${rowPath(c.id, 1)}"`), "n1: the row at its commit");
  // a row no pin lists yet: no future event stated as fact
  const c2 = await sealedCase("RJ2 B2 unlisted");
  assert.equal((await reference(c2)).status, 201);
  const unlisted = rowLine((await casePage(c2.id)).html, 1);
  assert.ok(unlisted.includes("commit_unrecorded: no pin of this case read when this page was read lists the commit that wrote this row"), unlisted);
  assert.doesNotMatch(unlisted, /next pin|anchored/);
  assert.ok(unlisted.includes(`href="${PINS_URL}/blob/${store.BRANCH}/${rowPath(c2.id, 1)}"`), "n1: the branch's row while it is not recorded");
});

// =============================================================================
// B1: a conflict is worded by its reason
// =============================================================================

const CONFLICT_WORDS = {
  pointer_holds_another_chain: "the pin pointer under this case's namespace holds another chain",
  pin_at_its_commit_holds_another_chain: "the pin record, read at the commit that wrote it, holds another chain",
  anchored_head_holds_another_chain: "the head a daily anchor record names holds another chain for this case's pin",
  anchored_head_off_branch: "a daily anchor record names a head that is not on the published branch of the pins repository",
  anchored_head_not_json: "the pin record at the head a daily anchor record names could not be read as a pin",
  pin_at_its_commit_not_json: "the pin record at the commit that wrote it could not be read as a pin",
};
// A sealed case whose numbered pin record held `content` at a commit a daily
// anchor record names, then put back.
async function anchoredAt(scope, content) {
  const c = await sealedCase(scope);
  const p = S.pinPaths(c.id).seq;
  const good = gh._repoMap(PINS).get(p).content;
  gh._repoMap(PINS).get(p).content = content;
  const head = gh.addCommit(PINS, p, "mock: the numbered pin record rewritten");
  const a = dailyAnchor(pinDay(c.id), head);
  gh._repoMap(PINS).get(p).content = good;
  gh.addCommit(PINS, p, "mock: put back");
  return { c, head, a };
}

test("B1: the page and the 409 anchor_conflict say 'holds another chain' only for the three *_holds_another_chain reasons; an off-branch head and a record that is not a pin are said as what they are", async () => {
  // each fixture is checked before the next is made (a day has one daily anchor record)
  const fixtures = {
    pointer_holds_another_chain: async () => {
      const c = await sealedCase("RJ2 B1 pointer");
      const latest = S.pinPaths(c.id).latest;
      gh.seed(PINS, latest, { ...gh.read(PINS, latest), chain: sha("another chain") });
      return c;
    },
    pin_at_its_commit_holds_another_chain: async () => {
      const c = await sealedCase("RJ2 B1 at its commit");
      const seq = S.pinPaths(c.id).seq;
      const mine = gh.read(PINS, seq);
      gh.seed(PINS, seq, { ...mine, chain: sha("yet another chain") });
      gh._repoMap(PINS).get(seq).content = JSON.stringify(mine, null, 2) + "\n";
      gh.addCommit(PINS, seq, "mock: put back");
      return c;
    },
    pin_at_its_commit_not_json: async () => {
      const c = await sealedCase("RJ2 B1 at its commit, text");
      gh.commitsFor(PINS, S.pinPaths(c.id).seq).slice(-1)[0].content = "not json\n";
      return c;
    },
    anchored_head_holds_another_chain: async () => {
      const c = await sealedCase("RJ2 B1 head chain");
      const p = S.pinPaths(c.id).seq;
      const mine = gh.read(PINS, p);
      const good = gh._repoMap(PINS).get(p).content;
      gh._repoMap(PINS).get(p).content = JSON.stringify({ ...mine, chain: sha("a chain at the head") }, null, 2) + "\n";
      const head = gh.addCommit(PINS, p, "mock: the numbered pin record rewritten");
      dailyAnchor(pinDay(c.id), head);
      gh._repoMap(PINS).get(p).content = good;
      gh.addCommit(PINS, p, "mock: put back");
      return c;
    },
    anchored_head_not_json: async () => (await anchoredAt("RJ2 B1 head text", "not json\n")).c,
    anchored_head_off_branch: async () => {
      const c = await sealedCase("RJ2 B1 head off branch");
      const p = S.pinPaths(c.id).seq;
      const side = gh.seedSideCommit(PINS, crypto.createHash("sha1").update("rj2 side head").digest("hex"));
      gh.seedRaw(PINS, side, p, gh._repoMap(PINS).get(p).content);
      dailyAnchor(pinDay(c.id), side);
      return c;
    },
  };
  for (const [reason, make] of Object.entries(fixtures)) {
    const c = await make();
    S._internal.clearCommitFiles();
    const st = await S.anchorState(c.id, storedCase(c.id));
    assert.deepEqual([st.pin, st.reason], ["conflict", reason], reason);
    const html = (await casePage(c.id)).html;
    assert.ok(html.includes(`conflict: ${esc(CONFLICT_WORDS[reason])} (${reason}).`), `${reason}: ${html.slice(html.indexOf("conflict:"), html.indexOf("conflict:") + 200)}`);
    if (!reason.endsWith("_holds_another_chain")) assert.doesNotMatch(html, /holds another chain/, reason);
    if (reason.startsWith("anchored_head_")) {
      const r = await reference(c);
      assert.deepEqual([r.status, r.body.error_code, r.body.reason], [409, "anchor_conflict", reason]);
      assert.ok(r.body.error.startsWith(`the case's pin holds its chain, and ${CONFLICT_WORDS[reason]} (`), `${reason}: ${r.body.error}`);
      if (reason !== "anchored_head_holds_another_chain") assert.doesNotMatch(r.body.error, /holds another chain/);
    }
  }
});
const esc = (s) => CP._internal.esc(s);

// =============================================================================
// M1: a commit the host does not show yet is could_not_look
// =============================================================================

test("M1: a case_commit or an anchor head the host does not show yet (a compare 404 on a branch that exists) is could_not_look, never a mismatch or an anchor conflict", async () => {
  const { id } = await sealedCase("RJ2 M1 case");
  const fresh = crypto.createHash("sha1").update("rj2 not shown case").digest("hex");
  gh.seedRaw(PINS, fresh, C.casePath(id), caseText(id));
  plantPin(id, chainOf(id), fresh);
  assert.deepEqual(await S.anchorState(id, storedCase(id)), { pin: "could_not_look", reason: "case_commit_not_shown" });
  const { id: id2 } = await sealedCase("RJ2 M1 head");
  const p = S.pinPaths(id2).seq;
  const freshHead = crypto.createHash("sha1").update("rj2 not shown head").digest("hex");
  gh.seedRaw(PINS, freshHead, p, gh._repoMap(PINS).get(p).content);
  dailyAnchor(pinDay(id2), freshHead);
  const st = await S.anchorState(id2, storedCase(id2));
  assert.deepEqual([st.pin, st.anchor], ["pinned", { could_not_look: "anchor_head_not_shown" }]);
});

// =============================================================================
// M2: the page cache keeps only a definite page, says when it was read, and
// never outlives the deadline or a changed root
// =============================================================================

test("M2: a page that could not look at something is not cached; a cached page prints its read time; 'on this request' is 'when this page was read'", async () => {
  const { id } = await sealedCase("RJ2 M2 cnl");
  const t0 = REVEAL_AT + 3600000;
  gh.forceGetFailure(PINS, "anchors", 1, 503);
  const first = await casePage(id, { now: t0 });
  assert.match(first.html, /could not be read when this page was read/);
  const r1 = reads();
  await casePage(id, { now: t0 + 1000, cached: true });
  assert.ok(reads() - r1 > 1, "read afresh, not only the root");
  // a definite page is kept and says when it was read
  const { id: id2 } = await sealedCase("RJ2 M2 kept");
  const page1 = await casePage(id2, { now: t0 });
  assert.ok(page1.html.includes(`read at ${utc(t0)}`));
  const r2 = reads();
  const page2 = await casePage(id2, { now: t0 + 30000, cached: true });
  assert.equal(reads() - r2, 1, "only the root is read");
  assert.ok(page2.html.includes(`read at ${utc(t0)}`), "the cached page keeps its read time");
  assert.doesNotMatch(PAGE_SRC(), /on this request/);
});

test("M2: a cached entry for an unsealed case does not outlive its deadline; a root that changed is never answered from the cache", async () => {
  const c = await committedCase("RJ2 M2 deadline");
  const dl = Date.parse(DEADLINE);
  const before = await casePage(c.id, { now: dl - 30000 });
  assert.match(before.html, /Case: COMMITTED/);
  const after = await casePage(c.id, { now: dl + 1000, cached: true });
  assert.match(after.html, /Case: EXPIRED/, "the entry stops at the deadline");
  // a COMMITTED page cached, then the case sealed: the root's change is seen
  const d = await committedCase("RJ2 M2 root");
  const t = REVEAL_AT - 10000;
  assert.match((await casePage(d.id, { now: t })).html, /Case: COMMITTED/);
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", revealBody(d.id, d.a, d.b)), res, { now: REVEAL_AT, env: KD.deployed(gh, KEYS, DOC), keyDocument: DOC });
  assert.equal(res._status, 201);
  assert.match((await casePage(d.id, { now: t + 20000, cached: true })).html, /Case: VERDICT/);
});

// =============================================================================
// MINORS
// =============================================================================

test("n2: the sealer's row read-back holds the row to its commit by the readers' routine: a row the raw host does not serve at its commit is pin_commit_mismatch (reference_absent_at_commit), not listed", async () => {
  const c = await sealedCase("RJ2 n2");
  assert.equal((await reference(c)).status, 201);
  gh.forceRawFailure(1, 404, `:${rowPath(c.id, 1)}`);
  const run = await sealerRun();
  assert.deepEqual(run.rows_unrecorded, [{ case_id: c.id, seq: 1, code: "pin_commit_mismatch", reason: "reference_absent_at_commit" }]);
});

test("n3: the general anchor sentence is printed only beside a case that reads pinned or anchored; otherwise the page says what was read", async () => {
  const { id } = await sealedCase("RJ2 n3 pinned");
  assert.ok((await casePage(id)).html.includes(CP._internal.esc(S.ANCHOR_NOTE)));
  const p = await sealedCase("RJ2 n3 unrecorded", { pinFails: true });
  const html = (await casePage(p.id)).html;
  assert.ok(!html.includes("It is pinned and anchored as its own record"));
  assert.ok(html.includes("This page read this case&#39;s pin as commit_unrecorded (not_pinned) and claims nothing more about its pin or its anchor."), html.slice(-1500));
});

test("n4: the preview tool says the anchor's proof is not checked by it", () => {
  assert.ok(fs.readFileSync(path.join(__dirname, "..", "tools", "preview_dry_run.js"), "utf8").includes("(the anchor's proof is not checked by this tool)"));
});

test("n5: given a chain the case served does not have, anchorState answers pin_commit_mismatch before reading the case at the commit", async () => {
  const { id } = await sealedCase("RJ2 n5");
  const other = sha("a chain this case does not have");
  plantPin(id, other, sealCommit(id));
  const r0 = gh.rawLog.length;
  assert.deepEqual(await S.anchorState(id, other).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_served_differs"]);
  assert.ok(!gh.rawLog.slice(r0).some((k) => k.endsWith(`:${C.casePath(id)}`)), "the case file was not read at the commit");
});

test("n6, n7: the page says 'in canonical form (json-c14n:v1)', never 'byte for byte'; a commit off the branch, or one the repository does not have, is not called 'that commit of the pins repository's branch'", async () => {
  assert.doesNotMatch(PAGE_SRC(), /byte for byte/);
  const early = gh.seedText(PINS, "notes/rj2-before.txt", "x\n");
  const { id } = await sealedCase("RJ2 n7");
  // differs: the case file as opened
  plantPin(id, chainOf(id), gh.commitsFor(PINS, C.casePath(id)).slice(-1)[0].sha);
  assert.ok((await casePage(id)).html.includes("the case file at that commit is not this case file in canonical form (json-c14n:v1) (case_at_commit_differs)"));
  for (const [commit, words, reason] of [
    ["f".repeat(40), "the pins repository does not show that commit", "case_commit_not_found"], // unit R-J3 (F2)
    [early, "the pins repository holds no case file at that commit", "case_absent_at_commit"],
  ]) {
    plantPin(id, chainOf(id), commit);
    const html = (await casePage(id)).html;
    assert.ok(html.includes(`${words} (${reason})`), reason);
    assert.doesNotMatch(html, /that commit of the pins repository&#39;s branch|that commit of the pins repository's branch/, reason);
  }
  const side = gh.seedSideCommit(PINS, crypto.createHash("sha1").update("rj2 n7 side").digest("hex"));
  gh.seedRaw(PINS, side, C.casePath(id), caseText(id));
  plantPin(id, chainOf(id), side);
  const off = (await casePage(id)).html;
  assert.ok(off.includes("that commit is not on the published branch of the pins repository (case_commit_off_branch)"));
});

// =============================================================================
// MUST-FAIL GAP (unit R-J2): the mutants the pass over the lines R-J2 changed
// left alive, each caught here
// =============================================================================

// Two views a few seconds apart: whether the second was made afresh (it
// says it was read at its own time) rather than answered from the cache.
async function readAgain(id, t0) {
  await casePage(id, { now: t0 });
  const second = await casePage(id, { now: t0 + 5000, cached: true });
  return { again: second.html.includes(`read at ${utc(t0 + 5000)}`), html: second.html };
}

test("MUST-FAIL GAP (S04): the sealer's row read-back that cannot read the row at its commit is could_not_look, never a mismatch", async () => {
  const c = await sealedCase("RJ2 gap sealer row read");
  assert.equal((await reference(c)).status, 201);
  gh.forceRawFailure(1, 503, `:${rowPath(c.id, 1)}`);
  const run = await sealerRun();
  assert.deepEqual(run.rows_unrecorded, [{ case_id: c.id, seq: 1, code: "could_not_look", reason: "reference_at_commit_http_503" }]);
});

test("MUST-FAIL GAP (S07): n5's mismatch names the commit the pin names", async () => {
  const { id } = await sealedCase("RJ2 gap n5 commit");
  plantPin(id, sha("another chain"), sealCommit(id));
  const st = await S.anchorState(id, sha("another chain"));
  assert.deepEqual([st.pin, st.reason, st.case_commit], ["pin_commit_mismatch", "case_served_differs", sealCommit(id)]);
});

test("MUST-FAIL GAP (S12, P06): a reason the words do not know claims no chain and no bytes", () => {
  assert.equal(S.conflictWords("some_other_reason"), "a pin under this case's namespace is in conflict with this case");
  assert.equal(CP._internal.mismatchWords("case_served_differs", "case file"), "the case file there is not shown to be this case file in canonical form (json-c14n:v1)");
});

test("MUST-FAIL GAP (P16): a page whose case reads anchored prints the general anchor sentence", async () => {
  const { id } = await sealedCase("RJ2 gap anchored note");
  dailyAnchor(pinDay(id));
  const html = (await casePage(id)).html;
  assert.match(html, /anchored: a daily anchor record/, "fixture: anchored");
  assert.ok(html.includes(CP._internal.esc(S.ANCHOR_NOTE)));
});

test("MUST-FAIL GAP (P18, P19, P21, P22, P23, P30): a page is not kept when its pin could not be read or mismatches, when its rows could not be read, when a row could not be read or mismatches, or when it does not verify", async () => {
  const t0 = REVEAL_AT + 3600000;
  // the pin pointer could not be read
  const a = await sealedCase("RJ2 gap pin cnl");
  gh.forceGetFailure(PINS, S.pinPaths(a.id).latest, 1, 503);
  assert.equal((await readAgain(a.id, t0)).again, true, "pin could_not_look");
  // a mismatch
  const b = await sealedCase("RJ2 gap pin mismatch");
  plantPin(b.id, chainOf(b.id), "f".repeat(40));
  assert.equal((await readAgain(b.id, t0)).again, true, "pin_commit_mismatch");
  // the reference rows could not be listed
  const c = await sealedCase("RJ2 gap rows cnl");
  assert.equal((await reference(c)).status, 201);
  gh.forceGetFailure(PINS, C.referencesDir(c.id), 1, 503);
  assert.equal((await readAgain(c.id, t0)).again, true, "rows could not be read");
  // a row's commit could not be read, and a row's commit that mismatches
  const d = await sealedCase("RJ2 gap row cnl");
  assert.equal((await reference(d)).status, 201);
  await sealerRun();
  S._internal.clearCommitFiles();
  gh.forceRawFailure(1, 503, `:${rowPath(d.id, 1)}`);
  const dv = await readAgain(d.id, t0);
  assert.match(rowLine(dv.html, 1), /recorded by commit/, "fixture: read again, and this time recorded");
  assert.equal(dv.again, true, "a row could_not_look");
  const e = await sealedCase("RJ2 gap row mismatch");
  assert.equal((await reference(e)).status, 201);
  await sealerRun();
  const latest = S.pinPaths(e.id).latest;
  gh.seed(PINS, latest, { ...gh.read(PINS, latest), reference_commits: [{ seq: 1, commit: "e".repeat(40) }] });
  assert.equal((await readAgain(e.id, t0)).again, true, "a row pin_commit_mismatch");
  // a page that does not verify
  const f = await sealedCase("RJ2 gap unverified");
  const k = storedCase(f.id);
  gh.seed(PINS, C.casePath(f.id), { ...k, sig: k.sig.replace(/.$/, (ch) => (ch === "A" ? "B" : "A")) }, { keepHistory: true });
  const fv = await readAgain(f.id, t0);
  assert.match(fv.html, /does not verify|DOES NOT VERIFY|not verify/i, "fixture: the page does not verify");
  assert.equal(fv.again, true, "an unverified page");
});

test("MUST-FAIL GAP (P25, P32): a sealed page viewed after the deadline is kept, and so is a withdrawn page", async () => {
  const dl = Date.parse(DEADLINE);
  const { id } = await sealedCase("RJ2 gap sealed late");
  assert.equal((await readAgain(id, dl + 3600000)).again, false, "a VERDICT page is not held to the deadline");
  const w = await committedCase("RJ2 gap withdrawn kept");
  const res = makeRes();
  await H.handleCaseWithdraw(req("case-withdraw", { case_id: w.id, role: "b", tape_sha256: w.b.tape_sha256, salt: w.b.salt }), res, { now: NOW + 2000, env: KEYS, keyDocument: DOC });
  assert.equal(res._status, 201, JSON.stringify(res._body).slice(0, 200));
  const wv = await readAgain(w.id, REVEAL_AT);
  assert.match(wv.html, /WITHDRAWN/);
  assert.equal(wv.again, false, "a withdrawn page is kept");
});

test("MUST-FAIL GAP (P31): a single-party page of an unsealed case is kept no later than its deadline", async () => {
  const c = await committedCase("RJ2 gap single party");
  const k = storedCase(c.id);
  gh.seed(PINS, C.casePath(c.id), { ...k, commitments: { ...k.commitments, b: { ...k.commitments.b, key_id: k.commitments.a.key_id } } }, { keepHistory: true });
  assert.equal(C.singleParty(storedCase(c.id)), true, "fixture: one key id in both commitments");
  const dl = Date.parse(DEADLINE);
  const before = await casePage(c.id, { now: dl - 2000 });
  assert.equal(before.status, 200, before.html.slice(0, 200));
  assert.doesNotMatch(before.html, /past its deadline/);
  const after = await casePage(c.id, { now: dl + 1000, cached: true });
  assert.match(after.html, /past its deadline/);
});
