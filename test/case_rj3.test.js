// test/case_rj3.test.js — unit R-J3 (2026-10-13): the last words on the
// case page's pin and anchor cells. The rule: every cell on the case page,
// and every refusal about a pin, anchor, commit or row, says only what was
// read, by state and reason; no cell states the absence of something read
// as present, and no reason names a cause the code did not establish.
//   THE TABLE  every (state, reason) pair anchorState, dailyAnchorOf,
//              servedAtCommit and the row reader can return, with the
//              sentence each cell and the reference's answer says for it;
//   BL1  the pin cell said "no pin of this case's chain" where the pin was
//        read and holds the chain;
//   BL2  *_holds_another_chain was said of any record that is not this
//        case's pin, also one that is not a pin record or has another seq;
//   F1-F9 the follow-ups.
// The setup below is test/case_rj2.test.js's.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0111:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rj3");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rj3");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rj3");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0111" });
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
async function casePage(id, { now = REVEAL_AT + 3600000, cached = false, ip = null, keyDocument = DOC } = {}) {
  if (!cached) CP._internal.clearPageCache();
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": ip || `10.98.0.${(ipSeq += 1) & 255}` } }), res,
    { now, keyDocument, env: {} });
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
// A daily anchor record whose listing serves a head, and whose newest
// commit names none (unit R-L2).
function noHead(c) {
  const a = dailyAnchor(pinDay(c.id));
  gh.seedText(PINS, a.path, "no head here\n");
  gh._repoMap(PINS).get(a.path).content = `${a.head} ${a.claimedAt}\n`;
  return a;
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
async function reference(c, role = "a", ref = "row", keyDocument = DOC) {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: { ...XREF, reference: ref } }),
    res, { now: REVEAL_AT + 1800000, env: KEYS, keyDocument });
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

const HTTP_SRC = () => fs.readFileSync(path.join(__dirname, "..", "lib", "_case_http.js"), "utf8");
const s12 = (x) => String(x).slice(0, 12);
const fresh = () => crypto.randomBytes(20).toString("hex");
const json = (o) => JSON.stringify(o, null, 2) + "\n";
const latestOf = (id) => S.pinPaths(id).latest;
const seqOf = (id) => S.pinPaths(id).seq;
const esc = (s) => CP._internal.esc(s);

// A cell's text, its tags dropped and its entities read back.
function plain(h) {
  return String(h).replace(/<[^>]+>/g, "").replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&").trim();
}
// The page's cells: pin, anchor and case commit, the note under them, and
// the commit cell of reference row 1.
function pageCells(html) {
  const cell = (name) => {
    const m = new RegExp(`<tr><th>${name}</th><td>([\\s\\S]*?)</td></tr>`).exec(html);
    assert.ok(m, `the page has a ${name} cell: ${html.slice(0, 300)}`);
    return plain(m[1]);
  };
  const at = html.indexOf("<h2>Anchor and signature</h2>");
  assert.ok(at >= 0, "the page has its anchor panel");
  const n = html.indexOf('<p class="muted">', html.indexOf("</table>", at));
  const line = rowLine(html, 1);
  return {
    pin: cell("pin"), anchor: cell("anchor"), caseCommit: cell("case commit"),
    note: plain(html.slice(n, html.indexOf("</p>", n))),
    row: plain(line.slice(line.lastIndexOf('<span class="muted">'))),
  };
}
// The same cells from the page's own functions, for an answer the page never
// reads (chain mode, or no anchor lookup).
function stateCells(st, rowState) {
  const k = CP._internal.cells;
  return { pin: plain(k.pin(st)), anchor: plain(k.anchor(st)), caseCommit: plain(k.caseCommit(st)), note: k.note(st), row: plain(k.row(rowState)) };
}
function fill(t, x) {
  return t.replace(/\{(\w+)\}/g, (_, k) => {
    assert.ok(x[k] !== undefined && x[k] !== null, `the table names {${k}}, and the fixture gives it`);
    return String(x[k]);
  });
}

// =============================================================================
// THE TABLE. Every (state, reason) pair anchorState, dailyAnchorOf,
// servedAtCommit and the row reader (referenceCommitStates, with the walk
// down the pins) can return, with what each cell of the case page says for
// it (the pin cell, the anchor cell, the case-commit cell, the note under
// them, and the row's commit cell) and the reference's answer. A sentence is
// the cell's text with its tags dropped; {name} is filled from the fixture.
// Each row is a test below, against a fixture that makes the pair.
// =============================================================================

// What a pin_commit_mismatch reason says (lib/_case_page.js mismatchWords).
const MISMATCH = {
  differs: (f) => `the ${f} at that commit is not this ${f} in canonical form (json-c14n:v1)`,
  absent: (f) => `the pins repository holds no ${f} at that commit`,
  not_found: "that commit is not shown by the repository", // unit R-L (g4): one wording, and "yet" only for could_not_look
  off_branch: "that commit is not on the published branch of the pins repository",
  other: (f) => `the ${f} there is not shown to be this ${f} in canonical form (json-c14n:v1)`,
};
// What a could_not_look reason says, of the pin, the case file or a row.
const CNL = {
  pin_commit: "the commit that wrote its pin record could not be read when this page was read",
  // unit R-L (g5): no read failed
  pin_commits_beyond_bound: "the pin's commit history is longer than this service reads",
  pin_commits_none: "the repository lists no commit for the pin",
  pin_at_commit: "its pin record could not be read at the commit that wrote it when this page was read",
  not_shown: "the commit it names is not shown by the repository yet",
  at_commit: (f) => `the ${f} at the commit it names could not be read when this page was read`,
  exists: "whether the pins repository has the commit it names could not be read when this page was read",
  on_branch: "whether the commit it names is on the published branch of the pins repository could not be read when this page was read",
  file: (f) => `the ${f} could not be read when this page was read`,
};
// What a conflict's reason says (lib/_case_seal.js conflictWords; BL2 adds
// the two *_not_a_pin reasons).
const CONFLICT_WORDS = {
  pointer_holds_another_chain: "the pin pointer under this case's namespace holds another chain",
  pin_at_its_commit_holds_another_chain: "the pin record, read at the commit that wrote it, holds another chain",
  pin_at_its_commit_not_a_pin: "the record at this case's pin path, read at the commit that wrote it, is not a pin record for this case",
  anchored_head_holds_another_chain: "the head a daily anchor record names holds another chain for this case's pin",
  anchored_head_not_a_pin: "the record at this case's pin path, at the head a daily anchor record names, is not a pin record for this case",
  anchored_head_off_branch: "a daily anchor record names a head that is not on the published branch of the pins repository",
  anchored_head_not_json: "the pin record at the head a daily anchor record names could not be read as a pin",
  pin_at_its_commit_not_json: "the pin record at the commit that wrote it could not be read as a pin",
};

const T = {
  // the pin cell (BL1)
  PIN_PINNED: "pinned at commit {pin_commit}, {pin_date} (the pins repository's commit time)",
  PIN_HELD: "a pin of this case's chain was read; the case is not shown as pinned or anchored ({reason})",
  PIN_NONE: "not pinned yet: no pin pointer is present under this case's namespace (not_pinned)",
  PIN_OTHER: "no pin of this case's chain: the pin pointer under this case's namespace holds another chain (pointer_holds_another_chain)",
  PIN_UNREADABLE: "a record is present at this case's pin pointer and cannot be read as a case seal record ({reason})",
  PIN_POINTER_CNL: "not known when this page was read: the pin pointer could not be read (pin_pointer_unreadable)",
  // the anchor cell (F1, F2, F6)
  ANCHORED: "anchored: a daily anchor record in this repository names a head that holds this pin; this page does not check the OpenTimestamps " +
    "proof. The record {record}, written at commit {record_commit}, names the head {head} of the pins repository, and the pin read at that " +
    "head holds this case's chain.",
  NOT_YET: "pinned, not anchored yet: no daily anchor record held its pin when this page was read. The operator's daily job records the pins " +
    "repository's head; once a record names a head that holds this pin, the case reads anchored.",
  NOT_LOOKED_UP: "pinned; no daily anchor record was read for this answer, so no anchor is claimed.",
  ANCHOR_CNL: "pinned; whether a daily anchor record holds its pin could not be read when this page was read (could_not_look: {reason}), so no " +
    "anchor is claimed.",
  // unit R-L (g2): it names the head
  HEAD_NOT_SHOWN: "pinned; a daily anchor record names the head {head_full}, which is not shown by the repository yet (could_not_look: " +
    "anchor_head_not_shown), so no anchor is claimed.",
  // unit R-L (g1, g7): what was read of the record
  RECORD_CHANGED: "pinned (could_not_look: anchor_record_changed); a daily anchor record for this case was read and named a different head " +
    "at its newest commit, so no anchor is claimed.",
  // unit R-L2 (a minor): a record whose newest commit names no head
  RECORD_NO_HEAD: "pinned (could_not_look: anchor_record_names_no_head); a daily anchor record for this case was read at its newest commit " +
    "and no longer names a head, so no anchor is claimed.",
  RECORD_COMMIT_CNL: "pinned; the commit that wrote a daily anchor record could not be read when this page was read (could_not_look: " +
    "{reason}), so no anchor is claimed.",
  RECORD_AT_COMMIT_CNL: "pinned; a daily anchor record could not be read at its own commit when this page was read (could_not_look: " +
    "{reason}), so no anchor is claimed.",
  RECORD_COMMITS_BEYOND: "pinned; a daily anchor record's commit history is longer than this service reads (could_not_look: " +
    "anchor_record_commits_beyond_bound), so no anchor is claimed.",
  RECORD_COMMITS_NONE: "pinned; the repository lists no commit for a daily anchor record (could_not_look: anchor_record_commits_none), so " +
    "no anchor is claimed.",
  A_NOT_PINNED: "commit_unrecorded: the case is sealed and not yet pinned (not_pinned), so it is not shown as pinned or anchored. A later " +
    "sealer run may pin it.",
  A_NO_CASE_COMMIT: "commit_unrecorded: its pin names no commit for the case file, so the case is not shown as pinned or anchored. A later " +
    "sealer run may record that commit in a next pin of the case.",
  A_MISMATCH: "pin_commit_mismatch: its pin names commit {case_commit} for the case file, and {words} ({reason}), so the case is not shown as " +
    "pinned or anchored.",
  A_POINTER_CNL: "could_not_look: its pin pointer could not be read when this page was read (pin_pointer_unreadable), so nothing is claimed " +
    "about its pin or its anchor.",
  A_HELD_CNL: "could_not_look: a pin of this case's chain was read, and {words} ({reason}), so the case is not shown as pinned or anchored.",
  A_CONFLICT: "conflict: {words} ({reason}). This service never writes over a pin; the case file is the authority.",
  A_UNREADABLE: "unreadable: a record is present at this case's pin pointer and cannot be read as a case seal record ({reason}).",
  // the case-commit cell (F9)
  CC_PINNED: "written at commit {case_commit} (named by its pin, and the case file read at that commit is this case)",
  CC_NOT_PINNED: "commit_unrecorded: no pin pointer is present to name it (not_pinned)",
  CC_NO_CASE_COMMIT: "commit_unrecorded: its pin names none (no_case_commit)",
  CC_MISMATCH: "not shown: its pin names {case_commit}, and {words} ({reason})",
  CC_CNL: "not known when this page was read ({reason})",
  // unit R-L (g3): what was read
  CC_NOT_SHOWN: "its pin names {case_commit}, and the case file read at that commit is this case; whether that commit is on the published " +
    "branch is not shown by the repository yet (case_commit_not_shown)",
  CC_OTHER: "not shown: the pin pointer under this case's namespace holds another chain (pointer_holds_another_chain)",
  CC_PIN_CONFLICT: "not shown: its pin names {case_commit}, and the case file there was not read: {words} ({reason})",
  CC_HEAD_CONFLICT: "the case file read at commit {case_commit}, which its pin names, is this case; the case is not shown as pinned or " +
    "anchored ({reason})",
  CC_UNREADABLE: "not shown: a record is present at this case's pin pointer and cannot be read as a case seal record ({reason})",
  // the note under them
  NOTE_PINNED: S.ANCHOR_NOTE,
  NOTE_READ: "This page read this case's pin as {state} ({reason}) and claims nothing more about its pin or its anchor.",
  // the row's commit cell (F6)
  ROW_RECORDED: "recorded by commit {listed}; listed by pin {pin_seq}, read when this page was read; anchor state: not computed",
  ROW_UNLISTED: "commit_unrecorded: no pin of this case read when this page was read lists the commit that wrote this row; anchor state: not computed",
  ROW_MISMATCH: "pin_commit_mismatch: pin {pin_seq} names commit {listed} for this row, and {words} ({row_reason}); anchor state: not computed",
  ROW_CNL: "could_not_look: pin {pin_seq} names commit {listed} for this row, and {words} ({row_reason}); anchor state: not computed",
  ROW_WALK_CNL: "could_not_look: a pin below the pointer could not be read when this page was read (pin_unreadable); anchor state: not computed",
  ROW_WALK_ABSENT: "not read: a pin below the pointer is absent (pin_below_absent), so the pins below it were not read for this row; anchor " +
    "state: not computed",
  ROW_WALK_NOT_A_PIN: "not read: a record below the pointer is not this case's pin at its seq (pin_below_not_a_pin), so the pins below it " +
    "were not read for this row; anchor state: not computed",
  ROW_WALK_BOUND: "not read: the pins read for this page (the pointer and 20 below it) do not list the commit that wrote this row, and the " +
    "pins below them were not read (pins_not_read); anchor state: not computed",
  ROW_CASE: "not read: this case is not shown as pinned ({state}: {reason}), so no pin was read for the commit that wrote this row; anchor " +
    "state: not computed",
  // the reference's answer (F5)
  RESP_NOT_PINNED: "the case is sealed, and its pin reads {state} ({reason}); a reference row is appended only to a case that reads pinned " +
    "or anchored, so no row was written",
  RESP_CNL: "could not look; this is not a refusal of the row. Try again. The case's pin reads could_not_look on this request ({reason}), " +
    "and no row was written",
  // unit R-L (g5): a history longer than this service reads does not shorten; no "Try again"
  RESP_CNL_BEYOND: "could not look; this is not a refusal of the row. The case's pin reads could_not_look on this request " +
    "(pin_commits_beyond_bound): the pin's commit history is longer than this service reads, and no row was written",
  RESP_ANCHOR_CONFLICT: "the case's pin holds its chain, and {words} ({record}); a row is not appended to a case whose anchor conflicts; no " +
    "row was written",
};
const R201 = [201];
const NOT_PINNED_409 = [409, "case_not_pinned", T.RESP_NOT_PINNED];
const CNL_503 = [503, "could_not_look", T.RESP_CNL];
// unit R-L2 (M4): an anchor that could not be looked up, a head not shown
// and a changed record refuse no row: the row's signed sentence asserts no
// anchoring, so the reference answers 201 for each
const ANCHOR_TAKES_ROW = R201;
const CONFLICT_409 = [409, "anchor_conflict", T.RESP_ANCHOR_CONFLICT];
// The reference reads the case it serves (never a chain), with its anchor
// looked up: it never meets these answers.
const NOT_REACHED = null;

const PINNED = { pin: T.PIN_PINNED, anchor: T.NOT_YET, caseCommit: T.CC_PINNED, note: T.NOTE_PINNED, row: T.ROW_UNLISTED, response: R201 };
const HELD = (anchor, caseCommit, response, words) => ({ pin: T.PIN_HELD, anchor, caseCommit, note: T.NOTE_READ, row: T.ROW_CASE, response, words });
const ANCHOR_CNL = { ...PINNED, anchor: T.ANCHOR_CNL, response: ANCHOR_TAKES_ROW };
const HEAD_CONFLICT = (reason) => ({ ...HELD(T.A_CONFLICT, T.CC_HEAD_CONFLICT, CONFLICT_409, CONFLICT_WORDS[reason]), state: "conflict", reason });
const PIN_CONFLICT = (reason) => ({ ...HELD(T.A_CONFLICT, T.CC_PIN_CONFLICT, NOT_PINNED_409, CONFLICT_WORDS[reason]), state: "conflict", reason });

// unit R-L (g8): each reason the seal judge (lib/_verdict.js judgeCaseSeal)
// gives a pin pointer, with a pointer that makes it (the stored pointer,
// changed), below
const JUDGE_POINTERS = {
  not_a_json_object: () => [1, 2],
  case_seal_unknown_field: (p) => ({ ...p, extra: 1 }),
  case_seal_missing_field: (p) => { const { auth_note: _a, ...q } = p; return q; }, // eslint-disable-line no-unused-vars
  case_seal_wrong_record_kind: (p) => ({ ...p, record_kind: "pin" }),
  case_seal_wrong_auth_level: (p) => ({ ...p, auth_level: "bearer" }),
  case_seal_namespace_unreadable: (p) => ({ ...p, namespace: "not/a/case" }),
  namespace_mismatch: (p) => ({ ...p, namespace: `case/${"0".repeat(64)}` }),
  case_seal_wrong_rows: (p) => ({ ...p, rows: 7 }),
  case_seal_wrong_seq: (p) => ({ ...p, seq: 0 }),
  chain_unreadable: (p) => ({ ...p, chain: "not hex" }),
  case_seal_pinned_at_unreadable: (p) => ({ ...p, pinned_at: "yesterday" }),
  case_seal_auth_note_unreadable: (p) => ({ ...p, auth_note: " " }),
  case_seal_case_commit_unreadable: (p) => ({ ...p, case_commit: "C".repeat(40) }),
  case_seal_reference_commits_unreadable: (p) => ({ ...p, reference_commits: [] }),
};
const JUDGE_REASONS = Object.keys(JUDGE_POINTERS).filter((r) => r !== "case_seal_unknown_field"); // the R-J3 row has it

// pair: whose (state, reason) the row names: "case" (anchorState's pin and
// reason), "anchor" (anchorState's pin and its anchor's could_not_look), or
// "row" (row 1's, from the row reader; `case` is then the case's own pair,
// pinned unless named). In a sentence, {state} and {reason} are the case's,
// {row_reason} the row's.
const TABLE = [
  // anchorState
  { from: "anchorState", pair: "case", fx: "pinned", state: "pinned", reason: null, ...PINNED },
  { from: "anchorState", pair: "case", fx: "anchored", state: "anchored", reason: null, ...PINNED, anchor: T.ANCHORED },
  { from: "anchorState", pair: "case", fx: "not_pinned", state: "commit_unrecorded", reason: "not_pinned", pin: T.PIN_NONE, anchor: T.A_NOT_PINNED,
    caseCommit: T.CC_NOT_PINNED, note: T.NOTE_READ, row: T.ROW_UNLISTED, response: NOT_PINNED_409 },
  { from: "anchorState", pair: "case", fx: "no_case_commit", state: "commit_unrecorded", reason: "no_case_commit",
    ...HELD(T.A_NO_CASE_COMMIT, T.CC_NO_CASE_COMMIT, NOT_PINNED_409) },
  { from: "anchorState", pair: "case", fx: "unreadable", state: "unreadable", reason: "case_seal_unknown_field", pin: T.PIN_UNREADABLE,
    anchor: T.A_UNREADABLE, caseCommit: T.CC_UNREADABLE, note: T.NOTE_READ, row: T.ROW_CASE, response: NOT_PINNED_409 },
  { from: "anchorState", pair: "case", fx: "pointer_other_chain", state: "conflict", reason: "pointer_holds_another_chain", pin: T.PIN_OTHER,
    anchor: T.A_CONFLICT, caseCommit: T.CC_OTHER, note: T.NOTE_READ, row: T.ROW_CASE, response: NOT_PINNED_409,
    words: CONFLICT_WORDS.pointer_holds_another_chain },
  { from: "anchorState", pair: "case", fx: "pointer_cnl", state: "could_not_look", reason: "pin_pointer_unreadable", pin: T.PIN_POINTER_CNL,
    anchor: T.A_POINTER_CNL, caseCommit: T.CC_CNL, note: T.NOTE_READ, row: T.ROW_CASE, response: CNL_503 },
  { from: "anchorState", pair: "case", fx: "pin_commit_cnl", state: "could_not_look", reason: "pin_commit_unreadable",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.pin_commit) },
  { from: "anchorState", pair: "case", fx: "pin_text", ...PIN_CONFLICT("pin_at_its_commit_not_json") },
  { from: "anchorState", pair: "case", fx: "pin_raw_503", state: "could_not_look", reason: "pin_at_commit_http_503",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.pin_at_commit) },
  { from: "anchorState", pair: "case", fx: "pin_raw_404", state: "could_not_look", reason: "pin_at_commit_http_404",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.pin_at_commit) },
  { from: "anchorState", pair: "case", fx: "pin_raw_failed", state: "could_not_look", reason: "pin_at_commit_fetch_failed",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.pin_at_commit) },
  { from: "anchorState", pair: "case", fx: "pin_other_chain", ...PIN_CONFLICT("pin_at_its_commit_holds_another_chain") },
  // unit R-L (g5): the pin's commit list read, and no read failed
  { from: "anchorState", pair: "case", fx: "pin_commits_beyond", state: "could_not_look", reason: "pin_commits_beyond_bound",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, [503, "could_not_look", T.RESP_CNL_BEYOND], CNL.pin_commits_beyond_bound) },
  { from: "anchorState", pair: "case", fx: "pin_commits_none", state: "could_not_look", reason: "pin_commits_none",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.pin_commits_none) },
  // unit R-L (g8): other http codes
  { from: "anchorState", pair: "case", fx: "pin_raw_500", state: "could_not_look", reason: "pin_at_commit_http_500",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.pin_at_commit) },
  // unit R-L (g8): every reason the seal judge gives a pin pointer
  ...JUDGE_REASONS.map((reason) => ({ from: "anchorState", pair: "case", fx: `unreadable_${reason}`, state: "unreadable", reason, pin: T.PIN_UNREADABLE,
    anchor: T.A_UNREADABLE, caseCommit: T.CC_UNREADABLE, note: T.NOTE_READ, row: T.ROW_CASE, response: NOT_PINNED_409 })),
  { from: "anchorState", pair: "case", fx: "pin_judge_fails", ...PIN_CONFLICT("pin_at_its_commit_not_a_pin") },
  { from: "anchorState", pair: "case", fx: "pin_other_seq", ...PIN_CONFLICT("pin_at_its_commit_not_a_pin") },
  // servedAtCommit, for the case file at the commit its pin names
  { from: "servedAtCommit (case)", pair: "case", fx: "case_differs", state: "pin_commit_mismatch", reason: "case_at_commit_differs",
    ...HELD(T.A_MISMATCH, T.CC_MISMATCH, NOT_PINNED_409, MISMATCH.differs("case file")) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_absent", state: "pin_commit_mismatch", reason: "case_absent_at_commit",
    ...HELD(T.A_MISMATCH, T.CC_MISMATCH, NOT_PINNED_409, MISMATCH.absent("case file")) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_not_found", state: "pin_commit_mismatch", reason: "case_commit_not_found",
    ...HELD(T.A_MISMATCH, T.CC_MISMATCH, NOT_PINNED_409, MISMATCH.not_found) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_off_branch", state: "pin_commit_mismatch", reason: "case_commit_off_branch",
    ...HELD(T.A_MISMATCH, T.CC_MISMATCH, NOT_PINNED_409, MISMATCH.off_branch) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_not_shown", state: "could_not_look", reason: "case_commit_not_shown",
    ...HELD(T.A_HELD_CNL, T.CC_NOT_SHOWN, CNL_503, CNL.not_shown) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_raw_503", state: "could_not_look", reason: "case_at_commit_http_503",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.at_commit("case file")) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_raw_failed", state: "could_not_look", reason: "case_at_commit_fetch_failed",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.at_commit("case file")) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_exists_503", state: "could_not_look", reason: "case_commit_exists_http_503",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.exists) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_exists_failed", state: "could_not_look", reason: "case_commit_exists_read_failed",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.exists) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_compare_503", state: "could_not_look", reason: "case_commit_compare_http_503",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.on_branch) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_compare_failed", state: "could_not_look", reason: "case_commit_compare_failed",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.on_branch) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_branch", state: "could_not_look", reason: "case_commit_branch_unreadable",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.on_branch) },
  // unit R-L (g8): another branch answer and other http codes
  { from: "servedAtCommit (case)", pair: "case", fx: "case_branch_name", state: "could_not_look", reason: "case_commit_branch_name_invalid",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.on_branch) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_raw_429", state: "could_not_look", reason: "case_at_commit_http_429",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.at_commit("case file")) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_exists_500", state: "could_not_look", reason: "case_commit_exists_http_500",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.exists) },
  { from: "servedAtCommit (case)", pair: "case", fx: "case_compare_500", state: "could_not_look", reason: "case_commit_compare_http_500",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, CNL_503, CNL.on_branch) },
  // anchorState given a chain (tools/preview_dry_run.js), and with no anchor
  // lookup (the revocation order): never the page's or the reference's
  { from: "anchorState (chain)", pair: "case", fx: "chain_case_unreadable", state: "could_not_look", reason: "case_unreadable",
    ...HELD(T.A_HELD_CNL, T.CC_CNL, NOT_REACHED, CNL.file("case file")) },
  { from: "anchorState (chain)", pair: "case", fx: "chain_served_differs", state: "pin_commit_mismatch", reason: "case_served_differs",
    ...HELD(T.A_MISMATCH, T.CC_MISMATCH, NOT_REACHED, MISMATCH.other("case file")) },
  { from: "anchorState (no anchor lookup)", pair: "case", fx: "not_looked_up", state: "pinned", reason: null, ...PINNED, anchor: T.NOT_LOOKED_UP,
    response: NOT_REACHED },
  // dailyAnchorOf
  { from: "dailyAnchorOf", pair: "case", fx: "head_text", ...HEAD_CONFLICT("anchored_head_not_json") },
  { from: "dailyAnchorOf", pair: "case", fx: "head_other_chain", ...HEAD_CONFLICT("anchored_head_holds_another_chain") },
  { from: "dailyAnchorOf", pair: "case", fx: "head_judge_fails", ...HEAD_CONFLICT("anchored_head_not_a_pin") },
  { from: "dailyAnchorOf", pair: "case", fx: "head_other_seq", ...HEAD_CONFLICT("anchored_head_not_a_pin") },
  { from: "dailyAnchorOf", pair: "case", fx: "head_off_branch", ...HEAD_CONFLICT("anchored_head_off_branch") },
  { from: "dailyAnchorOf", pair: "anchor", fx: "anchors_cnl", state: "pinned", reason: "anchors_unreadable", ...ANCHOR_CNL },
  { from: "dailyAnchorOf", pair: "anchor", fx: "record_cnl", state: "pinned", reason: "anchor_record_unreadable", ...ANCHOR_CNL },
  { from: "dailyAnchorOf", pair: "anchor", fx: "pin_at_head_503", state: "pinned", reason: "pin_at_head_http_503", ...ANCHOR_CNL },
  { from: "dailyAnchorOf", pair: "anchor", fx: "head_compare_503", state: "pinned", reason: "anchor_head_compare_http_503", ...ANCHOR_CNL },
  { from: "dailyAnchorOf", pair: "anchor", fx: "head_not_shown", state: "pinned", reason: "anchor_head_not_shown", ...PINNED,
    anchor: T.HEAD_NOT_SHOWN, response: ANCHOR_TAKES_ROW },
  { from: "dailyAnchorOf", pair: "anchor", fx: "head_absent_not_shown", state: "pinned", reason: "anchor_head_not_shown", ...PINNED,
    anchor: T.HEAD_NOT_SHOWN, response: ANCHOR_TAKES_ROW },
  { from: "dailyAnchorOf", pair: "anchor", fx: "head_exists_503", state: "pinned", reason: "anchor_head_exists_http_503", ...ANCHOR_CNL },
  { from: "dailyAnchorOf", pair: "anchor", fx: "head_before_pin", state: "pinned", reason: null, ...PINNED },
  { from: "dailyAnchorOf", pair: "anchor", fx: "record_commit_cnl", state: "pinned", reason: "anchor_record_commit_unreadable", ...PINNED,
    anchor: T.RECORD_COMMIT_CNL, response: ANCHOR_TAKES_ROW },
  { from: "dailyAnchorOf", pair: "anchor", fx: "record_at_commit_503", state: "pinned", reason: "anchor_record_at_commit_http_503", ...PINNED,
    anchor: T.RECORD_AT_COMMIT_CNL, response: ANCHOR_TAKES_ROW },
  { from: "dailyAnchorOf", pair: "anchor", fx: "record_changed", state: "pinned", reason: "anchor_record_changed", ...PINNED,
    anchor: T.RECORD_CHANGED, response: ANCHOR_TAKES_ROW },
  // unit R-L2: a record whose newest commit names no head
  { from: "dailyAnchorOf", pair: "anchor", fx: "record_no_head", state: "pinned", reason: "anchor_record_names_no_head", ...PINNED,
    anchor: T.RECORD_NO_HEAD, response: ANCHOR_TAKES_ROW },
  // unit R-L (g2, g5, g7, g8): the reasons the R-J3 table did not assert
  { from: "dailyAnchorOf", pair: "anchor", fx: "record_at_commit_failed", state: "pinned", reason: "anchor_record_at_commit_fetch_failed", ...PINNED,
    anchor: T.RECORD_AT_COMMIT_CNL, response: ANCHOR_TAKES_ROW },
  { from: "dailyAnchorOf", pair: "anchor", fx: "record_at_commit_404", state: "pinned", reason: "anchor_record_at_commit_http_404", ...PINNED,
    anchor: T.RECORD_AT_COMMIT_CNL, response: ANCHOR_TAKES_ROW },
  { from: "dailyAnchorOf", pair: "anchor", fx: "record_commits_beyond", state: "pinned", reason: "anchor_record_commits_beyond_bound", ...PINNED,
    anchor: T.RECORD_COMMITS_BEYOND, response: ANCHOR_TAKES_ROW },
  { from: "dailyAnchorOf", pair: "anchor", fx: "record_commits_none", state: "pinned", reason: "anchor_record_commits_none", ...PINNED,
    anchor: T.RECORD_COMMITS_NONE, response: ANCHOR_TAKES_ROW },
  { from: "dailyAnchorOf", pair: "anchor", fx: "pin_at_head_failed", state: "pinned", reason: "pin_at_head_fetch_failed", ...ANCHOR_CNL },
  { from: "dailyAnchorOf", pair: "anchor", fx: "pin_at_head_500", state: "pinned", reason: "pin_at_head_http_500", ...ANCHOR_CNL },
  { from: "dailyAnchorOf", pair: "anchor", fx: "head_compare_failed", state: "pinned", reason: "anchor_head_compare_failed", ...ANCHOR_CNL },
  { from: "dailyAnchorOf", pair: "anchor", fx: "head_branch_unreadable", state: "pinned", reason: "anchor_head_branch_unreadable", ...ANCHOR_CNL },
  { from: "dailyAnchorOf", pair: "anchor", fx: "head_exists_failed", state: "pinned", reason: "anchor_head_exists_read_failed", ...ANCHOR_CNL },
  { from: "dailyAnchorOf", pair: "anchor", fx: "head_not_shown_then_anchored", state: "anchored", reason: null, ...PINNED, anchor: T.ANCHORED },
  { from: "dailyAnchorOf", pair: "anchor", fx: "head_not_shown_then_none", state: "pinned", reason: "anchor_head_not_shown", ...PINNED,
    anchor: T.HEAD_NOT_SHOWN, response: ANCHOR_TAKES_ROW },
  // the row reader, and servedAtCommit for the row at the commit a pin lists
  { from: "row reader", pair: "row", fx: "row_recorded", state: "recorded", reason: null, ...PINNED, row: T.ROW_RECORDED },
  { from: "row reader", pair: "row", fx: "pinned", state: "commit_unrecorded", reason: null, ...PINNED },
  { from: "row reader", pair: "row", fx: "not_pinned", state: "commit_unrecorded", reason: "case_not_pinned", case: ["commit_unrecorded", "not_pinned"], pin: T.PIN_NONE,
    anchor: T.A_NOT_PINNED, caseCommit: T.CC_NOT_PINNED, note: T.NOTE_READ, row: T.ROW_UNLISTED, response: NOT_PINNED_409 },
  { from: "row reader", pair: "row", fx: "no_case_commit", state: "not_read", reason: "no_case_commit", case: ["commit_unrecorded", "no_case_commit"],
    ...HELD(T.A_NO_CASE_COMMIT, T.CC_NO_CASE_COMMIT, NOT_PINNED_409) },
  { from: "row reader", pair: "row", fx: "walk_cnl", state: "could_not_look", reason: "pin_unreadable", ...PINNED, row: T.ROW_WALK_CNL },
  { from: "row reader", pair: "row", fx: "walk_absent", state: "not_read", reason: "pin_below_absent", ...PINNED, row: T.ROW_WALK_ABSENT },
  { from: "row reader", pair: "row", fx: "walk_not_a_pin", state: "not_read", reason: "pin_below_not_a_pin", ...PINNED, row: T.ROW_WALK_NOT_A_PIN },
  { from: "row reader", pair: "row", fx: "walk_bound", state: "not_read", reason: "pins_not_read", ...PINNED, row: T.ROW_WALK_BOUND },
  { from: "servedAtCommit (row)", pair: "row", fx: "row_differs", state: "pin_commit_mismatch", reason: "reference_at_commit_differs", ...PINNED,
    row: T.ROW_MISMATCH, words: MISMATCH.differs("row") },
  { from: "servedAtCommit (row)", pair: "row", fx: "row_absent", state: "pin_commit_mismatch", reason: "reference_absent_at_commit", ...PINNED,
    row: T.ROW_MISMATCH, words: MISMATCH.absent("row") },
  { from: "servedAtCommit (row)", pair: "row", fx: "row_not_found", state: "pin_commit_mismatch", reason: "reference_commit_not_found", ...PINNED,
    row: T.ROW_MISMATCH, words: MISMATCH.not_found },
  { from: "servedAtCommit (row)", pair: "row", fx: "row_off_branch", state: "pin_commit_mismatch", reason: "reference_commit_off_branch", ...PINNED,
    row: T.ROW_MISMATCH, words: MISMATCH.off_branch },
  { from: "servedAtCommit (row)", pair: "row", fx: "row_not_shown", state: "could_not_look", reason: "reference_commit_not_shown", ...PINNED,
    row: T.ROW_CNL, words: CNL.not_shown },
  { from: "servedAtCommit (row)", pair: "row", fx: "row_raw_503", state: "could_not_look", reason: "reference_at_commit_http_503", ...PINNED,
    row: T.ROW_CNL, words: CNL.at_commit("row") },
  { from: "servedAtCommit (row)", pair: "row", fx: "row_exists_503", state: "could_not_look", reason: "reference_commit_exists_http_503", ...PINNED,
    row: T.ROW_CNL, words: CNL.exists },
  { from: "servedAtCommit (row)", pair: "row", fx: "row_compare_503", state: "could_not_look", reason: "reference_commit_compare_http_503", ...PINNED,
    row: T.ROW_CNL, words: CNL.on_branch },
  // unit R-L (g8): the other reference_* could_not_look reasons
  { from: "servedAtCommit (row)", pair: "row", fx: "row_raw_failed", state: "could_not_look", reason: "reference_at_commit_fetch_failed", ...PINNED,
    row: T.ROW_CNL, words: CNL.at_commit("row") },
  { from: "servedAtCommit (row)", pair: "row", fx: "row_exists_failed", state: "could_not_look", reason: "reference_commit_exists_read_failed", ...PINNED,
    row: T.ROW_CNL, words: CNL.exists },
  { from: "servedAtCommit (row)", pair: "row", fx: "row_compare_failed", state: "could_not_look", reason: "reference_commit_compare_failed", ...PINNED,
    row: T.ROW_CNL, words: CNL.on_branch },
  { from: "servedAtCommit (row)", pair: "row", fx: "row_branch_unreadable", state: "could_not_look", reason: "reference_commit_branch_unreadable", ...PINNED,
    row: T.ROW_CNL, words: CNL.on_branch },
  { from: "servedAtCommit (row)", pair: "row", fx: "row_raw_500", state: "could_not_look", reason: "reference_at_commit_http_500", ...PINNED,
    row: T.ROW_CNL, words: CNL.at_commit("row") },
];
// unit R-L (g8): the row reader's pair under every case state that is not
// shown pinned: not_read, with the case's own reason
TABLE.push(...TABLE.filter((t) => t.pair === "case" && t.row === T.ROW_CASE && t.state !== "commit_unrecorded")
  .map((t) => ({ ...t, from: "row reader", pair: "row", state: "not_read", reason: t.reason, case: [t.state, t.reason] })));

// A sealed case with reference row 1, appended while it read pinned.
async function withRow(scope) {
  const c = await sealedCase(scope);
  const r = await reference(c, "a", "row-1");
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  return c;
}
// A commit made before the case was opened (nothing of it there).
const early = () => gh.seedText(PINS, `notes/early-${fresh()}.txt`, "x\n");
// The seal's own pin record as stored, and its text at the commit that wrote it.
const sealPin = (id) => gh.read(PINS, seqOf(id));
function atItsCommit(id, text) {
  gh.commitsFor(PINS, seqOf(id)).slice(-1)[0].content = text;
}
// A daily anchor record naming a head at which the seal's pin record held
// `text`, then put back.
function headHolding(id, text) {
  const p = seqOf(id);
  const good = gh._repoMap(PINS).get(p).content;
  gh._repoMap(PINS).get(p).content = text;
  const head = gh.addCommit(PINS, p, "mock: the numbered pin record rewritten");
  const a = dailyAnchor(pinDay(id), head);
  gh._repoMap(PINS).get(p).content = good;
  gh.addCommit(PINS, p, "mock: put back");
  return { head: s12(head), record: a.path };
}
// The pointer, listing row 1 at `commit`.
function listRow(id, commit) {
  gh.seed(PINS, latestOf(id), { ...gh.read(PINS, latestOf(id)), reference_commits: [{ seq: 1, commit }] });
}
// Pins 2..top over the seal's, each this case's, listing nothing.
function plantPins(id, top) {
  const base = sealPin(id);
  let rec = base;
  for (let n = 2; n <= top; n += 1) {
    rec = { ...base, seq: n };
    gh.seed(PINS, S._internal.pinPath(id, n), rec);
  }
  gh.seed(PINS, latestOf(id), rec);
}
const rowText = (id) => gh._repoMap(PINS).get(rowPath(id, 1)).content;
// The day after a YYYY-MM-DD day.
const nextDay = (d) => new Date(Date.parse(`${d}T00:00:00Z`) + DAY).toISOString().slice(0, 10);
// A path's history made longer than lib/_case_seal.js reads (fifty pages):
// a page of one commit each, and more commits than pages (unit R-L, g5).
function longHistory(path) {
  gh.commitsPageCap = 1;
  for (let i = 0; i < S._internal.COMMIT_LIST_PAGES + 5; i += 1) gh.addCommit(PINS, path, "mock: one more commit");
}
// A path the repository lists no commit for (unit R-L, g5).
function noHistory(path) {
  const list = gh._commitsOf(PINS);
  for (let i = list.length - 1; i >= 0; i -= 1) if (list[i].path === path) list.splice(i, 1);
}
const anchored = (a) => ({ head: s12(a.head), record: a.path, record_commit: s12(a.commit) });
const cnlCompare = (sha, status) => () => {
  S._internal.clearDocumentCache();
  gh.forceCompareFailure(1, status, `...${sha}`);
};

// Each fixture -> {c, x (more names for the sentences), arm (the one-shot
// failure, set again before each read), chain (anchorState given a chain),
// noAnchor (no anchor lookup), rowArm (the row's failure: the reference
// does not read the row)}.
const FIXTURES = {
  pinned: async () => ({ c: await withRow("RJ3 pinned") }),
  anchored: async () => {
    const c = await withRow("RJ3 anchored");
    return { c, x: anchored(dailyAnchor(pinDay(c.id))) };
  },
  not_pinned: async () => {
    const c = await withRow("RJ3 not pinned");
    gh._repoMap(PINS).delete(latestOf(c.id));
    return { c };
  },
  no_case_commit: async () => {
    const c = await withRow("RJ3 no case commit");
    plantPin(c.id, chainOf(c.id), undefined);
    return { c };
  },
  unreadable: async () => {
    const c = await withRow("RJ3 unreadable");
    gh.seed(PINS, latestOf(c.id), { not: "a pin" });
    return { c };
  },
  pointer_other_chain: async () => {
    const c = await withRow("RJ3 pointer chain");
    gh.seed(PINS, latestOf(c.id), { ...gh.read(PINS, latestOf(c.id)), chain: sha("another chain") });
    return { c };
  },
  pointer_cnl: async () => {
    const c = await withRow("RJ3 pointer cnl");
    return { c, arm: () => gh.forceGetFailure(PINS, latestOf(c.id), 1, 503) };
  },
  pin_commit_cnl: async () => {
    const c = await withRow("RJ3 pin commit cnl");
    return { c, arm: () => gh.forceCommitsFailure(PINS, seqOf(c.id), 1, 503) };
  },
  pin_text: async () => {
    const c = await withRow("RJ3 pin text");
    atItsCommit(c.id, "not json\n");
    return { c };
  },
  pin_raw_503: async () => {
    const c = await withRow("RJ3 pin raw 503");
    return { c, arm: () => gh.forceRawFailure(1, 503, `:${seqOf(c.id)}`) };
  },
  pin_raw_404: async () => {
    const c = await withRow("RJ3 pin raw 404");
    return { c, arm: () => gh.forceRawFailure(1, 404, `:${seqOf(c.id)}`) };
  },
  pin_raw_failed: async () => {
    const c = await withRow("RJ3 pin raw failed");
    return { c, arm: () => gh.forceRawFailure(1, 0, `:${seqOf(c.id)}`) };
  },
  pin_other_chain: async () => {
    const c = await withRow("RJ3 pin other chain");
    atItsCommit(c.id, json({ ...sealPin(c.id), chain: sha("another chain") }));
    return { c };
  },
  pin_judge_fails: async () => {
    const c = await withRow("RJ3 pin judge fails");
    atItsCommit(c.id, json({ ...sealPin(c.id), rows: 7 }));
    return { c };
  },
  pin_other_seq: async () => {
    const c = await withRow("RJ3 pin other seq");
    atItsCommit(c.id, json({ ...sealPin(c.id), seq: 2 }));
    return { c };
  },
  case_differs: async () => {
    const c = await withRow("RJ3 case differs");
    plantPin(c.id, chainOf(c.id), gh.commitsFor(PINS, C.casePath(c.id)).slice(-1)[0].sha);
    return { c };
  },
  case_absent: async () => {
    const e = early();
    const c = await withRow("RJ3 case absent");
    plantPin(c.id, chainOf(c.id), e);
    return { c };
  },
  case_not_found: async () => {
    const c = await withRow("RJ3 case not found");
    plantPin(c.id, chainOf(c.id), "f".repeat(40));
    return { c };
  },
  case_off_branch: async () => {
    const c = await withRow("RJ3 case off branch");
    const side = gh.seedSideCommit(PINS, fresh());
    gh.seedRaw(PINS, side, C.casePath(c.id), caseText(c.id));
    plantPin(c.id, chainOf(c.id), side);
    return { c };
  },
  case_not_shown: async () => {
    const c = await withRow("RJ3 case not shown");
    const f = fresh();
    gh.seedRaw(PINS, f, C.casePath(c.id), caseText(c.id));
    plantPin(c.id, chainOf(c.id), f);
    return { c };
  },
  case_raw_503: async () => {
    const c = await withRow("RJ3 case raw 503");
    return { c, arm: () => gh.forceRawFailure(1, 503, `:${C.casePath(c.id)}`) };
  },
  case_raw_failed: async () => {
    const c = await withRow("RJ3 case raw failed");
    return { c, arm: () => gh.forceRawFailure(1, 0, `:${C.casePath(c.id)}`) };
  },
  case_exists_503: async () => {
    const e = early();
    const c = await withRow("RJ3 case exists 503");
    plantPin(c.id, chainOf(c.id), e);
    return { c, arm: () => gh.forceCommitFailure(1, 503) };
  },
  case_exists_failed: async () => {
    const e = early();
    const c = await withRow("RJ3 case exists failed");
    plantPin(c.id, chainOf(c.id), e);
    return { c, arm: () => gh.forceCommitFailure(1, 0) };
  },
  case_compare_503: async () => {
    const c = await withRow("RJ3 case compare 503");
    return { c, arm: cnlCompare(sealCommit(c.id), 503) };
  },
  case_compare_failed: async () => {
    const c = await withRow("RJ3 case compare failed");
    return { c, arm: cnlCompare(sealCommit(c.id), 0) };
  },
  case_branch: async () => {
    const c = await withRow("RJ3 case branch");
    const f = fresh();
    gh.seedRaw(PINS, f, C.casePath(c.id), caseText(c.id));
    plantPin(c.id, chainOf(c.id), f);
    return { c, arm: () => { S._internal.clearDocumentCache(); gh.forceBranchFailure(1, 503); } };
  },
  chain_case_unreadable: async () => {
    const c = await withRow("RJ3 chain case unreadable");
    return { c, chain: chainOf(c.id), arm: () => gh.forceGetFailure(PINS, C.casePath(c.id), 1, 503) };
  },
  chain_served_differs: async () => {
    const c = await withRow("RJ3 chain served differs");
    const other = sha("a chain this case does not have");
    plantPin(c.id, other, sealCommit(c.id));
    return { c, chain: other };
  },
  not_looked_up: async () => ({ c: await withRow("RJ3 not looked up"), noAnchor: true }),
  head_text: async () => {
    const c = await withRow("RJ3 head text");
    return { c, x: headHolding(c.id, "not json\n") };
  },
  head_other_chain: async () => {
    const c = await withRow("RJ3 head other chain");
    return { c, x: headHolding(c.id, json({ ...sealPin(c.id), chain: sha("a chain at the head") })) };
  },
  head_judge_fails: async () => {
    const c = await withRow("RJ3 head judge fails");
    return { c, x: headHolding(c.id, json({ ...sealPin(c.id), rows: 7 })) };
  },
  head_other_seq: async () => {
    const c = await withRow("RJ3 head other seq");
    return { c, x: headHolding(c.id, json({ ...sealPin(c.id), seq: 2 })) };
  },
  head_off_branch: async () => {
    const c = await withRow("RJ3 head off branch");
    const side = gh.seedSideCommit(PINS, fresh());
    gh.seedRaw(PINS, side, seqOf(c.id), gh._repoMap(PINS).get(seqOf(c.id)).content);
    return { c, x: { record: dailyAnchor(pinDay(c.id), side).path } };
  },
  anchors_cnl: async () => {
    const c = await withRow("RJ3 anchors cnl");
    dailyAnchor(pinDay(c.id));
    return { c, arm: () => gh.forceGetFailure(PINS, "anchors", 1, 503) };
  },
  record_cnl: async () => {
    const c = await withRow("RJ3 record cnl");
    const a = dailyAnchor(pinDay(c.id));
    return { c, arm: () => gh.forceGetFailure(PINS, a.path, 1, 503) };
  },
  pin_at_head_503: async () => {
    const c = await withRow("RJ3 pin at head 503");
    const a = dailyAnchor(pinDay(c.id));
    return { c, arm: () => gh.forceRawFailure(1, 503, `@${a.head}:${seqOf(c.id)}`) };
  },
  head_compare_503: async () => {
    const c = await withRow("RJ3 head compare 503");
    const a = dailyAnchor(pinDay(c.id));
    return { c, arm: cnlCompare(a.head, 503) };
  },
  head_not_shown: async () => {
    const c = await withRow("RJ3 head not shown");
    const f = fresh();
    gh.seedRaw(PINS, f, seqOf(c.id), gh._repoMap(PINS).get(seqOf(c.id)).content);
    dailyAnchor(pinDay(c.id), f);
    return { c, x: { head_full: f } };
  },
  // F3: no pin at the head, and the head is not a commit the repository shows
  head_absent_not_shown: async () => {
    const c = await withRow("RJ3 head absent not shown");
    const f = fresh();
    dailyAnchor(pinDay(c.id), f);
    return { c, x: { head_full: f } };
  },
  // unit R-L (g2): a record naming a head the repository does not show is a
  // miss, and the records after it are read
  head_not_shown_then_anchored: async () => {
    const c = await withRow("RJ3 head not shown then anchored");
    dailyAnchor(pinDay(c.id), fresh());
    return { c, x: anchored(dailyAnchor(nextDay(pinDay(c.id)))) };
  },
  head_not_shown_then_none: async () => {
    const e = early();
    const c = await withRow("RJ3 head not shown then none");
    const f = fresh();
    dailyAnchor(pinDay(c.id), f);
    dailyAnchor(nextDay(pinDay(c.id)), e);
    return { c, x: { head_full: f } };
  },
  head_branch_unreadable: async () => {
    const c = await withRow("RJ3 head branch unreadable");
    const f = fresh();
    gh.seedRaw(PINS, f, seqOf(c.id), gh._repoMap(PINS).get(seqOf(c.id)).content);
    dailyAnchor(pinDay(c.id), f);
    return { c, arm: () => { S._internal.clearDocumentCache(); gh.forceBranchFailure(1, 503); } };
  },
  head_exists_failed: async () => {
    const c = await withRow("RJ3 head exists failed");
    dailyAnchor(pinDay(c.id), fresh());
    return { c, arm: () => gh.forceCommitFailure(1, 0) };
  },
  head_compare_failed: async () => {
    const c = await withRow("RJ3 head compare failed");
    const a = dailyAnchor(pinDay(c.id));
    return { c, arm: cnlCompare(a.head, 0) };
  },
  pin_at_head_failed: async () => {
    const c = await withRow("RJ3 pin at head failed");
    const a = dailyAnchor(pinDay(c.id));
    return { c, arm: () => gh.forceRawFailure(1, 0, `@${a.head}:${seqOf(c.id)}`) };
  },
  pin_at_head_500: async () => {
    const c = await withRow("RJ3 pin at head 500");
    const a = dailyAnchor(pinDay(c.id));
    return { c, arm: () => gh.forceRawFailure(1, 500, `@${a.head}:${seqOf(c.id)}`) };
  },
  record_at_commit_failed: async () => {
    const c = await withRow("RJ3 record at commit failed");
    const a = dailyAnchor(pinDay(c.id));
    return { c, arm: () => gh.forceRawFailure(1, 0, `:${a.path}`) };
  },
  record_at_commit_404: async () => {
    const c = await withRow("RJ3 record at commit 404");
    const a = dailyAnchor(pinDay(c.id));
    return { c, arm: () => gh.forceRawFailure(1, 404, `:${a.path}`) };
  },
  record_commits_beyond: async () => {
    const c = await withRow("RJ3 record commits beyond");
    const a = dailyAnchor(pinDay(c.id));
    longHistory(a.path);
    return { c };
  },
  record_commits_none: async () => {
    const c = await withRow("RJ3 record commits none");
    const a = dailyAnchor(pinDay(c.id));
    noHistory(a.path);
    return { c };
  },
  pin_commits_beyond: async () => {
    const c = await withRow("RJ3 pin commits beyond");
    longHistory(seqOf(c.id));
    return { c };
  },
  pin_commits_none: async () => {
    const c = await withRow("RJ3 pin commits none");
    noHistory(seqOf(c.id));
    return { c };
  },
  pin_raw_500: async () => {
    const c = await withRow("RJ3 pin raw 500");
    return { c, arm: () => gh.forceRawFailure(1, 500, `:${seqOf(c.id)}`) };
  },
  case_branch_name: async () => {
    const c = await withRow("RJ3 case branch name");
    const was = store.BRANCH;
    store.BRANCH = "not a branch name";
    return { c, cleanup: () => { store.BRANCH = was; } };
  },
  case_raw_429: async () => {
    const c = await withRow("RJ3 case raw 429");
    return { c, arm: () => gh.forceRawFailure(1, 429, `:${C.casePath(c.id)}`) };
  },
  case_exists_500: async () => {
    const e = early();
    const c = await withRow("RJ3 case exists 500");
    plantPin(c.id, chainOf(c.id), e);
    return { c, arm: () => gh.forceCommitFailure(1, 500) };
  },
  case_compare_500: async () => {
    const c = await withRow("RJ3 case compare 500");
    return { c, arm: cnlCompare(sealCommit(c.id), 500) };
  },
  row_raw_failed: async () => {
    const c = await withRow("RJ3 row raw failed");
    await sealerRun();
    return { c, rowArm: () => gh.forceRawFailure(1, 0, `:${rowPath(c.id, 1)}`) };
  },
  row_raw_500: async () => {
    const c = await withRow("RJ3 row raw 500");
    await sealerRun();
    return { c, rowArm: () => gh.forceRawFailure(1, 500, `:${rowPath(c.id, 1)}`) };
  },
  row_exists_failed: async () => {
    const e = early();
    const c = await withRow("RJ3 row exists failed");
    listRow(c.id, e);
    return { c, rowArm: () => gh.forceCommitFailure(1, 0) };
  },
  row_compare_failed: async () => {
    const c = await withRow("RJ3 row compare failed");
    await sealerRun();
    return { c, rowArm: cnlCompare(rowCommit(c.id, 1), 0) };
  },
  row_branch_unreadable: async () => {
    const c = await withRow("RJ3 row branch unreadable");
    const f = fresh();
    gh.seedRaw(PINS, f, rowPath(c.id, 1), rowText(c.id));
    listRow(c.id, f);
    return { c, rowArm: () => { S._internal.clearDocumentCache(); gh.forceBranchFailure(1, 503); } };
  },
  head_exists_503: async () => {
    const c = await withRow("RJ3 head exists 503");
    dailyAnchor(pinDay(c.id), fresh());
    return { c, arm: () => gh.forceCommitFailure(1, 503) };
  },
  // F3's other side: a head from before the pin, which the repository has
  head_before_pin: async () => {
    const e = early();
    const c = await withRow("RJ3 head before pin");
    dailyAnchor(pinDay(c.id), e);
    return { c };
  },
  record_commit_cnl: async () => {
    const c = await withRow("RJ3 record commit cnl");
    const a = dailyAnchor(pinDay(c.id));
    return { c, arm: () => gh.forceCommitsFailure(PINS, a.path, 1, 503) };
  },
  record_at_commit_503: async () => {
    const c = await withRow("RJ3 record at commit 503");
    const a = dailyAnchor(pinDay(c.id));
    return { c, arm: () => gh.forceRawFailure(1, 503, `:${a.path}`) };
  },
  record_no_head: async () => {
    const c = await withRow("RJ3 record no head");
    noHead(c);
    return { c };
  },
  record_changed: async () => {
    const c = await withRow("RJ3 record changed");
    const a = dailyAnchor(pinDay(c.id));
    const later = gh.seedText(PINS, `notes/later-${fresh()}.txt`, "y\n");
    gh._repoMap(PINS).get(a.path).content = `${later} ${a.claimedAt}\n`;
    return { c };
  },
  row_recorded: async () => {
    const c = await withRow("RJ3 row recorded");
    await sealerRun();
    return { c };
  },
  row_differs: async () => {
    const c = await withRow("RJ3 row differs");
    await sealerRun();
    const row = gh.read(PINS, rowPath(c.id, 1));
    const other = gh.seed(PINS, rowPath(c.id, 1), { ...row, recorded_at: "2026-10-10T09:59:59Z" }, { keepHistory: true });
    gh.seed(PINS, rowPath(c.id, 1), row, { keepHistory: true });
    listRow(c.id, other);
    return { c };
  },
  row_absent: async () => {
    const c = await withRow("RJ3 row absent");
    listRow(c.id, sealCommit(c.id));
    return { c };
  },
  row_not_found: async () => {
    const c = await withRow("RJ3 row not found");
    listRow(c.id, "e".repeat(40));
    return { c };
  },
  row_off_branch: async () => {
    const c = await withRow("RJ3 row off branch");
    const side = gh.seedSideCommit(PINS, fresh());
    gh.seedRaw(PINS, side, rowPath(c.id, 1), rowText(c.id));
    listRow(c.id, side);
    return { c };
  },
  row_not_shown: async () => {
    const c = await withRow("RJ3 row not shown");
    const f = fresh();
    gh.seedRaw(PINS, f, rowPath(c.id, 1), rowText(c.id));
    listRow(c.id, f);
    return { c };
  },
  row_raw_503: async () => {
    const c = await withRow("RJ3 row raw 503");
    await sealerRun();
    return { c, rowArm: () => gh.forceRawFailure(1, 503, `:${rowPath(c.id, 1)}`) };
  },
  row_exists_503: async () => {
    const e = early();
    const c = await withRow("RJ3 row exists 503");
    listRow(c.id, e);
    return { c, rowArm: () => gh.forceCommitFailure(1, 503) };
  },
  row_compare_503: async () => {
    const c = await withRow("RJ3 row compare 503");
    await sealerRun();
    return { c, rowArm: cnlCompare(rowCommit(c.id, 1), 503) };
  },
  walk_cnl: async () => {
    const c = await withRow("RJ3 walk cnl");
    plantPins(c.id, 3);
    return { c, rowArm: () => gh.forceGetFailure(PINS, S._internal.pinPath(c.id, 2), 1, 503) };
  },
  walk_absent: async () => {
    const c = await withRow("RJ3 walk absent");
    plantPins(c.id, 3);
    gh._repoMap(PINS).delete(S._internal.pinPath(c.id, 2));
    return { c };
  },
  walk_not_a_pin: async () => {
    const c = await withRow("RJ3 walk not a pin");
    plantPins(c.id, 3);
    gh.seed(PINS, S._internal.pinPath(c.id, 2), { ...sealPin(c.id), seq: 2, chain: sha("not this case") });
    return { c };
  },
  walk_bound: async () => {
    const c = await withRow("RJ3 walk bound");
    plantPins(c.id, 23);
    return { c };
  },
};

// unit R-L (g8): a pointer for each reason the seal judge gives
for (const [reason, make] of Object.entries(JUDGE_POINTERS)) {
  FIXTURES[`unreadable_${reason}`] = async () => {
    const c = await withRow(`RJ3 unreadable ${reason}`);
    gh.seed(PINS, latestOf(c.id), make(gh.read(PINS, latestOf(c.id))));
    return { c };
  };
}

// The names a sentence may use, read off the fixture as it stands.
function namesOf(f, t) {
  const { id } = f.c;
  const m = gh._repoMap(PINS);
  const wrote = gh.commitsFor(PINS, seqOf(id)).slice(-1)[0];
  let ptr = null;
  try {
    ptr = m.has(latestOf(id)) ? JSON.parse(m.get(latestOf(id)).content) : null;
  } catch {
    ptr = null;
  }
  const listed = ptr && Array.isArray(ptr.reference_commits) ? ptr.reference_commits.find((e) => e && e.seq === 1) : null;
  const [state, reason] = t.pair !== "row" ? [t.state, t.reason] : t.case || ["pinned", null];
  return {
    state, reason, row_reason: t.pair === "row" ? t.reason : undefined, words: t.words,
    pin_commit: wrote && s12(wrote.sha), pin_date: wrote && wrote.date,
    case_commit: ptr && typeof ptr.case_commit === "string" ? s12(ptr.case_commit) : undefined,
    listed: listed ? s12(listed.commit) : undefined, pin_seq: ptr ? ptr.seq : undefined,
    ...(f.x || {}),
  };
}

for (const t of TABLE) {
  test(`THE TABLE: ${t.from}, ${t.state}${t.reason ? ` / ${t.reason}` : ""} (${t.fx}): the pin, anchor and case-commit cells, the note, the row's cell and the reference's answer`, async () => {
    const f = await FIXTURES[t.fx]();
    try {
      await tableRow(t, f);
    } finally {
      if (f.cleanup) f.cleanup();
    }
  });
}
async function tableRow(t, f) {
  {
    const { id } = f.c;
    const x = namesOf(f, t);
    const arm = () => {
      S._internal.clearCommitFiles();
      S._internal.clearDocumentCache();
      if (f.arm) f.arm();
    };
    // the pair, as its reader returns it
    arm();
    if (f.rowArm) f.rowArm();
    const st = f.chain ? await S.anchorState(id, f.chain) : await S.anchorState(id, storedCase(id), f.noAnchor ? { anchor: false } : {});
    const live = await S.liveRecords(storedCase(id), { keyDocument: DOC });
    assert.equal(live.ok, true, "fixture: the rows read");
    const rowState = (await S.referenceCommitStates(id, chainOf(id), st, live.rows)).get(1);
    const pair = t.pair === "row" ? [rowState.state, rowState.reason ?? null]
      : [st.pin, t.pair === "anchor" ? (st.anchor && st.anchor.could_not_look) || null : st.reason ?? null];
    assert.deepEqual(pair, [t.state, t.reason], `the fixture makes the pair: ${JSON.stringify(st).slice(0, 300)}`);
    const want = { pin: fill(t.pin, x), anchor: fill(t.anchor, x), caseCommit: fill(t.caseCommit, x), note: fill(t.note, x), row: fill(t.row, x) };
    if (f.chain || f.noAnchor) {
      // never the page's: its cells, from the page's own functions
      assert.deepEqual(stateCells(st, rowState), want);
      assert.equal(t.response, NOT_REACHED);
      return;
    }
    // the page
    arm();
    if (f.rowArm) f.rowArm();
    const page = await casePage(id);
    assert.equal(page.status, 200, page.html.slice(0, 300));
    assert.deepEqual(pageCells(page.html), want);
    // the reference's answer
    arm();
    const r = await reference(f.c, "b", "probe");
    const [status, code, error] = t.response;
    assert.equal(r.status, status, JSON.stringify(r.body).slice(0, 400));
    if (status === 201) return;
    assert.deepEqual([r.body.error_code, r.body.error], [code, fill(error, x)]);
  }
}

// =============================================================================
// BL1, BL2: the words the table's rows use
// =============================================================================

test("BL1: 'no pin of this case's chain' is said only where the pointer was read and holds no pin of this chain; where it holds the chain the pin cell says so", () => {
  const said = TABLE.filter((t) => t.pair === "case" && t.pin.startsWith("no pin of this case's chain")).map((t) => `${t.state}/${t.reason}`);
  assert.deepEqual([...new Set(said)], ["conflict/pointer_holds_another_chain"]);
  for (const r of ["anchored_head_off_branch", "anchored_head_not_json", "anchored_head_holds_another_chain", "anchored_head_not_a_pin",
    "case_at_commit_differs", "case_commit_not_shown"]) {
    assert.equal(TABLE.find((t) => t.reason === r).pin, T.PIN_HELD, r);
  }
});

test("BL2: conflictWords says 'holds another chain' only for the three *_holds_another_chain reasons; *_not_a_pin says the record there is not a pin record for this case", () => {
  for (const [reason, words] of Object.entries(CONFLICT_WORDS)) {
    assert.equal(S.conflictWords(reason), words, reason);
    if (!reason.endsWith("_holds_another_chain")) assert.doesNotMatch(S.conflictWords(reason), /another chain/, reason);
  }
  assert.match(S.conflictWords("pin_at_its_commit_not_a_pin"), /is not a pin record for this case$/);
  assert.match(S.conflictWords("anchored_head_not_a_pin"), /is not a pin record for this case$/);
});

// =============================================================================
// F1, F2: no future pin stated as fact, and no "never"
// =============================================================================

test("F1, F2: the page states no future pin as fact and says no 'never' of a pin or an anchor; the reference handler's comment states no future listing", () => {
  const page = PAGE_SRC();
  assert.doesNotMatch(page, /writes it on its next run|records that commit in the case's next pin|Never pinned|never anchored|has no such commit/);
  assert.doesNotMatch(page, /it was pinned before every write named its own commit/);
  assert.doesNotMatch(HTTP_SRC(), /the case's next pin lists it|once the operator's sealer run has pinned the case/);
});

// =============================================================================
// F4: under a revoked key, a pin that could not be read is could_not_look
// =============================================================================

const REVOKED = Object.freeze(KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11" }), KD.reconcileEntry(RECEIPT_KEY)));

test("F4: under a revoked key, a pin that could not be read renders the could-not-look page (503), never SEALED RECORD DOES NOT VERIFY; the reference answers 503 could_not_look and the sealer could_not_look", async () => {
  const c = await withRow("RJ3 F4 revoked");
  const latest = latestOf(c.id);
  S._internal.clearDocumentCache();
  gh.forceGetFailure(PINS, latest, 1, 503);
  const answer = await S.sealedRecordReason(storedCase(c.id), REVOKED);
  assert.deepEqual([answer.code, answer.reason], ["pin_unavailable", "pin_pointer_unreadable"]);
  assert.equal(S.sealHolds(answer), false, "not a yes");
  S._internal.clearDocumentCache();
  gh.forceGetFailure(PINS, latest, 1, 503);
  const page = await casePage(c.id, { keyDocument: REVOKED });
  assert.equal(page.status, 503);
  assert.match(page.html, /Case: COULD NOT LOOK/);
  assert.doesNotMatch(page.html, /DOES NOT VERIFY/);
  assert.ok(page.html.includes(esc("whether this case's pin shows that could not be read when this page was read (could_not_look: pin_pointer_unreadable)")),
    page.html.slice(page.html.indexOf("<h2>"), page.html.indexOf("<h2>") + 1200));
  assert.ok(page.html.includes("This is not a no; try again."));
  S._internal.clearDocumentCache();
  gh.forceGetFailure(PINS, latest, 1, 503);
  const r = await reference(c, "b", "probe", REVOKED);
  assert.deepEqual([r.status, r.body.error_code, r.body.reason], [503, "could_not_look", "pin_pointer_unreadable"]);
  assert.ok(r.body.error.startsWith("could not look; this is not a refusal of the row. Try again."), r.body.error);
  S._internal.clearDocumentCache();
  gh.forceGetFailure(PINS, latest, 1, 503);
  const sealer = await S.anchorCase(c.id, { now: REVEAL_AT + 3600000, keyDocument: REVOKED });
  assert.deepEqual([sealer.ok, sealer.code, sealer.reason], [false, "could_not_look", "pin_pointer_unreadable"]);
  // a pin read, that is not a case seal record, is still a no: signer_revoked
  gh.seed(PINS, latest, { not: "a pin" });
  S._internal.clearDocumentCache();
  const no = await S.sealedRecordReason(storedCase(c.id), REVOKED);
  assert.deepEqual([no.code, no.reason], ["signer_revoked", "pin_unreadable:case_seal_unknown_field"]);
  assert.match((await casePage(c.id, { keyDocument: REVOKED })).html, /DOES NOT VERIFY/);
});

// =============================================================================
// F8: a page kept again moves to the newest place in the eviction order
// =============================================================================

test("F8: re-setting a kept page's id moves it to the newest place, so the cap drops the oldest kept, never the one just kept again", async () => {
  const { keepPage, cachedIds, clearPageCache } = CP._internal;
  const e = { at: 0, until: 1, doc: null, sha: "s", html: "" };
  clearPageCache();
  keepPage("a", e);
  keepPage("b", e);
  keepPage("a", e);
  assert.deepEqual(cachedIds(), ["b", "a"]);
  clearPageCache();
  for (let i = 0; i < CP._internal.PAGE_CACHE_MAX; i += 1) keepPage(`id${i}`, e);
  keepPage("id0", e);
  keepPage("new", e);
  const ids = cachedIds();
  assert.equal(ids.length, CP._internal.PAGE_CACHE_MAX);
  assert.ok(ids.includes("id0") && !ids.includes("id1") && ids[ids.length - 1] === "new");
  // through the page: a case whose kept page ran out, viewed again, is newest
  const a = await sealedCase("RJ3 F8 a");
  const b = await sealedCase("RJ3 F8 b");
  const t0 = REVEAL_AT + 3600000;
  clearPageCache();
  await casePage(a.id, { now: t0, cached: true });
  await casePage(b.id, { now: t0 + 1000, cached: true });
  await casePage(a.id, { now: t0 + CP.PAGE_CACHE_MS + 2000, cached: true });
  assert.deepEqual(cachedIds(), [b.id, a.id]);
  clearPageCache();
});

// =============================================================================
// The row not read is not a definite answer: such a page is not kept
// =============================================================================

test("a page with a row whose commit was not read (not_read) is not kept", async () => {
  const c = await withRow("RJ3 not read not kept");
  plantPin(c.id, chainOf(c.id), undefined);
  const t0 = REVEAL_AT + 3600000;
  await casePage(c.id, { now: t0 });
  const second = await casePage(c.id, { now: t0 + 5000, cached: true });
  assert.match(rowLine(second.html, 1), /not read: this case is not shown as pinned/, "fixture: the row is not_read");
  assert.ok(second.html.includes(`read at ${utc(t0 + 5000)}`), "read again");
});

// =============================================================================
// UNIT R-L, THE FOLLOW-UPS TO R-J3 (g1-g8); the table rows above carry g1-g5,
// g7 and g8
// =============================================================================

test("R-L g6: the preview tool reports pin_unavailable as could-not-look, never as a sealed record that does not hold", () => {
  const TOOL = require("../tools/preview_dry_run.js");
  const v = TOOL._internal.holdsVerdict({ code: "pin_unavailable", reason: "pin_pointer_unreadable", revoked: [] });
  assert.equal(v.word, "COULD NOT LOOK");
  assert.equal(v.text, "a key that signed it is revoked in the current key document, and whether its pin shows its case file written before " +
    "the revocation was recorded could not be read (pin_pointer_unreadable)");
  assert.doesNotMatch(v.text, /does not hold/);
  assert.equal(TOOL._internal.holdsVerdict({ code: "valid_under_document" }), null, "control: a record that holds");
  assert.equal(TOOL._internal.holdsVerdict({ code: "signer_revoked", reason: "case_not_pinned" }).word, "BROKEN", "control: a no");
});

test("R-L g2: one record naming a commit that never exists does not hold back the case: the record after it is read, and anchors it", async () => {
  const c = await withRow("RJ3 g2 liveness");
  const never = fresh();
  dailyAnchor(pinDay(c.id), never);
  const st0 = await S.anchorState(c.id, storedCase(c.id));
  assert.deepEqual([st0.pin, st0.anchor], ["pinned", { could_not_look: "anchor_head_not_shown", head_commit: never }], "alone: could_not_look, naming the head");
  const a = dailyAnchor(nextDay(pinDay(c.id)));
  const st = await S.anchorState(c.id, storedCase(c.id));
  assert.deepEqual([st.pin, st.anchor.path, st.anchor.head_commit], ["anchored", a.path, a.head]);
});

test("R-L g8: the R-J3 change log entry says what the table covers, not 'every pair'", () => {
  const log = fs.readFileSync(path.join(__dirname, "..", "CHANGELOG.md"), "utf8");
  const rj3 = log.slice(log.indexOf("## 2026-10-13: Unit R-J3"), log.indexOf("## 2026-10-13: Unit R-J2"));
  assert.doesNotMatch(rj3, /It lists every pair/);
});

// =============================================================================
// MUST-FAIL GAP (unit R-J3): the mutants the pass over the lines R-J3 changed
// left alive, each caught here
// =============================================================================

test("MUST-FAIL GAP (S04, P38, P42): the could-not-look page under a revoked key names the revoked key and its pin's state and reason", async () => {
  const c = await withRow("RJ3 gap revoked page");
  S._internal.clearDocumentCache();
  gh.forceGetFailure(PINS, latestOf(c.id), 1, 503);
  const page = await casePage(c.id, { keyDocument: REVOKED });
  assert.equal(page.status, 503, "fixture: the could-not-look page");
  assert.ok(page.html.includes(`<tr><th>revoked in the current key document</th><td>the case key <code>${KD.keyIdOf(CASE_KEY)}</code></td></tr>`),
    page.html.slice(page.html.indexOf("<table"), page.html.indexOf("</table>")));
  assert.ok(page.html.includes('<tr><th>its pin</th><td>could_not_look <span class="muted">(<code>pin_pointer_unreadable</code>)</span></td></tr>'));
});

test("MUST-FAIL GAP (P24): a row not read for a reason the page has no words for says it was not read, with that reason", () => {
  assert.equal(plain(CP._internal.cells.row({ state: "not_read", reason: "some_other_reason" })),
    "not read: the commit that wrote this row was not read for this page (some_other_reason); anchor state: not computed");
});

// =============================================================================
// MUST-FAIL GAP (unit R-L): the mutants the pass over the lines R-L changed
// left alive, each caught here
// =============================================================================

test("MUST-FAIL GAP (unit R-L, S23): two daily anchor records that each miss: the answer names the first one's miss", async () => {
  const c = await withRow("RL gap first miss");
  const never = fresh();
  dailyAnchor(pinDay(c.id), never);
  const later = dailyAnchor(nextDay(pinDay(c.id)));
  gh.forceGetFailure(PINS, later.path, 1, 503);
  const st = await S.anchorState(c.id, storedCase(c.id));
  assert.deepEqual([st.pin, st.anchor], ["pinned", { could_not_look: "anchor_head_not_shown", head_commit: never }]);
});

test("MUST-FAIL GAP (unit R-L, S25): a daily anchor record that could not be read is passed over: the record after it is read, and anchors the case", async () => {
  const c = await withRow("RL gap unread record");
  const first = dailyAnchor(pinDay(c.id));
  const a = dailyAnchor(nextDay(pinDay(c.id)));
  gh.forceGetFailure(PINS, first.path, 1, 503);
  const st = await S.anchorState(c.id, storedCase(c.id));
  assert.deepEqual([st.pin, st.anchor.path, st.anchor.head_commit], ["anchored", a.path, a.head]);
});

test("MUST-FAIL GAP (unit R-L, P14): the could-not-look page under a revoked key, for a pin whose commit history is longer than this service reads, does not say try again", async () => {
  const c = await withRow("RL gap revoked beyond bound");
  longHistory(seqOf(c.id));
  S._internal.clearDocumentCache();
  const page = await casePage(c.id, { keyDocument: REVOKED });
  assert.equal(page.status, 503, "fixture: the could-not-look page");
  assert.ok(page.html.includes("pin_commits_beyond_bound"));
  assert.ok(page.html.includes("This is not a no.</p>"), page.html.slice(page.html.indexOf("This is not a no") - 200, page.html.indexOf("This is not a no") + 40));
  assert.doesNotMatch(page.html, /This is not a no; try again/);
});

// =============================================================================
// UNIT R-L2, M4: an anchor miss is passed over, and a row is refused only on
// a proven anchor conflict
// =============================================================================

test("R-L2 M4 (a): a daily anchor record whose head the host does not show (its compare not_found), one whose newest commit names another head, and one whose newest commit names no head are each passed over: the record after it is read, and anchors the case", async () => {
  for (const [scope, plant, reason] of [
    ["RL2 M4 compare not found", (c) => {
      const f = fresh();
      gh.seedRaw(PINS, f, seqOf(c.id), gh._repoMap(PINS).get(seqOf(c.id)).content);
      dailyAnchor(pinDay(c.id), f);
    }, "anchor_head_not_shown"],
    ["RL2 M4 record changed", (c) => {
      const a = dailyAnchor(pinDay(c.id));
      const later = gh.seedText(PINS, `notes/later-${fresh()}.txt`, "y\n");
      gh._repoMap(PINS).get(a.path).content = `${later} ${a.claimedAt}\n`;
    }, "anchor_record_changed"],
    ["RL2 M4 record no head", (c) => noHead(c), "anchor_record_names_no_head"],
  ]) {
    const c = await withRow(scope);
    plant(c);
    const alone = await S.anchorState(c.id, storedCase(c.id));
    assert.deepEqual([alone.pin, alone.anchor && alone.anchor.could_not_look], ["pinned", reason], `${scope}: alone, a miss`);
    const a = dailyAnchor(nextDay(pinDay(c.id)));
    S._internal.clearCommitFiles();
    const st = await S.anchorState(c.id, storedCase(c.id));
    assert.deepEqual([st.pin, st.anchor && st.anchor.path], ["anchored", a.path], scope);
  }
});

test("R-L2 M4 (b): a reference row is refused only on a proven anchor conflict: an anchor that could not be looked up, a head not shown and a changed record each take the row, and a record off the branch is 409 anchor_conflict", async () => {
  const lookup = await FIXTURES.anchors_cnl();
  lookup.arm();
  assert.equal((await reference(lookup.c, "b")).status, 201, "the anchors could not be listed");
  const head = await FIXTURES.head_absent_not_shown();
  assert.equal((await reference(head.c, "b")).status, 201, "a head not shown");
  const changed = await FIXTURES.record_changed();
  assert.equal((await reference(changed.c, "b")).status, 201, "a changed record");
  const off = await FIXTURES.head_off_branch();
  const r = await reference(off.c, "b");
  assert.deepEqual([r.status, r.body.error_code], [409, "anchor_conflict"], JSON.stringify(r.body).slice(0, 300));
  assert.doesNotMatch(HTTP_SRC(), /anchor_unreadable|anchorUnreadWords|refusal of the row; try again/);
});

// =============================================================================
// UNIT R-L3 (a): the last anchor returns
// =============================================================================

test("R-L3 (a): a record whose branch answer is unknown, whose commits could not be read, or which could not be read at its commit is passed over: a later record's proven conflict is still found, and still refuses a row", async () => {
  for (const fx of ["head_branch_unreadable", "record_commit_cnl", "record_at_commit_503"]) {
    const f = await FIXTURES[fx]();
    const side = gh.seedSideCommit(PINS, fresh());
    gh.seedRaw(PINS, side, seqOf(f.c.id), gh._repoMap(PINS).get(seqOf(f.c.id)).content);
    const later = dailyAnchor(nextDay(pinDay(f.c.id)), side);
    S._internal.clearCommitFiles();
    f.arm();
    const st = await S.anchorState(f.c.id, storedCase(f.c.id));
    assert.deepEqual([st.pin, st.reason, st.anchor && st.anchor.path], ["conflict", "anchored_head_off_branch", later.path], fx);
    S._internal.clearCommitFiles();
    f.arm();
    const r = await reference(f.c, "b");
    assert.deepEqual([r.status, r.body.error_code], [409, "anchor_conflict"], `${fx}: ${JSON.stringify(r.body).slice(0, 200)}`);
  }
});

// =============================================================================
// THE REGISTRATION FILE'S STATES (unit R-L4, rule 8): what the case page
// says of a role, from the case root and the presence of a file at the
// role's path alone. A file is a claim, inert until the case root projects
// it; one the root does not project says what it is, and once the case is
// withdrawn, sealed or past its deadline, that it can never stand. A row per
// state: the fixture that makes it, the page's time, and the words.
// =============================================================================
const REG_WORDS = Object.freeze({
  projected: "registered at",
  none: "not registered",
  written_not_confirmed: "written, not confirmed",
  written_never_confirmed: "written, never confirmed; this file has no standing and cannot acquire it",
  written_under_withdrawal: "written; the case is withdrawn, so this file has no standing and cannot acquire it",
});
async function openOnly(scope) {
  const o = makeRes();
  await H.handleCaseOpen(req("case-open", opening(scope), OPEN_AUTH), o, { now: NOW });
  assert.equal(o._status, 201, JSON.stringify(o._body));
  return o._body.case_id;
}
async function commitAs(id, p, now = NOW) {
  gh.seed(STAMPS, stamp.stampPath(p.commitment_sha256), { kind: "file-stamp", v: 1, sha256: p.commitment_sha256, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: "2026-10-10T07:45:00.123Z" });
  const r = makeRes();
  await H.handleCaseCommit(req("case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 })), r, { now });
  return { status: r._status, body: parsed(r) };
}
// role a written, and the read of the case root after the write failed
async function writtenNotConfirmed(scope) {
  const id = await openOnly(scope);
  const a = party(id, "a", AGENT_TAPE);
  // at the registration's write, the case root's next read is made to fail
  const viaMock = global.fetch;
  let fired = false;
  global.fetch = async (url, o) => {
    if (!fired && (o && o.method) === "PUT" && String(url).includes(`/repos/${PINS}/contents/${C.registrationPath(id, "a")}`)) {
      fired = true;
      gh.forceGetFailure(PINS, C.casePath(id), 1, 503);
    }
    return viaMock(url, o);
  };
  let r;
  try {
    r = await commitAs(id, a);
  } finally {
    global.fetch = viaMock;
  }
  assert.deepEqual([fired, r.status], [true, 503], JSON.stringify(r.body));
  return { id, a };
}
const PAST_DEADLINE = Date.parse(DEADLINE) + 1000;
const REG_FIXTURES = {
  committed: async () => (await committedCase("RJ3 reg projected")).id,
  open: async () => openOnly("RJ3 reg none"),
  unconfirmed: async () => (await writtenNotConfirmed("RJ3 reg not confirmed")).id,
  unconfirmed_late: async () => (await writtenNotConfirmed("RJ3 reg never confirmed")).id,
  withdrawn: async () => {
    const c = await committedCase("RJ3 reg withdrawn");
    const res = makeRes();
    await H.handleCaseWithdraw(req("case-withdraw", { case_id: c.id, role: "a", tape_sha256: c.a.tape_sha256, salt: c.a.salt }), res,
      { now: NOW + 2000, env: KEYS, keyDocument: DOC });
    assert.equal(res._status, 201, JSON.stringify(parsed(res)));
    return c.id;
  },
};
const REGISTRATION_TABLE = [
  { state: "projected", fx: "committed", role: "a", now: REVEAL_AT + 3600000 },
  { state: "none", fx: "open", role: "a", now: REVEAL_AT + 3600000 },
  { state: "written_not_confirmed", fx: "unconfirmed", role: "a", now: REVEAL_AT + 3600000 },
  { state: "none", fx: "unconfirmed", role: "b", now: REVEAL_AT + 3600000 },
  { state: "written_never_confirmed", fx: "unconfirmed_late", role: "a", now: PAST_DEADLINE },
  { state: "written_under_withdrawal", fx: "withdrawn", role: "a", now: REVEAL_AT + 3600000 },
  { state: "written_under_withdrawal", fx: "withdrawn", role: "b", now: REVEAL_AT + 3600000 },
];
function registrationRows(html) {
  const i = html.indexOf("<h2>Registrations</h2>");
  return i < 0 ? "" : plain(html.slice(i, html.indexOf("</section>", i)).replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ");
}
for (const t of REGISTRATION_TABLE) {
  test(`R-L4 TABLE (registration file): ${t.fx}, role ${t.role} -> ${t.state}: "${REG_WORDS[t.state]}"`, async () => {
    const id = await REG_FIXTURES[t.fx]();
    const rows = registrationRows((await casePage(id, { now: t.now })).html);
    assert.ok(rows.includes(`role ${t.role} ${REG_WORDS[t.state]}`), rows);
    for (const [state, words] of Object.entries(REG_WORDS)) {
      if (state !== t.state) assert.ok(!rows.includes(`role ${t.role} ${words}`), `${state} is not said: ${rows}`);
    }
  });
}
