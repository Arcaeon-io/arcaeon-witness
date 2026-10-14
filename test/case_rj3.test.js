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
// Unit R-PIN (2026-10-13): THE TABLE now holds every (state, reason) pair
// pinState and servedAtCommit can return; the anchor and row readers, their
// rows and their tests went with that code.
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
  return rec;
}
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0051", url: "https://second-operator.example/cases/0051" });
async function reference(c, role = "a", ref = "row", keyDocument = DOC) {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: { ...XREF, reference: ref } }),
    res, { now: REVEAL_AT + 1800000, env: KD.deployedFor(gh, KEYS, keyDocument), keyDocument });
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
const seqOf = (id) => S.pinPaths(id).seq;
const esc = (s) => CP._internal.esc(s);

// A cell's text, its tags dropped and its entities read back.
function plain(h) {
  return String(h).replace(/<[^>]+>/g, "").replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&").trim();
}
// The page's pin line, and the sentence under it, `code` spans read back as
// backticks (unit R-PIN).
// The pin cell: the pin line, then (since unit R-PINf, f2) the fixed
// sentence directly under it, in the same cell after a line break.
function pageCells(html) {
  const m = /<tr><th>pin<\/th><td>([\s\S]*?)<br><span class="muted">([\s\S]*?)<\/span><\/td><\/tr>/.exec(html);
  assert.ok(m, `the page has a pin line with the sentence under it: ${html.slice(0, 300)}`);
  assert.ok(html.indexOf("<h2>Pin and signature</h2>") >= 0, "the page has its pin panel");
  return { pin: plain(m[1]), note: plain(m[2].replace(/<code>([^<]*)<\/code>/g, "`$1`")) };
}
function fill(t, x) {
  return t.replace(/\{(\w+)\}/g, (_, k) => {
    assert.ok(x[k] !== undefined && x[k] !== null, `the table names {${k}}, and the fixture gives it`);
    return String(x[k]);
  });
}

// =============================================================================
// THE TABLE. Since unit R-PIN every (state, reason) pair the pin read
// (pinState, with servedAtCommit for the case file at the commit its pin
// names) can return, with the pin line the case page says for it, the fixed
// sentence under it, and the reference's answer (201: no row reads the pin).
// Rows of the anchor lookup, the pointer, next pins and row commits are gone
// with that machinery. A sentence is the cell's text with its tags dropped;
// {name} is filled from the fixture. Each row is a test below, against a
// fixture that makes the pair.
// =============================================================================

// What a pin_commit_mismatch reason says (lib/_case_page.js mismatchWords).
const MISMATCH = {
  differs: (f) => `the ${f} at that commit is not this ${f} in canonical form (json-c14n:v1)`,
  absent: (f) => `the pins repository holds no ${f} at that commit`,
  not_found: "that commit is not shown by the repository", // unit R-L (g4): one wording, and "yet" only for could_not_look
  off_branch: "that commit is not on the published branch of the pins repository",
  other: (f) => `the ${f} there is not shown to be this ${f} in canonical form (json-c14n:v1)`,
};
// What a could_not_look reason says, of the pin or the case file.
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
// What a conflict's reason says (lib/_case_seal.js conflictWords).
const CONFLICT_WORDS = {
  pin_holds_another_chain: "the pin file under this case's namespace holds another chain",
  pin_at_its_commit_holds_another_chain: "the pin record, read at the commit that wrote it, holds another chain",
  pin_at_its_commit_not_a_pin: "the record at this case's pin path, read at the commit that wrote it, is not a pin record for this case",
  pin_at_its_commit_not_json: "the pin record at the commit that wrote it could not be read as a pin",
};

// THE PIN LINE (lib/_case_page.js pinnedHtml), and the sentence once under it.
const T = {
  PINNED: "Pinned at commit {pin_commit} (the pins repository's commit time, {pin_date})",
  NOT_PINNED: "Not pinned: no pin file is present under this case's namespace (not_pinned).",
  MISMATCH: "pin_commit_mismatch: its pin names commit {case_commit} for the case file, and {words} ({reason}), so the case is not shown as pinned.",
  CONFLICT: "conflict: {words} ({reason}). This service never writes over a pin; the case file is the authority.",
  UNREADABLE: "unreadable: a record is present at this case's pin path and cannot be read as a case seal record ({reason}).",
  READ_FAILED: "could_not_look: this case's pin could not be read when this page was read (pin_read_failed), so nothing is claimed about it.",
  CNL: "could_not_look: {words} ({reason}), so the case is not shown as pinned.",
  NOTE: "Daily anchor records and their OpenTimestamps proofs are in `anchors/` in the pins repository; this page does not check them, " +
    "and you can check one yourself by running `ots verify` on the proof file beside the record.",
};
const R201 = [201];
// pinState given a chain (tools/preview_dry_run.js): never the page's or the reference's
const NOT_REACHED = null;
const row = (fx, state, reason, pin, words, response = R201) => ({ from: "pinState", fx, state, reason, pin, words, response });

// Each reason the seal judge (lib/_verdict.js judgeCaseSeal) gives a pin
// file, with a pin that makes it (the stored pin, changed on the branch)
const JUDGE_PINS = {
  not_a_json_object: () => [1, 2],
  case_seal_unknown_field: (p) => ({ ...p, extra: 1 }),
  case_seal_missing_field: (p) => { const { auth_note: _a, ...q } = p; return q; }, // eslint-disable-line no-unused-vars
  case_seal_wrong_record_kind: (p) => ({ ...p, record_kind: "pin" }),
  case_seal_wrong_auth_level: (p) => ({ ...p, auth_level: "bearer" }),
  case_seal_namespace_unreadable: (p) => ({ ...p, namespace: "not/a/case" }),
  namespace_mismatch: (p) => ({ ...p, namespace: `case/${"0".repeat(64)}` }),
  case_seal_wrong_rows: (p) => ({ ...p, rows: 7 }),
  case_seal_wrong_seq: (p) => ({ ...p, seq: 2 }),
  chain_unreadable: (p) => ({ ...p, chain: "not hex" }),
  case_seal_pinned_at_unreadable: (p) => ({ ...p, pinned_at: "yesterday" }),
  case_seal_auth_note_unreadable: (p) => ({ ...p, auth_note: " " }),
  case_seal_case_commit_unreadable: (p) => ({ ...p, case_commit: "C".repeat(40) }),
};

const TABLE = [
  row("pinned", "pinned", null, T.PINNED),
  row("not_pinned", "not_pinned", null, T.NOT_PINNED),
  // a pin without case_commit is unreadable (unit R-PIN, rule 2)
  row("no_case_commit", "unreadable", "case_seal_missing_field", T.UNREADABLE),
  row("unreadable", "unreadable", "case_seal_unknown_field", T.UNREADABLE),
  row("pin_not_json", "unreadable", "pin_not_json", T.UNREADABLE),
  ...Object.keys(JUDGE_PINS).filter((r) => r !== "case_seal_unknown_field" && r !== "case_seal_missing_field")
    .map((reason) => row(`unreadable_${reason}`, "unreadable", reason, T.UNREADABLE)),
  row("pin_file_other_chain", "conflict", "pin_holds_another_chain", T.CONFLICT, CONFLICT_WORDS.pin_holds_another_chain),
  row("pin_read_cnl", "could_not_look", "pin_read_failed", T.READ_FAILED),
  row("pin_commit_cnl", "could_not_look", "pin_commit_unreadable", T.CNL, CNL.pin_commit),
  row("pin_commits_beyond", "could_not_look", "pin_commits_beyond_bound", T.CNL, CNL.pin_commits_beyond_bound),
  row("pin_commits_none", "could_not_look", "pin_commits_none", T.CNL, CNL.pin_commits_none),
  row("pin_text", "conflict", "pin_at_its_commit_not_json", T.CONFLICT, CONFLICT_WORDS.pin_at_its_commit_not_json),
  row("pin_raw_503", "could_not_look", "pin_at_commit_http_503", T.CNL, CNL.pin_at_commit),
  row("pin_raw_404", "could_not_look", "pin_at_commit_http_404", T.CNL, CNL.pin_at_commit),
  row("pin_raw_failed", "could_not_look", "pin_at_commit_fetch_failed", T.CNL, CNL.pin_at_commit),
  row("pin_raw_500", "could_not_look", "pin_at_commit_http_500", T.CNL, CNL.pin_at_commit),
  row("pin_other_chain", "conflict", "pin_at_its_commit_holds_another_chain", T.CONFLICT, CONFLICT_WORDS.pin_at_its_commit_holds_another_chain),
  row("pin_judge_fails", "conflict", "pin_at_its_commit_not_a_pin", T.CONFLICT, CONFLICT_WORDS.pin_at_its_commit_not_a_pin),
  row("pin_other_seq", "conflict", "pin_at_its_commit_not_a_pin", T.CONFLICT, CONFLICT_WORDS.pin_at_its_commit_not_a_pin),
  // servedAtCommit, for the case file at the commit its pin names
  row("case_differs", "pin_commit_mismatch", "case_at_commit_differs", T.MISMATCH, MISMATCH.differs("case file")),
  row("case_absent", "pin_commit_mismatch", "case_absent_at_commit", T.MISMATCH, MISMATCH.absent("case file")),
  row("case_not_found", "pin_commit_mismatch", "case_commit_not_found", T.MISMATCH, MISMATCH.not_found),
  row("case_off_branch", "pin_commit_mismatch", "case_commit_off_branch", T.MISMATCH, MISMATCH.off_branch),
  row("case_not_shown", "could_not_look", "case_commit_not_shown", T.CNL, CNL.not_shown),
  row("case_raw_503", "could_not_look", "case_at_commit_http_503", T.CNL, CNL.at_commit("case file")),
  row("case_raw_failed", "could_not_look", "case_at_commit_fetch_failed", T.CNL, CNL.at_commit("case file")),
  row("case_raw_429", "could_not_look", "case_at_commit_http_429", T.CNL, CNL.at_commit("case file")),
  row("case_exists_503", "could_not_look", "case_commit_exists_http_503", T.CNL, CNL.exists),
  row("case_exists_failed", "could_not_look", "case_commit_exists_read_failed", T.CNL, CNL.exists),
  row("case_exists_500", "could_not_look", "case_commit_exists_http_500", T.CNL, CNL.exists),
  row("case_compare_503", "could_not_look", "case_commit_compare_http_503", T.CNL, CNL.on_branch),
  row("case_compare_failed", "could_not_look", "case_commit_compare_failed", T.CNL, CNL.on_branch),
  row("case_compare_500", "could_not_look", "case_commit_compare_http_500", T.CNL, CNL.on_branch),
  row("case_branch", "could_not_look", "case_commit_branch_unreadable", T.CNL, CNL.on_branch),
  row("case_branch_name", "could_not_look", "case_commit_branch_name_invalid", T.CNL, CNL.on_branch),
  // pinState given a chain (tools/preview_dry_run.js)
  { ...row("chain_case_unreadable", "could_not_look", "case_unreadable", T.CNL, CNL.file("case file"), NOT_REACHED), from: "pinState (chain)" },
  { ...row("chain_served_differs", "pin_commit_mismatch", "case_served_differs", T.MISMATCH, MISMATCH.other("case file"), NOT_REACHED),
    from: "pinState (chain)" },
];

// A sealed case with reference row 1.
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
// The pin file on the branch given `text`, its commit history kept.
function onBranch(id, text) {
  gh._repoMap(PINS).get(seqOf(id)).content = text;
}
// A path's history made longer than lib/_case_seal.js reads (fifty pages):
// a page of one commit each, and more commits than pages (unit R-L, g5).
function longHistory(p) {
  gh.commitsPageCap = 1;
  for (let i = 0; i < S._internal.COMMIT_LIST_PAGES + 5; i += 1) gh.addCommit(PINS, p, "mock: one more commit");
}
// A path the repository lists no commit for (unit R-L, g5).
function noHistory(p) {
  const list = gh._commitsOf(PINS);
  for (let i = list.length - 1; i >= 0; i -= 1) if (list[i].path === p) list.splice(i, 1);
}
const cnlCompare = (sha, status) => () => {
  S._internal.clearDocumentCache();
  gh.forceCompareFailure(1, status, `...${sha}`);
};

// Each fixture -> {c, arm (the one-shot failure, set again before each
// read), chain (pinState given a chain), cleanup}.
const FIXTURES = {
  pinned: async () => ({ c: await withRow("RJ3 pinned") }),
  not_pinned: async () => {
    const c = await committedCase("RJ3 not pinned");
    gh.forceFailure(PINS, seqOf(c.id), 1, 502);
    assert.equal((await reveal(c)).status, 201);
    const r = await reference(c, "a", "row-1");
    assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
    return { c };
  },
  no_case_commit: async () => {
    const c = await withRow("RJ3 no case commit");
    const { case_commit: _cc, ...rest } = sealPin(c.id); // eslint-disable-line no-unused-vars
    onBranch(c.id, json(rest));
    return { c };
  },
  unreadable: async () => {
    const c = await withRow("RJ3 unreadable");
    onBranch(c.id, json({ not: "a pin" }));
    return { c };
  },
  pin_not_json: async () => {
    const c = await withRow("RJ3 pin not json");
    onBranch(c.id, "not json\n");
    return { c };
  },
  pin_file_other_chain: async () => {
    const c = await withRow("RJ3 pin file chain");
    onBranch(c.id, json({ ...sealPin(c.id), chain: sha("another chain") }));
    return { c };
  },
  pin_read_cnl: async () => {
    const c = await withRow("RJ3 pin read cnl");
    return { c, arm: () => gh.forceGetFailure(PINS, seqOf(c.id), 1, 503) };
  },
  pin_commit_cnl: async () => {
    const c = await withRow("RJ3 pin commit cnl");
    return { c, arm: () => gh.forceCommitsFailure(PINS, seqOf(c.id), 1, 503) };
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
  pin_raw_500: async () => {
    const c = await withRow("RJ3 pin raw 500");
    return { c, arm: () => gh.forceRawFailure(1, 500, `:${seqOf(c.id)}`) };
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
  case_raw_429: async () => {
    const c = await withRow("RJ3 case raw 429");
    return { c, arm: () => gh.forceRawFailure(1, 429, `:${C.casePath(c.id)}`) };
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
  case_exists_500: async () => {
    const e = early();
    const c = await withRow("RJ3 case exists 500");
    plantPin(c.id, chainOf(c.id), e);
    return { c, arm: () => gh.forceCommitFailure(1, 500) };
  },
  case_compare_503: async () => {
    const c = await withRow("RJ3 case compare 503");
    return { c, arm: cnlCompare(sealCommit(c.id), 503) };
  },
  case_compare_failed: async () => {
    const c = await withRow("RJ3 case compare failed");
    return { c, arm: cnlCompare(sealCommit(c.id), 0) };
  },
  case_compare_500: async () => {
    const c = await withRow("RJ3 case compare 500");
    return { c, arm: cnlCompare(sealCommit(c.id), 500) };
  },
  case_branch: async () => {
    const c = await withRow("RJ3 case branch");
    const f = fresh();
    gh.seedRaw(PINS, f, C.casePath(c.id), caseText(c.id));
    plantPin(c.id, chainOf(c.id), f);
    return { c, arm: () => { S._internal.clearDocumentCache(); gh.forceBranchFailure(1, 503); } };
  },
  case_branch_name: async () => {
    const c = await withRow("RJ3 case branch name");
    const was = store.BRANCH;
    store.BRANCH = "not a branch name";
    return { c, cleanup: () => { store.BRANCH = was; } };
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
};
// each reason the seal judge gives, by the pin file on the branch
for (const [reason, make] of Object.entries(JUDGE_PINS)) {
  FIXTURES[`unreadable_${reason}`] = async () => {
    const c = await withRow(`RJ3 unreadable ${reason}`);
    onBranch(c.id, json(make(sealPin(c.id))));
    return { c };
  };
}

// The names a sentence may use, read off the fixture as it stands.
function namesOf(f, t) {
  const { id } = f.c;
  const m = gh._repoMap(PINS);
  const wrote = gh.commitsFor(PINS, seqOf(id)).slice(-1)[0];
  let pin = null;
  try {
    pin = m.has(seqOf(id)) ? JSON.parse(m.get(seqOf(id)).content) : null;
  } catch {
    pin = null;
  }
  return {
    state: t.state, reason: t.reason, words: t.words,
    pin_commit: wrote && s12(wrote.sha), pin_date: wrote && wrote.date,
    case_commit: pin && typeof pin.case_commit === "string" ? s12(pin.case_commit) : undefined,
  };
}

for (const t of TABLE) {
  test(`THE TABLE: ${t.from}, ${t.state}${t.reason ? ` / ${t.reason}` : ""} (${t.fx}): the pin line, the sentence under it, and the reference's answer`, async () => {
    const f = await FIXTURES[t.fx]();
    try {
      await tableRow(t, f);
    } finally {
      if (f.cleanup) f.cleanup();
    }
  });
}
async function tableRow(t, f) {
  const { id } = f.c;
  const x = namesOf(f, t);
  const arm = () => {
    S._internal.clearCommitFiles();
    S._internal.clearDocumentCache();
    if (f.arm) f.arm();
  };
  // the pair, as pinState returns it
  arm();
  const st = f.chain ? await S.pinState(id, f.chain) : await S.pinState(id, storedCase(id));
  assert.deepEqual([st.pin, st.reason ?? null], [t.state, t.reason], `the fixture makes the pair: ${JSON.stringify(st).slice(0, 300)}`);
  const want = { pin: fill(t.pin, x), note: T.NOTE };
  if (f.chain) {
    // never the page's: its pin line, from the page's own function
    assert.deepEqual({ pin: plain(CP._internal.cells.pin(st)), note: T.NOTE }, want);
    assert.equal(t.response, NOT_REACHED);
    return;
  }
  // the page
  arm();
  const page = await casePage(id);
  assert.equal(page.status, 200, page.html.slice(0, 300));
  assert.deepEqual(pageCells(page.html), want);
  assert.doesNotMatch(page.html, /anchored/i);
  // the reference's answer: no pin is read for a row (unit R-PIN)
  arm();
  const r = await reference(f.c, "b", "probe");
  assert.equal(r.status, t.response[0], JSON.stringify(r.body).slice(0, 400));
}

// =============================================================================
// BL2: the words the table's rows use
// =============================================================================

test("BL2: conflictWords says 'holds another chain' only for the two *_holds_another_chain reasons; *_not_a_pin says the record there is not a pin record for this case", () => {
  for (const [reason, words] of Object.entries(CONFLICT_WORDS)) {
    assert.equal(S.conflictWords(reason), words, reason);
    if (!reason.endsWith("_holds_another_chain")) assert.doesNotMatch(S.conflictWords(reason), /another chain/, reason);
  }
  assert.match(S.conflictWords("pin_at_its_commit_not_a_pin"), /is not a pin record for this case$/);
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
// F8: a page kept again moves to the newest place in the eviction order
// =============================================================================

// =============================================================================
// The row not read is not a definite answer: such a page is not kept
// =============================================================================

// =============================================================================
// UNIT R-L, THE FOLLOW-UPS TO R-J3 (g1-g8); the table rows above carry g1-g5,
// g7 and g8
// =============================================================================

test("R-L g8: the R-J3 change log entry says what the table covers, not 'every pair'", () => {
  const log = fs.readFileSync(path.join(__dirname, "..", "CHANGELOG.md"), "utf8");
  const rj3 = log.slice(log.indexOf("## 2026-10-13: Unit R-J3"), log.indexOf("## 2026-10-13: Unit R-J2"));
  assert.doesNotMatch(rj3, /It lists every pair/);
});

// =============================================================================
// MUST-FAIL GAP (unit R-J3): the mutants the pass over the lines R-J3 changed
// left alive, each caught here
// =============================================================================

// =============================================================================
// MUST-FAIL GAP (unit R-L): the mutants the pass over the lines R-L changed
// left alive, each caught here
// =============================================================================

// =============================================================================
// UNIT R-L2, M4: an anchor miss is passed over, and a row is refused only on
// a proven anchor conflict
// =============================================================================

// =============================================================================
// UNIT R-L3 (a): the last anchor returns
// =============================================================================

// =============================================================================
// THE REGISTRATION FILE'S STATES (unit R-L4, rule 8): what the case page
// says of a role, from the case root and the presence of a file at the
// role's path alone. A file is a claim, inert until the case root projects
// it; one the root does not project says what it is, and once the case is
// withdrawn, sealed or past its deadline, that it can never stand. A row per
// state: the fixture that makes it, the page's time, and the words.
// =============================================================================
// Since unit R-L4c (c4, as the architect ruled) the page lists no claim
// file: a role the root does not project has no confirmed registration,
// whether or not a claim file was written for it, and the WITHDRAWN and
// EXPIRED pages show no registration rows (no_rows).
const REG_WORDS = Object.freeze({
  projected: "registered at",
  not_confirmed: "no registration is confirmed for this role",
  no_rows: null,
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
    if (!fired && (o && o.method) === "PUT" && String(url).includes(`/repos/${PINS}/contents/${REG.dirOf(id, "a")}/`)) {
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
      { now: NOW + 2000, env: KD.deployedFor(gh, KEYS, DOC), keyDocument: DOC });
    assert.equal(res._status, 201, JSON.stringify(parsed(res)));
    return c.id;
  },
};
const REGISTRATION_TABLE = [
  { state: "projected", fx: "committed", role: "a", now: REVEAL_AT + 3600000 },
  { state: "not_confirmed", fx: "open", role: "a", now: REVEAL_AT + 3600000 },
  { state: "not_confirmed", fx: "unconfirmed", role: "a", now: REVEAL_AT + 3600000 },
  { state: "not_confirmed", fx: "unconfirmed", role: "b", now: REVEAL_AT + 3600000 },
  { state: "no_rows", fx: "unconfirmed_late", role: "a", now: PAST_DEADLINE },
  { state: "no_rows", fx: "withdrawn", role: "a", now: REVEAL_AT + 3600000 },
  { state: "no_rows", fx: "withdrawn", role: "b", now: REVEAL_AT + 3600000 },
];
function registrationRows(html) {
  const i = html.indexOf("<h2>Registrations</h2>");
  return i < 0 ? "" : plain(html.slice(i, html.indexOf("</section>", i)).replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ");
}
for (const t of REGISTRATION_TABLE) {
  test(`R-L4 TABLE (registration file): ${t.fx}, role ${t.role} -> ${t.state}: "${REG_WORDS[t.state]}"`, async () => {
    const id = await REG_FIXTURES[t.fx]();
    const html = (await casePage(id, { now: t.now })).html;
    const rows = registrationRows(html);
    if (REG_WORDS[t.state] === null) assert.equal(rows, "", "no registration rows");
    else assert.ok(rows.includes(`role ${t.role} ${REG_WORDS[t.state]}`), rows);
    for (const [state, words] of Object.entries(REG_WORDS)) {
      if (state !== t.state && words !== null) assert.ok(!rows.includes(`role ${t.role} ${words}`), `${state} is not said: ${rows}`);
    }
    assert.doesNotMatch(html, /written, not confirmed|never confirmed|cannot acquire/);
  });
}

// THE INCONSISTENT RECORD (unit R-L4b; its words since unit R-L4e): a case
// whose projected registration file is missing, or is not the file
// projected, or whose root entry its file does not hold. One row per reason:
// the page is 503, says one sentence and shows no registration row; the
// reason is not on the page (it goes to the operator log).
const INCONSISTENT_SENTENCE = "The stored record for this case does not agree with itself. Nothing is asserted about this case while that is so.";
const INCONSISTENT_TABLE = [
  { reason: "registration_file_differs", how: (id, p) => { gh._repoMap(PINS).get(p).content += " "; } },
  { reason: "registration_file_missing", how: (id, p) => { gh._repoMap(PINS).delete(p); } },
  { reason: "projection_differs_from_file", how: (id) => {
    const k = gh.read(PINS, C.casePath(id));
    gh.seed(PINS, C.casePath(id), { ...k, commitments: { ...k.commitments, a: { ...k.commitments.a, registered_at: "2026-10-10T07:59:00Z" } } }, { keepHistory: true });
  } },
];
for (const t of INCONSISTENT_TABLE) {
  test(`R-L4e TABLE (inconsistent record): ${t.reason} -> 503: "${INCONSISTENT_SENTENCE}"`, async () => {
    const c = await committedCase(`RJ3 inconsistent ${t.reason}`);
    t.how(c.id, REG.pathOf(gh, c.id, "a"));
    const page = await casePage(c.id, { now: NOW + 5000 });
    assert.equal(page.status, 503);
    assert.ok(page.html.includes(CP._internal.esc(INCONSISTENT_SENTENCE)), page.html.slice(0, 1500));
    assert.equal(registrationRows(page.html), "", "no registration rows");
    assert.equal(page.html.includes(t.reason), false, "the reason is not on the page");
  });
}
