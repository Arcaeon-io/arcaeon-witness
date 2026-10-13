// test/case_rl2.test.js — unit R-L2 (2026-10-13): fixes from the second
// reader's pass over R-L at c7ccdb2. Two false sentences on the case page's
// Removals panel blocked the unit:
//   B1  a repair note records that a removal was DECIDED, not that it
//       happened: the panel says what it read at the note's path, and the
//       sealer completes every recorded removal whose file is still there,
//       unless the case sealed with that registration;
//   B2  a note that could not be verified is not "removed without a record";
//   M1  a note is keyed on the file it removes (path, blob, creating commit);
//   M2  the withdrawal's 503 after a lost write says which of two things
//       happened;
//   M3  a case holds at most 500 reference rows;
//   M4  (in test/case_rj3.test.js) anchor misses continue, and a row is
//       refused only on a proven anchor conflict;
//   and the minors (L4's lost withdrawals here; L2, the guard and the legacy
//   auth_note in test/case_rl.test.js).
// The setup below is test/case_rl.test.js's.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0141:case-test-";
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
const USAGE = process.env.GITHUB_USAGE_REPO;
const STAMPS = process.env.STAMP_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z");
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rl2");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rl2");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rl2");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0141" });

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
  KD.serve(gh, DOC);
});
afterEach(() => {
  store._putRetry.sleep = realSleep;
  restore();
});

let ipSeq = 0;
const nextIp = () => {
  ipSeq += 1;
  return `10.92.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
};
function req(op, body, headers = {}) {
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": nextIp(), ...headers }, body });
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
function party(caseId, role, tape, key = undefined) {
  const salt = C.newSalt();
  const tape_sha256 = sha(tape);
  return { role, tape, tape_sha256, salt, key, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
}
async function openCase(scope) {
  const o = makeRes();
  await H.handleCaseOpen(req("case-open", opening(scope), OPEN_AUTH), o, { now: NOW });
  assert.equal(o._status, 201, JSON.stringify(o._body));
  return o._body.case_id;
}
function plantStamp(hash) {
  gh.seed(STAMPS, stamp.stampPath(hash), { kind: "file-stamp", v: 1, sha256: hash, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: "2026-10-10T07:45:00.123Z" });
}
// unit R-L (L3): the commit path signs a repair note before it removes
// anything, so it runs with a deployment's environment and key document
const deployedEnv = (env = KEYS) => KD.deployed(gh, env, DOC);
async function commit(id, p, now = NOW, extra = {}) {
  const res = makeRes();
  const body = REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 }, p.key);
  await H.handleCaseCommit(req("case-commit", body), res, { now, env: deployedEnv(), keyDocument: DOC, ...extra });
  return { status: res._status, body: parsed(res) };
}
async function register(id, p) {
  plantStamp(p.commitment_sha256);
  const r = await commit(id, p);
  assert.equal(r.status, 201, JSON.stringify(r.body));
}
async function withdraw(id, p, { now = NOW + 2000, env = KEYS, salt = p.salt } = {}) {
  const res = makeRes();
  await H.handleCaseWithdraw(req("case-withdraw", { case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt }), res, { now, env, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
async function committedCase(scope, keys = {}) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE, keys.a);
  const b = party(id, "b", TOOL_TAPE, keys.b);
  for (const p of [a, b]) await register(id, p);
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
// The requester's own refusal request (N3): its role named, and its own opening.
const ownOpening = (c, role) => ({ ...revealBody(c.id, c.a, c.b), role });
async function reveal(c, { now = REVEAL_AT, env = KEYS, keyDocument = DOC, body = revealBody(c.id, c.a, c.b) } = {}) {
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", body), res, { now, env: KD.deployed(gh, env, keyDocument), keyDocument });
  return { status: res._status, body: parsed(res) };
}
async function sealedCase(scope, keys = {}) {
  const c = await committedCase(scope, keys);
  const r = await reveal(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  return { ...c, r };
}
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0141", url: "https://second-operator.example/cases/0141" });
async function reference(c, { role = "a", env = KEYS, now = REVEAL_AT + 1800000 } = {}) {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: XREF }),
    res, { now, env, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
async function casePage(id, now = REVEAL_AT + 3600000) {
  const res = makeRes();
  CP._internal.clearPageCache(); // unit R-J (J7): each view here reads afresh
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": nextIp() } }), res,
    { now, keyDocument: DOC, env: {} });
  return { status: res._status, html: String(res._body) };
}
async function reconcileCall(tapeA, tapeB, { env = KEYS } = {}) {
  const res = makeRes();
  await RECONCILE.handleReconcile(makeReq({ method: "POST", query: { op: "reconcile" }, headers: { "content-type": "application/json", "x-forwarded-for": nextIp() },
    body: { agent_tape: tapeA.toString("utf-8"), tool_tape: tapeB.toString("utf-8") } }), res, { env, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
// Run `inner` when the first request matching `match` goes out, then let
// that request through.
async function during(match, inner, outer) {
  const viaMock = global.fetch;
  let got;
  let fired = false;
  global.fetch = async (url, o) => {
    if (!fired && match(String(url), (o && o.method) || "GET")) {
      fired = true;
      got = await inner();
    }
    return viaMock(url, o);
  };
  try {
    const out = await outer();
    return { out, inner: got, fired };
  } finally {
    global.fetch = viaMock;
  }
}
const storedCase = (id) => gh.read(PINS, C.casePath(id));
const lockOf = (id) => gh.read(USAGE, H._internal.caseLockPath(id));
const UNREG = require("../lib/_case_unregister.js");
const pinsPaths = () => [...gh._repoMap(PINS).keys()];
const esc = (s) => CP._internal.esc(s);
const sealerRun = (dt = 60000, env = deployedEnv()) => S.anchorPending({ now: REVEAL_AT + 3600000 + dt, keyDocument: DOC, env });
const read = (rel) => fs.readFileSync(path.join(__dirname, "..", rel), "utf8");
const README = () => read("README.md").replace(/\s+/g, " ");
function jsFiles(dir) {
  const out = [];
  for (const e of fs.readdirSync(path.join(__dirname, "..", dir), { withFileTypes: true })) {
    const rel = `${dir}/${e.name}`;
    if (e.isDirectory()) out.push(...jsFiles(rel));
    else if (/\.(js|mjs|cjs|json|html)$/.test(e.name)) out.push(rel);
  }
  return out;
}
// The commit that wrote the WITHDRAWN case file: nothing writes over it.
const withdrawalCommit = (id) => gh.commitsFor(PINS, C.casePath(id))[0].sha;
// The race lost after the write (the commit's lease ran out and the
// withdrawal took it over). `deleteFails`: the removal refused; `noteFails`:
// every write under the case's removals/ refused while the race runs (since
// unit R-L2, M1, a note's path names the file's blob and creating commit, so
// it is not known before the write); `commitEnv`: the commit path's
// environment. -> the case, the registration as written (its blob, the
// commit that created it, its bytes) and the note path for that file.
async function lostRace(scope, { deleteFails = false, noteFails = false, commitEnv } = {}) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const rpath = C.registrationPath(id, "b");
  const late = NOW + 1000 + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000;
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    const method = (o && o.method) || "GET";
    if (deleteFails && method === "DELETE") return { ok: false, status: 500, json: async () => ({}), text: async () => "" };
    if (noteFails && method === "PUT" && String(url).includes(`/contents/removals/${id}/`)) {
      return { ok: false, status: 502, json: async () => ({ message: "mock: refused" }), text: async () => "mock: refused" };
    }
    return viaMock(url, o);
  };
  let r;
  try {
    r = await during(
      (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
      () => withdraw(id, a, { now: late }),
      () => commit(id, b, NOW + 1000, commitEnv ? { env: commitEnv } : {}),
    );
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body));
  assert.equal(r.out.body.error_code, "case_withdrawn", JSON.stringify(r.out.body));
  return { id, a, b, rpath, out: r.out.body, ...asWritten(rpath, id) };
}
// The registration at `rpath` as its write left it: its blob (the mock's
// PUT log), the commit that created it and its bytes (the oldest commit
// touching the path since the newest removal), and the note path for that file.
function asWritten(rpath, id) {
  const list = gh.commitsFor(PINS, rpath).slice().reverse(); // oldest first
  let created = null;
  list.forEach((cm, k) => {
    if (cm.content !== null && (k === 0 || list[k - 1].content === null)) created = cm;
  });
  const blob = gh.putLog.filter((p) => p.path === rpath).at(-1).sha;
  return { blob, created: created.sha, text: created.content, notePath: S.repairNotePath(id, rpath, blob, created.sha) };
}
// The blob a removal named (the mock's DELETE log).
const removedBlob = (p) => (gh.deleteLog.find((d) => d.path === p) || {}).sha;
const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const CLAIM = "Withdrawal before the reveal closes that case; it does not recall a tape a counterparty already holds, and no verdict ever " +
  "binds a key that did not sign in the case that produced it.";
const LEGACY = "Files under withdrawn_commitments/ that a pins repository may hold from before this release are ignored: no code reads " +
  "or writes them.";
const CREATE_ONLY = "This repository is create-only except for removals that carry a signed repair note.";
const REVOCATION = "A key once shown revoked by a valid marker stays revoked. If the marker file is later removed, the answer is that the " +
  "marker cannot be read, never that the key is trusted again.";
const DATES = "Dates in a key document are shown for information and are not enforced; a key is judged by its status in the named document.";
const NOTE_FIELDS = ["kind", "v", "case_id", "removed_path", "removed_blob_sha", "removed_file_sha256", "reason", "withdrawal_commit", "at",
  "signed_under", "signed_by", "sig", "sig_reason"];

// A case whose registration of role a could not be confirmed after its
// write (the case read failed): the commit path records a removal of that
// file (registration_unconfirmed). `deleteFails`: the removal itself refused.
async function unconfirmed(scope, { deleteFails = false, id = null, a = null, now = NOW } = {}) {
  id = id || (await openCase(scope));
  a = a || party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const rpath = C.registrationPath(id, "a");
  const viaMock = global.fetch;
  if (deleteFails) {
    global.fetch = async (url, o) => ((o && o.method) === "DELETE" ? { ok: false, status: 500, json: async () => ({}), text: async () => "" } : viaMock(url, o));
  }
  let r;
  try {
    r = await during(
      (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
      async () => gh.forceGetFailure(PINS, C.casePath(id), 1, 503),
      () => commit(id, a, now),
    );
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(r.out.body.error_code, "registration_unconfirmed", JSON.stringify(r.out.body));
  return { id, a, rpath, out: r.out.body, ...asWritten(rpath, id) };
}
// A signed note, as this service writes one, for the file at `rpath` now.
function noteFor(id, rpath, { reason = "registration_unconfirmed", withdrawal = null, signer = S.loadCaseSigner(KEYS, { keyDocument: DOC }) } = {}) {
  const cur = gh._repoMap(PINS).get(rpath);
  const created = gh.commitsFor(PINS, rpath)[0].sha;
  const at = C.utcSeconds(NOW + 9000);
  const note = S.repairNote({ caseId: id, removedPath: rpath, removedBlobSha: cur.sha, createdInCommit: created, removedFileSha256: sha(cur.content),
    reason, withdrawalCommit: withdrawal, at, signedUnder: KD.signedUnder(gh, DOC, at) }, signer);
  return { note, notePath: S.repairNotePath(id, rpath, cur.sha, created) };
}
const render = (id, nowMs, doc = DOC) => CP._internal.renderCase(storedCase(id), nowMs, doc);
// The removals panel, as plain text.
function panelOf(html) {
  const i = html.indexOf("<h2>Removals</h2>");
  if (i < 0) return "";
  return html.slice(i, html.indexOf("</section>", i)).replace(/<[^>]+>/g, " ").replace(/&#39;/g, "'").replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&").replace(/\s+/g, " ");
}

// B1: the words, exactly
const RECORDED = (reason) => `a removal of this file was recorded for ${reason}`;
const NOT_MADE = "a repair note is written; the removal has not been made";
const REPLACED = "removed; another file is at that path now";
const SEALED_STOOD = "a repair note was written and the removal was not made; the registration stood and the case sealed";
const COMPLETION = "The sealer's runs complete a recorded removal whose file is still at its path, for every reason, without a second " +
  "note, unless the case has sealed with that registration: then nothing is removed, and the case page says a repair note was written " +
  "and the removal was not made; the registration stood and the case sealed.";
// B2
const UNVERIFIED = (p, r) => `${p} was removed; its repair note could not be verified when this page was read (${r})`;
const INVALID = (p, r) => `${p} was removed; its repair note does not verify (${r})`;
const UNRECORDED = (p) => `a file under this case was removed without a record: ${p}`;

// =============================================================================
// B1: a repair note records a removal decided, and the panel says what was read
// =============================================================================

test("R-L2 B1: each repair note is described as a removal recorded for its reason, and the panel says what it read at the note's path: the same file still there, nothing there, or another file there", async () => {
  const x = await lostRace("RL2 B1 states", { deleteFails: true });
  const p1 = panelOf((await casePage(x.id)).html);
  assert.ok(p1.includes(RECORDED("registration_after_withdrawal")), p1);
  assert.ok(p1.includes(`; ${NOT_MADE}; signed by`), p1);
  assert.doesNotMatch(p1, /removed for|a file is at that path/);
  // nothing at the path now
  gh._repoMap(PINS).delete(x.rpath);
  gh.addCommit(PINS, x.rpath, "mock: removed");
  const p2 = panelOf((await casePage(x.id)).html);
  assert.ok(p2.includes("; removed; signed by"), p2);
  assert.doesNotMatch(p2, /removed without a record/);
  // another file at the path now
  gh.seed(PINS, x.rpath, { another: "file" }, { keepHistory: true });
  const p3 = panelOf((await casePage(x.id)).html);
  assert.ok(p3.includes(`; ${REPLACED}; signed by`), p3);
});

test("R-L2 B1: the sealer completes a recorded removal whose file is still at its path, for registration_unconfirmed as for registration_after_withdrawal, without a second note", async () => {
  const u = await unconfirmed("RL2 B1 completes unconfirmed", { deleteFails: true });
  assert.deepEqual([u.out.registration_removed, gh.has(PINS, u.rpath), gh.has(PINS, u.notePath)], [false, true, true], "fixture: a note, and the file");
  assert.equal(gh.read(PINS, u.notePath).reason, "registration_unconfirmed");
  const run = await sealerRun();
  assert.equal(gh.has(PINS, u.rpath), false, "the recorded removal is made");
  assert.equal(gh.commitsFor(PINS, u.notePath).length, 1, "one note, written once");
  assert.deepEqual(run.removals_completed.find((e) => e.case_id === u.id), { case_id: u.id, completed: [u.rpath], sealed: [], unknown: [] });
  const panel = panelOf((await casePage(u.id)).html);
  assert.ok(panel.includes(RECORDED("registration_unconfirmed")) && panel.includes("; removed; signed by"), panel);
  // and for registration_after_withdrawal
  const x = await lostRace("RL2 B1 completes after withdrawal", { deleteFails: true });
  await sealerRun(120000);
  assert.equal(gh.has(PINS, x.rpath), false);
  assert.equal(gh.commitsFor(PINS, x.notePath).length, 1);
});

test("R-L2 B1: a recorded removal whose registration stood and sealed is never made: the sealer removes nothing, and the page says the registration stood and the case sealed", async () => {
  const c = await sealedCase("RL2 B1 sealed");
  const rpath = C.registrationPath(c.id, "a");
  const { note, notePath } = noteFor(c.id, rpath);
  gh.seed(PINS, notePath, note);
  const run = await sealerRun();
  assert.equal(gh.has(PINS, rpath), true, "nothing removed");
  assert.equal(gh.deleteLog.length, 0);
  assert.deepEqual(run.removals_completed.find((e) => e.case_id === c.id), { case_id: c.id, completed: [], sealed: [rpath], unknown: [] });
  const panel = panelOf((await casePage(c.id)).html);
  assert.ok(panel.includes(`; ${SEALED_STOOD}; signed by`), panel);
  assert.doesNotMatch(panel, /removal has not been made;/);
});

test("R-L2 B1: the README and the page describe a repair note as a removal recorded, never one made; the README says the sealer completes a recorded removal for every reason, with the sealed exception", () => {
  const readme = README();
  assert.ok(readme.includes(COMPLETION), "the completion sentence");
  assert.ok(readme.includes("a removal of this file was recorded for"));
  assert.doesNotMatch(readme, /the sealer's next run completes the removal without a second note|records the removal/);
  assert.doesNotMatch(read("lib/_case_page.js"), /removed for \$\{|a file is at that path when this page was read/);
  assert.doesNotMatch(read("lib/_case_seal.js") + read("lib/_case_http.js"), /repair note that records the removal|repair note records the removal/);
});

// =============================================================================
// B2: three outcomes for a removed file
// =============================================================================

test("R-L2 B2: a removed file whose note could not be verified says so and is no finding, and the page is not kept; one whose note is definitely invalid says it does not verify, with its reason; one with no note is a removal without a record", async () => {
  const x = await lostRace("RL2 B2 outcomes");
  const note = gh.read(PINS, x.notePath);
  const outcomes = async (doc = DOC) => (await S.caseRemovals(x.id, doc, storedCase(x.id))).removed.map((f) => [f.path, f.outcome, f.reason]);
  assert.deepEqual(await outcomes(), [[x.rpath, "recorded", null]], "control");
  assert.equal((await render(x.id, NOW + 5000)).definite, true, "control: kept");
  // could not look: the document the note names
  gh.seed(PINS, x.notePath, { ...note, signed_under: { ...note.signed_under, document_commit: "5".repeat(40) } });
  const p1 = await render(x.id, NOW + 5000);
  assert.ok(panelOf(p1.html).includes(UNVERIFIED(x.rpath, "document_unavailable")), panelOf(p1.html));
  assert.doesNotMatch(panelOf(p1.html), /without a record/);
  assert.equal(p1.definite, false);
  // the current document, and the note's own read
  gh.seed(PINS, x.notePath, note);
  assert.deepEqual(await outcomes({ not: "a key document" }), [[x.rpath, "unverified", "current_document_unreadable"]]);
  gh.forceGetFailure(PINS, x.notePath, 1, 503);
  const p2 = await render(x.id, NOW + 5000);
  assert.ok(panelOf(p2.html).includes(UNVERIFIED(x.rpath, "repair_note_unreadable")), panelOf(p2.html));
  assert.equal(p2.definite, false);
  // definitely invalid: a changed byte, a key of another role (the note's own fields, signed by the reconcile key), a revoked key
  gh.seed(PINS, x.notePath, { ...note, at: C.utcSeconds(NOW) });
  const p3 = await render(x.id, NOW + 5000);
  assert.ok(panelOf(p3.html).includes(INVALID(x.rpath, "bad_signature")), panelOf(p3.html));
  assert.equal(p3.definite, true);
  const fields = { caseId: x.id, removedPath: x.rpath, removedBlobSha: note.removed_blob_sha, createdInCommit: note.created_in_commit,
    removedFileSha256: note.removed_file_sha256, reason: note.reason, withdrawalCommit: note.withdrawal_commit, at: note.at, signedUnder: note.signed_under };
  gh.seed(PINS, x.notePath, S.repairNote(fields, S.loadReconcileSigner(KEYS, { keyDocument: DOC })));
  assert.deepEqual(await outcomes(), [[x.rpath, "invalid", "signer_unpublished"]]);
  gh.seed(PINS, x.notePath, note);
  assert.deepEqual(await outcomes(KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11" }), KD.reconcileEntry(RECEIPT_KEY))),
    [[x.rpath, "invalid", "signer_revoked"]]);
  // no note at all
  gh._repoMap(PINS).delete(x.notePath);
  const p4 = await render(x.id, NOW + 5000);
  assert.ok(panelOf(p4.html).includes(UNRECORDED(x.rpath)), panelOf(p4.html));
});

// =============================================================================
// M1: a note is keyed on the file it removes
// =============================================================================

test("R-L2 M1: a repair note is keyed on the file it removes, at the sha256 of its path, blob and creating commit (a newline between), and records the creating commit", async () => {
  const x = await lostRace("RL2 M1 key");
  assert.equal(x.notePath, `removals/${x.id}/${sha(`${x.rpath}\n${x.blob}\n${x.created}`)}.json`);
  const note = gh.read(PINS, x.notePath);
  assert.deepEqual([note.v, note.removed_blob_sha, note.created_in_commit], [2, x.blob, x.created]);
  assert.deepEqual(await S.verifyRepairNote(note, DOC), { ok: true });
  assert.equal(gh.has(PINS, `removals/${x.id}/${sha(x.rpath)}.json`), false, "not at the path-only name");
  assert.equal(gh.has(PINS, x.rpath), false);
});

test("R-L2 M1: a second removal on the same role path gets its own note, and each removal reads recorded", async () => {
  const u = await unconfirmed("RL2 M1 twice");
  assert.equal(u.out.registration_removed, true, JSON.stringify(u.out));
  const v = await unconfirmed(null, { id: u.id, a: u.a, now: NOW + 1000 });
  assert.equal(v.out.registration_removed, true, JSON.stringify(v.out));
  assert.notEqual(u.notePath, v.notePath);
  for (const p of [u.notePath, v.notePath]) assert.deepEqual(await S.verifyRepairNote(gh.read(PINS, p), DOC), { ok: true }, p);
  const r = await S.caseRemovals(u.id, DOC, storedCase(u.id));
  assert.deepEqual(r.removed.map((f) => [f.created_in_commit, f.outcome]), [[u.created, "recorded"], [v.created, "recorded"]]);
});

test("R-L2 M1: a byte-identical registration created by a later commit is another file: the earlier file's note removes nothing, and the page says another file is there", async () => {
  const u = await unconfirmed("RL2 M1 identical", { deleteFails: true });
  // the file stood (its removal failed); the same bytes written again by a later commit stand for git as the same blob
  const text = gh._repoMap(PINS).get(u.rpath).content;
  gh._repoMap(PINS).delete(u.rpath);
  gh.addCommit(PINS, u.rpath, "mock: removed by hand");
  gh.seedText(PINS, u.rpath, text, { keepHistory: true });
  gh._repoMap(PINS).get(u.rpath).sha = u.blob;
  await sealerRun();
  assert.equal(gh.has(PINS, u.rpath), true, "not removed under the earlier file's note");
  assert.equal(gh.deleteLog.length, 0);
  await assert.rejects(UNREG.removeRegistrationAfterWithdrawal(u.rpath, u.blob, "x", { createdInCommit: u.created, keyDocument: DOC }),
    /was not created by/);
  const panel = panelOf((await casePage(u.id)).html);
  assert.ok(panel.includes(`; ${REPLACED}; signed by`), panel);
});

test("R-L2 M1: a note in the old form (v 1, keyed on the path alone) is still read and labelled as the old form, and is never acted on", async () => {
  const u = await unconfirmed("RL2 M1 old form", { deleteFails: true });
  gh._repoMap(PINS).delete(u.notePath);
  const at = C.utcSeconds(NOW + 3000);
  const old = S.signRecord({ kind: "case-repair-note", v: 1, case_id: u.id, removed_path: u.rpath, removed_blob_sha: u.blob,
    removed_file_sha256: sha(u.text), reason: "registration_unconfirmed", withdrawal_commit: null, at, signed_under: KD.signedUnder(gh, DOC, at) },
  S.loadCaseSigner(KEYS, { keyDocument: DOC }), "This repair note is not signed");
  gh.seed(PINS, S.repairNotePathV1(u.id, u.rpath), old);
  assert.equal(S.repairNotePathV1(u.id, u.rpath), `removals/${u.id}/${sha(u.rpath)}.json`);
  assert.deepEqual(await S.verifyRepairNote(old, DOC), { ok: true });
  const panel = panelOf((await casePage(u.id)).html);
  assert.ok(panel.includes("(the old form, keyed on the path alone)"), panel);
  assert.ok(panel.includes(`; ${NOT_MADE}; signed by`), panel);
  await sealerRun();
  assert.equal(gh.has(PINS, u.rpath), true, "an old-form note is never acted on");
  assert.equal(gh.deleteLog.length, 0);
});

// =============================================================================
// M2: the withdrawal's 503 after a lost write
// =============================================================================

test("R-L2 M2: a withdrawal whose root write kept losing while the case read fine says the case kept changing; one whose read after the write failed says what the case is now could not be read", async () => {
  const c = await committedCase("RL2 M2 kept changing");
  gh.forceConflict(PINS, C.casePath(c.id), 4);
  const w = await withdraw(c.id, c.b);
  assert.deepEqual([w.status, w.body.error_code, w.body.reason, w.body.error, w.body.case_id],
    [503, "store_error", "case_kept_changing", "the case kept changing while this request tried to write; nothing was written. Send it again.", c.id],
    JSON.stringify(w.body));
  assert.equal(storedCase(c.id).status, "COMMITTED");
  const d = await committedCase("RL2 M2 read fails");
  gh.forceConflict(PINS, C.casePath(d.id), 4);
  const viaMock = global.fetch;
  let puts = 0;
  global.fetch = async (url, o) => {
    const method = (o && o.method) || "GET";
    if (String(url).includes(`/repos/${PINS}/contents/${C.casePath(d.id)}`)) {
      if (method === "PUT") puts += 1;
      else if (puts >= 4) return { ok: false, status: 503, json: async () => ({}), text: async () => "" };
    }
    return viaMock(url, o);
  };
  let r;
  try {
    r = await withdraw(d.id, d.b);
  } finally {
    global.fetch = viaMock;
  }
  assert.deepEqual([r.status, r.body.reason, r.body.error], [503, "case_moved",
    "the case moved while this withdrawal was written, and what it is now could not be read. This request wrote nothing to the pins repository. " +
      "Send the same withdrawal again."], JSON.stringify(r.body));
});

// =============================================================================
// M3: at most 500 reference rows a case
// =============================================================================

test("R-L2 M3: a case holds at most 500 reference rows: the 500th is written, the 501st is refused 409 row_limit in a plain sentence, and the README states the cap", async () => {
  assert.equal(S.MAX_REFERENCE_ROWS, 500);
  const c = await sealedCase("RL2 M3 cap");
  await sealerRun();
  for (let n = 1; n <= 499; n += 1) gh.seed(PINS, C.referencePath(c.id, n), { seeded: n });
  const at500 = await reference(c, { role: "a" });
  assert.equal(at500.status, 201, JSON.stringify(at500.body).slice(0, 300));
  assert.equal(gh.has(PINS, C.referencePath(c.id, 500)), true);
  const at501 = await reference(c, { role: "b" });
  assert.deepEqual([at501.status, at501.body.error_code, at501.body.error, at501.body.case_id],
    [409, "row_limit", "this case holds 500 reference rows, the most one case holds; no row was written", c.id], JSON.stringify(at501.body));
  assert.equal(gh.has(PINS, C.referencePath(c.id, 501)), false);
  assert.ok(README().includes("A case holds at most 500 reference rows; the 501st is refused 409 `row_limit`."));
});

// =============================================================================
// L4 (a minor): a withdrawal that lost to a reveal attempt, or to another withdrawal
// =============================================================================

test("R-L2 L4: a withdrawal that loses to a reveal attempt, or to another withdrawal, writes nothing to the pins repository and removes nothing", async () => {
  for (const [scope, code, seedWith] of [
    ["RL2 L4 lost to an attempt", "reveal_attempted", (c, k) => ({ ...k, reveal_attempts: [{ event: "attempt",
      commitments: { a: k.commitments.a.commitment_sha256, b: k.commitments.b.commitment_sha256 }, input_sha256: "e".repeat(64), at: C.utcSeconds(NOW + 1000) }] })],
    ["RL2 L4 lost to a withdrawal", "case_withdrawn",
      (c, k) => S.withdrawnRecord(k, { role: "a", at: C.utcSeconds(NOW + 1000), salt: c.a.salt }, S.loadCaseSigner(KEYS, { keyDocument: DOC }))],
  ]) {
    const c = await committedCase(scope);
    let before;
    const r = await during(
      (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(c.id)}`),
      async () => {
        gh.seed(PINS, C.casePath(c.id), seedWith(c, storedCase(c.id)), { keepHistory: true });
        before = gh._commitsOf(PINS).length;
      },
      () => withdraw(c.id, c.b),
    );
    assert.deepEqual([r.out.status, r.out.body.error_code], [409, code], JSON.stringify(r.out.body));
    assert.ok(r.out.body.error.endsWith("This request wrote nothing to the pins repository."), r.out.body.error);
    assert.equal(gh._commitsOf(PINS).length, before, `${scope}: nothing written to the pins repository`);
    assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c.id)), false, "no marker");
    assert.equal(gh.deleteLog.length, 0);
  }
});

// =============================================================================
// THE MINORS
// =============================================================================

// A case at pin `top` whose pins carry no index (written before unit R-L),
// row 1 listed by pin 2 (the R-L L5 legacy fixture).
async function legacyChain(scope, top) {
  const c = await sealedCase(scope);
  assert.equal((await reference(c, { role: "a" })).status, 201);
  const commit = gh.commitsFor(PINS, C.referencePath(c.id, 1))[0].sha;
  const base = gh.read(PINS, S.pinPaths(c.id).seq);
  let rec = base;
  for (let n = 2; n <= top; n += 1) {
    rec = { ...base, seq: n, ...(n === 2 ? { reference_commits: [{ seq: 1, commit }] } : {}) };
    gh.seed(PINS, S._internal.pinPath(c.id, n), rec);
  }
  gh.seed(PINS, S.pinPaths(c.id).latest, rec);
  return c;
}
const AUTH_INDEXED = "reference_commits, when present, lists the commits that wrote the case's reference rows that no earlier pin lists;";
const AUTH_PARTIAL = "reference_commits, when present, lists the commits that wrote the case's reference rows that the pins read below " +
  "this one do not list; the pins below were written before listed_by and were not read to the chain's start, so an earlier pin may list " +
  "some of them too;";

test("R-L2 (a minor): a next pin written after a walk that did not reach the chain's start says an earlier pin may list its rows too; a pin written from an index says no earlier pin lists them", async () => {
  const c = await legacyChain("RL2 auth legacy", 25);
  await sealerRun();
  const p26 = gh.read(PINS, S._internal.pinPath(c.id, 26));
  assert.ok(p26.auth_note.includes(AUTH_PARTIAL), p26.auth_note);
  assert.ok(!p26.auth_note.includes("rows that no earlier pin lists"), p26.auth_note);
  const d = await legacyChain("RL2 auth short legacy", 3);
  await sealerRun(120000);
  const p4 = gh.read(PINS, S._internal.pinPath(d.id, 4));
  assert.equal(p4, null, "fixture: row 1 is listed, nothing to write");
  const e = await sealedCase("RL2 auth indexed");
  assert.equal((await reference(e, { role: "a" })).status, 201);
  await sealerRun(180000);
  const p2 = gh.read(PINS, S._internal.pinPath(e.id, 2));
  assert.ok(p2.auth_note.includes(AUTH_INDEXED), p2.auth_note);
});

test("R-L2 (a minor): the one removal checks the note's signature itself and needs the file's creating commit: a note naming the file whose signature does not hold removes nothing", async () => {
  const u = await unconfirmed("RL2 guard signature", { deleteFails: true });
  const note = gh.read(PINS, u.notePath);
  gh.seed(PINS, u.notePath, { ...note, at: C.utcSeconds(NOW + 60000) });
  await assert.rejects(UNREG.removeRegistrationAfterWithdrawal(u.rpath, u.blob, "x", { createdInCommit: u.created, keyDocument: DOC }),
    /the repair note for .* does not verify \(bad_signature\), so nothing was removed/);
  await assert.rejects(UNREG.removeRegistrationAfterWithdrawal(u.rpath, u.blob, "x"), /the commit that created the file is required/);
  assert.equal(gh.has(PINS, u.rpath), true);
  assert.equal(gh.deleteLog.length, 0);
  gh.seed(PINS, u.notePath, note);
  await UNREG.removeRegistrationAfterWithdrawal(u.rpath, u.blob, "x", { createdInCommit: u.created, keyDocument: DOC });
  assert.equal(gh.has(PINS, u.rpath), false, "control: the note as signed");
});
