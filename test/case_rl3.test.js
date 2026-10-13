// test/case_rl3.test.js — unit R-L3 (2026-10-13): one rule about a noted
// file, and the last anchor returns. The re-read of R-L2 at b22b763 found
// one blocker, made by R-L2's own rule: a registration the service answered
// 200 for could be deleted by the sealer (the replay took the file still at
// the path, under a standing repair note, as the registration).
//   THE RULE: a registration file with a standing, verified repair note is
// CONDEMNED and never stands as a registration, for any reader or handler
// (lib/_case_seal.js registrationsStanding, the one helper every reader
// calls). Sending the registration again removes it under its note and
// writes a fresh file. The sealer's completion runs under the case lock.
//   And the follow-ups: the anchor's last early returns (in
// test/case_rj3.test.js), a 404 at a listed commit in the history walk, an
// old-form note marking only its own removal, and the withdrawal's words.
// The setup below is test/case_rl2.test.js's.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0151:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rl3");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rl3");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rl3");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0151" });

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
  return `10.93.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
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
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0151", url: "https://second-operator.example/cases/0151" });
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
// file (registration_unconfirmed). `deleteFails`: the removal itself refused;
// `stamp: false`: the stamp planted before is read again (a stamp planted
// again is another commit, and the registration names its commit).
async function unconfirmed(scope, { deleteFails = false, id = null, a = null, now = NOW, stamp = true } = {}) {
  id = id || (await openCase(scope));
  a = a || party(id, "a", AGENT_TAPE);
  if (stamp) plantStamp(a.commitment_sha256);
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


// THE RULE's words, exactly
const RULE3 = "The registration was written and could not be confirmed, so a removal of it was recorded. Send the same registration again; " +
  "it will be written fresh.";
const LATE_AFTER_REMOVAL = "the earlier registration was removed under a repair note and the deadline has passed; no commitment can be " +
  "registered to it now";
const README_RULE = "A registration file under a verified repair note never stands: no reader or handler counts it, and a case is not " +
  "COMMITTED and cannot reveal while either role's only file is such a file. Sending that registration again removes the file under its " +
  "note and writes a fresh one, which past the deadline is refused late_commitment.";
// A case whose role a's file is condemned (a verified note stands, its
// removal failed), and role b registered after it: the case reads OPEN.
async function condemnedA(scope) {
  const u = await unconfirmed(scope, { deleteFails: true });
  const b = party(u.id, "b", TOOL_TAPE);
  await register(u.id, b);
  return { ...u, b };
}
// The race THE RULE closes: a case object that projected the condemned
// file (role a's, or `c.role`'s) before its note stood (another role's
// projection read it first).
function projectedAnyway(c) {
  const k = storedCase(c.id);
  const reg = gh.read(PINS, c.rpath);
  gh.seed(PINS, C.casePath(c.id), { ...k, status: "COMMITTED", commitments: { ...k.commitments, [c.role || "a"]: C.commitmentEntry(reg) } },
    { keepHistory: true });
  assert.equal(C.validateCase(storedCase(c.id)).ok, true, "fixture: a valid COMMITTED case");
}
const revealOf = (c, now = REVEAL_AT) => reveal({ id: c.id, a: c.a, b: c.b }, { now });

// =============================================================================
// THE RULE: a condemned file never stands
// =============================================================================

test("R-L3: the exact replay: the read after the write fails, the removal fails, the registration is sent again: the old file is removed under its note, a fresh file with a new creating commit stands, 200", async () => {
  const u = await unconfirmed("RL3 replay", { deleteFails: true });
  assert.deepEqual([u.out.registration_removed, gh.has(PINS, u.rpath), gh.has(PINS, u.notePath)], [false, true, true], "fixture: condemned");
  assert.equal(u.out.error, RULE3);
  const again = await commit(u.id, u.a, NOW + 1500);
  assert.equal(again.status, 200, JSON.stringify(again.body).slice(0, 300));
  assert.deepEqual([again.body.existing, again.body.status], [false, "OPEN"]);
  assert.ok(gh.deleteLog.some((d) => d.path === u.rpath && d.sha === u.blob), "the old file, removed");
  const fresh = asWritten(u.rpath, u.id);
  assert.notEqual(fresh.created, u.created, "a new creating commit");
  assert.notEqual(fresh.blob, u.blob);
  assert.equal(gh.has(PINS, fresh.notePath), false, "no note names the fresh file");
  assert.equal(pinsPaths().filter((p) => p.startsWith(`removals/${u.id}/`)).length, 1, "no second note");
  assert.deepEqual(storedCase(u.id).commitments.a, C.commitmentEntry(gh.read(PINS, u.rpath)), "the case projects the fresh file");
  // the sealer never deletes a file the case projects
  await sealerRun();
  assert.equal(gh.has(PINS, u.rpath), true, "the fresh file stands after a sealer run");
  assert.equal(gh._repoMap(PINS).get(u.rpath).sha, fresh.blob);
  assert.deepEqual(storedCase(u.id).commitments.a, C.commitmentEntry(gh.read(PINS, u.rpath)));
});

test("R-L3: the same replay past the deadline is 409 late_commitment in plain words, and nothing stands", async () => {
  const u = await unconfirmed("RL3 replay late", { deleteFails: true });
  const late = await commit(u.id, u.a, Date.parse(DEADLINE) + 1000);
  assert.deepEqual([late.status, late.body.error_code, late.body.error], [409, "late_commitment", LATE_AFTER_REMOVAL], JSON.stringify(late.body));
  assert.equal(gh.has(PINS, u.rpath), false, "the condemned file, removed");
  assert.equal(storedCase(u.id).commitments.a, null);
});

test("R-L3: a replay whose note cannot be verified now is 503 could_not_look, and one whose removal cannot be completed is 503; neither changes anything", async () => {
  const u = await unconfirmed("RL3 replay cnl", { deleteFails: true });
  const note = gh.read(PINS, u.notePath);
  gh.seed(PINS, u.notePath, { ...note, signed_under: { ...note.signed_under, document_commit: "5".repeat(40) } });
  const commits = gh._commitsOf(PINS).length;
  const r = await commit(u.id, u.a, NOW + 1500);
  assert.deepEqual([r.status, r.body.error_code], [503, "could_not_look"], JSON.stringify(r.body));
  assert.equal(gh._commitsOf(PINS).length, commits, "nothing written");
  gh.seed(PINS, u.notePath, note);
  const viaMock = global.fetch;
  global.fetch = async (url, o) => ((o && o.method) === "DELETE" ? { ok: false, status: 500, json: async () => ({}), text: async () => "" } : viaMock(url, o));
  let f;
  try {
    f = await commit(u.id, u.a, NOW + 1500);
  } finally {
    global.fetch = viaMock;
  }
  assert.deepEqual([f.status, f.body.error_code], [503, "removal_incomplete"], JSON.stringify(f.body));
  assert.equal(gh._repoMap(PINS).get(u.rpath).sha, u.blob, "the condemned file, unchanged");
  assert.equal(storedCase(u.id).commitments.a, null);
});

test("R-L3: the 503 after a failed after-read says what is true when a removal was recorded, whether or not it was made", async () => {
  const made = await unconfirmed("RL3 503 made");
  assert.deepEqual([made.out.error_code, made.out.registration_removed, made.out.error], ["registration_unconfirmed", true, RULE3], JSON.stringify(made.out));
  const notMade = await unconfirmed("RL3 503 not made", { deleteFails: true });
  assert.deepEqual([notMade.out.registration_removed, notMade.out.error], [false, RULE3]);
});

test("R-L3: the other role's registration does not project a condemned file: the case stays OPEN, and a reveal is not committed", async () => {
  const c = await condemnedA("RL3 projection");
  const k = storedCase(c.id);
  assert.deepEqual([k.status, k.commitments.a, k.commitments.b !== null], ["OPEN", null, true]);
  const r = await revealOf(c);
  assert.deepEqual([r.status, r.body.error_code], [409, "not_committed"], JSON.stringify(r.body).slice(0, 300));
});

test("R-L3: a reveal while a condemned file is at the path is not committed, even when the case object projected it first", async () => {
  const c = await condemnedA("RL3 reveal");
  projectedAnyway(c);
  const r = await revealOf(c);
  assert.deepEqual([r.status, r.body.error_code], [409, "not_committed"], JSON.stringify(r.body).slice(0, 300));
  assert.match(r.body.error, /role a's registration file is under a repair note/);
  assert.notEqual(storedCase(c.id).status, "VERDICT");
});

test("R-L3: a role whose only file is condemned cannot withdraw by it, and the case page counts it as not registered", async () => {
  const c = await condemnedA("RL3 readers");
  const w = await withdraw(c.id, c.a);
  assert.deepEqual([w.status, w.body.error_code], [403, "withdraw_unauthorized"], JSON.stringify(w.body));
  projectedAnyway(c);
  const html = (await casePage(c.id)).html;
  assert.match(html, /Case: OPEN/);
  assert.ok(html.includes("its registration file is under a repair note (a removal of it was recorded), so it does not stand"), html.slice(html.indexOf("Registrations"), html.indexOf("Registrations") + 600));
});

test("R-L3: the sealer's sealable index counts a condemned file as absent", async () => {
  const c = await condemnedA("RL3 index");
  projectedAnyway(c);
  const run = await sealerRun();
  assert.deepEqual(run.not_standing.find((e) => e.case_id === c.id), { case_id: c.id, roles: ["a"] });
});

test("R-L3: completion holds the case lock around its removal, re-reads under it, and a reveal racing it is refused: never sealed and removed both", async () => {
  const c = await condemnedA("RL3 lock");
  projectedAnyway(c);
  let lockDuring = null;
  let revealDuring = null;
  const r = await during(
    (url, method) => method === "DELETE" && url.includes(`/repos/${PINS}/contents/${c.rpath}`),
    async () => {
      lockDuring = lockOf(c.id);
      revealDuring = await revealOf(c);
    },
    () => S.completeRemovals(c.id, { keyDocument: DOC }),
  );
  assert.equal(r.fired, true);
  assert.deepEqual([lockDuring.state, lockDuring.op], ["held", "complete"], JSON.stringify(lockDuring));
  assert.deepEqual(r.out, { case_id: c.id, completed: [c.rpath], sealed: [], unknown: [] });
  assert.deepEqual([revealDuring.status, revealDuring.body.error_code], [409, "not_committed"], JSON.stringify(revealDuring.body).slice(0, 200));
  assert.equal(gh.has(PINS, c.rpath), false);
  assert.notEqual(storedCase(c.id).status, "VERDICT", "never sealed and removed both");
  assert.equal(lockOf(c.id).state, "released");
  // the other order: the reveal first, then the completion
  const d = await condemnedA("RL3 lock other order");
  projectedAnyway(d);
  const first = await revealOf(d);
  assert.equal(first.status, 409);
  assert.deepEqual((await S.completeRemovals(d.id, { keyDocument: DOC })).completed, [d.rpath]);
  assert.notEqual(storedCase(d.id).status, "VERDICT");
  // a busy lock: nothing done, said
  const e = await condemnedA("RL3 lock busy");
  gh.seed(USAGE, H._internal.caseLockPath(e.id), { kind: "case-lock", v: 1, case_id: e.id, holder: "someone-else", op: "commit",
    acquired_at: new Date().toISOString(), expires_at: new Date(Date.now() + 600000).toISOString(), state: "held" });
  assert.deepEqual(await S.completeRemovals(e.id, { keyDocument: DOC }),
    { case_id: e.id, completed: [], sealed: [], unknown: [{ path: C.casePath(e.id), reason: "case_busy" }] });
  assert.equal(gh.has(PINS, e.rpath), true);
});

test("R-L3: completion does nothing once, under the lock, the case reads sealed or the file is no longer the noted one", async () => {
  const c = await condemnedA("RL3 recheck");
  const k = storedCase(c.id);
  // the file changed between the read outside the lock and the read inside it
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${USAGE}/contents/${H._internal.caseLockPath(c.id)}`),
    async () => {
      gh._repoMap(PINS).get(c.rpath).sha = "9".repeat(40);
    },
    () => S.completeRemovals(c.id, { keyDocument: DOC }),
  );
  assert.equal(r.fired, true);
  assert.deepEqual(r.out.completed, []);
  assert.equal(gh.has(PINS, c.rpath), true);
  gh._repoMap(PINS).get(c.rpath).sha = c.blob;
  // the case sealed meanwhile
  const s = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${USAGE}/contents/${H._internal.caseLockPath(c.id)}`),
    async () => gh.seed(PINS, C.casePath(c.id), { ...k, status: "VERDICT" }, { keepHistory: true }),
    () => S.completeRemovals(c.id, { keyDocument: DOC }),
  );
  assert.equal(s.fired, true);
  assert.deepEqual(s.out.completed, []);
  assert.equal(gh.has(PINS, c.rpath), true);
});

test("R-L3: the README states the rule in two sentences", () => {
  assert.ok(README().includes(README_RULE));
});

// =============================================================================
// THE FOLLOW-UPS (b, c, d; a is in test/case_rj3.test.js)
// =============================================================================

test("R-L3 (b): a 404 at a commit the path's own list names, where no file was there before it, is could_not_look for that path: its notes say so, and the page is not kept", async () => {
  const x = await lostRace("RL3 walk 404");
  S._internal.clearCommitFiles();
  gh.forceRawFailure(1, 404, `@${x.created}:${x.rpath}`);
  const r = await render(x.id, NOW + 5000);
  const p = panelOf(r.html);
  assert.ok(p.includes(`the history of ${x.rpath} could not be read when this page was read (registration_at_commit_not_shown)`), p);
  assert.ok(p.includes("; what is at its path could not be read when this page was read; signed by"), p);
  assert.doesNotMatch(p, /without a record/);
  assert.equal(r.definite, false);
  // the newest commit reads 404 while the file is there now: the same
  const y = await lostRace("RL3 walk 404 newest", { deleteFails: true });
  gh.addCommit(PINS, y.rpath, "mock: touched");
  S._internal.clearCommitFiles();
  gh.forceRawFailure(1, 404, `@${gh.commitsFor(PINS, y.rpath)[0].sha}:${y.rpath}`);
  const q = await S.caseRemovals(y.id, DOC, storedCase(y.id));
  assert.deepEqual(q.unread, [{ path: y.rpath, reason: "registration_at_commit_not_shown" }]);
});

test("R-L3 (c): an old-form note marks only the removal it names as recorded", async () => {
  const u = await unconfirmed("RL3 old form one");
  const v = await unconfirmed(null, { id: u.id, a: u.a, now: NOW + 1000 });
  for (const p of [u.notePath, v.notePath]) gh._repoMap(PINS).delete(p);
  const at = C.utcSeconds(NOW + 3000);
  gh.seed(PINS, S.repairNotePathV1(u.id, u.rpath), S.signRecord({ kind: "case-repair-note", v: 1, case_id: u.id, removed_path: u.rpath,
    removed_blob_sha: u.blob, removed_file_sha256: sha(u.text), reason: "registration_unconfirmed", withdrawal_commit: null, at,
    signed_under: KD.signedUnder(gh, DOC, at) }, S.loadCaseSigner(KEYS, { keyDocument: DOC }), "This repair note is not signed"));
  const r = await S.caseRemovals(u.id, DOC, storedCase(u.id));
  assert.deepEqual(r.removed.map((f) => [f.created_in_commit, f.outcome]), [[u.created, "recorded"], [v.created, "unrecorded"]]);
});

test("R-L3 (d): a withdrawal whose write kept losing says nothing was written to the case record", async () => {
  const c = await committedCase("RL3 kept changing");
  gh.forceConflict(PINS, C.casePath(c.id), 4);
  const w = await withdraw(c.id, c.b);
  assert.deepEqual([w.status, w.body.reason, w.body.error], [503, "case_kept_changing",
    "the case kept changing while this request tried to write; nothing was written to the case record. Send it again."], JSON.stringify(w.body));
});

// =============================================================================
// MUST-FAIL GAP TESTS: what the must-fail pass over the lines R-L3 changed
// found no test for
// =============================================================================

// Role b's registration could not be confirmed after its write, with role a
// registered before it, and the removal refused: role b's file is condemned.
async function unconfirmedB(scope) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  await register(id, a);
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(b.commitment_sha256);
  const rpath = C.registrationPath(id, "b");
  let r;
  await withoutDeletes(async () => {
    r = await during(
      (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
      async () => gh.forceGetFailure(PINS, C.casePath(id), 1, 503),
      () => commit(id, b, NOW),
    );
  });
  assert.equal(r.out.body.error_code, "registration_unconfirmed", JSON.stringify(r.out.body));
  return { id, a, b, rpath, role: "b", ...asWritten(rpath, id) };
}
// `fn` run with every removal refused (500).
async function withoutDeletes(fn) {
  const viaMock = global.fetch;
  global.fetch = async (url, o) => ((o && o.method) === "DELETE" ? { ok: false, status: 500, json: async () => ({}), text: async () => "" } : viaMock(url, o));
  try {
    return await fn();
  } finally {
    global.fetch = viaMock;
  }
}
// The note at `notePath` made to fail its check for now: it names a key
// document commit the repository does not show. -> the note as it was.
function unverifiable(notePath) {
  const note = gh.read(PINS, notePath);
  gh.seed(PINS, notePath, { ...note, signed_under: { ...note.signed_under, document_commit: "5".repeat(40) } });
  return note;
}
// THE RULE's could-not-look words at the commit path.
const unreadWords = (role, reason) => `whether role ${role}'s registration file is under a repair note could not be read now (${reason}); this is ` +
  "not a 'no', and nothing was registered";

test("MUST-FAIL GAP (S02, S05, S06, S29, S31): the sealer's index: a case whose role a file is condemned is neither a candidate nor counted withdrawn; one whose note could not be checked, or whose file could not be read, is pending with its reason", async () => {
  const c = await condemnedA("RL3 gap index");
  projectedAnyway(c);
  await withoutDeletes(async () => {
    const run = await sealerRun();
    assert.deepEqual([run.candidates, run.withdrawn_skipped, run.not_standing], [0, 0, [{ case_id: c.id, roles: ["a"] }]], JSON.stringify(run).slice(0, 400));
    const note = unverifiable(c.notePath);
    const unsure = await sealerRun(120000);
    assert.deepEqual(unsure.pending.filter((p) => p.case_id === c.id), [{ case_id: c.id, reason: "document_unavailable" }], JSON.stringify(unsure.pending));
    assert.deepEqual([unsure.candidates, unsure.not_standing], [0, []]);
    gh.seed(PINS, c.notePath, note);
    gh.forceGetFailure(PINS, c.rpath, 1, 503);
    const unread = await sealerRun(180000);
    assert.deepEqual(unread.pending.filter((p) => p.case_id === c.id), [{ case_id: c.id, reason: "registration_unreadable" }], JSON.stringify(unread.pending));
    assert.deepEqual([unread.candidates, unread.not_standing], [0, []]);
  });
});

test("MUST-FAIL GAP (S04): a case holding a note whose file was removed and registered afresh is a sealer candidate", async () => {
  const u = await unconfirmed("RL3 gap fresh candidate", { deleteFails: true });
  assert.equal((await commit(u.id, u.a, NOW + 1500)).status, 200);
  await register(u.id, party(u.id, "b", TOOL_TAPE));
  assert.equal(storedCase(u.id).status, "COMMITTED");
  const run = await sealerRun();
  assert.deepEqual([run.candidates, run.not_standing], [1, []], JSON.stringify(run).slice(0, 400));
});

test("MUST-FAIL GAP (S09, S10, H04, P17): a condemned file of role b is absent to the sealer's index, the reveal and the page", async () => {
  const c = await unconfirmedB("RL3 gap role b");
  projectedAnyway(c);
  const run = await withoutDeletes(() => sealerRun());
  assert.deepEqual(run.not_standing, [{ case_id: c.id, roles: ["b"] }]);
  const r = await revealOf(c);
  assert.deepEqual([r.status, r.body.error_code, r.body.role], [409, "not_committed", "b"], JSON.stringify(r.body).slice(0, 300));
  const html = (await render(c.id, NOW + 5000)).html;
  assert.ok(html.includes(`<title>Case ${c.id.slice(0, 12)}: OPEN</title>`), html.slice(0, 600));
});

test("MUST-FAIL GAP (S08, L10): completion's lease clock is the sealer run's own, and the real clock for a caller that names none", async () => {
  const c = await condemnedA("RL3 gap clock");
  const runAt = REVEAL_AT + 3600000 + 60000;
  const heldUntil = (expires) => gh.seed(USAGE, H._internal.caseLockPath(c.id), { kind: "case-lock", v: 1, case_id: c.id, holder: "someone-else",
    op: "commit", acquired_at: new Date(expires - 600000).toISOString(), expires_at: new Date(expires).toISOString(), state: "held" });
  // held at the run's clock, long expired at the real one
  heldUntil(runAt + 600000);
  const run = await sealerRun();
  assert.deepEqual(run.removals_completed.find((d) => d.case_id === c.id).unknown, [{ path: C.casePath(c.id), reason: "case_busy" }]);
  assert.equal(gh.has(PINS, c.rpath), true);
  // a caller naming no clock: a lock expired at the real clock is taken
  heldUntil(Date.now() - 1000);
  assert.deepEqual((await S.completeRemovals(c.id, { keyDocument: DOC })).completed, [c.rpath]);
});

test("MUST-FAIL GAP (S11, S13, S14, S17, S27, H06): a replay whose notes, note or file history could not be read, or whose note could not be checked, is 503 could_not_look naming the role and the reason, and changes nothing", async () => {
  const u = await unconfirmed("RL3 gap replay unread", { deleteFails: true });
  const replay = async () => {
    const r = await commit(u.id, u.a, NOW + 1500);
    return [r.status, r.body.error_code, r.body.reason, r.body.error];
  };
  gh.forceGetFailure(PINS, `removals/${u.id}`, 1, 503);
  assert.deepEqual(await replay(), [503, "could_not_look", "repair_notes_unreadable", unreadWords("a or b", "repair_notes_unreadable")]);
  gh.forceGetFailure(PINS, u.notePath, 1, 503);
  assert.deepEqual(await replay(), [503, "could_not_look", "repair_note_unreadable", unreadWords("a", "repair_note_unreadable")]);
  const note = unverifiable(u.notePath);
  assert.deepEqual(await replay(), [503, "could_not_look", "document_unavailable", unreadWords("a", "document_unavailable")]);
  gh.seed(PINS, u.notePath, note);
  const list = gh._commitsOf(PINS);
  for (let i = list.length - 1; i >= 0; i -= 1) if (list[i].path === u.rpath) list.splice(i, 1);
  assert.deepEqual(await replay(), [503, "could_not_look", "registration_commits_none", unreadWords("a", "registration_commits_none")]);
  assert.equal(gh._repoMap(PINS).get(u.rpath).sha, u.blob, "nothing changed");
  assert.equal(gh.deleteLog.length, 0);
});

test("MUST-FAIL GAP (S20, S21, S22, S24, S25): a note at the file's note path that names another path, blob or creating commit, or does not verify, condemns nothing: the file stands, and sending it again is the replay of a registration on file", async () => {
  const u = await unconfirmed("RL3 gap other notes", { deleteFails: true });
  const note = gh.read(PINS, u.notePath);
  const at = C.utcSeconds(NOW + 9000);
  const build = (over) => S.repairNote({ caseId: u.id, removedPath: u.rpath, removedBlobSha: u.blob, createdInCommit: u.created,
    removedFileSha256: sha(u.text), reason: "registration_unconfirmed", withdrawalCommit: null, at, signedUnder: KD.signedUnder(gh, DOC, at), ...over },
  S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  const file = await store.getRawFile(u.rpath);
  const standing = () => S.registrationsStanding(u.id, { a: file, b: null }, { keyDocument: DOC });
  const stands = { ok: true, standing: { a: file, b: null }, condemned: { a: null, b: null } };
  // the control: the note as written condemns the file
  assert.deepEqual(await standing(), { ok: true, standing: { a: null, b: null }, condemned: { a: { note_path: u.notePath, note, created: u.created }, b: null } });
  for (const [what, over] of [["another path", { removedPath: C.registrationPath(u.id, "b") }], ["another blob", { removedBlobSha: "1".repeat(40) }],
    ["another creating commit", { createdInCommit: "3".repeat(40) }]]) {
    gh.seed(PINS, u.notePath, build(over));
    assert.deepEqual(await standing(), stands, what);
  }
  gh.seed(PINS, u.notePath, { ...note, at: C.utcSeconds(NOW + 99000) }); // its signature no longer covers it
  assert.deepEqual(await standing(), stands, "a note that does not verify");
  const again = await commit(u.id, u.a, NOW + 1500);
  assert.deepEqual([again.status, again.body.existing], [200, true], JSON.stringify(again.body).slice(0, 300));
  assert.equal(gh._repoMap(PINS).get(u.rpath).sha, u.blob);
});

test("MUST-FAIL GAP (S15): a fresh file byte-identical to the removed one is another file: its creating commit is the newest at its path, so the removed file's note does not condemn it", async () => {
  const u = await unconfirmed("RL3 gap same bytes", { deleteFails: true });
  const again = await commit(u.id, u.a, NOW); // the same instant: the same bytes
  assert.equal(again.status, 200, JSON.stringify(again.body).slice(0, 300));
  const fresh = gh._repoMap(PINS).get(u.rpath);
  assert.equal(fresh.content, u.text, "fixture: the same bytes");
  fresh.sha = u.blob; // git names a blob by its bytes; the mock does not
  await register(u.id, party(u.id, "b", TOOL_TAPE));
  assert.deepEqual([storedCase(u.id).status, storedCase(u.id).commitments.a], ["COMMITTED", C.commitmentEntry(gh.read(PINS, u.rpath))]);
});

test("MUST-FAIL GAP (C02, C03): an old-form note names its file by its bytes: of two removals with the same bytes it marks the oldest, and it marks the removal whose bytes it names, not the first", async () => {
  const oldForm = (u, text) => {
    const at = C.utcSeconds(NOW + 3000);
    gh.seed(PINS, S.repairNotePathV1(u.id, u.rpath), S.signRecord({ kind: "case-repair-note", v: 1, case_id: u.id, removed_path: u.rpath,
      removed_blob_sha: u.blob, removed_file_sha256: sha(text), reason: "registration_unconfirmed", withdrawal_commit: null, at,
      signed_under: KD.signedUnder(gh, DOC, at) }, S.loadCaseSigner(KEYS, { keyDocument: DOC }), "This repair note is not signed"));
  };
  const u = await unconfirmed("RL3 gap old form same bytes");
  const v = await unconfirmed(null, { id: u.id, a: u.a, stamp: false }); // the same instant and stamp: the same bytes
  assert.equal(v.text, u.text, "fixture: the same bytes");
  for (const p of [u.notePath, v.notePath]) gh._repoMap(PINS).delete(p);
  oldForm(u, u.text);
  const r = await S.caseRemovals(u.id, DOC, storedCase(u.id));
  assert.deepEqual(r.removed.map((f) => [f.created_in_commit, f.outcome]), [[u.created, "recorded"], [v.created, "unrecorded"]]);
  const x = await unconfirmed("RL3 gap old form second");
  const y = await unconfirmed(null, { id: x.id, a: x.a, now: NOW + 1000 });
  for (const p of [x.notePath, y.notePath]) gh._repoMap(PINS).delete(p);
  oldForm(x, y.text);
  const q = await S.caseRemovals(x.id, DOC, storedCase(x.id));
  assert.deepEqual(q.removed.map((f) => [f.created_in_commit, f.outcome]), [[x.created, "unrecorded"], [y.created, "recorded"]]);
});

test("MUST-FAIL GAP (H07, H22): a projection that loses its write reads the files again under the same key document: a condemned file is still absent", async () => {
  const u = await unconfirmed("RL3 gap rebuild", { deleteFails: true });
  const b = party(u.id, "b", TOOL_TAPE);
  plantStamp(b.commitment_sha256);
  // the case file moves (another writer, the same bytes) after the read the
  // projection builds on: its write loses, and it reads the files again
  let lockPuts = 0;
  const { out: r, fired } = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${USAGE}/contents/${H._internal.caseLockPath(u.id)}`) && (lockPuts += 1) === 2,
    async () => gh.seed(PINS, C.casePath(u.id), storedCase(u.id), { keepHistory: true }),
    () => commit(u.id, b),
  );
  assert.equal(fired, true);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.deepEqual([storedCase(u.id).status, storedCase(u.id).commitments.a], ["OPEN", null]);
});

test("MUST-FAIL GAP (H12, H13, H21): the replay removes the condemned file holding the case lock, after reading the case again under it, and its answer says the earlier file was removed", async () => {
  const u = await unconfirmed("RL3 gap replay lock", { deleteFails: true });
  const r = await during(
    (url, method) => method === "DELETE" && url.includes(`/repos/${PINS}/contents/${u.rpath}`),
    async () => lockOf(u.id),
    () => commit(u.id, u.a, NOW + 1500),
  );
  assert.equal(r.fired, true);
  assert.deepEqual([r.inner && r.inner.state, r.inner && r.inner.op], ["held", "commit"], JSON.stringify(r.inner));
  assert.deepEqual([r.out.status, r.out.body.earlier_removed], [200, true]);
  // the case sealed between the first read and the lock: nothing is removed
  const v = await unconfirmed("RL3 gap replay recheck", { deleteFails: true });
  const k = storedCase(v.id);
  const s = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${USAGE}/contents/${H._internal.caseLockPath(v.id)}`),
    async () => gh.seed(PINS, C.casePath(v.id), { ...k, status: "VERDICT" }, { keepHistory: true }),
    () => commit(v.id, v.a, NOW + 1500),
  );
  assert.equal(s.fired, true);
  assert.deepEqual([s.out.status, s.out.body.error_code], [409, "case_not_open"], JSON.stringify(s.out.body).slice(0, 300));
  assert.equal(gh._repoMap(PINS).get(v.rpath).sha, v.blob);
});

test("MUST-FAIL GAP (H24, H27, H28): the reveal names the note of a condemned file; a reveal or a withdrawal whose note could not be checked is 503 could_not_look", async () => {
  const c = await condemnedA("RL3 gap reveal words");
  projectedAnyway(c);
  const r = await revealOf(c);
  assert.deepEqual([r.status, r.body.role, r.body.repair_note], [409, "a", c.notePath], JSON.stringify(r.body).slice(0, 300));
  unverifiable(c.notePath);
  const u = await revealOf(c);
  assert.deepEqual([u.status, u.body.error_code, u.body.reason], [503, "could_not_look", "document_unavailable"], JSON.stringify(u.body).slice(0, 300));
  const w = await withdraw(c.id, c.b);
  assert.deepEqual([w.status, w.body.error_code, w.body.reason], [503, "could_not_look", "document_unavailable"], JSON.stringify(w.body).slice(0, 300));
});

test("MUST-FAIL GAP (H30): a reference reads the files under the same key document: a sealed case whose role a file came under a verified note is not as its object shows, for either role", async () => {
  const c = await sealedCase("RL3 gap reference");
  const { note, notePath } = noteFor(c.id, C.registrationPath(c.id, "a"));
  gh.seed(PINS, notePath, note);
  for (const role of ["a", "b"]) {
    const r = await reference(c, { role });
    assert.deepEqual([r.status, r.body.error_code, r.body.role], [503, "case_record_inconsistent", "a"], JSON.stringify(r.body).slice(0, 300));
  }
});

test("MUST-FAIL GAP (H33): a write that could not be confirmed and whose note could not be written says nothing was removed", async () => {
  const id = await openCase("RL3 gap no note");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const rpath = C.registrationPath(id, "a");
  const viaMock = global.fetch;
  global.fetch = async (url, o) => ((o && o.method) === "PUT" && String(url).includes(`/contents/removals/${id}/`)
    ? { ok: false, status: 502, json: async () => ({ message: "mock: refused" }), text: async () => "mock: refused" } : viaMock(url, o));
  let r;
  try {
    r = await during((url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
      async () => gh.forceGetFailure(PINS, C.casePath(id), 1, 503), () => commit(id, a));
  } finally {
    global.fetch = viaMock;
  }
  assert.deepEqual([r.out.body.error_code, r.out.body.registration_removed, r.out.body.error], ["registration_unconfirmed", false,
    "the case record could not be read after the registration's write, so this service cannot show the case was not withdrawn meanwhile, and a " +
    "registration never stands on an assumption: no repair note could be written and confirmed, so nothing was removed: the file may be there, and " +
    "it stands only once a read of the case confirms it. Send the same registration again"], JSON.stringify(r.out.body));
  assert.equal(gh.has(PINS, rpath), true);
});

test("MUST-FAIL GAP (P01, P02, P03, P05, P14, P15, P16): the page: a condemned file's row links its note; a case its object shows COMMITTED is open in its title and its words; a check that could not look is said per role, and the page is not kept", async () => {
  const c = await condemnedA("RL3 gap page");
  projectedAnyway(c);
  const r = await render(c.id, NOW + 5000);
  assert.ok(r.html.includes(`<title>Case ${c.id.slice(0, 12)}: OPEN</title>`), r.html.slice(0, 600));
  assert.ok(r.html.includes("Each role registers a stamped commitment before the deadline"));
  assert.match(r.html, new RegExp(`href="[^"]*/${c.notePath.replace(/[.]/g, "\\.")}"[^>]*>the repair note</a>`));
  assert.equal(r.definite, true, "fixture: a page that is kept");
  // the case's notes listed by the removals read, and not by the second listing
  const viaMock = global.fetch;
  let listings = 0;
  global.fetch = async (url, o) => {
    const u = String(url);
    if (((o && o.method) || "GET") === "GET" && u.includes(`/contents/removals/${c.id}?`)) {
      listings += 1;
      if (listings === 2) return { ok: false, status: 503, json: async () => ({}), text: async () => "" };
    }
    return viaMock(url, o);
  };
  let unlisted;
  try {
    unlisted = await render(c.id, NOW + 5000);
  } finally {
    global.fetch = viaMock;
  }
  for (const role of ["a", "b"]) {
    assert.ok(unlisted.html.includes(esc(`whether its registration file is under a repair note could not be read when this page was read (repair_notes_unreadable)`)),
      role);
  }
  assert.equal(unlisted.html.split("whether its registration file is under a repair note could not be read").length - 1, 2);
  assert.equal(unlisted.definite, false);
  unverifiable(c.notePath);
  const unsure = await render(c.id, NOW + 5000);
  assert.equal(unsure.html.split(esc("whether its registration file is under a repair note could not be read when this page was read (document_unavailable)")).length - 1, 1);
});

test("MUST-FAIL GAP (P07): a case with no note and no removal whose path's history could not be read shows the Removals panel saying so", async () => {
  const c = await committedCase("RL3 gap only unread");
  const rpath = C.registrationPath(c.id, "a");
  gh.addCommit(PINS, rpath, "mock: touched");
  S._internal.clearCommitFiles();
  gh.forceRawFailure(1, 404, `@${gh.commitsFor(PINS, rpath)[0].sha}:${rpath}`);
  const p = panelOf((await render(c.id, NOW + 5000)).html);
  assert.ok(p.includes(`the history of ${rpath} could not be read when this page was read (registration_at_commit_not_shown)`), p);
});

test("MUST-FAIL GAP (S32, S33): a case with no registration file, or no note, reads nothing further: its notes are not listed, and no file's history is read", async () => {
  const id = await openCase("RL3 gap no reads");
  const notesKey = `${PINS}::removals/${id}`;
  gh.forceGetFailure(PINS, `removals/${id}`, 1, 503);
  const a = party(id, "a", AGENT_TAPE);
  await register(id, a);
  assert.equal(gh._forcedGetFailure.get(notesKey).remaining, 1, "the notes were not listed for a case with no file");
  gh._forcedGetFailure.delete(notesKey);
  const rpath = C.registrationPath(id, "a");
  gh.forceCommitsFailure(PINS, rpath, 1, 503);
  await register(id, party(id, "b", TOOL_TAPE));
  assert.equal(gh._forcedCommitsFailure.get(`${PINS}::${rpath}`).remaining, 1, "no file's history was read for a case with no note");
});
