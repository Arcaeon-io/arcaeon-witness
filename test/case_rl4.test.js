// test/case_rl4.test.js — unit R-L4 (2026-10-13): nothing is ever deleted.
// Four review rounds each found one more reader of a registration file that
// the rule "unwind an unconfirmed registration" could delete after the
// service had answered 200 for it. The architect's ruling: a 503 leaves the
// world where a re-send can finish from, never where something must be
// reversed. The unwind, the repair notes, the removals and "condemned" are
// gone.
//   THE RULE: a registration file is a claim, inert until the case root
// projects it. The handler projects only after a fresh read of the case
// root shows no withdrawal and no seal, by a compare-and-swap that carries
// the file's sha256. A confirming read or projection that fails writes
// nothing more and answers 503; the same registration sent again finds the
// file and projects it. Every reader takes registrations from the
// projection alone and checks the file at the path against the sha256 it
// carries: a mismatch or a missing file is DAMAGED. The setup below is
// test/case_rl3.test.js's.
"use strict";

"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0152:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rl4");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rl4");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rl4");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0152" });

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
  return `10.94.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
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
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0152", url: "https://second-operator.example/cases/0152" });
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
    else if (/\.(js|mjs|cjs)$/.test(e.name)) out.push(rel);
  }
  return out;
}

// The registration file at `rpath` as the pins repository holds it: its
// bytes, and their sha256.
const fileText = (rpath) => gh._repoMap(PINS).get(rpath).content;
const fileSha256 = (rpath) => sha(Buffer.from(fileText(rpath), "utf8"));
// What the case root projects for the file at `rpath` (unit R-L4, rule 2):
// the registration's entry and the sha256 of the file's bytes.
const projectionOf = (rpath) => ({ ...C.commitmentEntry(gh.read(PINS, rpath)), registration_sha256: fileSha256(rpath) });
// How many writes of the case root put role `role` into it (null before, an
// entry after).
function projectionsOf(id, role) {
  const list = gh.commitsFor(PINS, C.casePath(id)).slice().reverse(); // oldest first
  let n = 0;
  let before = null;
  for (const cm of list) {
    const k = cm.content === null ? null : JSON.parse(cm.content);
    const now = k && k.commitments ? k.commitments[role] : null;
    if (before === null && now) n += 1;
    before = now || null;
  }
  return n;
}
const deletes = () => gh.deleteLog.length;
// Role a's registration written, and the read of the case root after it
// (the confirming read) failed: the 503 of rule 3.
async function unconfirmedA(scope, { now = NOW } = {}) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const rpath = C.registrationPath(id, "a");
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
    async () => gh.forceGetFailure(PINS, C.casePath(id), 1, 503),
    () => commit(id, a, now),
  );
  assert.equal(r.fired, true);
  return { id, a, rpath, out: r.out };
}
// The registrations panel of a page, as plain text.
function registrationsOf(html) {
  const i = html.indexOf("<h2>Registrations</h2>");
  if (i < 0) return "";
  return html.slice(i, html.indexOf("</section>", i)).replace(/<[^>]+>/g, " ").replace(/&#39;/g, "'").replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&").replace(/\s+/g, " ");
}

// THE WORDS, exactly
const UNCONFIRMED = "the registration file is written and is not yet confirmed; send the same registration again";
const WITHDRAWN_BEFORE_CONFIRMED = "the case was withdrawn before this registration was confirmed; the registration file is written and has no standing";
const LATE_UNCONFIRMED = "the case's deadline has passed, and the registration file written for this role was never confirmed; it has no standing " +
  "and cannot acquire it";
const WRITTEN_NOT_CONFIRMED = "written, not confirmed";
const WRITTEN_NEVER_CONFIRMED = "written, never confirmed; this file has no standing and cannot acquire it";
const WRITTEN_UNDER_WITHDRAWAL = "written; the case is withdrawn, so this file has no standing and cannot acquire it";
const PROPERTY = "No file in the pins repository is ever deleted. Registration files, reference rows, pins, withdrawal records and seals " +
  "are written once and never changed. The case root is the one file that is updated, and only by a compare-and-swap that every reader " +
  "can follow in the repository's history.";
const PREVIEW_REMOVALS = "Files under removals/ that a preview pins repository may hold are ignored: no code reads or writes them.";

// =============================================================================
// THE RULE
// =============================================================================

test("R-L4: the confirming read fails: 503 in the rule's words, the file is there, the case root does not project it, and the page says written, not confirmed", async () => {
  const u = await unconfirmedA("RL4 unconfirmed");
  assert.deepEqual([u.out.status, u.out.body.error_code, u.out.body.error, u.out.body.registration_recorded],
    [503, "registration_unconfirmed", UNCONFIRMED, null], JSON.stringify(u.out.body));
  assert.equal(gh.has(PINS, u.rpath), true, "the file is there");
  assert.equal(storedCase(u.id).commitments.a, null, "the case root does not project it");
  assert.equal(deletes(), 0);
  const rows = registrationsOf((await casePage(u.id, NOW + 5000)).html);
  assert.ok(rows.includes(`role a ${WRITTEN_NOT_CONFIRMED}`), rows);
});

test("R-L4: the same registration sent again finds the file and projects it, with the file's sha256: 200, and no second file", async () => {
  const u = await unconfirmedA("RL4 resend");
  const again = await commit(u.id, u.a, NOW + 1500);
  assert.deepEqual([again.status, again.body.existing], [200, true], JSON.stringify(again.body).slice(0, 300));
  assert.equal(gh.commitsFor(PINS, u.rpath).length, 1, "the file written once");
  assert.deepEqual(storedCase(u.id).commitments.a, projectionOf(u.rpath));
  assert.deepEqual(again.body.case.commitments.a, projectionOf(u.rpath));
  assert.equal(projectionsOf(u.id, "a"), 1);
  assert.equal(deletes(), 0);
});

test("R-L4: two overlapping sends of the same registration: exactly one file, exactly one projection, and both answers say what the case root holds", async () => {
  const id = await openCase("RL4 overlap");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const rpath = C.registrationPath(id, "a");
  // the second send arrives once the first's lease has run out, and writes first
  const late = NOW + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000;
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
    () => commit(id, a, late),
    () => commit(id, a, NOW),
  );
  assert.equal(r.fired, true);
  assert.equal(gh.commitsFor(PINS, rpath).length, 1, "exactly one file");
  assert.equal(projectionsOf(id, "a"), 1, "exactly one projection");
  const held = projectionOf(rpath);
  assert.deepEqual(storedCase(id).commitments.a, held);
  assert.deepEqual([r.inner.status, r.out.status], [201, 200], JSON.stringify([r.inner.body, r.out.body]).slice(0, 400));
  for (const x of [r.inner, r.out]) assert.deepEqual(x.body.case.commitments.a, held);
});

test("R-L4: a different registration for a role whose file is written and not projected is 409 registration_exists naming the file's sha256, and nothing is written", async () => {
  const u = await unconfirmedA("RL4 exists");
  const other = party(u.id, "a", AGENT_TAPE);
  plantStamp(other.commitment_sha256);
  const before = gh._commitsOf(PINS).length;
  const r = await commit(u.id, other, NOW + 1500);
  assert.deepEqual([r.status, r.body.error_code, r.body.existing_sha256, r.body.registration_recorded], [409, "registration_exists", fileSha256(u.rpath), false],
    JSON.stringify(r.body));
  assert.equal(gh._commitsOf(PINS).length, before, "nothing written");
  assert.equal(storedCase(u.id).commitments.a, null);
});

test("R-L4: a file with no projection past the deadline is written, never confirmed, and the case never commits on it", async () => {
  const u = await unconfirmedA("RL4 late");
  await register(u.id, party(u.id, "b", TOOL_TAPE));
  assert.equal(storedCase(u.id).status, "OPEN", "role b alone is projected");
  const after = Date.parse(DEADLINE) + 1000;
  const late = await commit(u.id, u.a, after);
  assert.deepEqual([late.status, late.body.error_code, late.body.error], [409, "late_commitment", LATE_UNCONFIRMED], JSON.stringify(late.body));
  assert.deepEqual([storedCase(u.id).status, storedCase(u.id).commitments.a], ["OPEN", null]);
  const rows = registrationsOf((await casePage(u.id, after)).html);
  assert.ok(rows.includes(`role a ${WRITTEN_NEVER_CONFIRMED}`), rows);
  assert.equal(gh.has(PINS, u.rpath), true);
});

test("R-L4: a registration written after its case's withdrawal is 409 case_withdrawn, the file stays, the case stays WITHDRAWN, and nothing is deleted", async () => {
  const id = await openCase("RL4 after withdrawal");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const rpath = C.registrationPath(id, "b");
  const late = NOW + 1000 + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000;
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
    () => withdraw(id, a, { now: late }),
    () => commit(id, b, NOW + 1000),
  );
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body));
  assert.deepEqual([r.out.status, r.out.body.error_code, r.out.body.error, r.out.body.registration_recorded],
    [409, "case_withdrawn", WITHDRAWN_BEFORE_CONFIRMED, false], JSON.stringify(r.out.body));
  assert.equal(gh.has(PINS, rpath), true, "the file stays");
  assert.equal(storedCase(id).status, "WITHDRAWN");
  assert.equal(deletes(), 0);
  assert.deepEqual(pinsPaths().filter((p) => p.startsWith("removals/")), []);
  const rows = registrationsOf((await casePage(id)).html);
  assert.ok(rows.includes(`role b ${WRITTEN_UNDER_WITHDRAWAL}`), rows);
});

test("R-L4: a projected sha256 that the file at the path does not match, or a file missing under a projection, is DAMAGED: never sealed, never pinned, shown plainly", async () => {
  const c = await committedCase("RL4 damaged");
  const rpath = C.registrationPath(c.id, "a");
  gh._repoMap(PINS).get(rpath).content += " "; // the same JSON, other bytes
  const r = await reveal(c);
  assert.deepEqual([r.status, r.body.error_code, r.body.role, r.body.reason], [409, "case_damaged", "a", "registration_file_differs"],
    JSON.stringify(r.body).slice(0, 300));
  assert.equal(storedCase(c.id).status, "COMMITTED", "never sealed");
  const html = (await casePage(c.id)).html;
  assert.match(html, /Case: DAMAGED/);
  assert.ok(html.includes(esc(`role a's registration file, ${rpath}, is not the file the case root projects (registration_file_differs)`)), html.slice(0, 2000));
  const run = await sealerRun();
  assert.deepEqual(run.damaged, [{ case_id: c.id, role: "a", reason: "registration_file_differs" }]);
  const d = await committedCase("RL4 damaged missing");
  gh._repoMap(PINS).delete(C.registrationPath(d.id, "b"));
  const m = await reveal(d);
  assert.deepEqual([m.status, m.body.error_code, m.body.role, m.body.reason], [409, "case_damaged", "b", "registration_file_missing"]);
  assert.equal(storedCase(d.id).status, "COMMITTED");
});

test("R-L4: a reveal racing a withdrawal: exactly one of them writes the case root", async () => {
  // the withdrawal lands between the reveal's read of the case root and its first write
  const c = await committedCase("RL4 race withdrawal first");
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(c.id)}`),
    () => withdraw(c.id, c.b),
    () => reveal(c),
  );
  assert.deepEqual([r.inner.status, r.out.status, r.out.body.error_code], [201, 409, "case_withdrawn"], JSON.stringify(r.out.body).slice(0, 300));
  assert.equal(storedCase(c.id).status, "WITHDRAWN");
  const rows = registrationsOf((await casePage(c.id)).html);
  assert.ok(rows.includes(`role a ${WRITTEN_UNDER_WITHDRAWAL}`) && rows.includes(`role b ${WRITTEN_UNDER_WITHDRAWAL}`), rows);
  // the reveal lands between the withdrawal's read and its write
  const d = await committedCase("RL4 race reveal first");
  const s = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(d.id)}`),
    () => reveal(d),
    () => withdraw(d.id, d.b),
  );
  assert.deepEqual([s.inner.status, s.out.status, s.out.body.error_code], [201, 409, "case_sealed"], JSON.stringify(s.out.body).slice(0, 300));
  const k = storedCase(d.id);
  assert.equal(k.status, "VERDICT");
  for (const role of C.ROLES) assert.deepEqual(k.commitments[role], projectionOf(C.registrationPath(d.id, role)));
});

test("R-L4: no code in lib/ deletes from the pins store, and the one module that did is gone", () => {
  const DELETE_RE = /method\s*:\s*["'`]delete["'`]|["'`]DELETE["'`]|\bgit\s+rm\b|\bdeleteFile\s*\(/i;
  const hits = jsFiles("lib").filter((f) => DELETE_RE.test(read(f)));
  // lib/_balance.js deletes only from the private usage repository
  // (GITHUB_USAGE_REPO), never from the pins store; the case lock record
  // lives in that usage repository too, and is released by a write, never
  // deleted. Neither is the pins store.
  assert.deepEqual(hits, ["lib/_balance.js"]);
  assert.match(read("lib/_balance.js"), /fetch\(`\$\{API\}\/repos\/\$\{USAGE_REPO\}[^`]*`,\s*\{\s*method:\s*"DELETE"/);
  assert.equal(fs.existsSync(path.join(__dirname, "..", "lib", "_case_unregister.js")), false);
  assert.deepEqual(Object.keys(store).filter((k) => /del|remove|rm/i.test(k)), []);
});

test("R-L4: the README states the public property verbatim, says removals/ files are ignored, and describes no removal, repair note or exception", () => {
  const text = README();
  assert.ok(text.includes(PROPERTY));
  assert.ok(text.includes(PREVIEW_REMOVALS));
  assert.doesNotMatch(text, /repair note|create-only except|removals that carry|is removed only|recorded removal|removal of (this|a|the) file/i);
  assert.doesNotMatch(S.WITHDRAWN_REGISTRATIONS_NOTE, /remov|repair/i);
});

test("R-L4: the sealer's index and the status counts read no registration file: a case is a candidate by its root, and files make no count", () => {
  const id = "a".repeat(64);
  const bare = [{ path: C.casePath(id), type: "blob" }];
  const withFiles = [...bare, { path: C.registrationPath(id, "a"), type: "blob" }, { path: C.registrationPath(id, "b"), type: "blob" }];
  assert.deepEqual(S.caseTreeIndex(bare).sealable, [id]);
  assert.deepEqual(S.caseTreeIndex(withFiles).sealable, [id]);
  assert.deepEqual(S.caseAnchorSummary(bare), S.caseAnchorSummary(withFiles));
  assert.deepEqual(S.caseAnchorSummary(bare), { case_files: 1, pinned: 0, pending: 1, withdrawn: 0, partial: false });
});
