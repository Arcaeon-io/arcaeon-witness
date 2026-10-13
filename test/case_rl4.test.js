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
// carries: a mismatch or a missing file is never sealed (since unit R-L4b,
// 503 case_record_inconsistent). The setup below is
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
// Since unit R-L4c (c4) the entry names the file's claim too: the sha256 of
// the json-c14n:v1 bytes of the fields a party supplies, computed here.
const PARTY = ["case_id", "role", "commitment_sha256", "verifier", "key_id", "sig"];
const claimOf = (rec) => sha(canonicalBytes(Object.fromEntries(PARTY.map((k) => [k, rec[k]]))));
const projectionOf = (rpath) => ({ ...C.commitmentEntry(gh.read(PINS, rpath)), registration_sha256: fileSha256(rpath), claim_sha256: claimOf(gh.read(PINS, rpath)) });
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
  const rpath = REG.claimPath({ case_id: id, ...a }, a.key);
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
// since unit R-L4c: no "cannot acquire it"
const LATE_UNCONFIRMED = "the case's deadline has passed, and the registration file written for this request was never confirmed; it has no standing";
// since unit R-L4c (c4): the page lists no claim file; a role the root does
// not project is said to have no confirmed registration, and the WITHDRAWN
// and EXPIRED pages show no registration rows
const NO_REGISTRATION = "no registration is confirmed for this role";
// since unit R-L4c (c3), scoped to a case's own files
const PROPERTY = "No file that belongs to a case is ever deleted. A case's registration files, reference rows, withdrawal record and seal " +
  "are written once and never changed. The case root is the one case file that is updated, and only by a compare-and-swap that every " +
  "reader can follow in the repository's history.";
const PREVIEW_REMOVALS = "Files under removals/ that a preview pins repository may hold are ignored: no code reads or writes them.";

// =============================================================================
// THE RULE
// =============================================================================

test("R-L4: the confirming read fails: 503 in the rule's words, the file is there, the case root does not project it, and the page says no registration is confirmed for the role (since unit R-L4c, c4)", async () => {
  const u = await unconfirmedA("RL4 unconfirmed");
  assert.deepEqual([u.out.status, u.out.body.error_code, u.out.body.error, u.out.body.registration_recorded],
    [503, "registration_unconfirmed", UNCONFIRMED, null], JSON.stringify(u.out.body));
  assert.equal(gh.has(PINS, u.rpath), true, "the file is there");
  assert.equal(storedCase(u.id).commitments.a, null, "the case root does not project it");
  assert.equal(deletes(), 0);
  const rows = registrationsOf((await casePage(u.id, NOW + 5000)).html);
  assert.ok(rows.includes(`role a ${NO_REGISTRATION}`), rows);
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
  const rpath = REG.claimPath({ case_id: id, ...a }, a.key);
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

test("R-L4: a file with no projection past the deadline is written, never confirmed, and the case never commits on it", async () => {
  const u = await unconfirmedA("RL4 late");
  await register(u.id, party(u.id, "b", TOOL_TAPE));
  assert.equal(storedCase(u.id).status, "OPEN", "role b alone is projected");
  const after = Date.parse(DEADLINE) + 1000;
  const late = await commit(u.id, u.a, after);
  assert.deepEqual([late.status, late.body.error_code, late.body.error], [409, "late_commitment", LATE_UNCONFIRMED], JSON.stringify(late.body));
  assert.deepEqual([storedCase(u.id).status, storedCase(u.id).commitments.a], ["OPEN", null]);
  const rows = registrationsOf((await casePage(u.id, after)).html);
  assert.equal(rows, "", "an EXPIRED page shows no registration rows");
  assert.equal(gh.has(PINS, u.rpath), true);
});

test("R-L4: a registration written after its case's withdrawal is 409 case_withdrawn, the file stays, the case stays WITHDRAWN, and nothing is deleted", async () => {
  const id = await openCase("RL4 after withdrawal");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const rpath = REG.claimPath({ case_id: id, ...b }, b.key);
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
  assert.equal(rows, "", "a WITHDRAWN page shows no registration rows");
});

test("R-L4: a projected sha256 that the file at the path does not match, or a file missing under a projection, is never sealed and never pinned (since unit R-L4b: 503 case_record_inconsistent, the could-not-look page)", async () => {
  const c = await committedCase("RL4 inconsistent");
  const rpath = REG.pathOf(gh, c.id, "a");
  gh._repoMap(PINS).get(rpath).content += " "; // the same JSON, other bytes
  const r = await reveal(c);
  assert.deepEqual([r.status, r.body.error_code, r.body.role, r.body.reason], [503, "case_record_inconsistent", "a", "registration_file_differs"],
    JSON.stringify(r.body).slice(0, 300));
  assert.equal(storedCase(c.id).status, "COMMITTED", "never sealed");
  const page = await casePage(c.id);
  assert.equal(page.status, 503);
  assert.match(page.html, /Case: COULD NOT LOOK/);
  assert.ok(page.html.includes("<code>case_record_inconsistent</code>"), page.html.slice(0, 2000));
  const run = await sealerRun();
  assert.deepEqual(run.refused, [{ case_id: c.id, code: "case_record_inconsistent", role: "a", reason: "registration_file_differs" }]);
  const d = await committedCase("RL4 inconsistent missing");
  gh._repoMap(PINS).delete(REG.pathOf(gh, d.id, "b"));
  const m = await reveal(d);
  assert.deepEqual([m.status, m.body.error_code, m.body.role, m.body.reason], [503, "case_record_inconsistent", "b", "registration_file_missing"]);
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
  assert.equal(rows, "", "a WITHDRAWN page shows no registration rows");
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
  for (const role of C.ROLES) assert.deepEqual(k.commitments[role], projectionOf(REG.pathOf(gh, d.id, role)));
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
  const withFiles = [...bare, { path: REG.pathOf(gh, id, "a"), type: "blob" }, { path: REG.pathOf(gh, id, "b"), type: "blob" }];
  assert.deepEqual(S.caseTreeIndex(bare).sealable, [id]);
  assert.deepEqual(S.caseTreeIndex(withFiles).sealable, [id]);
  assert.deepEqual(S.caseAnchorSummary(bare), S.caseAnchorSummary(withFiles));
  assert.deepEqual(S.caseAnchorSummary(bare), { case_files: 1, pinned: 0, pending: 1, withdrawn: 0, partial: false });
});

// =============================================================================
// RULE 3 AS CORRECTED (the architect's finding): the same registration is
// the same PARTY-SUPPLIED fields, never the same bytes
// =============================================================================

test("R-L4 (rule 3 corrected): the same registration re-sent with a later clock projects the ORIGINAL file as it is: its own sha256 and its own registered_at, 200 existing", async () => {
  const u = await unconfirmedA("RL4 corrected later clock");
  const original = fileText(u.rpath);
  const later = NOW + 3600000;
  const again = await commit(u.id, u.a, later);
  assert.deepEqual([again.status, again.body.existing], [200, true], JSON.stringify(again.body).slice(0, 300));
  const k = storedCase(u.id);
  assert.equal(k.commitments.a.registration_sha256, sha(Buffer.from(original, "utf8")), "the original file's sha256");
  assert.equal(k.commitments.a.registered_at, C.utcSeconds(NOW), "the original file's registered_at, not the re-send's clock");
  assert.equal(again.body.registration.registered_at, C.utcSeconds(NOW));
  assert.equal(fileText(u.rpath), original, "nothing written over it");
});

test("R-L4 (rule 3 corrected): a file holding the same party-supplied fields in other bytes (another layout, the service's fields of its own) is the same registration, projected as it is", async () => {
  const u = await unconfirmedA("RL4 corrected other bytes");
  const rec = gh.read(PINS, u.rpath);
  // the same record, written compactly and with fields in another order
  const { sig, verifier, ...rest } = rec;
  const other = JSON.stringify({ sig, verifier, ...rest });
  gh._repoMap(PINS).get(u.rpath).content = other;
  const again = await commit(u.id, u.a, NOW + 1500);
  assert.deepEqual([again.status, again.body.existing], [200, true], JSON.stringify(again.body).slice(0, 300));
  assert.equal(storedCase(u.id).commitments.a.registration_sha256, sha(Buffer.from(other, "utf8")));
});

test("R-L4 (rule 3 corrected): two overlapping sends of the same registration with different clocks are answered by the one file: both answers carry its registered_at", async () => {
  const id = await openCase("RL4 corrected overlap clocks");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const rpath = REG.claimPath({ case_id: id, ...a }, a.key);
  const late = NOW + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000;
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
    () => commit(id, a, late),
    () => commit(id, a, NOW),
  );
  assert.equal(gh.commitsFor(PINS, rpath).length, 1, "one file");
  assert.equal(projectionsOf(id, "a"), 1, "one projection");
  const held = gh.read(PINS, rpath);
  assert.equal(held.registered_at, C.utcSeconds(late), "fixture: the later send wrote first");
  for (const x of [r.inner, r.out]) {
    assert.ok(x.status === 200 || x.status === 201, JSON.stringify(x.body).slice(0, 200));
    assert.equal(x.body.registration.registered_at, held.registered_at);
    assert.deepEqual(x.body.case.commitments.a, projectionOf(rpath));
  }
});

// =============================================================================
// MUST-FAIL GAP TESTS: what the must-fail pass over the lines R-L4 changed
// found no test for
// =============================================================================

const render = (id, nowMs = NOW + 5000, doc = DOC) => CP._internal.renderCase(storedCase(id), nowMs, doc);
const LATER = (ms = 0) => NOW + ms + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000; // a lease run out
// A root that projects role b's file registered under role a's key, written
// by hand (no request makes one since R-L4: the second projection is refused).
async function singlePartyByHand(scope) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  await register(id, a);
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(b.commitment_sha256);
  const rec = C.registrationRecord({ case_id: id, role: "b", commitment_sha256: b.commitment_sha256, registered_at: C.utcSeconds(NOW),
    stamp_commit: gh.commitsFor(STAMPS, stamp.stampPath(b.commitment_sha256))[0].sha, stamped_at: "2026-10-10T07:45:00.123Z",
    ...REG.keyFields({ case_id: id, role: "b", commitment_sha256: b.commitment_sha256 }, REG.KEYS.a) });
  const rpath = REG.recordPath(rec);
  gh.seed(PINS, rpath, rec);
  gh.seed(PINS, C.casePath(id), C.applyRegistration(storedCase(id), rec, fileSha256(rpath)), { keepHistory: true });
  assert.equal(C.singleParty(storedCase(id)), true, "fixture: single party");
  return { id, a, b };
}

test("MUST-FAIL GAP (H03, S19, S18, S20; since unit R-L4b, case_record_inconsistent): the refusal says which role and why: a file not the one projected, a file missing, a root entry its file does not hold", async () => {
  const c = await committedCase("RL4 gap inconsistent words");
  gh._repoMap(PINS).get(REG.pathOf(gh, c.id, "a")).content += " ";
  const r = await reveal(c);
  assert.ok(r.body.error.startsWith("role a's registration file does not match the hash this case records for it (registration_file_differs), " +
    "and nothing is answered from this case until it does"), r.body.error);
  const d = await committedCase("RL4 gap inconsistent missing words");
  gh._repoMap(PINS).delete(REG.pathOf(gh, d.id, "b"));
  const m = await reveal(d);
  assert.deepEqual([m.body.role, m.body.reason], ["b", "registration_file_missing"]);
  const e = await committedCase("RL4 gap inconsistent entry");
  const k = storedCase(e.id);
  gh.seed(PINS, C.casePath(e.id), { ...k, commitments: { ...k.commitments, b: { ...k.commitments.b, registered_at: "2026-10-10T08:00:01Z" } } });
  const x = await reveal(e);
  assert.deepEqual([x.status, x.body.error_code, x.body.role, x.body.reason], [503, "case_record_inconsistent", "b", "projection_differs_from_file"]);
});

test("MUST-FAIL GAP (H09, H10): a replay of a projected registration is not refused by the other role's key; another registration for a projected role names the registered entry without the file's sha256", async () => {
  const s = await singlePartyByHand("RL4 gap replay single party");
  const replay = await commit(s.id, s.a, NOW + 1500);
  assert.deepEqual([replay.status, replay.body.existing], [200, true], JSON.stringify(replay.body).slice(0, 300));
  const c = await committedCase("RL4 gap registered entry");
  const other = party(c.id, "a", AGENT_TAPE);
  plantStamp(other.commitment_sha256);
  const r = await commit(c.id, other, NOW + 1500);
  assert.deepEqual([r.status, r.body.error_code], [409, "role_already_committed"]);
  assert.deepEqual(r.body.registered, C.commitmentEntry(gh.read(PINS, REG.pathOf(gh, c.id, "a"))));
});

test("MUST-FAIL GAP (H11, H20, H38): the refusals after a write carry the time it was received and say the root does not project it", async () => {
  const u = await unconfirmedA("RL4 gap received at");
  assert.equal(u.out.body.received_at, C.utcSeconds(NOW));
  const late = await commit(u.id, u.a, Date.parse(DEADLINE) + 1000);
  assert.equal(late.body.registration_recorded, false);
  // the second projection under one key, refused at the projection
  const id = await openCase("RL4 gap bar at projection");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(a.commitment_sha256);
  plantStamp(b.commitment_sha256);
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${REG.dirOf(id, "b")}/`),
    () => commit(id, { ...a, key: REG.KEYS.a }, LATER()),
    () => commit(id, { ...b, key: REG.KEYS.a }, NOW),
  );
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body).slice(0, 200));
  assert.deepEqual([r.out.status, r.out.body.error_code, r.out.body.registration_recorded, r.out.body.received_at],
    [409, "same_key_both_roles", false, C.utcSeconds(NOW)], JSON.stringify(r.out.body));
});

test("MUST-FAIL GAP (H14; since unit R-L4c, c1): a case sealed between the re-send's read and its confirming read, after another re-send projected the file: the projection is looked at first, 200 existing:true with the projected values", async () => {
  const u = await unconfirmedA("RL4 gap sealed meanwhile");
  const b = party(u.id, "b", TOOL_TAPE);
  await register(u.id, b);
  const c = { id: u.id, a: u.a, b };
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${USAGE}/contents/${H._internal.caseLockPath(u.id)}`),
    async () => [(await commit(u.id, u.a, NOW + 1000)).status, (await reveal(c)).status],
    () => commit(u.id, u.a, NOW + 1500),
  );
  assert.deepEqual(r.inner, [200, 201], "another re-send projected it, and the case sealed");
  assert.deepEqual([r.out.status, r.out.body.existing, r.out.body.status], [200, true, "VERDICT"], JSON.stringify(r.out.body).slice(0, 300));
  assert.deepEqual(r.out.body.case.commitments.a, projectionOf(u.rpath));
});

test("MUST-FAIL GAP (H22, H28): a confirming read that is not a case, and a root re-read that fails after the projection lost, are 503 with the projection not known", async () => {
  const id = await openCase("RL4 gap junk root");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${REG.dirOf(id, "a")}/`),
    async () => gh.seed(PINS, C.casePath(id), { not: "a case" }, { keepHistory: true }),
    () => commit(id, a),
  );
  assert.deepEqual([r.out.status, r.out.body.error_code, r.out.body.registration_recorded], [503, "registration_unconfirmed", null], JSON.stringify(r.out.body));
  // the projection loses to a withdrawal, and the read after it fails
  const d = await openCase("RL4 gap reread fails");
  const da = party(d, "a", AGENT_TAPE);
  plantStamp(da.commitment_sha256);
  const cpath = C.casePath(d);
  const viaMock = global.fetch;
  let armed = false;
  let gets = 0;
  global.fetch = async (url, o) => {
    const method = (o && o.method) || "GET";
    const onCase = String(url).includes(`/repos/${PINS}/contents/${cpath}`);
    if (onCase && method === "PUT" && !armed) {
      armed = true;
      gh.seed(PINS, cpath, S.withdrawnRecord(storedCase(d), { role: "b", at: C.utcSeconds(NOW + 500), salt: C.newSalt() },
        S.loadCaseSigner(KEYS, { keyDocument: DOC })), { keepHistory: true });
    } else if (onCase && method === "GET" && armed && (gets += 1) === 2) {
      return { ok: false, status: 503, json: async () => ({}), text: async () => "" };
    }
    return viaMock(url, o);
  };
  let out;
  try {
    out = await commit(d, da);
  } finally {
    global.fetch = viaMock;
  }
  assert.deepEqual([out.status, out.body.error_code, out.body.registration_recorded], [503, "registration_unconfirmed", null], JSON.stringify(out.body));
});

test("MUST-FAIL GAP (H23, H29): a projection another send made first is answered 200 with nothing projected by this one, whether found at the confirming read or after the compare-and-swap lost", async () => {
  const u = await unconfirmedA("RL4 gap found after the swap");
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(u.id)}`),
    () => commit(u.id, u.a, LATER(1500)),
    () => commit(u.id, u.a, NOW + 1500),
  );
  assert.deepEqual([r.inner.status, r.inner.body.projected], [200, ["a"]], JSON.stringify(r.inner.body).slice(0, 200));
  assert.deepEqual([r.out.status, r.out.body.projected], [200, []], JSON.stringify(r.out.body).slice(0, 200));
  // found at the confirming read: the overlapping sends of the rule's own test
  const id = await openCase("RL4 gap found at the read");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const s = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${REG.dirOf(id, "a")}/`),
    () => commit(id, a, LATER()),
    () => commit(id, a, NOW),
  );
  assert.deepEqual([s.inner.body.projected, s.out.body.projected], [["a"], []]);
});

test("MUST-FAIL GAP (H34, H39, H40): a replay rechecks its stamp; a re-send of a written file rechecks the stamp without its history, and says so when the stamp is gone", async () => {
  const c = await committedCase("RL4 gap replay stamp");
  const spath = stamp.stampPath(c.a.commitment_sha256);
  gh.seed(STAMPS, spath, { kind: "file-stamp", v: 1, sha256: c.a.commitment_sha256, size: 64, stamped_at: "2026-10-10T07:45:00.123Z" });
  const r = await commit(c.id, c.a, NOW + 1500);
  assert.deepEqual([r.status, r.body.error_code], [409, "stamp_size_mismatch"], JSON.stringify(r.body).slice(0, 200));
  const u = await unconfirmedA("RL4 gap held stamp history");
  gh.addCommit(STAMPS, stamp.stampPath(u.a.commitment_sha256), "mock: a second commit touching the stamp");
  const again = await commit(u.id, u.a, NOW + 1500);
  assert.equal(again.status, 200, JSON.stringify(again.body).slice(0, 200));
  const v = await unconfirmedA("RL4 gap held stamp gone");
  gh._repoMap(STAMPS).delete(stamp.stampPath(v.a.commitment_sha256));
  const gone = await commit(v.id, v.a, NOW + 1500);
  assert.deepEqual([gone.status, gone.body.error_code, gone.body.reason], [503, "stamp_record_unreadable", "stamp_missing"]);
});

test("MUST-FAIL GAP (H36, H45): the file at the path that could not be read writes nothing; a write that kept losing to a file that is not there says the registration is not recorded", async () => {
  const id = await openCase("RL4 gap path unread");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  gh.forceGetFailure(PINS, REG.claimPath({ case_id: id, ...a }, a.key), 1, 503);
  const r = await commit(id, a);
  assert.deepEqual([r.status, r.body.error_code], [503, "store_unreachable"]);
  assert.equal(gh.has(PINS, REG.claimPath({ case_id: id, ...a }, a.key)), false);
  gh.forceConflict(PINS, REG.claimPath({ case_id: id, ...a }, a.key), 10);
  const lost = await commit(id, a);
  assert.deepEqual([lost.status, lost.body.error_code, lost.body.registration_recorded], [503, "store_error", false], JSON.stringify(lost.body));
});

test("MUST-FAIL GAP (H55): a retried withdrawal whose root before the withdrawal projects a file no longer at its path is 503 case_record_inconsistent (since unit R-L4b)", async () => {
  const c = await committedCase("RL4 gap retry damaged");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  gh._repoMap(PINS).get(REG.pathOf(gh, c.id, "b")).content += " ";
  const again = await withdraw(c.id, c.b, { now: NOW + 5000 });
  assert.deepEqual([again.status, again.body.error_code], [503, "case_record_inconsistent"], JSON.stringify(again.body).slice(0, 200));
});

test("MUST-FAIL GAP (S06, S07, S09): the root before the withdrawal is read within its bound, a read that fails says so, and a version that is not a case is not taken", async () => {
  const c = await committedCase("RL4 gap root bound");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  assert.equal((await S.rootBeforeWithdrawal(c.id)).ok, true, "fixture");
  for (let i = 0; i < 5; i += 1) gh.addCommit(PINS, C.casePath(c.id), "mock: the withdrawn root again");
  assert.deepEqual(await S.rootBeforeWithdrawal(c.id), { ok: false, reason: "withdrawal_commit_beyond_bound" });
  const d = await committedCase("RL4 gap root unread");
  assert.equal((await withdraw(d.id, d.b)).status, 201);
  S._internal.clearCommitFiles();
  gh.forceRawFailure(1, 503, `@${gh.commitsFor(PINS, C.casePath(d.id))[0].sha}:${C.casePath(d.id)}`);
  assert.deepEqual(await S.rootBeforeWithdrawal(d.id), { ok: false, reason: "case_at_commit_http_503" });
  const e = await committedCase("RL4 gap root not a case");
  const rec = S.withdrawnRecord(storedCase(e.id), { role: "b", at: C.utcSeconds(NOW + 2000), salt: e.b.salt }, S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  gh.seed(PINS, C.casePath(e.id), { not: "a case" }, { keepHistory: true });
  gh.seed(PINS, C.casePath(e.id), rec, { keepHistory: true });
  assert.deepEqual(await S.rootBeforeWithdrawal(e.id), { ok: false, reason: "case_before_withdrawal_unreadable" });
});

test("MUST-FAIL GAP (S21, S22, S24): the marker repair says a case it could not read and leaves a root that is not withdrawn; the sealer says a registration file it could not read", async () => {
  const c = await committedCase("RL4 gap marker");
  gh.forceGetFailure(PINS, C.casePath(c.id), 1, 503);
  assert.deepEqual(await S.repairWithdrawn(c.id), { case_id: c.id, marker: null, reason: "case_unreadable" });
  assert.equal(await S.repairWithdrawn(c.id), null, "a root that is not withdrawn");
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c.id)), false);
  gh.forceGetFailure(PINS, REG.pathOf(gh, c.id, "a"), 1, 503);
  const run = await sealerRun();
  assert.deepEqual(run.could_not_look, [{ case_id: c.id, reason: "registration_unreadable" }]);
});

test("MUST-FAIL GAP (P02, P03, P05, P10, P11, P13, P14, P18; since unit R-L4c, c4, the page reads no claim file): the page reads each projected file once, says a file it could not read and is then not kept, shows an EXPIRED case no registrations, and keeps no page of an inconsistent record", async () => {
  const c = await committedCase("RL4 gap page reads");
  const apath = REG.pathOf(gh, c.id, "a");
  const from = gh.getLog.length;
  assert.equal((await render(c.id)).definite, true, "fixture: a page that is kept");
  assert.equal(gh.getLog.slice(from).filter((p) => p === apath).length, 1, "the projected file, read once");
  gh.forceGetFailure(PINS, apath, 1, 503);
  const unread = await render(c.id);
  assert.ok(registrationsOf(unread.html).includes("role a its registration file could not be read when this page was read (registration_unreadable)"),
    registrationsOf(unread.html));
  assert.equal(unread.definite, false);
  // a file written and not confirmed is neither read nor linked
  const u = await unconfirmedA("RL4 gap page link");
  assert.equal((await render(u.id)).html.includes(u.rpath), false);
  // EXPIRED, every role projected: no registrations panel
  assert.doesNotMatch((await render(c.id, Date.parse(DEADLINE) + 1000)).html, /<h2>Registrations<\/h2>/);
  // an inconsistent record's page is never kept (unit R-L4b: 503)
  gh._repoMap(PINS).get(apath).content += " ";
  const inconsistent = await render(c.id);
  assert.deepEqual([inconsistent.status, inconsistent.definite], [503, undefined]);
});

test("MUST-FAIL GAP (C02): a case root whose projection's sha256 is not 64 hex is not a valid case record", async () => {
  const c = await committedCase("RL4 gap schema sha");
  const k = storedCase(c.id);
  const r = C.validateCase({ ...k, commitments: { ...k.commitments, a: { ...k.commitments.a, registration_sha256: "not hex" } } });
  assert.deepEqual([r.ok, r.field], [false, "commitments.a.registration_sha256"]);
});

test("MUST-FAIL GAP (X01, X06, X07; since unit R-L4c, c4, a file at the claim's path that is not the claim): the party-supplied comparison names the field: a file of another case, or another role, under the same key; and a file that is not a registration record at all", async () => {
  const u = await unconfirmedA("RL4 gap tuple fields");
  const other = await openCase("RL4 gap tuple other case");
  const asRecord = (over) => C.registrationRecord({ case_id: u.id, role: "a", commitment_sha256: u.a.commitment_sha256, registered_at: C.utcSeconds(NOW),
    stamp_commit: gh.read(PINS, u.rpath).stamp_commit, stamped_at: "2026-10-10T07:45:00.123Z", ...over,
    ...REG.keyFields({ case_id: over.case_id || u.id, role: over.role || "a", commitment_sha256: u.a.commitment_sha256 }, REG.KEYS.a) });
  for (const [differs, rec] of [["case_id", asRecord({ case_id: other })], ["role", asRecord({ role: "b" })],
    ["record", { ...gh.read(PINS, u.rpath), note: "a field no registration has" }]]) {
    gh.seed(PINS, u.rpath, rec);
    const r = await commit(u.id, u.a, NOW + 1500);
    assert.deepEqual([r.status, r.body.error_code, r.body.differs, r.body.registration_path], [503, "registration_record_unreadable", differs, u.rpath],
      JSON.stringify(r.body).slice(0, 300));
  }
  assert.equal(storedCase(u.id).commitments.a, null);
});

test("MUST-FAIL GAP (X14): in the lost create-only race the winner's file is projected by its own bytes", async () => {
  const id = await openCase("RL4 gap race bytes");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const rpath = REG.claimPath({ case_id: id, ...a }, a.key);
  let winner;
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
    async () => {
      // the same registration, written first by another request, in other bytes
      const rec = C.registrationRecord({ case_id: id, role: "a", commitment_sha256: a.commitment_sha256, registered_at: C.utcSeconds(NOW - 1000),
        stamp_commit: gh.commitsFor(STAMPS, stamp.stampPath(a.commitment_sha256))[0].sha, stamped_at: "2026-10-10T07:45:00.123Z",
        ...REG.keyFields({ case_id: id, role: "a", commitment_sha256: a.commitment_sha256 }) });
      winner = JSON.stringify(rec);
      gh.seedText(PINS, rpath, winner);
    },
    () => commit(id, a),
  );
  assert.deepEqual([r.out.status, r.out.body.existing], [200, true], JSON.stringify(r.out.body).slice(0, 300));
  assert.equal(storedCase(id).commitments.a.registration_sha256, sha(Buffer.from(winner, "utf8")));
});
