// test/case_rl4b.test.js — unit R-L4b (2026-10-13): the architect CUT the
// DAMAGED state that unit R-L4's rule 4 introduced. Its substance stands (a
// mismatch is never silently resolved, never sealed, never pinned); only the
// named state goes, because case_record_inconsistent already names that
// condition:
//   "A projected entry whose file is missing or does not hash to the
//   projected sha256 is answered 503 case_record_inconsistent by every
//   handler, and the page shows the could-not-look page with that reason and
//   the sentence: 'A registration file does not match the hash this case
//   records for it; this page shows nothing from this case until it does.'
//   The case cannot seal and is never pinned; nothing is written, nothing is
//   deleted."
// The setup below is test/case_rl4.test.js's.
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rl4b");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rl4b");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rl4b");
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
const INCONSISTENT = "A registration file does not match the hash this case records for it; this page shows nothing from this case until it does.";
const pinsWrites = () => gh.putLog.filter((w) => w.repo === PINS).length;
const deletes = () => gh.deleteLog.length;
// Role `role`'s projected file of case `id` given other bytes (the same
// JSON), or taken away.
function tamper(id, role, how = "bytes") {
  const p = REG.pathOf(gh, id, role);
  if (how === "missing") gh._repoMap(PINS).delete(p);
  else gh._repoMap(PINS).get(p).content += " ";
  return p;
}
async function referenceAs(c, role = "a") {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: XREF }),
    res, { now: REVEAL_AT + 1800000, env: KEYS, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}

test("R-L4b: a projected file that does not hash to the projected sha256, or is missing, is 503 case_record_inconsistent at every handler, and nothing is written or deleted", async () => {
  for (const how of ["bytes", "missing"]) {
    const reason = how === "missing" ? "registration_file_missing" : "registration_file_differs";
    const c = await committedCase(`RL4b handlers ${how}`);
    tamper(c.id, "a", how);
    const before = pinsWrites();
    const answers = {
      commit: await commit(c.id, c.b, NOW + 1500),
      reveal: await reveal(c),
      withdraw: await withdraw(c.id, c.b),
    };
    for (const [op, r] of Object.entries(answers)) {
      assert.deepEqual([r.status, r.body.error_code, r.body.role, r.body.reason], [503, "case_record_inconsistent", "a", reason],
        `${how} ${op}: ${JSON.stringify(r.body).slice(0, 300)}`);
      assert.equal(JSON.stringify(r.body).includes("DAMAGED"), false, `${op}: no DAMAGED`);
    }
    assert.equal(pinsWrites(), before, "nothing written");
    assert.equal(storedCase(c.id).status, "COMMITTED", "never sealed");
  }
  const s = await sealedCase("RL4b reference");
  tamper(s.id, "b");
  const before = pinsWrites();
  const ref = await referenceAs(s);
  assert.deepEqual([ref.status, ref.body.error_code, ref.body.role], [503, "case_record_inconsistent", "b"], JSON.stringify(ref.body).slice(0, 300));
  assert.equal(pinsWrites(), before);
  assert.equal(deletes(), 0, "nothing deleted");
});

test("R-L4b: the page is the could-not-look page with case_record_inconsistent and the sentence, and shows nothing from the case", async () => {
  const c = await sealedCase("RL4b page");
  tamper(c.id, "a");
  const page = await casePage(c.id);
  assert.equal(page.status, 503);
  assert.match(page.html, /<h1>Case: COULD NOT LOOK<\/h1>/);
  assert.ok(page.html.includes("<code>case_record_inconsistent</code>"), page.html.slice(0, 1500));
  assert.ok(page.html.includes(esc(INCONSISTENT)));
  for (const absent of ["DAMAGED", "registered at", "MATCHED", "agent-operator@example.com", "Registrations", "anchored"]) {
    assert.equal(page.html.includes(absent), false, `the page shows nothing from the case: ${absent}`);
  }
});

test("R-L4b: the sealer never seals or pins such a case, writes nothing, and says why", async () => {
  // sealed, and the reveal's own pin write failed: the sealer is the one to pin it
  const c = await committedCase("RL4b sealer");
  gh.forceFailure(PINS, `pins/case/${c.id}/00000001.json`, 1, 500);
  assert.equal((await reveal(c)).status, 201);
  assert.equal(pinsPaths().some((p) => p.startsWith(`pins/case/${c.id}/`)), false, "fixture: not pinned at the reveal");
  tamper(c.id, "a");
  const before = pinsWrites();
  const run = await sealerRun();
  assert.equal(pinsPaths().some((p) => p.startsWith(`pins/case/${c.id}/`)), false, "never pinned");
  assert.equal(pinsWrites(), before, "nothing written");
  assert.deepEqual(run.refused, [{ case_id: c.id, code: "case_record_inconsistent", role: "a", reason: "registration_file_differs" }]);
  assert.equal("damaged" in run, false);
  const d = await committedCase("RL4b sealer committed");
  tamper(d.id, "b", "missing");
  assert.equal((await reveal(d)).body.error_code, "case_record_inconsistent", "never sealed");
});

test("R-L4b: the DAMAGED name, its code and its words are gone", () => {
  for (const f of jsFiles("lib")) {
    assert.doesNotMatch(read(f), /DAMAGED|case_damaged|damagedWords|damagedPage/, f);
  }
  assert.doesNotMatch(read("README.md"), /DAMAGED/);
});
