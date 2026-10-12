// test/case_consent.test.js — the unit after Design J (2026-10-12): three
// confirmed red-team claims closed (GPT-5.6 §1.1 / §6.2, §1.2, §1.3), Design
// N (a withdrawal's reason, a reveal after it refused before its tapes are
// read, and a signed refusal receipt), and one signature rule everywhere.
//
// FIX C, here first: a registration file never stands after a withdrawal.
// The registration write and the withdrawal's root write take one per-case
// lock; under it the commit reads the case again and writes nothing once it
// sees WITHDRAWN. A race lost after the write (a lock whose lease ran out)
// removes the registration inside the same critical section and appends a
// case log event commit_after_withdrawal, so the attempt is not invisible.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0061:case-test-";
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
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const stamp = require("../lib/_stamp.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const PINS = process.env.GITHUB_PIN_REPO;
const USAGE = process.env.GITHUB_USAGE_REPO;
const STAMPS = process.env.STAMP_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z");
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-12n");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-12n");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-12n");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0061" });

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
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": `10.99.${(ipSeq >> 8) & 255}.${ipSeq & 255}`, ...headers }, body });
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
async function openCase(scope) {
  const o = makeRes();
  await H.handleCaseOpen(req("case-open", opening(scope), OPEN_AUTH), o, { now: NOW });
  assert.equal(o._status, 201, JSON.stringify(o._body));
  return o._body.case_id;
}
function plantStamp(hash) {
  gh.seed(STAMPS, stamp.stampPath(hash), { kind: "file-stamp", v: 1, sha256: hash, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: "2026-10-10T07:45:00.123Z" });
}
async function commit(id, p, now = NOW) {
  const res = makeRes();
  await H.handleCaseCommit(req("case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 })), res, { now });
  return { status: res._status, body: parsed(res) };
}
async function register(id, p) {
  plantStamp(p.commitment_sha256);
  const r = await commit(id, p);
  assert.equal(r.status, 201, JSON.stringify(r.body));
}
async function withdraw(id, p, { now = NOW + 2000, reason } = {}) {
  const res = makeRes();
  const body = { case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt: p.salt, ...(reason === undefined ? {} : { reason }) };
  await H.handleCaseWithdraw(req("case-withdraw", body), res, { now, env: KEYS, keyDocument: DOC });
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
const logFiles = (id) => [...gh.repos.get(PINS).keys()].filter((p) => p.startsWith(`${C.caseLogDir(id)}/`)).sort();

// =============================================================================
// FIX C: a registration file never stands after a withdrawal
// =============================================================================

test("FIX C: a withdrawal the commit sees under the case lock writes nothing: 409 case_withdrawn, nothing registered, no registration file, and the lock is released", async () => {
  const id = await openCase("C seen");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  // the withdrawal lands while the commit reads b's stamp, before it takes the lock
  const r = await during(
    (url, method) => method === "GET" && url.includes(`/repos/${STAMPS}/contents/${stamp.stampPath(b.commitment_sha256)}`),
    () => withdraw(id, a),
    () => commit(id, b, NOW + 1000),
  );
  assert.equal(r.fired, true);
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body));
  assert.equal(r.out.status, 409, JSON.stringify(r.out.body));
  assert.equal(r.out.body.error_code, "case_withdrawn");
  assert.equal(r.out.body.registration_recorded, false);
  assert.equal(r.out.body.received_at, C.utcSeconds(NOW + 1000), "the commit's arrival, before the withdrawal");
  assert.equal(gh.has(PINS, C.registrationPath(id, "b")), false, "no registration file");
  assert.ok(!gh.putLog.some((x) => x.path === C.registrationPath(id, "b")), "never written");
  assert.deepEqual(logFiles(id), [], "nothing was written, so nothing to log");
  assert.equal(lockOf(id).state, "released");
});

test("FIX C: the race lost after the write (the commit's lock lease ran out and the withdrawal took it over): the registration is removed inside the same critical section and a case log event commit_after_withdrawal records the attempt", async () => {
  const id = await openCase("C lost");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const rpath = C.registrationPath(id, "b");
  const late = NOW + 1000 + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000; // past the commit's lease, by the withdrawal's clock
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
    () => withdraw(id, a, { now: late }),
    () => commit(id, b, NOW + 1000),
  );
  assert.equal(r.fired, true);
  assert.equal(r.inner.status, 201, `the withdrawal took over the expired lock: ${JSON.stringify(r.inner.body)}`);
  assert.equal(r.out.status, 409, JSON.stringify(r.out.body));
  assert.equal(r.out.body.error_code, "case_withdrawn");
  assert.equal(r.out.body.registration_recorded, false);
  assert.equal(r.out.body.registration_removed, true);
  assert.equal(gh.has(PINS, rpath), false, "the registration does not stand");
  const history = gh.commitsFor(PINS, rpath);
  assert.equal(history.length, 2, "written, then removed: both are commits of the public history");
  const logs = logFiles(id);
  assert.deepEqual(logs, [C.caseLogPath(id, 1)]);
  assert.equal(r.out.body.log_event, logs[0]);
  const ev = gh.read(PINS, logs[0]);
  assert.deepEqual(C.validateCaseEvent(ev), { ok: true });
  assert.equal(ev.event, "commit_after_withdrawal");
  assert.equal(ev.case_id, id);
  assert.equal(ev.role, "b");
  assert.equal(ev.commitment_sha256, b.commitment_sha256);
  assert.equal(ev.registered_at, C.utcSeconds(NOW + 1000));
  assert.equal(ev.withdrawal_at, storedCase(id).withdrawal.at);
  assert.equal(ev.registration_commit, history[1].sha, "the commit that wrote the removed file");
  assert.equal(storedCase(id).status, "WITHDRAWN");
});

test("FIX C: a live case lock held by another request: the commit and the withdrawal each wait, then answer 503 case_busy and write nothing; an expired lock is taken over", async () => {
  const id = await openCase("C busy");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const held = { kind: "case-lock", v: 1, case_id: id, holder: "someone-else", op: "commit", acquired_at: C.utcSeconds(NOW),
    expires_at: new Date(NOW + 600000).toISOString(), state: "held" };
  gh.seed(USAGE, H._internal.caseLockPath(id), held);
  const c = await commit(id, b, NOW + 1000);
  assert.equal(c.status, 503, JSON.stringify(c.body));
  assert.equal(c.body.error_code, "case_busy");
  assert.equal(gh.has(PINS, C.registrationPath(id, "b")), false);
  const w = await withdraw(id, a, { now: NOW + 2000 });
  assert.equal(w.status, 503);
  assert.equal(w.body.error_code, "case_busy");
  assert.equal(storedCase(id).status, "OPEN");
  assert.deepEqual(lockOf(id), held, "another's lock is never written over while it is live");
  // past its expiry it is taken over
  const ok = await commit(id, b, NOW + 700000);
  assert.equal(ok.status, 201, JSON.stringify(ok.body));
  assert.equal(lockOf(id).state, "released");
});

test("FIX C: a case lock that cannot be read, or is unreadable, is 503 and nothing is written", async () => {
  const id = await openCase("C lock unreadable");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  gh.forceGetFailure(USAGE, H._internal.caseLockPath(id), 1, 503);
  const r = await commit(id, a);
  assert.equal(r.status, 503);
  assert.equal(r.body.error_code, "case_lock_unreachable");
  assert.equal(gh.has(PINS, C.registrationPath(id, "a")), false);
  gh.seed(USAGE, H._internal.caseLockPath(id), { not: "a lock" });
  const r2 = await commit(id, a);
  assert.equal(r2.status, 503);
  assert.equal(r2.body.error_code, "case_lock_unreadable");
  assert.equal(gh.has(PINS, C.registrationPath(id, "a")), false);
});

test("FIX C: the case log event's schema: exactly its fields, a known event, the times and hashes in their forms; anything else refused by name", () => {
  const id = "c".repeat(64);
  const good = { kind: "case-event", v: 1, case_id: id, seq: 1, event: "commit_after_withdrawal", at: "2026-10-10T08:00:40Z", role: "b",
    commitment_sha256: "d".repeat(64), registered_at: "2026-10-10T08:00:01Z", registration_commit: "e".repeat(40), withdrawal_at: "2026-10-10T08:00:32Z" };
  assert.deepEqual(C.validateCaseEvent(good), { ok: true });
  const bad = {
    unknown_field: [{ ...good, note: "x" }],
    missing_field: [(() => { const o = { ...good }; delete o.role; return o; })()],
    malformed_field: [{ ...good, event: "something_else" }, { ...good, seq: 0 }, { ...good, registration_commit: "E".repeat(40) },
      { ...good, at: "2026-10-10 08:00:40" }, { ...good, kind: "case-log" }],
    unknown_version: [{ ...good, v: 2 }],
    bad_role: [{ ...good, role: "c" }],
  };
  for (const [code, recs] of Object.entries(bad)) {
    for (const rec of recs) assert.equal(C.validateCaseEvent(rec).code, code, JSON.stringify(rec).slice(0, 80));
  }
});
