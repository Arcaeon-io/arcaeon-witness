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

// =============================================================================
// FIX D: a reference only to a case that is pinned or anchored
// =============================================================================

async function committedCase(scope) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
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
async function reveal(c, { now = REVEAL_AT, env = KEYS, keyDocument = DOC, body = revealBody(c.id, c.a, c.b) } = {}) {
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", body), res, { now, env: KD.deployed(gh, env, keyDocument), keyDocument });
  return { status: res._status, body: parsed(res) };
}
async function sealedCase(scope, { pinFails = false } = {}) {
  const c = await committedCase(scope);
  if (pinFails) gh.forceFailure(PINS, S.pinPaths(c.id).seq, 1, 502);
  const r = await reveal(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  return { ...c, r };
}
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0061", url: "https://second-operator.example/cases/0061" });
async function reference(c, role = "a", ref = "row") {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: { ...XREF, reference: ref } }),
    res, { now: REVEAL_AT + 1800000, env: KEYS, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
const referenceFiles = (id) => [...gh.repos.get(PINS).keys()].filter((p) => p.startsWith(`${C.referencesDir(id)}/`)).sort();
const sealerRun = (dt = 60000) => S.anchorPending({ now: REVEAL_AT + 3600000 + dt, keyDocument: DOC });

test("FIX D: a reference to a sealed case not pinned yet is 409 case_not_anchored with its state, writes no row and spends no quota; once the sealer pins it, the same reference is 201", async () => {
  const c = await sealedCase("D not pinned", { pinFails: true });
  const r = await reference(c, "a", "early");
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(r.body.error_code, "case_not_anchored");
  assert.equal(r.body.state, "commit_unrecorded");
  assert.equal(r.body.reason, "not_pinned");
  assert.match(r.body.error, /appended only to a case that is pinned or anchored/);
  assert.deepEqual(referenceFiles(c.id), []);
  assert.equal(gh.has(USAGE, H._internal.referenceQuotaPath(c.id, "a")), false, "no unit of the quota spent");
  await sealerRun();
  const ok = await reference(c, "a", "after the pin");
  assert.equal(ok.status, 201, JSON.stringify(ok.body));
  assert.deepEqual(referenceFiles(c.id), [C.referencePath(c.id, 1)]);
});

test("FIX D: every state that is not pinned or anchored is refused with that state: could_not_look, pin_commit_mismatch, conflict; the check reads no daily anchor record", async () => {
  const c = await sealedCase("D states");
  const { latest, seq } = S.pinPaths(c.id);
  const pin = gh.read(PINS, latest);
  // could_not_look
  gh.forceGetFailure(PINS, latest, 1, 503);
  let r = await reference(c);
  assert.equal(r.status, 409);
  assert.deepEqual([r.body.error_code, r.body.state, r.body.reason], ["case_not_anchored", "could_not_look", "pin_pointer_unreadable"]);
  // pin_commit_mismatch: the pin names the commit that opened the case
  const opened = gh.commitsFor(PINS, C.casePath(c.id)).slice(-1)[0].sha;
  gh.seed(PINS, latest, { ...pin, case_commit: opened });
  r = await reference(c);
  assert.deepEqual([r.body.error_code, r.body.state], ["case_not_anchored", "pin_commit_mismatch"]);
  // conflict: another chain
  gh.seed(PINS, latest, { ...pin, chain: sha("another chain") });
  r = await reference(c);
  assert.deepEqual([r.body.error_code, r.body.state], ["case_not_anchored", "conflict"]);
  assert.deepEqual(referenceFiles(c.id), []);
  // control: pinned again; and the check never reads a daily anchor record
  gh.seed(PINS, latest, pin);
  gh.seed(PINS, seq, pin);
  const g0 = gh.getLog.length;
  r = await reference(c);
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.ok(!gh.getLog.slice(g0).some((p) => p === "anchors" || p.startsWith("anchors/")), "no daily anchor record is read");
});

// =============================================================================
// FIX E: the two-phase reveal
// =============================================================================

const RECONCILE = require("../lib/_reconcile_http.js");
const CP = require("../lib/_case_page.js");
async function casePage(id, now = REVEAL_AT + 3600000) {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": `10.98.9.${(ipSeq += 1) & 255}` } }), res,
    { now, keyDocument: DOC, env: {} });
  return { status: res._status, html: String(res._body) };
}

test("FIX E: the reveal writes reveal_attempt (both commitment ids, the comparison input hash, the time) into the case record BEFORE the comparison runs; the root write then completes to VERDICT", async (t) => {
  const c = await committedCase("E attempt");
  const real = RECONCILE.compare;
  let seenAtCompare = null;
  t.mock.method(RECONCILE, "compare", (...args) => {
    seenAtCompare = storedCase(c.id);
    return real(...args);
  });
  const r = await reveal(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.ok(seenAtCompare, "the comparison ran");
  assert.equal(seenAtCompare.status, "COMMITTED");
  const k = storedCase(c.id);
  assert.deepEqual(seenAtCompare.reveal_attempt, {
    commitments: { a: c.a.commitment_sha256, b: c.b.commitment_sha256 },
    input_sha256: C.revealInputSha256({ case_id: c.id, policy_version: k.policy_version, tape_sha256: { a: c.a.tape_sha256, b: c.b.tape_sha256 } }),
    at: C.utcSeconds(REVEAL_AT),
  });
  assert.equal(Object.prototype.hasOwnProperty.call(seenAtCompare, "reveal_failure"), false);
  assert.equal(k.status, "VERDICT");
  assert.equal(Object.prototype.hasOwnProperty.call(k, "reveal_attempt"), false, "the sealed record is the seal: the attempt is not kept in it");
});

test("FIX E: a root write that fails after the comparison leaves COMMITTED with reveal_attempt and reveal_failure; the sealer reports not_sealed: reveal_incomplete, never a clean COMMITTED; the same reveal again seals", async () => {
  const c = await committedCase("E root fails");
  // the second PUT of the case file fails: the attempt's write, then the seal's
  let puts = 0;
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    if ((o && o.method) === "PUT" && String(url).includes(`/repos/${PINS}/contents/${C.casePath(c.id)}`) && ++puts === 2) gh.forceFailure(PINS, C.casePath(c.id), 1, 502);
    return viaMock(url, o);
  };
  let r;
  try {
    r = await reveal(c);
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(r.status, 503, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.error_code, "case_seal_failed");
  assert.equal(r.body.reveal_failure_recorded, true);
  const k = storedCase(c.id);
  assert.equal(k.status, "COMMITTED");
  assert.equal(k.reveal_attempt.at, C.utcSeconds(REVEAL_AT));
  assert.deepEqual(k.reveal_failure, { reason: "case_seal_failed", at: C.utcSeconds(REVEAL_AT) });
  assert.deepEqual(C.validateCase(k), { ok: true });
  const run = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.equal(run.not_sealed, 1);
  assert.deepEqual(run.reveal_incomplete, [c.id]);
  assert.deepEqual(await S.anchorCase(c.id, { now: REVEAL_AT + 60000, keyDocument: DOC }), { ok: false, code: "not_sealed", status: "COMMITTED", reason: "reveal_incomplete" });
  const page = (await casePage(c.id)).html;
  assert.match(page, /A joint reveal was attempted at 2026-10-10T09:00:00Z and did not complete \(case_seal_failed, at 2026-10-10T09:00:00Z\)/);
  // the same reveal again seals
  const again = await reveal(c, { now: REVEAL_AT + 120000 });
  assert.equal(again.status, 201, JSON.stringify(again.body).slice(0, 300));
  assert.equal(storedCase(c.id).status, "VERDICT");
});

test("FIX E: an attempt that cannot be written compares nothing; a failure after the attempt is recorded by its reason (the comparison raised, the receipt failed its check)", async (t) => {
  // the attempt's own write fails: nothing compared, the record as it was
  const c = await committedCase("E attempt fails");
  const before = storedCase(c.id);
  const compare = t.mock.method(RECONCILE, "compare");
  gh.forceFailure(PINS, C.casePath(c.id), 1, 502);
  const r = await reveal(c);
  assert.equal(r.status, 503);
  assert.equal(r.body.error_code, "reveal_attempt_unwritten");
  assert.equal(compare.mock.callCount(), 0, "nothing compared");
  assert.deepEqual(storedCase(c.id), before);
  compare.mock.restore();
  // the comparison raised
  const d = await committedCase("E port raised");
  t.mock.method(RECONCILE, "compare", () => {
    const e = new Error("port raised");
    e.portError = true;
    e.causeName = "TypeError";
    throw e;
  });
  const rd = await reveal(d);
  assert.equal(rd.status, 500);
  assert.deepEqual(storedCase(d.id).reveal_failure, { reason: "comparison_failed", at: C.utcSeconds(REVEAL_AT) });
  RECONCILE.compare.mock.restore();
  // the receipt failed its own check
  const e = await committedCase("E receipt check");
  const realCompare = RECONCILE.compare;
  t.mock.method(RECONCILE, "compare", (...args) => {
    const out = realCompare(...args);
    return { ...out, receipt: { ...out.receipt, compared_at: "2026-10-10T08:59:59Z" } };
  });
  const re = await reveal(e);
  assert.equal(re.status, 500);
  assert.deepEqual(storedCase(e.id).reveal_failure, { reason: "receipt_check_failed", at: C.utcSeconds(REVEAL_AT) });
});

test("FIX E: a case with a reveal attempt is not withdrawn by one role: 409 reveal_attempted, and the attempt stays", async (t) => {
  const c = await committedCase("E no withdrawal");
  t.mock.method(RECONCILE, "compare", () => {
    const e = new Error("port raised");
    e.portError = true;
    e.causeName = "TypeError";
    throw e;
  });
  assert.equal((await reveal(c)).status, 500);
  const w = await withdraw(c.id, c.a, { now: REVEAL_AT + 60000 });
  assert.equal(w.status, 409, JSON.stringify(w.body));
  assert.equal(w.body.error_code, "reveal_attempted");
  assert.equal(storedCase(c.id).status, "COMMITTED");
  assert.ok(storedCase(c.id).reveal_attempt);
});

test("FIX E: the schema: reveal_attempt only on a COMMITTED case, its commitments the case's own, exact fields; reveal_failure only beside an attempt, with a known reason", async () => {
  const c = await committedCase("E schema");
  const k = storedCase(c.id);
  const attempt = { commitments: { a: c.a.commitment_sha256, b: c.b.commitment_sha256 }, input_sha256: "e".repeat(64), at: "2026-10-10T09:00:00Z" };
  assert.deepEqual(C.validateCase({ ...k, reveal_attempt: attempt }), { ok: true });
  assert.deepEqual(C.validateCase({ ...k, reveal_attempt: attempt, reveal_failure: { reason: "case_seal_failed", at: "2026-10-10T09:00:00Z" } }), { ok: true });
  const bad = [
    [{ ...k, reveal_attempt: { ...attempt, commitments: { a: c.b.commitment_sha256, b: c.a.commitment_sha256 } } }, "status_inconsistent", "reveal_attempt.commitments"],
    [{ ...k, reveal_attempt: { ...attempt, extra: 1 } }, "unknown_field", "reveal_attempt.extra"],
    [{ ...k, reveal_attempt: { ...attempt, input_sha256: "E".repeat(64) } }, "malformed_field", "reveal_attempt.input_sha256"],
    [{ ...k, reveal_attempt: { ...attempt, at: "soon" } }, "malformed_field", "reveal_attempt.at"],
    [{ ...k, reveal_failure: { reason: "case_seal_failed", at: "2026-10-10T09:00:00Z" } }, "status_inconsistent", "reveal_failure"],
    [{ ...k, reveal_attempt: attempt, reveal_failure: { reason: "bad luck", at: "2026-10-10T09:00:00Z" } }, "malformed_field", "reveal_failure.reason"],
    [{ ...k, reveal_attempt: attempt, reveal_failure: { reason: "case_seal_failed" } }, "missing_field", "reveal_failure.at"],
  ];
  for (const [rec, code, field] of bad) {
    const v = C.validateCase(rec);
    assert.deepEqual([v.code, v.field], [code, field], JSON.stringify(v));
  }
  const open = await openCase("E schema open");
  assert.equal(C.validateCase({ ...storedCase(open), reveal_attempt: attempt }).code, "status_inconsistent", "an open case has no attempt");
});
