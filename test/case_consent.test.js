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

test("FIX C: the race lost after the write (the commit's lock lease ran out and the withdrawal took it over): the registration is removed inside the same critical section; since unit R-N (N4) no case log event is written, and the removal's commit names why", async () => {
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
  assert.match(history[0].message, /commitment b written after the withdrawal, removed/, "the removal's commit says why");
  assert.deepEqual(logFiles(id), [], "no public entry on the withdrawn case (unit R-N, N4)");
  assert.equal(Object.prototype.hasOwnProperty.call(r.out.body, "log_event"), false);
  assert.equal(r.out.body.received_at, C.utcSeconds(NOW + 1000));
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

test("FIX D: every state that is not pinned or anchored is refused with that state: could_not_look, pin_commit_mismatch, conflict; since unit R-N (D1) the check reads the daily anchor records for a conflict", async () => {
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
  // control: pinned again; and the check reads the daily anchor records
  // (unit R-N, D1: the anchor-conflict check)
  gh.seed(PINS, latest, pin);
  gh.seed(PINS, seq, pin);
  const g0 = gh.getLog.length;
  r = await reference(c);
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.ok(gh.getLog.slice(g0).some((p) => p === "anchors"), "the daily anchor records are listed");
  // a listing of them that fails is not a 'no': 503 anchor_unreadable, no row
  const rows = referenceFiles(c.id).length;
  gh.forceGetFailure(PINS, "anchors", 1, 503);
  r = await reference(c, "a", "anchors unread");
  assert.deepEqual([r.status, r.body.error_code], [503, "anchor_unreadable"], JSON.stringify(r.body));
  assert.equal(referenceFiles(c.id).length, rows);
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

test("FIX E: the reveal appends an attempt to reveal_attempts (both commitment ids, the comparison input hash, the time) BEFORE the comparison runs; the root write then completes to VERDICT, which keeps it (unit R-N, E1)", async (t) => {
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
  const attempt = {
    event: "attempt",
    commitments: { a: c.a.commitment_sha256, b: c.b.commitment_sha256 },
    input_sha256: C.revealInputSha256({ case_id: c.id, policy_version: k.policy_version, tape_sha256: { a: c.a.tape_sha256, b: c.b.tape_sha256 } }),
    at: C.utcSeconds(REVEAL_AT),
  };
  assert.deepEqual(seenAtCompare.reveal_attempts, [attempt]);
  assert.equal(k.status, "VERDICT");
  assert.deepEqual(k.reveal_attempts, [attempt], "the sealed record keeps the attempt, inside its signed bytes (unit R-N, E1)");
});

test("FIX E: a root write that fails after the comparison leaves COMMITTED with the attempt and its failure in reveal_attempts; the sealer reports not_sealed: reveal_incomplete, never a clean COMMITTED; the same reveal again seals", async () => {
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
  assert.equal(k.reveal_attempts[0].at, C.utcSeconds(REVEAL_AT));
  assert.deepEqual(k.reveal_attempts[1], { event: "failure", reason: "case_seal_failed", at: C.utcSeconds(REVEAL_AT) });
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
  assert.deepEqual(storedCase(d.id).reveal_attempts.at(-1), { event: "failure", reason: "comparison_failed", at: C.utcSeconds(REVEAL_AT) });
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
  assert.deepEqual(storedCase(e.id).reveal_attempts.at(-1), { event: "failure", reason: "receipt_check_failed", at: C.utcSeconds(REVEAL_AT) });
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
  assert.ok(storedCase(c.id).reveal_attempts.length);
});

test("FIX E: the schema (since unit R-N, E1, the append-only list): an attempt only on a COMMITTED or sealed case, its commitments the case's own, exact fields; a failure only right after an attempt, with a known reason", async () => {
  const c = await committedCase("E schema");
  const k = storedCase(c.id);
  const attempt = { event: "attempt", commitments: { a: c.a.commitment_sha256, b: c.b.commitment_sha256 }, input_sha256: "e".repeat(64), at: "2026-10-10T09:00:00Z" };
  const failure = { event: "failure", reason: "case_seal_failed", at: "2026-10-10T09:00:00Z" };
  assert.deepEqual(C.validateCase({ ...k, reveal_attempts: [attempt] }), { ok: true });
  assert.deepEqual(C.validateCase({ ...k, reveal_attempts: [attempt, failure] }), { ok: true });
  const bad = [
    [[{ ...attempt, commitments: { a: c.b.commitment_sha256, b: c.a.commitment_sha256 } }], "status_inconsistent", "reveal_attempts.0.commitments"],
    [[{ ...attempt, extra: 1 }], "unknown_field", "reveal_attempts.0.extra"],
    [[{ ...attempt, input_sha256: "E".repeat(64) }], "malformed_field", "reveal_attempts.0.input_sha256"],
    [[{ ...attempt, at: "soon" }], "malformed_field", "reveal_attempts.0.at"],
    [[failure], "status_inconsistent", "reveal_attempts.0"],
    [[attempt, { ...failure, reason: "bad luck" }], "malformed_field", "reveal_attempts.1.reason"],
    [[attempt, { event: "failure", reason: "case_seal_failed" }], "missing_field", "reveal_attempts.1.at"],
  ];
  for (const [list, code, field] of bad) {
    const v = C.validateCase({ ...k, reveal_attempts: list });
    assert.deepEqual([v.code, v.field], [code, field], JSON.stringify(v));
  }
  const open = await openCase("E schema open");
  assert.equal(C.validateCase({ ...storedCase(open), reveal_attempts: [attempt] }).code, "status_inconsistent", "an open case has no attempt");
});

// =============================================================================
// DESIGN N: a withdrawal's reason; a joint reveal after it refused before its
// tapes are read; a signed refusal receipt
// =============================================================================

test("DESIGN N (1): a withdrawal records its reason code beside by_role and at: party_choice, deadline or other, from the request, party_choice by default; any other is 400 and nothing is withdrawn", async () => {
  for (const [given, want] of [[undefined, "party_choice"], ["party_choice", "party_choice"], ["deadline", "deadline"], ["other", "other"]]) {
    const c = await committedCase(`N reason ${given}`);
    const w = await withdraw(c.id, c.a, { reason: given });
    assert.equal(w.status, 201, JSON.stringify(w.body));
    const rec = storedCase(c.id);
    assert.deepEqual(Object.keys(rec.withdrawal).sort(), ["at", "by_role", "reason", "salt_sha256"]);
    assert.equal(rec.withdrawal.reason, want);
    assert.equal(rec.withdrawal.by_role, "a");
    assert.deepEqual(C.validateCase(rec), { ok: true });
    assert.equal(S.signatureReason(rec, CASE_KEY.verifier), null, "the reason is inside the signed bytes");
    assert.ok((await casePage(c.id)).html.includes(`<th>reason</th><td><code>${want}</code></td>`), "the withdrawn page shows the code");
    assert.notEqual(S.signatureReason({ ...rec, withdrawal: { ...rec.withdrawal, reason: "other" === want ? "deadline" : "other" } }, CASE_KEY.verifier), null);
  }
  const c = await committedCase("N reason bad");
  for (const bad of ["regret", "", 7, null]) {
    const w = await withdraw(c.id, c.a, { reason: bad });
    assert.equal(w.status, 400, JSON.stringify(w.body));
    assert.equal(w.body.error_code, "malformed_field");
    assert.equal(w.body.field, "reason");
  }
  assert.equal(storedCase(c.id).status, "COMMITTED", "nothing withdrawn");
  // the record's schema: a reason is one of the three
  const w = await withdraw(c.id, c.b, { reason: "other" });
  assert.equal(w.status, 201);
  const rec = storedCase(c.id);
  assert.equal(C.validateCase({ ...rec, withdrawal: { ...rec.withdrawal, reason: "regret" } }).code, "malformed_field");
  assert.equal(C.validateCase({ ...rec, withdrawal: { ...rec.withdrawal, why: "x" } }).code, "unknown_field");
});

test("DESIGN N (2): a joint reveal after a withdrawal is refused 409 case_withdrawn before its tapes are read or hashed: they are never decoded, so even tapes that do not decode are refused so, and nothing about them is stored or logged", async (t) => {
  const c = await committedCase("N refused early");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const decode = t.mock.method(RECONCILE, "tapeFrom");
  const logged = [];
  for (const m of ["log", "error", "warn", "info"]) t.mock.method(console, m, (...args) => logged.push(args.join(" ")));
  const writes = gh.putLog.length;
  // unit R-N (N3): the requester names its role and carries its own opening
  const body = { ...revealBody(c.id, c.a, c.b), role: "a", tape_a_b64: "%%% not base64 %%%", tape_b_b64: c.b.tape.toString("base64") };
  const r = await reveal(c, { body });
  assert.equal(r.status, 409, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.error_code, "case_withdrawn");
  assert.equal(decode.mock.callCount(), 0, "the tapes are never decoded, so never hashed");
  const text = JSON.stringify(r.body) + logged.join("\n");
  for (const secret of [c.a.tape_sha256, c.b.tape_sha256, c.a.salt, c.b.salt, c.b.tape.toString("base64").slice(0, 40)]) {
    assert.ok(!text.includes(secret), "nothing about the tapes in the answer or the logs");
  }
  assert.deepEqual(gh.putLog.slice(writes), [], "nothing stored");
});

test("DESIGN N (3), since unit R-N (N1, N3): the refusal carries a refusal receipt {kind: comparison_refused, case_id, at, reason: consent_not_jointly_held, role, commitment_sha256, signed_under}, signed by the reconcile key under the key document the deployment carries, which anyone can verify; the public case record and page do not change; with no reconcile signer there is no receipt and no 409", async () => {
  const c = await committedCase("N receipt");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const record = storedCase(c.id);
  const before = (await casePage(c.id)).html;
  const writes = gh.putLog.length;
  const r = await reveal(c, { now: REVEAL_AT, body: { ...revealBody(c.id, c.a, c.b), role: "a" } });
  assert.equal(r.status, 409);
  const rr = r.body.refusal_receipt;
  assert.deepEqual([rr.kind, rr.v, rr.case_id, rr.at, rr.reason, rr.role, rr.commitment_sha256],
    ["comparison_refused", 1, c.id, C.utcSeconds(REVEAL_AT), "consent_not_jointly_held", "a", c.a.commitment_sha256]);
  assert.equal(rr.signed_by, KD.keyIdOf(RECEIPT_KEY));
  assert.deepEqual(await S.verifyRefusalReceipt(rr, DOC), { ok: true });
  // what anyone holding it can check: a changed field, another case, a document that does not list the key
  assert.equal((await S.verifyRefusalReceipt({ ...rr, at: C.utcSeconds(REVEAL_AT + 1000) }, DOC)).reason, "bad_signature");
  assert.equal((await S.verifyRefusalReceipt({ ...rr, case_id: "f".repeat(64) }, DOC)).reason, "bad_signature");
  assert.equal((await S.verifyRefusalReceipt(rr, KD.docWith(KD.entry(CASE_KEY)))).reason, "signer_unlisted");
  assert.equal((await S.verifyRefusalReceipt({ ...rr, reason: "other" }, DOC)).reason, "malformed_field");
  assert.equal((await S.verifyRefusalReceipt({ ...rr, extra: 1 }, DOC)).reason, "unknown_field");
  // the public record and page do not change
  assert.deepEqual(gh.putLog.slice(writes), [], "nothing written");
  assert.deepEqual(storedCase(c.id), record);
  assert.equal((await casePage(c.id)).html, before);
  // with no reconcile key that the document lists: no receipt at all (N1)
  const d = await committedCase("N receipt unsigned");
  assert.equal((await withdraw(d.id, d.a)).status, 201);
  const u = await reveal(d, { keyDocument: KD.docWith(KD.entry(CASE_KEY)), body: { ...revealBody(d.id, d.a, d.b), role: "b" } });
  assert.deepEqual([u.status, u.body.error_code], [503, "signer_unavailable"]);
  assert.equal(Object.prototype.hasOwnProperty.call(u.body, "refusal_receipt"), false);
});

test("DESIGN N (3), since unit R-N (N4): a withdrawal that lands while the reveal reads the case, before its attempt, is refused in true words (the tapes were read and the hashes are discarded), with no receipt and no comparison", async (t) => {
  const c = await committedCase("N race");
  const compare = t.mock.method(RECONCILE, "compare");
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(c.id)}`),
    () => withdraw(c.id, c.b, { now: REVEAL_AT - 1000 }),
    () => reveal(c),
  );
  assert.equal(r.fired, true);
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body));
  assert.equal(r.out.status, 409, JSON.stringify(r.out.body).slice(0, 300));
  assert.equal(r.out.body.error_code, "case_withdrawn");
  assert.equal(r.out.body.error, "Refused. A withdrawal landed while this reveal was in progress. Nothing computed from the tapes is kept.");
  assert.equal(Object.prototype.hasOwnProperty.call(r.out.body, "refusal_receipt"), false);
  assert.equal(compare.mock.callCount(), 0, "nothing compared");
  assert.equal(storedCase(c.id).status, "WITHDRAWN");
});

// =============================================================================
// ONE SIGNATURE RULE: verifyCase is gone; an unsigned seal never verifies
// =============================================================================

// A seal built by hand, as a sealer carrying DOC would build it, with the
// receipt the service's own and the case signed by `caseSigner` (a loaded
// signer, or a refused one: unsigned).
async function handSealed(scope, caseSigner) {
  const c = await committedCase(scope);
  const compared = RECONCILE.compare(c.a.tape, c.b.tape, { env: KEYS, now: REVEAL_AT, keyDocument: DOC });
  const st = S.storableReceipt(compared.receipt);
  assert.equal(st.ok, true);
  const sealed = S.sealCase(storedCase(c.id), {
    reveals: { a: { tape_sha256: c.a.tape_sha256, salt: c.a.salt }, b: { tape_sha256: c.b.tape_sha256, salt: c.b.salt } },
    receipt: st.receipt, crossReference: null, revealedAt: C.utcSeconds(REVEAL_AT), signedUnder: KD.signedUnder(gh, DOC, C.utcSeconds(REVEAL_AT)),
  }, caseSigner);
  gh.seed(PINS, C.casePath(c.id), sealed);
  return { ...c, sealed };
}

test("ONE SIGNATURE RULE: verifyCase is deleted (no caller outside the tests); nothing in lib/, api/ or tools/ defines, exports or calls it", () => {
  const fs = require("node:fs");
  const path = require("node:path");
  assert.equal(S.verifyCase, undefined);
  const root = path.join(__dirname, "..");
  const files = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(path.join(root, d), { withFileTypes: true })) {
      if (e.isDirectory()) walk(`${d}/${e.name}`);
      else if (/\.js$/.test(e.name)) files.push(`${d}/${e.name}`);
    }
  };
  for (const d of ["lib", "api", "tools"]) walk(d);
  // a definition, a call or an export entry; the seal module's header names it once, as history
  assert.deepEqual(files.filter((f) => /\bverifyCase\s*[(,]|function\s+verifyCase\b/.test(fs.readFileSync(path.join(root, f), "utf8"))), []);
});

test("ONE SIGNATURE RULE: a seal with sig null reads case_signature_invalid (unsigned_seal), never valid_under_document: the sealer pins nothing, a reference is refused, the page shows no verdict", async () => {
  const signed = await handSealed("sig rule signed", S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  assert.equal((await S.sealedRecordReason(signed.sealed, DOC)).code, "valid_under_document", "control: the same seal, signed");
  const u = await handSealed("sig rule unsigned", S.loadCaseSigner({ [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }, { keyDocument: DOC }));
  assert.equal(u.sealed.sig, null, "fixture: unsigned");
  assert.deepEqual(await S.sealedRecordReason(u.sealed, DOC), { code: "case_signature_invalid", reason: "unsigned_seal" });
  assert.equal(S.sealHolds(await S.sealedRecordReason(u.sealed, DOC)), false);
  // under any document, the current one included
  assert.equal((await S.sealedRecordReason(u.sealed, KD.docWith(KD.reconcileEntry(RECEIPT_KEY)))).reason, "unsigned_seal");
  const one = await S.anchorCase(u.id, { now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.deepEqual([one.ok, one.code, one.reason], [false, "case_signature_invalid", "unsigned_seal"]);
  assert.equal(gh.has(PINS, S.pinPaths(u.id).latest), false, "never pinned");
  const r = await reference(u);
  assert.deepEqual([r.status, r.body.error_code, r.body.reason], [409, "case_signature_invalid", "unsigned_seal"]);
  const page = (await casePage(u.id)).html;
  assert.match(page, /<h1>Case: SEALED RECORD DOES NOT VERIFY<\/h1>/);
  assert.ok(page.includes("<code>unsigned_seal</code>"));
});

test("ONE SIGNATURE RULE: the reveal seals only signed; without a case key the current document lists, it is 503 case_signer_unavailable before anything is written or compared", async (t) => {
  const compare = t.mock.method(RECONCILE, "compare");
  for (const [name, env, keyDocument, code] of [
    ["no case key", { [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer }, DOC, "case_key_unset"],
    ["the case key unlisted", KEYS, KD.docWith(KD.reconcileEntry(RECEIPT_KEY)), "key_unpublished"],
    ["separation not shown", { [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }, DOC, "key_separation_unverifiable"],
  ]) {
    const c = await committedCase(`sig rule ${name}`);
    const before = storedCase(c.id);
    const writes = gh.putLog.filter((w) => w.repo === PINS).length;
    const r = await reveal(c, { env, keyDocument });
    assert.equal(r.status, 503, `${name}: ${JSON.stringify(r.body).slice(0, 200)}`);
    assert.equal(r.body.error_code, "case_signer_unavailable", name);
    assert.equal(r.body.reason, code, name);
    assert.ok(!JSON.stringify(r.body).includes("PRIVATE"), "never a key");
    assert.deepEqual(storedCase(c.id), before, `${name}: no attempt, no seal`);
    assert.equal(gh.putLog.filter((w) => w.repo === PINS).length, writes, `${name}: nothing written`);
  }
  assert.equal(compare.mock.callCount(), 0, "nothing compared");
});

// =============================================================================
// THE MUST-FAIL PASS: tests for the planted defects the tests above let through
// =============================================================================

test("MUST-FAIL GAP (L04, L05, L06): a case lock record that names a held lease but cannot be read as one (an expiry that does not parse, an unknown state, another kind) is 503 case_lock_unreadable, never free, and nothing is written", async () => {
  const id = await openCase("gap lock forms");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const held = { kind: "case-lock", v: 1, case_id: id, holder: "someone-else", op: "commit", acquired_at: C.utcSeconds(NOW),
    expires_at: new Date(NOW + 600000).toISOString(), state: "held" };
  for (const [name, rec] of [["expiry", { ...held, expires_at: "not a time" }], ["state", { ...held, state: "taken" }], ["kind", { ...held, kind: "quota" }]]) {
    gh.seed(USAGE, H._internal.caseLockPath(id), rec);
    const r = await commit(id, a);
    assert.deepEqual([r.status, r.body.error_code], [503, "case_lock_unreadable"], `${name}: ${JSON.stringify(r.body).slice(0, 200)}`);
    assert.equal(gh.has(PINS, C.registrationPath(id, "a")), false, name);
    assert.deepEqual(lockOf(id), rec, `${name}: never written over`);
  }
  // control: the same lease, released, is free
  gh.seed(USAGE, H._internal.caseLockPath(id), { ...held, state: "released" });
  assert.equal((await commit(id, a)).status, 201);
});

test("MUST-FAIL GAP (L32, U04, U05, U08, U09, U10): the race-lost removal is one DELETE of the pins repository's registration file, at the blob sha its write left, on the pin branch, with the pin token", async () => {
  const id = await openCase("gap removal request");
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
  assert.equal(r.out.body.registration_removed, true, JSON.stringify(r.out.body));
  const wrote = gh.putLog.filter((w) => w.repo === PINS && w.path === rpath);
  assert.equal(wrote.length, 1);
  assert.deepEqual(gh.deleteLog, [{ repo: PINS, path: rpath, sha: wrote[0].sha, branch: "main", authorization: "Bearer test-token" }]);
  assert.equal(gh.has(PINS, rpath), false);
});

test("MUST-FAIL GAP (U06, U07, U09): the removal names the store's configured branch and answers the commit that removed the file, and a store that refuses it (another blob sha: 409) is an error, with the file left standing", async () => {
  const U = require("../lib/_case_unregister.js");
  const id = "a".repeat(64);
  const rpath = C.registrationPath(id, "a");
  gh.seed(PINS, rpath, { a: 1 });
  const blob = gh.repos.get(PINS).get(rpath).sha;
  await assert.rejects(U.removeRegistrationAfterWithdrawal(rpath, "0".repeat(40), "m"), /github remove .* -> 409/);
  assert.equal(gh.has(PINS, rpath), true, "a refused removal removes nothing");
  // the request names the store's configured branch, whatever it is (U09)
  const branch = store.BRANCH;
  store.BRANCH = "pins-test-branch";
  let out;
  try {
    out = await U.removeRegistrationAfterWithdrawal(rpath, blob, "m");
  } finally {
    store.BRANCH = branch;
  }
  assert.equal(gh.has(PINS, rpath), false);
  assert.deepEqual(out, { commit: gh.commitsFor(PINS, rpath)[0].sha }, "the removal's own commit");
  assert.equal(gh.deleteLog.at(-1).branch, "pins-test-branch");
});

test("MUST-FAIL GAP (R04): an unsigned seal reads case_signature_invalid (unsigned_seal) even when the document it names cannot be fetched: the rule needs no document, so it never reads could-not-look", async () => {
  const u = await handSealed("gap unsigned unfetchable", S.loadCaseSigner({ [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }, { keyDocument: DOC }));
  const elsewhere = { ...u.sealed, signed_under: { ...u.sealed.signed_under, document_commit: "f".repeat(40) } };
  assert.deepEqual(await S.sealedRecordReason(elsewhere, DOC), { code: "case_signature_invalid", reason: "unsigned_seal" });
  // control: a signed seal naming that commit could not be looked at
  const signed = await handSealed("gap signed unfetchable", S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  const s2 = S.signCase({ ...signed.sealed, signed_under: { ...signed.sealed.signed_under, document_commit: "f".repeat(40) }, sig: null, sig_reason: null, signed_by: null },
    S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  assert.equal((await S.sealedRecordReason(s2, DOC)).code, "document_unavailable");
});

test("MUST-FAIL GAP (L09, L13, L12): a live lock is waited on twice between three attempts before case_busy; a lock write the store refuses (not a conflict) is case_lock_unreachable at once, never retried as if busy", async () => {
  const id = await openCase("gap lock waits");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const lpath = H._internal.caseLockPath(id);
  gh.seed(USAGE, lpath, { kind: "case-lock", v: 1, case_id: id, holder: "someone-else", op: "commit", acquired_at: C.utcSeconds(NOW),
    expires_at: new Date(NOW + 600000).toISOString(), state: "held" });
  const waits = [];
  store._putRetry.sleep = async (ms) => { waits.push(ms); };
  const busy = await commit(id, a);
  assert.equal(busy.body.error_code, "case_busy");
  assert.equal(waits.length, 2, "two waits between three attempts");
  assert.ok(waits.every((ms) => ms > 0));
  // a lock write the store refuses
  gh.seed(USAGE, lpath, { kind: "case-lock", v: 1, case_id: id, holder: "x", op: "commit", acquired_at: C.utcSeconds(NOW),
    expires_at: C.utcSeconds(NOW), state: "released" });
  gh.forceFailure(USAGE, lpath, 3, 502);
  waits.length = 0;
  const r = await commit(id, a);
  assert.deepEqual([r.status, r.body.error_code], [503, "case_lock_unreachable"], JSON.stringify(r.body));
  assert.equal(gh.has(PINS, C.registrationPath(id, "a")), false);
  assert.equal(waits.length, 0, "a refused write is not waited on as a busy lock");
});

test("MUST-FAIL GAP (L16, L17): the lock lives at case_locks/<case_id>.json in the private usage repository, and a holder releases only its own lease: a lease another request took meanwhile is left as it is", async () => {
  const id = await openCase("gap lock holder");
  assert.equal(H._internal.caseLockPath(id), `case_locks/${id}.json`);
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const other = { kind: "case-lock", v: 1, case_id: id, holder: "another-request", op: "withdraw", acquired_at: C.utcSeconds(NOW),
    expires_at: new Date(NOW + 600000).toISOString(), state: "held" };
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.registrationPath(id, "a")}`),
    async () => gh.seed(USAGE, `case_locks/${id}.json`, other),
    () => commit(id, a),
  );
  assert.equal(r.out.status, 201, JSON.stringify(r.out.body));
  assert.deepEqual(gh.read(USAGE, `case_locks/${id}.json`), other, "another holder's lease is not released");
});

test("MUST-FAIL GAP (L23): a case that cannot be read again under the lock, before the registration's write, is 503 store_unreachable and nothing is registered", async () => {
  const id = await openCase("gap reread");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${USAGE}/contents/${H._internal.caseLockPath(id)}`),
    async () => gh.forceGetFailure(PINS, C.casePath(id), 1, 503),
    () => commit(id, a),
  );
  assert.deepEqual([r.out.status, r.out.body.error_code], [503, "store_unreachable"], JSON.stringify(r.out.body));
  assert.equal(gh.has(PINS, C.registrationPath(id, "a")), false);
  assert.equal(lockOf(id).state, "released");
});

// The race lost after the write, with `before` run first (a fault planted).
async function lostRace(scope, before = () => {}) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const rpath = C.registrationPath(id, "b");
  before(rpath);
  const late = NOW + 1000 + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000;
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
    () => withdraw(id, a, { now: late }),
    () => commit(id, b, NOW + 1000),
  );
  assert.equal(r.out.body.error_code, "case_withdrawn", JSON.stringify(r.out.body));
  return { id, rpath, out: r.out.body, wrote: gh.putLog.filter((w) => w.repo === PINS && w.path === rpath) };
}

test("MUST-FAIL GAP (L33): a removal the store refuses is reported as not removed (registration_removed false), and since unit R-N (C1) registration_recorded says the file is still there", async (t) => {
  const viaMock = global.fetch;
  global.fetch = async (url, o) => ((o && o.method) === "DELETE" ? { ok: false, status: 500, json: async () => ({}), text: async () => "" } : viaMock(url, o));
  t.after(() => { global.fetch = viaMock; });
  const x = await lostRace("gap removal refused");
  assert.equal(x.out.registration_removed, false);
  assert.equal(x.out.registration_recorded, true, "the file's real state");
  assert.equal(gh.has(PINS, x.rpath), true);
});

test("MUST-FAIL GAP (D04): anchorState with {anchor: false} answers pinned with anchor {not_looked_up: true}, so no reader takes it for 'not anchored'", async () => {
  const c = await sealedCase("gap not looked up");
  await sealerRun();
  const st = await S.anchorState(c.id, S.caseChain(storedCase(c.id)), { anchor: false });
  assert.equal(st.pin, "pinned");
  assert.deepEqual(st.anchor, { not_looked_up: true });
});

const portRaises = () => {
  const e = new Error("port raised");
  e.portError = true;
  e.causeName = "TypeError";
  throw e;
};

test("MUST-FAIL GAP (E11, E12): a seal the schema refuses is recorded seal_build_failed, and a verdict a JSON record cannot hold is recorded verdict_not_sealable", async (t) => {
  const c = await committedCase("gap seal build");
  const m = t.mock.method(S, "sealCase", () => { throw new C.CaseError("malformed_field", "verdict", "planted"); });
  const r = await reveal(c);
  assert.equal(r.status, 500, JSON.stringify(r.body).slice(0, 200));
  assert.equal(r.body.reveal_failure_recorded, true);
  assert.deepEqual(storedCase(c.id).reveal_attempts.at(-1), { event: "failure", reason: "seal_build_failed", at: C.utcSeconds(REVEAL_AT) });
  m.mock.restore();
  const d = await committedCase("gap not sealable");
  t.mock.method(S, "storableReceipt", () => ({ ok: false, reason: "integer_beyond_json" }));
  const rd = await reveal(d);
  assert.deepEqual([rd.status, rd.body.error_code, rd.body.reveal_failure_recorded], [422, "verdict_not_sealable", true]);
  assert.deepEqual(storedCase(d.id).reveal_attempts.at(-1), { event: "failure", reason: "verdict_not_sealable", at: C.utcSeconds(REVEAL_AT) });
});

test("MUST-FAIL GAP (E08): a failure write the store abandons (the case moved after the attempt) is answered reveal_failure_recorded false, and what moved it stands", async (t) => {
  const c = await committedCase("gap failure abandoned");
  let theirs = null;
  t.mock.method(RECONCILE, "compare", () => {
    const now = storedCase(c.id);
    theirs = { ...now, reveal_attempts: [...now.reveal_attempts, { ...now.reveal_attempts[0], at: "2026-10-10T09:00:30Z" }] };
    gh.seed(PINS, C.casePath(c.id), theirs);
    portRaises();
  });
  const r = await reveal(c);
  assert.equal(r.status, 500);
  assert.equal(r.body.reveal_failure_recorded, false);
  assert.deepEqual(storedCase(c.id), theirs);
});

test("MUST-FAIL GAP (E05): an attempt write whose answer names no blob sha is followed by a read for it, and the seal is written over the attempt", async () => {
  const c = await committedCase("gap attempt sha");
  const viaMock = global.fetch;
  let first = true;
  global.fetch = async (url, o) => {
    const resp = await viaMock(url, o);
    if (first && (o && o.method) === "PUT" && String(url).includes(`/repos/${PINS}/contents/${C.casePath(c.id)}`)) {
      first = false;
      const body = await resp.json();
      return { ok: resp.ok, status: resp.status, json: async () => ({ commit: body.commit }), text: async () => JSON.stringify({ commit: body.commit }) };
    }
    return resp;
  };
  let r;
  try {
    r = await reveal(c);
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(first, false, "the attempt's answer was stripped");
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.equal(storedCase(c.id).status, "VERDICT");
});

test("MUST-FAIL GAP (E19): a withdrawal whose root write meets a case that now records a reveal attempt does not write over it: 409 reveal_attempted, and the attempt stays", async (t) => {
  const c = await committedCase("gap withdraw meets attempt");
  t.mock.method(RECONCILE, "compare", portRaises);
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${USAGE}/contents/${H._internal.caseLockPath(c.id)}`),
    () => reveal(c),
    () => withdraw(c.id, c.a, { now: REVEAL_AT - 1000 }),
  );
  assert.equal(r.inner.status, 500, "the reveal left its attempt and failure");
  assert.deepEqual([r.out.status, r.out.body.error_code], [409, "reveal_attempted"], JSON.stringify(r.out.body));
  assert.equal(storedCase(c.id).status, "COMMITTED");
  assert.equal(storedCase(c.id).reveal_attempts.length, 2);
});

test("MUST-FAIL GAP (N15, N17, N19, N20, N22, N23, N24; since unit R-N): the refusal receipt's checker names each defect, and a withdrawal record built without a reason gets party_choice", async () => {
  const at = C.utcSeconds(REVEAL_AT);
  const signer = S.loadReconcileSigner(KEYS, { keyDocument: DOC });
  const signedUnder = KD.signedUnder(gh, DOC, at);
  const fields = { caseId: "c".repeat(64), at, role: "a", commitmentSha256: "d".repeat(64), signedUnder };
  const rr = S.refusalReceipt(fields, signer);
  assert.deepEqual(await S.verifyRefusalReceipt(rr, DOC), { ok: true });
  const { sig_reason: _gone, ...missing } = rr; // eslint-disable-line no-unused-vars
  const resigned = (over) => S.signRecord({ ...S.refusalReceipt(fields, signer), sig: null, sig_reason: null, signed_by: null, ...over },
    signer, "This refusal receipt is not signed");
  for (const [name, rec, doc, want] of [
    ["a field missing", missing, DOC, "missing_field"],
    ["a case id that is not one", resigned({ case_id: "C".repeat(64) }), DOC, "malformed_field"],
    ["a time that is not one", resigned({ at: "2026-10-10 09:00:00" }), DOC, "malformed_field"],
    ["another version", resigned({ v: 2 }), DOC, "malformed_field"],
    ["a role that is not one", resigned({ role: "c" }), DOC, "malformed_field"],
    ["a commitment that is not one", resigned({ commitment_sha256: "D".repeat(64) }), DOC, "malformed_field"],
    ["signed_under with a field more", resigned({ signed_under: { ...signedUnder, extra: 1 } }), DOC, "malformed_field"],
    ["a current document that does not read", rr, { not: "a key document" }, "current_document_unreadable"],
    ["the reconcile key revoked", rr, KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY, { status: "revoked", revokedSince: "2026-10-11" })), "signer_revoked"],
    ["signed by the case key", S.refusalReceipt(fields, S.loadCaseSigner(KEYS, { keyDocument: DOC })), DOC, "signer_unpublished"],
  ]) {
    assert.deepEqual(await S.verifyRefusalReceipt(rec, doc), { ok: false, reason: want }, name);
  }
  // the record builder's own default
  const c = await committedCase("gap withdrawn default");
  const w = S.withdrawnRecord(storedCase(c.id), { role: "a", at: C.utcSeconds(NOW + 2000), salt: c.a.salt }, S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  assert.equal(w.withdrawal.reason, "party_choice");
});

test("MUST-FAIL GAP (L39): a case that reads under the lock but is not a valid case record (here: WITHDRAWN with no withdrawal) cannot say whether it was withdrawn: 503 case_record_unreadable, nothing registered", async () => {
  const id = await openCase("gap invalid under lock");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const open = storedCase(id);
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${USAGE}/contents/${H._internal.caseLockPath(id)}`),
    async () => gh.seed(PINS, C.casePath(id), { ...open, status: "WITHDRAWN" }),
    () => commit(id, a),
  );
  assert.equal(C.validateCase({ ...open, status: "WITHDRAWN" }).ok, false, "fixture: not a valid record");
  assert.deepEqual([r.out.status, r.out.body.error_code], [503, "case_record_unreadable"], JSON.stringify(r.out.body));
  assert.equal(gh.has(PINS, C.registrationPath(id, "a")), false);
  assert.equal(lockOf(id).state, "released");
});

test("MUST-FAIL GAP (L42): a withdrawal whose root write the store refuses releases the case lock: 503 store_error, and the next request takes the lock at once", async () => {
  const c = await committedCase("gap withdraw store error");
  gh.forceFailure(PINS, C.casePath(c.id), 1, 502);
  const w = await withdraw(c.id, c.a);
  assert.deepEqual([w.status, w.body.error_code], [503, "store_error"], JSON.stringify(w.body));
  assert.equal(lockOf(c.id).state, "released");
  assert.equal((await withdraw(c.id, c.a, { now: NOW + 3000 })).status, 201);
});

test("MUST-FAIL GAP (C04): a reveal attempt with a field missing is missing_field by that field's name", async () => {
  const c = await committedCase("gap attempt missing");
  const k = storedCase(c.id);
  const attempt = { event: "attempt", commitments: { a: c.a.commitment_sha256, b: c.b.commitment_sha256 }, input_sha256: "e".repeat(64), at: "2026-10-10T09:00:00Z" };
  for (const f of ["commitments", "input_sha256", "at"]) {
    const { [f]: _gone, ...rest } = attempt; // eslint-disable-line no-unused-vars
    const v = C.validateCase({ ...k, reveal_attempts: [rest] });
    assert.deepEqual([v.code, v.field], ["missing_field", `reveal_attempts.0.${f}`], f);
  }
});

test("MUST-FAIL GAP (C09, C10, C11, C12, C13, C15, G03, G07, G08): the attempt's input hash is pinned to its formula; each malformed attempt, failure or log event is refused by name; the log lives at cases/<id>/log/<8 digits>.json", async () => {
  const checkRecord = require("../lib/_check_record.js");
  const id = "c".repeat(64);
  const tapes = { a: "a".repeat(64), b: "b".repeat(64) };
  const want = sha(checkRecord.canonicalBytes({ kind: "case-reveal-input", v: 1, case_id: id, policy_version: C.SUPPORTED_POLICY_VERSION,
    tape_a_sha256: tapes.a, tape_b_sha256: tapes.b }));
  assert.equal(C.revealInputSha256({ case_id: id, policy_version: C.SUPPORTED_POLICY_VERSION, tape_sha256: tapes }), want);
  assert.notEqual(C.revealInputSha256({ case_id: id, policy_version: "another-port/9", tape_sha256: tapes }), want, "the policy version is an input");
  // the schema, field by field
  const c = await committedCase("gap attempt forms");
  const k = storedCase(c.id);
  const attempt = { event: "attempt", commitments: { a: c.a.commitment_sha256, b: c.b.commitment_sha256 }, input_sha256: "e".repeat(64), at: "2026-10-10T09:00:00Z" };
  const failure = { event: "failure", reason: "case_seal_failed", at: "2026-10-10T09:00:00Z" };
  for (const [rec, code, field] of [
    [{ ...k, reveal_attempts: [{ ...attempt, commitments: { ...attempt.commitments, c: "f".repeat(64) } }] }, "unknown_field", "reveal_attempts.0.commitments.c"],
    [{ ...k, reveal_attempts: [{ ...attempt, commitments: { ...attempt.commitments, a: "E".repeat(64) } }] }, "malformed_field", "reveal_attempts.0.commitments.a"],
    [{ ...k, reveal_attempts: [attempt, { ...failure, at: "soon" }] }, "malformed_field", "reveal_attempts.1.at"],
    [{ ...k, reveal_attempts: [attempt, { ...failure, note: "x" }] }, "unknown_field", "reveal_attempts.1.note"],
  ]) {
    const v = C.validateCase(rec);
    assert.deepEqual([v.code, v.field], [code, field], JSON.stringify(v));
  }
  // the log event's times, each in its form
  const ev = { kind: "case-event", v: 1, case_id: id, seq: 1, event: "commit_after_withdrawal", at: "2026-10-10T08:00:40Z", role: "b",
    commitment_sha256: "d".repeat(64), registered_at: "2026-10-10T08:00:01Z", registration_commit: null, withdrawal_at: "2026-10-10T08:00:32Z" };
  for (const f of ["registered_at", "withdrawal_at"]) {
    const v = C.validateCaseEvent({ ...ev, [f]: "2026-10-10 08:00:01" });
    assert.deepEqual([v.code, v.field], ["malformed_field", f]);
  }
  // where the log lives
  assert.equal(C.caseLogDir(id), `cases/${id}/log`);
  assert.equal(C.caseLogPath(id, 7), `cases/${id}/log/00000007.json`);
});

test("MUST-FAIL GAP (PG06): a withdrawal record from before the reason existed reads, and its page says none was recorded rather than naming one", async () => {
  const c = await committedCase("gap legacy withdrawal");
  assert.equal((await withdraw(c.id, c.a)).status, 201);
  const rec = storedCase(c.id);
  const { reason: _r, ...legacyWithdrawal } = rec.withdrawal; // eslint-disable-line no-unused-vars
  const legacy = S.signRecord({ ...rec, withdrawal: legacyWithdrawal, sig: null, sig_reason: null, signed_by: null },
    S.loadCaseSigner(KEYS, { keyDocument: DOC }), "This case is withdrawn and not signed");
  assert.deepEqual(C.validateCase(legacy), { ok: true });
  gh.seed(PINS, C.casePath(c.id), legacy);
  const html = (await casePage(c.id)).html;
  assert.ok(html.includes('<th>reason</th><td><span class="muted">none recorded</span></td>'));
  assert.ok(!/<th>reason<\/th><td><code>/.test(html), "no reason is made up");
});
