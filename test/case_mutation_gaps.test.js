// test/case_mutation_gaps.test.js — the gaps a must-fail (mutation) pass
// over the case protocol code found: one planted defect at a time in a
// scratch copy, the suite run each time, and for every defect the suite let
// through and that changes behaviour, the smallest test here that fails with
// that defect and passes on the real code. The code under test is not
// changed. Each test names the mutant it kills (the id in the report) and the
// line it guards.
//
// The pass (harness not committed): 137 defects planted, one at a time,
// across lib/_case.js (33), lib/_case_http.js (46), lib/_case_seal.js (33),
// lib/_case_page.js (12), the case pass in lib/_sealer.js (3), judgeCaseSeal
// in lib/_verdict.js (4), the case rows in lib/_status_data.js (3) and the
// case ops dispatch in api/verify.js (3). 107 were caught by the suite as it
// stood. Of the 30 that survived, 27 are closed here, each test failing with
// its own mutant and passing on the real code. Three are equivalent, so no
// test can tell them apart:
//   - lib/_case_seal.js rotatingWindow `<=` to `<`: with exactly `max`
//     candidates the window starts at (k * max) % max = 0, the list in order;
//   - lib/_case_page.js sealedPanels' fallback word: a VERDICT reaches it
//     only after sealedRecordReason, whose receipt check admits only the four
//     words, each a key of the page's map;
//   - lib/_case_page.js recordsWords answering "one record" for anything but
//     2: its every call site passes 1 or 2 (the schema's records; a live
//     count that is not established returns before the call).
//
// The schema invariants below (lib/_case.js checkFull and checkWithdrawn) are
// enforced upstream by the handlers before any write, so no request can
// produce the records planted here; validateCase is what every reader of a
// STORED record runs (the handlers' judgeCase, the page, anchorCase), so a
// damaged or hand-written record is the only way to reach them, and that is
// what these tests plant.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0011:case-test-";
delete process.env.WITNESS_BATCH_SHADOW;
delete process.env.WITNESS_ADMIN_KEY;
delete process.env.WITNESS_CASE_OPERATOR_KEY;

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

const PINS = process.env.GITHUB_PIN_REPO;
const USAGE = process.env.GITHUB_USAGE_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z");
const DEADLINE = "2026-10-10T20:00:00Z";
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

let gh;
let restore;
let realSleep;
beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
  realSleep = store._putRetry.sleep;
  store._putRetry.sleep = async () => {};
});
afterEach(() => {
  store._putRetry.sleep = realSleep;
  restore();
});

// ---- pure fixtures: an opening, its OPEN, COMMITTED and VERDICT records ----

function opening(over = {}) {
  return {
    protocol_version: "case/1",
    policy_version: C.SUPPORTED_POLICY_VERSION,
    scope_digest: sha("the scope manifest both parties agreed"),
    party_a: { side: "agent", label: "agent-operator@example.com" },
    party_b: { side: "tool", label: "tool-operator@example.com" },
    opened_at: "2026-10-10T07:30:00Z",
    deadline: DEADLINE,
    ...over,
  };
}
const OPENING = C.validateOpening(opening()).opening;
const ID = C.deriveCaseId(OPENING);
function reg(role, commitment, registeredAt = "2026-10-10T08:00:00Z") {
  return C.registrationRecord({
    case_id: ID, role, commitment_sha256: commitment, registered_at: registeredAt,
    stamp_commit: "1".repeat(40), stamped_at: "2026-10-10T07:45:00.123Z",
    ...REG.keyFields({ case_id: ID, role, commitment_sha256: commitment }),
  });
}
const OPEN_CASE = C.newCase(OPENING, ID);
const WITH_A = C.applyRegistration(OPEN_CASE, reg("a", sha("commitment a")));
const COMMITTED = C.applyRegistration(WITH_A, reg("b", sha("commitment b")));
const REVEALED_AT = "2026-10-10T09:00:00Z";
const VERDICT = Object.freeze({
  ...COMMITTED,
  status: "VERDICT",
  reveals: {
    a: { tape_sha256: sha("tape a"), salt_sha256: sha("salt a"), revealed_at: REVEALED_AT },
    b: { tape_sha256: sha("tape b"), salt_sha256: sha("salt b"), revealed_at: REVEALED_AT },
  },
  verdict: { planted: "the schema asks only for an object here; the receipt has its own check" },
});
const WITHDRAWN = Object.freeze({
  v: 1, case_id: ID, protocol_version: "case/1", status: "WITHDRAWN", opened_at: OPENING.opened_at,
  withdrawal: { by_role: "a", at: "2026-10-10T08:30:00Z", salt_sha256: sha("salt a") },
  limits: C.LIMITS.slice(), signed_by: null, sig: null, sig_reason: "withdrawn in this test",
});

function refusedWith(rec, code, field) {
  const v = C.validateCase(rec);
  assert.equal(v.ok, false, `accepted: ${JSON.stringify(rec).slice(0, 160)}`);
  assert.equal(v.code, code, JSON.stringify(v));
  if (field !== undefined) assert.equal(v.field, field, JSON.stringify(v));
}

test("fixtures: the planted OPEN, COMMITTED, VERDICT and WITHDRAWN records are valid as built", () => {
  for (const r of [OPEN_CASE, WITH_A, COMMITTED, VERDICT, WITHDRAWN]) assert.deepEqual(C.validateCase(r), { ok: true }, r.status);
  assert.equal(COMMITTED.status, "COMMITTED");
});

// =============================================================================
// lib/_case.js
// =============================================================================

test("C05 (compareCodePoints, the length tie-break): a label that is a prefix of the other sorts first, as Python's str ordering does", () => {
  assert.ok(C.compareCodePoints("op", "op-2") < 0);
  assert.ok(C.compareCodePoints("op-2", "op") > 0);
  // through the rule: whichever order the opening lists them, party_a is the shorter label
  const short = { side: "tool", label: "op" };
  const long = { side: "agent", label: "op-2" };
  for (const [p, q] of [[short, long], [long, short]]) {
    const r = C.canonicalParties(p, q);
    assert.equal(r.party_a.label, "op");
    assert.equal(r.party_b.label, "op-2");
  }
  // ["op-2", "op"] sorted by Python is ["op", "op-2"]: the id's preimage lists op first
  const bytes = C.caseIdBytes(opening({ party_a: long, party_b: short })).toString("utf-8");
  assert.ok(bytes.indexOf('"label":"op"') < bytes.indexOf('"label":"op-2"'), bytes);
});

test("C21 (validateRevealBody, onlyFields on reveals): a reveal carrying a third role key is refused unknown_field, never silently dropped", () => {
  const e = { tape_sha256: sha("t"), salt: sha("s") };
  const body = { case_id: ID, reveals: { a: e, b: e, c: e } };
  assert.throws(() => C.validateRevealBody(body), (err) => err instanceof C.CaseError && err.code === "unknown_field" && err.field === "reveals.c");
  // control: the same body without the extra key reads
  assert.deepEqual(Object.keys(C.validateRevealBody({ case_id: ID, reveals: { a: e, b: e } }).reveals), ["a", "b"]);
});

test("C25 (applyRegistration, role_already_committed): a role that already holds an entry is refused, never overwritten", () => {
  assert.throws(() => C.applyRegistration(WITH_A, reg("a", sha("another commitment for a"))),
    (err) => err instanceof C.CaseError && err.code === "role_already_committed" && err.field === "role");
  assert.throws(() => C.applyRegistration({ ...COMMITTED }, reg("b", sha("another commitment for b"))), (err) => err.code === "role_already_committed");
});

test("C28 (checkSig): a signed record that also carries a sig_reason is refused", () => {
  const signed = { ...VERDICT, signed_by: "case-test+0123abcd", sig: "c2lnbmF0dXJl", sig_reason: null };
  assert.deepEqual(C.validateCase(signed), { ok: true }, "control: signed, no reason, reads (the schema does not check the signature)");
  refusedWith({ ...signed, sig_reason: "it is signed and says why not" }, "malformed_field", "sig_reason");
});

test("C30 (checkLimits): four limits with one sentence altered are refused limits_altered, not only a wrong count", () => {
  const altered = C.LIMITS.slice();
  altered[3] = "This service establishes fault.";
  refusedWith({ ...COMMITTED, limits: altered }, "limits_altered", "limits");
  refusedWith({ ...WITHDRAWN, limits: altered }, "limits_altered", "limits");
  refusedWith({ ...COMMITTED, limits: [...C.LIMITS.slice(1), C.LIMITS[0]] }, "limits_altered", "limits");
});

test("C31 (checkWithdrawn): a withdrawal dated before the case was opened is refused status_inconsistent", () => {
  refusedWith({ ...WITHDRAWN, withdrawal: { ...WITHDRAWN.withdrawal, at: "2026-10-10T07:29:59Z" } }, "status_inconsistent", "withdrawal.at");
  assert.deepEqual(C.validateCase({ ...WITHDRAWN, withdrawal: { ...WITHDRAWN.withdrawal, at: OPENING.opened_at } }), { ok: true }, "control: at the opening second");
});

test("C32 (checkFull, registered_at): a registration received exactly at the deadline is refused; one second before reads", () => {
  const at = C.applyRegistration(WITH_A, reg("b", sha("commitment b"), DEADLINE));
  refusedWith(at, "status_inconsistent", "commitments.b.registered_at");
  assert.deepEqual(C.validateCase(C.applyRegistration(WITH_A, reg("b", sha("commitment b"), "2026-10-10T19:59:59Z"))), { ok: true });
});

test("C33 (checkFull): one commitment hash registered to both roles is refused duplicate_commitment", () => {
  const dup = C.applyRegistration(WITH_A, reg("b", sha("commitment a")));
  refusedWith(dup, "duplicate_commitment", "commitments.b");
});

test("C36 (checkFull, VERDICT): two reveal times in one sealed case are refused (one joint reveal, one time)", () => {
  refusedWith({ ...VERDICT, reveals: { ...VERDICT.reveals, b: { ...VERDICT.reveals.b, revealed_at: "2026-10-10T09:00:01Z" } } }, "status_inconsistent", "status");
});

test("C37 (checkFull, VERDICT): a joint reveal dated exactly at the deadline is refused; one second before reads", () => {
  const at = (t) => ({ ...VERDICT, reveals: { a: { ...VERDICT.reveals.a, revealed_at: t }, b: { ...VERDICT.reveals.b, revealed_at: t } } });
  refusedWith(at(DEADLINE), "status_inconsistent", "status");
  assert.deepEqual(C.validateCase(at("2026-10-10T19:59:59Z")), { ok: true });
});

test("C38 (checkFull, VERDICT): a joint reveal dated before a role's registration is refused", () => {
  const t = "2026-10-10T07:59:59Z"; // after opened_at, before both registrations (08:00:00)
  refusedWith({ ...VERDICT, reveals: { a: { ...VERDICT.reveals.a, revealed_at: t }, b: { ...VERDICT.reveals.b, revealed_at: t } } }, "status_inconsistent", "status");
});

// =============================================================================
// lib/_case_http.js
// =============================================================================

const OPEN_KEY = "case-test-open-key-0011";

test("H03 (takeOpenQuota, the CAS rebuild): the counter moves to 20 between this open's read (19) and its write; the rebuilt count refuses: 429, no case written", async () => {
  const day = "2026-10-10";
  const qpath = H._internal.openQuotaPath(OPEN_KEY, day);
  gh.seed(USAGE, qpath, { kind: "case-open-quota", v: 1, day, count: 19 });
  const viaMock = global.fetch;
  let raced = false;
  global.fetch = async (url, o) => {
    // another open lands first: the counter is 20 when this PUT arrives with the sha of 19
    if (!raced && o && o.method === "PUT" && String(url).includes(`/repos/${USAGE}/contents/${qpath}`)) {
      raced = true;
      gh.seed(USAGE, qpath, { kind: "case-open-quota", v: 1, day, count: 20 });
    }
    return viaMock(url, o);
  };
  const res = makeRes();
  try {
    await H.handleCaseOpen(makeReq({ method: "POST", query: { op: "case-open" }, headers: { "content-type": "application/json", "x-forwarded-for": "10.91.0.1", authorization: `Bearer ${OPEN_KEY}` }, body: opening() }), res, { now: NOW });
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(raced, true, "the race was planted");
  assert.equal(res._status, 429, JSON.stringify(res._body));
  assert.equal(res._body.error_code, "open_quota_exceeded");
  assert.equal(gh.read(USAGE, qpath).count, 20, "the counter is not taken past twenty");
  assert.equal(gh.has(PINS, C.casePath(ID)), false, "no case file");
});

// ---- through the handlers: an open case, registrations, a planted store ----

const STAMPS = process.env.STAMP_REPO;
const stamp = require("../lib/_stamp.js");
let ipSeq = 0;
function post(op, body, headers = {}) {
  ipSeq += 1;
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": `10.92.${(ipSeq >> 8) & 255}.${ipSeq & 255}`, ...headers }, body });
}
async function openCase() {
  const res = makeRes();
  await H.handleCaseOpen(post("case-open", opening(), { authorization: `Bearer ${OPEN_KEY}` }), res, { now: NOW });
  assert.equal(res._status, 201, JSON.stringify(res._body));
  assert.equal(res._body.case_id, ID);
  return ID;
}
function plantStamp(hash) {
  gh.seed(STAMPS, stamp.stampPath(hash), { kind: "file-stamp", v: 1, sha256: hash, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: "2026-10-10T07:45:00.123Z" });
}
function commitmentFor(role, tape) {
  return C.commitmentSha256({ case_id: ID, role, tape_sha256: sha(tape), salt: C.newSalt() });
}
async function commit(role, commitment) {
  plantStamp(commitment);
  const res = makeRes();
  await H.handleCaseCommit(post("case-commit", REG.signedBody({ case_id: ID, role, commitment_sha256: commitment })), res, { now: NOW });
  return res;
}
// The case's PUT, held until `plant` has changed the store (another writer landed first).
async function withCasePutRace(plant, fn) {
  const viaMock = global.fetch;
  let planted = false;
  global.fetch = async (url, o) => {
    if (!planted && o && o.method === "PUT" && String(url).includes(`/repos/${PINS}/contents/${C.casePath(ID)}`)) {
      planted = true;
      plant();
    }
    return viaMock(url, o);
  };
  try {
    return { res: await fn(), planted: () => planted };
  } finally {
    global.fetch = viaMock;
  }
}

test("H18 (judgeRegistration, the role at its path): commit_a.json whose record says role b is unreadable, 503, and nothing is registered", async () => {
  await openCase();
  assert.equal((await commit("a", commitmentFor("a", "tape a")))._status, 201);
  const file = gh.read(PINS, C.registrationPath(ID, "a"));
  // a valid role-b record (signed as role b) at role a's path
  const asB = { ...file, role: "b", sig: C.signRegistration({ case_id: ID, role: "b", commitment_sha256: file.commitment_sha256 }, REG.KEYS.a.signer) };
  assert.deepEqual(C.validateRegistrationRecord(asB), { ok: true }, "fixture: a valid record");
  gh.seed(PINS, C.registrationPath(ID, "a"), asB);
  const res = await commit("b", commitmentFor("b", "tape b"));
  assert.equal(res._status, 503, JSON.stringify(res._body));
  assert.equal(res._body.error_code, "registration_record_unreadable");
  assert.equal(res._body.reason, "registration_not_at_its_path");
  assert.equal(res._body.role, "a");
  assert.equal(gh.has(PINS, C.registrationPath(ID, "b")), false, "nothing registered");
});

test("H36 (readRegistrations): a registration file that is present and unreadable is a 503 registration_record_unreadable, never read as absent", async () => {
  await openCase();
  assert.equal((await commit("a", commitmentFor("a", "tape a")))._status, 201);
  gh.seed(PINS, C.registrationPath(ID, "a"), { kind: "not-a-registration" });
  const res = await commit("b", commitmentFor("b", "tape b"));
  assert.equal(res._status, 503, JSON.stringify(res._body));
  assert.equal(res._body.error_code, "registration_record_unreadable");
  assert.equal(res._body.role, "a");
  assert.equal(gh.has(PINS, C.registrationPath(ID, "b")), false, "nothing registered");
});

test("H32 (projectFiles): a case moved meanwhile to show role a's entry with no registration file is never projected over; the answer is case_update_failed", async () => {
  await openCase();
  const phantom = C.applyRegistration(OPEN_CASE, reg("a", sha("a commitment no file holds")));
  const b = commitmentFor("b", "tape b");
  const { res, planted } = await withCasePutRace(() => gh.seed(PINS, C.casePath(ID), phantom), () => commit("b", b));
  assert.equal(planted(), true, "the race was planted");
  assert.equal(res._status, 503, JSON.stringify(res._body));
  assert.equal(res._body.error_code, "case_update_failed");
  assert.equal(res._body.registration_recorded, true, "b's file stands");
  assert.deepEqual(gh.read(PINS, C.casePath(ID)), phantom, "the moved case is not written over");
});

test("H33 (projectFiles): a case moved meanwhile to show role a's entry differing from its file is never projected over; the answer is case_update_failed", async () => {
  await openCase();
  assert.equal((await commit("a", commitmentFor("a", "tape a")))._status, 201);
  const cur = gh.read(PINS, C.casePath(ID));
  const drifted = { ...cur, commitments: { ...cur.commitments, a: { ...cur.commitments.a, stamped_at: "2026-10-10T07:45:01.000Z" } } };
  assert.deepEqual(C.validateCase(drifted), { ok: true }, "fixture: the drifted case is schema-valid");
  const { res, planted } = await withCasePutRace(() => gh.seed(PINS, C.casePath(ID), drifted), () => commit("b", commitmentFor("b", "tape b")));
  assert.equal(planted(), true, "the race was planted");
  assert.equal(res._status, 503, JSON.stringify(res._body));
  assert.equal(res._body.error_code, "case_update_failed");
  assert.deepEqual(gh.read(PINS, C.casePath(ID)), drifted, "the moved case is not written over");
});

// ---- the joint reveal (an unsigned seal: no case key in this environment) ----

const reconcileFixtures = require("./fixtures/reconcile/cases.json");
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
function tapePair() {
  const c = reconcileFixtures.cases.find((x) => /^receipt-test_call_proxy_tape\/test_cross_repo_adapter_tape_a0: agent vs tool$/.test(x.name) && x.python);
  assert.ok(c, "the fixture tape pair");
  return [Buffer.from(c.a_b64, "base64"), Buffer.from(c.b_b64, "base64")];
}
async function committedCase() {
  await openCase();
  const [ta, tb] = tapePair();
  const parties = {};
  for (const [role, tape] of [["a", ta], ["b", tb]]) {
    const salt = C.newSalt();
    const p = { role, tape, tape_sha256: sha(tape), salt, commitment_sha256: C.commitmentSha256({ case_id: ID, role, tape_sha256: sha(tape), salt }) };
    assert.equal((await commit(role, p.commitment_sha256))._status, 201);
    parties[role] = p;
  }
  assert.equal(gh.read(PINS, C.casePath(ID)).status, "COMMITTED");
  return parties;
}
// The service's reconcile signer (red-team fix B: with none, nothing is
// compared).
const RECEIPT_KEY = require("../lib/_checkpoint.js").generateKey("arcaeon.io/reconcile-test/2026-10-10");
// The one signature rule: the reveal seals only signed, so this
// environment carries a case key (and the log key, to show it apart) and
// the document lists it.
const CASE_KEY_G = require("../lib/_checkpoint.js").generateKey("arcaeon.io/case-test-gaps/2026-10-12");
const LOG_KEY_G = require("../lib/_checkpoint.js").generateKey("arcaeon.io/log-test-gaps/2026-10-12");
const RECEIPT_ENV = Object.freeze({ WITNESS_RECONCILE_SIGNER_KEY: RECEIPT_KEY.signer, WITNESS_CASE_SIGNER_KEY: CASE_KEY_G.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY_G.signer });
// The document the deployment carries (Design I): the reconcile key as a
// reconcile entry, and no case key, so the seal is unsigned.
const RECEIPT_DOC = Object.freeze({ ...require("../lib/_case_seal.js").PUBLISHED_KEYS, keys: [KD.entry(CASE_KEY_G), KD.reconcileEntry(RECEIPT_KEY)] });
async function reveal(p, { now = REVEAL_AT, env = RECEIPT_ENV } = {}) {
  const res = makeRes();
  const body = {
    case_id: ID,
    reveals: { a: { tape_sha256: p.a.tape_sha256, salt: p.a.salt }, b: { tape_sha256: p.b.tape_sha256, salt: p.b.salt } },
    tape_a_b64: p.a.tape.toString("base64"),
    tape_b_b64: p.b.tape.toString("base64"),
  };
  await H.handleCaseReveal(post("case-reveal", body), res, { now, env: KD.deployed(gh, env, RECEIPT_DOC), keyDocument: RECEIPT_DOC });
  return { status: res._status, body: typeof res._body === "string" ? JSON.parse(res._body) : res._body };
}

test("H41 (reveal step 2b): a stamp whose one public commit is no longer the commit its registration recorded is refused case_record_inconsistent; nothing is sealed", async () => {
  const p = await committedCase();
  const spath = stamp.stampPath(p.b.commitment_sha256);
  const registered = gh.read(PINS, C.registrationPath(ID, "b")).stamp_commit;
  // the same stamp record, same stamped_at, now held by exactly one OTHER commit
  gh.seed(STAMPS, spath, gh.read(STAMPS, spath));
  const now = gh.commitsFor(STAMPS, spath);
  assert.equal(now.length, 1, "fixture: one commit, so the history is not ambiguous");
  assert.notEqual(now[0].sha, registered, "fixture: another commit");
  const r = await reveal(p);
  assert.equal(r.status, 503, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.error_code, "case_record_inconsistent");
  assert.equal(r.body.reason, "stamp_differs_from_registration");
  assert.equal(r.body.role, "b");
  assert.equal(gh.read(PINS, C.casePath(ID)).status, "COMMITTED", "nothing sealed");
});

test("H57 (operatorBearer): a bearer of the operator key's length that is not the key is refused 401 reference_unauthorized, before anything is read", async () => {
  const want = "case-test-case-operator-key-0001";
  const wrong = "case-test-case-operator-key-0002";
  assert.equal(wrong.length, want.length, "fixture: same length");
  const env = { [H.OPERATOR_KEY_ENV]: want };
  const body = { case_id: ID, cross_reference: { operator: "second-operator.example", reference: "ref-1", url: "https://second-operator.example/r/1" } };
  const reads = gh.getLog.length;
  const res = makeRes();
  await H.handleCaseReference(post("case-reference", body, { authorization: `Bearer ${wrong}` }), res, { now: NOW, env });
  assert.equal(res._status, 401, JSON.stringify(res._body));
  assert.equal(res._body.error_code, "reference_unauthorized");
  assert.equal(gh.getLog.length, reads, "nothing read");
  // control: the key itself passes the bearer check (and then finds no case)
  const ok = makeRes();
  await H.handleCaseReference(post("case-reference", body, { authorization: `Bearer ${want}` }), ok, { now: NOW, env });
  assert.equal(ok._status, 404, JSON.stringify(ok._body));
});

// =============================================================================
// lib/_case_seal.js, lib/_case_page.js, lib/_sealer.js, api/verify.js
// =============================================================================

const S = require("../lib/_case_seal.js");
const CP = require("../lib/_case_page.js");
const sealer = require("../lib/_sealer.js");
const pending = require("../lib/_pending.js");
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const verifyHandler = require("../api/verify.js");

async function sealedCase({ pinFails = false } = {}) {
  const p = await committedCase();
  if (pinFails) gh.forceFailure(PINS, S.pinPaths(ID).seq, 1, 502);
  const r = await reveal(p);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.pin, pinFails ? "commit_unrecorded" : "pinned");
  return p;
}
// unit R-I: the reader's current document lists both keys of the seal (a
// key it does not list is signer_unlisted), as RECEIPT_DOC does
async function page(id = ID, keyDocument = RECEIPT_DOC) {
  const res = makeRes();
  CP._internal.clearPageCache(); // unit R-J (J7): each view here reads afresh
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": "10.93.0.1" } }), res, { now: REVEAL_AT + 3600000, keyDocument });
  return { status: res._status, html: String(res._body) };
}
// GET of `dirPath`'s listing answers 500 while `fn` runs.
async function withListingFailure(dirPath, fn) {
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    const u = String(url);
    if ((!o || !o.method || o.method === "GET") && u.includes(`/repos/${PINS}/contents/${dirPath}?`)) {
      return new Response(JSON.stringify({ message: "planted listing failure" }), { status: 500, headers: { "content-type": "application/json" } });
    }
    return viaMock(url, o);
  };
  try {
    return await fn();
  } finally {
    global.fetch = viaMock;
  }
}

test("S39 (caseTreeIndex): a case holding one registration file is not a sealer candidate; since unit R-N2 (M3) its root is read once, by the withdrawn path, and nothing is written", async () => {
  await openCase();
  assert.equal((await commit("a", commitmentFor("a", "tape a")))._status, 201);
  const from = gh.getLog.length;
  const r = await S.anchorPending({ now: NOW });
  assert.equal(r.ok, true);
  assert.equal(r.candidates, 0);
  assert.equal(r.read, 0);
  assert.equal(r.not_sealed, 0);
  assert.equal(gh.getLog.slice(from).filter((p) => p === C.casePath(ID)).length, 1, "read once, by the withdrawn path");
  assert.deepEqual(r.withdrawn_repaired, [], "an OPEN case is left as it is");
});

test("S55 (referenceSeqs): a references listing that cannot be read is never read as no rows: liveRecords is references_unreadable, a reference is 503 and writes nothing", async () => {
  const p = await sealedCase();
  const sealed = gh.read(PINS, C.casePath(ID));
  const live = await withListingFailure(C.referencesDir(ID), () => S.liveRecords(sealed));
  assert.deepEqual(live, { ok: false, reason: "references_unreadable" });
  const writes = gh.putLog.length;
  const res = makeRes();
  await withListingFailure(C.referencesDir(ID), () => H.handleCaseReference(post("case-reference",
    { case_id: ID, role: "a", tape_sha256: p.a.tape_sha256, salt: p.a.salt, cross_reference: { operator: "op.example", reference: "r-1", url: "https://op.example/r/1" } }), res, { now: REVEAL_AT + 3600000, env: RECEIPT_ENV, keyDocument: RECEIPT_DOC }));
  assert.equal(res._status, 503, JSON.stringify(res._body));
  assert.equal(res._body.error_code, "store_unreachable");
  assert.equal(gh.putLog.length, writes, "nothing written");
});

test("P07 (signedByHtml): a WITHDRAWN record signed by a key the key document does not list says its signature cannot be confirmed, never that it verifies", async () => {
  const p = await committedCase();
  const caseKey = checkpoint.generateKey("arcaeon.io/case-test/2026-10-10");
  const env = {
    [S.CASE_SIGNER_ENV]: caseKey.signer,
    [receipts.SIGNER_ENV]: checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-10").signer,
    WITNESS_LOG_SIGNER_KEY: checkpoint.generateKey("arcaeon.io/log-test/2026-10-10").signer,
  };
  const keyId = caseKey.verifier.split("+").slice(0, 2).join("+");
  const listing = { ...S.PUBLISHED_KEYS, keys: [{ key_id: keyId, verifier: caseKey.verifier, since: "2026-10-10", note: "a test key", status: "active" }] };
  const res = makeRes();
  await H.handleCaseWithdraw(post("case-withdraw", { case_id: ID, role: "a", tape_sha256: p.a.tape_sha256, salt: p.a.salt }), res, { now: REVEAL_AT, env, keyDocument: listing });
  assert.equal(res._status, 201, JSON.stringify(res._body));
  assert.equal(gh.read(PINS, C.casePath(ID)).signed_by, keyId, "fixture: signed");
  const listed = await page(ID, listing);
  assert.match(listed.html, /the signature verifies under the published verifier/, "control");
  const unlisted = await page(ID, S.PUBLISHED_KEYS);
  assert.equal(unlisted.status, 200);
  assert.match(unlisted.html, /the signature cannot be confirmed by the key document \(signer_unpublished\)/);
  assert.ok(!unlisted.html.includes("the signature verifies under the published verifier"));
});

test("P08 (anchorHtml): a pin pointer holding another chain reads as a conflict on the page, never as anchored", async () => {
  await sealedCase();
  const latest = S.pinPaths(ID).latest;
  gh.seed(PINS, latest, { ...gh.read(PINS, latest), chain: "f".repeat(64) });
  const pg = await page();
  assert.equal(pg.status, 200);
  // unit R-J2 (B1): worded by the reason
  assert.match(pg.html, /conflict: the pin pointer under this case&#39;s namespace holds another chain \(pointer_holds_another_chain\)/);
  assert.ok(!pg.html.includes("anchored: a daily anchor record"), "not anchored");
  assert.ok(!pg.html.includes("pinned at commit"), "not pinned");
});

test("P10 (crossRows): a reference row's operator is escaped on the page", async () => {
  const p = await sealedCase();
  const res = makeRes();
  await H.handleCaseReference(post("case-reference",
    { case_id: ID, role: "a", tape_sha256: p.a.tape_sha256, salt: p.a.salt, cross_reference: { operator: "<i>op</i>", reference: "r-1", url: "https://op.example/r/1" } }), res, { now: REVEAL_AT + 3600000, env: RECEIPT_ENV, keyDocument: RECEIPT_DOC });
  assert.equal(res._status, 201, JSON.stringify(res._body));
  const pg = await page();
  assert.ok(pg.html.includes("&lt;i&gt;op&lt;/i&gt;"), "escaped");
  assert.ok(!pg.html.includes("<i>op</i>"), "never raw");
});

test("P11 (handleCasePage): a valid case stored at another id's path is not rendered: 503 case_not_at_its_path", async () => {
  const other = sha("another case id");
  gh.seed(PINS, C.casePath(other), OPEN_CASE);
  const pg = await page(other);
  assert.equal(pg.status, 503);
  assert.match(pg.html, /case_not_at_its_path/);
});

test("E01 (anchorCases): a case pass that throws is reported case_pass_threw, never as a pass that ran", async (t) => {
  t.mock.method(S, "anchorPending", async () => {
    throw new Error("planted throw");
  });
  assert.deepEqual(await sealer.anchorCases({ now: new Date(NOW) }), { ok: false, reason: "case_pass_threw", detail: "planted throw" });
});

test("E03 (sealOnce): a batch pass that refuses does not stop the case pass: a pending case is pinned on the same run", async () => {
  await sealedCase({ pinFails: true });
  gh.seed(USAGE, pending.PENDING_PATH, { open: { batch_id: 1 } }); // no leaf array: the batch refuses
  const r = await sealer.sealOnce({ now: new Date(REVEAL_AT + 60000), keyDocument: RECEIPT_DOC });
  assert.equal(r.refused, true);
  assert.equal(r.reason, "pending_document_corrupt");
  assert.ok(r.cases && r.cases.ok, JSON.stringify(r.cases));
  assert.deepEqual(r.cases.newly_pinned, [ID]);
  assert.equal(gh.has(PINS, S.pinPaths(ID).latest), true);
});

test("A01 (api/verify.js): ?op=case-withdraw reaches the withdrawal handler: a withdrawal's body for an unknown case is 404 case_not_found, not a reveal's unknown_field", async () => {
  const res = makeRes();
  await verifyHandler(post("case-withdraw", { case_id: sha("no such case"), role: "a", tape_sha256: sha("t"), salt: sha("s") }), res);
  assert.equal(res._status, 404, JSON.stringify(res._body));
  assert.equal(res._body.error_code, "case_not_found");
  assert.match(res._body.error, /no case is open with this id/);
});
