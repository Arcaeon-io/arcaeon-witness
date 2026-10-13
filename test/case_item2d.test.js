// test/case_item2d.test.js — the case protocol, item 2d: a fix pass after
// the code review of 2c.
//
//   FIX 1  ?op=case-reference and the case page hold a VERDICT to the full
//          sealed check before treating it as sealed: the receipt's binding
//          and a signed receipt's signature (lib/_case_seal.js
//          checkStoredReceipt), then a signed case's own signature under the
//          verifier its signed_by names in the published key document. A
//          record that fails is refused for a reference (a typed 409, no row
//          written), and the page shows the does-not-verify state instead of
//          a verdict. Planted: a schema-valid VERDICT with an unbound
//          receipt, and one with its sig replaced.
//   FIX 2  liveRecords never states a definitive count from a truncated
//          read: a row window that ends without a valid row is
//          indeterminate, and the page says the count could not be
//          established. Planted: twenty invalid rows, then a valid one.
//   FIX 3  the operator path for references reads WITNESS_CASE_OPERATOR_KEY
//          and never WITNESS_ADMIN_KEY; unset, no bearer is 401 and a bearer
//          is 503.
//   FIX 4  the review's claim that takeOpenQuota throws on the first open of
//          a day for a new key: planted first, through the real read path.
//   FIX 5  the conflict-observation count carries partial when the tree
//          read was truncated, the way the case row does.
//
// The fixtures are 2c's (the same tape pair, opening, party and stamp
// helpers), repeated because a test file cannot require another test file
// without running it. Each test plants the failure it exists to catch;
// MUST-FAIL ARMs show the wrong behaviour caught by the same check. Every
// store is the in-memory mock: no network.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
// Three env keys: FIX 4 needs keys that have never opened a case.
process.env.WITNESS_KEYS = "case-test-open-key-0007:case-test-,case-test-open-key-0008:case-test2-,case-test-open-key-0009:case-test3-";
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
const keys = require("../lib/_keys.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const S = require("../lib/_case_seal.js");
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const stamp = require("../lib/_stamp.js");
const CP = require("../lib/_case_page.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const USAGE = process.env.GITHUB_USAGE_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z"); // open and register
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

let ipSeq = 0;
function freshIp() {
  ipSeq += 1;
  return `10.77.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
}
function req(op, body, headers = {}) {
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": freshIp(), ...headers }, body });
}

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

// ---- 2c's fixtures: keys, tapes, a sealed case, the three calls ----

const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-10");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-10");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-10");
const SIGNED = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const CASE_KEY_ID = CASE_KEY.verifier.split("+").slice(0, 2).join("+");
const ENTRY = Object.freeze({ key_id: CASE_KEY_ID, verifier: CASE_KEY.verifier, since: "2026-10-10", note: "the test environment's case key", status: "active" });
// The committed document lists no key; these tests hand the seal, the page
// and the reference a copy that lists the test key (and, since Design I, the
// reconcile key as a reconcile entry).
const KEYS_DOC = Object.freeze({ ...S.PUBLISHED_KEYS, keys: [ENTRY, KD.reconcileEntry(RECEIPT_KEY)] });
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0007" });
const OPERATOR_KEY = "case-test-case-operator-key-0001";
const ADMIN_KEY = "case-test-admin-key-0001";
const OPERATOR_ENV = Object.freeze({ ...SIGNED, [H.OPERATOR_KEY_ENV]: OPERATOR_KEY });
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0042", url: "https://second-operator.example/cases/0042" });

function pairNamed(re) {
  const c = reconcileFixtures.cases.find((x) => re.test(x.name) && x.python);
  assert.ok(c, String(re));
  return [Buffer.from(c.a_b64, "base64"), Buffer.from(c.b_b64, "base64")];
}
const [AGENT_TAPE, TOOL_TAPE] = pairNamed(/^receipt-test_call_proxy_tape\/test_cross_repo_adapter_tape_a0: agent vs tool$/);

function parsed(res) {
  return typeof res._body === "string" ? JSON.parse(res._body) : res._body;
}
function plantStamp(hash, stampedAt = "2026-10-10T07:45:00.123Z") {
  gh.seed(STAMPS, stamp.stampPath(hash), { kind: "file-stamp", v: 1, sha256: hash, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: stampedAt });
}
function party(caseId, role, tape, salt = C.newSalt()) {
  const tape_sha256 = sha(tape);
  return { role, tape, tape_sha256, salt, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
}
async function committedCase({ over } = {}) {
  const o = makeRes();
  await H.handleCaseOpen(req("case-open", opening(over), OPEN_AUTH), o, { now: NOW });
  assert.equal(o._status, 201, JSON.stringify(o._body));
  const id = o._body.case_id;
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  for (const p of [a, b]) {
    plantStamp(p.commitment_sha256);
    const r = makeRes();
    await H.handleCaseCommit(req("case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 })), r, { now: NOW });
    assert.equal(r._status, 201, JSON.stringify(r._body));
  }
  return { id, a, b };
}
function revealBody(id, a, b, extra = {}) {
  return {
    case_id: id,
    reveals: { a: { tape_sha256: a.tape_sha256, salt: a.salt }, b: { tape_sha256: b.tape_sha256, salt: b.salt } },
    tape_a_b64: a.tape.toString("base64"),
    tape_b_b64: b.tape.toString("base64"),
    ...extra,
  };
}
async function sealedCase({ over, keyDocument = KEYS_DOC, extra } = {}) {
  const c = await committedCase({ over });
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", revealBody(c.id, c.a, c.b, extra)), res, { now: REVEAL_AT, env: KD.deployed(gh, SIGNED, keyDocument), keyDocument });
  assert.equal(res._status, 201, String(res._body).slice(0, 300));
  return c;
}
function storedCase(id) {
  return gh.read(PINS, C.casePath(id));
}
const proofOf = (id, p) => ({ case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt: p.salt });
async function reference(body, { now = REVEAL_AT + 3600000, env = SIGNED, keyDocument = KEYS_DOC, headers = {} } = {}) {
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", body, headers), res, { now, env, keyDocument });
  return { status: res._status, body: parsed(res), headers: res._headers };
}
async function casePage(id, { now = REVEAL_AT + 3600000, keyDocument = KEYS_DOC } = {}) {
  const res = makeRes();
  CP._internal.clearPageCache(); // unit R-J (J7): each view here reads afresh
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": freshIp() } }), res, { now, keyDocument });
  return { status: res._status, html: String(res._body) };
}
function referenceFiles(id) {
  return [...gh.repos.get(PINS).keys()].filter((p) => p.startsWith(`${C.referencesDir(id)}/`)).sort();
}
// The page's records cell: what it states as the live count.
function recordsCell(html) {
  const m = /<th>records<\/th><td>(.*?)<\/td>/.exec(html);
  assert.ok(m, "the page has a records row");
  return m[1];
}

// =============================================================================
// FIX 1: the sealed check before a VERDICT is treated as sealed
// =============================================================================

test("FIX 1 (planted): a schema-valid VERDICT with an unbound receipt, and one with its sig replaced: ?op=case-reference refuses each with a typed 409 and writes nothing; the page shows the does-not-verify state, no verdict", async () => {
  const { id, a } = await sealedCase({ over: { scope_digest: sha("fix 1") } });
  const good = storedCase(id);
  assert.equal(typeof good.sig, "string", "fixture: the case is signed");
  assert.equal((await S.sealedRecordReason(good, KEYS_DOC)).code, "valid_under_document", "fixture: the case as sealed verifies");
  const k = checkpoint.parseSignerKey(CASE_KEY.signer);
  const plants = {
    // the receipt's compared_at is not the reveal time: the receipt no longer binds
    "an unbound receipt": [{ ...good, verdict: { ...good.verdict, compared_at: "2026-10-10T09:00:01Z" } }, "verdict_unbound", "receipt_time_mismatch"],
    // only sig replaced, by a well-formed signature of other bytes made with the right key
    "a replaced sig": [{ ...good, sig: crypto.sign(null, Buffer.from("other bytes"), k.privateKey).toString("base64") }, "case_signature_invalid", "bad_signature"],
  };
  for (const [name, [bad, code, reason]] of Object.entries(plants)) {
    assert.deepEqual(C.validateCase(bad), { ok: true }, `${name}: fixture is schema-valid`);
    assert.equal(bad.status, "VERDICT", name);
    gh.seed(PINS, C.casePath(id), bad);
    const writes = gh.putLog.length;
    // the reference, by a role's proof and by the operator: refused, typed, nothing written
    for (const [who, body, o] of [
      ["role a", { ...proofOf(id, a), cross_reference: XREF }, {}],
      ["the operator", { case_id: id, cross_reference: XREF }, { env: OPERATOR_ENV, headers: { authorization: `Bearer ${OPERATOR_KEY}` } }],
    ]) {
      const r = await reference(body, o);
      assert.equal(r.status, 409, `${name}, ${who}: ${JSON.stringify(r.body)}`);
      assert.equal(r.body.ok, false);
      assert.equal(r.body.error_code, code, `${name}, ${who}`);
      assert.equal(r.body.reason, reason, `${name}, ${who}`);
      assert.match(r.body.error, /no row was written/);
      assert.equal(r.body.row, undefined);
    }
    assert.equal(gh.putLog.length, writes, `${name}: nothing written`);
    assert.deepEqual(referenceFiles(id), [], `${name}: no row`);
    // the page: the does-not-verify state, no verdict, and nothing read past the case file
    const reads = gh.getLog.length;
    const p = await casePage(id);
    assert.equal(p.status, 200, name);
    assert.match(p.html, /<h1>Case: SEALED RECORD DOES NOT VERIFY<\/h1>/, name);
    assert.ok(p.html.includes(`<code>${code}</code>`) && p.html.includes(`<code>${reason}</code>`), `${name}: the check and its reason`);
    for (const absent of [">MATCHED<", "<th>verdict</th>", "<th>first divergence</th>", "<th>records</th>", "<th>anchor</th>", "Cross-reference", "agent-operator@example.com", "registered at"]) {
      assert.ok(!p.html.includes(absent), `${name}: the page shows ${absent}`);
    }
    for (const l of C.LIMITS) assert.ok(p.html.includes(l.replace(/&/g, "&amp;")), `${name}: the limits`);
    assert.deepEqual(gh.getLog.slice(reads), [C.casePath(id)], `${name}: the case file alone was read (no pin, no reference row)`);
    // one vocabulary: the sealer's retry refuses the same record by the same code
    const anchored = await S.anchorCase(id, { now: REVEAL_AT + 60000, keyDocument: KEYS_DOC });
    assert.deepEqual([anchored.ok, anchored.code, anchored.reason], [false, code, reason], name);
    // MUST-FAIL ARM: 2c checked the status alone, and both plants read VERDICT
    assert.equal(bad.status === "VERDICT" && C.validateCase(bad).ok, true, `${name}: 2c would have taken it as sealed`);
  }
  // an unsigned seal whose receipt does not bind: the same state, naming no key
  // (built the seal module's way: since the one signature rule the reveal
  // never seals unsigned)
  const u = await sealedCase({ over: { scope_digest: sha("fix 1 unsigned") } });
  const ug = S.signRecord({ ...storedCase(u.id), signed_by: null, sig: null, sig_reason: null }, S.loadCaseSigner({}), "This case is sealed and not signed");
  assert.equal(ug.sig, null, "fixture: unsigned");
  gh.seed(PINS, C.casePath(u.id), { ...ug, verdict: { ...ug.verdict, compared_at: "2026-10-10T09:00:01Z" } });
  const up = await casePage(u.id);
  assert.match(up.html, /<h1>Case: SEALED RECORD DOES NOT VERIFY<\/h1>/);
  assert.match(up.html, /no key: it is stored unsigned/);
  assert.equal((await reference({ ...proofOf(u.id, u.a), cross_reference: XREF })).body.error_code, "verdict_unbound");
  // control: the case as sealed takes a row and shows its verdict. Red-team
  // fix D reads its pin first, and the pin names the commit that wrote the
  // case file; re-seeding a path drops its history in the mock, so the pin
  // is pointed at the case file's commit as it now stands.
  gh.seed(PINS, C.casePath(id), good);
  const now = gh.commitsFor(PINS, C.casePath(id))[0].sha;
  for (const p of [S.pinPaths(id).seq, S.pinPaths(id).latest]) gh.seed(PINS, p, { ...gh.read(PINS, p), case_commit: now });
  const ok = await reference({ ...proofOf(id, a), cross_reference: XREF });
  assert.equal(ok.status, 201, JSON.stringify(ok.body));
  const shown = await casePage(id);
  assert.match(shown.html, /<h1>Case: VERDICT<\/h1>/);
  assert.match(shown.html, /<span class="word pass">MATCHED<\/span>/);
});

// =============================================================================
// FIX 2: no definitive count from a truncated read
// =============================================================================

test("FIX 2 (planted): twenty invalid reference rows then a valid one: liveRecords is indeterminate, never one record, and the page says the count could not be established", async () => {
  const { id } = await sealedCase({ over: { scope_digest: sha("fix 2") } });
  const sealed = storedCase(id);
  assert.equal(sealed.cross_reference, null, "fixture: the seal carries no cross_reference");
  assert.equal(S.REFERENCE_ROW_READS, 20, "fixture: the window is twenty rows");
  const signer = S.loadCaseSigner(SIGNED, { keyDocument: KEYS_DOC });
  const row = (seq) => S.referenceRow({ caseId: id, seq, crossReference: XREF, recordedAt: "2026-10-10T10:00:00Z", appendedBy: "operator" }, signer);
  for (let seq = 1; seq <= 20; seq += 1) gh.seed(PINS, C.referencePath(id, seq), { ...row(seq), extra: true }); // invalid: an unknown field
  gh.seed(PINS, C.referencePath(id, 21), row(21)); // valid, past the window
  const live = await S.liveRecords(sealed, { keyDocument: KEYS_DOC });
  assert.equal(live.ok, true);
  assert.equal(live.indeterminate, true);
  assert.equal(live.records, null, "not established, so no number");
  assert.equal(live.rows.length, 0);
  assert.equal(live.invalid.length, 20);
  assert.ok(live.invalid.every((x) => x.reason === "reference_unknown_field"));
  assert.equal(live.unread, 1);
  assert.equal(live.partial, true);
  // the page says so in words, and never states one record as the live count
  const p = await casePage(id);
  const cell = recordsCell(p.html);
  assert.match(cell, /^the live count could not be established on this request/);
  assert.ok(!/^one record/.test(cell) && !/^two records/.test(cell), cell);
  assert.match(cell, /at seal time: one record/, "the count at seal time is still stated, as that");
  assert.match(cell, /20 reference row\(s\) are not valid/);
  // the reference answer reads the count back the same way: null, never 1
  const r = await reference({ case_id: id, cross_reference: { ...XREF, reference: "fix 2, row 22" } }, { env: OPERATOR_ENV, headers: { authorization: `Bearer ${OPERATOR_KEY}` } });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(r.body.seq, 22);
  assert.equal(r.body.records_live, null);
  gh._repoMap(PINS).delete(C.referencePath(id, 22));
  // MUST-FAIL ARM: 2c's rule over the same read (a valid row read, or the
  // seal's cross_reference, else 1) said one record
  assert.equal(sealed.cross_reference !== null || live.rows.length > 0 ? 2 : 1, 1);

  // controls: a window that reaches the valid row says 2, established
  const wide = await S.liveRecords(sealed, { keyDocument: KEYS_DOC, maxRows: 21 });
  assert.deepEqual([wide.records, wide.indeterminate], [2, false]);
  // twenty invalid rows and nothing past them: the read was whole, so 1 is established
  gh._repoMap(PINS).delete(C.referencePath(id, 21));
  const whole = await S.liveRecords(sealed, { keyDocument: KEYS_DOC });
  assert.deepEqual([whole.records, whole.indeterminate, whole.partial], [1, false, false]);
  assert.match(recordsCell((await casePage(id)).html), /^one record/);
  // a valid row INSIDE the window settles it at 2 whatever is left unread
  gh.seed(PINS, C.referencePath(id, 5), row(5));
  for (let seq = 21; seq <= 25; seq += 1) gh.seed(PINS, C.referencePath(id, seq), { ...row(seq), extra: true });
  const early = await S.liveRecords(sealed, { keyDocument: KEYS_DOC });
  assert.deepEqual([early.records, early.indeterminate, early.unread], [2, false, 5]);
  gh.seed(PINS, C.referencePath(id, 5), { ...row(5), extra: true }); // back to twenty invalid rows
  for (let seq = 21; seq <= 25; seq += 1) gh._repoMap(PINS).delete(C.referencePath(id, seq));

  // a row whose read fails was not seen, so it is not an invalid row: with no
  // valid row read, the count is not established either
  const failing = C.referencePath(id, 7);
  const viaMock = global.fetch;
  global.fetch = async (url, o) => ((!o || !o.method || o.method === "GET") && String(url).includes(`/contents/${failing}?`)
    ? { status: 502, ok: false, json: async () => ({}), text: async () => "{}" }
    : viaMock(url, o));
  let unseen;
  try {
    unseen = await S.liveRecords(sealed, { keyDocument: KEYS_DOC });
  } finally {
    global.fetch = viaMock;
  }
  assert.deepEqual(unseen.unreadable, [7]);
  assert.equal(unseen.invalid.length, 19, "the failed read is not counted as an invalid row");
  assert.deepEqual([unseen.records, unseen.indeterminate], [null, true]);

  // a seal that carries its own cross_reference is two records whatever the window
  const x = await sealedCase({ over: { scope_digest: sha("fix 2 xref") }, extra: { cross_reference: XREF } });
  const xs = storedCase(x.id);
  for (let seq = 1; seq <= 21; seq += 1) gh.seed(PINS, C.referencePath(x.id, seq), { ...S.referenceRow({ caseId: x.id, seq, crossReference: XREF, recordedAt: "2026-10-10T10:00:00Z", appendedBy: "operator" }, signer), extra: true });
  const xl = await S.liveRecords(xs, { keyDocument: KEYS_DOC });
  assert.deepEqual([xl.records, xl.indeterminate, xl.partial], [2, false, true]);
});

// =============================================================================
// FIX 3: the operator's own key
// =============================================================================

test("FIX 3: the operator path reads WITNESS_CASE_OPERATOR_KEY and never WITNESS_ADMIN_KEY; unset, no bearer is 401 reference_unauthorized and a bearer is 503 operator_key_not_configured; nothing written", async (t) => {
  assert.equal(H.OPERATOR_KEY_ENV, "WITNESS_CASE_OPERATOR_KEY");
  const { id, b } = await sealedCase({ over: { scope_digest: sha("fix 3") } });
  const body = { case_id: id, cross_reference: XREF };
  const writes = gh.putLog.length;
  // unset, with the admin key set: what the code does
  const adminOnly = { ...SIGNED, WITNESS_ADMIN_KEY: ADMIN_KEY };
  const anon = await reference(body, { env: adminOnly });
  assert.equal(anon.status, 401, JSON.stringify(anon.body));
  assert.equal(anon.body.error_code, "reference_unauthorized");
  assert.match(anon.body.error, /neither was presented/);
  assert.equal(anon.headers["www-authenticate"], 'Bearer realm="arcaeon-witness"');
  for (const bearer of [ADMIN_KEY, OPERATOR_KEY, "anything"]) {
    const r = await reference(body, { env: adminOnly, headers: { authorization: `Bearer ${bearer}` } });
    assert.equal(r.status, 503, `${bearer}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.error_code, "operator_key_not_configured", bearer);
    // unit R-N2 (B2): the body carries the code only, never a variable's name
    assert.doesNotMatch(JSON.stringify(r.body), /WITNESS_|_KEY\b/, "no environment variable named");
  }
  // and with nothing set at all, the same two answers
  assert.equal((await reference(body, { env: SIGNED })).status, 401);
  assert.equal((await reference(body, { env: SIGNED, headers: { authorization: `Bearer ${OPERATOR_KEY}` } })).status, 503);
  assert.equal(gh.putLog.length, writes, "no refusal wrote anything");
  assert.deepEqual(referenceFiles(id), []);
  // set to its own key beside a different admin key: the admin key is not the operator's
  const both = { ...SIGNED, WITNESS_ADMIN_KEY: ADMIN_KEY, [H.OPERATOR_KEY_ENV]: OPERATOR_KEY };
  const admin = await reference(body, { env: both, headers: { authorization: `Bearer ${ADMIN_KEY}` } });
  assert.equal(admin.status, 401, JSON.stringify(admin.body));
  assert.equal(admin.body.error_code, "reference_unauthorized");
  assert.match(admin.body.error, /the bearer key is not the operator's/);
  assert.equal((await reference(body, { env: both })).status, 401, "no bearer, the key set: 401 too");
  assert.equal(gh.putLog.length, writes);
  const op = await reference(body, { env: both, headers: { authorization: `Bearer ${OPERATOR_KEY}` } });
  assert.equal(op.status, 201, JSON.stringify(op.body));
  assert.equal(op.body.appended_by, "operator");
  // a role's proof never reads the variable
  assert.equal((await reference({ ...proofOf(id, b), cross_reference: XREF }, { env: SIGNED })).status, 201);
  // through the real dispatch, which hands the handler no env: process.env
  const verifyHandler = require("../api/verify.js");
  const saved = { admin: process.env.WITNESS_ADMIN_KEY, op: process.env[H.OPERATOR_KEY_ENV] };
  t.after(() => {
    for (const [k, v] of [["WITNESS_ADMIN_KEY", saved.admin], [H.OPERATOR_KEY_ENV, saved.op]]) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });
  const dispatch = async (bearer) => {
    const res = makeRes();
    await verifyHandler(req("case-reference", { case_id: id, cross_reference: { ...XREF, reference: `via verify.js ${bearer}` } }, { authorization: `Bearer ${bearer}` }), res);
    return { status: res._status, body: parsed(res) };
  };
  process.env.WITNESS_ADMIN_KEY = ADMIN_KEY;
  delete process.env[H.OPERATOR_KEY_ENV];
  const viaAdmin = await dispatch(ADMIN_KEY);
  assert.equal(viaAdmin.status, 503, JSON.stringify(viaAdmin.body));
  assert.equal(viaAdmin.body.error_code, "operator_key_not_configured");
  // MUST-FAIL ARM: 2c read WITNESS_ADMIN_KEY, and this environment sets it to
  // the bearer just sent, so 2c would have appended this row as the operator
  assert.equal(process.env.WITNESS_ADMIN_KEY, ADMIN_KEY);
  process.env[H.OPERATOR_KEY_ENV] = OPERATOR_KEY;
  // a signed seal, held to the document it names (the dispatch carries the
  // committed document as the current one; since the one signature rule an
  // unsigned seal would not verify). Since unit R-I the current document must
  // list both keys (else signer_unlisted), and the committed one lists no
  // test key: the check is handed this test's document as the current one.
  const un = await sealedCase({ over: { scope_digest: sha("fix 3 dispatch") } });
  const realCheck = S.sealedRecordReason;
  t.mock.method(S, "sealedRecordReason", (rec) => realCheck(rec, KEYS_DOC));
  const res = makeRes();
  await verifyHandler(req("case-reference", { case_id: un.id, cross_reference: XREF }, { authorization: `Bearer ${OPERATOR_KEY}` }), res);
  // the operator's bearer is accepted (not 401): the request reaches the
  // signer, and since unit R-N (N1: an unsigned row is not a record) this
  // environment, which carries no case key the committed document lists,
  // writes no row
  assert.deepEqual([res._status, parsed(res).error_code, parsed(res).reason], [503, "signer_unavailable", "case_key_unset"], JSON.stringify(parsed(res)));
  assert.equal(gh.has(PINS, C.referencePath(un.id, 1)), false);
  // the code reads no WITNESS_ADMIN_KEY: no property access and no string of it
  const fs = require("node:fs");
  const path = require("node:path");
  const code = fs.readFileSync(path.join(__dirname, "..", "lib", "_case_http.js"), "utf-8").replace(/\r\n/g, "\n").split("\n").filter((l) => !/^\s*\/\//.test(l)).join("\n");
  assert.ok(!code.includes("WITNESS_ADMIN_KEY"), "lib/_case_http.js's code (its comments aside) never names WITNESS_ADMIN_KEY");
});

// =============================================================================
// FIX 4: the first open of a day for a new key, through the real read path
// =============================================================================

test("FIX 4 (planted first): the first open of a UTC day for a key that has never opened reads the absent counter through the real read path, opens 201 and writes count 1; the second reads the present counter and writes 2", async () => {
  const fresh = "case-test-open-key-0008";
  const day = "2026-10-10";
  const qpath = H._internal.openQuotaPath(fresh, day);
  assert.equal(gh.has(USAGE, qpath), false, "fixture: no counter for this key on this day");
  assert.ok(![...(gh.repos.get(USAGE) || new Map()).keys()].some((p) => p.startsWith(`case_opens/${keys.keyHash(fresh)}/`)), "fixture: this key has no counter on any day");
  const reads = gh.getLog.length;
  // the handler, its key, its quota store and the store's getFile: nothing stubbed but fetch
  const res = makeRes();
  await H.handleCaseOpen(req("case-open", opening({ scope_digest: sha("fix 4, first open") }), { authorization: `Bearer ${fresh}` }), res, { now: NOW });
  assert.equal(res._status, 201, JSON.stringify(res._body));
  assert.ok(gh.getLog.slice(reads).includes(qpath), "the counter was read through the store, and was absent (a 404 read, null)");
  assert.deepEqual(gh.read(USAGE, qpath), { kind: "case-open-quota", v: 1, day, count: 1 });
  // the second open of the day reads the counter as present ({json, sha}) and counts on
  const again = makeRes();
  await H.handleCaseOpen(req("case-open", opening({ scope_digest: sha("fix 4, second open") }), { authorization: `Bearer ${fresh}` }), again, { now: NOW + 1000 });
  assert.equal(again._status, 201, JSON.stringify(again._body));
  assert.equal(gh.read(USAGE, qpath).count, 2);

  // takeOpenQuota itself, for a third key on a day it has never opened: no throw
  const other = "case-test-open-key-0009";
  const nextDay = NOW + 86400000;
  const taken = await H._internal.takeOpenQuota(other, nextDay);
  assert.deepEqual(taken, { ok: true, used: 1, day: "2026-10-11" });
  const second = await H._internal.takeOpenQuota(other, nextDay);
  assert.deepEqual(second, { ok: true, used: 2, day: "2026-10-11" });
  // the CAS rebuild hook is the other place a store read reaches judgeCounter:
  // the counter moves between the read and the write (the wrapper), or is
  // gone (null); either way the hook counts on from what it reads, no throw
  const opath = H._internal.openQuotaPath(other, "2026-10-11");
  for (const [name, move, want] of [
    ["moved to 5", () => gh.seed(USAGE, opath, { kind: "case-open-quota", v: 1, day: "2026-10-11", count: 5 }), 6],
    ["gone", () => gh._repoMap(USAGE).delete(opath), 1],
  ]) {
    const viaMock = global.fetch;
    let moved = false;
    global.fetch = async (url, o) => {
      if (!moved && o && o.method === "PUT" && String(url).endsWith(`/contents/${opath}`)) {
        moved = true;
        move();
      }
      return viaMock(url, o);
    };
    let got;
    try {
      got = await H._internal.takeOpenQuota(other, nextDay);
    } finally {
      global.fetch = viaMock;
    }
    assert.equal(moved, true, `${name}: fixture, the counter moved under the write`);
    assert.deepEqual(got, { ok: true, used: want, day: "2026-10-11" }, name);
    assert.equal(gh.read(USAGE, opath).count, want, name);
  }
  // MUST-FAIL ARM: the read path really does hand judgeCounter both shapes the
  // review named, null for the absent counter and the {json, sha} wrapper for
  // the present one, and judgeCounter reads both without a throw.
  const q = store.forTarget({ repo: keys.USAGE_REPO, branch: keys.USAGE_BRANCH, tokenEnv: "GITHUB_PIN_TOKEN", ua: "test" });
  const absent = await q.getFile(H._internal.openQuotaPath(other, "2026-10-12"));
  const present = await q.getFile(H._internal.openQuotaPath(other, "2026-10-11"));
  assert.equal(absent, null);
  assert.deepEqual(Object.keys(present).sort(), ["json", "sha"]);
  const verdict = require("../lib/_verdict.js");
  const opts = { what: "case open quota", integer: true };
  assert.equal(verdict.counterValue(verdict.judgeCounter(absent, "count", opts), "case open quota"), 0);
  assert.equal(verdict.counterValue(verdict.judgeCounter(present, "count", opts), "case open quota"), gh.read(USAGE, opath).count);
  // and what WOULD throw is a read that was never done (undefined), which no path here passes
  assert.throws(() => verdict.judgeCounter(undefined, "count", opts), verdict.VerdictRequiredError);
});

// =============================================================================
// FIX 5: the conflict-observation count carries partial
// =============================================================================

test("FIX 5: the conflict-observation count carries partial when the tree read was truncated, on the page and in the JSON, the way the case row does; whole it is false, uncounted it is null; the verdict is unchanged", async (t) => {
  const { gatherStatusData } = require("../lib/_status_data.js");
  const statusHandler = require("../api/status.js");
  // 2c's healthy board: a reachable store, one current namespace, today's anchor
  const realReachable = store.repoReachable;
  store.repoReachable = async () => true;
  t.after(() => {
    store.repoReachable = realReachable;
  });
  const now = Date.now();
  gh.seed(PINS, "pins/acme-prod/latest.json", { namespace: "acme-prod", rows: 40, chain: "cafebabe", seq: 1, pinned_at: new Date(now - 60000).toISOString(),
    cadence_hours: 24, next_pin_due_by: new Date(now + 3600e3).toISOString() });
  gh._repoMap(PINS).set(`anchors/${new Date(now).toISOString().slice(0, 10)}-head.txt`, { content: `${"a".repeat(40)} ${new Date(now - 3600e3).toISOString()}\n`, sha: "f".repeat(40) });
  for (const at of ["2026-10-09T08-00-00Z", "2026-10-10T08-00-00Z"]) {
    gh.seed(PINS, `observations/${at}.json`, { observed_at: at, claimed: { namespace: "acme-prod", rows: 40, chain: "deadbeef" }, accepted_head: { chain: "cafebabe", seq: 1 }, verdict: "head-conflict" });
  }
  const page = async () => {
    const res = makeRes();
    await statusHandler(makeReq({ method: "GET", headers: { "x-forwarded-for": freshIp() } }), res);
    return String(res._body);
  };
  const json = async () => {
    const res = makeRes();
    await statusHandler(makeReq({ method: "GET", query: { format: "json" }, headers: { "x-forwarded-for": freshIp() } }), res);
    return parsed(res);
  };
  const OBS_PARTIAL = /<strong>Partial\.<\/strong> The repository tree came back truncated on this read, so this count may be short\. It is not a full count\./;

  // whole
  const d = await gatherStatusData();
  assert.equal(d.obsCount, 2);
  assert.equal(d.obsPartial, false);
  assert.equal(d.caseAnchors.partial, false);
  assert.ok(!OBS_PARTIAL.test(await page()));
  const jw = await json();
  assert.equal(jw.conflict_observations.count, 2);
  assert.equal(jw.conflict_observations.partial, false);

  // truncated: the same count, now marked partial beside the case row's flag
  gh.treeTruncated = true;
  const dp = await gatherStatusData();
  assert.equal(dp.obsCount, 2);
  assert.equal(dp.obsPartial, true);
  assert.equal(dp.caseAnchors.partial, true, "the case row, read from the same tree, says so too");
  assert.equal(dp.overallOk, d.overallOk, "the flag feeds no verdict, like the case row's");
  assert.equal(dp.indeterminate, d.indeterminate);
  const hp = await page();
  assert.match(hp, OBS_PARTIAL);
  assert.ok(hp.indexOf("<h2>Conflict observations</h2>") < hp.search(OBS_PARTIAL), "said in the conflict panel");
  const jp = await json();
  assert.equal(jp.conflict_observations.count, 2);
  assert.equal(jp.conflict_observations.partial, true);
  assert.match(jp.conflict_observations.note, /^partial: the repository tree came back truncated/);
  assert.equal(jp.case_anchors.partial, true);
  // MUST-FAIL ARM: the count alone is the same number truncated or whole, so
  // without the flag a truncated read printed exactly like a whole one
  assert.equal(dp.obsCount, d.obsCount);

  // uncounted: no count, so no partial either (null, never false)
  gh.treeTruncated = false;
  gh.treeStatus = 502;
  const du = await gatherStatusData();
  assert.equal(du.obsCount, null);
  assert.equal(du.obsPartial, null);
  assert.equal((await json()).conflict_observations.partial, null);
  gh.treeStatus = 200;
});
