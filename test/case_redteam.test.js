// test/case_redteam.test.js — two outside red-team reviews of the whole case
// protocol at 858b2c3 (GPT-5.6, then Gemini 3.1 Pro), each concrete claim
// held to one planted test. Every claim is treated as unverified. A test
// asserts what the claim says does NOT happen:
//   - the real code passes it: the claim is REFUTED, and the test stays;
//   - the real code fails it: the claim is real (CONFIRMED). Nothing is
//     fixed here; the test carries the runner's `todo` option, so the suite
//     stays green, and its name quotes the claim. The todo text names the
//     assertion that fails.
// One claim says the code has NO defect (GPT-5.6 §4, a cross-key quota
// burn): its test asserts that, and passes.
// When this file was written no code under test was changed. Every store is
// the in-memory mock.
//
// FIXED SINCE, each in its own commit, its test's `todo` removed and its
// named assertion kept, with tests of the fix beside it:
//   - GPT-5.6 §2A, a one-key bilateral case: red-team fix A, ONE KEY PER
//     ROLE (lib/_case.js). Registration is signed by a registration key, the
//     two roles take two distinct key ids (409 same_key_both_roles), and a
//     case whose two commitments share one is single_party, never sealed.
//   - GPT-5.6 §1.4 and §3.3, three claims (a later revocation, a later
//     document listing a key, no document recorded): Design I. A sealed
//     case records signed_under {document_sha256, document_commit,
//     retrieved_at} and is held to the document it names, read at its
//     commit (lib/_case_seal.js THE SEALED CHECK); a later revocation is
//     signer_since_revoked, still sealed.
//   - GPT-5.6 §3.1, a verdict no comparison produced: red-team fix B, A
//     RECEIPT IS THE SERVICE'S (lib/_case_seal.js). A stored receipt holds
//     only when the service's reconcile signer signed it (receipt_unsigned
//     otherwise, and the page does not verify the record), and with no
//     reconcile signer nothing is compared (503 signer_unavailable).
//   - GPT-5.6 §3.2, no commit bound to a sealed case: Design J, THE PIN IS
//     THE SECOND PHASE (lib/_case_seal.js). The pin records case_commit, the
//     commit that wrote the sealed case file, and every reader reads the
//     case file at it (pin_commit_mismatch when it is another case).
//   - GPT-5.6 §5, no reference row storing its write commit: Design J, THE
//     ROW'S TWO WRITES (lib/_case_seal.js). The row's answer names
//     row_commit, and the case's next pin, written by the sealer's run,
//     lists the commits of the rows written since the pin before it.
//   - GPT-5.6 §3.4, anchored meaning only that latest.json exists: Design J,
//     THE ANCHOR WORDS (lib/_case_seal.js). A reader says pinned (the pin
//     holds the case's chain at the commit that wrote it, named), anchored
//     (a daily anchor record names a head of the pins repository that holds
//     the pin, and the record's own commit is named) or could_not_look.
//
// NOT TESTABLE HERE (no test, one line why):
//   - GPT-5.6 §1.2 and the reference row's note, "no code verifies that
//     daily anchor": the daily head anchor and its OpenTimestamps proof are
//     an outside job, not in this repository (since Design J a reader reads
//     the record and the pin at the head it names; the proof is not checked
//     here);
//   - GPT-5.6 §3.2 and Gemini §3, an operator backdating the service clock:
//     the clock is the deployment's; a test hands the handlers any time it
//     likes, which shows nothing about a live operator;
//   - GPT-5.6 §4, the tree "eventually ... truncated": the threshold is
//     GitHub's tree API's, on a live repository;
//   - GPT-5.6 §5's page and key-document sentences, as wording (their
//     function claims are tested: §1.4, §3.1, §3.4);
//   - Gemini §1, clock skew and processing delay at the deadline: needs a
//     live clock; each handler reads one clock, on arrival;
//   - Gemini §2, canonicalization divergence: names no input; the Python
//     byte fixtures of test/case_protocol.test.js (TEST 1, TEST 2) are the
//     check;
//   - Gemini §3, censorship and reordering by the operator: operator conduct
//     on a live deployment;
//   - Gemini §5, the strength of anchoring: a property of the outside anchor.
// Gemini 3.1 Pro declined to analyse the code and named no function or call
// sequence; its classes with a concrete reading here have a test below.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0021:case-test-,case-test-open-key-0022:case-test2-";
delete process.env.WITNESS_BATCH_SHADOW;
delete process.env.WITNESS_ADMIN_KEY;
delete process.env.WITNESS_CASE_OPERATOR_KEY;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const S = require("../lib/_case_seal.js");
const CP = require("../lib/_case_page.js");
const RECONCILE = require("../lib/_reconcile_http.js");
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const ratelimit = require("../lib/_ratelimit.js");
const stamp = require("../lib/_stamp.js");
const { canonicalBytes } = require("../lib/_check_record.js");
const REG = require("./helpers/case_registration.js");
const KD = require("./helpers/key_document.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const USAGE = process.env.GITHUB_USAGE_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z"); // open and register
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-10");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-10");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-10");
const OTHER_KEY = checkpoint.generateKey("arcaeon.io/case-test-unlisted/2026-10-10");
const SIGNED = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const keyIdOf = (k) => k.verifier.split("+").slice(0, 2).join("+");
const entry = (k, status = "active") => ({ key_id: keyIdOf(k), verifier: k.verifier, since: "2026-10-10", note: "a test key", status,
  ...(status === "revoked" ? { revoked_since: "2026-10-11" } : {}) });
const docWith = (...entries) => ({ ...S.PUBLISHED_KEYS, keys: entries });
// Design I: the document lists the reconcile key too, as a reconcile entry.
const KEYS_DOC = Object.freeze(docWith(entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_KEY = "case-test-open-key-0021";
const VICTIM_KEY = "case-test-open-key-0022";
const OPEN_AUTH = Object.freeze({ authorization: `Bearer ${OPEN_KEY}` });
const ATTACKER = Object.freeze({ side: "agent", label: "attacker-account" });
const HONEST = Object.freeze({ side: "tool", label: "honest-party-account" });
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0042", url: "https://second-operator.example/cases/0042" });

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
});
afterEach(() => {
  store._putRetry.sleep = realSleep;
  restore();
});

let ipSeq = 0;
function freshIp() {
  ipSeq += 1;
  return `10.73.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
}
function req(op, body, headers = {}, ip = freshIp()) {
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": ip, ...headers }, body });
}
function parsed(res) {
  return typeof res._body === "string" ? JSON.parse(res._body) : res._body;
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
async function open(over, { headers = OPEN_AUTH, ip, now = NOW } = {}) {
  const res = makeRes();
  await H.handleCaseOpen(req("case-open", opening(over), headers, ip), res, { now });
  return res;
}
async function openCase(over) {
  const o = await open(over);
  assert.equal(o._status, 201, JSON.stringify(o._body));
  return o._body.case_id;
}
function plantStamp(hash) {
  gh.seed(STAMPS, stamp.stampPath(hash), { kind: "file-stamp", v: 1, sha256: hash, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: "2026-10-10T07:45:00.123Z" });
}
function party(caseId, role, tape, salt = C.newSalt()) {
  const tape_sha256 = sha(tape);
  return { role, tape, tape_sha256, salt, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
}
// A registration, signed by `key` (the role's own test key by default: two
// roles, two key ids, red-team fix A).
async function commit(id, p, now = NOW, key = REG.KEYS[p.role]) {
  const res = makeRes();
  await H.handleCaseCommit(req("case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 }, key)), res, { now });
  return res;
}
async function register(id, p, key = REG.KEYS[p.role]) {
  plantStamp(p.commitment_sha256);
  const r = await commit(id, p, NOW, key);
  assert.equal(r._status, 201, JSON.stringify(r._body));
}
async function committedCase(over) {
  const id = await openCase(over);
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
async function reveal(body, { now = REVEAL_AT, env = SIGNED, keyDocument = KEYS_DOC } = {}) {
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", body), res, { now, env: KD.deployed(gh, env, keyDocument), keyDocument });
  return { status: res._status, body: parsed(res) };
}
async function sealedCase(over, { pinFails = false } = {}) {
  const c = await committedCase(over);
  if (pinFails) gh.forceFailure(PINS, S.pinPaths(c.id).seq, 1, 502);
  const r = await reveal(revealBody(c.id, c.a, c.b));
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.pin, pinFails ? "commit_unrecorded" : "pinned");
  return c;
}
const proofOf = (id, p) => ({ case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt: p.salt });
async function withdraw(body, { now = REVEAL_AT, env = SIGNED } = {}) {
  const res = makeRes();
  await H.handleCaseWithdraw(req("case-withdraw", body), res, { now, env, keyDocument: KEYS_DOC });
  return { status: res._status, body: parsed(res) };
}
async function reference(body, { now = REVEAL_AT + 3600000 } = {}) {
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", body), res, { now, env: SIGNED, keyDocument: KEYS_DOC });
  return { status: res._status, body: parsed(res) };
}
async function casePage(id, { now = REVEAL_AT + 3600000, keyDocument = KEYS_DOC } = {}) {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": freshIp() } }), res, { now, keyDocument });
  return { status: res._status, html: String(res._body) };
}
const storedCase = (id) => gh.read(PINS, C.casePath(id));
const referenceFiles = (id) => [...gh.repos.get(PINS).keys()].filter((p) => p.startsWith(`${C.referencesDir(id)}/`)).sort();
// Run `during` when the first request matching `match` goes out, then let that request through.
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

// =============================================================================
// GPT-5.6, section 1: cross-item holes
// =============================================================================

// §1.1: case-commit reads OPEN; the withdrawal lands while the commit reads
// its stamp (after its root read, before its registration write).
async function commitAcrossWithdrawal() {
  const id = await openCase({ scope_digest: sha("1.1") });
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const r = await during(
    (url, method) => method === "GET" && url.includes(`/repos/${STAMPS}/contents/${stamp.stampPath(b.commitment_sha256)}`),
    () => withdraw(proofOf(id, a), { now: NOW + 2000 }),
    () => commit(id, b, NOW + 1000),
  );
  assert.equal(r.fired, true, "the withdrawal ran inside the commit");
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body));
  assert.equal(storedCase(id).status, "WITHDRAWN");
  assert.equal(r.out._status, 409, JSON.stringify(r.out._body));
  assert.equal(r.out._body.error_code, "case_withdrawn");
  return { id, res: r.out };
}

test('GPT-5.6 §1.1 / §6.2: "A commitment can land after withdrawal ... project() then rereads, sees WITHDRAWN, and returns case_withdrawn, but the registration file remains written"',
  { todo: "CONFIRMED: commit_b.json is present after the withdrawal (the assertion 'no registration file is written after the case was withdrawn' fails)" }, async () => {
    const { id } = await commitAcrossWithdrawal();
    assert.equal(gh.has(PINS, C.registrationPath(id, "b")), false, "no registration file is written after the case was withdrawn");
  });

test('GPT-5.6 §1.1: "It also creates a public registration dated after a redacted withdrawal": the file\'s registered_at is the commit\'s arrival, before withdrawal.at (only its pins-repository commit comes after)', async () => {
  const { id } = await commitAcrossWithdrawal();
  const regB = gh.read(PINS, C.registrationPath(id, "b"));
  const w = storedCase(id).withdrawal;
  assert.ok(Date.parse(regB.registered_at) < Date.parse(w.at), `${regB.registered_at} vs ${w.at}`);
  // the order of the writes themselves: the withdrawal's root write, then b's file
  const order = gh.putLog.map((x) => x.path);
  assert.ok(order.indexOf(C.registrationPath(id, "b")) > order.indexOf(C.casePath(id)), "the file is written after the redacted root");
});

test('GPT-5.6 §1.2 (and Gemini §1, intermediate states): "A reference may be appended before the case anchor exists"',
  { todo: "CONFIRMED: a role's reference to a sealed case whose pin is pending is 201 (the assertion 'a reference row is appended only once the case is anchored' fails)" }, async () => {
    const { id, a } = await sealedCase({ scope_digest: sha("1.2") }, { pinFails: true });
    assert.equal((await S.anchorState(id, S.caseChain(storedCase(id)))).pin, "commit_unrecorded", "fixture: not pinned");
    const r = await reference({ ...proofOf(id, a), cross_reference: XREF });
    assert.notEqual(r.status, 201, "a reference row is appended only once the case is anchored");
    assert.deepEqual(referenceFiles(id), []);
  });

test('GPT-5.6 §1.3: "If the reveal subsequently fails its root write after comparison, the system has run the comparison but leaves only a normal COMMITTED case" (the sealer, run mid-reveal, reports it as not_sealed)',
  { todo: "CONFIRMED: after the comparison ran and the root write failed, the case record is byte-identical to the COMMITTED case before the reveal (the assertion 'a comparison that ran leaves a trace in the case record' fails)" }, async (t) => {
    const { id, a, b } = await committedCase({ scope_digest: sha("1.3") });
    const before = storedCase(id);
    const compare = t.mock.method(RECONCILE, "compare");
    gh.forceFailure(PINS, C.casePath(id), 1, 502);
    const r = await during(
      (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(id)}`),
      () => S.anchorPending({ now: REVEAL_AT }),
      () => reveal(revealBody(id, a, b)),
    );
    assert.equal(r.fired, true);
    assert.equal(r.inner.not_sealed, 1, "the sealer, mid-reveal, saw a COMMITTED case");
    assert.equal(r.out.status, 503, JSON.stringify(r.out.body).slice(0, 300));
    assert.equal(r.out.body.error_code, "case_seal_failed");
    assert.equal(compare.mock.callCount(), 1, "the comparison ran");
    assert.notDeepEqual(storedCase(id), before, "a comparison that ran leaves a trace in the case record");
  });

test('GPT-5.6 §1.4 / §3.3 / §6.4: "A later edit changing a key from active or retired to revoked makes old sealed cases fail sealedRecordReason() and display SEALED RECORD DOES NOT VERIFY"', async () => {
  // FIXED (Design I, lib/_case_seal.js THE SEALED CHECK): a sealed case is
  // held to the document it names; a later revocation makes it
  // signer_since_revoked, still sealed, with a dated banner.
  const { id } = await sealedCase({ scope_digest: sha("1.4 revoke") });
  const rec = storedCase(id);
  assert.equal(typeof rec.sig, "string", "fixture: signed");
  assert.equal((await S.sealedRecordReason(rec, KEYS_DOC)).code, "valid_under_document", "verifies under the document it was sealed under");
  assert.equal((await S.sealedRecordReason(rec, docWith(entry(CASE_KEY, "retired"), KD.reconcileEntry(RECEIPT_KEY)))).code, "valid_under_document",
    "control: a retired key's seals stay trusted");
  const revoked = docWith(entry(CASE_KEY, "revoked"), KD.reconcileEntry(RECEIPT_KEY));
  const page = await casePage(id, { keyDocument: revoked });
  const answer = await S.sealedRecordReason(rec, revoked);
  assert.deepEqual({ holds: S.sealHolds(answer), doesNotVerify: page.html.includes("SEALED RECORD DOES NOT VERIFY") },
    { holds: true, doesNotVerify: false },
    "a case sealed while its key was active still verifies, and its page shows its verdict, after a later document revokes the key");
  assert.equal(answer.code, "signer_since_revoked");
  assert.match(page.html, /<h2>The verdict<\/h2>/);
  assert.match(page.html, /Revoked since this case was sealed/);
});

test('GPT-5.6 §1.4: "Conversely, a later document can introduce a verifier that makes a formerly unverifiable stored signature appear valid"', async () => {
  // FIXED (Design I): the named document alone decides whether a stored
  // signature verifies; a later document never makes it verify.
  const { id } = await sealedCase({ scope_digest: sha("1.4 later listing") });
  const rec = storedCase(id);
  const other = checkpoint.parseSignerKey(OTHER_KEY.signer);
  const resigned = S.signRecord({ ...rec, signed_by: null, sig: null, sig_reason: null }, { ok: true, keyId: keyIdOf(OTHER_KEY), privateKey: other.privateKey }, "unused");
  assert.deepEqual(C.validateCase(resigned), { ok: true }, "fixture: schema-valid");
  const earlier = await S.sealedRecordReason(resigned, KEYS_DOC);
  assert.deepEqual(earlier, { code: "case_signature_invalid", reason: "signer_unpublished" });
  const later = await S.sealedRecordReason(resigned, docWith(entry(CASE_KEY), entry(OTHER_KEY), KD.reconcileEntry(RECEIPT_KEY)));
  assert.deepEqual(later, earlier, "the verdict on stored bytes does not change with the document alone");
});

test('GPT-5.6 §1.4 / §3.3: "No sealed case records the key-document hash, Git commit, or retrieval time"', async () => {
  // FIXED (Design I, step 1): signed_under, inside the signed bytes.
  const { id } = await sealedCase({ scope_digest: sha("1.4 binding") });
  const k = storedCase(id);
  const text = JSON.stringify(k);
  const digests = [sha(JSON.stringify(KEYS_DOC)), sha(JSON.stringify(KEYS_DOC, null, 2)), sha(canonicalBytes(KEYS_DOC))];
  assert.ok(digests.some((d) => text.includes(d)), "the sealed case names the key document it was signed under");
  assert.equal(k.signed_under.document_sha256, sha(canonicalBytes(KEYS_DOC)));
  assert.equal(k.signed_under.document_commit, KD.commitOf(KEYS_DOC), "and the Git commit");
  assert.equal(k.signed_under.retrieved_at, C.utcSeconds(REVEAL_AT), "and the retrieval time (the service clock)");
});

test('GPT-5.6 §1.5 / §4 / §6.5 (and Gemini §4, unauthenticated consumption): "admit() runs ratelimit.check(req) before openKey() ... The victim is blocked before their valid bearer key is even checked"', async () => {
  const ip = "10.74.0.1";
  let n = 0;
  let last;
  do {
    last = await open({ scope_digest: sha(`junk ${n}`) }, { headers: {}, ip });
    n += 1;
  } while (last._status === 401 && n <= ratelimit.LIMIT + 5);
  assert.equal(last._status, 429, "the address's budget is spent by requests that carry no key");
  assert.ok(n > 1);
  const victim = await open({ scope_digest: sha("the victim's real opening") }, { ip });
  assert.equal(victim._status, 201, `an authenticated open is not refused by the budget unauthenticated requests spent: ${JSON.stringify(victim._body)}`);
});

// =============================================================================
// GPT-5.6, section 2: what an adversarial role can do
// =============================================================================

test('GPT-5.6 §2A: "Create a seemingly bilateral case using an honest party\'s label": one key holder opens, registers both roles and reveals', async () => {
  // FIXED (red-team fix A, lib/_case.js ONE KEY PER ROLE): role b's
  // registration under the key id role a registered with is refused 409
  // same_key_both_roles, so the case never reaches COMMITTED and the reveal
  // seals nothing.
  const id = await openCase({ scope_digest: sha("2A"), party_a: ATTACKER, party_b: HONEST });
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  const one = REG.KEYS.a; // the one key holder's key
  await register(id, a, one);
  plantStamp(b.commitment_sha256);
  const second = await commit(id, b, NOW, one);
  assert.equal(second._status, 409, JSON.stringify(second._body));
  assert.equal(second._body.error_code, "same_key_both_roles");
  assert.equal(gh.has(PINS, C.registrationPath(id, "b")), false, "nothing was registered for role b");
  assert.equal(storedCase(id).status, "OPEN");
  const r = await reveal(revealBody(id, a, b));
  assert.equal(r.status, 409, JSON.stringify(r.body).slice(0, 200));
  const page = await casePage(id);
  assert.equal(page.status, 200);
  assert.ok(page.html.includes(CP.LABELS_SENTENCE), "the page carries the labels sentence");
  const shown = page.html.includes("honest-party-account") && page.html.includes("<h2>The verdict</h2>");
  assert.equal(shown, false, "a case one requester opened, registered and revealed alone is not shown as a sealed verdict naming another party");
});

// -----------------------------------------------------------------------------
// Red-team fix A: ONE KEY PER ROLE (lib/_case.js). The two roles of a case are
// registered by two distinct key ids; a case whose two commitments share one
// never reaches sealed.
// -----------------------------------------------------------------------------

test("FIX A: the refusal is symmetric and writes nothing: role a under the key id role b registered with is 409 same_key_both_roles too", async () => {
  const id = await openCase({ scope_digest: sha("A sym"), party_a: ATTACKER, party_b: HONEST });
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, b, REG.KEYS.b);
  plantStamp(a.commitment_sha256);
  const writes = gh.putLog.length;
  const r = await commit(id, a, NOW, REG.KEYS.b);
  assert.equal(r._status, 409, JSON.stringify(r._body));
  assert.equal(r._body.error_code, "same_key_both_roles");
  assert.equal(r._body.role, "a");
  assert.equal(r._body.key_id, REG.keyIdOf(REG.KEYS.b));
  assert.equal(gh.putLog.length, writes, "nothing written");
  // the same role under its own key registers
  const ok = await commit(id, a, NOW, REG.KEYS.a);
  assert.equal(ok._status, 201, JSON.stringify(ok._body));
  assert.equal(ok._body.status, "COMMITTED");
});

test("FIX A: two registrations under two distinct key ids still seal, and the page shows the verdict naming both parties", async () => {
  const { id } = await sealedCase({ scope_digest: sha("A two keys"), party_a: ATTACKER, party_b: HONEST });
  const k = storedCase(id);
  assert.equal(k.status, "VERDICT");
  assert.equal(k.commitments.a.key_id, REG.keyIdOf(REG.KEYS.a));
  assert.equal(k.commitments.b.key_id, REG.keyIdOf(REG.KEYS.b));
  assert.equal(C.singleParty(k), false);
  assert.equal((await S.sealedRecordReason(k, KEYS_DOC)).code, "valid_under_document");
  for (const r of C.ROLES) {
    const file = gh.read(PINS, C.registrationPath(id, r));
    assert.equal(file.key_id, REG.keyIdOf(REG.KEYS[r]));
    assert.equal(file.verifier, REG.KEYS[r].verifier);
    assert.deepEqual(C.validateRegistrationRecord(file), { ok: true });
  }
  const page = await casePage(id);
  assert.match(page.html, /<h2>The verdict<\/h2>/);
  assert.ok(page.html.includes("honest-party-account") && page.html.includes("attacker-account"));
  const run = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: KEYS_DOC });
  assert.deepEqual(run.already, [id]);
  assert.deepEqual(run.single_party, []);
});

// Two registrations under one key that race past the check: role b's
// request reads both registration files (role a has none yet), and while it
// reads its stamp, role a registers under the same key. Each file is first
// write wins, so both stand, and the case projects both: COMMITTED, with one
// key id in both commitments.
async function racedSingleParty(scope) {
  const id = await openCase({ scope_digest: sha(scope), party_a: ATTACKER, party_b: HONEST });
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  const one = REG.KEYS.a;
  plantStamp(a.commitment_sha256);
  plantStamp(b.commitment_sha256);
  const r = await during(
    (url, method) => method === "GET" && url.includes(`/repos/${STAMPS}/contents/${stamp.stampPath(b.commitment_sha256)}`),
    () => commit(id, a, NOW + 1000, one),
    () => commit(id, b, NOW + 2000, one),
  );
  assert.equal(r.fired, true, "role a registered inside role b's request");
  assert.equal(r.inner._status, 201, JSON.stringify(r.inner._body));
  assert.equal(r.out._status, 201, JSON.stringify(r.out._body));
  const k = storedCase(id);
  assert.equal(k.status, "COMMITTED");
  assert.equal(k.commitments.a.key_id, k.commitments.b.key_id, "fixture: one key id in both commitments");
  assert.equal(C.singleParty(k), true);
  return { id, a, b };
}

test("FIX A: a case whose two commitments share a key id never reaches sealed: the joint reveal is 409 single_party and writes nothing", async () => {
  const { id, a, b } = await racedSingleParty("A raced reveal");
  const before = storedCase(id);
  const writes = gh.putLog.length;
  const r = await reveal(revealBody(id, a, b));
  assert.equal(r.status, 409, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.error_code, "single_party");
  assert.equal(r.body.key_id, before.commitments.a.key_id);
  assert.equal(r.body.verdict, undefined, "no verdict");
  assert.equal(gh.putLog.length, writes, "nothing written");
  assert.deepEqual(storedCase(id), before);
});

test("FIX A: the sealer reports such a case not_sealed: single_party, and pins nothing", async () => {
  const { id } = await racedSingleParty("A raced sealer");
  const one = await S.anchorCase(id, { now: REVEAL_AT, keyDocument: KEYS_DOC });
  assert.deepEqual(one, { ok: false, code: "not_sealed", status: "COMMITTED", reason: "single_party" });
  const run = await S.anchorPending({ now: REVEAL_AT, keyDocument: KEYS_DOC });
  assert.equal(run.not_sealed, 1);
  assert.deepEqual(run.single_party, [id]);
  assert.deepEqual(run.newly_pinned, []);
  assert.equal(gh.has(PINS, S.pinPaths(id).latest), false);
});

test("FIX A: the case page shows such a case as single_party and names no second label", async () => {
  const { id } = await racedSingleParty("A raced page");
  const page = await casePage(id);
  assert.equal(page.status, 200);
  assert.match(page.html, /<h1>Case: SINGLE PARTY<\/h1>/);
  assert.ok(page.html.includes("single_party"));
  assert.ok(page.html.includes(REG.keyIdOf(REG.KEYS.a)), "the page names the one key id");
  assert.equal(page.html.includes("honest-party-account"), false, "no second label");
  assert.equal(page.html.includes("attacker-account"), false, "no label at all: the labels are the opener's text");
  assert.equal(page.html.includes("<h2>The verdict</h2>"), false);
  assert.equal(page.html.includes("<h2>Parties</h2>"), false);
});

// DECISION ON THE A + B REPORT: two key ids prove two keys, not two holders,
// so the page says "two keys" and never "two parties", on the single-party
// page and on a sealed one.
test("A + B DECISION: the page says two keys, never two parties", async () => {
  const single = await racedSingleParty("A page in words");
  const one = await casePage(single.id);
  assert.match(one.html, /not shown as a case between two keys/);
  assert.equal(/two parties/i.test(one.html), false, "the single-party page");
  const sealed = await sealedCase({ scope_digest: sha("A sealed page in words") });
  const two = await casePage(sealed.id);
  assert.match(two.html, /<h2>The verdict<\/h2>/, "fixture: a sealed page");
  assert.equal(/two parties/i.test(two.html), false, "the sealed page");
});

test("FIX A: a VERDICT whose two commitments share a key id (signed by the case key) is still not sealed: page, sealed check, sealer and reference all refuse it", async () => {
  const { id, a } = await sealedCase({ scope_digest: sha("A forged verdict"), party_a: ATTACKER, party_b: HONEST }, { pinFails: true });
  const k = storedCase(id);
  const forged = S.signCase({ ...k, commitments: { ...k.commitments, b: { ...k.commitments.b, key_id: k.commitments.a.key_id } } },
    S.loadCaseSigner(SIGNED, { keyDocument: KEYS_DOC }));
  assert.deepEqual(C.validateCase(forged), { ok: true }, "fixture: the schema reads it");
  assert.notEqual(forged.sig, null, "fixture: signed by the published case key");
  gh.seed(PINS, C.casePath(id), forged);
  assert.deepEqual(await S.sealedRecordReason(forged, KEYS_DOC), { code: "single_party", reason: "same_key_both_roles" });
  const page = await casePage(id);
  assert.match(page.html, /<h1>Case: SINGLE PARTY<\/h1>/);
  assert.equal(page.html.includes("honest-party-account"), false);
  assert.equal(page.html.includes("<h2>The verdict</h2>"), false);
  const one = await S.anchorCase(id, { now: REVEAL_AT + 60000, keyDocument: KEYS_DOC });
  assert.deepEqual(one, { ok: false, code: "not_sealed", status: "VERDICT", reason: "single_party" });
  assert.equal(gh.has(PINS, S.pinPaths(id).latest), false, "no pin");
  const ref = await reference({ ...proofOf(id, a), cross_reference: XREF });
  assert.equal(ref.status, 409, JSON.stringify(ref.body));
  assert.equal(ref.body.error_code, "single_party");
  assert.deepEqual(referenceFiles(id), []);
});

test("FIX A: a registration proves its key: a signature the verifier does not confirm is 403 registration_unauthorized, and a body without a key is 400", async () => {
  const id = await openCase({ scope_digest: sha("A proof") });
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const fields = { case_id: id, role: "a", commitment_sha256: a.commitment_sha256 };
  const send = async (body) => {
    const res = makeRes();
    await H.handleCaseCommit(req("case-commit", body), res, { now: NOW });
    return res;
  };
  const writes = gh.putLog.length;
  // signed by key b, presented under key a's verifier
  const stolen = await send({ ...REG.signedBody(fields, REG.KEYS.b), verifier: REG.KEYS.a.verifier });
  assert.equal(stolen._status, 403, JSON.stringify(stolen._body));
  assert.equal(stolen._body.error_code, "registration_unauthorized");
  // a signature over another role's fields
  const otherRole = await send({ ...fields, verifier: REG.KEYS.a.verifier, sig: REG.signedBody({ ...fields, role: "b" }, REG.KEYS.a).sig });
  assert.equal(otherRole._status, 403);
  for (const drop of ["verifier", "sig"]) {
    const body = REG.signedBody(fields);
    delete body[drop];
    const r = await send(body);
    assert.equal(r._status, 400, drop);
    assert.equal(r._body.error_code, "missing_field", drop);
  }
  assert.equal(gh.putLog.length, writes, "nothing written");
  assert.equal((await send(REG.signedBody(fields)))._status, 201);
});

test("FIX A: a registration under another key for a role already registered is role_already_committed, never a replay", async () => {
  const id = await openCase({ scope_digest: sha("A replay key") });
  const a = party(id, "a", AGENT_TAPE);
  await register(id, a, REG.KEYS.a);
  const other = checkpoint.generateKey("party-c.example/case-registration");
  const r = await commit(id, a, NOW, other);
  assert.equal(r._status, 409, JSON.stringify(r._body));
  assert.equal(r._body.error_code, "role_already_committed");
  const same = await commit(id, a, NOW, REG.KEYS.a);
  assert.equal(same._status, 200, "the same registration under the same key is the replay");
  assert.equal(same._body.existing, true);
});

test('GPT-5.6 §2B: "Before either submits the joint reveal, B sends case-withdraw ... A\'s reveal returns 409 case_withdrawn"',
  { todo: "CONFIRMED: after B's withdrawal, A's joint reveal (with both reveals, exchanged out of band) is 409 case_withdrawn (the assertion 'A's reveal still seals' fails)" }, async () => {
    const { id, a, b } = await committedCase({ scope_digest: sha("2B") });
    const w = await withdraw(proofOf(id, b));
    assert.equal(w.status, 201, JSON.stringify(w.body));
    const r = await reveal(revealBody(id, a, b), { now: REVEAL_AT + 1000 });
    assert.equal(r.status, 201, `A's reveal still seals: ${JSON.stringify(r.body).slice(0, 200)}`);
  });

test('GPT-5.6 §2B: "The public root is redacted. It does not identify ... which side prevented the comparison": it names the withdrawing role (by_role), and the page says so', async () => {
  const { id, b } = await committedCase({ scope_digest: sha("2B side") });
  assert.equal((await withdraw(proofOf(id, b))).status, 201);
  assert.equal(storedCase(id).withdrawal.by_role, "b");
  const page = await casePage(id);
  assert.match(page.html, /by role b, at /);
});

test('GPT-5.6 §2B: "It does not identify the parties, commitments"',
  { todo: "CONFIRMED: the redacted root carries no label and no commitment (design: WITHDRAWN_FIELDS); the assertion 'the redacted root identifies the parties and their commitments' fails" }, async () => {
    const { id, a, b } = await committedCase({ scope_digest: sha("2B parties") });
    assert.equal((await withdraw(proofOf(id, b))).status, 201);
    const text = JSON.stringify(storedCase(id));
    assert.ok(text.includes("agent-operator@example.com") && text.includes(a.commitment_sha256) && text.includes(b.commitment_sha256),
      "the redacted root identifies the parties and their commitments");
  });

test('GPT-5.6 §2C / §6.1 (and Gemini §4, storage bloat): "Either can repeatedly call case-reference as role:a or role:b ... There is no per-case, per-role, per-key, or lifetime addendum quota"', async () => {
  const { id, a } = await sealedCase({ scope_digest: sha("2C") });
  let accepted = 0;
  for (let i = 0; i < 100; i += 1) {
    const r = await reference({ ...proofOf(id, a), cross_reference: { ...XREF, reference: `flood-${i}` } });
    if (r.status !== 201) break;
    accepted += 1;
  }
  assert.ok(accepted < 100, `a role cannot append a hundred reference rows to one case (${accepted} accepted)`);
});

// =============================================================================
// GPT-5.6, section 3: silent operator actions
// =============================================================================

test('GPT-5.6 §3.1 / §5 / §6.3: "Fabricate a case verdict without actually running reconcile ... If the reconcile receipt is unsigned, checkStoredReceipt() accepts it" (and the page says "The service ran its recorded comparison once")', async (t) => {
  // FIXED (red-team fix B, lib/_case_seal.js A RECEIPT IS THE SERVICE'S): a
  // stored receipt not signed by the service's reconcile signer is
  // receipt_unsigned, and the page shows the record as not verifying.
  const { id, a, b } = await committedCase({ scope_digest: sha("3.1") });
  const compare = t.mock.method(RECONCILE, "compare");
  const result = { verdict: "MATCHED", at: null, side: null, matched: 999, counts: { agent: 999, tool: 999 }, findings: [], could_not_look: [], exit_code: 0 };
  const receipt = receipts.signReceipt(receipts.buildReceipt({ bytesA: AGENT_TAPE, bytesB: TOOL_TAPE, result, now: REVEAL_AT }), { ok: false, reason: "no signer" });
  const st = S.storableReceipt(receipt);
  assert.equal(st.ok, true);
  const fabricated = S.sealCase(storedCase(id), {
    reveals: { a: { tape_sha256: a.tape_sha256, salt: a.salt }, b: { tape_sha256: b.tape_sha256, salt: b.salt } },
    receipt: st.receipt, crossReference: null, revealedAt: C.utcSeconds(REVEAL_AT), signedUnder: KD.signedUnder(gh, KEYS_DOC, C.utcSeconds(REVEAL_AT)),
  }, { ok: false, code: "case_key_unset", reason: "no case signing key is configured" });
  gh.seed(PINS, C.casePath(id), fabricated);
  const page = await casePage(id);
  assert.equal(compare.mock.callCount(), 0, "reconcile never ran");
  assert.match(page.html, /<h1>Case: SEALED RECORD DOES NOT VERIFY<\/h1>/);
  assert.ok(page.html.includes("receipt_unsigned"));
  assert.doesNotMatch(page.html, /<span class="word pass">MATCHED<\/span>/);
  assert.doesNotMatch(page.html, /The service ran its recorded comparison once/);
  assert.equal(S.checkStoredReceipt(fabricated), "receipt_unsigned");
  assert.deepEqual(await S.sealedRecordReason(fabricated, KEYS_DOC), { code: "receipt_unsigned", reason: "unsigned" });
  // the named assertion, for the async check (Design I): it does not hold
  assert.equal(S.sealHolds(await S.sealedRecordReason(fabricated, KEYS_DOC)), false, "a verdict no comparison produced does not pass the sealed check");
});

// -----------------------------------------------------------------------------
// Red-team fix B: A RECEIPT IS THE SERVICE'S (lib/_case_seal.js). A stored
// receipt holds only with a signature by the service's reconcile signer over
// its canonical bytes; with no reconcile signer, the service compares nothing.
// -----------------------------------------------------------------------------

const WRONG_RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-10");

test("FIX B: op=reconcile with WITNESS_RECONCILE_SIGNER_KEY absent or unreadable is 503 signer_unavailable: no receipt, no verdict, and the comparison never runs", async (t) => {
  const T = require("../lib/_reconcile_tapes.js");
  const port = t.mock.method(T, "reconcileTapes");
  const body = { agent_tape_b64: AGENT_TAPE.toString("base64"), tool_tape_b64: TOOL_TAPE.toString("base64") };
  for (const env of [{}, { [receipts.SIGNER_ENV]: "" }, { [receipts.SIGNER_ENV]: "PRIVATE+KEY+not-a-key" }, { [receipts.VERIFIER_ENV]: RECEIPT_KEY.verifier }]) {
    const res = makeRes();
    await RECONCILE.handleReconcile(req("reconcile", body), res, { env });
    const got = parsed(res);
    assert.equal(res._status, 503, JSON.stringify(got));
    assert.equal(got.error_code, "signer_unavailable");
    assert.equal(got.receipt, undefined, "no receipt");
    assert.equal(got.verdict, undefined, "no verdict");
  }
  assert.equal(port.mock.callCount(), 0, "nothing was compared");
  const ok = makeRes();
  await RECONCILE.handleReconcile(req("reconcile", body), ok, { env: { [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }, keyDocument: KEYS_DOC });
  const signed = parsed(ok);
  assert.equal(ok._status, 200);
  assert.equal(signed.receipt.signer.verifier, RECEIPT_KEY.verifier, "control: with the signer, a signed receipt");
  assert.equal(port.mock.callCount(), 1);
});

test("FIX B: the joint reveal with no reconcile signer is 503 signer_unavailable; nothing is compared and nothing is sealed", async () => {
  const { id, a, b } = await committedCase({ scope_digest: sha("B reveal") });
  const before = storedCase(id);
  const writes = gh.putLog.length;
  const { [receipts.SIGNER_ENV]: _gone, ...noSigner } = SIGNED; // eslint-disable-line no-unused-vars
  const r = await reveal(revealBody(id, a, b), { env: noSigner });
  assert.equal(r.status, 503, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.error_code, "signer_unavailable");
  assert.equal(r.body.verdict, undefined);
  assert.equal(gh.putLog.length, writes, "nothing written");
  assert.deepEqual(storedCase(id), before);
  // control: the same reveal with the signer seals
  assert.equal((await reveal(revealBody(id, a, b))).status, 201);
});

// A case sealed exactly as the service seals one, except that its receipt
// was signed by another reconcile key: the comparison ran, the case key
// signed the seal, only the receipt's signer is not the service's.
async function wronglySignedCase(scope, named = KEYS_DOC) {
  const { id, a, b } = await committedCase({ scope_digest: sha(scope) });
  // computed under the wrong key's own document, which publishes it
  const compared = RECONCILE.compare(AGENT_TAPE, TOOL_TAPE, { env: { [receipts.SIGNER_ENV]: WRONG_RECEIPT_KEY.signer }, now: REVEAL_AT,
    keyDocument: docWith(entry(CASE_KEY), KD.reconcileEntry(WRONG_RECEIPT_KEY)) });
  const st = S.storableReceipt(compared.receipt);
  assert.equal(st.ok, true);
  const sealed = S.sealCase(storedCase(id), {
    reveals: { a: { tape_sha256: a.tape_sha256, salt: a.salt }, b: { tape_sha256: b.tape_sha256, salt: b.salt } },
    receipt: st.receipt, crossReference: null, revealedAt: C.utcSeconds(REVEAL_AT), signedUnder: KD.signedUnder(gh, named, C.utcSeconds(REVEAL_AT)),
  }, S.loadCaseSigner(SIGNED, { keyDocument: KEYS_DOC }));
  assert.notEqual(sealed.sig, null, "fixture: the case key signed it");
  assert.equal(S.checkSealedReceipt(sealed), null, "fixture: the receipt is bound to the case");
  gh.seed(PINS, C.casePath(id), sealed);
  return { id, a, b, sealed };
}

test("FIX B: a receipt signed by another key than the service's reconcile signer is receipt_unsigned: the sealed check, the page, the sealer and the reference all refuse it", async () => {
  const { id, a, sealed } = await wronglySignedCase("B wrong key");
  assert.equal(S.checkStoredReceipt(sealed), "receipt_unsigned");
  assert.deepEqual(await S.sealedRecordReason(sealed, KEYS_DOC), { code: "receipt_unsigned", reason: "unknown_signer" });
  const page = await casePage(id);
  assert.match(page.html, /<h1>Case: SEALED RECORD DOES NOT VERIFY<\/h1>/);
  assert.ok(page.html.includes("receipt_unsigned"));
  assert.ok(page.html.includes("unknown_signer"));
  assert.equal(page.html.includes("<h2>The verdict</h2>"), false);
  assert.deepEqual(await S.anchorCase(id, { now: REVEAL_AT + 60000, keyDocument: KEYS_DOC }), { ok: false, code: "receipt_unsigned", reason: "unknown_signer" });
  const run = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: KEYS_DOC });
  assert.deepEqual(run.refused, [{ case_id: id, code: "receipt_unsigned", reason: "unknown_signer" }]);
  assert.equal(gh.has(PINS, S.pinPaths(id).latest), false, "no pin");
  const ref = await reference({ ...proofOf(id, a), cross_reference: XREF });
  assert.equal(ref.status, 409, JSON.stringify(ref.body));
  assert.equal(ref.body.error_code, "receipt_unsigned");
  assert.deepEqual(referenceFiles(id), []);
  // control (Design I): it is the document the case NAMES that decides. The
  // same receipt in a seal naming a document that publishes that key holds.
  const named = await wronglySignedCase("B wrong key, named", docWith(entry(CASE_KEY), KD.reconcileEntry(WRONG_RECEIPT_KEY)));
  assert.equal((await S.sealedRecordReason(named.sealed, KEYS_DOC)).code, "valid_under_document");
});

test("FIX B, AFTER DESIGN I: a reader holds a receipt to the reconcile key the case's named document publishes, never to its own environment; WITNESS_RECONCILE_VERIFIER is only the private-side pointer to which published entry is ours", async () => {
  const { id } = await sealedCase({ scope_digest: sha("B readers") });
  const k = storedCase(id);
  assert.equal((await S.sealedRecordReason(k, KEYS_DOC)).code, "valid_under_document", "the service's own receipt holds");
  // no verifier is set anywhere in this process, and it still holds: the named document publishes it
  assert.equal(process.env[receipts.VERIFIER_ENV], undefined, "fixture");
  assert.equal(process.env[receipts.SIGNER_ENV], undefined, "fixture");
  // checkStoredReceipt holds a receipt to a GIVEN verifier only, and refuses without one
  assert.equal(S.checkStoredReceipt(k, { receiptVerifier: RECEIPT_KEY.verifier }), null);
  assert.equal(S.checkStoredReceipt(k), "receipt_unsigned");
  // the pointer, as the operator's tools read it
  assert.equal(receipts.expectedVerifier({}), null);
  assert.equal(receipts.expectedVerifier({ [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }), RECEIPT_KEY.verifier);
  assert.equal(receipts.expectedVerifier({ [receipts.VERIFIER_ENV]: ` ${RECEIPT_KEY.verifier}\n` }), RECEIPT_KEY.verifier);
  assert.equal(receipts.expectedVerifier({ [receipts.VERIFIER_ENV]: "not a verifier" }), null);
  assert.equal(receipts.expectedVerifier({ [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, [receipts.VERIFIER_ENV]: WRONG_RECEIPT_KEY.verifier }), RECEIPT_KEY.verifier,
    "the signer key, when this environment holds it, names its own verifier");
  // the page's environment does not decide either
  for (const env of [{}, { [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }, { [receipts.VERIFIER_ENV]: WRONG_RECEIPT_KEY.verifier }]) {
    const res = makeRes();
    await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": freshIp() } }), res,
      { now: REVEAL_AT + 3600000, keyDocument: KEYS_DOC, env });
    assert.match(String(res._body), /<h2>The verdict<\/h2>/, JSON.stringify(Object.keys(env)));
  }
});

test('GPT-5.6 §3.2 (and Gemini §3, timestamps): "The public case does not bind them [the service-clock fields] to a Git commit ID"', async () => {
  const { id } = await sealedCase({ scope_digest: sha("3.2") });
  const commits = gh.commitsFor(PINS, C.casePath(id)).map((c) => c.sha);
  assert.ok(commits.length >= 2, "fixture: the case file's commits (open, registrations, seal)");
  const text = JSON.stringify(storedCase(id)) + JSON.stringify(gh.read(PINS, S.pinPaths(id).latest));
  assert.ok(commits.some((c) => text.includes(c)), "the sealed case or its pin names the commit that wrote it");
  // Design J: the pin names the commit that wrote the SEALED file, the newest touching it
  assert.equal(gh.read(PINS, S.pinPaths(id).latest).case_commit, commits[0]);
});

test('GPT-5.6 §3.4 / §5: "pinChain(), anchorState(), and the page only establish that latest.json exists and has the matching chain. They do not establish inclusion in any daily anchor"', async () => {
  const { id } = await sealedCase({ scope_digest: sha("3.4") });
  const chain = S.caseChain(storedCase(id));
  // Design J: the pin alone is pinned, never anchored
  assert.equal((await S.anchorState(id, chain)).pin, "pinned");
  // a daily anchor record naming a head of the pins repository that holds the pin
  const day = gh.commitsFor(PINS, S.pinPaths(id).seq).slice(-1)[0].date.slice(0, 10);
  gh.seedText(PINS, `anchors/${day}-head.txt`, `${gh.headOf(PINS)} ${day}T03:15:00+00:00\n`);
  const from = gh.getLog.length;
  const st = await S.anchorState(id, chain);
  assert.equal(st.pin, "anchored");
  const reads = gh.getLog.slice(from);
  assert.ok(reads.length > 1, "anchored is said only after something beyond the pin pointer is read");
});

test('GPT-5.6 §5 (REFERENCE_ANCHOR_NOTE): "No reference row stores its write commit"', async () => {
  const { id, a } = await sealedCase({ scope_digest: sha("5 row") });
  const r = await reference({ ...proofOf(id, a), cross_reference: XREF });
  assert.equal(r.status, 201);
  const [c] = gh.commitsFor(PINS, C.referencePath(id, 1));
  assert.ok(c, "fixture: the row's commit");
  assert.ok(JSON.stringify(r.body).includes(c.sha) || JSON.stringify(gh.read(PINS, C.referencePath(id, 1))).includes(c.sha), "the row or its answer names the commit that wrote it");
  // Design J: the answer's row_commit, and the case's next pin lists it too
  assert.equal(r.body.row_commit, c.sha);
  await S.anchorPending({ now: REVEAL_AT + 7200000, keyDocument: KEYS_DOC });
  assert.deepEqual(gh.read(PINS, S.pinPaths(id).latest).reference_commits, [{ seq: 1, commit: c.sha }]);
});

// =============================================================================
// GPT-5.6, section 4: denial of service and cost
// =============================================================================

test('GPT-5.6 §4: "Each accepted request does at least a root read, reference-directory listing, reference-row write, then liveRecords() listing and up to 20 row reads"',
  { todo: "CONFIRMED: with 21 rows present, one accepted reference reads the root, lists twice, writes one row and reads 20 rows (the assertion 'an accepted reference reads fewer than 20 rows' fails)" }, async () => {
    const { id, a, b } = await sealedCase({ scope_digest: sha("4 cost") });
    // both roles write the 21 rows: one role may append 20 (FIX G, THE REFERENCE QUOTA)
    for (let i = 0; i < 21; i += 1) assert.equal((await reference({ ...proofOf(id, i % 2 ? b : a), cross_reference: { ...XREF, reference: `row-${i}` } })).status, 201);
    const g0 = gh.getLog.length;
    const pinWrites = () => gh.putLog.filter((x) => x.repo === PINS).length;
    const p0 = pinWrites();
    assert.equal((await reference({ ...proofOf(id, a), cross_reference: { ...XREF, reference: "measured" } })).status, 201);
    const reads = gh.getLog.slice(g0);
    const rowReads = reads.filter((p) => /\/references\/\d{8}\.json$/.test(p)).length;
    assert.ok(reads.includes(C.casePath(id)), "a root read");
    assert.equal(reads.filter((p) => p === C.referencesDir(id)).length, 2, "two listings");
    assert.equal(pinWrites() - p0, 1, "one row write (the quota's counter is in the private usage repository)");
    assert.ok(rowReads < 20, `an accepted reference reads fewer than 20 rows (${rowReads})`);
  });

test('GPT-5.6 §4: "Burning another user\'s 20/day open quota requires their bearer key; the code does not provide an unauthenticated cross-key quota burn. With a stolen key, twenty distinct valid openings consume it directly"', async () => {
  const qpath = H._internal.openQuotaPath(VICTIM_KEY, "2026-10-10");
  let n = 0;
  for (const headers of [{}, { authorization: "Bearer not-a-key" }, { authorization: `Bearer ${VICTIM_KEY}x` }, OPEN_AUTH]) {
    for (let i = 0; i < 22; i += 1) {
      n += 1;
      await open({ scope_digest: sha(`attempt ${n}`) }, { headers });
    }
  }
  assert.equal(gh.has(USAGE, qpath), false, "no request without the victim's key touched its counter");
  for (let i = 0; i < 20; i += 1) {
    const r = await open({ scope_digest: sha(`victim ${i}`) }, { headers: { authorization: `Bearer ${VICTIM_KEY}` } });
    assert.equal(r._status, 201, `victim open ${i + 1}: ${JSON.stringify(r._body)}`);
  }
  const over = await open({ scope_digest: sha("victim 21") }, { headers: { authorization: `Bearer ${VICTIM_KEY}` } });
  assert.equal(over._status, 429);
  assert.equal(over._body.error_code, "open_quota_exceeded");
});

// =============================================================================
// Gemini 3.1 Pro: the classes with a concrete reading in this code
// =============================================================================

test('Gemini 3.1 Pro §1: "if a withdraw and a reveal are processed simultaneously, the system must guarantee that only one succeeds and the final state is consistent": started together, one 201 and one typed 409', async () => {
  const { id, a, b } = await committedCase({ scope_digest: sha("G1") });
  const [w, r] = await Promise.all([withdraw(proofOf(id, a), { now: REVEAL_AT }), reveal(revealBody(id, a, b), { now: REVEAL_AT })]);
  const statuses = [w.status, r.status].sort();
  assert.deepEqual(statuses, [201, 409], `${JSON.stringify(w.body).slice(0, 120)} / ${JSON.stringify(r.body).slice(0, 120)}`);
  const final = storedCase(id).status;
  assert.equal(final, w.status === 201 ? "WITHDRAWN" : "VERDICT");
  assert.equal((w.status === 201 ? r : w).body.error_code, w.status === 201 ? "case_withdrawn" : "case_sealed");
});

test('Gemini 3.1 Pro §2: "one party commits but refuses to reveal ... to prevent the protocol from stalling indefinitely": at the deadline the case reads EXPIRED and is terminal', async () => {
  const { id, a, b } = await committedCase({ scope_digest: sha("G4") });
  const at = Date.parse(DEADLINE);
  const r = await reveal(revealBody(id, a, b), { now: at });
  assert.equal(r.status, 409);
  assert.equal(r.body.error_code, "expired");
  assert.deepEqual(await S.anchorCase(id, { now: at, keyDocument: KEYS_DOC }), { ok: false, code: "terminal", status: "EXPIRED" });
  assert.match((await casePage(id, { now: at })).html, /<h1>Case: EXPIRED<\/h1>/);
});

test('Gemini 3.1 Pro §2: "If the commitment preimage includes variable-length fields or optional parameters, an adversary might attempt length extension attacks or parameter confusion": the preimage is fixed-length, every field fixed-width, no optional field', () => {
  for (let i = 0; i < 50; i += 1) {
    const input = { case_id: sha(`c${i}`), role: i % 2 ? "a" : "b", tape_sha256: sha(`t${i}`), salt: C.newSalt() };
    assert.equal(C.commitmentBytes(input).length, C.COMMITMENT_BYTES_LENGTH);
    assert.equal(C.commitmentBytes({ ...input, protocol_version: "case/1" }).length, C.COMMITMENT_BYTES_LENGTH);
  }
  const base = { case_id: sha("c"), role: "a", tape_sha256: sha("t"), salt: sha("s") };
  for (const [field, bad] of [["salt", sha("s").slice(1)], ["salt", sha("s") + "0"], ["tape_sha256", sha("t").slice(2)], ["case_id", sha("c").toUpperCase()]]) {
    assert.throws(() => C.commitmentBytes({ ...base, [field]: bad }), (e) => e.code === "malformed_field" && e.field === field);
  }
  assert.throws(() => C.commitmentBytes({ ...base, manifest_sha256: sha("m") }), (e) => e.code === "unknown_field");
});

test('Gemini 3.1 Pro §4: "If quotas are tracked using non-atomic operations ..., an attacker might exceed the quota by sending many concurrent requests": 30 opens with one key at once, at most 20 succeed', async () => {
  const results = await Promise.all(Array.from({ length: 30 }, (_, i) => open({ scope_digest: sha(`concurrent ${i}`) })));
  const ok = results.filter((r) => r._status === 201).length;
  assert.ok(ok > 0, "some opened");
  assert.ok(ok <= 20, `${ok} opened`);
  const count = gh.read(USAGE, H._internal.openQuotaPath(OPEN_KEY, "2026-10-10")).count;
  assert.ok(count >= ok && count <= 20, `counter ${count}, opened ${ok}`);
  for (const r of results) assert.ok([201, 429, 503].includes(r._status), JSON.stringify(r._body));
});

test('Gemini 3.1 Pro §5: "If the salt used in the commitment is too short or predictable, the hiding property is compromised": a salt is 32 random bytes, and a shorter one is refused', () => {
  const salts = new Set(Array.from({ length: 200 }, () => C.newSalt()));
  assert.equal(salts.size, 200);
  for (const s of salts) assert.match(s, /^[0-9a-f]{64}$/);
  assert.throws(() => C.commitmentSha256({ case_id: sha("c"), role: "a", tape_sha256: sha("t"), salt: "ab".repeat(16) }), (e) => e.code === "malformed_field" && e.field === "salt");
});

test('Gemini 3.1 Pro §5: "if the signature does not cover the entire context of the record (e.g., missing a timestamp or a protocol version)": changing any field of a signed sealed case breaks its signature', async () => {
  const { id } = await sealedCase({ scope_digest: sha("G13") });
  const rec = storedCase(id);
  assert.equal(S.signatureReason(rec, CASE_KEY.verifier), null, "control: verifies");
  for (const f of C.TOP_LEVEL_FIELDS.filter((x) => x !== "sig")) {
    const changed = { ...rec, [f]: f === "signed_by" ? `${rec.signed_by.split("+")[0]}x+${rec.signed_by.split("+")[1]}` : { changed: f } };
    assert.notEqual(S.signatureReason(changed, CASE_KEY.verifier), null, f);
  }
  const t = { ...rec, reveals: { ...rec.reveals, a: { ...rec.reveals.a, revealed_at: "2026-10-10T09:00:01Z" } } };
  assert.notEqual(S.signatureReason(t, CASE_KEY.verifier), null, "a timestamp inside the record");
});
