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
// No code under test is changed. Every store is the in-memory mock.
//
// NOT TESTABLE HERE (no test, one line why):
//   - GPT-5.6 §1.2 and the reference row's note, "no code verifies that
//     daily anchor": the daily head anchor is an outside job, not in this
//     repository (§3.4's test shows anchorState reads the pointer alone);
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
const entry = (k, status = "active") => ({ key_id: keyIdOf(k), verifier: k.verifier, since: "2026-10-10", note: "a test key", status });
const docWith = (...entries) => ({ ...S.PUBLISHED_KEYS, keys: entries });
const KEYS_DOC = Object.freeze(docWith(entry(CASE_KEY)));
const OPEN_KEY = "case-test-open-key-0021";
const VICTIM_KEY = "case-test-open-key-0022";
const OPEN_AUTH = Object.freeze({ authorization: `Bearer ${OPEN_KEY}` });
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
async function commit(id, p, now = NOW) {
  const res = makeRes();
  await H.handleCaseCommit(req("case-commit", { case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 }), res, { now });
  return res;
}
async function register(id, p) {
  plantStamp(p.commitment_sha256);
  const r = await commit(id, p);
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
  await H.handleCaseReveal(req("case-reveal", body), res, { now, env, keyDocument });
  return { status: res._status, body: parsed(res) };
}
async function sealedCase(over, { pinFails = false } = {}) {
  const c = await committedCase(over);
  if (pinFails) gh.forceFailure(PINS, S.pinPaths(c.id).seq, 1, 502);
  const r = await reveal(revealBody(c.id, c.a, c.b));
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.pin, pinFails ? "pending" : "anchored");
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
    assert.equal((await S.anchorState(id, S.caseChain(storedCase(id)))).pin, "pending", "fixture: not anchored");
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

test('GPT-5.6 §1.4 / §3.3 / §6.4: "A later edit changing a key from active or retired to revoked makes old sealed cases fail sealedRecordReason() and display SEALED RECORD DOES NOT VERIFY"',
  { todo: "CONFIRMED: once the document marks the sealing key revoked, sealedRecordReason answers case_signature_invalid / signer_revoked and the page shows SEALED RECORD DOES NOT VERIFY (the assertion 'a case sealed while its key was active still verifies, and its page shows its verdict, after a later document revokes the key' fails)" }, async () => {
    const { id } = await sealedCase({ scope_digest: sha("1.4 revoke") });
    const rec = storedCase(id);
    assert.equal(typeof rec.sig, "string", "fixture: signed");
    assert.equal(S.sealedRecordReason(rec, KEYS_DOC), null, "verifies under the document it was sealed under");
    assert.equal(S.sealedRecordReason(rec, docWith(entry(CASE_KEY, "retired"))), null, "control: a retired key's seals stay trusted");
    const revoked = docWith(entry(CASE_KEY, "revoked"));
    const page = await casePage(id, { keyDocument: revoked });
    assert.deepEqual({ reason: S.sealedRecordReason(rec, revoked), doesNotVerify: page.html.includes("SEALED RECORD DOES NOT VERIFY") },
      { reason: null, doesNotVerify: false },
      "a case sealed while its key was active still verifies, and its page shows its verdict, after a later document revokes the key");
  });

test('GPT-5.6 §1.4: "Conversely, a later document can introduce a verifier that makes a formerly unverifiable stored signature appear valid"',
  { todo: "CONFIRMED: a stored case signed by an unlisted key reads signer_unpublished under one document and verifies under a later one that lists the key (the assertion 'the verdict on stored bytes does not change with the document alone' fails)" }, async () => {
    const { id } = await sealedCase({ scope_digest: sha("1.4 later listing") });
    const rec = storedCase(id);
    const other = checkpoint.parseSignerKey(OTHER_KEY.signer);
    const resigned = S.signRecord({ ...rec, signed_by: null, sig: null, sig_reason: null }, { ok: true, keyId: keyIdOf(OTHER_KEY), privateKey: other.privateKey }, "unused");
    assert.deepEqual(C.validateCase(resigned), { ok: true }, "fixture: schema-valid");
    const earlier = S.sealedRecordReason(resigned, KEYS_DOC);
    assert.deepEqual(earlier, { code: "case_signature_invalid", reason: "signer_unpublished" });
    const later = S.sealedRecordReason(resigned, docWith(entry(CASE_KEY), entry(OTHER_KEY)));
    assert.deepEqual(later, earlier, "the verdict on stored bytes does not change with the document alone");
  });

test('GPT-5.6 §1.4 / §3.3: "No sealed case records the key-document hash, Git commit, or retrieval time"',
  { todo: "CONFIRMED: neither the sha256 of the key document's bytes nor of its json-c14n:v1 form appears in the sealed case (the assertion 'the sealed case names the key document it was signed under' fails)" }, async () => {
    const { id } = await sealedCase({ scope_digest: sha("1.4 binding") });
    const text = JSON.stringify(storedCase(id));
    const digests = [sha(JSON.stringify(KEYS_DOC)), sha(JSON.stringify(KEYS_DOC, null, 2)), sha(canonicalBytes(KEYS_DOC))];
    assert.ok(digests.some((d) => text.includes(d)), "the sealed case names the key document it was signed under");
  });

test('GPT-5.6 §1.5 / §4 / §6.5 (and Gemini §4, unauthenticated consumption): "admit() runs ratelimit.check(req) before openKey() ... The victim is blocked before their valid bearer key is even checked"',
  { todo: "CONFIRMED: after unauthenticated case-open requests spend one address's per-IP budget, a valid keyed open from that address is 429 rate_limited (the assertion 'an authenticated open is not refused by the budget unauthenticated requests spent' fails)" }, async () => {
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

test('GPT-5.6 §2A: "Create a seemingly bilateral case using an honest party\'s label": one key holder opens, registers both roles and reveals',
  { todo: "CONFIRMED: one requester seals a case naming another party's label, and the page shows it as a party of a sealed verdict (the assertion 'a case one requester opened, registered and revealed alone is not shown as a sealed verdict naming another party' fails)" }, async () => {
    const { id } = await sealedCase({
      scope_digest: sha("2A"),
      party_a: { side: "agent", label: "attacker-account" },
      party_b: { side: "tool", label: "honest-party-account" },
    });
    const page = await casePage(id);
    assert.equal(page.status, 200);
    assert.ok(page.html.includes(CP.LABELS_SENTENCE), "the page carries the labels sentence");
    const shown = page.html.includes("honest-party-account") && page.html.includes("<h2>The verdict</h2>");
    assert.equal(shown, false, "a case one requester opened, registered and revealed alone is not shown as a sealed verdict naming another party");
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

test('GPT-5.6 §2C / §6.1 (and Gemini §4, storage bloat): "Either can repeatedly call case-reference as role:a or role:b ... There is no per-case, per-role, per-key, or lifetime addendum quota"',
  { todo: "CONFIRMED: one role's proof appends 100 reference rows to one case, each 201 (the assertion 'a role cannot append a hundred reference rows to one case' fails)" }, async () => {
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

test('GPT-5.6 §3.1 / §5 / §6.3: "Fabricate a case verdict without actually running reconcile ... If the reconcile receipt is unsigned, checkStoredReceipt() accepts it" (and the page says "The service ran its recorded comparison once")',
  { todo: "CONFIRMED: a sealed case built from a receipt no comparison produced passes sealedRecordReason and the page shows its verdict (the assertion 'a verdict no comparison produced does not pass the sealed check' fails)" }, async (t) => {
    const { id, a, b } = await committedCase({ scope_digest: sha("3.1") });
    const compare = t.mock.method(RECONCILE, "compare");
    const result = { verdict: "MATCHED", at: null, side: null, matched: 999, counts: { agent: 999, tool: 999 }, findings: [], could_not_look: [], exit_code: 0 };
    const receipt = receipts.signReceipt(receipts.buildReceipt({ bytesA: AGENT_TAPE, bytesB: TOOL_TAPE, result, now: REVEAL_AT }), { ok: false, reason: "no signer" });
    const st = S.storableReceipt(receipt);
    assert.equal(st.ok, true);
    const fabricated = S.sealCase(storedCase(id), {
      reveals: { a: { tape_sha256: a.tape_sha256, salt: a.salt }, b: { tape_sha256: b.tape_sha256, salt: b.salt } },
      receipt: st.receipt, crossReference: null, revealedAt: C.utcSeconds(REVEAL_AT),
    }, { ok: false, code: "case_key_unset", reason: "no case signing key is configured" });
    gh.seed(PINS, C.casePath(id), fabricated);
    const page = await casePage(id);
    assert.equal(compare.mock.callCount(), 0, "reconcile never ran");
    assert.match(page.html, /<span class="word pass">MATCHED<\/span>/);
    assert.match(page.html, /The service ran its recorded comparison once/);
    assert.notEqual(S.sealedRecordReason(fabricated, KEYS_DOC), null, "a verdict no comparison produced does not pass the sealed check");
  });

test('GPT-5.6 §3.2 (and Gemini §3, timestamps): "The public case does not bind them [the service-clock fields] to a Git commit ID"',
  { todo: "CONFIRMED: the commit that wrote the sealed case appears neither in the case nor in its pin (the assertion 'the sealed case or its pin names the commit that wrote it' fails)" }, async () => {
    const { id } = await sealedCase({ scope_digest: sha("3.2") });
    const commits = gh.commitsFor(PINS, C.casePath(id)).map((c) => c.sha);
    assert.ok(commits.length >= 2, "fixture: the case file's commits (open, registrations, seal)");
    const text = JSON.stringify(storedCase(id)) + JSON.stringify(gh.read(PINS, S.pinPaths(id).latest));
    assert.ok(commits.some((c) => text.includes(c)), "the sealed case or its pin names the commit that wrote it");
  });

test('GPT-5.6 §3.4 / §5: "pinChain(), anchorState(), and the page only establish that latest.json exists and has the matching chain. They do not establish inclusion in any daily anchor"',
  { todo: "CONFIRMED: anchorState answers anchored after reading pins/case/<id>/latest.json and nothing else (the assertion 'anchored is said only after something beyond the pin pointer is read' fails)" }, async () => {
    const { id } = await sealedCase({ scope_digest: sha("3.4") });
    const from = gh.getLog.length;
    const st = await S.anchorState(id, S.caseChain(storedCase(id)));
    assert.equal(st.pin, "anchored");
    const reads = gh.getLog.slice(from);
    assert.deepEqual(reads, [S.pinPaths(id).latest]);
    assert.ok(reads.length > 1, "anchored is said only after something beyond the pin pointer is read");
  });

test('GPT-5.6 §5 (REFERENCE_ANCHOR_NOTE): "No reference row stores its write commit"',
  { todo: "CONFIRMED: the commit that wrote a reference row appears neither in the row nor in the answer (the assertion 'the row or its answer names the commit that wrote it' fails)" }, async () => {
    const { id, a } = await sealedCase({ scope_digest: sha("5 row") });
    const r = await reference({ ...proofOf(id, a), cross_reference: XREF });
    assert.equal(r.status, 201);
    const [c] = gh.commitsFor(PINS, C.referencePath(id, 1));
    assert.ok(c, "fixture: the row's commit");
    assert.ok(JSON.stringify(r.body).includes(c.sha) || JSON.stringify(gh.read(PINS, C.referencePath(id, 1))).includes(c.sha), "the row or its answer names the commit that wrote it");
  });

// =============================================================================
// GPT-5.6, section 4: denial of service and cost
// =============================================================================

test('GPT-5.6 §4: "Each accepted request does at least a root read, reference-directory listing, reference-row write, then liveRecords() listing and up to 20 row reads"',
  { todo: "CONFIRMED: with 21 rows present, one accepted reference reads the root, lists twice, writes one row and reads 20 rows (the assertion 'an accepted reference reads fewer than 20 rows' fails)" }, async () => {
    const { id, a } = await sealedCase({ scope_digest: sha("4 cost") });
    for (let i = 0; i < 21; i += 1) assert.equal((await reference({ ...proofOf(id, a), cross_reference: { ...XREF, reference: `row-${i}` } })).status, 201);
    const g0 = gh.getLog.length;
    const p0 = gh.putLog.length;
    assert.equal((await reference({ ...proofOf(id, a), cross_reference: { ...XREF, reference: "measured" } })).status, 201);
    const reads = gh.getLog.slice(g0);
    const rowReads = reads.filter((p) => /\/references\/\d{8}\.json$/.test(p)).length;
    assert.ok(reads.includes(C.casePath(id)), "a root read");
    assert.equal(reads.filter((p) => p === C.referencesDir(id)).length, 2, "two listings");
    assert.equal(gh.putLog.length - p0, 1, "one row write");
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
