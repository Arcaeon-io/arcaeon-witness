// test/case_fix_mutation_gaps.test.js — the gaps a must-fail (mutation) pass
// over red-team fix A (ONE KEY PER ROLE, lib/_case.js) and fix B (A RECEIPT
// IS THE SERVICE'S, lib/_case_seal.js) found, in the style of
// test/case_mutation_gaps.test.js: one planted defect at a time in a scratch
// copy, the whole suite run each time, and for every defect the suite let
// through, the smallest test here that fails with that defect and passes on
// the real code. Each test names the mutant it kills.
//
// Two passes, one per red-team fix (harness not committed).
//
// FIX A's pass: 37 defects planted in the code fix A
// added or changed, across lib/_case.js (17), lib/_case_http.js (8),
// lib/_case_seal.js (5), lib/_case_page.js (5) and tools/preview_dry_run.js
// (2). 18 were caught by the suite with fix A's own tests. Of the 19 that
// survived, 18 are closed here and one is equivalent:
//   - A18, lib/_case.js singleParty taking one registered role as enough
//     ((c.a || {}).key_id === (c.b || {}).key_id once either is an object):
//     a valid commitment entry always holds a string key_id, so a registered
//     role never matches an absent one, and every caller passes a case the
//     schema read.
// Two more were planted after, and are killed here: A16 (no registration at
// all reading as one key), to aim the singleParty test at what A18 cannot
// show, and A19 (a key name longer than a key id holds), for a defect found
// reading the diff and fixed before the commit (it answered a 500). Final:
// 39 planted, lib/_case.js 19, 38 caught, 1 equivalent.
//
// FIX B's pass: 34 defects planted in the code fix B added or changed,
// across lib/_reconcile_receipt.js (4), lib/_reconcile_http.js (4),
// lib/_case_http.js (4), lib/_case_seal.js (13), lib/_sealer.js (1),
// lib/_case_page.js (3) and tools/preview_dry_run.js (5). 28 were caught by
// the suite with fix B's own tests. Of the 6 that survived, 5 are closed
// here and one is equivalent:
//   - S11, lib/_case_seal.js receiptSignerReason verifying under the
//     verifier the receipt carries instead of the expected one: the line
//     before it returns unless the two are the same string.
// Final: 34 planted, 33 caught, 1 equivalent.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0031:case-test-";
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
const S = require("../lib/_case_seal.js");
const CP = require("../lib/_case_page.js");
const receipts = require("../lib/_reconcile_receipt.js");
const RECONCILE = require("../lib/_reconcile_http.js");
const checkpoint = require("../lib/_checkpoint.js");
const stamp = require("../lib/_stamp.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z");
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const PAST_DEADLINE = Date.parse(DEADLINE) + 1000;
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-10");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-10");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-10");
const SIGNED = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const KEYS_DOC = Object.freeze({ ...S.PUBLISHED_KEYS, keys: [{ key_id: REG.keyIdOf(CASE_KEY), verifier: CASE_KEY.verifier, since: "2026-10-10", note: "a test key", status: "active" },
  KD.reconcileEntry(RECEIPT_KEY)] });
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0031" });

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
function req(op, body, headers = {}) {
  ipSeq += 1;
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": `10.94.${(ipSeq >> 8) & 255}.${ipSeq & 255}`, ...headers }, body });
}
function parsed(res) {
  return typeof res._body === "string" ? JSON.parse(res._body) : res._body;
}
function opening(over = {}) {
  return {
    protocol_version: "case/1",
    policy_version: C.SUPPORTED_POLICY_VERSION,
    scope_digest: sha("the scope manifest both parties agreed"),
    party_a: { side: "agent", label: "attacker-account" },
    party_b: { side: "tool", label: "honest-party-account" },
    opened_at: "2026-10-10T07:30:00Z",
    deadline: DEADLINE,
    ...over,
  };
}
async function openCase(scope) {
  const res = makeRes();
  await H.handleCaseOpen(req("case-open", opening({ scope_digest: sha(scope) }), OPEN_AUTH), res, { now: NOW });
  assert.equal(res._status, 201, JSON.stringify(res._body));
  return res._body.case_id;
}
function plantStamp(hash) {
  gh.seed(STAMPS, stamp.stampPath(hash), { kind: "file-stamp", v: 1, sha256: hash, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: "2026-10-10T07:45:00.123Z" });
}
function party(caseId, role, tape) {
  const salt = C.newSalt();
  const tape_sha256 = sha(tape);
  return { role, tape, tape_sha256, salt, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
}
async function send(op, body, opts = {}) { // op is case-commit
  const res = makeRes();
  await H.handleCaseCommit(req(op, body), res, { now: NOW, ...opts });
  return { status: res._status, body: parsed(res) };
}
const fieldsOf = (id, p) => ({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 });
async function commit(id, p, key = REG.KEYS[p.role], now = NOW) {
  plantStamp(p.commitment_sha256);
  return send("case-commit", REG.signedBody(fieldsOf(id, p), key), { now });
}
async function casePage(id, now = REVEAL_AT) {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": "10.95.0.1" } }), res, { now, keyDocument: KEYS_DOC });
  return { status: res._status, html: String(res._body) };
}
// Run `inner` when the first request matching `match` goes out, then let that request through.
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
    return { out: await outer(), inner: got, fired };
  } finally {
    global.fetch = viaMock;
  }
}
const stampGet = (p) => (url, method) => method === "GET" && url.includes(`/repos/${STAMPS}/contents/${stamp.stampPath(p.commitment_sha256)}`);

// A case one key registered both roles of: role a registers while role b's
// request reads its stamp (both files stand, first write wins per role).
async function racedSingleParty(scope) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(a.commitment_sha256);
  const r = await during(stampGet(b), () => commit(id, a, REG.KEYS.a), () => commit(id, b, REG.KEYS.a));
  assert.equal(r.inner.status, 201);
  assert.equal(r.out.status, 201);
  assert.equal(C.singleParty(gh.read(PINS, C.casePath(id))), true, "fixture: single party");
  return { id, a, b };
}

// =============================================================================
// lib/_case.js
// =============================================================================

test("A06, A07, A08, A09 (registrationSigningBytes): the bytes a registration key signs are exactly the json-c14n:v1 of {case_id, commitment_sha256, kind, role, v}", () => {
  const f = { case_id: "1".repeat(64), role: "b", commitment_sha256: "2".repeat(64) };
  assert.equal(C.registrationSigningBytes(f).toString("utf-8"),
    `{"case_id":"${"1".repeat(64)}","commitment_sha256":"${"2".repeat(64)}","kind":"case-registration-signature","role":"b","v":1}`);
  // signRegistration signs exactly those bytes, checked with node's own verify
  const sig = Buffer.from(C.signRegistration(f, REG.KEYS.b.signer), "base64");
  const pub = checkpoint.parseVerifierKey(REG.KEYS.b.verifier).publicKey;
  assert.equal(crypto.verify(null, C.registrationSigningBytes(f), pub, sig), true);
  // and a signature for another case, role or commitment is refused
  for (const other of [{ ...f, case_id: "3".repeat(64) }, { ...f, role: "a" }, { ...f, commitment_sha256: "4".repeat(64) }]) {
    assert.equal(C.registrationSignatureReason({ ...other, verifier: REG.KEYS.b.verifier, sig: sig.toString("base64") }), "bad_signature", JSON.stringify(other));
  }
});

test("A01, A02 (validateRegistrationBody / checkRegistrationKey): a verifier that is not a verifier string is 400 malformed_field verifier, never read as a key", async () => {
  const id = await openCase("A02");
  const a = party(id, "a", AGENT_TAPE);
  const good = REG.signedBody(fieldsOf(id, a));
  const k = good.verifier;
  // not one, a key id whose hash is not the key's, a truncated key, not a string
  const wrongHash = k.replace(/\+[0-9a-f]{8}\+/, "+00000000+");
  assert.notEqual(wrongHash, k, "fixture");
  for (const verifier of ["not a verifier", wrongHash, k.slice(0, -4), 7]) {
    const res = await send("case-commit", { ...good, verifier });
    assert.equal(res.status, 400, `${String(verifier).slice(0, 30)}: ${JSON.stringify(res.body)}`);
    assert.equal(res.body.error_code, "malformed_field");
    assert.equal(res.body.field, "verifier");
  }
});

test("A19 (checkRegistrationKey, the name's length): a verifier whose key name is longer than a key id holds (180) is 400 malformed_field verifier, never a 500", async () => {
  const id = await openCase("A19");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  for (const [n, want] of [[181, 400], [180, 201]]) {
    const key = checkpoint.generateKey("n".repeat(n));
    const res = await send("case-commit", REG.signedBody(fieldsOf(id, a), key));
    assert.equal(res.status, want, `${n}: ${JSON.stringify(res.body).slice(0, 200)}`);
    if (want === 400) assert.equal(res.body.field, "verifier");
  }
});

test("A03, A04 (checkRegistrationKey): a sig that is not 64 bytes of canonical base64 is 400 malformed_field sig, even when its bytes would verify", async () => {
  const id = await openCase("A04");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const good = REG.signedBody(fieldsOf(id, a));
  assert.match(good.sig, /==$/, "fixture: 64 bytes in base64 end in ==");
  const writes = gh.putLog.length;
  for (const sig of [good.sig.slice(0, -2), good.sig.slice(0, 40), 12345, null, ""]) {
    const res = await send("case-commit", { ...good, sig });
    assert.equal(res.status, 400, `${JSON.stringify(sig)}: ${JSON.stringify(res.body)}`);
    assert.equal(res.body.error_code, "malformed_field");
    assert.equal(res.body.field, "sig");
  }
  assert.equal(gh.putLog.length, writes, "nothing written");
  assert.equal((await send("case-commit", good)).status, 201, "control: the canonical form registers");
});

test("A11, A12 (validateRegistrationRecord): a stored registration whose key_id is not its verifier's, or whose sig is not its key's, is not a valid record", async () => {
  const id = await openCase("A11");
  const a = party(id, "a", AGENT_TAPE);
  assert.equal((await commit(id, a)).status, 201);
  const file = gh.read(PINS, C.registrationPath(id, "a"));
  assert.deepEqual(C.validateRegistrationRecord(file), { ok: true });
  const otherKeyId = { ...file, key_id: REG.keyIdOf(REG.KEYS.b) };
  assert.equal(C.validateRegistrationRecord(otherKeyId).field, "key_id");
  const otherSig = { ...file, sig: C.signRegistration(fieldsOf(id, a), REG.KEYS.b.signer) };
  assert.equal(C.validateRegistrationRecord(otherSig).field, "sig");
  // planted, either one makes the file unreadable to the next registration
  for (const bad of [otherKeyId, otherSig]) {
    gh.seed(PINS, C.registrationPath(id, "a"), bad);
    const b = party(id, "b", TOOL_TAPE);
    const res = await commit(id, b);
    assert.equal(res.status, 503, JSON.stringify(res.body));
    assert.equal(res.body.error_code, "registration_record_unreadable");
  }
});

test("A13 (checkCommitmentEntry): a case whose commitment entry has no key id, or a malformed one, is not a valid record", async () => {
  const id = await openCase("A13");
  const a = party(id, "a", AGENT_TAPE);
  assert.equal((await commit(id, a)).status, 201);
  const k = gh.read(PINS, C.casePath(id));
  assert.deepEqual(C.validateCase(k), { ok: true });
  for (const key_id of [undefined, null, "", "no-hash", `${REG.keyIdOf(REG.KEYS.a)}0`]) {
    const e = { ...k.commitments.a, key_id };
    if (key_id === undefined) delete e.key_id;
    const v = C.validateCase({ ...k, commitments: { ...k.commitments, a: e } });
    assert.equal(v.ok, false, String(key_id));
    assert.match(v.field, /^commitments\.a/);
  }
});

test("A16 (singleParty): a case with no registration, or one, is not single party; the page of a fresh case reads OPEN", async () => {
  const id = await openCase("A16");
  const k0 = gh.read(PINS, C.casePath(id));
  assert.equal(C.singleParty(k0), false, "no registration");
  assert.match((await casePage(id)).html, /<h1>Case: OPEN<\/h1>/);
  const a = party(id, "a", AGENT_TAPE);
  assert.equal((await commit(id, a)).status, 201);
  assert.equal(C.singleParty(gh.read(PINS, C.casePath(id))), false, "one registration");
  assert.equal(C.singleParty({ status: "WITHDRAWN" }), false, "a redacted record has no commitments");
});

// =============================================================================
// lib/_case_http.js
// =============================================================================

test("H03 (commit step 4b, new registrations only): role b's file raced in under role a's key and its case write failed; b's replay completes the projection (200), and the case reads single party", async () => {
  const id = await openCase("H03");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(a.commitment_sha256);
  const r = await during(stampGet(b), async () => {
    const ra = await commit(id, a, REG.KEYS.a);
    gh.forceFailure(PINS, C.casePath(id), 1, 502); // b's case write fails (a 5xx is not retried)
    return ra;
  }, () => commit(id, b, REG.KEYS.a));
  assert.equal(r.inner.status, 201);
  assert.equal(r.out.status, 503, JSON.stringify(r.out.body));
  assert.equal(r.out.body.error_code, "case_update_failed");
  assert.equal(gh.read(PINS, C.casePath(id)).status, "OPEN", "fixture: b's file stands, unprojected");
  const replay = await commit(id, b, REG.KEYS.a);
  assert.equal(replay.status, 200, JSON.stringify(replay.body));
  assert.deepEqual(replay.body.projected, ["b"]);
  const k = gh.read(PINS, C.casePath(id));
  assert.equal(k.status, "COMMITTED");
  assert.equal(C.singleParty(k), true);
});

test("H05 (commit, the lost race): another key's registration of the same commitment for this role lands first; this one is role_already_committed, never answered as its own", async () => {
  const id = await openCase("H05");
  const a = party(id, "a", AGENT_TAPE);
  const thief = checkpoint.generateKey("someone-else.example/case-registration");
  plantStamp(a.commitment_sha256);
  const r = await during(stampGet(a), () => commit(id, a, thief), () => commit(id, a, REG.KEYS.a));
  assert.equal(r.inner.status, 201, "the other key landed first");
  assert.equal(r.out.status, 409, JSON.stringify(r.out.body));
  assert.equal(r.out.body.error_code, "role_already_committed");
  assert.equal(gh.read(PINS, C.registrationPath(id, "a")).key_id, REG.keyIdOf(thief));
});

test("H08 (commit step 4b, the other role's FILE): role a's registration stands unprojected (its case write failed); role b under the same key is still 409 same_key_both_roles", async () => {
  const id = await openCase("H08");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  gh.forceFailure(PINS, C.casePath(id), 1, 502);
  const ra = await commit(id, a, REG.KEYS.a);
  assert.equal(ra.status, 503, JSON.stringify(ra.body));
  assert.equal(ra.body.registration_recorded, true);
  assert.equal(gh.read(PINS, C.casePath(id)).commitments.a, null, "fixture: the case does not show role a");
  const rb = await commit(id, b, REG.KEYS.a);
  assert.equal(rb.status, 409, JSON.stringify(rb.body));
  assert.equal(rb.body.error_code, "same_key_both_roles");
  assert.equal(gh.has(PINS, C.registrationPath(id, "b")), false);
});

test("H07 (reference, the words for single_party): the refusal says one key registered both roles", async () => {
  const { id } = await racedSingleParty("H07");
  const k = gh.read(PINS, C.casePath(id));
  // the stored record as a VERDICT (a forger's, or a build before fix A)
  const verdictLike = { ...k, status: "VERDICT", reveals: { a: { tape_sha256: sha("t"), salt_sha256: sha("s"), revealed_at: "2026-10-10T09:00:00Z" }, b: { tape_sha256: sha("u"), salt_sha256: sha("s2"), revealed_at: "2026-10-10T09:00:00Z" } }, verdict: { kind: "x" } };
  assert.deepEqual(C.validateCase(verdictLike), { ok: true });
  gh.seed(PINS, C.casePath(id), verdictLike);
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: id, cross_reference: { operator: "second-operator.example", reference: "r-1", url: "https://second-operator.example/r/1" } },
    { authorization: "Bearer case-test-operator-key-0031" }), res, { now: REVEAL_AT, env: { [H.OPERATOR_KEY_ENV]: "case-test-operator-key-0031" }, keyDocument: KEYS_DOC });
  assert.equal(res._status, 409, JSON.stringify(res._body));
  assert.equal(res._body.error_code, "single_party");
  assert.match(res._body.error, /one key registered both of its roles/);
});

// =============================================================================
// lib/_case_seal.js
// =============================================================================

test("S02 (sealCase): a single-party COMMITTED case is never sealed, whatever it is handed", async () => {
  const { id } = await racedSingleParty("S02");
  const k = gh.read(PINS, C.casePath(id));
  const signedUnder = KD.signedUnder(gh, KEYS_DOC, "2026-10-10T09:00:00Z");
  assert.throws(() => S.sealCase(k, { reveals: null, receipt: null, crossReference: null, revealedAt: "2026-10-10T09:00:00Z", signedUnder }, null),
    (e) => e instanceof C.CaseError && e.code === "status_inconsistent" && e.field === "commitments");
});

test("S05 (anchorCase, the order): a single-party case past its deadline is terminal EXPIRED, as any unsealed case past it is", async () => {
  const { id } = await racedSingleParty("S05");
  assert.deepEqual(await S.anchorCase(id, { now: PAST_DEADLINE, keyDocument: KEYS_DOC }), { ok: false, code: "terminal", status: "EXPIRED" });
  assert.deepEqual(await S.anchorCase(id, { now: REVEAL_AT, keyDocument: KEYS_DOC }), { ok: false, code: "not_sealed", status: "COMMITTED", reason: "single_party" });
});

// =============================================================================
// lib/_case_page.js
// =============================================================================

test("P03, P04 (the single-party page past the deadline): still SINGLE PARTY, never the EXPIRED page with its labels, and it says the deadline passed", async () => {
  const { id } = await racedSingleParty("P04");
  const p = await casePage(id, PAST_DEADLINE);
  assert.equal(p.status, 200);
  assert.match(p.html, /<h1>Case: SINGLE PARTY<\/h1>/);
  assert.ok(p.html.includes("stored as COMMITTED, past its deadline"));
  assert.equal(p.html.includes("honest-party-account"), false);
  assert.equal(p.html.includes("attacker-account"), false);
  const before = await casePage(id, REVEAL_AT);
  assert.ok(before.html.includes("stored as COMMITTED, not shown"), "before the deadline: the stored status alone");
});

// =============================================================================
// red-team fix B: A RECEIPT IS THE SERVICE'S (lib/_case_seal.js)
// =============================================================================

// A case sealed as the service seals one (the comparison run, the case key
// signing the seal), with its receipt signed by `receiptKey`.
async function sealedWith(scope, receiptKey = RECEIPT_KEY) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  for (const p of [a, b]) assert.equal((await commit(id, p)).status, 201);
  // computed under a document that publishes `receiptKey`
  const compared = RECONCILE.compare(AGENT_TAPE, TOOL_TAPE, { env: { [receipts.SIGNER_ENV]: receiptKey.signer }, now: REVEAL_AT,
    keyDocument: { ...KEYS_DOC, keys: [KEYS_DOC.keys[0], KD.reconcileEntry(receiptKey)] } });
  const st = S.storableReceipt(compared.receipt);
  assert.equal(st.ok, true);
  const sealed = S.sealCase(gh.read(PINS, C.casePath(id)), {
    reveals: { a: { tape_sha256: a.tape_sha256, salt: a.salt }, b: { tape_sha256: b.tape_sha256, salt: b.salt } },
    receipt: st.receipt, crossReference: null, revealedAt: C.utcSeconds(REVEAL_AT), signedUnder: KD.signedUnder(gh, KEYS_DOC, C.utcSeconds(REVEAL_AT)),
  }, S.loadCaseSigner(SIGNED, { keyDocument: KEYS_DOC }));
  gh.seed(PINS, C.casePath(id), sealed);
  return { id, a, b, sealed };
}
const withReceipt = (k, over) => ({ ...k, verdict: { ...k.verdict, ...over } });

test("S10 (receiptSignerReason, the carried verifier first): a receipt naming a verifier that is not one is receipt_unsigned, unknown_signer, never read as malformed", async () => {
  const { sealed } = await sealedWith("S10");
  const odd = withReceipt(sealed, { signer: { ...sealed.verdict.signer, verifier: "not-a-verifier" } });
  assert.equal(S.checkSealedReceipt(odd), null, "fixture: still bound");
  assert.deepEqual(await S.sealedRecordReason(odd, KEYS_DOC), { code: "receipt_unsigned", reason: "unknown_signer" });
  assert.equal(S.checkStoredReceipt(odd, { receiptVerifier: RECEIPT_KEY.verifier }), "receipt_unsigned");
});

test("S12 (checkStoredReceipt): a receipt the service's signer signed and someone altered after is receipt_bad_signature, not receipt_unsigned", async () => {
  const { sealed } = await sealedWith("S12");
  const given = { receiptVerifier: RECEIPT_KEY.verifier };
  assert.equal(S.checkStoredReceipt(sealed, given), null, "control: as sealed");
  const altered = withReceipt(sealed, { verdict: { ...sealed.verdict.verdict, findings: sealed.verdict.verdict.findings + 1 } });
  assert.equal(S.checkStoredReceipt(altered, given), "receipt_bad_signature");
  assert.deepEqual(await S.sealedRecordReason(altered, KEYS_DOC), { code: "verdict_unbound", reason: "receipt_bad_signature" });
});

test("H13 (reference, the words for receipt_unsigned); since Design I its environment does not decide: a case holds under the document it names whatever the deployment's environment", async () => {
  const at = (id, p, env) => {
    const res = makeRes();
    const body = { case_id: id, role: "a", tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: { operator: "second-operator.example", reference: "r-1", url: "https://second-operator.example/r/1" } };
    return H.handleCaseReference(req("case-reference", body), res, { now: REVEAL_AT + 3600000, env, keyDocument: KEYS_DOC }).then(() => res);
  };
  const wrong = await sealedWith("H13", checkpoint.generateKey("arcaeon.io/reconcile-test-other/2026-10-12"));
  const refused = await at(wrong.id, wrong.a, SIGNED);
  assert.equal(refused._status, 409, JSON.stringify(refused._body));
  assert.equal(refused._body.error_code, "receipt_unsigned");
  assert.equal(refused._body.reason, "unknown_signer");
  assert.match(refused._body.error, /the receipt it carries is not signed by this service's reconcile signer/);
  const good = await sealedWith("H11");
  const ok = await at(good.id, good.a, {});
  assert.equal(ok._status, 201, JSON.stringify(ok._body));
});

test("P08 (the page's words for receipt_unsigned): the failed check is named in words, not only by its code", async () => {
  const other = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-10");
  const { id } = await sealedWith("P08", other);
  const p = await casePage(id);
  assert.match(p.html, /SEALED RECORD DOES NOT VERIFY/);
  assert.ok(p.html.includes("the receipt&#39;s signer: the reconcile receipt it carries is not signed by this service&#39;s reconcile signer"), p.html.slice(0, 200));
});
