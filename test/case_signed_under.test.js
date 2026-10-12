// test/case_signed_under.test.js — Design I (2026-10-12): a sealed case
// records the key document it was signed under, and a reader holds it to
// that document, never to whatever document is current.
//
// The defect (GPT-5.6's red-team review, §1.4 and §3.3): the verdict on a
// sealed case changed when the public key document changed. A later
// revocation made an old valid case show DOES NOT VERIFY, a later document
// could make a formerly unverifiable signature verify, and no sealed case
// recorded which document it was signed under.
//
// STEP 1, here: the key document's entries gain a role ("case" |
// "reconcile", absent = "case") and, beside status revoked, revoked_since;
// the reconcile signer must be an active reconcile entry of the document
// the deployment carries (else 503 signer_unavailable, nothing compared);
// the sealed case gains signed_under {document_sha256, document_commit,
// retrieved_at} inside its signed bytes; and the joint reveal, when the
// sealer cannot read its document or its commit, refuses 503
// document_unavailable before anything is compared.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0041:case-test-";
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
const RECONCILE = require("../lib/_reconcile_http.js");
const T = require("../lib/_reconcile_tapes.js");
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const stamp = require("../lib/_stamp.js");
const verifyHandler = require("../api/verify.js");
const { canonicalBytes } = require("../lib/_check_record.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z");
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-12");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-12");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-12");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
// The document a deployment carries: the case key and the reconcile key.
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0041" });

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
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": `10.96.${(ipSeq >> 8) & 255}.${ipSeq & 255}`, ...headers }, body });
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
async function committedCase(scope) {
  const o = makeRes();
  await H.handleCaseOpen(req("case-open", opening(scope), OPEN_AUTH), o, { now: NOW });
  assert.equal(o._status, 201, JSON.stringify(o._body));
  const id = o._body.case_id;
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  for (const p of [a, b]) {
    gh.seed(STAMPS, stamp.stampPath(p.commitment_sha256), { kind: "file-stamp", v: 1, sha256: p.commitment_sha256, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: "2026-10-10T07:45:00.123Z" });
    const r = makeRes();
    await H.handleCaseCommit(req("case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 })), r, { now: NOW });
    assert.equal(r._status, 201, JSON.stringify(r._body));
  }
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
// The reveal on a deployment that carries `doc` (built at commitOf(doc)),
// or exactly `env` and `keyDocument` when `raw` is set.
async function reveal(body, { doc = DOC, env = KEYS, raw = false, keyDocument = doc } = {}) {
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", body), res, { now: REVEAL_AT, env: raw ? env : KD.deployed(gh, env, doc), keyDocument });
  return { status: res._status, body: parsed(res) };
}
const storedCase = (id) => gh.read(PINS, C.casePath(id));

// =============================================================================
// STEP 1: the document's roles, the reconcile key's publication, signed_under
// =============================================================================

test("KEY DOCUMENT ROLES: an entry's role is case or reconcile (absent = case); a revoked entry carries revoked_since, and only a revoked one", () => {
  assert.equal(S.checkKeyDocument(DOC).ok, true);
  assert.equal(S.checkKeyDocument(S.PUBLISHED_KEYS).ok, true, "the committed document, whose entry has no role, still reads");
  const revoked = KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11" });
  assert.equal(S.checkKeyDocument(KD.docWith(revoked, KD.reconcileEntry(RECEIPT_KEY, { status: "revoked", revokedSince: "2026-10-11" }))).ok, true);
  assert.equal(S.checkKeyDocument(KD.docWith(KD.entry(CASE_KEY, { role: "case" }))).ok, true);
  const bad = {
    "malformed_field keys[0].role": KD.docWith(KD.entry(CASE_KEY, { role: "admin" })),
    "malformed_field keys[0].role (not a string)": KD.docWith(KD.entry(CASE_KEY, { role: null })),
    "missing_field keys[0].revoked_since": KD.docWith(KD.entry(CASE_KEY, { status: "revoked" })),
    "malformed_field keys[0].revoked_since": KD.docWith(KD.entry(CASE_KEY, { status: "active", revokedSince: "2026-10-11" })),
    "malformed_field keys[0].revoked_since (not a date)": KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11T00:00:00Z" })),
    "unknown_field keys[0].roles": KD.docWith({ ...KD.entry(CASE_KEY), roles: ["case"] }),
  };
  for (const [want, doc] of Object.entries(bad)) {
    const c = S.checkKeyDocument(doc);
    assert.equal(c.ok, false, want);
    assert.equal(`${c.reason} ${c.at}`, want.replace(/ \(.*\)$/, ""), want);
  }
});

test("A KEY SIGNS ONLY IN ITS ROLE: the case key must be an active case entry, the reconcile key an active reconcile entry", () => {
  assert.equal(S.loadCaseSigner(KEYS, { keyDocument: DOC }).ok, true);
  assert.equal(S.loadReconcileSigner(KEYS, { keyDocument: DOC }).ok, true);
  const swapped = KD.docWith(KD.entry(CASE_KEY, { role: "reconcile" }), KD.entry(RECEIPT_KEY));
  const c = S.loadCaseSigner(KEYS, { keyDocument: swapped });
  assert.equal(c.code, "key_unpublished");
  assert.match(c.reason, /listed .* as a reconcile key, not a case key/);
  const r = S.loadReconcileSigner(KEYS, { keyDocument: swapped });
  assert.equal(r.ok, false);
  assert.match(r.reason, /listed .* as a case key, not a reconcile key/);
  for (const [name, doc, why] of [
    ["unlisted", KD.docWith(KD.entry(CASE_KEY)), /is not listed in/],
    ["retired", KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY, { status: "retired" })), /as retired, not active/],
    ["revoked", KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY, { status: "revoked", revokedSince: "2026-10-11" })), /as revoked, not active/],
    ["another verifier", KD.docWith(KD.entry(CASE_KEY), { ...KD.reconcileEntry(RECEIPT_KEY), verifier: LOG_KEY.verifier }), /does not read/],
    ["no document", null, /does not read/],
  ]) {
    const l = S.loadReconcileSigner(KEYS, { keyDocument: doc });
    assert.equal(l.ok, false, name);
    assert.match(l.reason, why, `${name}: ${l.reason}`);
    assert.ok(!l.reason.includes("PRIVATE"), "never the key");
  }
  assert.equal(S.loadReconcileSigner({}, { keyDocument: DOC }).ok, false, "no key at all");
});

test("RECONCILE FAILS CLOSED: op=reconcile with its key not an active reconcile entry of the document it carries is 503 signer_unavailable and compares nothing; the committed document lists none, so production refuses until one is published", async (t) => {
  const port = t.mock.method(T, "reconcileTapes");
  const body = { agent_tape_b64: AGENT_TAPE.toString("base64"), tool_tape_b64: TOOL_TAPE.toString("base64") };
  const call = async (opts) => {
    const res = makeRes();
    await RECONCILE.handleReconcile(req("reconcile", body), res, opts);
    return { status: res._status, body: parsed(res) };
  };
  for (const [name, doc] of [["no reconcile entry", KD.docWith(KD.entry(CASE_KEY))], ["listed as a case key", KD.docWith(KD.entry(RECEIPT_KEY))],
    ["revoked", KD.docWith(KD.reconcileEntry(RECEIPT_KEY, { status: "revoked", revokedSince: "2026-10-11" }))], ["no document", null]]) {
    const r = await call({ env: KEYS, keyDocument: doc });
    assert.equal(r.status, 503, `${name}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.error_code, "signer_unavailable", name);
    assert.equal(r.body.receipt, undefined, name);
  }
  assert.equal(port.mock.callCount(), 0, "nothing was compared");
  // The committed document, through the real dispatch: the production state.
  assert.equal(S.PUBLISHED_KEYS.keys.some((e) => e.role === "reconcile"), false, "fixture: no reconcile key is published yet");
  process.env[receipts.SIGNER_ENV] = RECEIPT_KEY.signer;
  try {
    const res = makeRes();
    await verifyHandler(req("reconcile", body), res);
    assert.equal(res._status, 503, String(res._body).slice(0, 200));
    assert.equal(parsed(res).error_code, "signer_unavailable");
  } finally {
    delete process.env[receipts.SIGNER_ENV];
  }
  assert.equal(port.mock.callCount(), 0);
  // control: published, it compares and signs
  const ok = await call({ env: KEYS, keyDocument: DOC });
  assert.equal(ok.status, 200, JSON.stringify(ok.body).slice(0, 200));
  assert.equal(ok.body.receipt.signer.verifier, RECEIPT_KEY.verifier);
  assert.equal(port.mock.callCount(), 1);
});

test("SIGNED_UNDER: the sealed case names the document its sealer carried (sha256 of its json-c14n:v1 form), the commit the deployment was built from, and the service time it read it", async () => {
  const { id, a, b } = await committedCase("signed under");
  const r = await reveal(revealBody(id, a, b));
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  const k = storedCase(id);
  assert.deepEqual(k.signed_under, {
    document_sha256: sha(canonicalBytes(DOC)),
    document_commit: KD.commitOf(DOC),
    retrieved_at: C.utcSeconds(REVEAL_AT),
  });
  assert.deepEqual(r.body.case.signed_under, k.signed_under);
  assert.deepEqual(C.validateCase(k), { ok: true });
  // inside the signed bytes: the case signature covers it, and so does the chain
  assert.equal(S.signatureReason(k, CASE_KEY.verifier), null);
  for (const [field, value] of [["document_sha256", "0".repeat(64)], ["document_commit", "1".repeat(40)], ["retrieved_at", "2026-10-10T09:00:01Z"]]) {
    const moved = { ...k, signed_under: { ...k.signed_under, [field]: value } };
    assert.deepEqual(C.validateCase(moved), { ok: true }, field);
    assert.equal(S.signatureReason(moved, CASE_KEY.verifier).reason, "bad_signature", field);
    assert.notEqual(S.caseChain(moved), S.caseChain(k), field);
  }
});

test("SIGNED_UNDER, THE SCHEMA: only a VERDICT carries it, as exactly {document_sha256, document_commit, retrieved_at}; a VERDICT may lack it (it is read as unrecorded)", async () => {
  const { id, a, b } = await committedCase("schema");
  const committed = storedCase(id);
  assert.equal(committed.signed_under, undefined, "an open or committed case carries none");
  const su = { document_sha256: "a".repeat(64), document_commit: "b".repeat(40), retrieved_at: "2026-10-10T09:00:00Z" };
  assert.equal(C.validateCase({ ...committed, signed_under: su }).code, "status_inconsistent");
  assert.equal((await reveal(revealBody(id, a, b))).status, 201);
  const k = storedCase(id);
  const { signed_under: _drop, ...without } = k; // eslint-disable-line no-unused-vars
  assert.deepEqual(C.validateCase(without), { ok: true }, "a VERDICT without it still reads");
  for (const [name, bad] of [
    ["null", null],
    ["extra field", { ...su, document_url: "https://x" }],
    ["missing field", { document_sha256: su.document_sha256, document_commit: su.document_commit }],
    ["short sha256", { ...su, document_sha256: "a".repeat(63) }],
    ["upper-case commit", { ...su, document_commit: "B".repeat(40) }],
    ["a time with a fraction", { ...su, retrieved_at: "2026-10-10T09:00:00.5Z" }],
  ]) {
    const v = C.validateCase({ ...k, signed_under: bad });
    assert.equal(v.ok, false, name);
    assert.match(v.field, /^signed_under/, name);
  }
});

test("DOCUMENT UNAVAILABLE AT THE SEAL: no deployment commit, a malformed one, or a document that does not read is 503 document_unavailable; the comparison never runs and nothing is written", async (t) => {
  const { id, a, b } = await committedCase("unavailable");
  const compare = t.mock.method(RECONCILE, "compare");
  const before = storedCase(id);
  const writes = gh.putLog.length;
  for (const [name, env, keyDocument] of [
    ["no commit", KEYS, DOC],
    ["a short commit", { ...KEYS, [S.DEPLOY_COMMIT_ENV]: "abc123" }, DOC],
    ["an upper-case commit", { ...KEYS, [S.DEPLOY_COMMIT_ENV]: "A".repeat(40) }, DOC],
    ["no document", { ...KEYS, [S.DEPLOY_COMMIT_ENV]: "a".repeat(40) }, null],
    ["a document that does not read", { ...KEYS, [S.DEPLOY_COMMIT_ENV]: "a".repeat(40) }, { ...DOC, schema: "other" }],
  ]) {
    const r = await reveal(revealBody(id, a, b), { raw: true, env, keyDocument });
    assert.equal(r.status, 503, `${name}: ${JSON.stringify(r.body).slice(0, 200)}`);
    assert.equal(r.body.error_code, "document_unavailable", name);
    assert.equal(r.body.verdict, undefined, name);
  }
  assert.equal(compare.mock.callCount(), 0, "the comparison never ran");
  assert.equal(gh.putLog.length, writes, "nothing written");
  assert.deepEqual(storedCase(id), before);
});

test("SEALCASE: a seal is never built without signed_under", async () => {
  const { id } = await committedCase("no signed_under");
  const k = storedCase(id);
  const args = { reveals: { a: { tape_sha256: "1".repeat(64), salt: "2".repeat(64) }, b: { tape_sha256: "3".repeat(64), salt: "4".repeat(64) } },
    receipt: { kind: "x" }, crossReference: null, revealedAt: "2026-10-10T09:00:00Z" };
  assert.throws(() => S.sealCase(k, args, null), (e) => e instanceof C.CaseError && e.field === "signed_under");
});
