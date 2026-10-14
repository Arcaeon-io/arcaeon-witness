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
// "reconcile", absent = "case") and, beside status revoked, revoked_since
// (since unit R-REV a status is active or revoked, and revoked_since is
// gone);
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
const CP = require("../lib/_case_page.js");
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
  S._internal.clearDocumentCache();
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

test("KEY DOCUMENT ROLES: an entry's role is case or reconcile (absent = case); since unit R-REV its status is active or revoked, and revoked_since is an unknown field", () => {
  assert.equal(S.checkKeyDocument(DOC).ok, true);
  assert.equal(S.checkKeyDocument(S.PUBLISHED_KEYS).ok, true, "the committed document, whose entry has no role, still reads");
  const revoked = KD.entry(CASE_KEY, { status: "revoked" });
  assert.equal(S.checkKeyDocument(KD.docWith(revoked, KD.reconcileEntry(RECEIPT_KEY, { status: "revoked" }))).ok, true);
  assert.equal(S.checkKeyDocument(KD.docWith(KD.entry(CASE_KEY, { role: "case" }))).ok, true);
  const bad = {
    "malformed_field keys[0].role": KD.docWith(KD.entry(CASE_KEY, { role: "admin" })),
    "malformed_field keys[0].role (not a string)": KD.docWith(KD.entry(CASE_KEY, { role: null })),
    "malformed_field keys[0].status (retired)": KD.docWith(KD.entry(CASE_KEY, { status: "retired" })),
    "unknown_field keys[0].revoked_since": KD.docWith({ ...KD.entry(CASE_KEY, { status: "revoked" }), revoked_since: "2026-10-11" }),
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
  // since unit R-I (I4) the case key is held apart from the document's
  // reconcile keys first: listed as one, it is the other key, by name
  const c = S.loadCaseSigner(KEYS, { keyDocument: swapped });
  assert.equal(c.code, "case_key_is_other_key");
  assert.match(c.reason, /reconcile key the key document lists/);
  assert.match(S._internal.activeEntry(swapped, KD.keyIdOf(CASE_KEY), CASE_KEY.verifier, "case").reason, /listed .* as a reconcile key, not a case key/);
  const r = S.loadReconcileSigner(KEYS, { keyDocument: swapped });
  assert.equal(r.ok, false);
  assert.match(r.reason, /listed .* as a case key, not a reconcile key/);
  for (const [name, doc, why] of [
    ["unlisted", KD.docWith(KD.entry(CASE_KEY)), /is not listed in/],
    ["retired, no longer a status", KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY, { status: "retired" })), /does not read/],
    ["revoked", KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY, { status: "revoked" })), /as revoked, not active/],
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
    ["revoked", KD.docWith(KD.reconcileEntry(RECEIPT_KEY, { status: "revoked" }))], ["no document", null]]) {
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

// =============================================================================
// STEP 2: a reader holds a sealed case to the document it NAMES
// =============================================================================

const OTHER_KEY = checkpoint.generateKey("arcaeon.io/case-test-unlisted/2026-10-12");
const OTHER_RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test-unlisted/2026-10-12");
const CURRENT_COMMIT = "c".repeat(40);
const revokedIn = (k, role) => (role === "reconcile" ? KD.reconcileEntry(k, { status: "revoked" }) : KD.entry(k, { status: "revoked" }));

async function sealedCase(scope, { doc = DOC, pinFails = false } = {}) {
  const c = await committedCase(scope);
  if (pinFails) gh.forceFailure(PINS, S.pinPaths(c.id).seq, 1, 502);
  const r = await reveal(revealBody(c.id, c.a, c.b), { doc });
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  return { ...c, k: storedCase(c.id), r };
}
// A seal built by hand, as a sealer carrying `named` would have built it,
// with the receipt signed by `receiptKey` and the case by `caseKey` (null:
// unsigned); `named` is served at its commit.
async function handSealed(scope, { named, caseKey = CASE_KEY, receiptKey = RECEIPT_KEY } = {}) {
  const c = await committedCase(scope);
  const compared = RECONCILE.compare(c.a.tape, c.b.tape, { env: { [receipts.SIGNER_ENV]: receiptKey.signer }, now: REVEAL_AT,
    keyDocument: KD.docWith(KD.reconcileEntry(receiptKey)) });
  const st = S.storableReceipt(compared.receipt);
  assert.equal(st.ok, true);
  const signer = caseKey ? { ok: true, keyId: KD.keyIdOf(caseKey), privateKey: checkpoint.parseSignerKey(caseKey.signer).privateKey } : null;
  const k = S.sealCase(storedCase(c.id), {
    reveals: { a: { tape_sha256: c.a.tape_sha256, salt: c.a.salt }, b: { tape_sha256: c.b.tape_sha256, salt: c.b.salt } },
    receipt: st.receipt, crossReference: null, revealedAt: C.utcSeconds(REVEAL_AT), signedUnder: KD.signedUnder(gh, named, C.utcSeconds(REVEAL_AT)),
  }, signer);
  gh.seed(PINS, C.casePath(c.id), k);
  return { ...c, k };
}
async function referenceAs(id, p) {
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt: p.salt,
    cross_reference: { operator: "second-operator.example", reference: "r-1", url: "https://second-operator.example/r/1" } }), res,
  { now: REVEAL_AT + 3600000, env: KEYS, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}

test("VALID UNDER THE DOCUMENT IT NAMES: the reader fetches the named document from the public repository at the named commit, with no credentials, and both signatures verify under it", async () => {
  const { k } = await sealedCase("valid");
  const heard = [];
  S._internal.clearDocumentCache(); // the reveal kept its own reads: a fresh reader
  const viaMock = global.fetch;
  global.fetch = (url, o) => {
    heard.push({ url: String(url), headers: (o && o.headers) || {} });
    return viaMock(url, o);
  };
  let got;
  try {
    got = await S.sealedRecordReason(k, DOC);
  } finally {
    global.fetch = viaMock;
  }
  assert.deepEqual(got, { code: "valid_under_document", ...k.signed_under });
  const raw = heard.filter((h) => h.url.startsWith("https://raw.githubusercontent.com/"));
  assert.deepEqual(raw.map((h) => h.url), [`https://raw.githubusercontent.com/${S.KEY_DOCUMENT_REPO}/${k.signed_under.document_commit}/${S.CASE_KEYS_FILE}`]);
  assert.equal(Object.keys(raw[0].headers).some((h) => /^authorization$/i.test(h)), false, "no credentials");
  // unit R-I (ANCESTRY): and one branch read, that the commit is on the published branch
  const api = heard.filter((h) => h.url.startsWith("https://api.github.com/"));
  assert.deepEqual(api.map((h) => h.url), [`https://api.github.com/repos/${S.KEY_DOCUMENT_REPO}/compare/main...${k.signed_under.document_commit}`]);
  assert.equal(heard.length, raw.length + api.length, "nothing else is read");
  assert.equal(S.sealHolds(got), true);
});

test("THE CURRENT DOCUMENT MUST LIST BOTH KEYS (unit R-I, I3; Design I said the current document does not decide): a later document that drops a key, or lists no key at all, is signer_unlisted; one that lists both active with a note that they no longer sign (rotated out, since unit R-REV) still holds", async () => {
  const { k } = await sealedCase("current");
  for (const [name, current, code] of [
    ["the case key dropped", KD.docWith(KD.reconcileEntry(RECEIPT_KEY)), "signer_unlisted"],
    ["the reconcile key dropped", KD.docWith(KD.entry(CASE_KEY)), "signer_unlisted"],
    ["both rotated out", KD.docWith(KD.entry(CASE_KEY, { note: "rotated out: it no longer signs" }), KD.reconcileEntry(RECEIPT_KEY, { note: "rotated out: it no longer signs" })), "valid_under_document"],
    ["no key at all", KD.docWith(), "signer_unlisted"],
  ]) {
    assert.equal((await S.sealedRecordReason(k, current)).code, code, name);
  }
});

test("REVOKED IN THE NAMED DOCUMENT (by status; since unit R-I retrieved_at is display only and no date is read): a case key the document the case names lists as revoked is case_signature_invalid signer_revoked; a key listed from a later day is active", async () => {
  // revoked in the named document: a sealer carrying that document never
  // signs with it, so it does not verify
  const early = await handSealed("revoked at the seal", { named: KD.docWith(revokedIn(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)) });
  assert.deepEqual(await S.sealedRecordReason(early.k, DOC), { code: "case_signature_invalid", reason: "signer_revoked" });
  // one listed from a later day is active
  const future = await handSealed("listed from a later day", { named: KD.docWith(KD.entry(CASE_KEY, { since: "2026-10-11" }), KD.reconcileEntry(RECEIPT_KEY)) });
  assert.equal((await S.sealedRecordReason(future.k, DOC)).code, "valid_under_document");
  // the reconcile key, revoked at the seal in the named document
  const receipt = await handSealed("receipt key revoked at the seal", { named: KD.docWith(KD.entry(CASE_KEY), revokedIn(RECEIPT_KEY, "reconcile")) });
  assert.deepEqual(await S.sealedRecordReason(receipt.k, DOC), { code: "receipt_unsigned", reason: "signer_not_active" });
  // the sealer refuses it and pins nothing; the reference refuses it
  const run = await S.anchorCase(early.id, { now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.deepEqual(run, { ok: false, code: "case_signature_invalid", reason: "signer_revoked" });
  assert.equal(gh.has(PINS, S.pinPaths(early.id).seq), false);
  assert.equal((await referenceAs(early.id, early.a)).status, 409);
});

test("A LATER DOCUMENT NEVER MAKES A FORMERLY UNVERIFIABLE STORED SIGNATURE VERIFY: a key the named document does not list stays unlisted, whatever the current document lists", async () => {
  const caseUnlisted = await handSealed("case key unlisted", { named: DOC, caseKey: OTHER_KEY });
  const receiptUnlisted = await handSealed("receipt key unlisted", { named: DOC, receiptKey: OTHER_RECEIPT_KEY });
  const before = {
    caseKey: await S.sealedRecordReason(caseUnlisted.k, DOC),
    receiptKey: await S.sealedRecordReason(receiptUnlisted.k, DOC),
  };
  assert.deepEqual(before.caseKey, { code: "case_signature_invalid", reason: "signer_unpublished" });
  assert.deepEqual(before.receiptKey, { code: "receipt_unsigned", reason: "unknown_signer" });
  // a later document lists both keys, active
  const later = KD.docWith(KD.entry(CASE_KEY), KD.entry(OTHER_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.reconcileEntry(OTHER_RECEIPT_KEY));
  assert.deepEqual(await S.sealedRecordReason(caseUnlisted.k, later), before.caseKey);
  assert.deepEqual(await S.sealedRecordReason(receiptUnlisted.k, later), before.receiptKey);
  // and so does the sealer, which pins neither
  for (const c of [caseUnlisted, receiptUnlisted]) {
    const run = await S.anchorCase(c.id, { now: REVEAL_AT + 60000, keyDocument: later });
    assert.equal(run.ok, false, JSON.stringify(run));
    assert.equal(gh.has(PINS, S.pinPaths(c.id).seq), false);
  }
});

test("DOCUMENT UNAVAILABLE: the named commit cannot be fetched (404, 5xx, network): never a yes and never a no; the sealer pins nothing and reports could_not_look, the reference refuses 409 with the reason, and once it can be fetched the next run pins", async () => {
  const { id, a, k } = await sealedCase("unavailable", { pinFails: true });
  S._internal.clearDocumentCache(); // the reveal kept its own matching read: a fresh reader
  const commit = k.signed_under.document_commit;
  const path = S.CASE_KEYS_FILE;
  gh.raw.delete(`${S.KEY_DOCUMENT_REPO}@${commit}:${path}`); // the commit cannot be fetched (404)
  const missing = await S.sealedRecordReason(k, DOC);
  assert.deepEqual(missing, { code: "document_unavailable", reason: "http_404", document: "named", document_commit: commit });
  assert.equal(S.sealHolds(missing), false);
  for (const [status, reason] of [[503, "http_503"], [0, "fetch_failed"]]) {
    KD.serve(gh, DOC);
    gh.forceRawFailure(1, status);
    assert.deepEqual(await S.sealedRecordReason(k, DOC), { code: "document_unavailable", reason, document: "named", document_commit: commit });
  }
  gh.raw.delete(`${S.KEY_DOCUMENT_REPO}@${commit}:${path}`);
  const run = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.deepEqual(run.could_not_look, [{ case_id: id, reason: "http_404" }]);
  assert.deepEqual(run.refused, []);
  assert.deepEqual(run.newly_pinned, []);
  assert.equal(gh.has(PINS, S.pinPaths(id).seq), false, "no pin");
  const ref = await referenceAs(id, a);
  assert.equal(ref.status, 409, JSON.stringify(ref.body));
  assert.equal(ref.body.error_code, "document_unavailable");
  assert.equal(ref.body.reason, "http_404");
  // the page: could not look, 503, neither the verdict nor DOES NOT VERIFY
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": "10.97.0.1" } }), res,
    { now: REVEAL_AT + 3600000, keyDocument: DOC, env: {} });
  const html = String(res._body);
  assert.equal(res._status, 503);
  assert.match(html, /<h1>Case: COULD NOT LOOK<\/h1>/);
  assert.ok(html.includes(commit) && html.includes("http_404"));
  assert.ok(!html.includes("<h2>The verdict</h2>") && !html.includes("SEALED RECORD DOES NOT VERIFY"));
  // the document is back: the next run pins
  KD.serve(gh, DOC);
  const again = await S.anchorPending({ now: REVEAL_AT + 120000, keyDocument: DOC });
  assert.deepEqual(again.newly_pinned, [id]);
  assert.deepEqual(again.could_not_look, []);
});

test("THE DOCUMENT AT THE COMMIT MUST BE THE ONE NAMED: other bytes at the named commit, or a file there that is not a key document, is case_signature_invalid", async () => {
  const { k } = await sealedCase("named");
  S._internal.clearDocumentCache(); // the reveal kept its own matching read: a fresh reader
  const commit = k.signed_under.document_commit;
  KD.serve(gh, KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.entry(OTHER_KEY)), commit);
  assert.deepEqual(await S.sealedRecordReason(k, DOC), { code: "case_signature_invalid", reason: "document_sha256_mismatch" });
  // a seal that names, by its true sha256, a document that is not a key document
  const odd = await handSealed("named unreadable", { named: { ...DOC, schema: "other" } });
  assert.deepEqual(await S.sealedRecordReason(odd.k, DOC), { code: "case_signature_invalid", reason: "named_document_unreadable" });
  S._internal.clearDocumentCache();
  gh.seedRaw(S.KEY_DOCUMENT_REPO, commit, S.CASE_KEYS_FILE, "<html>not json</html>");
  assert.deepEqual(await S.sealedRecordReason(k, DOC), { code: "document_unavailable", reason: "not_json", document: "named", document_commit: commit });
});

test("THE NAMED DOCUMENT IS FETCHED ONCE PER COMMIT: a commit's document never changes, so a read is cached; a failed read is not", async () => {
  const { k } = await sealedCase("cache");
  S._internal.clearDocumentCache(); // the reveal kept its own matching read: a fresh reader
  const commit = k.signed_under.document_commit;
  gh.forceRawFailure(1, 500);
  assert.equal((await S.sealedRecordReason(k, DOC)).code, "document_unavailable");
  assert.equal((await S.sealedRecordReason(k, DOC)).code, "valid_under_document", "a failure is not remembered");
  const reads = gh.rawLog.length;
  assert.equal((await S.sealedRecordReason(k, DOC)).code, "valid_under_document");
  assert.equal(gh.rawLog.length, reads, "the second good read fetched nothing");
  assert.ok(gh.rawLog.every((x) => x.includes(commit)));
});

test("AN UNREADABLE CURRENT DOCUMENT: whether a key was since revoked cannot be told, so it is could-not-look (document_unavailable), never a yes", async () => {
  const { k } = await sealedCase("current unreadable");
  assert.deepEqual(await S.sealedRecordReason(k, null), { code: "document_unavailable", reason: "current_document_unreadable", document: "current", document_commit: k.signed_under.document_commit });
});

// =============================================================================
// STEP 3: the page says which document and which pin
// =============================================================================

async function pageOf(id, { keyDocument = DOC, env = {} } = {}) {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": `10.98.0.${(ipSeq += 1) & 255}` } }), res,
    { now: REVEAL_AT + 3600000, keyDocument, env });
  return { status: res._status, html: String(res._body) };
}
const verdictWord = (html) => {
  const m = /<span class="word (?:pass|fail)?">([A-Z ]+)<\/span>/.exec(html.slice(html.indexOf("<h2>The verdict</h2>")));
  return m ? m[1] : null;
};

test("THE PAGE NAMES ITS DOCUMENT AND ITS PIN: sealed under document <sha256> at commit <W> (a link to the document there), since unit R-PIN \"Pinned at commit <P> (the pins repository's commit time, T)\"; retrieved_at is labelled service clock, unverified", async () => {
  const { id, k } = await sealedCase("page names");
  const su = k.signed_under;
  const p = await pageOf(id);
  assert.equal(p.status, 200);
  assert.ok(p.html.includes(`sealed under document <code>${su.document_sha256.slice(0, 16)}</code> at commit`), "the document, by its sha256");
  assert.ok(p.html.includes(`href="https://github.com/${S.KEY_DOCUMENT_REPO}/blob/${su.document_commit}/${S.CASE_KEYS_FILE}"`), "a link to the document at that commit");
  assert.ok(p.html.includes(`>${su.document_commit.slice(0, 12)}<`));
  assert.ok(p.html.includes(`${su.retrieved_at} (service clock, unverified)`));
  const pinCommits = gh.commitsFor(PINS, S.pinPaths(id).seq);
  assert.equal(pinCommits.length, 1, "fixture: the numbered pin record was written once");
  const P = pinCommits[0];
  assert.ok(p.html.includes(`Pinned at commit <a href="https://github.com/${store.REPO}/commit/${P.sha}"`), "the pin's commit, linked");
  assert.ok(p.html.includes(`(the pins repository&#39;s commit time, ${P.date})`), "with the repository's commit time");
  assert.equal(verdictWord(p.html), "MATCHED");
});

test("THE PAGE, NOT PINNED YET, OR A PIN COMMIT IT CANNOT READ: it says so, and still shows the verdict", async () => {
  const pending = await sealedCase("page pending", { pinFails: true });
  const p = await pageOf(pending.id);
  assert.ok(p.html.includes("Not pinned: no pin file is present under this case's namespace (not_pinned)."), "no pin, no pin commit");
  assert.equal(verdictWord(p.html), "MATCHED");
  const pinned = await sealedCase("page pin unreadable");
  gh.forceCommitsFailure(PINS, S.pinPaths(pinned.id).seq, 1, 500);
  const q = await pageOf(pinned.id);
  // Design J: a pin whose commit cannot be read is could_not_look, no claim,
  // and the cell says which read failed
  assert.ok(q.html.includes("could_not_look: the commit that wrote its pin record could not be read when this page was read (pin_commit_unreadable), so the case is not shown as pinned."));
  assert.equal(verdictWord(q.html), "MATCHED");
});

test("THE VERDICT WORD NEVER CHANGES ON A LATER DOCUMENT: whatever the current document says of the two keys, a sealed case shows the word it was sealed with, or (since unit R-I, a key it no longer lists; since unit R-REV, a key it lists revoked) no verdict at all; never another word", async () => {
  const { id } = await sealedCase("word stays");
  const sealedWord = verdictWord((await pageOf(id)).html);
  assert.equal(sealedWord, "MATCHED");
  const rotated = { note: "rotated out: it no longer signs" };
  for (const [name, later, heading] of [
    ["the case key dropped", KD.docWith(KD.reconcileEntry(RECEIPT_KEY)), /SEALED RECORD DOES NOT VERIFY/],
    ["both rotated out", KD.docWith(KD.entry(CASE_KEY, rotated), KD.reconcileEntry(RECEIPT_KEY, rotated)), null],
    ["both revoked", KD.docWith(revokedIn(CASE_KEY), revokedIn(RECEIPT_KEY, "reconcile")), /SIGNED BY A REVOKED KEY/],
    ["no key at all", KD.docWith(), /SEALED RECORD DOES NOT VERIFY/],
    ["another key added", KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.entry(OTHER_KEY)), null],
  ]) {
    const p = await pageOf(id, { keyDocument: later });
    assert.equal(p.status, 200, name);
    assert.equal(verdictWord(p.html), heading ? null : sealedWord, name);
    if (heading) assert.match(p.html, heading, name);
  }
});

// =============================================================================
// STEP 5: a seal that names no document is document_unrecorded
// =============================================================================

// A seal as a build before Design I wrote one: no signed_under, signed by
// the case key over the bytes it does have (or unsigned).
async function unrecordedCase(scope, { signed = true } = {}) {
  const { id, a, k } = await sealedCase(scope, { pinFails: true });
  const { signed_under: _gone, ...old } = k; // eslint-disable-line no-unused-vars
  const signer = signed ? S.loadCaseSigner(KEYS, { keyDocument: DOC }) : { ok: false, code: "case_key_unset", reason: "no case signing key is configured" };
  const rec = S.signCase(old, signer);
  assert.deepEqual(C.validateCase(rec), { ok: true }, "fixture: the schema reads it");
  assert.equal(rec.signed_under, undefined);
  gh.seed(PINS, C.casePath(id), rec);
  return { id, a, rec };
}

test("DOCUMENT UNRECORDED: a sealed case with no signed_under is document_unrecorded under every current document, signed or not; never valid_under_document", async () => {
  let reads = 0;
  for (const signed of [true, false]) {
    const { rec } = await unrecordedCase(`unrecorded ${signed}`, { signed });
    const n = gh.rawLog.length + gh.compareLog.length; // the reveal that made the fixture read its own document
    for (const current of [DOC, KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY), KD.entry(OTHER_KEY)), KD.docWith(), null]) {
      const answer = await S.sealedRecordReason(rec, current);
      assert.deepEqual(answer, { code: "document_unrecorded", reason: "no_signed_under" }, `signed ${signed}`);
      assert.equal(S.sealHolds(answer), false);
    }
    reads += gh.rawLog.length + gh.compareLog.length - n;
  }
  assert.equal(reads, 0, "no document is fetched for a case that names none");
});

test("DOCUMENT UNRECORDED, THE READERS: the page shows the record as not verifying and says why in words, the sealer does not pin it, and the reference refuses it 409", async () => {
  const { id, a } = await unrecordedCase("unrecorded readers");
  const p = await pageOf(id);
  assert.equal(p.status, 200);
  assert.match(p.html, /<h1>Case: SEALED RECORD DOES NOT VERIFY<\/h1>/);
  assert.ok(p.html.includes("document_unrecorded"));
  assert.ok(p.html.includes("the key document: the record names none it was sealed under, so it cannot be held to one"));
  assert.equal(p.html.includes("<h2>The verdict</h2>"), false);
  assert.deepEqual(await S.anchorCase(id, { now: REVEAL_AT + 60000, keyDocument: DOC }), { ok: false, code: "document_unrecorded", reason: "no_signed_under" });
  const run = await S.anchorPending({ now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.deepEqual(run.refused, [{ case_id: id, code: "document_unrecorded", reason: "no_signed_under" }]);
  assert.equal(gh.has(PINS, S.pinPaths(id).seq), false, "no pin");
  const ref = await referenceAs(id, a);
  assert.equal(ref.status, 409, JSON.stringify(ref.body));
  assert.equal(ref.body.error_code, "document_unrecorded");
  assert.match(ref.body.error, /it names no key document it was signed under/);
});

// =============================================================================
// THE MUST-FAIL PASS OVER DESIGN I (harness not committed): the gaps it found
// =============================================================================
// 84 defects planted, one at a time, in the code Design I added or changed:
// lib/_case.js (9), lib/_reconcile_http.js (2), lib/_case_http.js (9),
// lib/_case_seal.js (42), lib/_case_page.js (15), lib/_sealer.js (1) and
// tools/preview_dry_run.js (6). 72 were caught by the suite with Design I's
// own tests. Of the 12 that survived, 11 are closed by the tests below (two
// of them, T06 and T07, in test/preview_dry_run.test.js) and one is
// equivalent:
//   - H08, lib/_case_http.js ?op=case-reference not passing its own commit
//     to the sealed check: the reference reads only an answer's code and
//     reason, and current_commit appears only in signer_since_revoked,
//     which it accepts without reading further.

const sealer = require("../lib/_sealer.js");

test("K06 (checkSignedUnder): a signed_under missing a field is missing_field, named", async () => {
  const { k } = await sealedCase("K06");
  for (const f of C.SIGNED_UNDER_FIELDS) {
    const { [f]: _gone, ...rest } = k.signed_under; // eslint-disable-line no-unused-vars
    const v = C.validateCase({ ...k, signed_under: rest });
    assert.deepEqual([v.code, v.field], ["missing_field", `signed_under.${f}`], f);
  }
});

test("H09 (reference, the words for document_unavailable): the refusal says the document could not be read, and that this is not a no", async () => {
  const { id, a, k } = await sealedCase("H09");
  S._internal.clearDocumentCache(); // the reveal kept its own matching read: a fresh reader
  gh.raw.delete(`${S.KEY_DOCUMENT_REPO}@${k.signed_under.document_commit}:${S.CASE_KEYS_FILE}`);
  const ref = await referenceAs(id, a);
  assert.equal(ref.status, 409);
  assert.match(ref.body.error, /the key document it names could not be read on this request, which is not a no/);
});

test("S21, S24 (the sealed check, each key in its role): a receipt key the named document lists only as a case key, or a case key it lists only as a reconcile key, does not count", async () => {
  const receiptAsCase = await handSealed("S21", { named: KD.docWith(KD.entry(CASE_KEY), KD.entry(RECEIPT_KEY)) });
  assert.deepEqual(await S.sealedRecordReason(receiptAsCase.k, DOC), { code: "receipt_unsigned", reason: "unknown_signer" });
  const caseAsReconcile = await handSealed("S24", { named: KD.docWith(KD.reconcileEntry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)) });
  assert.deepEqual(await S.sealedRecordReason(caseAsReconcile.k, DOC), { code: "case_signature_invalid", reason: "signer_unpublished" });
});

test("S32, SINCE UNIT R-REV: the revoked page names V, the commit of the key document this deployment carries, as a link; a deployment whose commit is not 40 hex, or not set, says it is not known and never prints what it names", async () => {
  const { id } = await sealedCase("S32");
  const revoked = KD.docWith(revokedIn(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY));
  const named = await pageOf(id, { keyDocument: revoked, env: { [S.DEPLOY_COMMIT_ENV]: CURRENT_COMMIT } });
  assert.ok(named.html.includes(`(commit <a href="https://github.com/${S.KEY_DOCUMENT_REPO}/blob/${CURRENT_COMMIT}/${S.CASE_KEYS_FILE}" ` +
    `rel="nofollow noopener noreferrer">${CURRENT_COMMIT.slice(0, 12)}</a>)`), "V, linked");
  for (const env of [{ [S.DEPLOY_COMMIT_ENV]: "<script>" }, {}]) {
    const p = await pageOf(id, { keyDocument: revoked, env });
    assert.ok(p.html.includes("(commit not known to this deployment)"), JSON.stringify(env));
    assert.ok(!p.html.includes("<script>"), "never what a malformed commit names");
  }
});

test("S44 (checkStoredReceipt): with no verifier given it refuses every signed receipt, even where the environment names one", async () => {
  const { k } = await sealedCase("S44");
  process.env[receipts.VERIFIER_ENV] = RECEIPT_KEY.verifier;
  process.env[receipts.SIGNER_ENV] = RECEIPT_KEY.signer;
  try {
    assert.equal(S.checkStoredReceipt(k), "receipt_unsigned");
    assert.equal(S.checkStoredReceipt(k, { receiptVerifier: RECEIPT_KEY.verifier }), null, "control: given, it holds");
  } finally {
    delete process.env[receipts.VERIFIER_ENV];
    delete process.env[receipts.SIGNER_ENV];
  }
});

test("P03 (pinCommitOf): the page names the commit that WROTE the numbered pin record, the oldest touching it, not a later one", async () => {
  const { id } = await sealedCase("P03");
  const seq = S.pinPaths(id).seq;
  const wrote = gh.commitsFor(PINS, seq)[0];
  const later = gh.addCommit(PINS, seq, "mock: a later commit touching the pin record");
  assert.deepEqual(gh.commitsFor(PINS, seq).map((c) => c.sha), [later, wrote.sha], "fixture: newest first");
  const p = await pageOf(id);
  assert.ok(p.html.includes(`/commit/${wrote.sha}"`), "the commit that wrote it");
  assert.ok(!p.html.includes(`/commit/${later}"`));
});

test("P13 (the page's reads): a case not pinned yet reads no pin commit history", async () => {
  const { id } = await sealedCase("P13", { pinFails: true });
  const before = gh.commitsLog.length;
  const p = await pageOf(id);
  assert.ok(p.html.includes("Not pinned: no pin file is present"));
  // (since unit R-L2, B2: the page reads the registration paths' histories for removals, and no pin's)
  assert.deepEqual(gh.commitsLog.slice(before).filter((k) => !/cases\/[0-9a-f]{64}\/commit_[ab]\.json/.test(String(k))), [], "no pin's commits listing");
});

test("L01 (lib/_sealer.js anchorCases): the current document it is handed is the one the pass reads; an unreadable one is could_not_look, not a pin", async () => {
  const { id } = await sealedCase("L01", { pinFails: true });
  const run = await sealer.anchorCases({ now: new Date(REVEAL_AT + 60000), keyDocument: { ...DOC, extra: true } });
  assert.deepEqual(run.could_not_look, [{ case_id: id, reason: "current_document_unreadable" }]);
  assert.deepEqual(run.newly_pinned, []);
  assert.equal(gh.has(PINS, S.pinPaths(id).seq), false);
});
