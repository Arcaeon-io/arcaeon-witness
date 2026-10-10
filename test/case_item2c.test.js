// test/case_item2c.test.js — the case protocol, item 2c
// (CASE_PROTOCOL_DESIGN_2026-10-10.md, "After item 2b"): the six fixes after
// the GPT-5.6 and Gemini 3.1 Pro reviews of 2b (with GPT's two planted
// tests), authorized withdrawal (design test 10 and the real race), the
// addendum row (design test 11), the per-key open quota, and the public
// case page.
//
//   FIX 1  anchorCase verifies the stored case's own signature under the
//          verifier its signed_by names in the key document: a replaced sig
//          is case_signature_invalid, no pin (GPT's planted test).
//   FIX 2  signing fails closed unless the key is an ACTIVE entry of the
//          committed key document: three valid distinct keys, a document
//          without the case key, and the seal is unsigned, key_unpublished
//          (GPT's planted test).
//   FIX 3  the status row counts from the tree alone and says partial when
//          the tree came back truncated.
//   FIX 4  the key document checker refuses an unknown top-level field.
//   FIX 5  the sealer's window keeps pinned cases and reports a squatter or
//          an unreadable pin.
//   FIX 6  the sealer skips terminal root states: a withdrawn marker by the
//          tree alone, an expired or withdrawn root after one read.
//
// Item 2d (test/case_item2d.test.js) changed two fixtures here and one
// expectation. Fixtures: the operator's key is WITNESS_CASE_OPERATOR_KEY
// (OPERATOR_ENV below, and the env deleted at the top), no longer
// WITNESS_ADMIN_KEY. Expectation: the page test's real-dispatch arm, where
// a case signed by the test key is read against the committed key document,
// which lists no key. 2c rendered its verdict with "not listed in the key
// document"; since 2d the case page holds a VERDICT to the sealed check, so
// that case shows the does-not-verify state (signer_unpublished). The
// verdict assertions moved to the arm whose document lists the key, and an
// unsigned seal now carries "a verdict through the real dispatch".
//
// The fixtures are 2a's and 2b's (the same tape pair, opening, party and
// stamp helpers), repeated because a test file cannot require another test
// file without running it. Each test plants the failure it exists to catch;
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
// Two env keys: the open quota is per key, so one test needs a second.
process.env.WITNESS_KEYS = "case-test-open-key-0004:case-test-,case-test-open-key-0005:case-test2-";
delete process.env.WITNESS_BATCH_SHADOW;
delete process.env.WITNESS_ADMIN_KEY;
delete process.env.WITNESS_CASE_OPERATOR_KEY;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const S = require("../lib/_case_seal.js");
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const sealer = require("../lib/_sealer.js");
const stamp = require("../lib/_stamp.js");
const { gatherStatusData } = require("../lib/_status_data.js");
const statusHandler = require("../api/status.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const ROOT = path.join(__dirname, "..");
const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z"); // open and register
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-10");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-10");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-10");
const LOG_ENV = "WITNESS_LOG_SIGNER_KEY";
const SIGNED = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, [LOG_ENV]: LOG_KEY.signer });
const CASE_KEY_ID = CASE_KEY.verifier.split("+").slice(0, 2).join("+");
const ENTRY = Object.freeze({ key_id: CASE_KEY_ID, verifier: CASE_KEY.verifier, since: "2026-10-10", note: "the test environment's case key", status: "active" });
// The committed document lists the production case key (item 3b), never
// this test's; the signing tests hand the seal a copy that lists the test key
// (lib/_case_seal.js, PUBLICATION FAILS CLOSED), and the tests that need "a
// document without the case key" hand it a copy that lists no key at all.
const KEYS_DOC = Object.freeze({ ...S.PUBLISHED_KEYS, keys: [ENTRY] });
const NO_KEYS_DOC = Object.freeze({ ...S.PUBLISHED_KEYS, keys: Object.freeze([]) });
// The production case key's public entry, as item 3b committed it.
const PRODUCTION_KEY_ID = "case-2026-10+295a9a61";
const OPEN_KEY = "case-test-open-key-0004";
const OPEN_AUTH = Object.freeze({ authorization: `Bearer ${OPEN_KEY}` });

function pairNamed(re) {
  const c = reconcileFixtures.cases.find((x) => re.test(x.name) && x.python);
  assert.ok(c, String(re));
  return [Buffer.from(c.a_b64, "base64"), Buffer.from(c.b_b64, "base64")];
}
const [AGENT_TAPE, TOOL_TAPE] = pairNamed(/^receipt-test_call_proxy_tape\/test_cross_repo_adapter_tape_a0: agent vs tool$/);

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
  return `10.55.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
}
function req(op, body, headers) {
  const auth = headers === undefined ? (op === "case-open" ? OPEN_AUTH : {}) : headers;
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": freshIp(), ...auth }, body });
}
function parsed(res) {
  return typeof res._body === "string" ? JSON.parse(res._body) : res._body;
}

const AGENT = Object.freeze({ side: "agent", label: "agent-operator@example.com" });
const TOOL = Object.freeze({ side: "tool", label: "tool-operator@example.com" });
function opening(over = {}) {
  return {
    protocol_version: "case/1",
    policy_version: C.SUPPORTED_POLICY_VERSION,
    scope_digest: sha("the scope manifest both parties agreed"),
    party_a: { ...AGENT },
    party_b: { ...TOOL },
    opened_at: "2026-10-10T07:30:00Z",
    deadline: DEADLINE,
    ...over,
  };
}
function plantStamp(hash, stampedAt = "2026-10-10T07:45:00.123Z") {
  gh.seed(STAMPS, stamp.stampPath(hash), { kind: "file-stamp", v: 1, sha256: hash, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: stampedAt });
}
function party(caseId, role, tape, salt = C.newSalt()) {
  const tape_sha256 = sha(tape);
  return { role, tape, tape_sha256, salt, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
}
async function call(handler, op, body, now, headers, extra = {}) {
  const res = makeRes();
  await handler(req(op, body, headers), res, { now, ...extra });
  return res;
}
async function openCase(over, now = NOW) {
  const o = await call(H.handleCaseOpen, "case-open", opening(over), now);
  assert.equal(o._status, 201, JSON.stringify(o._body));
  return o._body.case_id;
}
async function register(id, p, now = NOW) {
  plantStamp(p.commitment_sha256);
  const r = await call(H.handleCaseCommit, "case-commit", { case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 }, now);
  assert.equal(r._status, 201, JSON.stringify(r._body));
}
async function committedCase({ over } = {}) {
  const id = await openCase(over);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  for (const p of [a, b]) await register(id, p);
  assert.equal(storedCase(id).status, "COMMITTED");
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
async function reveal(body, { now = REVEAL_AT, env = SIGNED, keyDocument = KEYS_DOC } = {}) {
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", body), res, { now, env, keyDocument });
  return { status: res._status, body: parsed(res) };
}
async function sealedCase({ over, env = SIGNED, pinFails = false, keyDocument = KEYS_DOC, extra } = {}) {
  const c = await committedCase({ over });
  if (pinFails) gh.forceFailure(PINS, S.pinPaths(c.id).seq, 1, 502);
  const r = await reveal(revealBody(c.id, c.a, c.b, extra), { env, keyDocument });
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.pin, pinFails ? "pending" : "anchored");
  return { ...c, r };
}
function storedCase(id) {
  return gh.read(PINS, C.casePath(id));
}
function pinFilesOf(id) {
  return [...gh.repos.get(PINS).keys()].filter((p) => p.startsWith(`pins/case/${id}/`));
}

// =============================================================================
// FIX 1: anchorCase verifies the stored case's own signature
// =============================================================================

test("FIX 1 (GPT's planted test): a signed case sealed with a failed pin, its sig alone replaced, is refused case_signature_invalid by anchorCase and no pin is written", async () => {
  const { id } = await sealedCase({ pinFails: true });
  const good = storedCase(id);
  assert.equal(typeof good.sig, "string", "fixture: the case is signed");
  assert.equal(good.signed_by, CASE_KEY_ID);
  assert.deepEqual(pinFilesOf(id), [], "fixture: sealed, no pin yet");
  // Only sig is replaced, by a well-formed Ed25519 signature of other bytes
  // made with the right key: everything else is the sealed case.
  const k = checkpoint.parseSignerKey(CASE_KEY.signer);
  const forged = { ...good, sig: crypto.sign(null, Buffer.from("other bytes"), k.privateKey).toString("base64") };
  assert.deepEqual(C.validateCase(forged), { ok: true }, "fixture: schema-valid");
  assert.equal(S.checkStoredReceipt(forged), null, "fixture: the receipt still binds");
  gh.seed(PINS, C.casePath(id), forged);
  const writes = gh.putLog.length;
  const got = await S.anchorCase(id, { now: REVEAL_AT + 60000, keyDocument: KEYS_DOC });
  assert.equal(got.ok, false);
  assert.equal(got.code, "case_signature_invalid", JSON.stringify(got));
  assert.equal(got.reason, "bad_signature");
  assert.equal(gh.putLog.length, writes, "no write");
  assert.deepEqual(pinFilesOf(id), [], "no pin");
  // and through the sealer's run: refused, reported, no pin
  const run = await sealer.sealOnce({ now: new Date(REVEAL_AT + 120000), keyDocument: KEYS_DOC });
  assert.deepEqual(run.cases.refused, [{ case_id: id, code: "case_signature_invalid", reason: "bad_signature" }]);
  assert.deepEqual(pinFilesOf(id), []);

  // The signer the case names must be in the document, and not revoked.
  gh.seed(PINS, C.casePath(id), good);
  for (const [name, doc, reason] of [
    ["the committed document (no key)", undefined, "signer_unpublished"],
    ["revoked", { ...KEYS_DOC, keys: [{ ...ENTRY, status: "revoked" }] }, "signer_revoked"],
    ["unreadable", { ...KEYS_DOC, extra: true }, "key_document_unreadable"],
  ]) {
    const r = await S.anchorCase(id, { now: REVEAL_AT + 60000, keyDocument: doc });
    assert.equal(r.code, "case_signature_invalid", name);
    assert.equal(r.reason, reason, name);
  }
  assert.deepEqual(pinFilesOf(id), [], "none of them pinned");
  // MUST-FAIL ARM: 2b's retry checked the receipt only, which passes the
  // forged case, so only the signature check stood between it and a pin.
  assert.equal(S.checkStoredReceipt(forged), null);
  // control: the case as sealed anchors, under a retired key too (a
  // retired key's cases stay trusted: the document's status_meaning)
  const retired = await S.anchorCase(id, { now: REVEAL_AT + 60000, keyDocument: { ...KEYS_DOC, keys: [{ ...ENTRY, status: "retired" }] } });
  assert.equal(retired.ok, true, JSON.stringify(retired));
  assert.equal(retired.pin, "anchored");
  assert.equal(retired.chain, S.caseChain(good));
});

test("FIX 1: an unsigned seal is still a seal and anchors with no signature to check", async () => {
  const { id } = await sealedCase({ pinFails: true, env: { [receipts.SIGNER_ENV]: RECEIPT_KEY.signer } });
  assert.equal(storedCase(id).sig, null);
  const r = await S.anchorCase(id, { now: REVEAL_AT + 60000 });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.pin, "anchored");
});

// =============================================================================
// FIX 2: signing fails closed unless the key is an active published entry
// =============================================================================

test("FIX 2 (GPT's planted test): three valid distinct signer keys configured and a key document without the case key: the reveal seals UNSIGNED, key_unpublished", async () => {
  // the three keys are distinct and valid, so separation holds
  const loaded = S.loadCaseSigner(SIGNED, { keyDocument: NO_KEYS_DOC });
  assert.equal(loaded.ok, false);
  assert.equal(loaded.code, "key_unpublished");
  assert.equal(loaded.privateKey, undefined, "an unpublished key is not handed out");
  assert.equal(loaded.keyId, CASE_KEY_ID, "its public half is, for the entry");
  assert.deepEqual(NO_KEYS_DOC.keys, [], "fixture: the injected document lists no key");
  assert.equal(S.checkKeyDocument(NO_KEYS_DOC).ok, true, "fixture: and reads as a key document");
  const { id, r } = await sealedCase({ keyDocument: NO_KEYS_DOC });
  const k = storedCase(id);
  assert.equal(k.sig, null, "never signed");
  assert.equal(k.signed_by, null);
  assert.match(k.sig_reason, /^This case is sealed and not signed \(key_unpublished\): /);
  assert.ok(!k.sig_reason.includes("PRIVATE") && !k.sig_reason.includes(CASE_KEY.verifier.split("+").slice(2).join("+")), "the reason never quotes a key");
  assert.equal(r.body.sealed_by, null);
  // with no keyDocument at all, the default is the committed document, which
  // lists the production key and not this test's
  const plain = await committedCase({ over: { scope_digest: sha("default document") } });
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", revealBody(plain.id, plain.a, plain.b)), res, { now: REVEAL_AT, env: SIGNED });
  assert.equal(res._status, 201);
  assert.match(storedCase(plain.id).sig_reason, /\(key_unpublished\)/);
  // the other ways a key is not an active entry
  for (const [name, doc, why] of [
    ["retired", { ...KEYS_DOC, keys: [{ ...ENTRY, status: "retired" }] }, /listed .* as retired, not active/],
    ["revoked", { ...KEYS_DOC, keys: [{ ...ENTRY, status: "revoked" }] }, /as revoked, not active/],
    ["a document that does not read", { ...KEYS_DOC, keys: [{ ...ENTRY, note: "" }] }, /does not read/],
    ["no document", null, /does not read/],
  ]) {
    const l = S.loadCaseSigner(SIGNED, { keyDocument: doc });
    assert.equal(l.code, "key_unpublished", name);
    assert.match(l.reason, why, name);
  }
  // separation is still checked first: its codes keep their precedence
  assert.equal(S.loadCaseSigner({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer }, { keyDocument: KEYS_DOC }).code, "key_separation_unverifiable");
  // MUST-FAIL ARM: listed as active, the same three keys sign
  const ok = S.loadCaseSigner(SIGNED, { keyDocument: KEYS_DOC });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.entry, ENTRY);
  const signed = await sealedCase({ over: { scope_digest: sha("published") } });
  assert.equal(storedCase(signed.id).signed_by, CASE_KEY_ID);
  assert.equal(S.publishedSignatureReason(storedCase(signed.id), KEYS_DOC), null, "and the document confirms the signature");
});

test("FIX 2: the committed key document is loaded with require() at module load, frozen, and is the default", () => {
  const src = fs.readFileSync(path.join(ROOT, "lib", "_case_seal.js"), "utf-8");
  assert.ok(src.includes('require("../public/.well-known/arcaeon/case-signing-keys.json")'), "a require, so the function bundle carries it");
  const onDisk = JSON.parse(fs.readFileSync(path.join(ROOT, ...S.CASE_KEYS_FILE.split("/")), "utf-8"));
  assert.deepEqual(S.PUBLISHED_KEYS, onDisk);
  assert.ok(Object.isFrozen(S.PUBLISHED_KEYS) && Object.isFrozen(S.PUBLISHED_KEYS.keys), "frozen: nothing can change the trust anchor at runtime");
  assert.throws(() => { S.PUBLISHED_KEYS.keys.push(ENTRY); }, TypeError);
  assert.equal(S.loadCaseSigner(SIGNED).code, "key_unpublished", "the default is the committed document");
});

// =============================================================================
// FIX 3: the status row counts from the tree alone, and says partial
// =============================================================================

function healthyBoard(t) {
  const realReachable = store.repoReachable;
  store.repoReachable = async () => true;
  t.after(() => {
    store.repoReachable = realReachable;
  });
  const now = Date.now();
  gh.seed(PINS, "pins/acme-prod/latest.json", { namespace: "acme-prod", rows: 40, chain: "cafebabe", seq: 1, pinned_at: new Date(now - 60000).toISOString(),
    cadence_hours: 24, next_pin_due_by: new Date(now + 3600e3).toISOString() });
  const day = new Date(now).toISOString().slice(0, 10);
  gh._repoMap(PINS).set(`anchors/${day}-head.txt`, { content: `${"a".repeat(40)} ${new Date(now - 3600e3).toISOString()}\n`, sha: "f".repeat(40) });
}

test("FIX 3: the status row reads no case file and no pin; a truncated tree makes it partial on the page and in the JSON; getTree carries truncated", async (t) => {
  healthyBoard(t);
  await sealedCase();
  await sealedCase({ over: { scope_digest: sha("pending") }, pinFails: true });
  const w = await committedCase({ over: { scope_digest: sha("withdrawn by marker") } });
  gh.seed(PINS, C.withdrawnMarkerPath(w.id), { case_id: w.id });
  const reads = gh.getLog.length;
  const d = await gatherStatusData();
  assert.ok(!gh.getLog.slice(reads).some((p) => p.startsWith("cases/") || p.startsWith("pins/case/")), "no case file, no case pin read");
  assert.deepEqual(d.caseAnchors, { case_files: 3, anchored: 1, pending: 1, withdrawn: 1, partial: false });

  // the mock tree, marked truncated
  gh.treeTruncated = true;
  const tree = await store.getTree();
  assert.equal(tree.truncated, true, "getTree surfaces the flag");
  assert.ok(!Object.keys(tree).includes("truncated"), "as a non-enumerable property: the entries are what every caller reads");
  const dp = await gatherStatusData();
  assert.equal(dp.caseAnchors.partial, true);
  assert.equal(dp.overallOk, d.overallOk, "the row still feeds no verdict");
  const html = makeRes();
  await statusHandler(makeReq({ method: "GET", headers: { "x-forwarded-for": freshIp() } }), html);
  assert.match(String(html._body), /<strong>Partial\.<\/strong> The repository tree came back truncated/);
  const json = makeRes();
  await statusHandler(makeReq({ method: "GET", query: { format: "json" }, headers: { "x-forwarded-for": freshIp() } }), json);
  const j = parsed(json);
  assert.equal(j.case_anchors.partial, true);
  assert.equal(j.case_anchors.counted_from, "tree");
  assert.equal(j.case_anchors.feeds_status, false);
  // MUST-FAIL ARM: 2b's getTree returned the bare entries, and the row set
  // partial only from its own read cap, so this tree read as complete.
  const bare = [...tree];
  assert.equal(bare.truncated, undefined);
  assert.equal(S.caseAnchorSummary(bare).partial, false, "without the flag the row would say complete");
  gh.treeTruncated = false;
  assert.equal((await store.getTree()).truncated, false);
});

// =============================================================================
// FIX 4: the key document checker refuses an unknown top-level field
// =============================================================================

test("FIX 4: checkKeyDocument refuses an unknown top-level field by name; the committed document passes", () => {
  // The property, on the injected document with no key.
  assert.deepEqual(S.checkKeyDocument(NO_KEYS_DOC), { ok: true, keys: [] });
  for (const extra of ["private_keys", "trusted", "mirror", "keys_v2"]) {
    const got = S.checkKeyDocument({ ...NO_KEYS_DOC, [extra]: "x" });
    assert.deepEqual(got, { ok: false, reason: "unknown_field", at: extra }, extra);
  }
  // The committed document passes, with its one active entry: the
  // production case key, holding the verifier the file holds.
  const doc = JSON.parse(fs.readFileSync(path.join(ROOT, ...S.CASE_KEYS_FILE.split("/")), "utf-8"));
  const checked = S.checkKeyDocument(doc);
  assert.equal(checked.ok, true, JSON.stringify(checked));
  assert.equal(checked.keys.length, 1);
  const [prod] = checked.keys;
  assert.equal(prod.key_id, PRODUCTION_KEY_ID);
  assert.equal(prod.status, "active");
  assert.equal(prod.verifier, doc.keys[0].verifier);
  const vk = checkpoint.parseVerifierKey(prod.verifier);
  assert.equal(vk.ok, true, "the verifier parses");
  assert.equal(`${vk.name}+${vk.hash}`, PRODUCTION_KEY_ID, "and names the key the entry names");
  // and a document the checker refuses publishes no key
  assert.equal(S.loadCaseSigner(SIGNED, { keyDocument: { ...KEYS_DOC, trusted: [CASE_KEY.verifier] } }).code, "key_unpublished");
  // MUST-FAIL ARM: the 2b checker read only its required fields, and the
  // extra one is not among them.
  assert.ok(!["schema", "issuer", "description", "matching", "status_meaning", "rotation", "updated", "keys"].includes("private_keys"));
});

// =============================================================================
// FIX 5: pinned cases stay in the sealer's window; a squatter is reported
// =============================================================================

test("FIX 5: a squatter or unreadable latest.json under a pinned case is reported by the sealer's pass, never skipped, and never written over", async () => {
  const { id } = await sealedCase();
  const { latest, seq } = S.pinPaths(id);
  const squatter = S._internal.pinRecord(id, "e".repeat(64), REVEAL_AT);
  gh.seed(PINS, latest, squatter);
  const writes = gh.putLog.length;
  const run = await sealer.sealOnce({ now: new Date(REVEAL_AT + 60000), keyDocument: KEYS_DOC });
  assert.equal(run.cases.ok, true, JSON.stringify(run.cases));
  assert.equal(run.cases.candidates, 1);
  assert.equal(run.cases.pinned, 1);
  assert.deepEqual(run.cases.conflict, [id], "the squatter is reported");
  assert.equal(gh.putLog.length, writes, "nothing written over");
  assert.deepEqual(gh.read(PINS, latest), squatter);
  // an unreadable pointer
  const { auth_note, ...partial } = squatter; // eslint-disable-line no-unused-vars
  gh.seed(PINS, latest, partial);
  const run2 = await sealer.sealOnce({ now: new Date(REVEAL_AT + 120000), keyDocument: KEYS_DOC });
  assert.deepEqual(run2.cases.unreadable, [id]);
  assert.equal(gh.putLog.length, writes);
  // a pin under a case that is not sealed at all: a pin no seal backs
  const c = await committedCase({ over: { scope_digest: sha("pin without seal") } });
  gh.seed(PINS, S.pinPaths(c.id).latest, S._internal.pinRecord(c.id, "d".repeat(64), REVEAL_AT));
  const w2 = gh.putLog.length;
  const run3 = await S.anchorPending({ now: REVEAL_AT + 180000, keyDocument: KEYS_DOC });
  assert.ok(run3.conflict.includes(c.id), JSON.stringify(run3));
  assert.equal(run3.not_sealed, 0, "reported as the conflict it is, not passed over");
  assert.equal(gh.putLog.length, w2);
  // control: the real pin reads as already anchored
  gh.seed(PINS, latest, gh.read(PINS, seq));
  const run4 = await S.anchorPending({ now: REVEAL_AT + 240000, keyDocument: KEYS_DOC });
  assert.ok(run4.already.includes(id));
  // MUST-FAIL ARM: 2b's candidate list left out every pinned case, so the
  // squatter was never read again.
  const idx = S.caseTreeIndex([...gh.repos.get(PINS).keys()].map((p) => ({ path: p, type: "blob" })));
  assert.deepEqual(idx.sealable.filter((x) => !idx.pinned.has(x)), [], "2b's window would have been empty");
});

// =============================================================================
// FIX 6: the sealer skips terminal root states
// =============================================================================

test("FIX 6: a case with the withdrawn marker is not considered (its case file is never read); a root read as expired or withdrawn is skipped as terminal; nothing is written", async () => {
  // (a) the marker, by the tree alone
  const w = await committedCase({ over: { scope_digest: sha("marker") } });
  gh.seed(PINS, C.withdrawnMarkerPath(w.id), { case_id: w.id });
  const reads = gh.getLog.length;
  let writes = gh.putLog.length;
  const r1 = await S.anchorPending({ now: REVEAL_AT, keyDocument: KEYS_DOC });
  assert.equal(gh.putLog.length, writes, "the pass wrote nothing");
  assert.equal(r1.withdrawn_skipped, 1);
  assert.equal(r1.candidates, 0);
  assert.ok(!gh.getLog.slice(reads).includes(C.casePath(w.id)), "the case file is never read");
  // (b) COMMITTED, past its deadline with no reveal: read once, terminal
  const e = await committedCase({ over: { scope_digest: sha("expired") } });
  const after = Date.parse(DEADLINE) + 60000;
  writes = gh.putLog.length;
  const r2 = await S.anchorPending({ now: after, keyDocument: KEYS_DOC });
  assert.equal(gh.putLog.length, writes, "the pass wrote nothing");
  assert.deepEqual(r2.terminal, [{ case_id: e.id, status: "EXPIRED" }]);
  assert.equal(r2.not_sealed, 0, "terminal, not merely not sealed");
  assert.equal((await S.anchorCase(e.id, { now: after })).code, "terminal");
  // (c) a WITHDRAWN root whose marker is missing: read once, terminal
  const x = await committedCase({ over: { scope_digest: sha("withdrawn root") } });
  gh.seed(PINS, C.casePath(x.id), { v: 1, case_id: x.id, protocol_version: "case/1", status: "WITHDRAWN", opened_at: "2026-10-10T07:30:00Z",
    withdrawal: { by_role: "a", at: "2026-10-10T08:30:00Z", salt_sha256: sha("s") }, limits: C.LIMITS.slice(), signed_by: null, sig: null, sig_reason: "unsigned in this test" });
  writes = gh.putLog.length;
  const r3 = await S.anchorPending({ now: REVEAL_AT, keyDocument: KEYS_DOC });
  assert.deepEqual(r3.terminal, [{ case_id: x.id, status: "WITHDRAWN" }]);
  assert.equal(gh.putLog.length, writes, "the pass wrote nothing");
  // MUST-FAIL ARM: before the deadline the same committed case is merely not sealed
  const before = await S.anchorPending({ now: REVEAL_AT, keyDocument: KEYS_DOC });
  assert.ok(!before.terminal.some((t) => t.case_id === e.id));
  assert.equal(before.not_sealed, 1);
});

// =============================================================================
// the endpoints: helpers
// =============================================================================

const keys = require("../lib/_keys.js");
const CP = require("../lib/_case_page.js");
const verifyHandler = require("../api/verify.js");
const USAGE = process.env.GITHUB_USAGE_REPO;
const ADMIN_KEY = "case-test-operator-admin-key-0001";
// The operator's key for references is its own variable since item 2d
// (lib/_case_http.js, THE OPERATOR'S KEY), never WITNESS_ADMIN_KEY.
const OPERATOR_ENV = Object.freeze({ ...SIGNED, [H.OPERATOR_KEY_ENV]: ADMIN_KEY });
const [ALT_AGENT, ALT_TOOL] = pairNamed(/^receipt-test_call_proxy_tape\/test_cross_repo_answer_changed0: agent vs tool$/);
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0042", url: "https://second-operator.example/cases/0042" });

function storedText() {
  let out = "";
  for (const [, files] of gh.repos) for (const [, f] of files) out += f.content;
  return out;
}
async function committedWith(over, tapeA, tapeB) {
  const id = await openCase(over);
  const a = party(id, "a", tapeA);
  const b = party(id, "b", tapeB);
  for (const p of [a, b]) await register(id, p);
  return { id, a, b };
}
const proofOf = (id, p) => ({ case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt: p.salt });
async function withdraw(body, { now = REVEAL_AT, env = SIGNED, keyDocument = KEYS_DOC } = {}) {
  const res = makeRes();
  await H.handleCaseWithdraw(req("case-withdraw", body), res, { now, env, keyDocument });
  return { status: res._status, body: parsed(res) };
}
async function reference(body, { now = REVEAL_AT + 3600000, env = SIGNED, keyDocument = KEYS_DOC, headers = {} } = {}) {
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", body, headers), res, { now, env, keyDocument });
  return { status: res._status, body: parsed(res) };
}
async function casePage(id, { now = REVEAL_AT + 3600000, keyDocument = KEYS_DOC } = {}) {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": freshIp() } }), res, { now, keyDocument });
  return { status: res._status, html: String(res._body), headers: res._headers };
}
function referenceFiles(id) {
  return [...gh.repos.get(PINS).keys()].filter((p) => p.startsWith(`${C.referencesDir(id)}/`)).sort();
}

// =============================================================================
// WITHDRAWAL (design test 10, the race, the proof)
// =============================================================================

test("TEST 10: a withdrawal before the joint reveal publishes only the redacted record, signed with the case key, with no labels or commitments; the marker is written; withdrawal after the seal is refused", async () => {
  const { id, a, b } = await committedCase({ over: { scope_digest: sha("test 10") } });
  const before = storedCase(id);
  const regA = gh.read(PINS, C.registrationPath(id, "a"));
  const regB = gh.read(PINS, C.registrationPath(id, "b"));
  const w = await withdraw(proofOf(id, a));
  assert.equal(w.status, 201, JSON.stringify(w.body));
  assert.equal(w.body.ok, true);
  assert.equal(w.body.withdrawn_by, "a");
  const k = storedCase(id);
  assert.deepEqual(k, w.body.case, "the answer carries the record as written");
  // exactly the redacted form, and nothing else
  assert.deepEqual(Object.keys(k).sort(), [...C.WITHDRAWN_FIELDS].sort());
  assert.deepEqual(C.validateCase(k), { ok: true });
  assert.equal(k.status, "WITHDRAWN");
  assert.deepEqual(k.withdrawal, { by_role: "a", at: "2026-10-10T09:00:00Z", salt_sha256: C.saltSha256(a.salt) });
  assert.deepEqual(k.limits, C.LIMITS.slice());
  // no labels, no commitments
  const text = JSON.stringify(k);
  for (const leak of [AGENT.label, TOOL.label, a.commitment_sha256, b.commitment_sha256, before.scope_digest, regA.stamp_commit, regB.stamp_commit]) {
    assert.ok(!text.includes(leak), `the redacted record carries ${leak.slice(0, 20)}`);
  }
  for (const f of ["party_a", "party_b", "commitments", "scope_digest", "reveals", "verdict"]) assert.ok(!(f in k), f);
  // signed with the case key, confirmed by the document
  assert.equal(k.signed_by, CASE_KEY_ID);
  assert.equal(S.publishedSignatureReason(k, KEYS_DOC), null);
  // the marker, create-only, and the registrations left in place, said in words
  assert.equal(w.body.marker, "written");
  assert.equal(gh.read(PINS, C.withdrawnMarkerPath(id)).case_id, id);
  assert.deepEqual(gh.read(PINS, C.registrationPath(id, "a")), regA);
  assert.deepEqual(gh.read(PINS, C.registrationPath(id, "b")), regB);
  assert.match(w.body.registrations_note, /remain in the public record/);
  assert.match(w.body.registrations_note, /does not erase them/);
  // the preimage is spent: no reveal, no second withdrawal
  const r = await reveal(revealBody(id, a, b));
  assert.equal(r.status, 409);
  assert.equal(r.body.error_code, "case_withdrawn");
  const again = await withdraw(proofOf(id, b));
  assert.equal(again.status, 409);
  assert.equal(again.body.error_code, "case_withdrawn");

  // after the seal: refused, nothing written, the sealed case untouched
  const s = await sealedCase({ over: { scope_digest: sha("test 10 sealed") } });
  const sealed = storedCase(s.id);
  const writes = gh.putLog.length;
  const late = await withdraw(proofOf(s.id, s.a), { now: REVEAL_AT + 60000 });
  assert.equal(late.status, 409, JSON.stringify(late.body));
  assert.equal(late.body.error_code, "case_sealed");
  assert.equal(gh.putLog.length, writes, "nothing written");
  assert.deepEqual(storedCase(s.id), sealed);
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(s.id)), false);
  // MUST-FAIL ARM: the case object it replaced carried both labels and both commitments
  const full = JSON.stringify(before);
  assert.ok(full.includes(AGENT.label) && full.includes(a.commitment_sha256));
});

test("WITHDRAWAL: a preimage that does not recompute the named role's registration is refused withdraw_unauthorized; nothing is written, and nothing of any preimage but salt_sha256 is kept or logged", async (t) => {
  const { id, a, b } = await committedCase({ over: { scope_digest: sha("unauthorized") } });
  const wrongSalt = C.newSalt();
  const writes = gh.putLog.length;
  for (const [name, body] of [
    ["a wrong salt", { ...proofOf(id, a), salt: wrongSalt }],
    ["a wrong tape hash", { ...proofOf(id, a), tape_sha256: sha("another tape") }],
    ["role b's preimage under role a", { ...proofOf(id, b), role: "a" }],
    ["role a's preimage under role b", { ...proofOf(id, a), role: "b" }],
  ]) {
    const r = await withdraw(body);
    assert.equal(r.status, 403, `${name}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.error_code, "withdraw_unauthorized", name);
    assert.ok(!JSON.stringify(r.body).includes(body.salt), `${name}: the refusal does not echo the salt`);
  }
  assert.equal(gh.putLog.length, writes, "no refused proof wrote anything");
  // a role with no registration cannot prove itself
  const o = await openCase({ scope_digest: sha("half registered") });
  const ha = party(o, "a", AGENT_TAPE);
  const hb = party(o, "b", TOOL_TAPE);
  await register(o, ha);
  const w0 = gh.putLog.length;
  const unreg = await withdraw(proofOf(o, hb));
  assert.equal(unreg.status, 403);
  assert.equal(unreg.body.error_code, "withdraw_unauthorized");
  assert.equal(gh.putLog.length, w0);
  // the body: exactly {case_id, role, tape_sha256, salt}; a caller's time is refused
  const w1 = gh.putLog.length;
  for (const [extra, code] of [[{ at: "2026-10-10T08:00:00Z" }, "unknown_field"], [{ by_role: "a" }, "unknown_field"], [{ salt_sha256: sha("x") }, "unknown_field"]]) {
    const r = await withdraw({ ...proofOf(id, a), ...extra });
    assert.equal(r.status, 400);
    assert.equal(r.body.error_code, code);
  }
  const noSalt = await withdraw({ case_id: id, role: "a", tape_sha256: a.tape_sha256 });
  assert.equal(noSalt.body.error_code, "missing_field");
  // past the deadline the case reads EXPIRED and is not withdrawn
  const exp = await withdraw(proofOf(id, a), { now: Date.parse(DEADLINE) });
  assert.equal(exp.status, 409);
  assert.equal(exp.body.error_code, "expired");
  assert.equal(exp.body.status, "EXPIRED");
  assert.equal(gh.putLog.length, w1, "no refused body and no expired case wrote anything");
  assert.equal(storedCase(id).status, "COMMITTED", "no refusal withdrew it");

  // the accepted withdrawal keeps only salt_sha256: no store write, request or log line carries the salt or the tape hash
  const requests = [];
  const viaMock = global.fetch;
  global.fetch = async (url, opt) => {
    requests.push(`${String(url)} ${opt && opt.body ? Buffer.from(JSON.parse(opt.body).content || "", "base64").toString("utf-8") + opt.body : ""}`);
    return viaMock(url, opt);
  };
  const logged = [];
  const orig = { log: console.log, error: console.error, warn: console.warn, info: console.info };
  for (const k of Object.keys(orig)) console[k] = (...x) => logged.push(x.join(" "));
  t.after(() => {
    global.fetch = viaMock;
    Object.assign(console, orig);
  });
  gh.forceFailure(PINS, C.withdrawnMarkerPath(id), 1, 502); // a failed marker, which logs
  const ok = await withdraw(proofOf(id, a));
  global.fetch = viaMock;
  Object.assign(console, orig);
  assert.equal(ok.status, 201, JSON.stringify(ok.body));
  assert.equal(ok.body.marker, "failed", "a failed marker leaves the withdrawal standing");
  assert.equal(storedCase(id).status, "WITHDRAWN");
  assert.ok(logged.length > 0, "control: the failed marker was logged");
  for (const [where, text] of [["store writes and reads", requests.join("\n")], ["log lines", logged.join("\n")], ["stored data", storedText()]]) {
    for (const s of [a.salt, b.salt, wrongSalt, a.tape_sha256, b.tape_sha256]) assert.ok(!text.includes(s), `${where} carry ${s.slice(0, 16)}`);
  }
  assert.ok(storedText().includes(C.saltSha256(a.salt)), "control: the scan sees what IS stored");
  // and with the case key unpublished the record is unsigned and says why
  const u = await committedCase({ over: { scope_digest: sha("unsigned withdrawal") } });
  const uw = await withdraw(proofOf(u.id, u.b), { keyDocument: S.PUBLISHED_KEYS });
  assert.equal(uw.status, 201);
  assert.equal(storedCase(u.id).sig, null);
  assert.equal(storedCase(u.id).signed_by, null);
  assert.match(storedCase(u.id).sig_reason, /^This withdrawal record is not signed \(key_unpublished\): /);
});

// The real race: one handler's root write held until the other has run whole.
async function interleave(cpath, first, second) {
  const viaMock = global.fetch;
  let inner = null;
  global.fetch = async (url, o) => {
    if (inner === null && o && o.method === "PUT" && String(url).endsWith(`/contents/${cpath}`)) {
      inner = "running";
      inner = await second();
    }
    return viaMock(url, o);
  };
  let outer;
  try {
    outer = await first();
  } finally {
    global.fetch = viaMock;
  }
  return { outer, inner };
}

test("WITHDRAWAL RACE: a withdrawal and a reveal interleaved both ways; the CAS on the root record decides and the loser answers the typed 409", async () => {
  // (1) the reveal reads COMMITTED and compares; the withdrawal lands first
  const c1 = await committedCase({ over: { scope_digest: sha("race reveal loses") } });
  const r1 = await interleave(C.casePath(c1.id), () => reveal(revealBody(c1.id, c1.a, c1.b)), () => withdraw(proofOf(c1.id, c1.b), { now: REVEAL_AT + 1000 }));
  assert.equal(r1.inner.status, 201, `the withdrawal won: ${JSON.stringify(r1.inner.body)}`);
  assert.equal(r1.outer.status, 409, JSON.stringify(r1.outer.body));
  assert.equal(r1.outer.body.error_code, "case_withdrawn");
  assert.equal(r1.outer.body.verdict, undefined, "the loser carries no verdict");
  assert.equal(storedCase(c1.id).status, "WITHDRAWN");
  assert.deepEqual(pinFilesOf(c1.id), [], "no pin");
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c1.id)), true);

  // (2) the withdrawal reads COMMITTED and proves; the reveal seals first
  const c2 = await committedCase({ over: { scope_digest: sha("race withdrawal loses") } });
  const r2 = await interleave(C.casePath(c2.id), () => withdraw(proofOf(c2.id, c2.a)), () => reveal(revealBody(c2.id, c2.a, c2.b), { now: REVEAL_AT + 1000 }));
  assert.equal(r2.inner.status, 201, `the reveal won: ${JSON.stringify(r2.inner.body).slice(0, 200)}`);
  assert.equal(r2.outer.status, 409, JSON.stringify(r2.outer.body));
  assert.equal(r2.outer.body.error_code, "case_sealed");
  assert.equal(storedCase(c2.id).status, "VERDICT", "the seal stands");
  assert.equal(storedCase(c2.id).reveals.a.revealed_at, "2026-10-10T09:00:01Z");
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c2.id)), false, "no marker for a sealed case");

  // (3) a registration projected between the withdrawal's read and write is
  // no race to lose: the redacted record goes over the fresh case, and the
  // new registration file stays where it is
  const o = await openCase({ scope_digest: sha("race registration") });
  const pa = party(o, "a", AGENT_TAPE);
  const pb = party(o, "b", TOOL_TAPE);
  await register(o, pa);
  plantStamp(pb.commitment_sha256);
  const r3 = await interleave(C.casePath(o), () => withdraw(proofOf(o, pa)),
    () => call(H.handleCaseCommit, "case-commit", { case_id: o, role: "b", commitment_sha256: pb.commitment_sha256 }, NOW));
  assert.equal(r3.inner._status, 201, JSON.stringify(r3.inner._body));
  assert.equal(r3.outer.status, 201, JSON.stringify(r3.outer.body));
  assert.equal(storedCase(o).status, "WITHDRAWN");
  assert.equal(gh.read(PINS, C.registrationPath(o, "b")).commitment_sha256, pb.commitment_sha256, "b's registration file stands");
  // MUST-FAIL ARM: without the CAS (a blind write over whatever is there)
  // the loser of race (2) would have overwritten the sealed case; the
  // withdrawal's PUT in (2) was sent with the sha it read, which is what
  // made it lose.
  assert.ok(gh.putLog.some((w) => w.path === C.casePath(c2.id)));
});

// =============================================================================
// THE ADDENDUM (design test 11)
// =============================================================================

test("TEST 11: records is 2 only when a valid cross-reference row exists; an addendum appends a signed create-only row and never rewrites the sealed case; it has no pin of its own", async () => {
  const { id, a } = await sealedCase({ over: { scope_digest: sha("test 11") } });
  const sealed = storedCase(id);
  assert.equal(sealed.records, 1);
  assert.equal((await S.liveRecords(sealed, { keyDocument: KEYS_DOC })).records, 1, "no row, one record");
  const pinsBefore = [...gh.repos.get(PINS).keys()].filter((p) => p.startsWith("pins/")).sort();

  const r = await reference({ ...proofOf(id, a), cross_reference: XREF });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(r.body.seq, 1);
  assert.equal(r.body.appended_by, "role:a");
  assert.equal(r.body.records_sealed, 1);
  assert.equal(r.body.records_live, 2);
  const row = gh.read(PINS, C.referencePath(id, 1));
  assert.deepEqual(row, r.body.row);
  assert.deepEqual(Object.keys(row).sort(), [...C.REFERENCE_FIELDS].sort(), "exactly the case_reference fields");
  assert.equal(row.kind, "case_reference");
  assert.equal(row.v, 1);
  assert.equal(row.case_id, id);
  assert.deepEqual(row.cross_reference, XREF);
  assert.equal(row.recorded_at, "2026-10-10T10:00:00Z", "the service clock");
  assert.equal(row.signed_by, CASE_KEY_ID);
  assert.equal(S.publishedSignatureReason(row, KEYS_DOC), null, "signed with the case key");
  assert.match(row.anchor_note, /no pin of its own/);
  assert.match(row.anchor_note, /pins-repository commit that writes it and by the daily anchor of the repository head/);
  // the sealed case is untouched, and records in it is still the count at seal time
  assert.deepEqual(storedCase(id), sealed);
  assert.equal((await S.liveRecords(storedCase(id), { keyDocument: KEYS_DOC })).records, 2, "the live count, from the row");
  // no pin of its own
  assert.deepEqual([...gh.repos.get(PINS).keys()].filter((p) => p.startsWith("pins/")).sort(), pinsBefore);
  // the operator's key appends too, and the row says so
  const op = await reference({ case_id: id, cross_reference: { ...XREF, reference: "case-ref-0042-b" } }, { env: OPERATOR_ENV, headers: { authorization: `Bearer ${ADMIN_KEY}` } });
  assert.equal(op.status, 201, JSON.stringify(op.body));
  assert.equal(op.body.seq, 2);
  assert.equal(op.body.appended_by, "operator");
  assert.equal(op.body.records_live, 2, "records counts operators that hold a record, never rows");
  // MUST-FAIL ARM: the sealed object cannot say 2 without its own
  // cross_reference, so the second record can only come from a valid row
  assert.equal(C.validateCase({ ...sealed, records: 2 }).code, "status_inconsistent");
  // and a case sealed with a cross_reference already says 2
  const x = await sealedCase({ over: { scope_digest: sha("test 11 xref") }, extra: { cross_reference: XREF } });
  assert.equal(storedCase(x.id).records, 2);
  assert.equal((await S.liveRecords(storedCase(x.id), { keyDocument: KEYS_DOC })).records, 2);
});

test("ADDENDUM: an invalid row is ignored by the count; a valid unsigned row counts", async () => {
  const { id } = await sealedCase({ over: { scope_digest: sha("invalid rows") } });
  const sealed = storedCase(id);
  const signer = S.loadCaseSigner(SIGNED, { keyDocument: KEYS_DOC });
  const good = (seq, over = {}) => S.referenceRow({ caseId: id, seq, crossReference: XREF, recordedAt: "2026-10-10T10:00:00Z", appendedBy: "operator", ...over }, signer);
  const other = checkpoint.generateKey("arcaeon.io/case-other/2026-10-10");
  const otherSigner = S.loadCaseSigner({ ...SIGNED, [S.CASE_SIGNER_ENV]: other.signer }, { keyDocument: { ...KEYS_DOC, keys: [ENTRY, { ...ENTRY, key_id: other.verifier.split("+").slice(0, 2).join("+"), verifier: other.verifier }] } });
  assert.equal(otherSigner.ok, true, "fixture: a key the test document lists but KEYS_DOC does not");
  const plants = {
    reference_unknown_field: { ...good(1), extra: true },
    reference_not_at_its_path: { ...good(1), case_id: "9".repeat(64) },
    reference_bad_seq: good(2), // a seq-2 row filed at seq 1
    reference_signature_bad_signature: { ...good(1), cross_reference: { ...XREF, reference: "altered after signing" } },
    reference_before_seal: good(1, { recordedAt: "2026-10-10T08:59:59Z" }),
    reference_signature_signer_unpublished: S.referenceRow({ caseId: id, seq: 1, crossReference: XREF, recordedAt: "2026-10-10T10:00:00Z", appendedBy: "operator" }, otherSigner),
    reference_malformed_field: { ...good(1), anchor_note: "anchored by a pin" },
  };
  for (const [name, row] of Object.entries(plants)) {
    gh.seed(PINS, C.referencePath(id, 1), row);
    const live = await S.liveRecords(sealed, { keyDocument: KEYS_DOC });
    assert.equal(live.ok, true, name);
    assert.equal(live.records, 1, `${name}: an invalid row is not counted`);
    assert.equal(live.invalid.length, 1, name);
    if (name !== "reference_bad_seq") assert.equal(live.invalid[0].reason, name, `${name}: ${live.invalid[0].reason}`);
    else assert.equal(live.invalid[0].reason, "reference_not_at_its_path");
  }
  // a valid unsigned row is a record, unsigned
  const unsigned = S.referenceRow({ caseId: id, seq: 1, crossReference: XREF, recordedAt: "2026-10-10T10:00:00Z", appendedBy: "role:b" }, { ok: false, code: "key_unpublished", reason: "no key in this test" });
  assert.equal(unsigned.sig, null);
  assert.match(unsigned.sig_reason, /^This reference row is not signed \(key_unpublished\)/);
  gh.seed(PINS, C.referencePath(id, 1), unsigned);
  assert.equal((await S.liveRecords(sealed, { keyDocument: KEYS_DOC })).records, 2);
  // MUST-FAIL ARM: a count of files, not of valid rows, would have said 2 for every plant
  assert.equal(referenceFiles(id).length, 1);
});

test("ADDENDUM: a role that cannot prove itself, a missing or wrong operator key, an unconfigured operator key, an unsealed or withdrawn case: each refused, typed, and nothing written", async () => {
  const { id, a } = await sealedCase({ over: { scope_digest: sha("refusals") } });
  const c = await committedCase({ over: { scope_digest: sha("refusals, committed") } });
  const w = await committedCase({ over: { scope_digest: sha("refusals, withdrawn") } });
  assert.equal((await withdraw(proofOf(w.id, w.a))).status, 201);
  const writes = gh.putLog.length;
  const cases = [
    ["a wrong salt", { ...proofOf(id, a), salt: C.newSalt(), cross_reference: XREF }, {}, 403, "reference_unauthorized"],
    ["a role alone", { case_id: id, role: "a", cross_reference: XREF }, {}, 400, "missing_field"],
    ["no proof and no key", { case_id: id, cross_reference: XREF }, { env: OPERATOR_ENV }, 401, "reference_unauthorized"],
    ["the wrong operator key", { case_id: id, cross_reference: XREF }, { env: OPERATOR_ENV, headers: { authorization: "Bearer not-the-operator" } }, 401, "reference_unauthorized"],
    ["an issued key is not the operator's", { case_id: id, cross_reference: XREF }, { env: OPERATOR_ENV, headers: OPEN_AUTH }, 401, "reference_unauthorized"],
    ["no operator key configured", { case_id: id, cross_reference: XREF }, { headers: { authorization: `Bearer ${ADMIN_KEY}` } }, 503, "operator_key_not_configured"],
    ["a caller's recorded_at", { ...proofOf(id, a), cross_reference: XREF, recorded_at: "2026-10-10T10:00:00Z" }, {}, 400, "unknown_field"],
    ["an http url", { ...proofOf(id, a), cross_reference: { ...XREF, url: "http://second-operator.example/x" } }, {}, 400, "malformed_field"],
    ["no cross_reference", proofOf(id, a), {}, 400, "missing_field"],
    ["an unsealed case", { ...proofOf(c.id, c.a), cross_reference: XREF }, {}, 409, "case_not_sealed"],
    ["a withdrawn case", { ...proofOf(w.id, w.a), cross_reference: XREF }, {}, 409, "case_withdrawn"],
  ];
  for (const [name, body, o, status, code] of cases) {
    const r = await reference(body, o);
    assert.equal(r.status, status, `${name}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.error_code, code, name);
  }
  assert.equal(gh.putLog.length, writes, "no refusal wrote anything");
  assert.deepEqual(referenceFiles(id), []);
  // MUST-FAIL ARM: the right proof is accepted
  assert.equal((await reference({ ...proofOf(id, a), cross_reference: XREF })).status, 201);
});

test("ADDENDUM: rows are create-only: the second append takes seq 2; a row that lands first at the next seq is never written over, and the append moves to the one after", async () => {
  const { id, a, b } = await sealedCase({ over: { scope_digest: sha("create only") } });
  assert.equal((await reference({ ...proofOf(id, a), cross_reference: XREF })).body.seq, 1);
  const second = await reference({ ...proofOf(id, b), cross_reference: { ...XREF, reference: "second" } });
  assert.equal(second.body.seq, 2);
  assert.equal(second.body.appended_by, "role:b");
  const first = gh.read(PINS, C.referencePath(id, 1));
  // a row lands at seq 3 between this append's listing and its write
  const signer = S.loadCaseSigner(SIGNED, { keyDocument: KEYS_DOC });
  const squat = S.referenceRow({ caseId: id, seq: 3, crossReference: { ...XREF, reference: "landed first" }, recordedAt: "2026-10-10T10:00:00Z", appendedBy: "operator" }, signer);
  const p3 = C.referencePath(id, 3);
  const viaMock = global.fetch;
  let planted = false;
  global.fetch = async (url, o) => {
    if (!planted && o && o.method === "PUT" && String(url).endsWith(`/contents/${p3}`)) {
      planted = true;
      gh.seed(PINS, p3, squat);
    }
    return viaMock(url, o);
  };
  let third;
  try {
    third = await reference({ ...proofOf(id, a), cross_reference: { ...XREF, reference: "third" } });
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(planted, true);
  assert.equal(third.status, 201, JSON.stringify(third.body));
  assert.equal(third.body.seq, 4, "moved to the next seq");
  assert.deepEqual(gh.read(PINS, p3), squat, "the row that landed first is never written over");
  assert.deepEqual(gh.read(PINS, C.referencePath(id, 1)), first, "nor is any earlier row");
  assert.deepEqual(referenceFiles(id), [1, 2, 3, 4].map((n) => C.referencePath(id, n)));
  // MUST-FAIL ARM: a write with no sha to an existing row path is refused by the store itself
  await assert.rejects(() => store.putFile(C.referencePath(id, 1), first, "overwrite", undefined), (e) => e.conflict === true);
});

// =============================================================================
// THE OPEN QUOTA
// =============================================================================

test("OPEN QUOTA: twenty opens per key per UTC day; the twenty-first is 429 open_quota_exceeded and writes nothing; another key and the next day open; the count is a store record, not a Map", async () => {
  const day = "2026-10-10";
  for (let i = 0; i < H.OPEN_QUOTA_PER_DAY; i += 1) {
    const r = await call(H.handleCaseOpen, "case-open", opening({ scope_digest: sha(`quota ${i}`) }), NOW);
    assert.equal(r._status, 201, `open ${i + 1}: ${JSON.stringify(r._body)}`);
  }
  assert.equal(H.OPEN_QUOTA_PER_DAY, 20);
  const cpath = C.casePath(C.deriveCaseId(C.validateOpening(opening({ scope_digest: sha("quota 20") })).opening));
  const writes = gh.putLog.length;
  const over = await call(H.handleCaseOpen, "case-open", opening({ scope_digest: sha("quota 20") }), NOW);
  assert.equal(over._status, 429, JSON.stringify(over._body));
  assert.equal(over._body.error_code, "open_quota_exceeded");
  assert.equal(over._body.quota_per_day, 20);
  assert.equal(over._body.day, day);
  assert.equal(Number(over._headers["retry-after"]), 16 * 3600, "until 00:00 UTC");
  assert.equal(gh.putLog.length, writes, "nothing written");
  assert.equal(gh.has(PINS, cpath), false);
  // the counter: in the private usage repository, named by the key's hash, never the key
  const qpath = H._internal.openQuotaPath(OPEN_KEY, day);
  assert.equal(qpath, `case_opens/${keys.keyHash(OPEN_KEY)}/${day}.json`);
  assert.deepEqual(gh.read(USAGE, qpath), { kind: "case-open-quota", v: 1, day, count: 20 });
  assert.equal(gh.has(PINS, qpath), false, "never the public pins repository");
  for (const [, files] of gh.repos) for (const [p, f] of files) assert.ok(!p.includes(OPEN_KEY) && !f.content.includes(OPEN_KEY), p);
  // another key opens
  const k2 = await call(H.handleCaseOpen, "case-open", opening({ scope_digest: sha("quota 20") }), NOW, { authorization: "Bearer case-test-open-key-0005" });
  assert.equal(k2._status, 201, JSON.stringify(k2._body));
  // the next UTC day opens
  const next = await call(H.handleCaseOpen, "case-open", opening({ scope_digest: sha("next day"), opened_at: "2026-10-11T07:30:00Z", deadline: "2026-10-11T20:00:00Z" }), NOW + 86400000);
  assert.equal(next._status, 201, JSON.stringify(next._body));
  // the count is read from the store: a counter planted at 20 refuses a key that has not opened that day in this process
  gh.seed(USAGE, H._internal.openQuotaPath(OPEN_KEY, "2026-10-12"), { kind: "case-open-quota", v: 1, day: "2026-10-12", count: 20 });
  const planted = await call(H.handleCaseOpen, "case-open", opening({ scope_digest: sha("day 3"), opened_at: "2026-10-12T07:30:00Z", deadline: "2026-10-12T20:00:00Z" }), NOW + 2 * 86400000);
  assert.equal(planted._status, 429, JSON.stringify(planted._body));
  // a damaged counter is not zero: 503, nothing written
  gh.seed(USAGE, H._internal.openQuotaPath(OPEN_KEY, "2026-10-13"), { kind: "case-open-quota", v: 1, day: "2026-10-13", count: "many" });
  const w4 = gh.putLog.length;
  const damaged = await call(H.handleCaseOpen, "case-open", opening({ scope_digest: sha("day 4"), opened_at: "2026-10-13T07:30:00Z", deadline: "2026-10-13T20:00:00Z" }), NOW + 3 * 86400000);
  assert.equal(damaged._status, 503, JSON.stringify(damaged._body));
  assert.equal(damaged._body.error_code, "open_quota_unreadable");
  assert.ok(!JSON.stringify(damaged._body).includes(keys.keyHash(OPEN_KEY)), "the answer never names the counter's path");
  assert.equal(gh.putLog.length, w4);
  // a duplicate opening spends nothing
  const d5 = { scope_digest: sha("day 5"), opened_at: "2026-10-14T07:30:00Z", deadline: "2026-10-14T20:00:00Z" };
  assert.equal((await call(H.handleCaseOpen, "case-open", opening(d5), NOW + 4 * 86400000))._status, 201);
  const dup = await call(H.handleCaseOpen, "case-open", opening(d5), NOW + 4 * 86400000);
  assert.equal(dup._status, 409);
  assert.equal(dup._body.error_code, "case_exists");
  assert.equal(gh.read(USAGE, H._internal.openQuotaPath(OPEN_KEY, "2026-10-14")).count, 1);
  // MUST-FAIL ARM: the per-IP limiter alone (2b) would have let the 21st through: each open came from its own address
  assert.ok(over._body.error_code !== "rate_limited");
});

// =============================================================================
// THE PAGE
// =============================================================================

const LIMIT_LINES = C.LIMITS.map((l) => l.replace(/&/g, "&amp;"));

test("PAGE: each status renders what the design lists (OPEN, COMMITTED, VERDICT anchored and pending, ALTERED with its first divergence, WITHDRAWN, EXPIRED), through verify.js and the /case/<case_id> rewrite", async () => {
  const cfg = JSON.parse(fs.readFileSync(path.join(ROOT, "vercel.json"), "utf8"));
  const rw = Object.fromEntries(cfg.rewrites.map((r) => [r.source, r.destination]));
  assert.equal(rw["/case/:case_id"], "/api/verify?op=case-page&case_id=:case_id");
  assert.equal(fs.readdirSync(path.join(ROOT, "api")).filter((f) => f.endsWith(".js")).length, 12, "no thirteenth function");

  // OPEN
  const openId = await openCase({ scope_digest: sha("page open") });
  const po = await casePage(openId, { now: NOW });
  assert.equal(po.status, 200);
  assert.match(po.headers["content-type"], /^text\/html/);
  assert.match(po.headers["content-security-policy"], /default-src 'none'/);
  assert.match(po.html, /<h1>Case: OPEN<\/h1>/);
  assert.match(po.html, /Labels are recorded, not verified\./);
  assert.ok(po.html.includes(AGENT.label) && po.html.includes(TOOL.label));
  assert.ok(po.html.includes("case/1") && po.html.includes(C.SUPPORTED_POLICY_VERSION));
  for (const l of LIMIT_LINES) assert.ok(po.html.includes(l), l);
  assert.ok(!/<script/i.test(po.html), "no script");

  // COMMITTED: both registration times, the stamp commits and the registration records, derived
  const c = await committedCase({ over: { scope_digest: sha("page committed") } });
  const pc = await casePage(c.id, { now: NOW });
  assert.match(pc.html, /<h1>Case: COMMITTED<\/h1>/);
  for (const r of ["a", "b"]) {
    const e = storedCase(c.id).commitments[r];
    assert.ok(pc.html.includes(`role ${r} registered at`), r);
    assert.ok(pc.html.includes(`https://github.com/${STAMPS}/commit/${e.stamp_commit}`), `${r}: the stamp commit`);
    assert.ok(pc.html.includes(`https://github.com/${PINS}/commits/main/${C.registrationPath(c.id, r)}`), `${r}: the registration record`);
  }

  // VERDICT, anchored, signed, with the test key listed in the key document
  const s = await sealedCase({ over: { scope_digest: sha("page sealed") } });
  const listed = await casePage(s.id);
  assert.equal(listed.status, 200);
  const pv = listed.html;
  assert.match(pv, /<h1>Case: VERDICT<\/h1>/);
  assert.ok(pv.includes("2026-10-10T09:00:00Z"), "the reveal time");
  assert.match(pv, /<span class="word pass">MATCHED<\/span>/);
  assert.match(pv, /none: every call matched \(5 matched\)/);
  assert.match(pv, /one record: this service&#39;s/);
  assert.match(pv, /anchored: its pin/);
  assert.ok(pv.includes(S.ANCHOR_NOTE.replace(/'/g, "&#39;").replace(/</g, "&lt;").replace(/>/g, "&gt;")), "the anchor sentence");
  assert.ok(pv.includes(CASE_KEY_ID), "signed_by");
  assert.ok(pv.includes(`href="/${S.CASE_KEYS_DOC}"`), "the key document, cited");
  assert.match(pv, /listed in the key document as active; the signature verifies under the published verifier/);
  // the same case through the real dispatch (the committed key document, the
  // service clock): that document lists no key, so the case's signature is
  // not confirmed, and since item 2d the page shows the does-not-verify state
  // instead of the verdict (test/case_item2d.test.js, FIX 1)
  const res = makeRes();
  await verifyHandler(makeReq({ method: "GET", query: { op: "case-page", case_id: s.id }, headers: { "x-forwarded-for": freshIp() } }), res);
  assert.equal(res._status, 200);
  const pd = String(res._body);
  assert.match(pd, /<h1>Case: SEALED RECORD DOES NOT VERIFY<\/h1>/);
  assert.match(pd, /signer_unpublished/);
  assert.ok(pd.includes(CASE_KEY_ID), "the key the record names");
  assert.ok(pd.includes(`href="/${S.CASE_KEYS_DOC}"`), "the key document, cited");
  assert.ok(!pd.includes(">MATCHED<") && !pd.includes("anchored: its pin"), "no verdict and no anchor state");
  // an unsigned seal verifies through the real dispatch and shows its verdict
  const u = await sealedCase({ over: { scope_digest: sha("page sealed unsigned") }, keyDocument: S.PUBLISHED_KEYS });
  const ru = makeRes();
  await verifyHandler(makeReq({ method: "GET", query: { op: "case-page", case_id: u.id }, headers: { "x-forwarded-for": freshIp() } }), ru);
  assert.equal(ru._status, 200);
  assert.match(String(ru._body), /<h1>Case: VERDICT<\/h1>/);
  assert.match(String(ru._body), /<span class="word pass">MATCHED<\/span>/);
  assert.match(String(ru._body), /unsigned: This case is sealed and not signed \(key_unpublished\)/);
  // VERDICT, pending
  const p = await sealedCase({ over: { scope_digest: sha("page pending") }, pinFails: true });
  assert.match((await casePage(p.id)).html, /sealed, not yet anchored/);
  // ALTERED: the word and the first divergence; and a reference row makes it two records, with the cross-reference shown
  const alt = await committedWith({ scope_digest: sha("page altered") }, ALT_AGENT, ALT_TOOL);
  assert.equal((await reveal(revealBody(alt.id, alt.a, alt.b))).status, 201);
  assert.equal((await reference({ ...proofOf(alt.id, alt.b), cross_reference: XREF })).status, 201);
  const pa = await casePage(alt.id);
  assert.match(pa.html, /<span class="word fail">ALTERED<\/span>/);
  assert.match(pa.html, /at call 2/);
  assert.match(pa.html, /two records: a second operator holds a record of this case \(at seal time: one record/);
  assert.ok(pa.html.includes(XREF.reference) && pa.html.includes(`href="${XREF.url}"`), "the cross-reference");

  // WITHDRAWN: the redacted record only, and the sentence about the registrations
  const w = await committedCase({ over: { scope_digest: sha("page withdrawn") } });
  assert.equal((await withdraw(proofOf(w.id, w.a))).status, 201);
  const pw = await casePage(w.id);
  assert.match(pw.html, /<h1>Case: WITHDRAWN<\/h1>/);
  assert.match(pw.html, /by role a, at 2026-10-10T09:00:00Z/);
  assert.ok(pw.html.includes(S.WITHDRAWN_REGISTRATIONS_NOTE), "registrations remain public, in words");
  // (the first limit itself says "Labels are recorded, never verified"; the
  // page's own labels sentence, beside the labels, is what must be absent)
  for (const absent of [AGENT.label, TOOL.label, "registered at", CP.LABELS_SENTENCE, C.registrationPath(w.id, "a"), STAMPS]) {
    assert.ok(!pw.html.includes(absent), `a withdrawn page shows ${absent}`);
  }
  for (const l of LIMIT_LINES) assert.ok(pw.html.includes(l));

  // EXPIRED: the opening and the word
  const e = await committedCase({ over: { scope_digest: sha("page expired") } });
  const pe = await casePage(e.id, { now: Date.parse(DEADLINE) + 1000 });
  assert.match(pe.html, /<h1>Case: EXPIRED<\/h1>/);
  assert.ok(pe.html.includes("2026-10-10T07:30:00Z") && pe.html.includes(DEADLINE), "the opening");
  assert.match(pe.html, /Labels are recorded, not verified\./);
  assert.ok(!pe.html.includes("registered at"), "the opening and the word, not the registrations");
  assert.equal(storedCase(e.id).status, "COMMITTED", "expiry writes nothing");

  // not found, not an id, not a GET
  assert.equal((await casePage("9".repeat(64))).status, 404);
  assert.equal((await casePage("not-a-case")).status, 400);
  const post = makeRes();
  await verifyHandler(makeReq({ method: "POST", query: { op: "case-page", case_id: s.id }, headers: { "x-forwarded-for": freshIp() } }), post);
  assert.equal(post._status, 405);
  // MUST-FAIL ARM: a label the parties chose is escaped, never markup
  const evil = await openCase({ scope_digest: sha("page escape"), party_a: { side: "agent", label: 'agent <b>x</b> & "q"' } });
  const pz = await casePage(evil, { now: NOW });
  assert.ok(pz.html.includes("agent &lt;b&gt;x&lt;/b&gt; &amp; &quot;q&quot;"));
  assert.ok(!pz.html.includes("<b>x</b>"));
});

test("PAGE: nothing secret appears for any status: no tape bytes, tape hash, salt, salt hash or scope digest", async () => {
  const tapeLines = [AGENT_TAPE, TOOL_TAPE].flatMap((tp) => tp.toString("utf-8").split("\n").filter((l) => l)).map((l) => JSON.parse(l).req).filter(Boolean);
  assert.ok(tapeLines.length >= 5, "fixture: tape content to look for");
  const pages = [];
  const secrets = [];
  const add = (p) => secrets.push(p.salt, C.saltSha256(p.salt), p.tape_sha256, p.tape.toString("base64").slice(0, 60));
  const openId = await openCase({ scope_digest: sha("secret open") });
  pages.push((await casePage(openId, { now: NOW })).html);
  const c = await committedCase({ over: { scope_digest: sha("secret committed") } });
  add(c.a);
  add(c.b);
  pages.push((await casePage(c.id, { now: NOW })).html);
  const s = await sealedCase({ over: { scope_digest: sha("secret sealed") } });
  add(s.a);
  add(s.b);
  assert.equal((await reference({ ...proofOf(s.id, s.a), cross_reference: XREF })).status, 201);
  pages.push((await casePage(s.id)).html);
  const w = await committedCase({ over: { scope_digest: sha("secret withdrawn") } });
  add(w.a);
  add(w.b);
  assert.equal((await withdraw(proofOf(w.id, w.b))).status, 201);
  pages.push((await casePage(w.id)).html);
  pages.push((await casePage(c.id, { now: Date.parse(DEADLINE) + 1000 })).html); // EXPIRED
  for (const id of [openId, c.id, s.id, w.id]) {
    const k = storedCase(id);
    if (k.scope_digest) secrets.push(k.scope_digest);
  }
  secrets.push(...tapeLines);
  for (const html of pages) for (const x of secrets) assert.ok(!html.includes(x), `a page shows ${String(x).slice(0, 24)}`);
  // MUST-FAIL ARM: the sealed case file itself holds the tape hashes and the
  // salt hashes; only the page leaves them out.
  const stored = JSON.stringify(storedCase(s.id));
  assert.ok(stored.includes(s.a.tape_sha256) && stored.includes(C.saltSha256(s.a.salt)));
});
