// test/case_rab.test.js — unit R-AB (2026-10-14): parties are told apart
// by public key, never by key id, everywhere a case is read. A case root's
// per-role entry carries key_fp, the sha256 of the registering key's public
// key, computed from the registration file's verifier when the root
// projects it (the registration file carries none). Registration refuses one
// public key in both roles, 409 same_key_both_roles, codes only; a stored
// case whose two entries share a key_fp is single party, and its page is the
// one-sentence shape at 200. With the R-RVf3 carry-overs: the sealer's
// withdrawn-marker repair reads the withdrawal record through
// signedUnderReason, and the reference answers a could-not-look on a sealed
// case's named document 503, codes only. The setup below is
// test/case_rsig.test.js's.
"use strict";


process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0171:case-test-";
for (const k of ["WITNESS_BATCH_SHADOW", "WITNESS_ADMIN_KEY", "WITNESS_CASE_OPERATOR_KEY", "WITNESS_CASE_SIGNER_KEY",
  "WITNESS_RECONCILE_SIGNER_KEY", "WITNESS_RECONCILE_VERIFIER", "WITNESS_LOG_SIGNER_KEY", "VERCEL_GIT_COMMIT_SHA", "KEY_DOCUMENT_BRANCH"]) {
  delete process.env[k];
}

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

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
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const stamp = require("../lib/_stamp.js");
const { canonicalBytes } = require("../lib/_check_record.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const PINS = process.env.GITHUB_PIN_REPO;
const USAGE = process.env.GITHUB_USAGE_REPO;
const STAMPS = process.env.STAMP_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z");
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-14rab");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-14rab");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-14rab");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0171" });

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
  KD.serve(gh, DOC);
});
afterEach(() => {
  store._putRetry.sleep = realSleep;
  restore();
});

let ipSeq = 0;
const nextIp = () => {
  ipSeq += 1;
  return `10.95.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
};
function req(op, body, headers = {}) {
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": nextIp(), ...headers }, body });
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
function party(caseId, role, tape, key = undefined) {
  const salt = C.newSalt();
  const tape_sha256 = sha(tape);
  return { role, tape, tape_sha256, salt, key, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
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
// unit R-L (L3): the commit path signs a repair note before it removes
// anything, so it runs with a deployment's environment and key document
const deployedEnv = (env = KEYS) => KD.deployed(gh, env, DOC);
async function commit(id, p, now = NOW, extra = {}) {
  const res = makeRes();
  const body = REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 }, p.key);
  await H.handleCaseCommit(req("case-commit", body), res, { now, env: deployedEnv(), keyDocument: DOC, ...extra });
  return { status: res._status, body: parsed(res) };
}
async function register(id, p) {
  plantStamp(p.commitment_sha256);
  const r = await commit(id, p);
  assert.equal(r.status, 201, JSON.stringify(r.body));
}
async function withdraw(id, p, { now = NOW + 2000, env = KEYS, salt = p.salt, reason } = {}) {
  const res = makeRes();
  const body = { case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt, ...(reason === undefined ? {} : { reason }) };
  await H.handleCaseWithdraw(req("case-withdraw", body), res, { now, env: KD.deployed(gh, env, DOC), keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
async function committedCase(scope, keys = {}) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE, keys.a);
  const b = party(id, "b", TOOL_TAPE, keys.b);
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
// The requester's own refusal request (N3): its role named, and its own opening.
const ownOpening = (c, role) => ({ ...revealBody(c.id, c.a, c.b), role });
async function reveal(c, { now = REVEAL_AT, env = KEYS, keyDocument = DOC, body = revealBody(c.id, c.a, c.b) } = {}) {
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", body), res, { now, env: KD.deployed(gh, env, keyDocument), keyDocument });
  return { status: res._status, body: parsed(res) };
}
async function sealedCase(scope, keys = {}) {
  const c = await committedCase(scope, keys);
  const r = await reveal(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  return { ...c, r };
}
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0171", url: "https://second-operator.example/cases/0152" });
async function reference(c, { role = "a", env = KEYS, now = REVEAL_AT + 1800000, deploy = true } = {}) {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: XREF }),
    res, { now, env: deploy ? KD.deployed(gh, env, DOC) : env, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
// The operator's reference (no proof; the operator's bearer key).
const OPERATOR_KEY = "case-operator-key-0171-rsig";
async function operatorReference(c, { now = REVEAL_AT + 1800000 } = {}) {
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, cross_reference: { ...XREF, reference: "operator-ref" } },
    { authorization: `Bearer ${OPERATOR_KEY}` }), res, { now, env: KD.deployed(gh, { ...KEYS, [H.OPERATOR_KEY_ENV]: OPERATOR_KEY }, DOC), keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
async function casePage(id, now = REVEAL_AT + 3600000) {
  const res = makeRes();

  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": nextIp() } }), res,
    { now, keyDocument: DOC, env: {} });
  return { status: res._status, html: String(res._body) };
}
async function reconcileCall(tapeA, tapeB, { env = KEYS } = {}) {
  const res = makeRes();
  await RECONCILE.handleReconcile(makeReq({ method: "POST", query: { op: "reconcile" }, headers: { "content-type": "application/json", "x-forwarded-for": nextIp() },
    body: { agent_tape: tapeA.toString("utf-8"), tool_tape: tapeB.toString("utf-8") } }), res, { env, keyDocument: DOC });
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
const pinsPaths = () => [...gh._repoMap(PINS).keys()];
const esc = (s) => CP._internal.esc(s);
const sealerRun = (dt = 60000, env = deployedEnv()) => S.anchorPending({ now: REVEAL_AT + 3600000 + dt, keyDocument: DOC, env });
const read = (rel) => fs.readFileSync(path.join(__dirname, "..", rel), "utf8");
const README = () => read("README.md").replace(/\s+/g, " ");
function jsFiles(dir) {
  const out = [];
  for (const e of fs.readdirSync(path.join(__dirname, "..", dir), { withFileTypes: true })) {
    const rel = `${dir}/${e.name}`;
    if (e.isDirectory()) out.push(...jsFiles(rel));
    else if (/\.(js|mjs|cjs)$/.test(e.name)) out.push(rel);
  }
  return out;
}

// The registration file at `rpath` as the pins repository holds it: its
// bytes, and their sha256.
const pinFile = (id) => `pins/case/${id}/00000001.json`;
const pinTree = (id) => pinsPaths().filter((p) => p.startsWith(`pins/case/${id}/`)).sort();
// The pin read: pinState since this unit, anchorState before it.
const pinRead = (id, served) => (S.pinState || S.anchorState)(id, served);
// Every request this test's code sends, while `fn` runs: method, decoded
// URL and, for a PUT, whether it named a sha (an update, not a create).
async function spyRequests(fn) {
  const viaMock = global.fetch;
  const seen = [];
  global.fetch = async (url, o) => {
    const method = (o && o.method) || "GET";
    let update = false;
    if (method === "PUT") {
      try {
        update = !!JSON.parse(o.body).sha;
      } catch {
        update = false;
      }
    }
    const r = await viaMock(url, o);
    seen.push({ method, url: decodeURIComponent(String(url)), update, ok: r.ok });
    return r;
  };
  try {
    await fn();
  } finally {
    global.fetch = viaMock;
  }
  return seen;
}

const TAPES = require("../lib/_reconcile_tapes.js");
const rootSha = (id) => gh._repoMap(PINS).get(C.casePath(id)).sha;
const casePuts = (id) => gh.putLog.filter((p) => p.path === C.casePath(id) || p === C.casePath(id)).length;
const RULE_4 = "The case may not have been sealed. Nothing was pinned. Send the same reveal again: it seals the case, or answers that it is already sealed.";
const WITHDRAWN_TEXT = "The case was withdrawn before this reveal could seal it. Nothing was recorded, and this response carries no verdict.";
// The port, failing `n` times (Infinity: always) before it answers.
function portFails(t, n = Infinity) {
  const real = TAPES.reconcileTapes;
  let left = n;
  return t.mock.method(TAPES, "reconcileTapes", (...args) => {
    if (left > 0) {
      left -= 1;
      const e = new Error("the port broke");
      e.name = "PortBroke";
      throw e;
    }
    return real(...args);
  });
}
const noTapeDigest = (c, body) => {
  const text = JSON.stringify(body);
  return !text.includes(c.a.tape_sha256) && !text.includes(c.b.tape_sha256);
};

// =============================================================================
// UNIT R-SIG
// =============================================================================

const checkRecord = require("../lib/_check_record.js");
const LATER = checkpoint.generateKey("arcaeon.io/case-test/2026-10-14rab-later");
// The current document lists a case key that the document a record names
// did not: one published only later.
const CURRENT = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.entry(LATER), KD.reconcileEntry(RECEIPT_KEY)));
const suOf = (doc) => ({ document_sha256: KD.sha256(canonicalBytes(doc)), document_commit: KD.serve(gh, doc) });
const laterSigner = () => {
  const signer = S.loadCaseSigner({ ...KEYS, [S.CASE_SIGNER_ENV]: LATER.signer }, { keyDocument: CURRENT });
  assert.equal(signer.ok, true, JSON.stringify(signer));
  return signer;
};
// A record signed by hand as the service signs one: signed_by, sig_reason
// null, and the signature over the record minus sig.
function signByHand(unsigned, signer) {
  const rec = { ...unsigned, signed_by: signer.keyId, sig_reason: null, sig: null };
  rec.sig = crypto.sign(null, checkRecord.preimage(rec), signer.privateKey).toString("base64");
  return rec;
}
function withoutSig(rec) {
  const { sig: _s, signed_by: _b, sig_reason: _r, ...rest } = rec; // eslint-disable-line no-unused-vars
  return rest;
}
const flipSig = (rec) => {
  const b = Buffer.from(rec.sig, "base64");
  b[10] ^= 1;
  return { ...rec, sig: b.toString("base64") };
};
async function pageUnder(id, doc, now = REVEAL_AT + 3600000) {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": nextIp() } }), res,
    { now, keyDocument: doc, env: {} });
  return { status: res._status, html: String(res._body) };
}
const cell = (html, name) => {
  const m = html.match(new RegExp(`<tr><th>${name}</th><td>(.*?)</td></tr>`));
  return m ? m[1] : null;
};
const RECEIPT_FIELDS_TWO = ["document_commit", "document_sha256"];
// One of each signed record kind, written by this service's own handlers.
async function fourRecords(scope) {
  const s = await sealedCase(`${scope} seal`);
  const ref = await reference(s);
  assert.equal(ref.status, 201, JSON.stringify(ref.body).slice(0, 300));
  const w = await committedCase(`${scope} withdrawal`);
  assert.equal((await withdraw(w.id, w.b)).status, 201);
  const r = await reveal(w, { body: ownOpening(w, "a") });
  assert.equal(r.status, 409, JSON.stringify(r.body).slice(0, 300));
  return { s, w, seal: storedCase(s.id), row: gh.read(PINS, C.referencePath(s.id, 1)), withdrawal: storedCase(w.id), receipt: r.body.refusal_receipt };
}

// =============================================================================
// UNIT R-AB
// =============================================================================

// A key's public key, as R-AB names it: the sha256 of the 32 raw Ed25519
// public-key bytes the verifier carries.
const keyFp = (k) => sha(checkpoint.parseVerifierKey(k.verifier).pub);
// Another name for the same key: the same seed, so the same public key,
// under another name, so another key id.
function renamed(k, name) {
  const b64 = k.signer.split("+").slice(4).join("+");
  const pub = checkpoint.parseSignerKey(k.signer).pub;
  const h = checkpoint.keyHash(name, pub).toString("hex");
  return { signer: `PRIVATE+KEY+${name}+${h}+${b64}`, verifier: `${name}+${h}+${Buffer.concat([Buffer.from([1]), pub]).toString("base64")}` };
}
const ALICE = REG.KEYS.a;
const ALICE_AGAIN = renamed(ALICE, "party-a.example/another-name");
const COLLISION = require("./fixtures/key_id_collision.json");
const caseSigner = () => S.loadCaseSigner(KEYS, { keyDocument: DOC });
const decoded = (u) => decodeURIComponent(String(u));
// A codes-only same_key_both_roles (R-AB 3): no sentence, the roles, and no
// key id anywhere in it (the registration's own path and sha256, data the
// registration refusals carry, may stand beside them).
function sameKeyCodesOnly(body, id, keys) {
  assert.deepEqual([body.ok, body.error_code, body.case_id, body.role, body.other_role, has(body, "error"), has(body, "key_id")],
    [false, "same_key_both_roles", id, "b", "a", false, false], JSON.stringify(body));
  for (const k of keys) assert.equal(JSON.stringify(body).includes(REG.keyIdOf(k)), false, REG.keyIdOf(k));
}
// One public key in both roles, under two names: role a registers under
// ALICE inside role b's request under ALICE_AGAIN, after b's pre-write
// check read no role a; b's projection is then refused and its file stays,
// and the root is written by hand projecting it too (a record no build of
// this service writes since unit R-AB).
async function racedOneKey(scope) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE, ALICE);
  const b = party(id, "b", TOOL_TAPE, ALICE_AGAIN);
  plantStamp(a.commitment_sha256);
  plantStamp(b.commitment_sha256);
  const r = await during((u, m) => m === "GET" && decoded(u).includes(`/repos/${STAMPS}/contents/${stamp.stampPath(b.commitment_sha256)}`),
    () => commit(id, a, NOW + 1000), () => commit(id, b, NOW + 2000));
  assert.equal(r.fired, true, "fixture: role a registered inside role b's request");
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body));
  assert.deepEqual([r.out.status, r.out.body.error_code], [409, "same_key_both_roles"], JSON.stringify(r.out.body));
  const rpath = REG.pathOf(gh, id, "b");
  const text = gh._repoMap(PINS).get(rpath).content;
  gh.seed(PINS, C.casePath(id), C.applyRegistration(storedCase(id), JSON.parse(text), sha(Buffer.from(text, "utf8"))), { keepHistory: true });
  const k = storedCase(id);
  assert.equal(k.status, "COMMITTED");
  assert.notEqual(k.commitments.a.key_id, k.commitments.b.key_id, "fixture: two key ids");
  return { id, a, b };
}
async function withdrawnBy(scope, role) {
  const c = await committedCase(scope);
  assert.equal((await withdraw(c.id, c[role])).status, 201);
  return c;
}
// A VERDICT whose two entries share a key_fp AND agree with their files
// (unit R-ABf, B1): sealed with role a under ALICE, then role b's file
// written again under ALICE_AGAIN (the same commitment) and the root
// projecting it, signed again (a record no build of this service writes).
async function verdictOneKey(scope) {
  const s = await sealedCase(scope, { a: ALICE });
  const v = storedCase(s.id);
  const old = v.commitments.b;
  const rec = C.registrationRecord({ case_id: s.id, role: "b", commitment_sha256: old.commitment_sha256, registered_at: old.registered_at,
    stamp_commit: old.stamp_commit, stamped_at: old.stamped_at, ...REG.keyFields({ case_id: s.id, role: "b", commitment_sha256: old.commitment_sha256 }, ALICE_AGAIN) });
  const rpath = REG.recordPath(rec);
  gh.seed(PINS, rpath, rec);
  const text = gh._repoMap(PINS).get(rpath).content;
  const b = { ...C.commitmentEntry(rec), key_fp: C.keyFpOf(rec.verifier), registration_sha256: sha(Buffer.from(text, "utf8")), claim_sha256: C.claimSha256(rec) };
  const k = signByHand(withoutSig({ ...v, commitments: { ...v.commitments, b } }), caseSigner());
  assert.deepEqual(C.validateCase(k), { ok: true });
  gh.seed(PINS, C.casePath(s.id), k);
  assert.equal((await S.projectedRegistrations(k)).ok, true, "fixture: the root agrees with its files");
  assert.equal(C.singleParty(k), true, "fixture: one key");
  return s;
}
// A root whose b.key_fp is overwritten with a's while file b holds another
// key (unit R-ABf, B1): it does not agree with its files.
const forgedFp = (k) => ({ ...k, commitments: { ...k.commitments, b: { ...k.commitments.b, key_fp: k.commitments.a.key_fp } } });
// Every GET of `path` in the pins repository fails while `fn` runs.
async function unreadable(path, fn) {
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    if (((o && o.method) || "GET") === "GET" && decoded(url).includes(`/repos/${PINS}/contents/${path}`)) {
      return { ok: false, status: 503, headers: { get: () => null }, json: async () => ({}), text: async () => "" };
    }
    return viaMock(url, o);
  };
  try {
    return await fn();
  } finally {
    global.fetch = viaMock;
  }
}

const V3_ANCHOR_NOTE = "This row has no pin of its own. It is recorded by the pins-repository commit that writes it. A later pin of the case " +
  "may list that commit. This row is anchored only if a pin that lists it is, and no anchoring is asserted here.";
const textOf = (html) => html.replace(/<style[\s\S]*?<\/style>/g, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

// --- 1. key_fp on the root's entries ---

test("R-AB 1: a projected entry carries key_fp, the sha256 of the registering key's 32-byte public key, from its registration file's verifier; the file carries none", async () => {
  const c = await committedCase("RAB 1");
  const k = storedCase(c.id);
  for (const r of ["a", "b"]) {
    const file = gh.read(PINS, REG.pathOf(gh, c.id, r));
    assert.equal(has(file, "key_fp"), false, `role ${r}: the registration file carries no key_fp`);
    assert.equal(k.commitments[r].key_fp, keyFp({ verifier: file.verifier }), `role ${r}`);
    assert.equal(k.commitments[r].key_fp, keyFp(REG.KEYS[r]));
  }
  assert.ok(C.CASE_ENTRY_FIELDS.includes("key_fp"));
  assert.equal(C.REGISTRATION_FIELDS.includes("key_fp"), false);
  assert.equal(C.keyFpOf(ALICE.verifier), keyFp(ALICE));
  assert.equal(C.keyFpOf(ALICE_AGAIN.verifier), keyFp(ALICE), "one public key under two names: one key_fp");
});

test("R-AB 1: an entry without key_fp fails the schema, missing_field at commitments.<role>.key_fp, in a COMMITTED root and a WITHDRAWN record; one not 64 lowercase hex is malformed_field; the readers name it", async () => {
  const c = await committedCase("RAB 1 schema");
  const k = storedCase(c.id);
  const { key_fp: _f, ...noFp } = k.commitments.b; // eslint-disable-line no-unused-vars
  const v = C.validateCase({ ...k, commitments: { ...k.commitments, b: noFp } });
  assert.deepEqual([v.ok, v.code, v.field], [false, "missing_field", "commitments.b.key_fp"]);
  for (const bad of ["AB".repeat(32), "ab".repeat(31), 7]) {
    const m = C.validateCase({ ...k, commitments: { ...k.commitments, b: { ...k.commitments.b, key_fp: bad } } });
    assert.deepEqual([m.code, m.field], ["malformed_field", "commitments.b.key_fp"], String(bad));
  }
  const w = await withdrawnBy("RAB 1 schema withdrawn", "a");
  const rec = storedCase(w.id);
  const { key_fp: _g, ...noFpA } = rec.commitments.a; // eslint-disable-line no-unused-vars
  const vw = C.validateCase({ ...rec, commitments: { ...rec.commitments, a: noFpA } });
  assert.deepEqual([vw.code, vw.field], ["missing_field", "commitments.a.key_fp"]);
  gh.seed(PINS, C.casePath(c.id), { ...k, commitments: { ...k.commitments, b: noFp } });
  const r = await withdraw(c.id, c.a);
  assert.deepEqual([r.status, r.body.error_code, r.body.reason], [503, "case_record_unreadable", "case_missing_field"], JSON.stringify(r.body));
});

test("R-AB 1: a root whose key_fp is not its registration file's verifier's does not agree with itself: the page is the inconsistent page, and the withdrawal answers 503 case_record_inconsistent", async () => {
  const c = await committedCase("RAB 1 reader");
  const k = storedCase(c.id);
  gh.seed(PINS, C.casePath(c.id), { ...k, commitments: { ...k.commitments, b: { ...k.commitments.b, key_fp: sha("another public key") } } });
  const p = await casePage(c.id);
  assert.equal(p.status, 503);
  assert.ok(p.html.includes("<code>case_record_inconsistent</code>"), p.html.slice(0, 1500));
  const w = await withdraw(c.id, c.a);
  assert.deepEqual([w.status, w.body.error_code], [503, "case_record_inconsistent"], JSON.stringify(w.body));
});

// --- 2, 3. every key comparison by key_fp; same_key_both_roles codes only ---

test("R-AB 2, 3: role b under role a's public key in another name (another key id) is 409 same_key_both_roles, codes only, and nothing is written to the pins repository", async () => {
  const id = await openCase("RAB 2 renamed");
  await register(id, party(id, "a", AGENT_TAPE, ALICE));
  const b = party(id, "b", TOOL_TAPE, ALICE_AGAIN);
  assert.notEqual(REG.keyIdOf(ALICE_AGAIN), REG.keyIdOf(ALICE), "fixture: another key id");
  plantStamp(b.commitment_sha256);
  const before = pinsPaths().sort();
  const r = await commit(id, b);
  assert.equal(r.status, 409, JSON.stringify(r.body));
  sameKeyCodesOnly(r.body, id, [ALICE, ALICE_AGAIN]);
  assert.deepEqual(r.body, { ok: false, error_code: "same_key_both_roles", case_id: id, role: "b", other_role: "a" }, "refused before the write: the codes alone");
  assert.deepEqual(pinsPaths().sort(), before, "nothing written");
  assert.equal(storedCase(id).commitments.b, null);
});

test("R-AB 3: one key under one name in both roles is 409 same_key_both_roles, codes only: the body names no key id, the requester's or any other", async () => {
  const id = await openCase("RAB 3 one name");
  await register(id, party(id, "a", AGENT_TAPE, ALICE));
  const b = party(id, "b", TOOL_TAPE, ALICE);
  plantStamp(b.commitment_sha256);
  const r = await commit(id, b);
  sameKeyCodesOnly(r.body, id, [ALICE]);
});

test("R-AB 3: a registration that raced past the pre-write check under the other role's public key is refused at its projection, 409 same_key_both_roles, codes only; its file stays and is not projected", async () => {
  const id = await openCase("RAB 3 raced");
  const a = party(id, "a", AGENT_TAPE, ALICE);
  const b = party(id, "b", TOOL_TAPE, ALICE_AGAIN);
  plantStamp(a.commitment_sha256);
  plantStamp(b.commitment_sha256);
  const r = await during((u, m) => m === "GET" && decoded(u).includes(`/repos/${STAMPS}/contents/${stamp.stampPath(b.commitment_sha256)}`),
    () => commit(id, a, NOW + 1000), () => commit(id, b, NOW + 2000));
  assert.equal(r.fired, true);
  sameKeyCodesOnly(r.out.body, id, [ALICE, ALICE_AGAIN]);
  assert.equal(gh.has(PINS, REG.pathOf(gh, id, "b")), true, "its file stays");
  assert.equal(storedCase(id).commitments.b, null, "not projected");
});

test("R-AB 2: two public keys that share a key id (test/fixtures/key_id_collision.json) are two keys: both roles register, the case is not single party, and the reveal seals it", async () => {
  const [k1, k2] = COLLISION.keys;
  const id = await openCase("RAB 2 collision");
  const a = party(id, "a", AGENT_TAPE, k1);
  const b = party(id, "b", TOOL_TAPE, k2);
  for (const p of [a, b]) {
    plantStamp(p.commitment_sha256);
    const r = await commit(id, p);
    assert.equal(r.status, 201, `role ${p.role}: ${JSON.stringify(r.body)}`);
  }
  const k = storedCase(id);
  assert.equal(k.commitments.a.key_id, k.commitments.b.key_id, "one key id");
  assert.notEqual(k.commitments.a.key_fp, k.commitments.b.key_fp, "two public keys");
  assert.equal(C.singleParty(k), false);
  const r = await reveal({ id, a, b });
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  const sealed = storedCase(id);
  assert.equal((await S.sealedRecordReason(sealed, DOC)).code, "valid_under_document");
  assert.match((await casePage(id)).html, /<h2>The verdict<\/h2>/);
});

// Since unit R-ABf (B1) a root is read as single party only once it agrees
// with its files: a VERDICT whose b.key_fp was overwritten with a's while
// file b holds another key is case_record_inconsistent wherever it is read.
test("R-AB 2 (since unit R-ABf, B1): a stored case whose two entries share a key_fp and agree with their files is single party wherever it is read; one whose key_fp was overwritten is case_record_inconsistent on the page, the sealer and the reference", async () => {
  const c = await racedOneKey("RAB 2 one key two names");
  const k = storedCase(c.id);
  assert.equal(C.singleParty(k), true);
  const root = rootSha(c.id);
  const r = await reveal(c);
  assert.deepEqual([r.status, r.body.error_code], [409, "single_party"], JSON.stringify(r.body).slice(0, 300));
  assert.equal(rootSha(c.id), root, "nothing written");
  // a VERDICT signed over such entries, b's key_fp overwritten with a's
  // (a record no build of this service writes)
  const s = await sealedCase("RAB 2 forged verdict");
  const v = storedCase(s.id);
  const forged = signByHand(withoutSig(forgedFp(v)), caseSigner());
  assert.deepEqual(C.validateCase(forged), { ok: true });
  assert.notEqual(forged.commitments.a.key_id, forged.commitments.b.key_id);
  gh.seed(PINS, C.casePath(s.id), forged);
  // the sealed check alone reads no file: the readers read the files first
  assert.deepEqual(await S.sealedRecordReason(forged, DOC), { code: "single_party", reason: "same_key_both_roles" });
  const one = await S.anchorCase(s.id, { now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.deepEqual([one.ok, one.code, one.role, one.reason], [false, "case_record_inconsistent", "b", "projection_differs_from_file"]);
  const ref = await reference(s);
  assert.deepEqual([ref.status, ref.body], [503, { ok: false, error_code: "case_record_inconsistent" }], JSON.stringify(ref.body).slice(0, 300));
  const p = await casePage(s.id);
  assert.equal(p.status, 503);
  assert.ok(p.html.includes("<code>case_record_inconsistent</code>"));
  assert.equal(p.html.includes(CP.SINGLE_PARTY_SENTENCE), false);
});

test("R-AB 2: the seal refuses a COMMITTED case whose entries share a key_fp under two key ids", async () => {
  const c = await racedOneKey("RAB 2 seal");
  assert.throws(() => S.sealCase(storedCase(c.id), {
    reveals: { a: { tape_sha256: c.a.tape_sha256, salt: c.a.salt }, b: { tape_sha256: c.b.tape_sha256, salt: c.b.salt } },
    receipt: {}, revealedAt: "2026-10-10T09:00:00Z", signedUnder: KD.signedUnder(gh, DOC),
  }, caseSigner()), (e) => e instanceof C.CaseError && e.code === "status_inconsistent" && e.field === "commitments");
});

// --- 4. a re-send under another name stays role_already_committed ---

test("R-AB 4: role a sent again under its own public key in another name is 409 role_already_committed; the claim hash is the party-supplied fields' as before, and the same registration sent again is answered as it stands", async () => {
  const id = await openCase("RAB 4");
  const a = party(id, "a", AGENT_TAPE, ALICE);
  await register(id, a);
  const k = storedCase(id);
  const file = gh.read(PINS, REG.pathOf(gh, id, "a"));
  const supplied = { case_id: file.case_id, role: file.role, commitment_sha256: file.commitment_sha256, verifier: file.verifier, key_id: file.key_id, sig: file.sig };
  assert.equal(k.commitments.a.claim_sha256, sha(canonicalBytes(supplied)), "the claim: the party-supplied fields");
  const again = await commit(id, { ...a, key: ALICE_AGAIN });
  assert.deepEqual([again.status, again.body.error_code], [409, "role_already_committed"], JSON.stringify(again.body));
  assert.equal(storedCase(id).commitments.a.claim_sha256, k.commitments.a.claim_sha256);
  assert.equal((await commit(id, a)).status, 200);
});

// --- 5. a WITHDRAWN root with one key is never single party ---

test("R-AB 5: a WITHDRAWN record whose entries share a key_fp is never single party: the withdrawal of such a case is written, and its page is the withdrawn page", async () => {
  const c = await racedOneKey("RAB 5");
  assert.equal((await withdraw(c.id, c.a)).status, 201);
  const w = storedCase(c.id);
  assert.equal(w.status, "WITHDRAWN");
  assert.equal(w.commitments.a.key_fp, w.commitments.b.key_fp, "fixture: the kept projection shares a key_fp");
  assert.equal(C.singleParty(w), false);
  const p = await casePage(c.id);
  assert.match(p.html, /<h1>Case: WITHDRAWN<\/h1>/);
});

// --- 6. the single-party page: one sentence, at 200 ---

test("R-AB 6: a single-key stored case's page is the one-sentence shape at 200: the sentence, single_party as a code, and the record's links; no key id, label, time, verdict, limits or holder", async () => {
  const c = await racedOneKey("RAB 6");
  const k = storedCase(c.id);
  const p = await casePage(c.id);
  assert.equal(p.status, 200);
  assert.match(p.html, /<h1>Case: SINGLE PARTY<\/h1>/);
  assert.equal(CP.SINGLE_PARTY_SENTENCE, "One key signs the registrations of both roles of this case; this page shows nothing else from it.");
  assert.ok(p.html.includes(`<section class="panel"><p class="notice">${esc(CP.SINGLE_PARTY_SENTENCE)}</p><p class="muted"><code>single_party</code> &middot; `),
    p.html.slice(0, 2500));
  for (const s of [k.commitments.a.key_id, k.commitments.b.key_id, "agent-operator@example.com", "tool-operator@example.com", k.commitments.a.registered_at,
    k.opened_at, "<h2>", "What this service does not establish"]) {
    assert.equal(p.html.includes(s), false, s);
  }
  assert.doesNotMatch(textOf(p.html), /\bholds?\b|holder|held by|one party|two parties|who /i);
  // a VERDICT read so, its root agreeing with its files: the same page
  const s = await verdictOneKey("RAB 6 verdict");
  const pv = await casePage(s.id);
  assert.equal(pv.status, 200);
  assert.ok(pv.html.includes(`<p class="notice">${esc(CP.SINGLE_PARTY_SENTENCE)}</p><p class="muted"><code>single_party</code> &middot; `));
  assert.equal(pv.html.includes("<h2>The verdict</h2>"), false);
});

// --- 7. the sealed page makes no claim about key identity ---

test("R-AB 7: the sealed page makes no claim about key identity, and no library file says \"two keys, never two parties\"", async () => {
  const s = await sealedCase("RAB 7");
  const p = await casePage(s.id);
  assert.match(p.html, /<h2>The verdict<\/h2>/, "fixture: a sealed page");
  assert.doesNotMatch(textOf(p.html), /two keys|one key\b|same key|distinct keys|different keys|two parties|two holders|two people|held by|belongs to|identity of/i);
  for (const f of jsFiles("lib")) assert.equal(read(f).includes("two keys, never two parties"), false, f);
});

// --- 8. the record of section 2A ---

test("R-AB 8: the red-team header marks section 2A NARROWED, and no library comment says a key id is one key, that the roles take two distinct key ids, or that a withdrawn root holds no projection", () => {
  const head = read("test/case_redteam.test.js").split("\n").slice(0, 60).join("\n");
  assert.match(head, /§2A[^\n]*\n?[^\n]*NARROWED/);
  for (const f of ["lib/_case.js", "lib/_case_http.js", "lib/_case_seal.js", "lib/_case_page.js"]) {
    assert.doesNotMatch(read(f), /one key id is one key|two distinct key ids|share a key id|one key id registered both roles|holds no projection/, f);
  }
});

// --- the R-RVf3 carry-overs ---

test("R-AB (a): the sealer writes a withdrawn case's missing marker only when the withdrawal record verifies; one whose signature does not verify, or whose named document cannot be read, is logged and left, nothing written", async (t) => {
  const ok = await withdrawnBy("RAB a control", "b");
  const bad = await withdrawnBy("RAB a invalid", "b");
  const away = await withdrawnBy("RAB a unavailable", "b");
  gh.seed(PINS, C.casePath(bad.id), flipSig(storedCase(bad.id)));
  const w = storedCase(away.id);
  gh.seed(PINS, C.casePath(away.id), signByHand(withoutSig({ ...w, signed_under: { ...w.signed_under, document_commit: "0".repeat(40) } }), caseSigner()));
  for (const c of [ok, bad, away]) gh._repoMap(PINS).delete(C.withdrawnMarkerPath(c.id));
  const logged = [];
  t.mock.method(console, "error", (...args) => logged.push(args.join(" ")));
  const run = await sealerRun();
  assert.equal(run.ok, true, JSON.stringify(run));
  assert.deepEqual(run.withdrawn_repaired.map((x) => x.case_id), [ok.id], JSON.stringify(run.withdrawn_repaired));
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(ok.id)), true, "the control is repaired");
  for (const c of [bad, away]) {
    assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c.id)), false, "no marker");
    assert.ok(logged.some((l) => l.includes(c.id)), `logged: ${c.id.slice(0, 12)}`);
  }
  assert.deepEqual(run.terminal.map((x) => x.case_id).sort(), [ok.id, bad.id, away.id].sort(), "each read as terminal, as before");
});

test("R-AB (b): the reference answers a sealed case whose named key document cannot be read 503 document_unavailable, codes only, writing nothing; sent again once it reads, the row is written; a document that reads and refuses the key stays 409", async () => {
  const s = await sealedCase("RAB b");
  const k = storedCase(s.id);
  // the seal names a second document, listing the same keys and one more,
  // served at its own commit, so that only its read can be made to fail
  const OTHER = checkpoint.generateKey("arcaeon.io/case-test/2026-10-14rab-other");
  const DOC2 = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.entry(OTHER), KD.reconcileEntry(RECEIPT_KEY)));
  const su2 = suOf(DOC2);
  gh.seed(PINS, C.casePath(s.id), signByHand(withoutSig({ ...k, signed_under: su2 }), caseSigner()));
  S._internal.clearDocumentCache();
  gh.forceRawFailure(1000, 503, su2.document_commit);
  const puts = gh.putLog.length;
  let r;
  try {
    r = await reference(s);
  } finally {
    gh.forceRawFailure(0);
  }
  assert.equal(r.status, 503, JSON.stringify(r.body));
  assert.deepEqual(r.body, { ok: false, error_code: "document_unavailable", case_id: s.id, reason: r.body.reason });
  assert.equal(typeof r.body.reason, "string");
  assert.equal(gh.putLog.length, puts, "nothing written");
  const again = await reference(s);
  assert.equal(again.status, 201, JSON.stringify(again.body).slice(0, 300));
  // the document reads, and the case's signature does not hold under it: 409
  const t2 = await sealedCase("RAB b refused");
  gh.seed(PINS, C.casePath(t2.id), flipSig(storedCase(t2.id)));
  const no = await reference(t2);
  assert.deepEqual([no.status, no.body.error_code], [409, "signature_invalid"], JSON.stringify(no.body).slice(0, 300));
});

// --- the R-RVf3 reader's small items ---

test("R-AB m1: a withdrawal record whose key the current document lists revoked is refused with the revoked-key words, never the bare code", async () => {
  const c = await withdrawnBy("RAB m1", "b");
  const REVOKED = Object.freeze(KD.docWith(KD.entry(CASE_KEY, { status: "revoked" }), KD.reconcileEntry(RECEIPT_KEY)));
  const res = makeRes();
  await H.handleCaseWithdraw(req("case-withdraw", { case_id: c.id, role: "b", tape_sha256: c.b.tape_sha256, salt: c.b.salt }), res,
    { now: NOW + 3000, env: KD.deployed(gh, KEYS, DOC), keyDocument: REVOKED });
  const body = parsed(res);
  assert.deepEqual([res._status, body.error_code, body.reason], [409, "signer_revoked", "key_revoked"], JSON.stringify(body));
  assert.ok(body.error.includes("one of the keys it is signed with is listed as revoked in the key document this service carries"), body.error);
  assert.doesNotMatch(body.error, /: signer_revoked\b/);
});

test("R-AB m2: a withdrawal record whose named document cannot be read for a moment: the refusal receipt and the retried withdrawal each answer 503 document_unavailable, and each sent again once it reads finishes", async () => {
  const c = await withdrawnBy("RAB m2", "b");
  gh._repoMap(PINS).delete(C.withdrawnMarkerPath(c.id));
  S._internal.clearDocumentCache();
  gh.forceRawFailure(1000, 503);
  let r1;
  let w1;
  try {
    r1 = await reveal(c, { body: ownOpening(c, "a") });
    w1 = await withdraw(c.id, c.b);
  } finally {
    gh.forceRawFailure(0);
  }
  assert.deepEqual([r1.status, r1.body.error_code, has(r1.body, "refusal_receipt")], [503, "document_unavailable", false], JSON.stringify(r1.body).slice(0, 300));
  assert.deepEqual([w1.status, w1.body.error_code], [503, "document_unavailable"], JSON.stringify(w1.body).slice(0, 300));
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c.id)), false, "no marker yet");
  const r2 = await reveal(c, { body: ownOpening(c, "a") });
  assert.deepEqual([r2.status, r2.body.error_code], [409, "case_withdrawn"]);
  assert.deepEqual(await S.verifyRefusalReceipt(r2.body.refusal_receipt, DOC), { ok: true });
  const w2 = await withdraw(c.id, c.b);
  assert.deepEqual([w2.status, w2.body.existing], [200, true], JSON.stringify(w2.body).slice(0, 300));
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c.id)), true, "the marker, written by the re-send");
});

test("R-AB m3: a version-3 row whose named document cannot be read is unreadable: neither counted nor invalid", async () => {
  const f = await fourRecords("RAB m3");
  gh.seed(PINS, C.referencePath(f.s.id, 1), signByHand({ ...withoutSig(f.row), note_version: 3, anchor_note: V3_ANCHOR_NOTE }, caseSigner()));
  S._internal.clearDocumentCache();
  gh.forceRawFailure(1000, 503);
  let live;
  try {
    live = await S.liveRecords(f.seal, { keyDocument: DOC });
  } finally {
    gh.forceRawFailure(0);
  }
  assert.deepEqual([live.records, live.indeterminate, live.unreadable, live.invalid], [null, true, [1], []], JSON.stringify(live));
});

test("R-AB m5: a receipt alteration the binding sees reads verdict_unbound with the binding's reason, whether or not the case was signed again over it", async () => {
  const s = await sealedCase("RAB m5");
  const k = storedCase(s.id);
  const altered = { ...k, verdict: { ...k.verdict, compared_at: "2026-10-10T08:59:59Z" } };
  const resigned = signByHand(withoutSig(altered), caseSigner());
  assert.notEqual(resigned.sig, k.sig, "fixture: signed again");
  for (const rec of [altered, resigned]) {
    assert.deepEqual(await S.sealedRecordReason(rec, DOC), { code: "verdict_unbound", reason: "receipt_time_mismatch" });
  }
});

// R-AB's must-fail gap tests: each fails with its planted defect
test("MUST-FAIL GAP (K07): singleParty reads one key only from two key_fp values that are one: entries in the form before unit R-AB (no key_fp, two key ids) are not one key", async () => {
  const c = await committedCase("RAB gap K07");
  const k = storedCase(c.id);
  const bare = (e) => {
    const { key_fp: _f, ...rest } = e; // eslint-disable-line no-unused-vars
    return rest;
  };
  assert.notEqual(k.commitments.a.key_id, k.commitments.b.key_id, "fixture: two keys");
  assert.equal(C.singleParty({ ...k, commitments: { a: bare(k.commitments.a), b: bare(k.commitments.b) } }), false);
  assert.equal(C.singleParty(k), false, "control: the stored form");
});

// =============================================================================
// UNIT R-ABf (the fixes for R-AB)
// =============================================================================

// --- B1: the files are read before a root is judged single party ---

test("R-ABf B1: a COMMITTED root whose b.key_fp is overwritten with a's while file b holds another key reads case_record_inconsistent on the page and the sealer, never the single-party page", async () => {
  const c = await committedCase("RABf B1 committed");
  const k = storedCase(c.id);
  gh.seed(PINS, C.casePath(c.id), forgedFp(k));
  assert.equal(C.singleParty(storedCase(c.id)), true, "fixture: the stored key_fp reads one key");
  const p = await casePage(c.id);
  assert.equal(p.status, 503);
  assert.ok(p.html.includes("<code>case_record_inconsistent</code>"), p.html.slice(0, 1500));
  assert.equal(p.html.includes(CP.SINGLE_PARTY_SENTENCE), false, "the page never says one key signs both roles");
  const one = await S.anchorCase(c.id, { now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.deepEqual([one.ok, one.code, one.role, one.reason], [false, "case_record_inconsistent", "b", "projection_differs_from_file"]);
  const r = await reveal(c);
  assert.deepEqual([r.status, r.body.error_code], [503, "case_record_inconsistent"], "the reveal, as before");
});

test("R-ABf B1: a single-key VERDICT whose root agrees with its files is single party everywhere: the page 200, the sealer not_sealed single_party, the reference 409 single_party, codes only (m-a)", async () => {
  const s = await verdictOneKey("RABf B1 verdict one key");
  const p = await casePage(s.id);
  assert.equal(p.status, 200);
  assert.ok(p.html.includes(CP.SINGLE_PARTY_SENTENCE));
  const one = await S.anchorCase(s.id, { now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.deepEqual([one.ok, one.code, one.reason], [false, "not_sealed", "single_party"]);
  const ref = await reference(s);
  assert.equal(ref.status, 409, JSON.stringify(ref.body));
  assert.deepEqual(ref.body, { ok: false, error_code: "single_party", case_id: s.id });
  const op = await reference(s, { role: "b" });
  assert.deepEqual([op.status, op.body.error_code], [409, "single_party"]);
});

test("R-ABf B1: a single-key root whose registration file cannot be read is could-not-look: the page 503 (never the single-party page), the sealer could_not_look, the reference 503", async () => {
  const c = await racedOneKey("RABf B1 unread");
  const rpath = REG.pathOf(gh, c.id, "b");
  const p = await unreadable(rpath, () => casePage(c.id));
  assert.equal(p.status, 503);
  assert.equal(p.html.includes(CP.SINGLE_PARTY_SENTENCE), false);
  assert.ok(p.html.includes(`<p class="notice">${esc(CP.UNREAD_SENTENCE)}</p><p class="muted"><code>could_not_look</code> &middot; `), p.html.slice(0, 2000));
  const one = await unreadable(rpath, () => S.anchorCase(c.id, { now: REVEAL_AT + 60000, keyDocument: DOC }));
  assert.deepEqual([one.ok, one.code], [false, "could_not_look"]);
  // read again once the file reads: the single-party page
  assert.ok((await casePage(c.id)).html.includes(CP.SINGLE_PARTY_SENTENCE));
});

test("R-ABf B1: the reference reads the projected files before the sealed check, for the operator too: a forged key_fp is 503 case_record_inconsistent, codes only, and nothing is written", async () => {
  const s = await sealedCase("RABf B1 operator");
  const v = storedCase(s.id);
  gh.seed(PINS, C.casePath(s.id), signByHand(withoutSig(forgedFp(v)), caseSigner()));
  const puts = gh.putLog.length;
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: s.id, cross_reference: XREF }, { authorization: "Bearer case-operator-key-0171-rab" }), res,
    { now: REVEAL_AT + 1800000, env: KD.deployed(gh, { ...KEYS, [H.OPERATOR_KEY_ENV]: "case-operator-key-0171-rab" }, DOC), keyDocument: DOC });
  assert.deepEqual([res._status, parsed(res)], [503, { ok: false, error_code: "case_record_inconsistent" }], JSON.stringify(parsed(res)));
  assert.equal(gh.putLog.length, puts, "nothing written");
});

// --- M2: a named commit definitely off the published branch is a known refusal ---

// A sealed case naming a document served at a commit off the published
// branch (diverged), its case signature good.
async function sealedOffBranch(scope) {
  const c = await committedCase(scope);
  const compared = RECONCILE.compare(c.a.tape, c.b.tape, { env: KEYS, now: REVEAL_AT, keyDocument: DOC });
  const named = KD.docWith(KD.entry(CASE_KEY, { note: "the off-branch document" }), KD.reconcileEntry(RECEIPT_KEY));
  const side = KD.serveOffBranch(gh, named, "9".repeat(40));
  const k = S.sealCase(storedCase(c.id), {
    reveals: { a: { tape_sha256: c.a.tape_sha256, salt: c.a.salt }, b: { tape_sha256: c.b.tape_sha256, salt: c.b.salt } },
    receipt: S.storableReceipt(compared.receipt).receipt, crossReference: null, revealedAt: C.utcSeconds(REVEAL_AT),
    signedUnder: { document_sha256: KD.sha256(canonicalBytes(named)), document_commit: side },
  }, S.loadCaseSigner(KEYS, { keyDocument: named }));
  gh.seed(PINS, C.casePath(c.id), k);
  return { ...c, k, side };
}

test("R-ABf M2: a sealed case naming a commit definitely off the published branch: the one reader answers document_off_branch; the reference 409 document_off_branch, codes only; the page 200, saying so; the sealer refuses it, never could_not_look", async () => {
  const c = await sealedOffBranch("RABf M2 off branch");
  assert.deepEqual(await S.sealedRecordReason(c.k, DOC), { code: "document_off_branch", reason: "commit_not_on_branch", document: "named", document_commit: c.side });
  const puts = gh.putLog.length;
  const ref = await reference(c);
  assert.equal(ref.status, 409, JSON.stringify(ref.body));
  assert.deepEqual(ref.body, { ok: false, error_code: "document_off_branch", case_id: c.id, reason: "commit_not_on_branch" });
  assert.equal(gh.putLog.length, puts, "nothing written");
  const p = await casePage(c.id);
  assert.equal(p.status, 200);
  assert.ok(p.html.includes("is not on the published branch"));
  const run = await sealerRun();
  assert.deepEqual(run.could_not_look, []);
  assert.deepEqual(run.refused.filter((x) => x.case_id === c.id), [{ case_id: c.id, code: "document_off_branch", reason: "commit_not_on_branch" }]);
});

test("R-ABf M2: a named commit the repository does not have (404) stays a could-not-look: the reference 503 document_unavailable, the page 503", async () => {
  const s = await sealedCase("RABf M2 not found");
  const v = storedCase(s.id);
  gh.seed(PINS, C.casePath(s.id), signByHand(withoutSig({ ...v, signed_under: { ...v.signed_under, document_commit: "6".repeat(40) } }), caseSigner()));
  const ref = await reference(s);
  assert.deepEqual([ref.status, ref.body.error_code], [503, "document_unavailable"], JSON.stringify(ref.body));
  assert.equal((await casePage(s.id)).status, 503);
});

test("R-ABf M2: a withdrawal record naming a commit off the published branch: the retried withdrawal and the refusal receipt are 409 document_off_branch, with words, never the bare code; verifyRefusalReceipt says document_off_branch", async () => {
  const c = await withdrawnBy("RABf M2 withdrawn", "b");
  const w = storedCase(c.id);
  const named = KD.docWith(KD.entry(CASE_KEY, { note: "the off-branch document" }), KD.reconcileEntry(RECEIPT_KEY));
  const side = KD.serveOffBranch(gh, named, "8".repeat(40));
  gh.seed(PINS, C.casePath(c.id), signByHand(withoutSig({ ...w, signed_under: { document_sha256: KD.sha256(canonicalBytes(named)), document_commit: side } }), caseSigner()));
  const r = await withdraw(c.id, c.b);
  assert.deepEqual([r.status, r.body.error_code, r.body.reason], [409, "document_off_branch", "commit_not_on_branch"], JSON.stringify(r.body));
  assert.ok(r.body.error.includes("the key document it names is at a commit that is not on the published branch"), r.body.error);
  const rr = await reveal(c, { body: ownOpening(c, "a") });
  assert.deepEqual([rr.status, rr.body.error_code], [409, "document_off_branch"]);
  const good = await withdrawnBy("RABf M2 receipt", "b");
  const receipt = (await reveal(good, { body: ownOpening(good, "a") })).body.refusal_receipt;
  assert.deepEqual(await S.verifyRefusalReceipt({ ...receipt, signed_under: { ...receipt.signed_under, document_commit: side } }, DOC),
    { ok: false, reason: "document_off_branch", detail: "commit_not_on_branch" });
});

// --- m-b: UNSEALED_WORDS.document_unavailable is still reached ---

test("R-ABf m-b: the withdrawn root's could-not-look (unconfirmedWithdrawal) still prints UNSEALED_WORDS.document_unavailable, so the words stay", async () => {
  const c = await withdrawnBy("RABf m-b", "b");
  S._internal.clearDocumentCache();
  gh.forceRawFailure(1000, 503);
  let r;
  try {
    r = await withdraw(c.id, c.b);
  } finally {
    gh.forceRawFailure(0);
  }
  assert.deepEqual([r.status, r.body.error_code], [503, "document_unavailable"]);
  assert.ok(r.body.error.includes("the key document it names could not be read on this request, which is not a no"), r.body.error);
});

// R-ABf's must-fail gap tests: each fails with its planted defect
test("MUST-FAIL GAP (PG4): the could-not-look sentence for a single-key root whose file could not be read, exactly", () => {
  assert.equal(CP.UNREAD_SENTENCE, "A registration file this case projects could not be read when this page was read, so nothing is asserted about " +
    "this case; this is not a no.");
});

test("MUST-FAIL GAP (PG6): a named commit the repository does not have (404) is worded as a read that failed, 'try again', never as off the published branch", async () => {
  const s = await sealedCase("RABf gap PG6");
  const v = storedCase(s.id);
  gh.seed(PINS, C.casePath(s.id), signByHand(withoutSig({ ...v, signed_under: { ...v.signed_under, document_commit: "6".repeat(40) } }), caseSigner()));
  const p = await casePage(s.id);
  assert.equal(p.status, 503);
  assert.ok(p.html.includes("This is not a no; try again."), p.html.slice(0, 2500));
  assert.equal(p.html.includes("is not on the published branch"), false);
});
