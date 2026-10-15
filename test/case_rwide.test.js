// test/case_rwide.test.js — unit R-WIDE (2026-10-15): the fixes three
// outside readers asked for after reading the whole protocol at a118c94 as
// hostile strangers, in four groups (A: page sentences that claim more than
// the record; B: fail-closed and the read budget; C: small truth fixes; D:
// stamps). Each test fails on the code at 07903f3. The setup below is
// test/case_rab.test.js's.
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-15rwide");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-15rwide");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-15rwide");
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
const OPERATOR_KEY = "case-operator-key-0171-rwide";
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
const LATER = checkpoint.generateKey("arcaeon.io/case-test/2026-10-15rwide-later");
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
const statusHandler = require("../api/status.js");

// =============================================================================
// GROUP A: page sentences that claim more than the record
// =============================================================================

// A1. The records line prints only what was read.
const XREF_SENTENCE = "one cross-reference was recorded by the sender of the reveal; this service did not contact the operator it names";
const recordsCell = (html) => cell(html, "records");

test("R-WIDE A1: a reveal that carried a typed cross_reference: the records line says one cross-reference was recorded by the sender of the reveal and that this service did not contact the operator it names, and nothing about a second operator", async () => {
  const c = await committedCase("RWIDE A1 xref");
  const r = await reveal(c, { body: { ...revealBody(c.id, c.a, c.b), cross_reference: XREF } });
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.equal(storedCase(c.id).records, 2, "fixture: the sealed record's records counts the typed cross_reference");
  const p = await casePage(c.id);
  assert.equal(p.status, 200);
  const t = recordsCell(p.html);
  assert.ok(t.startsWith(esc(XREF_SENTENCE)), t);
  assert.ok(t.includes(esc("no reference row was appended")), t);
  // "holds" is read as the records line's word (the UNSURE list): the page
  // keeps it in ruled sentences about labels, pins and the withdrawal claim
  assert.doesNotMatch(t, /\bholds?\b/);
  for (const word of [/second operator/i, /holds? a record/, /two records/, /one record/]) assert.doesNotMatch(p.html, word, String(word));
});

test("R-WIDE A1: a case with two party rows prints the count and, per row, the preimage that appended it; an operator row says the operator key; nothing about a second operator", async () => {
  const s = await sealedCase("RWIDE A1 rows");
  const none = recordsCell((await casePage(s.id)).html);
  assert.equal(none, esc("no reference row was appended"), none);
  for (const role of ["a", "b"]) assert.equal((await reference(s, { role })).status, 201);
  const p = await casePage(s.id);
  const t = recordsCell(p.html);
  assert.equal(t, esc("2 reference rows were appended: row 1 on presentation of role a's commitment preimage; row 2 on presentation of " +
    "role b's commitment preimage"), t);
  assert.doesNotMatch(t, /\bholds?\b/);
  assert.doesNotMatch(p.html, /second operator|holds? a record|two records|one record/);
  assert.equal((await operatorReference(s)).status, 201);
  const t3 = recordsCell((await casePage(s.id)).html);
  assert.ok(t3.startsWith(esc("3 reference rows were appended: row 1 on presentation of role a's commitment preimage; ")), t3);
  assert.ok(t3.endsWith(esc("; row 3 with the operator key")), t3);
});

test("R-WIDE A1: the README says what a reference row and a typed cross-reference are, and never 'second operator'", () => {
  const r = README();
  assert.doesNotMatch(r, /second operator/i);
  assert.ok(r.includes(`When the reveal carried a cross_reference, the page says "${XREF_SENTENCE}"`), "the README's records sentence");
});

// A2. A withdrawal is accepted on presentation of a preimage, not of a party.
test("R-WIDE A2: the withdrawn page says 'withdrawn on presentation of role a's commitment preimage, at T', never that the role proved itself; the README says the same", async () => {
  const c = await committedCase("RWIDE A2");
  assert.equal((await withdraw(c.id, c.a)).status, 201);
  const at = storedCase(c.id).withdrawal.at;
  const p = await casePage(c.id);
  assert.equal(p.status, 200);
  assert.ok(p.html.includes(esc(`withdrawn on presentation of role a's commitment preimage, at ${at}`)), p.html);
  assert.doesNotMatch(p.html, /proved itself|by role a,/);
  const r = README();
  assert.doesNotMatch(r, /proves the requesting role|proved itself with its commitment preimage/);
  assert.ok(r.includes("A withdrawal (`?op=case-withdraw`) is accepted on presentation of a role's commitment preimage"), "README withdrawal sentence");
  assert.ok(r.includes("withdrawn on presentation of role a's commitment preimage"), "README page sentence");
});

test("R-WIDE A2: a refusal receipt is issued on presentation of a party's preimage, and the refusal says so in those words", async () => {
  const c = await committedCase("RWIDE A2 receipt");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const r = await reveal(c); // no role named: no receipt
  assert.deepEqual([r.status, r.body.error_code], [404, "not_a_party"], JSON.stringify(r.body).slice(0, 300));
  assert.ok(r.body.error.startsWith("the case was withdrawn, and a refusal receipt is issued on presentation of a party's preimage: name your role"), r.body.error);
  assert.doesNotMatch(r.body.error, /to a party only/);
});

// A3. The WITHDRAWN page fails closed.
const caseSigner = () => S.loadCaseSigner(KEYS, { keyDocument: DOC });
const namingNoDocument = (w) => signByHand({ ...withoutSig(w), signed_under: { ...w.signed_under, document_commit: "0".repeat(40) } }, caseSigner());
async function withdrawnBy(scope, role) {
  const c = await committedCase(scope);
  assert.equal((await withdraw(c.id, c[role])).status, 201);
  return c;
}
const WITHDRAWAL_DETAIL = [/withdrawn on presentation/, /by role [ab]/, /No reason was given/, /The withdrawal record<\/h2>/,
  new RegExp(esc(S.WITHDRAWAL_CLAIM).slice(0, 60).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), /registrations, if any/i];
const OTHER_CASE_DOC = Object.freeze(KD.docWith(KD.entry(LATER), KD.reconcileEntry(RECEIPT_KEY)));
const REVOKED_CASE_DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY, { status: "revoked" }), KD.reconcileEntry(RECEIPT_KEY)));

test("R-WIDE A3: a withdrawal record whose signature does not verify (signature_invalid, signer_unlisted) shows no withdrawal detail: the one-sentence refusal page with its code, at 200", async () => {
  const bad = await withdrawnBy("RWIDE A3 invalid", "a");
  gh.seed(PINS, C.casePath(bad.id), flipSig(storedCase(bad.id)));
  const unlisted = await withdrawnBy("RWIDE A3 unlisted", "a");
  for (const [id, doc, code] of [[bad.id, DOC, "signature_invalid"], [unlisted.id, OTHER_CASE_DOC, "signer_unlisted"]]) {
    const p = await pageUnder(id, doc);
    assert.equal(p.status, 200, code);
    assert.ok(p.html.includes(esc(CP.WITHDRAWAL_UNVERIFIED_SENTENCE)), `${code}: ${p.html.slice(0, 2000)}`);
    assert.ok(p.html.includes(`<code>${code}</code>`), code);
    for (const d of WITHDRAWAL_DETAIL) assert.doesNotMatch(p.html, d, `${code}: ${d}`);
  }
  // control: the record as written shows its detail
  const ok = await withdrawnBy("RWIDE A3 control", "a");
  assert.ok((await pageUnder(ok.id, DOC)).html.includes("withdrawn on presentation of role a&#39;s commitment preimage"));
});

test("R-WIDE A3: a withdrawal record signed by a key the current document lists revoked is the SIGNED BY A REVOKED KEY page, with no withdrawal detail", async () => {
  const c = await withdrawnBy("RWIDE A3 revoked", "a");
  const p = await pageUnder(c.id, REVOKED_CASE_DOC);
  assert.equal(p.status, 200);
  assert.match(p.html, /<h1>Case: SIGNED BY A REVOKED KEY<\/h1>/);
  assert.ok(p.html.includes("so this page does not show its withdrawal record, whenever it was signed."), p.html.slice(0, 3000));
  for (const d of WITHDRAWAL_DETAIL) assert.doesNotMatch(p.html, d, String(d));
});

test("R-WIDE A3: a withdrawal record whose named document cannot be read is the could-not-look page at 503, with no withdrawal detail", async () => {
  const c = await withdrawnBy("RWIDE A3 could not look", "a");
  gh.seed(PINS, C.casePath(c.id), namingNoDocument(storedCase(c.id)));
  const p = await pageUnder(c.id, DOC);
  assert.equal(p.status, 503);
  assert.match(p.html, /<h1>Case: COULD NOT LOOK<\/h1>/);
  assert.ok(p.html.includes("says neither that the withdrawal record verifies nor that it does not"), p.html.slice(0, 3000));
  for (const d of WITHDRAWAL_DETAIL) assert.doesNotMatch(p.html, d, String(d));
});

// A4. What a registration's signature binds, and the key the opening names.
const REGISTRATION_SENTENCE = "A registration file is signed by the key that registered it; this service does not bind that key to the party label " +
  "or to the commitment's preimage.";
test("R-WIDE A4: the registration sentence says the file is signed by the key that registered it and binds that key to nothing else, on the page and in the README", async () => {
  const c = await committedCase("RWIDE A4 sentence");
  const p = await casePage(c.id, NOW + 60000);
  assert.ok(p.html.includes(esc(REGISTRATION_SENTENCE)), p.html.slice(0, 4000));
  assert.doesNotMatch(p.html, /registering party/);
  assert.ok(README().includes(REGISTRATION_SENTENCE));
  assert.doesNotMatch(README(), /signed by the registering party/);
});

const OTHER_A = checkpoint.generateKey("party-a-named.example/case-registration");
async function openNaming(scope, keys) {
  const body = opening(scope);
  if (keys.a) body.party_a = { ...body.party_a, key_id: keys.a };
  if (keys.b) body.party_b = { ...body.party_b, key_id: keys.b };
  const o = makeRes();
  await H.handleCaseOpen(req("case-open", body, OPEN_AUTH), o, { now: NOW });
  assert.equal(o._status, 201, JSON.stringify(o._body));
  return o._body.case_id;
}
test("R-WIDE A4: a registration under a key other than the one the opening names for that role is refused 409 key_mismatch, codes only, and nothing is written", async () => {
  const id = await openNaming("RWIDE A4 key", { a: REG.keyIdOf(OTHER_A), b: REG.keyIdOf(REG.KEYS.b) });
  const a = party(id, "a", AGENT_TAPE); // signed with REG.KEYS.a, not the key the opening names
  plantStamp(a.commitment_sha256);
  const puts = gh.putLog.length;
  const r = await commit(id, a);
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.deepEqual(r.body, { ok: false, error_code: "key_mismatch", case_id: id, role: "a" });
  assert.equal(gh.putLog.length, puts, "nothing written");
  assert.deepEqual(REG.filesOf(gh, id, "a"), []);
  // controls: the named key registers; a role whose key the opening names
  // with its own key registers
  const a2 = party(id, "a", AGENT_TAPE, OTHER_A);
  plantStamp(a2.commitment_sha256);
  assert.equal((await commit(id, a2)).status, 201);
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(b.commitment_sha256);
  assert.equal((await commit(id, b)).status, 201);
  // and an opening that names no key compares nothing
  const free = await committedCase("RWIDE A4 no key named");
  assert.equal(storedCase(free.id).status, "COMMITTED");
});

// A5. A document with no active reconcile key offers no sealing.
const NO_RECONCILE = Object.freeze(KD.docWith(KD.entry(CASE_KEY)));
const RECONCILE_REVOKED = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY, { status: "revoked" })));
test("R-WIDE A5: a reveal from a deployment whose document lists no active reconcile key is 409 sealing_not_offered, codes only; nothing is compared or written", async () => {
  for (const [what, doc] of [["none listed", NO_RECONCILE], ["revoked", RECONCILE_REVOKED]]) {
    const c = await committedCase(`RWIDE A5 reveal ${what}`);
    const root = rootSha(c.id);
    const puts = gh.putLog.length;
    const r = await reveal(c, { keyDocument: doc });
    assert.equal(r.status, 409, `${what}: ${JSON.stringify(r.body)}`);
    assert.deepEqual(r.body, { ok: false, error_code: "sealing_not_offered", case_id: c.id }, what);
    assert.equal(rootSha(c.id), root, what);
    assert.equal(gh.putLog.length, puts, what);
  }
  // control: a document that lists the reconcile key, with no reconcile key
  // configured, is still the 503 an operator can finish
  const c = await committedCase("RWIDE A5 reveal control");
  const { [receipts.SIGNER_ENV]: _r, ...noSigner } = KEYS; // eslint-disable-line no-unused-vars
  const u = await reveal(c, { env: noSigner });
  assert.deepEqual([u.status, u.body.error_code], [503, "signer_unavailable"]);
});

test("R-WIDE A5: a refusal receipt from a deployment whose document lists no active reconcile key is 409 sealing_not_offered, codes only, and carries no receipt", async () => {
  const c = await withdrawnBy("RWIDE A5 receipt", "b");
  const r = await reveal(c, { body: ownOpening(c, "a"), keyDocument: NO_RECONCILE });
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.deepEqual(r.body, { ok: false, error_code: "sealing_not_offered", case_id: c.id, status: "WITHDRAWN" });
  // control: the document that lists it gives the receipt
  const g = await reveal(c, { body: ownOpening(c, "a") });
  assert.deepEqual([g.status, g.body.error_code, has(g.body, "refusal_receipt")], [409, "case_withdrawn", true]);
});

test("R-WIDE A5: the committed key document's description does not describe a reconcile key it does not list", () => {
  const doc = JSON.parse(read("public/.well-known/arcaeon/case-signing-keys.json"));
  const listsOne = doc.keys.some((e) => e.role === "reconcile" && e.status === "active");
  assert.equal(listsOne, false, "fixture: the committed document lists no active reconcile key (publishing it is a deploy step)");
  assert.doesNotMatch(doc.description, /The reconcile key \(role reconcile\) signs/);
  assert.ok(doc.description.includes("while this document lists no active reconcile key, this service seals no case and issues no refusal receipt " +
    "(it answers sealing_not_offered)"), doc.description);
});

// A6. The deployment's own document commit off the published branch.
const OFF_COMMIT = "e".repeat(40);
const offEnv = () => {
  KD.serveOffBranch(gh, DOC, OFF_COMMIT);
  return { ...KEYS, [S.DEPLOY_COMMIT_ENV]: OFF_COMMIT };
};
const OFF_BODY = (id) => ({ ok: false, error_code: "deployment_document_off_branch", case_id: id });
test("R-WIDE A6: a deployment whose own document commit is off the published branch answers the withdrawal, the reference, the reveal and the refusal receipt 503 deployment_document_off_branch, codes only; nothing is written", async () => {
  const w = await committedCase("RWIDE A6 withdraw");
  let puts = gh.putLog.length;
  const wr = makeRes();
  await H.handleCaseWithdraw(req("case-withdraw", { case_id: w.id, role: "a", tape_sha256: w.a.tape_sha256, salt: w.a.salt }), wr,
    { now: NOW + 2000, env: offEnv(), keyDocument: DOC });
  assert.equal(wr._status, 503, JSON.stringify(wr._body));
  assert.deepEqual(parsed(wr), OFF_BODY(w.id));
  assert.equal(gh.putLog.length, puts);

  const v = makeRes();
  await H.handleCaseReveal(req("case-reveal", revealBody(w.id, w.a, w.b)), v, { now: REVEAL_AT, env: offEnv(), keyDocument: DOC });
  assert.equal(v._status, 503, JSON.stringify(v._body));
  assert.deepEqual(parsed(v), OFF_BODY(w.id));
  assert.equal(gh.putLog.length, puts);

  const s = await sealedCase("RWIDE A6 reference");
  puts = gh.putLog.length;
  const f = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: s.id, role: "a", tape_sha256: s.a.tape_sha256, salt: s.a.salt, cross_reference: XREF }),
    f, { now: REVEAL_AT + 1800000, env: offEnv(), keyDocument: DOC });
  assert.equal(f._status, 503, JSON.stringify(f._body));
  assert.deepEqual(parsed(f), OFF_BODY(s.id));
  assert.equal(gh.putLog.length, puts);

  const x = await withdrawnBy("RWIDE A6 receipt", "b");
  const g = makeRes();
  await H.handleCaseReveal(req("case-reveal", ownOpening(x, "a")), g, { now: REVEAL_AT, env: offEnv(), keyDocument: DOC });
  assert.equal(g._status, 503, JSON.stringify(g._body));
  assert.deepEqual(parsed(g), OFF_BODY(x.id));

  // control: a commit the repository does not show (404) is still the
  // could-not-look document_unavailable a re-send can finish
  const y = await committedCase("RWIDE A6 control");
  const n = makeRes();
  await H.handleCaseWithdraw(req("case-withdraw", { case_id: y.id, role: "a", tape_sha256: y.a.tape_sha256, salt: y.a.salt }), n,
    { now: NOW + 2000, env: { ...KEYS, [S.DEPLOY_COMMIT_ENV]: "f".repeat(40) }, keyDocument: DOC });
  assert.deepEqual([n._status, parsed(n).error_code], [503, "document_unavailable"]);
});

test("R-WIDE A6: the status page says in one line that the deployment's document commit is off the published branch; the README calls it an operator fault, not a sender's", async () => {
  const before = process.env[S.DEPLOY_COMMIT_ENV];
  KD.serveOffBranch(gh, S.PUBLISHED_KEYS, OFF_COMMIT);
  process.env[S.DEPLOY_COMMIT_ENV] = OFF_COMMIT;
  let html;
  try {
    const res = makeRes();
    await statusHandler(makeReq({ method: "GET", query: {}, headers: { "x-forwarded-for": nextIp() } }), res);
    html = String(res._body);
  } finally {
    if (before === undefined) delete process.env[S.DEPLOY_COMMIT_ENV];
    else process.env[S.DEPLOY_COMMIT_ENV] = before;
  }
  const lines = html.split("\n").filter((l) => l.includes("deployment_document_off_branch"));
  assert.equal(lines.length, 1, html.slice(0, 200));
  assert.ok(lines[0].includes(OFF_COMMIT.slice(0, 12)), lines[0]);
  assert.ok(lines[0].includes("an operator fault, not a sender&#39;s") || lines[0].includes("an operator fault, not a sender's"), lines[0]);
  assert.ok(README().includes("503 `deployment_document_off_branch`, codes only"), "README");
  assert.ok(README().includes("This is an operator fault, not a sender's"), "README");
});

// Group A's must-fail gap tests: each fails with its planted defect
async function withFailingGet(match, fn) {
  const viaMock = global.fetch;
  global.fetch = async (url, o) => ((!o || !o.method || o.method === "GET") && match(decodeURIComponent(String(url)))
    ? { status: 502, ok: false, json: async () => ({}), text: async () => "{}" }
    : viaMock(url, o));
  try {
    return await fn();
  } finally {
    global.fetch = viaMock;
  }
}
test("MUST-FAIL GAP (WA04): when the reference rows cannot be listed, the records line says they could not be read, never that no row was appended", async () => {
  const s = await sealedCase("RWIDE gap WA04");
  const p = await withFailingGet((u) => u.includes(`/contents/${C.referencesDir(s.id)}`) && !u.includes(".json"), () => casePage(s.id));
  assert.equal(p.status, 200);
  assert.equal(recordsCell(p.html), esc("the reference rows could not be read when this page was read"));
});

test("MUST-FAIL GAP (WA05): a reference row whose read failed is not seen: the records line never says no row was appended, and says the row could not be read", async () => {
  const s = await sealedCase("RWIDE gap WA05");
  assert.equal((await reference(s, { role: "a" })).status, 201);
  const p = await withFailingGet((u) => u.includes(`/contents/${C.referencePath(s.id, 1)}`), () => casePage(s.id));
  const t = recordsCell(p.html);
  assert.ok(t.startsWith(esc("no valid reference row was among the rows read when this page was read")), t);
  assert.ok(t.includes("1 reference row(s) could not be read when this page was read."), t);
});

test("MUST-FAIL GAP (WA06): an invalid reference row is not counted as appended: one valid row and one invalid row read '1 reference row was appended'", async () => {
  const s = await sealedCase("RWIDE gap WA06");
  assert.equal((await reference(s, { role: "a" })).status, 201);
  gh.seed(PINS, C.referencePath(s.id, 2), { ...gh.read(PINS, C.referencePath(s.id, 1)), seq: 2, extra: true });
  const t = recordsCell((await casePage(s.id)).html);
  assert.ok(t.startsWith(esc("1 reference row was appended: row 1 on presentation of role a's commitment preimage")), t);
  assert.ok(t.includes("1 reference row(s) are not valid and are not counted"), t);
});

test("MUST-FAIL GAP (WA08): a withdrawal record naming a document commit off the published branch is the could-not-look page at 200, worded off the branch, with no withdrawal detail", async () => {
  const c = await withdrawnBy("RWIDE gap WA08", "a");
  const side = KD.serveOffBranch(gh, DOC, "7".repeat(40));
  const w = storedCase(c.id);
  gh.seed(PINS, C.casePath(c.id), signByHand({ ...withoutSig(w), signed_under: { ...w.signed_under, document_commit: side } }, caseSigner()));
  const p = await pageUnder(c.id, DOC);
  assert.equal(p.status, 200);
  assert.match(p.html, /<h1>Case: COULD NOT LOOK<\/h1>/);
  assert.ok(p.html.includes("The key document this case names is not on the published branch"), p.html.slice(0, 3000));
  assert.ok(p.html.includes("says neither that the withdrawal record verifies nor that it does not"));
  for (const d of WITHDRAWAL_DETAIL) assert.doesNotMatch(p.html, d, String(d));
});
