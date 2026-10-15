// test/case_rfg.test.js — unit R-FG (v2, 2026-10-15; the architect's
// rulings): a case takes at most 40 reference rows, judged from the listing
// of its rows, for every caller, the operator too; there is no reference
// counter, and no quota unit is spent on any request, a refused one
// included. Each test fails on the code at 98866db (and at c5770ce, which
// the brief was written against). The setup below is
// test/case_rwide_f.test.js's.
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

const NO_RECONCILE = Object.freeze(KD.docWith(KD.entry(CASE_KEY)));
async function withdrawnBy(scope, role) {
  const c = await committedCase(scope);
  assert.equal((await withdraw(c.id, c[role])).status, 201);
  return c;
}
async function statusHtml() {
  const res = makeRes();
  await statusHandler(makeReq({ method: "GET", query: {}, headers: { "x-forwarded-for": nextIp() } }), res);
  return String(res._body);
}
// The deployment's own commit off the published branch, for the status page.
async function withDeployCommit(commit, fn) {
  const before = process.env[S.DEPLOY_COMMIT_ENV];
  process.env[S.DEPLOY_COMMIT_ENV] = commit;
  try {
    return await fn();
  } finally {
    if (before === undefined) delete process.env[S.DEPLOY_COMMIT_ENV];
    else process.env[S.DEPLOY_COMMIT_ENV] = before;
  }
}


// =============================================================================
// UNIT R-FG
// =============================================================================

const CAP = 40;
const OP_ENV = () => KD.deployed(gh, { ...KEYS, [H.OPERATOR_KEY_ENV]: OPERATOR_KEY }, DOC);
async function roleReference(c, role, ref, { now = REVEAL_AT + 1800000 } = {}) {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: { ...XREF, reference: ref } }),
    res, { now, env: KD.deployed(gh, KEYS, DOC), keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
const plantRows = (id, seqs) => { for (const n of seqs) gh.seed(PINS, C.referencePath(id, n), { planted: n }); };
const usagePaths = () => [...gh._repoMap(USAGE).keys()];

test("R-FG 1: a case takes at most 40 reference rows, for every caller: the 40th row is written; the 41st, a role's or the operator's, is 409 row_limit, codes only, with the listed count and the limit", async () => {
  assert.equal(S.MAX_REFERENCE_ROWS, CAP);
  const c = await sealedCase("RFG 1 cap");
  plantRows(c.id, Array.from({ length: CAP - 1 }, (_, i) => i + 1));
  const at40 = await roleReference(c, "a", "the fortieth");
  assert.equal(at40.status, 201, JSON.stringify(at40.body).slice(0, 300));
  assert.equal(gh.has(PINS, C.referencePath(c.id, CAP)), true);
  const puts = gh.putLog.length;
  const byRole = await roleReference(c, "b", "the forty-first");
  assert.equal(byRole.status, 409, JSON.stringify(byRole.body));
  assert.deepEqual(byRole.body, { ok: false, error_code: "row_limit", case_id: c.id, count: CAP, limit: CAP });
  const byOperator = await operatorReference(c);
  assert.equal(byOperator.status, 409, JSON.stringify(byOperator.body));
  assert.deepEqual(byOperator.body, { ok: false, error_code: "row_limit", case_id: c.id, count: CAP, limit: CAP });
  assert.equal(gh.putLog.length, puts, "nothing written");
  assert.equal(gh.has(PINS, C.referencePath(c.id, CAP + 1)), false);
  // the README says 40
  assert.ok(README().includes("A case takes at most 40 reference rows, for every appender, the operator too; the 41st is refused 409 `row_limit`."), "README");
  assert.doesNotMatch(README(), /at most 500 reference rows|the 501st/);
});

test("R-FG 2: the cap is judged from the listing either way: the highest seq plus one past 40 refuses with one file listed, and 40 files listed refuse with the highest seq below 40; count is the listed file count", async () => {
  // one row, at seq 40: the next seq would be 41
  const high = await sealedCase("RFG 2 high seq");
  plantRows(high.id, [CAP]);
  const r1 = await roleReference(high, "a", "past the seq");
  assert.deepEqual([r1.status, r1.body], [409, { ok: false, error_code: "row_limit", case_id: high.id, count: 1, limit: CAP }]);
  // 39 rows and one file that is not a row: 40 files listed, highest seq 39
  const many = await sealedCase("RFG 2 many files");
  plantRows(many.id, Array.from({ length: CAP - 1 }, (_, i) => i + 1));
  gh.seed(PINS, `${C.referencesDir(many.id)}/not-a-row.json`, { stray: true });
  const r2 = await roleReference(many, "a", "past the count");
  assert.deepEqual([r2.status, r2.body], [409, { ok: false, error_code: "row_limit", case_id: many.id, count: CAP, limit: CAP }]);
  assert.equal(gh.has(PINS, C.referencePath(many.id, CAP)), false);
  // the page says it, and the body never does
  const page = (await casePage(many.id)).html;
  assert.ok(page.includes(esc(CP.ROW_LIMIT_SENTENCE)), "the page's sentence");
  assert.equal("error" in r2.body, false);
});

test("R-FG 3: there is no reference counter: one role appends past 20 rows; nothing under case_references/ is read or written; reference_quota is answered nowhere", async () => {
  const c = await sealedCase("RFG 3 no counter");
  for (let i = 1; i <= 21; i += 1) {
    const r = await roleReference(c, "a", `row-${i}`);
    assert.equal(r.status, 201, `row ${i}: ${JSON.stringify(r.body).slice(0, 200)}`);
  }
  assert.deepEqual(usagePaths().filter((p) => p.startsWith("case_references/")), []);
  assert.equal("REFERENCE_QUOTA_PER_ROLE" in H, false);
  assert.equal("takeReferenceQuota" in H._internal || "referenceQuotaPath" in H._internal, false);
  for (const f of jsFiles("lib").concat(jsFiles("api"))) assert.doesNotMatch(read(f), /reference_quota|case_references\//, f);
  // the open quota still counts, through takeUnit
  assert.equal(typeof H._internal.takeOpenQuota, "function");
});

test("R-FG 4: a reference refused 503 reference_seq_contended spends nothing: twenty contended sends, then the same send finishes, never 409 reference_quota", async () => {
  const c = await sealedCase("RFG 4 contended");
  const p1 = C.referencePath(c.id, 1);
  gh.forceConflict(PINS, p1, 100000);
  for (let i = 0; i < 20; i += 1) {
    const r = await roleReference(c, "a", "contended");
    assert.deepEqual([r.status, r.body.error_code], [503, "reference_seq_contended"], JSON.stringify(r.body).slice(0, 200));
  }
  gh.forceConflict(PINS, p1, 0);
  const again = await roleReference(c, "a", "contended");
  assert.equal(again.status, 201, JSON.stringify(again.body).slice(0, 300));
  assert.equal(gh.has(PINS, p1), true);
});

test("R-FG 5: no request reads or writes a case_references/ path: the page, the status page, open, commit, reveal, withdrawal, a reference with no proof and no bearer, with a bearer that is not the operator's, with the operator's key unset, by a role and by the operator", async () => {
  const touched = async (fn) => {
    const viaMock = global.fetch;
    const seen = [];
    global.fetch = async (url, o) => {
      if (decodeURIComponent(String(url)).includes("case_references/")) seen.push(`${(o && o.method) || "GET"} ${decodeURIComponent(String(url))}`);
      return viaMock(url, o);
    };
    try {
      await fn();
    } finally {
      global.fetch = viaMock;
    }
    return seen;
  };
  const s = await sealedCase("RFG 5 sealed");
  const w = await committedCase("RFG 5 withdraw");
  const ref = (body, headers, env) => async () => {
    const res = makeRes();
    await H.handleCaseReference(req("case-reference", body, headers), res, { now: REVEAL_AT + 1800000, env, keyDocument: DOC });
  };
  const noProof = { case_id: s.id, cross_reference: XREF };
  const steps = {
    page: () => casePage(s.id),
    status: () => statusHtml(),
    open: () => openCase("RFG 5 open"),
    commit_and_reveal: () => committedCase("RFG 5 committed").then((c) => reveal(c)),
    withdraw: () => withdraw(w.id, w.a),
    reference_no_proof_no_bearer: ref(noProof, {}, OP_ENV()),
    reference_not_the_operators_bearer: ref(noProof, { authorization: "Bearer not-the-operator" }, OP_ENV()),
    reference_operator_key_unset: ref(noProof, { authorization: `Bearer ${OPERATOR_KEY}` }, KD.deployed(gh, KEYS, DOC)),
    reference_by_a_role: () => roleReference(s, "a", "by a role"),
    reference_by_the_operator: () => operatorReference(s),
  };
  for (const [name, fn] of Object.entries(steps)) assert.deepEqual(await touched(fn), [], name);
});
