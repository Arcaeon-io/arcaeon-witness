// test/case_rl2.test.js — unit R-L2 (2026-10-13): fixes from the second
// reader's pass over R-L at c7ccdb2. Its tests of the repair notes and the
// removals (B1, B2, M1, the one removal, and their must-fail gaps) were
// deleted in unit R-L4, which took that machinery out: nothing is ever
// deleted. What stays:
//   M2  the withdrawal's 503 after a lost write says which of two things
//       happened;
//   M3  a case holds at most 500 reference rows;
//   M4  (in test/case_rj3.test.js) anchor misses continue, and a row is
//       refused only on a proven anchor conflict;
//   and the minors (L4's lost withdrawals here; L2, the guard and the legacy
//   auth_note in test/case_rl.test.js).
// The setup below is test/case_rl.test.js's.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0141:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rl2");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rl2");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rl2");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0141" });

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
  return `10.92.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
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
async function withdraw(id, p, { now = NOW + 2000, env = KEYS, salt = p.salt } = {}) {
  const res = makeRes();
  await H.handleCaseWithdraw(req("case-withdraw", { case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt }), res, { now, env, keyDocument: DOC });
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
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0141", url: "https://second-operator.example/cases/0141" });
async function reference(c, { role = "a", env = KEYS, now = REVEAL_AT + 1800000 } = {}) {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: XREF }),
    res, { now, env, keyDocument: DOC });
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
const read = (rel) => fs.readFileSync(path.join(__dirname, "..", rel), "utf8");
const README = () => read("README.md").replace(/\s+/g, " ");
// =============================================================================
// M2: the withdrawal's 503 after a lost write
// =============================================================================

test("R-L2 M2: a withdrawal whose root write kept losing while the case read fine says the case kept changing; one whose read after the write failed says what the case is now could not be read", async () => {
  const c = await committedCase("RL2 M2 kept changing");
  gh.forceConflict(PINS, C.casePath(c.id), 4);
  const w = await withdraw(c.id, c.b);
  assert.deepEqual([w.status, w.body.error_code, w.body.reason, w.body.error, w.body.case_id],
    // (since unit R-L3, d: the lock record was written, so the sentence names what was not)
    [503, "store_error", "case_kept_changing", "the case kept changing while this request tried to write; nothing was written to the case record. Send it again.", c.id],
    JSON.stringify(w.body));
  assert.equal(storedCase(c.id).status, "COMMITTED");
  const d = await committedCase("RL2 M2 read fails");
  gh.forceConflict(PINS, C.casePath(d.id), 4);
  const viaMock = global.fetch;
  let puts = 0;
  global.fetch = async (url, o) => {
    const method = (o && o.method) || "GET";
    if (String(url).includes(`/repos/${PINS}/contents/${C.casePath(d.id)}`)) {
      if (method === "PUT") puts += 1;
      else if (puts >= 4) return { ok: false, status: 503, json: async () => ({}), text: async () => "" };
    }
    return viaMock(url, o);
  };
  let r;
  try {
    r = await withdraw(d.id, d.b);
  } finally {
    global.fetch = viaMock;
  }
  assert.deepEqual([r.status, r.body.reason, r.body.error], [503, "case_moved",
    "the case moved while this withdrawal was written, and what it is now could not be read. This request wrote nothing to the pins repository. " +
      "Send the same withdrawal again."], JSON.stringify(r.body));
});

// =============================================================================
// M3: at most 500 reference rows a case
// =============================================================================

test("R-L2 M3: a case holds at most 500 reference rows: the 500th is written, the 501st is refused 409 row_limit in a plain sentence, and the README states the cap", async () => {
  assert.equal(S.MAX_REFERENCE_ROWS, 500);
  const c = await sealedCase("RL2 M3 cap");
  for (let n = 1; n <= 499; n += 1) gh.seed(PINS, C.referencePath(c.id, n), { seeded: n });
  const at500 = await reference(c, { role: "a" });
  assert.equal(at500.status, 201, JSON.stringify(at500.body).slice(0, 300));
  assert.equal(gh.has(PINS, C.referencePath(c.id, 500)), true);
  const at501 = await reference(c, { role: "b" });
  assert.deepEqual([at501.status, at501.body.error_code, at501.body.error, at501.body.case_id],
    [409, "row_limit", "this case holds 500 reference rows, the most one case holds; no row was written", c.id], JSON.stringify(at501.body));
  assert.equal(gh.has(PINS, C.referencePath(c.id, 501)), false);
  assert.ok(README().includes("A case holds at most 500 reference rows; the 501st is refused 409 `row_limit`."));
});

// =============================================================================
// L4 (a minor): a withdrawal that lost to a reveal attempt, or to another withdrawal
// =============================================================================

test("R-L2 L4 (since unit R-RV no reveal attempt): a withdrawal that loses to another withdrawal writes nothing to the pins repository and removes nothing", async () => {
  for (const [scope, code, seedWith] of [
    ["RL2 L4 lost to a withdrawal", "case_withdrawn",
      (c, k) => S.withdrawnRecord(k, { role: "a", at: C.utcSeconds(NOW + 1000), salt: c.a.salt }, S.loadCaseSigner(KEYS, { keyDocument: DOC }))],
  ]) {
    const c = await committedCase(scope);
    let before;
    const r = await during(
      (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(c.id)}`),
      async () => {
        gh.seed(PINS, C.casePath(c.id), seedWith(c, storedCase(c.id)), { keepHistory: true });
        before = gh._commitsOf(PINS).length;
      },
      () => withdraw(c.id, c.b),
    );
    assert.deepEqual([r.out.status, r.out.body.error_code], [409, code], JSON.stringify(r.out.body));
    assert.ok(r.out.body.error.endsWith("This request wrote nothing to the pins repository."), r.out.body.error);
    assert.equal(gh._commitsOf(PINS).length, before, `${scope}: nothing written to the pins repository`);
    assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c.id)), false, "no marker");
    assert.equal(gh.deleteLog.length, 0);
  }
});

// =============================================================================
// THE MINORS
// =============================================================================

// (Unit R-PIN removed the minor's next-pin tests with the next pins.)

// =============================================================================
// MUST-FAIL GAP (unit R-L2): the mutants the pass over the lines R-L2 changed
// left alive, each caught here
// =============================================================================

const failedFetch = () => ({ ok: false, status: 503, json: async () => ({}), text: async () => "" });
