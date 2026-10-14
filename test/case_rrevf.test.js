// test/case_rrevf.test.js — unit R-REVf (2026-10-14): the architect's
// rulings on R-REV's two majors. One sentence for either revoked key, naming
// no role (option c): "One of the keys this case is signed with (KEY_ID) is
// listed as revoked in the key document this service carries (commit V), so
// this page does not show its verdict, whenever it was signed." KEY_ID is
// the revoked key, the case key when both are. The verdict is withheld when
// only the reconcile key is revoked. KEY_DATES_NOTE reads as ruled. One
// reason code, key_revoked, with key_id. The setup below is
// test/case_rrev.test.js's.
"use strict";


process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0181:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-14rrevf");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-14rrevf");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-14rrevf");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0181" });

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
  return `10.94.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
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
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0181", url: "https://second-operator.example/cases/0152" });
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
// A daily anchor record naming `head`, as the operator's job writes one.
const DAY = (id) => gh.commitsFor(PINS, pinFile(id)).slice(-1)[0].date.slice(0, 10);
function dailyAnchor(day, head = gh.headOf(PINS)) {
  return gh.seedText(PINS, `anchors/${day}-head.txt`, `${head} ${day}T03:15:00+00:00\n`);
}
// A sealed case whose reveal's own pin write failed: sealed, and not pinned.
async function sealedUnpinned(scope) {
  const c = await committedCase(scope);
  gh.forceFailure(PINS, pinFile(c.id), 1, 500);
  const r = await reveal(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.deepEqual(pinTree(c.id), [], "fixture: not pinned at the reveal");
  return c;
}
const OTS = "Daily anchor records and their OpenTimestamps proofs are in `anchors/` in the pins repository; this page does not check them, " +
  "and you can check one yourself by running `ots verify` on the proof file beside the record.";
const pagePlain = (html) => html.replace(/<code>([^<]*)<\/code>/g, "`$1`").replace(/<[^>]+>/g, " ").replace(/&#39;/g, "'").replace(/&quot;/g, '"')
  .replace(/&amp;/g, "&").replace(/\s+/g, " ");



// =============================================================================
// UNIT R-REVf
// =============================================================================

const docRevoking = ({ caseKey = "active", reconcileKey = "active" } = {}) =>
  KD.docWith(KD.entry(CASE_KEY, { status: caseKey }), KD.reconcileEntry(RECEIPT_KEY, { status: reconcileKey }));
async function pageUnder(id, keyDocument, env) {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": nextIp() } }), res,
    { now: REVEAL_AT + 3600000, keyDocument, env: env === undefined ? KD.deployed(gh, {}, keyDocument) : env });
  return { status: res._status, html: String(res._body), V: env === undefined ? null : undefined };
}
const textOf = (html) => html.replace(/<style[\s\S]*?<\/style>/g, "").replace(/<[^>]+>/g, "").replace(/&#39;/g, "'").replace(/&quot;/g, '"')
  .replace(/&amp;/g, "&").replace(/\s+/g, " ");
const SENTENCE = (keyId, commitText) => `One of the keys this case is signed with (${keyId}) is listed as revoked in the key document this service carries ` +
  `(commit ${commitText}), so this page does not show its verdict, whenever it was signed.`;
const VERDICT_WORDS = /MATCHED|ALTERED|MISSING|class="word pass"|class="word fail"|first divergence/;
const count = (s, sub) => s.split(sub).length - 1;
const CASE_ID = KD.keyIdOf(CASE_KEY);
const RECEIPT_ID = KD.keyIdOf(RECEIPT_KEY);

for (const [name, statuses, keyId] of [
  ["(a) only the case key revoked", { caseKey: "revoked" }, CASE_ID],
  ["(b) only the reconcile key revoked", { reconcileKey: "revoked" }, RECEIPT_ID],
  ["(c) both revoked: the case key's id, printed once", { caseKey: "revoked", reconcileKey: "revoked" }, CASE_ID],
]) {
  test(`R-REVf 1 ${name}: the page prints the ruled sentence exactly and withholds the verdict`, async () => {
    const c = await sealedCase(`RREVf page ${name}`);
    const doc = docRevoking(statuses);
    const env = KD.deployed(gh, {}, doc);
    const V = env[S.DEPLOY_COMMIT_ENV];
    const p = await pageUnder(c.id, doc, env);
    assert.equal(p.status, 200);
    assert.match(p.html, /<h1>Case: SIGNED BY A REVOKED KEY<\/h1>/);
    const text = textOf(p.html);
    assert.ok(text.includes(SENTENCE(keyId, V.slice(0, 12))), text.slice(0, 900));
    assert.ok(p.html.includes(`href="https://github.com/${S.KEY_DOCUMENT_REPO}/blob/${V}/${S.CASE_KEYS_FILE}"`), "the full commit in the link");
    assert.doesNotMatch(p.html, VERDICT_WORDS, "the verdict is withheld");
    assert.equal(count(p.html, keyId), 1, "the key id, printed once");
    if (keyId === CASE_ID) assert.equal(count(p.html, RECEIPT_ID), 0);
    assert.doesNotMatch(text, /case key|reconcile key/, "no role word");
    // a deployment that does not know its commit says so in V's place
    const unknown = await pageUnder(c.id, doc, {});
    assert.ok(textOf(unknown.html).includes(SENTENCE(keyId, "not known to this deployment")));
  });
}

test("R-REVf 2: KEY_DATES_NOTE reads exactly as ruled, beside the key document a valid seal names", async () => {
  const c = await sealedCase("RREVf key dates");
  const p = await pageUnder(c.id, DOC);
  assert.ok(p.html.includes("A key is judged by its status in the named document and in the key document this service carries; it counts as active " +
    "only when both list it active."));
  assert.ok(!p.html.includes("Dates in a key document are shown for information"));
});

test("R-REVf 3: the sealed check answers key_revoked with the revoked key's id, for either key, and no role", async () => {
  const c = await sealedCase("RREVf answers");
  for (const [statuses, keyId] of [[{ caseKey: "revoked" }, CASE_ID], [{ reconcileKey: "revoked" }, RECEIPT_ID], [{ caseKey: "revoked", reconcileKey: "revoked" }, CASE_ID]]) {
    assert.deepEqual(await S.sealedRecordReason(storedCase(c.id), docRevoking(statuses)), { code: "signer_revoked", reason: "key_revoked", key_id: keyId });
  }
  assert.deepEqual(await S.anchorCase(c.id, { now: REVEAL_AT + 60000, keyDocument: docRevoking({ reconcileKey: "revoked" }) }),
    { ok: false, code: "not_sealed", status: "VERDICT", reason: "signer_revoked" });
});

test("R-REVf 4: the reference refuses 409 signer_revoked, reason key_revoked, with key_id and the page's words, no role word, and writes no row", async () => {
  const c = await sealedCase("RREVf reference");
  for (const [statuses, keyId] of [[{ caseKey: "revoked" }, CASE_ID], [{ reconcileKey: "revoked" }, RECEIPT_ID]]) {
    const doc = docRevoking(statuses);
    const env = KD.deployed(gh, KEYS, doc);
    const V = env[S.DEPLOY_COMMIT_ENV];
    const res = makeRes();
    await H.handleCaseReference(req("case-reference", { case_id: c.id, role: "a", tape_sha256: c.a.tape_sha256, salt: c.a.salt, cross_reference: XREF }),
      res, { now: REVEAL_AT + 1800000, env, keyDocument: doc });
    const body = parsed(res);
    assert.deepEqual([res._status, body.error_code, body.reason, body.key_id], [409, "signer_revoked", "key_revoked", keyId], JSON.stringify(body));
    assert.equal(has(body, "role"), false);
    assert.equal(body.error, `One of the keys this case is signed with (${keyId}) is listed as revoked in the key document this service carries ` +
      `(commit ${V}), so this case takes no reference row, whenever it was signed; no row was written.`);
    assert.doesNotMatch(JSON.stringify(body), /case key|reconcile key|case_key_revoked|reconcile_key_revoked/);
  }
  assert.deepEqual(pinsPaths().filter((p) => p.startsWith(`cases/${c.id}/references/`)), []);
});

test("R-REVf 5: the preview tool names the key document this checkout carries, listed revoked, and the key", () => {
  const TOOL = require("../tools/preview_dry_run.js");
  const v = TOOL._internal.holdsVerdict({ code: "signer_revoked", reason: "key_revoked", key_id: CASE_ID });
  assert.equal(v.word, "BROKEN");
  assert.equal(v.text, `one of the keys it is signed with (${CASE_ID}) is listed as revoked in the key document this checkout carries, so it is ` +
    "not shown as holding, whenever it was signed");
  assert.doesNotMatch(v.text, /the key document it names/);
});

test("R-REVf 6: no comment or note in lib/, tools/ or the test helpers describes the removed marker machinery, and the code names one revoked reason", () => {
  for (const f of [...jsFiles("lib"), ...jsFiles("tools"), "test/helpers/mock_store.js"]) {
    assert.doesNotMatch(read(f), /marker's check|marker tool|revocation marker|case_key_revoked|reconcile_key_revoked/, f);
  }
});
