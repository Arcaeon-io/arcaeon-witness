// test/case_rl.test.js — unit R-L (2026-10-13): the withdrawn-tape listing
// removed, a signed record for every non-create change, and a pin chain that
// always advances. The architect's three decisions after four review rounds:
//   (1) the public listing of withdrawn tape digests is removed: a blocklist
//       keyed on a digest is a permanent, one-sided, one-byte-evadable way
//       for a stranger to stop a published tape from ever being compared,
//       and the service cannot recall bytes a counterparty already holds;
//   (2) every change to the pins repository that is not a create carries a
//       signed record of its own;
//   (3) a commit message is not a record.
// L1-L7 are in each test's name. The tests of L3 (the repair notes and the
// removals) and their must-fail gaps were deleted in unit R-L4, which took
// that machinery out: nothing in the pins repository is ever deleted. The
// setup below is test/case_rn.test.js's, with a key per role that a test
// may change.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0131:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rl");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rl");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rl");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0131" });

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
  return `10.91.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
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
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0131", url: "https://second-operator.example/cases/0131" });
async function reference(c, { role = "a", env = KEYS, now = REVEAL_AT + 1800000 } = {}) {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: XREF }),
    res, { now, env, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
async function casePage(id, now = REVEAL_AT + 3600000) {
  const res = makeRes();
  CP._internal.clearPageCache(); // unit R-J (J7): each view here reads afresh
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
    else if (/\.(js|mjs|cjs|json|html)$/.test(e.name)) out.push(rel);
  }
  return out;
}

const CLAIM = "Withdrawal before the reveal closes that case; it does not recall a tape a counterparty already holds, and no verdict ever " +
  "binds a key that did not sign in the case that produced it.";
const LEGACY = "Files under withdrawn_commitments/ that a pins repository may hold from before this release are ignored: no code reads " +
  "or writes them.";
const REVOCATION = "A key once shown revoked by a valid marker stays revoked. If the marker file is later removed, the answer is that the " +
  "marker cannot be read, never that the key is trusted again.";
const DATES = "Dates in a key document are shown for information and are not enforced; a key is judged by its status in the named document.";

// =============================================================================
// L1: the withdrawn-tape listing is removed
// =============================================================================

test("R-L L1: a withdrawal proves the role, takes the lock, writes the signed record and the marker, and answers; nothing is written under withdrawn_commitments/, and the answer carries no listing field", async () => {
  const c = await committedCase("RL L1 withdraw");
  const before = pinsPaths();
  const w = await withdraw(c.id, c.b);
  assert.equal(w.status, 201, JSON.stringify(w.body));
  assert.deepEqual(pinsPaths().filter((p) => !before.includes(p)), [C.withdrawnMarkerPath(c.id)], "the marker is the one new file");
  assert.equal(storedCase(c.id).status, "WITHDRAWN");
  assert.equal(S.publishedSignatureReason(storedCase(c.id), DOC), null, "the withdrawal record is signed");
  for (const k of ["withdrawn_commitment", "withdrawn_commitment_note"]) assert.equal(has(w.body, k), false, k);
  assert.doesNotMatch(JSON.stringify(w.body), /listed|listing|consent_withdrawn|withdrawn_commitments|tape digest/);
  assert.equal(lockOf(c.id).state, "released");
});

test("R-L L1: a withdrawal request that wrote nothing ends with exactly 'This request wrote nothing.'", async () => {
  const c = await committedCase("RL L1 tail");
  const bad = await withdraw(c.id, c.a, { salt: C.newSalt() });
  assert.equal(bad.status, 403, JSON.stringify(bad.body));
  assert.ok(bad.body.error.endsWith(" This request wrote nothing."), bad.body.error);
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const again = await withdraw(c.id, c.a);
  assert.deepEqual([again.status, again.body.error_code], [409, "case_withdrawn"], JSON.stringify(again.body));
  assert.ok(again.body.error.endsWith(". This request wrote nothing."), again.body.error);
  for (const e of [bad.body.error, again.body.error]) assert.doesNotMatch(e, /listed|listing/);
  // a retry by the withdrawer: 200, the marker, and nothing else
  const before = pinsPaths().length;
  const retry = await withdraw(c.id, c.b);
  assert.deepEqual([retry.status, retry.body.existing], [200, true], JSON.stringify(retry.body));
  assert.equal(pinsPaths().length, before);
  assert.equal(has(retry.body, "withdrawn_commitment"), false);
});

test("R-L L1: ?op=reconcile and a joint reveal compare a tape whose committer withdrew another case; a withdrawn_commitments/ file left in the repository is never read", async () => {
  const c = await committedCase("RL L1 withdrawn tape");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  gh.seed(PINS, `withdrawn_commitments/${sha(Buffer.from(c.b.tape_sha256, "hex"))}.json`, { listed_at: "2026-10-10T08:00:02Z" });
  const g0 = gh.getLog.length;
  const r = await reconcileCall(AGENT_TAPE, TOOL_TAPE);
  assert.equal(r.status, 200, JSON.stringify(r.body).slice(0, 300));
  assert.ok(r.body.receipt, "a receipt, signed");
  await sealedCase("RL L1 the same tapes, another case");
  assert.equal(gh.getLog.slice(g0).some((p) => p.startsWith("withdrawn_commitments")), false, "never read");
});

test("R-L L1: the listing is gone from the code, the README, the page and the red-team suite: writer, reader, gates, words and fields", () => {
  for (const name of ["writeWithdrawnCommitment", "tapeWithdrawn", "withdrawnCommitmentPath"]) assert.equal(S[name], undefined, name);
  assert.equal(RECONCILE.LISTED_WORDS, undefined);
  const gone = /withdrawn_commitment|writeWithdrawnCommitment|tapeWithdrawn|listingRefusal|LISTED_WORDS|RETRY_UNCONFIRMED|lostAfterListing|SEALED_FIRST|NOT_WRITTEN|consent_withdrawn|consent_unreadable|tape_listed|stays listed|tape so listed/;
  for (const f of [...jsFiles("lib"), ...jsFiles("tools")]) assert.doesNotMatch(read(f), gone, f);
  const readme = README();
  assert.doesNotMatch(readme, /consent_withdrawn|consent_unreadable|A withdrawn tape's listing|A listing only ever refuses/);
  assert.ok(readme.includes(LEGACY), "one sentence: files left there are ignored");
  assert.doesNotMatch(read("lib/_case_page.js"), /since been listed as withdrawn/);
  assert.doesNotMatch(read("test/case_redteam.test.js"), /can still be listed by a stranger/);
});

// =============================================================================
// L2: the public claim, and nothing more
// =============================================================================

test("R-L L2: the README's withdrawal section and the WITHDRAWN case page carry the public claim verbatim", async () => {
  const readme = README();
  const at = readme.indexOf("### Withdrawal");
  assert.ok(at >= 0, "a withdrawal section");
  assert.ok(readme.slice(at, readme.indexOf("###", at + 4)).includes(CLAIM), "in the withdrawal section");
  const c = await committedCase("RL L2 page");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const page = await casePage(c.id);
  assert.match(page.html, /Case: WITHDRAWN/);
  assert.ok(page.html.includes(esc(CLAIM)), page.html.slice(page.html.indexOf("notice"), page.html.indexOf("notice") + 800));
});

test("R-L L2: no page, response or document says this service stops a tape being compared, or recalls one", () => {
  const files = [...jsFiles("lib"), ...jsFiles("tools"), ...jsFiles("public"), "README.md"];
  const more = /will not compare|not compare a tape|refuses that tape|never compared (here|again)|listed as withdrawn|consent to compare these tapes|withdrawn tape is never/i;
  for (const f of files) assert.doesNotMatch(read(f), more, f);
});

test("R-L L2 (since unit R-L2, the verdict and the receipt inspected): every key id a sealed case, its receipt and its reveal's answer name, past the service's own keys, is one of the two that registered in that case, and no key id of another case in the same store appears", async () => {
  const other = { a: checkpoint.generateKey("party-a2.example/rl"), b: checkpoint.generateKey("party-b2.example/rl") };
  const one = await sealedCase("RL L2 keys one");
  const two = await sealedCase("RL L2 keys two", other);
  const idsOne = [REG.keyIdOf(REG.KEYS.a), REG.keyIdOf(REG.KEYS.b)];
  const idsTwo = [REG.keyIdOf(other.a), REG.keyIdOf(other.b)];
  // the service's own keys, by key id and by the name and key number their verifier strings carry
  const service = [CASE_KEY, RECEIPT_KEY, LOG_KEY].flatMap((key) => [KD.keyIdOf(key), key.verifier.split("+").slice(0, 2).join("+")]);
  const KEY_ID = /[A-Za-z0-9._\-/:]+\+[0-9a-f]{8}/g;
  for (const [c, own, theirs] of [[one, idsOne, idsTwo], [two, idsTwo, idsOne]]) {
    const k = storedCase(c.id);
    assert.equal(k.verdict.signer.verifier, RECEIPT_KEY.verifier, "the receipt, signed by the reconcile key");
    assert.deepEqual([k.commitments.a.key_id, k.commitments.b.key_id], own);
    const named = new Set([...JSON.stringify([k, k.verdict, c.r.body]).matchAll(KEY_ID)].map((m) => m[0]));
    assert.deepEqual([...named].filter((id) => !service.includes(id)).sort(), [...own].sort(), `case ${c.id.slice(0, 8)}: the parties' key ids`);
    const page = (await casePage(c.id)).html;
    for (const id of theirs) assert.ok(!named.has(id) && !page.includes(id), `case ${c.id.slice(0, 8)} names no key of the other case`);
  }
});

// =============================================================================
// L4: the withdrawal race
// =============================================================================

test("R-L L4: a withdrawal that loses (the case sealed first, or expired) writes nothing and removes nothing", async () => {
  const c = await committedCase("RL L4 lost to the seal");
  const before = gh._commitsOf(PINS).length;
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(c.id)}`),
    () => reveal(c),
    () => withdraw(c.id, c.b),
  );
  assert.equal(r.inner.status, 201, "fixture: the reveal sealed first");
  assert.deepEqual([r.out.status, r.out.body.error_code], [409, "case_sealed"], JSON.stringify(r.out.body));
  // the lock, in the private usage repository, was written and released
  assert.ok(r.out.body.error.endsWith("This request wrote nothing to the pins repository."), r.out.body.error);
  const made = gh._commitsOf(PINS).slice(before).map((cm) => cm.path);
  assert.ok(made.every((p) => p === C.casePath(c.id) || p.startsWith(`pins/case/${c.id}/`)), `only the reveal's writes: ${made.join(", ")}`);
  assert.equal(storedCase(c.id).status, "VERDICT");
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c.id)), false);
  assert.equal(gh.deleteLog.length, 0);
  const d = await committedCase("RL L4 expired");
  const n = gh._commitsOf(PINS).length;
  const late = await withdraw(d.id, d.b, { now: Date.parse(DEADLINE) + 1000 });
  assert.deepEqual([late.status, late.body.error_code], [409, "expired"]);
  assert.equal(gh._commitsOf(PINS).length, n, "nothing written");
  assert.equal(gh.deleteLog.length, 0);
});

// =============================================================================
// L5: the pin chain always advances
// =============================================================================

// Reads that touch case `id`'s files or pins, across the mock's logs.
const caseReads = (id) => [...gh.getLog, ...gh.commitsLog, ...gh.rawLog].filter((k) => String(k).includes(id)).length;
const pinReadsOf = (id, from) => [...gh.getLog.slice(from.get), ...gh.rawLog.slice(from.raw)].filter((k) => String(k).includes(`pins/case/${id}/`));
const logMarks = () => ({ get: gh.getLog.length, raw: gh.rawLog.length });

// A case at pin `top`: row 1 listed by pin 2 (the sealer's), and pins
// 3..top over it carrying its index.
async function atPin(scope, top) {
  const c = await sealedCase(scope);
  assert.equal((await reference(c, { role: "a" })).status, 201);
  await sealerRun();
  const { latest } = S.pinPaths(c.id);
  const p2 = gh.read(PINS, S._internal.pinPath(c.id, 2));
  assert.deepEqual(p2.listed_by, [{ seq: 1, pin_seq: 2 }], "the sealer's pin carries its index");
  const { reference_commits: _r, ...carry } = p2; // eslint-disable-line no-unused-vars
  for (let n = 3; n <= top; n += 1) gh.seed(PINS, S._internal.pinPath(c.id, n), { ...carry, seq: n });
  if (top > 2) gh.seed(PINS, latest, { ...carry, seq: top });
  return c;
}
// Row 2, appended: never refused for the pin count.
async function rowTwo(c) {
  const r = await reference(c, { role: "b" });
  assert.equal(r.status, 201, `a row is never refused for the pin count: ${JSON.stringify(r.body).slice(0, 200)}`);
}

test("R-L L5: a case at pin 40 with a new row gets pin 41 listing it, and what writing it reads does not grow with the pin count", async () => {
  const small = await atPin("RL L5 at pin 3", 3);
  const big = await atPin("RL L5 at pin 40", 40);
  await rowTwo(small);
  await rowTwo(big);
  const r0 = { small: caseReads(small.id), big: caseReads(big.id) };
  const m = logMarks();
  await sealerRun(120000);
  const p41 = gh.read(PINS, S._internal.pinPath(big.id, 41));
  assert.deepEqual(p41.reference_commits, [{ seq: 2, commit: gh.commitsFor(PINS, C.referencePath(big.id, 2))[0].sha }]);
  assert.deepEqual(p41.listed_by, [{ seq: 1, pin_seq: 2 }, { seq: 2, pin_seq: 41 }]);
  assert.equal(gh.read(PINS, S.pinPaths(big.id).latest).seq, 41);
  assert.equal(gh.read(PINS, S.pinPaths(small.id).latest).seq, 4);
  const cost = { small: caseReads(small.id) - r0.small, big: caseReads(big.id) - r0.big };
  assert.equal(cost.big, cost.small, `the same reads at pin 40 as at pin 3: ${JSON.stringify(cost)}`);
  assert.ok(cost.big <= L5_BOUND, `at most ${L5_BOUND} reads of the case: ${cost.big}`);
  const pinsRead = pinReadsOf(big.id, m);
  for (let n = 2; n <= 40; n += 1) assert.ok(!pinsRead.some((k) => k.endsWith(`/${String(n).padStart(8, "0")}.json`)), `pin ${n} is not read`);
  // the page: each row's listing pin read directly, no walk
  const m2 = logMarks();
  const page = (await casePage(big.id)).html;
  assert.match(page, /reference row 1[\s\S]*listed by pin 2, read when this page was read/);
  assert.match(page, /reference row 2[\s\S]*listed by pin 41, read when this page was read/);
  const below = pinReadsOf(big.id, m2).map((k) => k.slice(k.lastIndexOf("/") + 1)).filter((n) => /^\d{8}\.json$/.test(n) && n !== "00000001.json");
  assert.deepEqual([...new Set(below)], ["00000002.json"], "only pin 2 is read below the pointer");
});
const L5_BOUND = 20;

test("R-L L5: a chain written before the index, longer than the walk reads, still gets its next pin: the rows the walk did not reach are listed again, with the index", async () => {
  const c = await sealedCase("RL L5 legacy");
  assert.equal((await reference(c, { role: "a" })).status, 201);
  const commit = gh.commitsFor(PINS, C.referencePath(c.id, 1))[0].sha;
  const base = gh.read(PINS, S.pinPaths(c.id).seq);
  let rec = base;
  for (let n = 2; n <= 25; n += 1) {
    rec = { ...base, seq: n, ...(n === 2 ? { reference_commits: [{ seq: 1, commit }] } : {}) };
    gh.seed(PINS, S._internal.pinPath(c.id, n), rec);
  }
  gh.seed(PINS, S.pinPaths(c.id).latest, rec);
  await sealerRun();
  const p26 = gh.read(PINS, S._internal.pinPath(c.id, 26));
  assert.deepEqual([p26.reference_commits, p26.listed_by], [[{ seq: 1, commit }], [{ seq: 1, pin_seq: 26 }]]);
  assert.equal(gh.read(PINS, S.pinPaths(c.id).latest).seq, 26);
});

test("R-L L5: an index that names a pin that does not list the row says so on the page", async () => {
  const c = await atPin("RL L5 index wrong", 2);
  await rowTwo(c);
  await sealerRun(120000);
  const { latest } = S.pinPaths(c.id);
  const top = gh.read(PINS, latest);
  gh.seed(PINS, S._internal.pinPath(c.id, 2), { ...gh.read(PINS, S._internal.pinPath(c.id, 2)), reference_commits: [{ seq: 5, commit: "e".repeat(40) }], listed_by: [{ seq: 5, pin_seq: 2 }] });
  assert.ok(top.listed_by.some((e) => e.seq === 1 && e.pin_seq === 2), "fixture: the pointer's index names pin 2 for row 1");
  const page = (await casePage(c.id)).html;
  assert.match(page, /reference row 1[\s\S]*not read: the pin the pointer&#39;s index names for this row does not list it \(index_not_in_pin\)/);
});

test("R-L L5: the seal judge holds an index to its own pin: sorted, each row once, no later pin, and this pin's own rows in it", () => {
  const verdict = require("../lib/_verdict.js");
  const id = "a".repeat(64);
  const pin = S._internal.pinRecord(id, "b".repeat(64), REVEAL_AT, "c".repeat(40));
  const judge = (rec) => verdict.judgeCaseSeal({ json: rec }, { namespace: S.pinNamespace(id) });
  const at3 = { ...pin, seq: 3, reference_commits: [{ seq: 2, commit: "d".repeat(40) }] };
  assert.equal(judge({ ...at3, listed_by: [{ seq: 1, pin_seq: 2 }, { seq: 2, pin_seq: 3 }] }).ok, true);
  for (const bad of [
    [{ seq: 2, pin_seq: 3 }, { seq: 1, pin_seq: 2 }],
    [{ seq: 1, pin_seq: 2 }, { seq: 1, pin_seq: 2 }, { seq: 2, pin_seq: 3 }],
    [{ seq: 1, pin_seq: 4 }, { seq: 2, pin_seq: 3 }],
    [{ seq: 1, pin_seq: 2 }],
    [],
    [{ seq: 1, pin_seq: 2, extra: 1 }, { seq: 2, pin_seq: 3 }],
  ]) assert.equal(judge({ ...at3, listed_by: bad }).reason, "case_seal_listed_by_unreadable", JSON.stringify(bad));
  assert.equal(judge({ ...pin, listed_by: [{ seq: 1, pin_seq: 1 }] }).reason, "case_seal_listed_by_unreadable", "the seal's own pin lists no row");
});

// =============================================================================
// L6: two sentences
// =============================================================================

test("R-L L6 (a): the README and the key document's notes say a revoked key stays revoked, and a removed marker reads as a marker that cannot be read", () => {
  assert.ok(README().includes(REVOCATION));
  const doc = read("public/.well-known/arcaeon/case-signing-keys.json");
  assert.ok(JSON.stringify(JSON.parse(doc)).includes(REVOCATION));
  assert.equal(S.checkKeyDocument(JSON.parse(doc)).ok, true);
});

test("R-L L6 (a): a marker removed after it was read: the answer is that the marker cannot be read, never that the key is trusted again", async () => {
  const c = await sealedCase("RL L6 marker removed");
  const CASE_REVOKED = KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11" }), KD.reconcileEntry(RECEIPT_KEY));
  KD.serve(gh, CASE_REVOKED);
  const out = await require("../tools/record_key_revocation.js").recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: CASE_REVOKED, write: true });
  assert.equal(out.ok, true, JSON.stringify(out));
  const k = storedCase(c.id);
  const held = await S.sealedRecordReason(k, CASE_REVOKED);
  assert.equal(held.code, "signer_since_revoked", JSON.stringify(held));
  gh._repoMap(PINS).delete(out.path);
  gh.addCommit(PINS, out.path, "mock: the marker removed");
  // no cache stands in for the file: the same instance, read again
  const after = await S.sealedRecordReason(k, CASE_REVOKED);
  assert.deepEqual([after.code, after.reason], ["signer_revoked", "revocation_marker_unreadable"]);
  S._internal.clearDocumentCache();
  const fresh = await S.sealedRecordReason(k, CASE_REVOKED);
  assert.deepEqual([fresh.code, fresh.reason], ["signer_revoked", "revocation_marker_unreadable"]);
});

test("R-L L6 (b): the case page says, beside the key document it names, that dates in a key document are not enforced", async () => {
  const c = await sealedCase("RL L6 dates");
  const html = (await casePage(c.id)).html;
  const at = html.indexOf("<tr><th>key document</th>");
  assert.ok(at >= 0);
  assert.ok(html.slice(at, html.indexOf("</tr>", at)).includes(esc(DATES)));
});

// =============================================================================
// L7: the change log
// =============================================================================

test("R-L L7: the change log says the withdrawn-tape listing was removed before release, and why", () => {
  const log = read("CHANGELOG.md");
  const rl = log.slice(log.indexOf("## 2026-10-13: Unit R-L"), log.indexOf("## 2026-10-13: Unit R-J3"));
  assert.ok(rl.length > 0, "an R-L entry above R-J3");
  assert.match(rl, /withdrawn-tape listing introduced in unit R-N was removed before release/);
});

// =============================================================================
// MUST-FAIL GAP (unit R-L): the mutants the pass over the lines R-L changed
// left alive, each caught here
// =============================================================================

// A case at pin 3 whose index lists row 1 by pin 2 and row 2 by pin 3.
async function indexed(scope) {
  const c = await atPin(scope, 2);
  await rowTwo(c);
  await sealerRun(120000);
  const top = gh.read(PINS, S.pinPaths(c.id).latest);
  assert.deepEqual([top.seq, top.listed_by], [3, [{ seq: 1, pin_seq: 2 }, { seq: 2, pin_seq: 3 }]]);
  return { c, top, chain: S.caseChain(storedCase(c.id)) };
}

test("MUST-FAIL GAP (S08, S22b): the index reads only the pins that list the rows wanted; a next pin's auth_note says what listed_by is", async () => {
  const { c, top, chain } = await indexed("RL gap want");
  gh.forceGetFailure(PINS, S._internal.pinPath(c.id, 2), 1, 503);
  const r = await S._internal.listedReferences(c.id, chain, top, new Set([2]));
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual([...r.listed], [[2, { commit: top.reference_commits[0].commit, pin_seq: 3 }]]);
  assert.ok(top.auth_note.endsWith("; listed_by, when present, names for every row this pin or a pin below it lists the pin that lists it."),
    top.auth_note);
});

test("MUST-FAIL GAP (S10, S11, S12): a pin the index names for a wanted row is pin_unreadable when its read fails, pin_below_not_a_pin when it is not this case's pin, and pin_below_absent when it is gone", async () => {
  const { c, top, chain } = await indexed("RL gap index reads");
  const p2 = S._internal.pinPath(c.id, 2);
  const reasonFor = async () => (await S._internal.listedReferences(c.id, chain, top, new Set([1]))).reason;
  assert.equal(await reasonFor(), undefined, "control: row 1 is read from pin 2");
  gh.forceGetFailure(PINS, p2, 1, 503);
  assert.equal(await reasonFor(), "pin_unreadable");
  gh.seed(PINS, p2, { not: "a pin" });
  assert.equal(await reasonFor(), "pin_below_not_a_pin");
  gh._repoMap(PINS).delete(p2);
  assert.equal(await reasonFor(), "pin_below_absent");
});

test("MUST-FAIL GAP (S17, S22): a chain from before the index whose walk stops on a pin it read gets no next pin, and the sealer is told why", async () => {
  const c = await sealedCase("RL gap legacy stops");
  assert.equal((await reference(c, { role: "a" })).status, 201);
  const commit = gh.commitsFor(PINS, C.referencePath(c.id, 1))[0].sha;
  const base = gh.read(PINS, S.pinPaths(c.id).seq);
  gh.seed(PINS, S._internal.pinPath(c.id, 2), { ...base, seq: 2, reference_commits: [{ seq: 1, commit }] });
  const p3 = { ...base, seq: 3 };
  gh.seed(PINS, S._internal.pinPath(c.id, 3), p3);
  gh.seed(PINS, S.pinPaths(c.id).latest, p3);
  gh._repoMap(PINS).delete(S._internal.pinPath(c.id, 2));
  const caseCommit = gh.commitsFor(PINS, C.casePath(c.id))[0].sha;
  const r = await S._internal.nextPin(c.id, S.caseChain(storedCase(c.id)), REVEAL_AT + 7200000, caseCommit);
  assert.deepEqual(r, { ok: false, reason: "pin_below_absent" });
  assert.equal(gh.has(PINS, S._internal.pinPath(c.id, 4)), false, "no next pin");
});

test("MUST-FAIL GAP (S02): a revocation marker held from an earlier read whose file cannot be read this time is a marker that cannot be read", async () => {
  const c = await sealedCase("RL gap marker read fails");
  const CASE_REVOKED = KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11" }), KD.reconcileEntry(RECEIPT_KEY));
  KD.serve(gh, CASE_REVOKED);
  const out = await require("../tools/record_key_revocation.js").recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: CASE_REVOKED, write: true });
  assert.equal(out.ok, true, JSON.stringify(out));
  const k = storedCase(c.id);
  assert.equal((await S.sealedRecordReason(k, CASE_REVOKED)).code, "signer_since_revoked", "fixture: the marker read, and held");
  gh.forceGetFailure(PINS, out.path, 1, 503);
  const after = await S.sealedRecordReason(k, CASE_REVOKED);
  assert.deepEqual([after.code, after.reason], ["signer_revoked", "revocation_marker_unreadable"]);
});


test("MUST-FAIL GAP (H21, H22): the withdrawal's answer carries the public claim, and says that only the salt's sha256 is kept, in the withdrawal record", async () => {
  const c = await committedCase("RL gap answer notes");
  const w = await withdraw(c.id, c.b);
  assert.equal(w.status, 201);
  assert.equal(w.body.withdrawal_note, CLAIM);
  assert.equal(w.body.preimage_note, "Presenting the preimage spends this commitment: a withdrawn case can never be revealed. Nothing of the preimage " +
    "is kept except the sha256 of the salt, in the withdrawal record.");
});


test("MUST-FAIL GAP (V02): a next pin's index is never empty", () => {
  const verdict = require("../lib/_verdict.js");
  const id = "a".repeat(64);
  const pin = S._internal.pinRecord(id, "b".repeat(64), REVEAL_AT, "c".repeat(40));
  const judge = (rec) => verdict.judgeCaseSeal({ json: rec }, { namespace: S.pinNamespace(id) });
  assert.equal(judge({ ...pin, seq: 3 }).ok, true, "control: no index");
  assert.equal(judge({ ...pin, seq: 3, listed_by: [] }).reason, "case_seal_listed_by_unreadable");
});

test("MUST-FAIL GAP (V07, V08): an index entry's seq is within the seal's bound, and its pin is a next pin, never the seal's own", () => {
  const verdict = require("../lib/_verdict.js");
  const id = "a".repeat(64);
  const pin = S._internal.pinRecord(id, "b".repeat(64), REVEAL_AT, "c".repeat(40));
  const judge = (rec) => verdict.judgeCaseSeal({ json: rec }, { namespace: S.pinNamespace(id) });
  const at3 = { ...pin, seq: 3, reference_commits: [{ seq: 2, commit: "d".repeat(40) }] };
  assert.equal(judge({ ...at3, listed_by: [{ seq: 1, pin_seq: 1 }, { seq: 2, pin_seq: 3 }] }).reason, "case_seal_listed_by_unreadable", "pin 1");
  assert.equal(judge({ ...at3, listed_by: [{ seq: 2, pin_seq: 3 }, { seq: 100000000, pin_seq: 2 }] }).reason, "case_seal_listed_by_unreadable", "seq bound");
});
