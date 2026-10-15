// test/case_rwide_f.test.js — unit R-WIDEf (2026-10-15): the fixes for the
// R-WIDE reader's findings (F1: the two false sentences; F3: page words and
// small truths; the runner's, F2, are in test/must_fail_runner.test.js).
// Each test fails on the code at 40e0473. The setup below is
// test/case_rwide.test.js's.
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
// GROUP F1: the two false sentences
// =============================================================================

const OFF_COMMIT = "e".repeat(40);
// The README's KEY_DOCUMENT_BRANCH paragraph, whitespace folded.
function branchParagraph() {
  const r = read("README.md");
  const a = r.indexOf("### KEY_DOCUMENT_BRANCH");
  return r.slice(a, r.indexOf("\n#", a + 5)).replace(/\s+/g, " ");
}
const AHEAD_SENTENCE = "A deployment whose own commit is ahead of the branch answers 503 `document_unavailable` until the branch reaches it.";
const OFF_LINE = (at) => `<p class="muted"><code>deployment_document_off_branch</code>: the commit this deployment was built from (<code>${at}</code>) ` +
  "is not on the published branch of the key document's repository, so this deployment signs nothing: withdrawals and references are answered " +
  "503 deployment_document_off_branch; an operator fault.</p>";

test("R-WIDEf F1-a: the README's KEY_DOCUMENT_BRANCH paragraph says diverged, never 'ahead of the branch or diverged', and that a commit ahead of the branch answers 503 document_unavailable until the branch reaches it; the comment and the A6 change-log bullet say the same", () => {
  const p = branchParagraph();
  assert.equal(p.includes("ahead of the branch or diverged"), false, p);
  assert.ok(p.includes("A deployment whose own commit has diverged from the branch signs nothing"), p);
  assert.ok(p.includes(AHEAD_SENTENCE), p);
  // the comment on deploymentOffBranch
  const http = read("lib/_case_http.js");
  const at = http.indexOf("// THE DEPLOYMENT'S OWN DOCUMENT OFF THE BRANCH");
  const comment = http.slice(at, http.indexOf("function deploymentOffBranch", at));
  assert.equal(/ahead or diverged/.test(comment), false, comment);
  assert.match(comment.replace(/\/\/ ?/g, "").replace(/\s+/g, " "), /a commit ahead of the branch answers 503 document_unavailable until the branch reaches it/i);
  // the Group A change log's A6 bullet, corrected in place
  const log = read("CHANGELOG.md");
  const a6 = log.split("\n").find((l) => l.startsWith("- **A6. The deployment's own document commit off the branch.**"));
  assert.ok(a6, "the A6 bullet");
  assert.equal(a6.includes("(ahead or diverged; a 404 is not off)"), false, a6);
  assert.ok(a6.includes("Corrected by unit R-WIDEf, F1-a"), a6);
});

test("R-WIDEf F1-b: in the off state the status line says only what is always true (this deployment signs nothing: withdrawals and references are answered 503); and a reveal and a refusal receipt under a document with no active reconcile entry still answer 409 sealing_not_offered first", async () => {
  KD.serveOffBranch(gh, S.PUBLISHED_KEYS, OFF_COMMIT);
  const html = await withDeployCommit(OFF_COMMIT, statusHtml);
  const lines = html.split("\n").map((l) => l.trim()).filter((l) => l.includes("deployment_document_off_branch"));
  assert.deepEqual(lines, [OFF_LINE(OFF_COMMIT.slice(0, 12))]);
  assert.equal(/every reveal|refusal receipt/.test(lines[0]), false, lines[0]);
  // the README's sentence, corrected the same way
  const p = branchParagraph();
  assert.equal(p.includes("answers every reveal, withdrawal, reference and refusal receipt"), false, p);
  assert.ok(p.includes("withdrawals and references are answered 503 `deployment_document_off_branch`, codes only"), p);
  // the ordering the line no longer claims past: with no active reconcile
  // entry, the reveal and the refusal receipt answer 409 sealing_not_offered
  // before the commit is confirmed
  KD.serveOffBranch(gh, NO_RECONCILE, OFF_COMMIT);
  const offEnv = { ...KEYS, [S.DEPLOY_COMMIT_ENV]: OFF_COMMIT };
  const c = await committedCase("RWIDEf F1-b reveal");
  const v = makeRes();
  await H.handleCaseReveal(req("case-reveal", revealBody(c.id, c.a, c.b)), v, { now: REVEAL_AT, env: offEnv, keyDocument: NO_RECONCILE });
  assert.deepEqual([v._status, parsed(v)], [409, { ok: false, error_code: "sealing_not_offered", case_id: c.id }]);
  const x = await withdrawnBy("RWIDEf F1-b receipt", "b");
  const g = makeRes();
  await H.handleCaseReveal(req("case-reveal", ownOpening(x, "a")), g, { now: REVEAL_AT, env: offEnv, keyDocument: NO_RECONCILE });
  assert.deepEqual([g._status, parsed(g)], [409, { ok: false, error_code: "sealing_not_offered", case_id: x.id, status: "WITHDRAWN" }]);
});

// =============================================================================
// GROUP F3: page words and small truths
// =============================================================================

// F3-a. The words a page must not print (the reader's overrule of R-WIDE's
// A1 UNSURE): "holds" and "second operator".
const FORBIDDEN = [/\bholds\b/i, /second operator/i];
const refuseWords = (html, what) => {
  for (const re of FORBIDDEN) assert.doesNotMatch(html, re, `${what}: ${(html.match(new RegExp(`.{0,80}${re.source}.{0,40}`, "i")) || [""])[0]}`);
};
const chainOf = (id) => S.caseChain(storedCase(id));
function plantPin(id, chain, caseCommit) {
  gh.seed(PINS, S.pinPaths(id).seq, S._internal.pinRecord(id, chain, REVEAL_AT, caseCommit));
}

test("R-WIDEf F3-a: no page prints 'holds' or 'second operator': the case page in every state reached here (OPEN, COMMITTED, WITHDRAWN, sealed and pinned, a pin conflict, a pin naming a commit with no case file), every pin and conflict word, the withdrawal claim, the status page and the reconcile page", async () => {
  const early = gh.seedText(PINS, "notes/rwidef-before.txt", "x\n");
  const open = await openCase("RWIDEf F3-a open");
  refuseWords((await casePage(open, NOW + 1000)).html, "OPEN");
  const committed = await committedCase("RWIDEf F3-a committed");
  const cpage = (await casePage(committed.id, NOW + 1000)).html;
  assert.ok(cpage.includes("this service records it and never checks who has it."), "the parties sentence");
  refuseWords(cpage, "COMMITTED");
  const w = await withdrawnBy("RWIDEf F3-a withdrawn", "a");
  const wpage = (await casePage(w.id)).html;
  assert.ok(wpage.includes(esc(S.WITHDRAWAL_CLAIM).slice(0, 80)), "the withdrawal claim is on the page");
  refuseWords(wpage, "WITHDRAWN");
  const s = await sealedCase("RWIDEf F3-a sealed");
  await sealerRun();
  refuseWords((await casePage(s.id)).html, "sealed and pinned");
  // a conflict: the pin file now names another chain
  const seq = S.pinPaths(s.id).seq;
  gh.seed(PINS, seq, { ...gh.read(PINS, seq), chain: sha("another chain") }, { keepHistory: true });
  S._internal.clearCommitFiles();
  const conflict = (await casePage(s.id)).html;
  assert.ok(conflict.includes(`conflict: ${esc("the pin file under this case's namespace names another chain")} (pin_holds_another_chain).`), "the conflict words");
  refuseWords(conflict, "conflict");
  // a pin naming a commit at which the pins repository has no case file
  const t = await sealedCase("RWIDEf F3-a absent");
  plantPin(t.id, chainOf(t.id), early);
  S._internal.clearCommitFiles();
  const absent = (await casePage(t.id)).html;
  assert.ok(absent.includes("the pins repository has no case file at that commit (case_absent_at_commit)"), "the absent words");
  refuseWords(absent, "absent at commit");
  // every word table a page draws from
  for (const reason of ["pin_holds_another_chain", "pin_at_its_commit_holds_another_chain", "pin_at_its_commit_not_a_pin", "pin_at_its_commit_not_json", "other"]) {
    refuseWords(S.conflictWords(reason), reason);
  }
  for (const r of ["case_at_commit_differs", "case_absent_at_commit", "row_absent_at_commit", "case_commit_not_found", "case_commit_off_branch", "other"]) {
    for (const file of ["case file", "row"]) refuseWords(CP._internal.mismatchWords(r, file), `${r} ${file}`);
  }
  assert.ok(S.WITHDRAWAL_CLAIM.includes("a tape a counterparty already has"), S.WITHDRAWAL_CLAIM);
  refuseWords(S.WITHDRAWAL_CLAIM, "WITHDRAWAL_CLAIM");
  refuseWords(await statusHtml(), "the status page");
  const rp = makeRes();
  RECONCILE.handlePage(makeReq({ method: "GET", query: { op: "reconcile-page" }, headers: { "x-forwarded-for": nextIp() } }), rp);
  refuseWords(String(rp._body), "the reconcile page");
});

// F3-b. The page cache keeps no root sha, and no page whose case deadline
// falls inside the next 60 seconds.
// Every request `fn` sends to the store: their URLs.
async function storeCalls(fn) {
  const viaMock = global.fetch;
  const seen = [];
  global.fetch = async (url, o) => {
    seen.push(String(url));
    return viaMock(url, o);
  };
  try {
    await fn();
  } finally {
    global.fetch = viaMock;
  }
  return seen;
}
test("R-WIDEf F3-b: a case whose deadline is 30 seconds away is not kept (the page would show OPEN past it); one 120 seconds away, or already past, is; the kept page records no root sha", async () => {
  const id = await openCase("RWIDEf F3-b");
  const deadline = Date.parse(DEADLINE);
  const viewAt = (cache, now) => async () => {
    const res = makeRes();
    await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": nextIp() } }), res,
      { now, keyDocument: DOC, env: {}, cache });
    assert.equal(res._status, 200, String(res._body).slice(0, 200));
    return String(res._body);
  };
  for (const [ahead, kept] of [[30000, false], [60000, false], [60001, true], [120000, true], [-10000, true]]) {
    const cache = CP.pageCache({ clock: () => 0 });
    const view = viewAt(cache, deadline - ahead);
    await view();
    assert.equal(cache.size(), kept ? 1 : 0, `deadline ${ahead / 1000} s away`);
    const again = await storeCalls(view);
    assert.equal(again.length === 0, kept, `deadline ${ahead / 1000} s away: the second view ${kept ? "makes no store call" : "reads again"}`);
    if (kept) assert.equal("root_sha" in cache.get(id), false, "no root sha is kept");
  }
  // the footer still says it may be up to 60 seconds old
  const cache = CP.pageCache({ clock: () => 0 });
  assert.ok((await viewAt(cache, deadline - 120000)()).includes("may be up to 60 seconds old"));
});

// F3-c. The document at the tip, read through the contents API at the
// branch head, not from the raw host's cache.
const NEWER = Object.freeze(KD.docWith(KD.entry(CASE_KEY, { status: "revoked" }), KD.reconcileEntry(RECEIPT_KEY)));
async function spyFetch(fn) {
  const viaMock = global.fetch;
  const seen = [];
  global.fetch = async (url, o) => {
    seen.push({ url: decodeURIComponent(String(url)), auth: (o && o.headers && (o.headers.authorization || o.headers.Authorization)) || null });
    return viaMock(url, o);
  };
  try {
    return { out: await fn(), seen };
  } finally {
    global.fetch = viaMock;
  }
}
test("R-WIDEf F3-c: the document at the tip is read through the contents API at the head of the published branch (the API road the compare takes), never from the raw host, whose copy of a branch may be minutes old", async () => {
  // the branch now carries a revocation; the raw host still serves the copy before it
  KD.publishTip(gh, NEWER);
  gh.seedRaw(S.KEY_DOCUMENT_REPO, "main", S.CASE_KEYS_FILE, `${JSON.stringify(DOC, null, 2)}\n`);
  const r = await spyFetch(() => S.carriedDocumentPublished(DOC, {}));
  assert.deepEqual(r.out, { ok: false, code: "carried_document_not_published", reason: "published_document_differs" });
  assert.deepEqual(r.seen.map((x) => x.url), [`https://api.github.com/repos/${S.KEY_DOCUMENT_REPO}/contents/${S.CASE_KEYS_FILE}?ref=main`]);
  assert.equal(r.seen[0].auth, `Bearer ${process.env.GITHUB_PIN_TOKEN}`, "the pin token, as the compare");
  // the branch it names, and the carried document there: ok
  KD.publishTip(gh, DOC, "preview-branch");
  const p = await spyFetch(() => S.carriedDocumentPublished(DOC, { KEY_DOCUMENT_BRANCH: "preview-branch" }));
  assert.deepEqual(p.out, { ok: true });
  assert.ok(p.seen[0].url.endsWith(`/contents/${S.CASE_KEYS_FILE}?ref=preview-branch`), p.seen[0].url);
  // a read that fails is could-not-look, with its status
  gh.forceGetFailure(S.KEY_DOCUMENT_REPO, S.CASE_KEYS_FILE, 1, 502);
  assert.deepEqual(await S.carriedDocumentPublished(DOC, {}), { ok: false, code: "published_document_unreadable", reason: "http_502" });
  assert.deepEqual(await S.carriedDocumentPublished(DOC, { KEY_DOCUMENT_BRANCH: "no-such-branch" }), { ok: false, code: "published_document_unreadable", reason: "http_404" });
  // README: the tip is read through the API
  assert.ok(README().includes("read once through the contents API at the head of the published branch"), "README");
});

// F3-d. The status page's view of the deployment's document is kept 60
// seconds, as "on the branch" is (C2).
test("R-WIDEf F3-d: two status views within 60 seconds in the off state make one compare call; past 60 seconds the branch is read again", async () => {
  KD.serveOffBranch(gh, S.PUBLISHED_KEYS, OFF_COMMIT);
  let t0 = 5_000_000;
  const before = S._internal.onBranchClock.now;
  S._internal.onBranchClock.now = () => t0;
  try {
    await withDeployCommit(OFF_COMMIT, async () => {
      const n = gh.compareLog.length;
      const first = await statusHtml();
      assert.ok(first.includes("<code>deployment_document_off_branch</code>"), "fixture: the off state");
      assert.equal(gh.compareLog.length, n + 1, "the first view compares once");
      t0 += 59_999;
      const second = await statusHtml();
      assert.ok(second.includes("<code>deployment_document_off_branch</code>"));
      assert.equal(gh.compareLog.length, n + 1, "within 60 seconds: no compare");
      t0 += 1;
      await statusHtml();
      assert.equal(gh.compareLog.length, n + 2, "at 60 seconds: compared again");
    });
  } finally {
    S._internal.onBranchClock.now = before;
  }
});

// F3-f. The README's stamp section names the retired refusal.
test("R-WIDEf F3-f: the README's stamp section says stamp_size_mismatch is retired: no new stamp carries a size, and old stamps keep theirs and are never deleted", () => {
  const r = read("README.md");
  const a = r.indexOf("### Stamps");
  const section = r.slice(a, r.indexOf("\n### ", a + 5)).replace(/\s+/g, " ");
  assert.ok(section.includes("The case registration's `stamp_size_mismatch` refusal is retired: no new stamp carries a size, and old stamps keep theirs and are never deleted."), section);
});
