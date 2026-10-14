// test/case_rrvf.test.js — unit R-RVf (2026-10-14): the architect's rulings
// on R-RV's second read. B1: revealed_at is the arrival time, read before
// any port call; compared_at is the clock after the port returns; the
// receipt check binds revealed_at <= compared_at; the deadline is judged on
// the arrival clock and nothing else, so a reveal that arrived in time seals
// even when its comparison lands after the deadline. B2: a stamp history
// past the bound is 409 commits_beyond_bound with readStamp's "Draw a new
// salt" sentence. M1: the stamp is read at the oldest commit that touched it
// and its bytes must equal the current file's, else 409 stamp_rewritten. M2:
// the registrations panel's ruled sentence. The setup below is
// test/case_rrv.test.js's.
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-14rrvf");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-14rrvf");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-14rrvf");
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
  await H.handleCaseWithdraw(req("case-withdraw", { case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt }), res, { now, env: KD.deployedFor(gh, env, DOC), keyDocument: DOC });
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
async function reference(c, { role = "a", env = KEYS, now = REVEAL_AT + 1800000 } = {}) {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: XREF }),
    res, { now, env: KD.deployedFor(gh, env, DOC), keyDocument: DOC });
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
// UNIT R-RVf
// =============================================================================

const ADVICE = `Draw a new salt, compute a new commitment, stamp it with size ${C.COMMITMENT_BYTES_LENGTH} and register that hash. Nothing was registered.`;
const EXPIRED_SENTENCE = "No joint reveal was received before the deadline, by this service's clock";
const DEADLINE_MS = Date.parse(DEADLINE);
// A reveal whose clock reads `arrival` when it arrives and moves `portMs`
// while the port runs.
async function timedReveal(t, c, arrival, portMs) {
  let ms = arrival;
  const real = TAPES.reconcileTapes;
  t.mock.method(TAPES, "reconcileTapes", (...args) => {
    ms += portMs;
    return real(...args);
  });
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", revealBody(c.id, c.a, c.b)), res, { clock: () => ms, env: KD.deployed(gh, KEYS, DOC), keyDocument: DOC });
  TAPES.reconcileTapes.mock.restore();
  return { status: res._status, body: parsed(res) };
}
const revealedAtRow = (html) => {
  const m = html.match(/<tr><th>revealed at<\/th><td>([^<]*)<\/td><\/tr>/);
  return m ? m[1] : null;
};

test("R-RVf B1: a reveal that arrives before the deadline whose comparison and compare-and-swap land after it answers 201 and seals; revealed_at is the arrival time and compared_at the clock after the port", async (t) => {
  const c = await committedCase("RRVf B1 late port");
  const arrival = DEADLINE_MS - 500;
  const r = await timedReveal(t, c, arrival, 1000);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  const k = storedCase(c.id);
  assert.equal(k.status, "VERDICT");
  assert.deepEqual([k.reveals.a.revealed_at, k.reveals.b.revealed_at], [C.utcSeconds(arrival), C.utcSeconds(arrival)], "the arrival time");
  assert.equal(k.verdict.compared_at, C.utcSeconds(arrival + 1000), "the clock after the port returns");
  assert.ok(Date.parse(k.verdict.compared_at) >= DEADLINE_MS, "the comparison landed at or after the deadline");
  assert.equal((await S.sealedRecordReason(k, DOC)).code, "valid_under_document");
});

test("R-RVf B1: the receipt check accepts revealed_at earlier than compared_at, and refuses revealed_at later than compared_at, at the seal and on a stored case", async (t) => {
  const c = await committedCase("RRVf B1 binding");
  assert.equal((await timedReveal(t, c, REVEAL_AT, 7000)).status, 201);
  const k = storedCase(c.id);
  assert.ok(Date.parse(k.reveals.a.revealed_at) < Date.parse(k.verdict.compared_at), "fixture: earlier");
  assert.equal(S.checkSealedReceipt(k), null, "earlier is accepted");
  const at = (iso) => ({ ...k, reveals: { a: { ...k.reveals.a, revealed_at: iso }, b: { ...k.reveals.b, revealed_at: iso } } });
  assert.equal(S.checkSealedReceipt(at(k.verdict.compared_at)), null, "equal is accepted");
  assert.equal(S.checkSealedReceipt(at(C.utcSeconds(Date.parse(k.verdict.compared_at) + 1000))), "receipt_time_mismatch", "later is refused");
  // at the seal: a clock that reads earlier after the port than at arrival
  const d = await committedCase("RRVf B1 binding at the seal");
  const before = rootSha(d.id);
  const back = await timedReveal(t, d, REVEAL_AT, -2000);
  assert.deepEqual([back.status, back.body.error_code, back.body.reason], [500, "receipt_check_failed", "receipt_time_mismatch"], JSON.stringify(back.body).slice(0, 300));
  assert.equal(rootSha(d.id), before, "nothing written");
});

test("R-RVf B1: the page's 'revealed at' is the arrival time, and a case sealed by a reveal that arrived in time never prints the EXPIRED sentence", async (t) => {
  const c = await committedCase("RRVf B1 page");
  const arrival = DEADLINE_MS - 500;
  assert.equal((await timedReveal(t, c, arrival, 1000)).status, 201);
  const p = await casePage(c.id, DEADLINE_MS + 3600000);
  assert.equal(p.status, 200);
  assert.equal(revealedAtRow(p.html), C.utcSeconds(arrival), "the arrival time, not the clock after the port");
  assert.ok(!p.html.includes(EXPIRED_SENTENCE));
  assert.doesNotMatch(p.html, /EXPIRED/);
});

test("R-RVf B1: the EXPIRED sentence prints only when no reveal arrived before the deadline", async () => {
  // no reveal at all
  const c = await committedCase("RRVf B1 no reveal");
  assert.ok((await casePage(c.id, DEADLINE_MS + 1000)).html.includes(EXPIRED_SENTENCE));
  assert.ok(!(await casePage(c.id, DEADLINE_MS - 1000)).html.includes(EXPIRED_SENTENCE), "before the deadline: not expired");
  // a reveal that arrives at the deadline is refused, and the case reads EXPIRED
  const d = await committedCase("RRVf B1 at the deadline");
  const before = rootSha(d.id);
  const late = await reveal(d, { now: DEADLINE_MS });
  assert.deepEqual([late.status, late.body.error_code], [409, "expired"], JSON.stringify(late.body).slice(0, 300));
  assert.equal(rootSha(d.id), before, "nothing written");
  assert.ok((await casePage(d.id, DEADLINE_MS + 1000)).html.includes(EXPIRED_SENTENCE));
});

test("R-RVf B1: a re-send after the deadline is a new arrival, judged on its own arrival time", async (t) => {
  const c = await committedCase("RRVf B1 resend");
  const before = rootSha(c.id);
  portFails(t, 1);
  const first = await reveal(c, { now: DEADLINE_MS - 1000 });
  assert.deepEqual([first.status, first.body.error_code], [500, "comparison_failed"]);
  const again = await reveal(c, { now: DEADLINE_MS + 1000 });
  assert.deepEqual([again.status, again.body.error_code], [409, "expired"], JSON.stringify(again.body).slice(0, 300));
  assert.equal(rootSha(c.id), before, "nothing written");
  assert.ok((await casePage(c.id, DEADLINE_MS + 2000)).html.includes(EXPIRED_SENTENCE));
});

test("R-RVf B2: a stamp path with more than ten pages of history answers 409 commits_beyond_bound with the existing sentence, writes nothing, and a re-send with a new salt finishes", async () => {
  const id = await openCase("RRVf B2");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const spath = stamp.stampPath(a.commitment_sha256);
  for (let i = 0; i < 1000; i += 1) gh.addCommit(STAMPS, spath);
  const root = rootSha(id);
  const puts = gh.putLog.length;
  const r = await commit(id, a);
  assert.deepEqual([r.status, r.body.error_code], [409, "commits_beyond_bound"], JSON.stringify(r.body));
  assert.ok(r.body.error.endsWith(` ${ADVICE}`), r.body.error);
  assert.equal(gh.putLog.length, puts, "nothing written");
  assert.equal(rootSha(id), root);
  assert.equal(storedCase(id).commitments.a, null);
  // a new salt, a new commitment, a new stamp
  const a2 = party(id, "a", AGENT_TAPE);
  plantStamp(a2.commitment_sha256);
  const r2 = await commit(id, a2);
  assert.equal(r2.status, 201, JSON.stringify(r2.body));
  assert.equal(storedCase(id).commitments.a.commitment_sha256, a2.commitment_sha256);
});

test("R-RVf M1: the stamp is read at the oldest commit that touched it, and its bytes there must equal the current file's; stamped_at is taken from those bytes", async () => {
  const id = await openCase("RRVf M1 equal");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const spath = stamp.stampPath(a.commitment_sha256);
  gh.addCommit(STAMPS, spath);
  const oldest = gh.commitsFor(STAMPS, spath).slice(-1)[0].sha;
  let r;
  const seen = await spyRequests(async () => { r = await commit(id, a); });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.ok(seen.some((s) => s.method === "GET" && s.url.includes(`/repos/${STAMPS}/contents/${spath}?ref=${oldest}`)), "the read at the oldest commit");
  const reg = gh.read(PINS, REG.pathOf(gh, id, "a"));
  assert.deepEqual([reg.stamp_commit, reg.stamped_at], [oldest, "2026-10-10T07:45:00.123Z"]);
});

test("R-RVf M1: a stamp whose bytes differ from those its oldest commit wrote answers 409 stamp_rewritten with the existing sentence; nothing is recorded and the case is unchanged", async () => {
  const id = await openCase("RRVf M1 rewritten");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const spath = stamp.stampPath(a.commitment_sha256);
  const rec = gh.read(STAMPS, spath);
  gh.seed(STAMPS, spath, { ...rec, stamped_at: "2026-10-10T07:40:00.000Z" }, { keepHistory: true });
  assert.equal(gh.commitsFor(STAMPS, spath).length, 2, "fixture: written, then rewritten");
  const root = rootSha(id);
  const puts = gh.putLog.length;
  const r = await commit(id, a);
  assert.deepEqual([r.status, r.body.error_code], [409, "stamp_rewritten"], JSON.stringify(r.body));
  assert.ok(r.body.error.endsWith(` ${ADVICE}`), r.body.error);
  assert.equal(gh.putLog.length, puts, "nothing written");
  assert.equal(rootSha(id), root, "the case unchanged");
  assert.equal(storedCase(id).commitments.a, null);
  assert.equal(gh.has(PINS, REG.claimPath({ case_id: id, ...a }, a.key)), false, "no registration file");
  // the same record in other bytes is rewritten too: the bytes are compared
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(b.commitment_sha256);
  const bpath = stamp.stampPath(b.commitment_sha256);
  gh.seedText(STAMPS, bpath, JSON.stringify(gh.read(STAMPS, bpath)));
  const rb = await commit(id, b);
  assert.deepEqual([rb.status, rb.body.error_code], [409, "stamp_rewritten"], JSON.stringify(rb.body));
});

test("R-RVf M1: a listing cut at a page boundary never takes a newer commit as the oldest", async (t) => {
  // a full first page that names no next page: the next page is read
  const id = await openCase("RRVf M1 boundary");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const spath = stamp.stampPath(a.commitment_sha256);
  for (let i = 0; i < 99; i += 1) gh.addCommit(STAMPS, spath);
  const all = gh.commitsFor(STAMPS, spath);
  assert.equal(all.length, 100, "fixture: exactly one full page");
  const viaMock = global.fetch;
  let failPage2 = false;
  global.fetch = async (url, o) => {
    const u = String(url);
    if (!u.includes(`/repos/${STAMPS}/commits?`)) return viaMock(url, o);
    const page = Number(new URL(u).searchParams.get("page") || 1);
    if (page === 2 && failPage2) return { ok: false, status: 502, headers: { get: () => null }, json: async () => ({}), text: async () => "" };
    const r = await viaMock(url, o);
    return { ...r, headers: { get: () => null } };
  };
  t.after(() => { global.fetch = viaMock; });
  const r = await commit(id, a);
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(gh.read(PINS, REG.pathOf(gh, id, "a")).stamp_commit, all[99].sha, "the oldest");
  // the page after a full one cannot be read: no oldest is taken from the part read
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(b.commitment_sha256);
  const bpath = stamp.stampPath(b.commitment_sha256);
  for (let i = 0; i < 149; i += 1) gh.addCommit(STAMPS, bpath);
  failPage2 = true;
  const puts = gh.putLog.length;
  const rb = await commit(id, b);
  assert.deepEqual([rb.status, rb.body.error_code], [503, "stamp_history_unreachable"], JSON.stringify(rb.body));
  assert.equal(gh.putLog.length, puts, "nothing written");
  assert.equal(storedCase(id).commitments.b, null);
});

test("R-RVf M1: a history of exactly ten full pages is past the bound: 409 commits_beyond_bound, never the tenth page's last as the oldest", async () => {
  const id = await openCase("RRVf M1 ten pages");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const spath = stamp.stampPath(a.commitment_sha256);
  for (let i = 0; i < 999; i += 1) gh.addCommit(STAMPS, spath);
  assert.equal(gh.commitsFor(STAMPS, spath).length, 1000);
  const r = await commit(id, a);
  assert.deepEqual([r.status, r.body.error_code], [409, "commits_beyond_bound"], JSON.stringify(r.body));
  assert.equal(storedCase(id).commitments.a, null);
});

test("R-RVf M2: the registrations panel prints the ruled sentence exactly, keeps the stamp commit and stamped line, and no longer says 'stamped first as a public, dated commit'", async () => {
  const c = await committedCase("RRVf M2");
  const p = await casePage(c.id, NOW + 60000);
  assert.equal(p.status, 200);
  assert.ok(p.html.includes(esc("Before registration the commitment's stamp must already be in the stamps repository; this service records the oldest " +
    "commit that touched it for metering, and this page does not treat that commit or its date as evidence of when the commitment was made.")), p.html);
  assert.ok(!p.html.includes("stamped first as a public, dated commit"));
  assert.ok(!read("lib/_case_page.js").includes("stamped first as a public, dated commit"));
  const e = storedCase(c.id).commitments.a;
  assert.ok(p.html.includes(`(stamped ${e.stamped_at})`));
  assert.ok(p.html.includes(`stamp commit ${e.stamp_commit.slice(0, 12)}`) || p.html.includes(e.stamp_commit));
});

// =============================================================================
// UNIT R-RVf, THE MUST-FAIL PASS: tests for the planted defects the tests
// above let through (the ids are the pass's)
// =============================================================================

test("MUST-FAIL GAP (W05, W06): a stored receipt whose compared_at is not a UTC-seconds string is receipt_time_mismatch", async (t) => {
  const c = await committedCase("RRVf gap compared_at form");
  assert.equal((await timedReveal(t, c, REVEAL_AT, 3000)).status, 201);
  const k = storedCase(c.id);
  const with_ = (v) => ({ ...k, verdict: { ...k.verdict, compared_at: v } });
  for (const v of ["not a time", "2026-10-10T09:00:03.000Z", [k.verdict.compared_at], null]) {
    assert.equal(S.checkSealedReceipt(with_(v)), "receipt_time_mismatch", JSON.stringify(v));
  }
});

// The stamps repository's contents read at a commit, answered by `answer`.
function stampReadAt(t, answer) {
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    const u = String(url);
    if (u.includes(`/repos/${STAMPS}/contents/`) && /[?&]ref=[0-9a-f]{40}/.test(u)) return answer(u, viaMock, o);
    return viaMock(url, o);
  };
  t.after(() => { global.fetch = viaMock; });
}

test("MUST-FAIL GAP (W15, W25): a stamp the oldest commit did not leave at its path is 409 stamp_rewritten, never a 500; nothing is recorded", async (t) => {
  const id = await openCase("RRVf gap 404 at oldest");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  stampReadAt(t, async () => ({ ok: false, status: 404, headers: { get: () => null }, json: async () => ({ message: "Not Found" }), text: async () => "" }));
  const puts = gh.putLog.length;
  const r = await commit(id, a);
  assert.deepEqual([r.status, r.body.error_code], [409, "stamp_rewritten"], JSON.stringify(r.body));
  assert.equal(gh.putLog.length, puts, "nothing written");
});

test("MUST-FAIL GAP (W20): a read at the oldest commit that fails is 503 stamp_store_unreachable, not a 409; nothing is recorded, and the same registration sent again finishes", async (t) => {
  const id = await openCase("RRVf gap read fails at oldest");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  let fail = true;
  stampReadAt(t, async (u, viaMock, o) => (fail ? { ok: false, status: 502, headers: { get: () => null }, json: async () => ({}), text: async () => "" } : viaMock(u, o)));
  const puts = gh.putLog.length;
  const r = await commit(id, a);
  assert.deepEqual([r.status, r.body.error_code], [503, "stamp_store_unreachable"], JSON.stringify(r.body));
  assert.equal(gh.putLog.length, puts, "nothing written");
  fail = false;
  assert.equal((await commit(id, a)).status, 201);
});
