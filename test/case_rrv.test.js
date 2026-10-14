// test/case_rrv.test.js — unit R-RV (2026-10-14): the reveal is one
// compare-and-swap; no stamp re-check; no legacy stamp form. The joint
// reveal writes the case root once, the VERDICT seal, by compare-and-swap on
// the blob sha of the COMMITTED root it read; a failure before or after the
// comparison writes nothing, so a failed reveal leaves a clean COMMITTED
// case its parties can send again or withdraw. The reveal reads no stamp: a
// seal's stamp fields are the projected registration's, and stamp_commit is
// required. With the architect's rulings: (a) a lost compare-and-swap that
// re-reads COMMITTED is 503 case_seal_failed with rule 4's text; (b) a stamp
// touched by more than one commit is registered at the oldest; (c)
// compared_at is the clock read after the port returns; (d) the 503 text
// says nothing was pinned, never "anchored". The setup below is
// test/case_rrev.test.js's.
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-14rrv");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-14rrv");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-14rrv");
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
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0171", url: "https://second-operator.example/cases/0152" });
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
// THE BRIEF'S TEN TESTS
// =============================================================================

test("R-RV 1: a reveal that fails after the comparison leaves the case unchanged: 500 comparison_failed, the root's blob sha as before, no reveal_attempts", async (t) => {
  const c = await committedCase("RRV 1");
  const before = rootSha(c.id);
  const puts = casePuts(c.id);
  portFails(t);
  const r = await reveal(c);
  assert.deepEqual([r.status, r.body.error_code], [500, "comparison_failed"], JSON.stringify(r.body));
  assert.equal(rootSha(c.id), before, "the root is as it was read");
  assert.equal(casePuts(c.id), puts, "nothing was written to the root");
  assert.equal(has(storedCase(c.id), "reveal_attempts"), false);
  assert.equal(storedCase(c.id).status, "COMMITTED");
});

test("R-RV 2: a withdrawal after a failed reveal succeeds, and the root is WITHDRAWN", async (t) => {
  const c = await committedCase("RRV 2");
  portFails(t);
  assert.equal((await reveal(c)).status, 500);
  const w = await withdraw(c.id, c.b);
  assert.equal(w.status, 201, JSON.stringify(w.body));
  assert.equal(storedCase(c.id).status, "WITHDRAWN");
});

test("R-RV 3: a deterministic reveal failure does not trap the case: two reveals fail, the page never says a reveal sent again seals it, and a withdrawal succeeds", async (t) => {
  const c = await committedCase("RRV 3");
  portFails(t);
  for (let i = 0; i < 2; i += 1) assert.deepEqual([(await reveal(c)).body.error_code], ["comparison_failed"]);
  const page = await casePage(c.id);
  assert.equal(page.status, 200);
  assert.doesNotMatch(page.html, /seals it|sent again|send it again|attempted/);
  // the rule, as a condition, never a promise that sending seals
  assert.ok(page.html.includes("Both roles are registered. A case is sealed only by one request carrying both reveals and both tapes, received before the deadline."));
  assert.equal((await withdraw(c.id, c.a)).status, 201);
  assert.equal(storedCase(c.id).status, "WITHDRAWN");
});

test("R-RV 4 (a guard: it passes before this unit too): the same reveal re-sent after a transient failure seals", async (t) => {
  const c = await committedCase("RRV 4");
  portFails(t, 1);
  assert.equal((await reveal(c)).status, 500);
  const r = await reveal(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.equal(storedCase(c.id).status, "VERDICT");
});

test("R-RV 5: a seal that loses to a withdrawal returns no verdict: 409 case_withdrawn, the rule's text, no verdict, receipt or tape digest, and the root WITHDRAWN", async () => {
  const c = await committedCase("RRV 5");
  const { out: r, fired } = await during((url, method) => method === "PUT" && url.includes(`/contents/${C.casePath(c.id)}`),
    () => withdraw(c.id, c.b), () => reveal(c));
  assert.ok(fired, "fixture: the withdrawal landed before the reveal's root write");
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.deepEqual([r.body.error_code, r.body.error], ["case_withdrawn", WITHDRAWN_TEXT]);
  for (const k of ["verdict", "receipt", "case", "refusal_receipt"]) assert.equal(has(r.body, k), false, k);
  assert.ok(noTapeDigest(c, r.body), "no tape digest");
  assert.equal(storedCase(c.id).status, "WITHDRAWN");
});

test("R-RV 6: the reveal does not read the stamps repository: with every stamps read failing it seals, and the seal's stamp fields are the registration files'", async () => {
  const c = await committedCase("RRV 6");
  const viaMock = global.fetch;
  const stampReads = [];
  global.fetch = async (url, o) => {
    if (String(url).includes(STAMPS)) {
      stampReads.push(String(url));
      throw new Error("the stamps repository is unreachable");
    }
    return viaMock(url, o);
  };
  let r;
  try {
    r = await reveal(c);
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.deepEqual(stampReads, []);
  for (const role of C.ROLES) {
    const file = gh.read(PINS, REG.pathOf(gh, c.id, role));
    const e = storedCase(c.id).commitments[role];
    assert.deepEqual([e.stamp_commit, e.stamped_at], [file.stamp_commit, file.stamped_at], role);
  }
});

test("R-RV 7: a registration with stamp_commit null is malformed, and so is a commitment entry with null", async () => {
  const c = await committedCase("RRV 7");
  const file = gh.read(PINS, REG.pathOf(gh, c.id, "a"));
  assert.deepEqual(C.validateRegistrationRecord(file), { ok: true }, "control");
  const v = C.validateRegistrationRecord({ ...file, stamp_commit: null });
  assert.deepEqual([v.ok, v.code, v.field], [false, "malformed_field", "registration.stamp_commit"]);
  const k = storedCase(c.id);
  const w = C.validateCase({ ...k, commitments: { ...k.commitments, a: { ...k.commitments.a, stamp_commit: null } } });
  assert.deepEqual([w.ok, w.code, w.field], [false, "malformed_field", "commitments.a.stamp_commit"]);
});

test("R-RV 8: a root carrying reveal_attempts is refused unknown_field", async () => {
  const c = await committedCase("RRV 8");
  const k = storedCase(c.id);
  const attempts = [{ event: "attempt", commitments: { a: k.commitments.a.commitment_sha256, b: k.commitments.b.commitment_sha256 }, input_sha256: "e".repeat(64), at: "2026-10-10T09:00:00Z" }];
  const v = C.validateCase({ ...k, reveal_attempts: attempts });
  assert.deepEqual([v.ok, v.code, v.field], [false, "unknown_field", "reveal_attempts"]);
});

test("R-RV 9: the dead case-event schema and the reveal-attempt machinery are gone", () => {
  for (const name of ["validateCaseEvent", "caseLogPath", "caseLogDir", "CASE_EVENT_KIND", "CASE_EVENT_FIELDS", "revealInputSha256"]) {
    assert.equal(C[name], undefined, name);
  }
  for (const f of jsFiles("lib")) {
    assert.doesNotMatch(read(f), /reveal_attempts|reveal_attempted|reveal_incomplete|commitment_history_missing|reveal_attempt_unwritten|revealAttemptHtml|recordRevealFailure/, f);
  }
});

test("R-RV 10: a seal write that throws is 503 case_seal_failed saying the case may not have been sealed and nothing was pinned; the same reveal sent again seals", async () => {
  const c = await committedCase("RRV 10");
  gh.forceFailure(PINS, C.casePath(c.id), 1, 502);
  const r = await reveal(c);
  assert.equal(r.status, 503, JSON.stringify(r.body));
  assert.deepEqual([r.body.error_code, r.body.error], ["case_seal_failed", RULE_4]);
  assert.doesNotMatch(JSON.stringify(r.body), /anchored/);
  assert.equal(storedCase(c.id).status, "COMMITTED");
  assert.equal((await reveal(c)).status, 201, "sent again, it seals");
});

// =============================================================================
// THE RULINGS AND RULE 3
// =============================================================================

test("R-RV rule 3 (ruling a): a lost compare-and-swap that re-reads COMMITTED is 503 case_seal_failed with rule 4's text; one that re-reads VERDICT is 409 not_committed", async () => {
  const c = await committedCase("RRV 3a");
  // the root rewritten under the reveal, still COMMITTED: the same record, its keys in another order, so another blob sha
  const { out: r } = await during((url, method) => method === "PUT" && url.includes(`/contents/${C.casePath(c.id)}`),
    async () => gh.seed(PINS, C.casePath(c.id), Object.fromEntries(Object.entries(storedCase(c.id)).reverse())), () => reveal(c));
  assert.deepEqual([r.status, r.body.error_code, r.body.error], [503, "case_seal_failed", RULE_4], JSON.stringify(r.body));
  assert.equal(storedCase(c.id).status, "COMMITTED");
  const d = await committedCase("RRV 3a, sealed meanwhile");
  const { out: lost } = await during((url, method) => method === "PUT" && url.includes(`/contents/${C.casePath(d.id)}`),
    () => reveal(d), () => reveal(d));
  assert.deepEqual([lost.status, lost.body.error_code, lost.body.status], [409, "not_committed", "VERDICT"], JSON.stringify(lost.body));
  assert.equal(has(lost.body, "verdict"), false);
});

test("R-RV rule 2: each failure writes nothing and logs the case id and its code only", async (t) => {
  const c = await committedCase("RRV log");
  const logged = [];
  t.mock.method(console, "error", (...args) => { logged.push(args.join(" ")); });
  portFails(t);
  const before = rootSha(c.id);
  assert.equal((await reveal(c)).status, 500);
  assert.equal(rootSha(c.id), before);
  const lines = logged.filter((l) => l.includes("comparison_failed"));
  assert.deepEqual(lines, [`[case] reveal: case ${c.id}, comparison_failed`]);
  for (const l of logged) assert.ok(noTapeDigest(c, l) && !l.includes(c.a.salt) && !l.includes(c.b.salt), l);
});

test("R-RV ruling b: a stamp touched by more than one commit is registered at the oldest commit that touched it", async () => {
  const id = await openCase("RRV ruling b");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const spath = stamp.stampPath(a.commitment_sha256);
  gh.addCommit(STAMPS, spath);
  gh.addCommit(STAMPS, spath);
  const commits = gh.commitsFor(STAMPS, spath);
  assert.equal(commits.length, 3, "fixture: three commits touch the stamp");
  const r = await commit(id, a);
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(gh.read(PINS, REG.pathOf(gh, id, "a")).stamp_commit, commits[commits.length - 1].sha, "the oldest");
});

test("R-RV ruling b: the oldest is found past the first page of the stamp's history", async () => {
  const id = await openCase("RRV ruling b, pages");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const spath = stamp.stampPath(a.commitment_sha256);
  for (let i = 0; i < 104; i += 1) gh.addCommit(STAMPS, spath);
  const oldest = gh.commitsFor(STAMPS, spath).slice(-1)[0].sha;
  const r = await commit(id, a);
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(gh.read(PINS, REG.pathOf(gh, id, "a")).stamp_commit, oldest);
});

test("R-RV ruling c: compared_at is the clock read after the port returns, and the seal's times are that one read", async (t) => {
  const c = await committedCase("RRV ruling c");
  let ms = REVEAL_AT;
  const real = TAPES.reconcileTapes;
  t.mock.method(TAPES, "reconcileTapes", (...args) => {
    ms += 5000; // the port takes five seconds
    return real(...args);
  });
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", revealBody(c.id, c.a, c.b)), res, { clock: () => ms, env: KD.deployed(gh, KEYS, DOC), keyDocument: DOC });
  const r = parsed(res);
  assert.equal(res._status, 201, JSON.stringify(r).slice(0, 300));
  const after = C.utcSeconds(REVEAL_AT + 5000);
  assert.equal(r.case.verdict.compared_at, after);
  assert.deepEqual([r.case.reveals.a.revealed_at, r.case.reveals.b.revealed_at, r.case.signed_under.retrieved_at], [after, after, after]);
  assert.equal(r.case.verdict.claim, receipts.CLAIM, "the signed sentence is unchanged");
  assert.equal((await S.sealedRecordReason(storedCase(c.id), DOC)).code, "valid_under_document");
});

test("R-RV: the sealer reads a COMMITTED case as not_sealed with its status and no reason, and its run has no reveal_incomplete", async () => {
  const c = await committedCase("RRV sealer");
  assert.deepEqual(await S.anchorCase(c.id, { now: REVEAL_AT, keyDocument: DOC }), { ok: false, code: "not_sealed", status: "COMMITTED" });
  const run = await sealerRun();
  assert.equal(has(run.cases || run, "reveal_incomplete"), false);
});

test("R-RV ruling c, at the deadline: a reveal received before the deadline whose comparison ends at or after it builds a seal the schema refuses: 500 seal_build_failed, nothing written", async (t) => {
  const c = await committedCase("RRV ruling c deadline");
  const before = rootSha(c.id);
  let ms = Date.parse(DEADLINE) - 500; // received half a second before the deadline
  const real = TAPES.reconcileTapes;
  t.mock.method(TAPES, "reconcileTapes", (...args) => {
    ms += 1000; // the comparison ends after it
    return real(...args);
  });
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", revealBody(c.id, c.a, c.b)), res, { clock: () => ms, env: KD.deployed(gh, KEYS, DOC), keyDocument: DOC });
  const r = parsed(res);
  assert.deepEqual([res._status, r.error_code], [500, "seal_build_failed"], JSON.stringify(r).slice(0, 300));
  assert.equal(rootSha(c.id), before, "nothing written");
});
