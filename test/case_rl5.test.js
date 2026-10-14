// test/case_rl5.test.js — unit R-L5 (2026-10-14): R-L4's leftovers. The
// WITHDRAWN root keeps its projection (commitments, exactly as it stood when
// the withdrawal was written, inside the signed record; no labels), and
// every reader of a withdrawn case takes standing from it: the refusal
// receipt and the retried withdrawal read no registration file and order
// nothing by commit. The DAMAGED removal was done by R-L4b and R-L4e (the
// architect's ruling), and the sealer's terminal branch is the one place a
// missing withdrawn marker is written. The setup below is
// test/case_rrev.test.js's.
"use strict";


process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0191:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-14rl5");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-14rl5");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-14rl5");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0191" });

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
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0191", url: "https://second-operator.example/cases/0152" });
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
// UNIT R-L5
// =============================================================================

// Every read of a registration file, and every read of the case root's
// history or of a file at a commit, recorded.
function spyReads(t, { failRegistrations = false } = {}) {
  const viaMock = global.fetch;
  const seen = [];
  global.fetch = async (url, o) => {
    const u = decodeURIComponent(String(url));
    seen.push(`${(o && o.method) || "GET"} ${u}`);
    if (failRegistrations && /registrations\//.test(u) && !((o && o.method) === "PUT")) throw new Error("planted: a registration file read");
    return viaMock(url, o);
  };
  t.after(() => { global.fetch = viaMock; });
  return seen;
}
const registrationReads = (seen) => seen.filter((s) => /^GET .*registrations\//.test(s));
const historyReads = (seen, id) => seen.filter((s) => s.includes(`commits?path=${C.casePath(id)}`) || (s.startsWith("GET https://raw.githubusercontent.com/") && s.includes(C.casePath(id))));

test("R-L5 1: a withdrawn root keeps its projection: commitments exactly as they stood, inside the signed record, and no labels", async () => {
  const c = await committedCase("RL5 keeps");
  const projected = storedCase(c.id).commitments;
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const w = storedCase(c.id);
  assert.equal(w.status, "WITHDRAWN");
  assert.deepEqual(w.commitments, projected);
  assert.equal(has(w, "party_a"), false);
  assert.equal(has(w, "party_b"), false);
  assert.ok(C.WITHDRAWN_FIELDS.includes("commitments"));
  // the record's signature covers it: one byte of the projection changed and the signature no longer holds
  const altered = { ...w, commitments: { ...w.commitments, a: { ...w.commitments.a, stamped_at: "2026-10-10T07:45:00.124Z" } } };
  assert.equal(S.signatureReason(w, CASE_KEY.verifier), null);
  assert.notEqual(S.signatureReason(altered, CASE_KEY.verifier), null);
});

test("R-L5 1b: an OPEN case withdrawn by its one registered role keeps that role's entry and a null for the other", async () => {
  const id = await openCase("RL5 open");
  const a = party(id, "a", AGENT_TAPE);
  await register(id, a);
  const projected = storedCase(id).commitments;
  assert.equal(projected.b, null, "fixture: OPEN, role b not registered");
  assert.equal((await withdraw(id, a)).status, 201);
  assert.deepEqual(storedCase(id).commitments, projected);
});

test("R-L5 1c: a WITHDRAWN root with no commitments, or with no entry for the role that withdrew, is not a valid record", async () => {
  const c = await committedCase("RL5 schema");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const w = storedCase(c.id);
  const { commitments: _gone, ...without } = w; // eslint-disable-line no-unused-vars
  assert.deepEqual([C.validateCase(without).code, C.validateCase(without).field], ["missing_field", "commitments"]);
  const noWithdrawer = { ...w, commitments: { ...w.commitments, b: null } };
  assert.deepEqual([C.validateCase(noWithdrawer).code, C.validateCase(noWithdrawer).field], ["status_inconsistent", "commitments.b"]);
});

test("R-L5 2: the refusal receipt reads no registration file and no history: with every registration read failing, a valid own opening gets the signed receipt", async (t) => {
  const c = await committedCase("RL5 receipt");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const seen = spyReads(t, { failRegistrations: true });
  const r = await reveal(c, { body: ownOpening(c, "a") });
  assert.deepEqual([r.status, r.body.error_code], [409, "case_withdrawn"], JSON.stringify(r.body).slice(0, 300));
  assert.equal(typeof r.body.refusal_receipt, "object");
  assert.equal(r.body.refusal_receipt.commitment_sha256, c.a.commitment_sha256);
  assert.deepEqual(registrationReads(seen), []);
  assert.deepEqual(historyReads(seen, c.id), []);
});

test("R-L5 3: a retried withdrawal reads no registration file and no history: 200", async (t) => {
  const c = await committedCase("RL5 retry");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const seen = spyReads(t, { failRegistrations: true });
  const again = await withdraw(c.id, c.b, { now: NOW + 4000 });
  assert.equal(again.status, 200, JSON.stringify(again.body).slice(0, 300));
  assert.deepEqual(registrationReads(seen), []);
  assert.deepEqual(historyReads(seen, c.id), []);
  // another salt is not the withdrawer
  const other = await withdraw(c.id, c.b, { now: NOW + 5000, salt: C.newSalt() });
  assert.deepEqual([other.status, other.body.error_code], [409, "case_withdrawn"]);
});

test("R-L5 4: a registration file written after the withdrawal is not in the kept projection and never stands; the page says registrations the record does not project do not stand", async () => {
  const id = await openCase("RL5 late file");
  const a = party(id, "a", AGENT_TAPE);
  await register(id, a);
  assert.equal((await withdraw(id, a)).status, 201);
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(b.commitment_sha256);
  const late = await commit(id, b);
  assert.equal(late.status, 409, JSON.stringify(late.body));
  assert.equal(storedCase(id).commitments.b, null, "not projected");
  const p = await casePage(id);
  assert.match(p.html, /<h1>Case: WITHDRAWN<\/h1>/);
  assert.ok(p.html.includes(esc(S.WITHDRAWN_REGISTRATIONS_NOTE)));
});

test("R-L5 5 (a guard; R-L4b and R-L4e did it): a projected file that does not match is 503 case_record_inconsistent, the could-not-look page, and the sealer does not pin", async () => {
  const c = await committedCase("RL5 inconsistent");
  const rpath = REG.pathOf(gh, c.id, "a");
  gh.seed(PINS, rpath, { ...gh.read(PINS, rpath), registered_at: "2026-10-10T07:59:59Z" }, { keepHistory: true });
  const r = await reveal(c);
  assert.deepEqual([r.status, r.body], [503, { ok: false, error_code: "case_record_inconsistent" }]);
  const w = await withdraw(c.id, c.b);
  assert.deepEqual([w.status, w.body.error_code], [503, "case_record_inconsistent"]);
  const p = await casePage(c.id);
  assert.equal(p.status, 503);
  assert.ok(p.html.includes("The stored record for this case does not agree with itself."));
  await sealerRun();
  assert.deepEqual(pinTree(c.id), []);
});

test("R-L5 6 (a guard): a withdrawn root without its marker gets one from the sealer's terminal branch, and no other window runs", async () => {
  const c = await committedCase("RL5 marker");
  gh.forceFailure(PINS, C.withdrawnMarkerPath(c.id), 1, 502);
  const w = await withdraw(c.id, c.b);
  assert.equal(w.status, 201);
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c.id)), false, "fixture: the marker write failed");
  const run = await sealerRun();
  assert.deepEqual(run.withdrawn_repaired, [{ case_id: c.id, marker: "written" }]);
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(c.id)), true);
  for (const f of jsFiles("lib")) assert.doesNotMatch(read(f), /WITHDRAWN_REPAIR_READS|markerless/, f);
});

test("R-L5: the root's history is no longer read for a withdrawn case: rootBeforeWithdrawal, withdrawalCommitOf and registrationAgainstWithdrawal are gone, and the withdrawn note says the record keeps the projection", () => {
  for (const name of ["rootBeforeWithdrawal", "withdrawalCommitOf", "registrationAgainstWithdrawal"]) assert.equal(S[name], undefined, name);
  for (const f of jsFiles("lib")) assert.doesNotMatch(read(f), /rootBeforeWithdrawal|WITHDRAWAL_COMMIT_READS/, f);
  assert.equal(S.WITHDRAWN_REGISTRATIONS_NOTE, "The registration files of this case, if any, remain in the public record of the pins repository. " +
    "This withdrawal record keeps the registrations the case root projected when it was withdrawn; a registration file it does not project " +
    "does not stand: no reader counts it.");
});

// =============================================================================
// UNIT R-L5, THE MUST-FAIL PASS: tests for the planted defects the tests
// above let through (the ids are the pass's)
// =============================================================================

test("MUST-FAIL GAP (L04, L05, L06, L07, L08, L10): the withdrawn record's projection is checked as the root's is: an object, no other key, both roles, whole entries, 64-hex sha256 and claim, one commitment per role", async () => {
  const c = await committedCase("RL5 gap schema");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const w = storedCase(c.id);
  const at = (commitments) => C.validateCase({ ...w, commitments });
  const { b: _b, ...onlyA } = w.commitments; // eslint-disable-line no-unused-vars
  const { key_id: _k, ...noKey } = w.commitments.a; // eslint-disable-line no-unused-vars
  const plants = [
    ["not an object", null, "malformed_field"],
    ["an array", [], "malformed_field"],
    ["another key", { ...w.commitments, c: null }, "unknown_field"],
    ["a role missing", onlyA, "missing_field"],
    ["an entry missing a field", { ...w.commitments, a: noKey }, "missing_field"],
    ["a registration_sha256 not 64 hex", { ...w.commitments, a: { ...w.commitments.a, registration_sha256: "nope" } }, "malformed_field"],
    ["a claim_sha256 not 64 hex", { ...w.commitments, a: { ...w.commitments.a, claim_sha256: "A".repeat(64) } }, "malformed_field"],
    ["one commitment in both roles", { ...w.commitments, a: { ...w.commitments.a, commitment_sha256: w.commitments.b.commitment_sha256 } }, "duplicate_commitment"],
  ];
  for (const [what, commitments, code] of plants) {
    const v = at(commitments);
    assert.equal(v.ok, false, what);
    assert.equal(v.code, code, `${what}: ${JSON.stringify(v)}`);
  }
  assert.deepEqual(at(w.commitments), { ok: true }, "control");
});

// Registration refuses one key for both roles (same_key_both_roles), so such
// a withdrawn record is planted.
test("MUST-FAIL GAP (L11): a withdrawn record whose kept projection names one key for both roles is WITHDRAWN, never single party", async () => {
  const c = await committedCase("RL5 gap one key");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const w = storedCase(c.id);
  const one = { ...w, commitments: { ...w.commitments, b: { ...w.commitments.b, key_id: w.commitments.a.key_id } } };
  assert.deepEqual(C.validateCase(one), { ok: true }, "fixture: a valid record");
  assert.equal(C.singleParty(one), false);
  gh.seed(PINS, C.casePath(c.id), one);
  const p = await casePage(c.id);
  assert.match(p.html, /<h1>Case: WITHDRAWN<\/h1>/);
  assert.doesNotMatch(p.html, /single_party/);
});

test("MUST-FAIL GAP (L17): the README says the withdrawal record keeps the root's commitments and every reader of a withdrawn case takes standing from them", () => {
  assert.ok(README().includes("The withdrawal record keeps the case root's `commitments` exactly as they stood when it was written, inside the signed record. " +
    "Every reader of a withdrawn case takes a role's standing from them: the refusal receipt, a withdrawal sent again, and the case page. None of them " +
    "reads a registration file or the root's history to decide it, and a registration file the record does not project does not stand."));
});

// =============================================================================
// UNIT R-L5f (the reader's blocker B1, and M1)
// =============================================================================

// B1: the root write is a compare-and-swap on the root as read before the
// case lock was taken, and a registration may be projected in between. The
// built record carries the projection it was built from, so it is written
// only over a root whose two entries are the ones it carries; otherwise
// nothing is written, and the re-send builds and signs it again from the
// root as it then stands.
const lockPut = (id) => (u, m) => m === "PUT" && decodeURIComponent(u).includes(`/repos/${USAGE}/contents/${H._internal.caseLockPath(id)}`);
async function projectedUnderWithdrawal(scope) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  const openRoot = storedCase(id);
  assert.equal(openRoot.commitments.b, null, "fixture: OPEN, role b not projected");
  await register(id, b);
  const committedRoot = storedCase(id);
  assert.equal(committedRoot.status, "COMMITTED");
  // the withdrawal reads the root before b's projection lands; it lands
  // while the withdrawal takes the case lock
  gh.seed(PINS, C.casePath(id), openRoot);
  return { id, a, b, committedRoot };
}

test("R-L5f B1: a registration projected between the withdrawal's read and its write: 503, nothing written; the re-send withdraws with the projected entry, and that role's refusal receipt answers", async () => {
  const c = await projectedUnderWithdrawal("RL5f B1");
  const before = pinsPaths().sort();
  const { out: r, fired } = await during(lockPut(c.id), async () => gh.seed(PINS, C.casePath(c.id), c.committedRoot), () => withdraw(c.id, c.a));
  assert.equal(fired, true, "fixture: the projection landed under the withdrawal");
  assert.deepEqual([r.status, r.body.error_code, r.body.reason, r.body.error, r.body.case_id],
    [503, "store_error", "case_kept_changing", "the case changed while this request tried to write; nothing was written to the case record. Send it again.", c.id],
    JSON.stringify(r.body).slice(0, 400));
  assert.deepEqual(storedCase(c.id), c.committedRoot, "the root is as the projection left it");
  assert.deepEqual(pinsPaths().sort(), before, "no marker and no other file");
  // the re-send builds and signs the record from the root as it now stands
  const again = await withdraw(c.id, c.a);
  assert.equal(again.status, 201, JSON.stringify(again.body).slice(0, 300));
  const w = storedCase(c.id);
  assert.equal(w.status, "WITHDRAWN");
  assert.deepEqual(w.commitments, c.committedRoot.commitments);
  assert.equal(S.signatureReason(w, CASE_KEY.verifier), null);
  assert.deepEqual(again.body.case, w);
  // role b, projected under the first withdrawal, is a party of the withdrawn case
  const rb = await reveal(c, { body: ownOpening(c, "b") });
  assert.equal(rb.status, 409, JSON.stringify(rb.body).slice(0, 300));
  assert.equal(rb.body.error_code, "case_withdrawn");
  const receipt = rb.body.refusal_receipt;
  assert.equal(receipt.role, "b");
  assert.equal(receipt.commitment_sha256, c.b.commitment_sha256);
  assert.deepEqual(await S.verifyRefusalReceipt(receipt, DOC), { ok: true });
});

test("R-L5f B1: when the root moved and both entries are the ones the built record carries, the built record is written", async () => {
  const c = await committedCase("RL5f B1 unchanged");
  const root = storedCase(c.id);
  // the root is written again with the same projection (a new blob sha)
  const { out: r, fired } = await during(lockPut(c.id), async () => gh.seed(PINS, C.casePath(c.id), { ...root }), () => withdraw(c.id, c.a));
  assert.equal(fired, true);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  const w = storedCase(c.id);
  assert.deepEqual(w.commitments, root.commitments);
  assert.deepEqual(r.body.case, w);
});

// M1: since unit R-L5 a withdrawal record carries `commitments`. A record
// in the form written before it (no commitments; and, before unit R-SIG, no
// signed_under) is refused by its schema with a named reason. Nothing is
// deployed, so no such record exists.
test("R-L5f M1: an old-form withdrawal record (no commitments, no signed_under) is refused as missing_field and never read as a valid withdrawal", async () => {
  const c = await committedCase("RL5f M1");
  const root = storedCase(c.id);
  const old = S.signCase({
    v: C.CASE_VERSION, case_id: c.id, protocol_version: root.protocol_version, status: "WITHDRAWN", opened_at: root.opened_at,
    withdrawal: { by_role: "a", at: "2026-10-10T08:00:02Z", salt_sha256: C.saltSha256(c.a.salt), reason: "party_choice" },
    limits: C.LIMITS.slice(),
  }, S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  assert.deepEqual([C.validateCase(old).code, C.validateCase(old).field], ["missing_field", "commitments"]);
  const judged = S.judgeCase({ json: old }, c.id);
  assert.deepEqual([judged.ok, judged.reason], [false, "case_missing_field"]);
  gh.seed(PINS, C.casePath(c.id), old);
  // the withdrawal sent again: the record is not read as a withdrawal
  const w = await withdraw(c.id, c.a);
  assert.deepEqual([w.status, w.body.error_code, w.body.reason], [503, "case_record_unreadable", "case_missing_field"], JSON.stringify(w.body));
  // the refusal receipt: none is issued from it
  const rr = await reveal(c, { body: ownOpening(c, "a") });
  assert.equal(rr.status, 503, JSON.stringify(rr.body).slice(0, 300));
  assert.equal(rr.body.error_code, "case_record_unreadable");
  assert.equal(has(rr.body, "refusal_receipt"), false);
  // the page does not show a withdrawn case
  const p = await casePage(c.id);
  assert.doesNotMatch(p.html, /<h1>Case: WITHDRAWN<\/h1>/);
  assert.match(p.html, /case_missing_field/);
  assert.deepEqual(storedCase(c.id), old, "nothing rewritten");
});

test("R-L5f B1: the README says a registration projected under a withdrawal makes it write nothing and answer 503, and the re-send keeps it", () => {
  assert.ok(README().includes("A registration projected between a withdrawal's read of the case and its write makes the withdrawal write nothing " +
    "and answer 503 `store_error`; sent again, it keeps the new registration."));
});
