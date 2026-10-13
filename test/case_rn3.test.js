// test/case_rn3.test.js — unit R-N3 (2026-10-13): the words and edges from
// the re-review of R-N2 at 18ae018:
//   N1  a listing can stand with no withdrawn case (the listing is written
//       before the withdrawal record): its words say "or asked to", and every
//       refusal after a confirmed listing says the tape is listed;
//   N2  the retry's 503 on a withdrawn case says the case is withdrawn;
//   (unit R-L, L1: the withdrawn-tape listing is removed; the tests of N1,
//   N2, N4 and the listing gate are deleted with it)
//   N3  the offline receipt check is partial, never ok;
//   N4  the listing's field is listed_at;
//   N6  the sealer's window cannot stall under a fixed run period;
//   N8  the body audit reads 2xx bodies too, by path, and checks its child run.
// The setup below is test/case_rn2.test.js's. Its header follows.
//
// (unit R-N2:) fixes from the second
// reader's pass over R-N at bc99662 (DO NOT MERGE on two blockers):
//   B1  the withdrawn-tape listing failed open and the answer said it landed;
//   B2  four response bodies named environment variables;
//   M1  the joint reveal was not gated by the withdrawn list;
//   M2  the listing's refusal said more than is proven;
//   M3  a failed marker was rewritten only with both registration files;
//   m1-m10 the minor findings.
// The setup below is test/case_rn.test.js's. Its header follows.
//
// (unit R-N:) one signature rule
// everywhere, the refusal receipt made real, the reconcile bypass closed, and
// the withdrawal lease made honest. A second reader's pass over Design N and
// red-team fixes C, D and E found:
//
//   BLOCKER  an unsigned refusal receipt went out under a 409 that said it
//            was signed, and its sig_reason named environment variables to
//            an anonymous caller.
//   MAJOR    ?op=reconcile compared any two tapes, a withdrawn one included,
//            and returned a receipt signed by the reconcile key.
//   MAJOR    unsigned reference rows were counted as records, shown as "two
//            records", and written when the signer failed.
//   MAJOR    fix C: a failed DELETE left the file standing for good while the
//            answer said registration_recorded: false; a failed read after
//            the write left the registration standing on an assumption; the
//            lease clock was stale.
//   MINORS   publishedSignatureReason ignored key role; the refusal receipt
//            bound nothing; the race branch said the tapes were not read; a
//            retried withdrawal was 409; a failed marker was never
//            rewritten; fix E's trace lived only in git history; a reference
//            skipped the anchor-conflict check; the §2B todos asserted the
//            opposite of a closed decision.
//
// The binding decisions (N1-N4, C1-C3, E1, D1, T1) and the owner's four
// answers of 2026-10-13: C1 deletes only a registration whose creating
// commit comes after the withdrawal's; the lease race writes no log event;
// the refusal names the requester by a `role` field; the withdrawn tape is
// recorded at withdrawn_commitments/<sha256(tape_sha256)>.json.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0101:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rn3");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rn3");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rn3");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0101" });

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
function party(caseId, role, tape) {
  const salt = C.newSalt();
  const tape_sha256 = sha(tape);
  return { role, tape, tape_sha256, salt, commitment_sha256: C.commitmentSha256({ case_id: caseId, role, tape_sha256, salt }) };
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
async function commit(id, p, now = NOW, extra = {}) {
  const res = makeRes();
  // unit R-L (L3): the commit path signs a repair note before it removes anything
  await H.handleCaseCommit(req("case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 })), res,
    { now, env: KD.deployed(gh, KEYS, DOC), keyDocument: DOC, ...extra });
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
async function committedCase(scope) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
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
async function sealedCase(scope) {
  const c = await committedCase(scope);
  const r = await reveal(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  return c;
}
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0081", url: "https://second-operator.example/cases/0081" });
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
// The race lost after the write (the commit's lease ran out and the
// withdrawal took it over), the removal refused when `deleteFails`.
async function lostRace(scope, { deleteFails = false } = {}) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const rpath = REG.claimPath({ case_id: id, ...b }, b.key);
  const late = NOW + 1000 + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000;
  const viaMock = global.fetch;
  if (deleteFails) {
    global.fetch = async (url, o) => ((o && o.method) === "DELETE" ? { ok: false, status: 500, json: async () => ({}), text: async () => "" } : viaMock(url, o));
  }
  let r;
  try {
    r = await during(
      (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
      () => withdraw(id, a, { now: late }),
      () => commit(id, b, NOW + 1000),
    );
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body));
  assert.equal(r.out.body.error_code, "case_withdrawn", JSON.stringify(r.out.body));
  return { id, a, b, rpath, out: r.out.body };
}
const storedCase = (id) => gh.read(PINS, C.casePath(id));
const lockOf = (id) => gh.read(USAGE, H._internal.caseLockPath(id));
const logFiles = (id) => [...gh.repos.get(PINS).keys()].filter((p) => p.startsWith(`${C.caseLogDir(id)}/`)).sort();
const pinsText = () => [...gh.repos.get(PINS).values()].map((r) => r.content).join("\n");
const sealerRun = (dt = 60000) => S.anchorPending({ now: REVEAL_AT + 3600000 + dt, keyDocument: DOC, env: KD.deployed(gh, KEYS, DOC) });
// N2: the sha256 of the digest's 32 bytes, as a salt is kept (lib/_case.js saltSha256)
// The case key revoked (unit R-I): the current document, its marker, the tool.
const CASE_REVOKED = Object.freeze(KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11" }), KD.reconcileEntry(RECEIPT_KEY)));
const revokedDoc = () => CASE_REVOKED;
const TOOL = { recordRevocation: (...args) => require("../tools/record_key_revocation.js").recordRevocation(...args) };
const markerFor = (W) => ({ kind: "key-revocation", v: 1, key_id: KD.keyIdOf(CASE_KEY), key_fingerprint: S.keyFingerprint(CASE_KEY.verifier), revoked_in_commit: W });
async function revoke() {
  const W = KD.serve(gh, CASE_REVOKED);
  const out = await TOOL.recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: CASE_REVOKED, write: true });
  assert.equal(out.ok, true, JSON.stringify(out));
  return { W, R: out.commit, path: out.path };
}

// UNIT R-N3
// =============================================================================

// (unit R-L, L1: the listing N1, N2 and N4 were about is removed, with its
// tests; a withdrawal that loses after it took the lock ends with this tail)
const WROTE_NO_PINS = "This request wrote nothing to the pins repository.";

test("R-N3 N3: the offline receipt check is partial: it prints ok false, offline_partial, whether the signature holds against the supplied document, what it did not check, and exits 3; only the online check prints ok true and exits 0", async (t) => {
  const c = await committedCase("RN3 offline partial");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const rr = (await reveal(c, { body: ownOpening(c, "a") })).body.refusal_receipt;
  const { spawnSync } = require("node:child_process");
  const dir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "rn3-"));
  fs.writeFileSync(path.join(dir, "receipt.json"), JSON.stringify(rr));
  fs.writeFileSync(path.join(dir, "forged.json"), JSON.stringify({ ...rr, role: "b" }));
  fs.writeFileSync(path.join(dir, "doc.json"), JSON.stringify(DOC));
  const tool = path.join(__dirname, "..", "tools", "check_refusal_receipt.js");
  const offline = (file) => spawnSync(process.execPath, [tool, path.join(dir, file), "--document", path.join(dir, "doc.json")], { encoding: "utf8" });
  const notChecked = ["the document's commit is on the published branch", "the key is still listed, not revoked, in the current key document"];
  const good = offline("receipt.json");
  assert.equal(good.status, 3, good.stdout + good.stderr);
  assert.deepEqual(JSON.parse(good.stdout), { ok: false, reason: "offline_partial", signature_ok: true, signature_reason: null, not_checked: notChecked });
  const forged = offline("forged.json");
  assert.equal(forged.status, 3);
  assert.deepEqual(JSON.parse(forged.stdout), { ok: false, reason: "offline_partial", signature_ok: false, signature_reason: "bad_signature", not_checked: notChecked });
  // online: the readers' own check decides; its answer is printed and sets the exit code
  const T = require("../tools/check_refusal_receipt.js");
  const run = async (answer) => {
    t.mock.method(S, "verifyRefusalReceipt", async () => answer);
    const lines = [];
    const write = process.stdout.write;
    process.stdout.write = (s) => { lines.push(String(s)); return true; };
    let code;
    try {
      code = await T.main([path.join(dir, "receipt.json")]);
    } finally {
      process.stdout.write = write;
      S.verifyRefusalReceipt.mock.restore();
    }
    return { code, out: JSON.parse(lines.join("")) };
  };
  assert.deepEqual(await run({ ok: true }), { code: 0, out: { ok: true } });
  assert.deepEqual(await run({ ok: false, reason: "signer_unlisted" }), { code: 1, out: { ok: false, reason: "signer_unlisted" } });
  // the header comment and the README say what offline proves, and what it does not
  const text = fs.readFileSync(tool, "utf8");
  const readme = fs.readFileSync(path.join(__dirname, "..", "README.md"), "utf8");
  for (const [where, s] of [["the tool", text], ["the README", readme]]) {
    assert.match(s.replace(/\s+/g, " ").replace(/\/\/ /g, ""), /proves the signature against the document you supplied and nothing about whether that document is the published one/, where);
  }
});

test("R-N3 N6: the sealer's window cannot read one slice forever under a fixed run period: hourly runs advance through 12 entries and through 30, five a run, and runs a minute apart do too", () => {
  const W = S._internal.rotatingWindow;
  const t0 = Date.parse("2026-10-13T00:00:00Z");
  const covered = (n, max, period, runs) => {
    const ids = Array.from({ length: n }, (_, i) => `id-${i}`);
    const seen = new Set();
    for (let k = 0; k < runs; k += 1) for (const x of W(ids, max, t0 + k * period)) seen.add(x);
    return seen.size;
  };
  assert.equal(covered(12, 5, 3600000, 24), 12, "hourly, 12 entries, within a day");
  assert.equal(covered(30, 5, 3600000, 48), 30, "hourly, 30 entries, within two days");
  assert.equal(covered(30, 5, 60000, 60), 30, "a minute apart, 30 entries, within an hour");
  assert.equal(covered(3, 1, 60000, 60), 3);
  // the rule is stated
  const src = fs.readFileSync(path.join(__dirname, "..", "lib", "_case_seal.js"), "utf8");
  assert.match(src, /THE WINDOW'S START \(unit R-N3, N6\)/);
});

test("R-N3 N8: a retried withdrawal's 200 never carries a stored sig_reason", async () => {
  const c = await committedCase("RN3 retry sig_reason");
  const rec = S.withdrawnRecord(storedCase(c.id), { role: "b", at: C.utcSeconds(NOW + 2000), salt: c.b.salt },
    { ok: false, code: "case_key_unset", reason: "no case signing key is configured (WITNESS_CASE_SIGNER_KEY is not set)" });
  gh.seed(PINS, C.casePath(c.id), rec, { keepHistory: true });
  const r = await withdraw(c.id, c.b, { now: NOW + 5000 });
  assert.equal(r.status, 200, JSON.stringify(r.body).slice(0, 300));
  assert.doesNotMatch(JSON.stringify(r.body), /WITNESS_|is not set/);
  assert.equal(has(r.body.case, "sig_reason"), false);
});

// =============================================================================
// MUST-FAIL GAP (unit R-N3): the mutants the first pass over the lines R-N3
// changed left alive, each caught here
// =============================================================================

// A withdrawal whose root write loses to the case `seedWith` writes while
// the root write goes out (since unit R-L, L1: there is no listing before it).
async function lostRootWrite(scope, seedWith) {
  const c = await committedCase(scope);
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(c.id)}`),
    async () => gh.seed(PINS, C.casePath(c.id), seedWith(c, storedCase(c.id)), { keepHistory: true }),
    () => withdraw(c.id, c.b),
  );
  assert.equal(r.fired, true);
  return { c, w: r.out };
}

test("MUST-FAIL GAP (H11-H15; since unit R-L, L1, no listing): a root write lost to another withdrawal, a reveal attempt or a deadline keeps the case's standing, says this request wrote nothing to the pins repository, and never says 'nothing was withdrawn'", async () => {
  const signer = S.loadCaseSigner(KEYS, { keyDocument: DOC });
  const byA = await lostRootWrite("RN3 gap lost to a withdrawal",
    (c, k) => S.withdrawnRecord(k, { role: "a", at: C.utcSeconds(NOW + 1000), salt: c.a.salt }, signer));
  assert.deepEqual([byA.w.status, byA.w.body.error_code, byA.w.body.status, byA.w.body.case_id],
    [409, "case_withdrawn", "WITHDRAWN", byA.c.id], JSON.stringify(byA.w.body));
  assert.equal(byA.w.body.error, `the case is already withdrawn. ${WROTE_NO_PINS}`);
  const tried = await lostRootWrite("RN3 gap lost to an attempt", (c, k) => ({ ...k, reveal_attempts: [{ event: "attempt",
    commitments: { a: k.commitments.a.commitment_sha256, b: k.commitments.b.commitment_sha256 }, input_sha256: "e".repeat(64), at: C.utcSeconds(NOW + 1000) }] }));
  assert.deepEqual([tried.w.status, tried.w.body.error_code, tried.w.body.status, tried.w.body.reveal_attempt_at], [409, "reveal_attempted", "COMMITTED", C.utcSeconds(NOW + 1000)],
    JSON.stringify(tried.w.body));
  assert.equal(tried.w.body.error, "a joint reveal of this case was attempted (the case records the attempt), and a case whose comparison was attempted " +
    `is not withdrawn by one role. ${WROTE_NO_PINS}`);
  // a root rewritten with an earlier deadline (only a write outside this
  // service moves a deadline) reads EXPIRED by the withdrawal's clock
  const late = await lostRootWrite("RN3 gap lost to a deadline", (c, k) => ({ ...k, deadline: C.utcSeconds(NOW + 1000) }));
  assert.deepEqual([late.w.status, late.w.body.error_code, late.w.body.status], [409, "expired", "EXPIRED"],
    JSON.stringify(late.w.body));
  assert.equal(late.w.body.error, "the case's deadline has passed by this service's clock, so it reads EXPIRED, and an expired case is not withdrawn. " +
    WROTE_NO_PINS);
  for (const b of [byA.w.body, tried.w.body, late.w.body]) {
    assert.doesNotMatch(JSON.stringify(b), /nothing was withdrawn|listed/);
    assert.equal(has(b, "tape_listed"), false);
  }
});

test("MUST-FAIL GAP (H06-H08; since unit R-L, L1, no listing): a root that moved to something unreadable while the withdrawal was written is 503 store_error, reason case_moved, in plain words", async () => {
  const lost = await lostRootWrite("RN3 gap case moved", () => ({ not: "a case" }));
  assert.deepEqual([lost.w.status, lost.w.body.error_code, lost.w.body.reason, lost.w.body.case_id, lost.w.body.error],
    [503, "store_error", "case_moved", lost.c.id,
      `the case moved while this withdrawal was written, and what it is now could not be read. ${WROTE_NO_PINS} Send the same withdrawal again.`],
    JSON.stringify(lost.w.body));
});

test("MUST-FAIL GAP (H21): the retry's 503 names its case; and a signed record's 200 shows the case exactly as stored", async () => {
  const c = await committedCase("RN3 gap retry body");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const again = await withdraw(c.id, c.b, { now: NOW + 4000 });
  assert.equal(again.status, 200);
  assert.deepEqual(again.body.case, storedCase(c.id), "signed: shown whole, sig_reason: null included");
  // (since unit R-L, L1: the retry's 503 is its registration read failing)
  gh.forceGetFailure(PINS, REG.pathOf(gh, c.id, "b"), 1, 503);
  const r = await withdraw(c.id, c.b, { now: NOW + 5000 });
  assert.deepEqual([r.status, r.body.error_code, r.body.case_id], [503, "store_unreachable", c.id], JSON.stringify(r.body));
});

test("MUST-FAIL GAP (S02, S03, S04, S07): the window's start: G is odd, so a period of 2^63 ms moves it; a clock that is not finite or not whole never throws; every millisecond counts", () => {
  const W = S._internal.rotatingWindow;
  assert.deepEqual([W(["a", "b"], 1, 0), W(["a", "b"], 1, 2 ** 63)], [["a"], ["b"]], "x = 2^63 * G mod 2^64 is 2^63 for an odd G");
  assert.deepEqual(W(["a", "b", "c"], 1, NaN), ["a"]);
  assert.deepEqual(W(["a", "b", "c"], 1, 60000.5), W(["a", "b", "c"], 1, 60000));
  const ten = Array.from({ length: 10 }, (_, i) => `id-${i}`);
  const t0 = Date.parse("2026-10-13T00:00:00Z");
  assert.notDeepEqual(W(ten, 1, t0), W(ten, 1, t0 + 30000), "half a minute turns the start by 0.309 of the list");
});

test("MUST-FAIL GAP (P02; since unit R-L, L1, no listing clause): the page of an attempt with no recorded completion says the same reveal, sent again before the deadline, seals it", async () => {
  const c = await committedCase("RN3 gap page attempt");
  const k = storedCase(c.id);
  gh.seed(PINS, C.casePath(c.id), { ...k, reveal_attempts: [{ event: "attempt",
    commitments: { a: k.commitments.a.commitment_sha256, b: k.commitments.b.commitment_sha256 }, input_sha256: "e".repeat(64), at: C.utcSeconds(NOW + 1000) }] },
    { keepHistory: true });
  const html = (await casePage(c.id)).html;
  assert.ok(html.includes("does not record that it completed"), html.slice(0, 400));
  assert.ok(html.includes("the same reveal, sent again before the deadline, seals it."));
  assert.equal(html.includes("listed as withdrawn"), false);
});

test("MUST-FAIL GAP (T05, T06, T09): the online check exits 0 only for ok: true itself; --document before the receipt is still the partial offline check; an unreadable receipt offline is signature_ok false", async (t) => {
  const T = require("../tools/check_refusal_receipt.js");
  const dir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "rn3gap-"));
  fs.writeFileSync(path.join(dir, "receipt.json"), JSON.stringify({ kind: "comparison_refused" }));
  fs.writeFileSync(path.join(dir, "doc.json"), JSON.stringify(DOC));
  fs.writeFileSync(path.join(dir, "garbled.json"), "{ not json");
  const lines = [];
  const write = process.stdout.write;
  process.stdout.write = (s) => { lines.push(String(s)); return true; };
  let online;
  let first;
  let firstOut;
  let garbled;
  let garbledOut;
  try {
    t.mock.method(S, "verifyRefusalReceipt", async () => ({ ok: "yes" }));
    online = await T.main([path.join(dir, "receipt.json")]);
    S.verifyRefusalReceipt.mock.restore();
    lines.length = 0;
    first = await T.main(["--document", path.join(dir, "doc.json"), path.join(dir, "receipt.json")]);
    firstOut = JSON.parse(lines.join(""));
    lines.length = 0;
    garbled = await T.main([path.join(dir, "garbled.json"), "--document", path.join(dir, "doc.json")]);
    garbledOut = JSON.parse(lines.join(""));
  } finally {
    process.stdout.write = write;
  }
  assert.equal(online, 1, "ok must be true itself");
  assert.equal(first, 3);
  assert.equal(firstOut.reason, "offline_partial");
  assert.equal(garbled, 3);
  assert.deepEqual([garbledOut.ok, garbledOut.reason, garbledOut.signature_ok, garbledOut.signature_reason], [false, "offline_partial", false, "unreadable"]);
});
