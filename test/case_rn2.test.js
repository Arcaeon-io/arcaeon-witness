// test/case_rn2.test.js — unit R-N2 (2026-10-13): fixes from the second
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
// the refusal names the requester by a `role` field. (The withdrawn-tape
// listing B1, M1 and M2 were about was removed in unit R-L, L1, with its tests.)
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0091:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rn2");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rn2");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rn2");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0091" });

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
// The race lost after the write (the commit's lease ran out and the
// withdrawal took it over), the removal refused when `deleteFails`.
async function lostRace(scope, { deleteFails = false } = {}) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const rpath = C.registrationPath(id, "b");
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

// =============================================================================
// UNIT R-N2
// =============================================================================

test("R-N2 B1: the marker reads its path back before it answers \"existing\": a conflict with no file there is a failure, a file there is existing", async () => {
  const c = await committedCase("RN2 marker read back");
  gh.forceConflict(PINS, C.withdrawnMarkerPath(c.id), 4);
  const w = await withdraw(c.id, c.b);
  assert.equal(w.status, 201, JSON.stringify(w.body));
  assert.equal(w.body.marker, "failed", "no file there");
  assert.equal(await S.writeWithdrawnMarker(c.id, storedCase(c.id).withdrawal.at), "written");
  assert.equal(await S.writeWithdrawnMarker(c.id, storedCase(c.id).withdrawal.at), "existing", "a file there");
});

test("R-N2 M3: the sealer writes a failed withdrawn marker for a case with ONE registration file, a WITHDRAWN root and no pin", async () => {
  const id = await openCase("RN2 one registration");
  const a = party(id, "a", AGENT_TAPE);
  await register(id, a);
  gh.forceFailure(PINS, C.withdrawnMarkerPath(id), 1, 502);
  const w = await withdraw(id, a);
  assert.deepEqual([w.status, w.body.marker], [201, "failed"]);
  const run = await sealerRun();
  assert.deepEqual(gh.read(PINS, C.withdrawnMarkerPath(id)), { kind: "case-withdrawn-marker", v: 1, case_id: id, withdrawn_at: storedCase(id).withdrawal.at });
  const entry = run.withdrawn_repaired.find((e) => e.case_id === id);
  assert.ok(entry, JSON.stringify(run.withdrawn_repaired));
  assert.deepEqual([entry.marker, entry.kept, entry.removed], ["written", ["a"], []]);
  // an OPEN case with one registration is read and left alone
  const open = await openCase("RN2 one registration, open");
  await register(open, party(open, "a", AGENT_TAPE));
  const writes = gh.putLog.length;
  const again = await sealerRun(120000);
  assert.ok(!again.withdrawn_repaired.some((e) => e.case_id === open));
  assert.deepEqual(gh.putLog.slice(writes), []);
});

test("R-N2 m3: the commit walk goes on when the page is full, whether or not the host names a next page", async (t) => {
  const c = await sealedCase("RN2 full page");
  const { R, path: mp } = await revoke();
  const late = await sealedCase("RN2 full page, late");
  for (let i = 0; i < 105; i += 1) gh.addCommit(PINS, mp);
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    const r = await viaMock(url, o);
    return String(url).includes("/commits?") ? { ...r, headers: { get: () => null } } : r;
  };
  t.after(() => { global.fetch = viaMock; });
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  const a = await S.sealedRecordReason(storedCase(late.id), revokedDoc());
  assert.deepEqual([a.code, a.reason], ["signer_revoked", "pinned_at_or_after_revocation"], "R is the oldest, past the full page");
  assert.equal((await S.sealedRecordReason(storedCase(c.id), revokedDoc())).revoked[0].revoking_commit, R);
});

test("R-N2 m4, m5: the lease race says exactly what happened; the withdrawn refusal says the tapes are never decoded or hashed", async () => {
  const c = await committedCase("RN2 race words");
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(c.id)}`),
    () => withdraw(c.id, c.b, { now: REVEAL_AT - 1000 }),
    () => reveal(c),
  );
  assert.equal(r.out.body.error, "Refused. A withdrawal landed while this reveal was in progress. Nothing computed from the tapes is kept.");
  const d = await committedCase("RN2 refusal words");
  assert.equal((await withdraw(d.id, d.b)).status, 201);
  const w = await reveal(d, { body: ownOpening(d, "a") });
  assert.equal(w.status, 409);
  assert.match(w.body.error, /never decoded or hashed/);
  assert.doesNotMatch(w.body.error, /tapes are read|never read/);
});

test("R-N2 m6: a receipt naming a commit definitely off the published branch has its own reason; one whose branch cannot be read is could-not-look", async () => {
  const c = await committedCase("RN2 off branch");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const rr = (await reveal(c, { body: ownOpening(c, "a") })).body.refusal_receipt;
  const off = KD.serveOffBranch(gh, DOC, "4".repeat(40));
  assert.equal((await S.verifyRefusalReceipt({ ...rr, signed_under: { ...rr.signed_under, document_commit: off } }, DOC)).reason, "document_not_on_branch");
  S._internal.clearDocumentCache();
  gh.forceCompareFailure(1, 503, S.KEY_DOCUMENT_REPO);
  assert.equal((await S.verifyRefusalReceipt(rr, DOC)).reason, "document_unavailable");
  assert.deepEqual(await S.verifyRefusalReceipt(rr, DOC), { ok: true });
});

test("R-N2 m6: the README has a section on checking a refusal receipt, and tools/check_refusal_receipt.js checks one offline", async () => {
  const readme = fs.readFileSync(path.join(__dirname, "..", "README.md"), "utf8");
  assert.match(readme, /^#+ Checking a refusal receipt/m);
  assert.match(readme, /tools\/check_refusal_receipt\.js/);
  const tool = fs.readFileSync(path.join(__dirname, "..", "tools", "check_refusal_receipt.js"), "utf8");
  assert.ok(tool.split("\n").length < 80, "under 80 lines");
  // offline: the receipt and the named document, both files
  const c = await committedCase("RN2 offline check");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const rr = (await reveal(c, { body: ownOpening(c, "a") })).body.refusal_receipt;
  const { spawnSync } = require("node:child_process");
  const dir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "rn2-"));
  fs.writeFileSync(path.join(dir, "receipt.json"), JSON.stringify(rr));
  fs.writeFileSync(path.join(dir, "doc.json"), JSON.stringify(DOC));
  const run = (file, doc) => spawnSync(process.execPath, [path.join(__dirname, "..", "tools", "check_refusal_receipt.js"), file, "--document", doc], { encoding: "utf8" });
  // since unit R-N3 (N3) offline is partial: ok false, exit 3, and whether the signature holds
  const good = run(path.join(dir, "receipt.json"), path.join(dir, "doc.json"));
  assert.equal(good.status, 3, good.stdout + good.stderr);
  assert.deepEqual([JSON.parse(good.stdout).reason, JSON.parse(good.stdout).signature_ok, JSON.parse(good.stdout).signature_reason], ["offline_partial", true, null]);
  fs.writeFileSync(path.join(dir, "forged.json"), JSON.stringify({ ...rr, role: "b" }));
  const bad = run(path.join(dir, "forged.json"), path.join(dir, "doc.json"));
  assert.equal(bad.status, 3);
  assert.deepEqual([JSON.parse(bad.stdout).signature_ok, JSON.parse(bad.stdout).signature_reason], [false, "bad_signature"], "unit R-N4 (R4)");
  fs.writeFileSync(path.join(dir, "other.json"), JSON.stringify(KD.docWith(KD.entry(CASE_KEY))));
  const other = JSON.parse(run(path.join(dir, "receipt.json"), path.join(dir, "other.json")).stdout);
  assert.deepEqual([other.signature_ok, other.signature_reason], [false, "document_sha256_mismatch"], "another document (unit R-N4, R4)");
});

test("R-N2 m7: an unsigned withdrawal record is labelled 'withdrawal record, unsigned: not a record' and its sig_reason is never printed; the case still reads WITHDRAWN and the refusal does not depend on the signature", async () => {
  const c = await committedCase("RN2 unsigned withdrawal");
  const rec = S.withdrawnRecord(storedCase(c.id), { role: "b", at: C.utcSeconds(NOW + 2000), salt: c.b.salt },
    { ok: false, code: "case_key_unset", reason: "no case signing key is configured (WITNESS_CASE_SIGNER_KEY is not set)" });
  assert.equal(rec.sig, null, "fixture: unsigned, as an earlier build wrote one");
  gh.seed(PINS, C.casePath(c.id), rec, { keepHistory: true });
  const p = await casePage(c.id);
  assert.equal(p.status, 200);
  assert.match(p.html, /WITHDRAWN/);
  assert.ok(p.html.includes("withdrawal record, unsigned: not a record"));
  assert.ok(!p.html.includes("WITNESS_CASE_SIGNER_KEY") && !p.html.includes(rec.sig_reason), "never the sig_reason");
  const r = await reveal(c, { body: ownOpening(c, "a") });
  assert.deepEqual([r.status, r.body.error_code], [409, "case_withdrawn"]);
});

test("R-N2 m8 (since unit R-L, L3: after a signed repair note): the WITHDRAWN page says a registration shown to be written after the withdrawal is removed, and one whose order cannot be shown stays and does not stand", async () => {
  const c = await committedCase("RN2 note");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  assert.ok((await casePage(c.id)).html.includes(
    // (since unit R-L2, B1: a note records a removal decided)
    "A registration shown to be written after the withdrawal is removed only once a signed repair note says of it: a removal of this file was " +
    "recorded for registration_after_withdrawal. One whose order cannot be shown stays and does not stand."));
});

test("R-N2 m10: registration_recorded reports the file's real state on the projection path and on the abandoned branch", async () => {
  // the projection path: the case withdrawn while the registration was projected, and the file gone by then
  const id = await openCase("RN2 projection");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const rpath = C.registrationPath(id, "b");
  let puts = 0;
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(id)}`) && ++puts === 1,
    async () => {
      await withdraw(id, a, { now: NOW + 1500 });
      gh.repos.get(PINS).delete(rpath);
    },
    () => commit(id, b, NOW + 1000),
  );
  assert.deepEqual([r.out.status, r.out.body.error_code], [409, "case_withdrawn"], JSON.stringify(r.out.body));
  assert.equal(r.out.body.registration_recorded, false, "the file is not there");
  // the abandoned branch: another registration for the role landed first
  const id2 = await openCase("RN2 abandoned");
  const a2 = party(id2, "a", AGENT_TAPE);
  plantStamp(a2.commitment_sha256);
  const other = party(id2, "a", AGENT_TAPE);
  const rpath2 = C.registrationPath(id2, "a");
  const r2 = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath2}`),
    async () => {
      const body = C.validateRegistrationBody(REG.signedBody({ case_id: id2, role: "a", commitment_sha256: other.commitment_sha256 }));
      gh.seed(PINS, rpath2, C.registrationRecord({ case_id: id2, role: "a", commitment_sha256: other.commitment_sha256, registered_at: C.utcSeconds(NOW),
        stamp_commit: "a".repeat(40), stamped_at: "2026-10-10T07:45:00.123Z", key_id: body.key_id, verifier: body.verifier, sig: body.sig }));
      gh.forceConflict(PINS, rpath2, 1);
    },
    () => commit(id2, a2),
  );
  assert.equal(r2.out.status, 409, JSON.stringify(r2.out.body));
  assert.equal(r2.out.body.error_code, "role_already_committed");
  assert.equal(r2.out.body.registration_recorded, false, "this registration is not the one on file");
});

// =============================================================================
// UNIT R-N2: the must-fail pass's gaps
// =============================================================================

test("MUST-FAIL GAP (B03, B05): a create-only write that errors is failed, even when it may have landed; a conflict whose read-back fails is failed, never existing", async () => {
  const id = "c".repeat(64);
  const mpath = C.withdrawnMarkerPath(id);
  gh.forceConflict(PINS, mpath, 4);
  gh.forceGetFailure(PINS, mpath, 5, 503);
  assert.equal(await S.writeWithdrawnMarker(id, "2026-10-10T08:00:02Z"), "failed");
  // a write that errors (not a conflict) after it landed, on another path
  const id2 = "d".repeat(64);
  const mpath2 = C.withdrawnMarkerPath(id2);
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    if ((o && o.method) === "PUT" && String(url).includes(`/contents/${mpath2}`)) {
      await viaMock(url, o);
      return { ok: false, status: 502, json: async () => ({}), text: async () => "" };
    }
    return viaMock(url, o);
  };
  let landed;
  try {
    landed = await S.writeWithdrawnMarker(id2, "2026-10-10T08:00:02Z");
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(gh.has(PINS, mpath2), true, "fixture: it landed");
  assert.equal(landed, "failed", "an error is a failure");
});

test("MUST-FAIL GAP (C03, C11): the loaders' codes: a reconcile key the document does not list, and a carried document that does not read", async () => {
  assert.equal(S.loadReconcileSigner(KEYS, { keyDocument: KD.docWith(KD.entry(CASE_KEY)) }).code, "reconcile_key_unpublished");
  assert.equal(S.sealingDocument({ [S.DEPLOY_COMMIT_ENV]: "a".repeat(40) }, { keyDocument: { not: "a key document" } }).code, "carried_document_unreadable");
  assert.equal(S.sealingDocument({}, { keyDocument: DOC }).code, "deploy_commit_unknown");
  assert.equal(S.sealingDocument({ [S.DEPLOY_COMMIT_ENV]: "x" }, { keyDocument: DOC }).code, "deploy_commit_malformed");
  const c = await committedCase("RN2 gap unpublished reconcile");
  const r = await reveal(c, { keyDocument: KD.docWith(KD.entry(CASE_KEY)) });
  assert.deepEqual([r.status, r.body.error_code, r.body.reason], [503, "signer_unavailable", "reconcile_key_unpublished"]);
});

test("MUST-FAIL GAP (M08): a withdrawn case with one registration file and its marker is reported once by a run, marker present", async () => {
  const id = await openCase("RN2 gap one registration, marked");
  const a = party(id, "a", AGENT_TAPE);
  await register(id, a);
  assert.equal((await withdraw(id, a)).status, 201);
  const run = await sealerRun();
  const entries = run.withdrawn_repaired.filter((e) => e.case_id === id);
  assert.equal(entries.length, 1, JSON.stringify(entries));
  assert.equal(entries[0].marker, "present");
});

test("MUST-FAIL GAP (L07, L08): the marker tool's walk goes on after a full page with no next page named, to the page after it", async (t) => {
  const revokedAt = (note) => KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11", note }), KD.reconcileEntry(RECEIPT_KEY));
  const first = KD.serve(gh, revokedAt("revoked, 0"));
  for (let i = 1; i <= 100; i += 1) KD.serve(gh, revokedAt(`revoked, ${i}`));
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    const r = await viaMock(url, o);
    return String(url).includes("/commits?") ? { ...r, headers: { get: () => null } } : r;
  };
  t.after(() => { global.fetch = viaMock; });
  const out = await TOOL.recordRevocation({ keyId: KD.keyIdOf(CASE_KEY), currentDocument: revokedAt("revoked, 100") });
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(out.marker.revoked_in_commit, first);
});

test("MUST-FAIL GAP (R02, R04): a receipt whose commit the repository does not show, or whose document cannot be fetched, is could-not-look, never definitely off the branch", async () => {
  const c = await committedCase("RN2 gap could not look");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const rr = (await reveal(c, { body: ownOpening(c, "a") })).body.refusal_receipt;
  assert.equal((await S.verifyRefusalReceipt({ ...rr, signed_under: { ...rr.signed_under, document_commit: "6".repeat(40) } }, DOC)).reason, "document_unavailable");
  S._internal.clearDocumentCache();
  gh.forceRawFailure(1, 503, rr.signed_under.document_commit);
  assert.equal((await S.verifyRefusalReceipt(rr, DOC)).reason, "document_unavailable");
});

test("MUST-FAIL GAP (R10, R11, R13, R15): the offline checker holds the receipt to its form, an ACTIVE RECONCILE key, and says what it did not check", async () => {
  const offline = require("../tools/check_refusal_receipt.js").offline;
  const at = C.utcSeconds(REVEAL_AT);
  const fields = { caseId: "c".repeat(64), at, role: "a", commitmentSha256: "d".repeat(64) };
  const good = S.refusalReceipt({ ...fields, signedUnder: KD.signedUnder(gh, DOC, at) }, S.loadReconcileSigner(KEYS, { keyDocument: DOC }));
  // unit R-N4 (R4): {signature_ok, reason}, never a key named ok
  assert.deepEqual(offline(good, DOC), { signature_ok: true, reason: null }, "the signature holds against the document supplied");
  assert.deepEqual(offline({ ...good, v: 2 }, DOC), { signature_ok: false, reason: "malformed_field" });
  const byCase = S.refusalReceipt({ ...fields, signedUnder: KD.signedUnder(gh, DOC, at) }, S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  assert.deepEqual(offline(byCase, DOC), { signature_ok: false, reason: "signer_unpublished" });
  const retired = KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY, { status: "retired" }));
  const underRetired = S.refusalReceipt({ ...fields, signedUnder: KD.signedUnder(gh, retired, at) }, S.loadReconcileSigner(KEYS, { keyDocument: DOC }));
  assert.deepEqual(offline(underRetired, retired), { signature_ok: false, reason: "signer_not_active" });
});

// The commit's projection, with `then` run as its first case-file PUT goes out.
async function projectionWith(scope, then) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const rpath = C.registrationPath(id, "b");
  let puts = 0;
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(id)}`) && ++puts === 1,
    () => then({ id, a, b, rpath }),
    () => commit(id, b, NOW + 1000),
  );
  return r.out;
}

test("MUST-FAIL GAP (T01, T03, T07): registration_recorded on the projection path: another key's file is not this registration, a read-back that fails is null, and a projection that fails reads the file too", async () => {
  const other = await projectionWith("RN2 gap other key", async ({ id, a, b, rpath }) => {
    await withdraw(id, a, { now: NOW + 1500 });
    const body = C.validateRegistrationBody(REG.signedBody({ case_id: id, role: "b", commitment_sha256: b.commitment_sha256 }, REG.KEYS.a));
    gh.seed(PINS, rpath, { ...gh.read(PINS, rpath), key_id: body.key_id, verifier: body.verifier, sig: body.sig });
  });
  assert.deepEqual([other.body.error_code, other.body.registration_recorded], ["case_withdrawn", false]);
  const unread = await projectionWith("RN2 gap read-back fails", async ({ id, a, rpath }) => {
    await withdraw(id, a, { now: NOW + 1500 });
    gh.forceGetFailure(PINS, rpath, 1, 503);
  });
  assert.deepEqual([unread.body.error_code, unread.body.registration_recorded], ["case_withdrawn", null]);
  const failed = await projectionWith("RN2 gap projection fails", async ({ id, rpath }) => {
    gh.repos.get(PINS).delete(rpath);
    gh.forceFailure(PINS, C.casePath(id), 1, 502);
  });
  assert.deepEqual([failed.status, failed.body.error_code, failed.body.registration_recorded], [503, "case_update_failed", false]);
});

test("MUST-FAIL GAP (T05): on the abandoned branch, a read-back that fails leaves registration_recorded unknown (null)", async () => {
  const id = await openCase("RN2 gap abandoned unread");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const rpath = C.registrationPath(id, "a");
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
    async () => {
      gh.forceConflict(PINS, rpath, 1);
      gh.forceGetFailure(PINS, rpath, 2, 503);
    },
    () => commit(id, a),
  );
  assert.deepEqual([r.out.status, r.out.body.error_code, r.out.body.registration_recorded], [503, "store_error", null], JSON.stringify(r.out.body));
});

test("MUST-FAIL GAP (B01): a create-only write abandoned because another writer created the path meanwhile reads that file back: existing, never written", async () => {
  const id = "e".repeat(64);
  const mpath = C.withdrawnMarkerPath(id);
  const viaMock = global.fetch;
  let fired = false;
  global.fetch = async (url, o) => {
    if (!fired && (o && o.method) === "PUT" && String(url).includes(`/contents/${mpath}`)) {
      fired = true;
      gh.seed(PINS, mpath, { kind: "case-withdrawn-marker", v: 1, case_id: id, withdrawn_at: "2026-10-10T08:00:01Z" });
      gh.forceConflict(PINS, mpath, 1);
    }
    return viaMock(url, o);
  };
  let got;
  try {
    got = await S.writeWithdrawnMarker(id, "2026-10-10T08:00:02Z");
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(fired, true);
  assert.equal(got, "existing");
  assert.equal(gh.read(PINS, mpath).withdrawn_at, "2026-10-10T08:00:01Z", "theirs, never written over");
});
