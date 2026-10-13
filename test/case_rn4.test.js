// test/case_rn4.test.js — unit R-N4 (2026-10-13): the last words pass on
// the withdrawal path, from the re-review of R-N3 at 5e24fec:
//   R1  no response from the withdrawal handler says "nothing was withdrawn"
//       or claims the state of the listing unless this request confirmed
//       it: every such tail is "This request wrote nothing. A tape digest
//       listed by an earlier withdrawal request stays listed.", and the
//       listing's own refusal says the listing could not be confirmed;
//   R3  the root write that fails says the record may not have been written;
//   R4  the offline receipt check returns {signature_ok, reason}, never ok;
//   R6  the sealer's window: runs to cover 30 entries hourly and daily;
//   R7  "withdrawn by another request".
// The setup below is test/case_rn3.test.js's (its header there).
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rn4");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rn4");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rn4");
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
  await H.handleCaseCommit(req("case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 })), res, { now, ...extra });
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
const sealerRun = (dt = 60000) => S.anchorPending({ now: REVEAL_AT + 3600000 + dt, keyDocument: DOC });
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
const withdrawnCommitmentPath = (tapeSha256) => `withdrawn_commitments/${sha(Buffer.from(tapeSha256, "hex"))}.json`;


// =============================================================================
// UNIT R-N4
// =============================================================================

// A withdrawal whose root write loses, after its listing is confirmed, to
// the case `seedWith` writes while the listing goes out (test/case_rn3.test.js).
async function lostAfterListing(scope, seedWith) {
  const c = await committedCase(scope);
  const listing = withdrawnCommitmentPath(c.b.tape_sha256);
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${listing}`),
    async () => gh.seed(PINS, C.casePath(c.id), seedWith(c, storedCase(c.id)), { keepHistory: true }),
    () => withdraw(c.id, c.b),
  );
  assert.equal(r.fired, true);
  assert.equal(gh.has(PINS, listing), true, "the listing stands");
  return { c, w: r.out };
}
// Every case here holds the same two fixture tapes, so a listing left by one
// case's withdrawal refuses the next case's reveal: forgotten before one.
function forgetListings() {
  for (const p of [...gh.repos.get(PINS).keys()]) if (p.startsWith("withdrawn_commitments/")) gh.repos.get(PINS).delete(p);
}
// A withdrawal that loses to a reveal sealing the case after it took the
// lock and before it listed (test/case_rn3.test.js, N1).
async function sealedFirst(scope) {
  const c = await committedCase(scope);
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${USAGE}/contents/${H._internal.caseLockPath(c.id)}`),
    () => reveal(c),
    () => withdraw(c.id, c.b, { now: REVEAL_AT + 1000 }),
  );
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body).slice(0, 200));
  assert.equal(r.out.body.error_code, "case_sealed");
  return { c, w: r.out };
}

// R1: the tail of every refusal that wrote nothing, exactly; the listing's
// own refusal; R3 and R7, the words after a confirmed listing.
const TAIL = "This request wrote nothing. A tape digest listed by an earlier withdrawal request stays listed.";
const LISTING_UNCONFIRMED = "The tape listing could not be confirmed, so this request went no further. Send the same withdrawal again.";
const MAY_NOT_BE_WRITTEN = "The withdrawal record may not have been written. Your tape digest is already listed, so this service will not compare " +
  "that tape. Send the same withdrawal again to finish or to confirm.";
const LOST_TO_ANOTHER = "The withdrawal record was not written by this request: the case was withdrawn by another request while it ran. " +
  "Your tape digest is listed, so this service will not compare that tape.";
const NOTHING = /nothing was withdrawn/;
// follow-up f1: a lock write that failed may have landed, so the lock's own
// refusal claims only the case record
const LOCK_TAIL = "This request wrote nothing to the case record. Try again shortly.";

test("R-N4 R1 (b): the listing lands, a reveal seals first, the same withdrawal is sent again: the second body ends with the tail and never says 'nothing was withdrawn'", async () => {
  const { c, w } = await sealedFirst("RN4 sealed first, again");
  assert.doesNotMatch(JSON.stringify(w.body), NOTHING);
  const again = await withdraw(c.id, c.b, { now: REVEAL_AT + 5000 });
  assert.deepEqual([again.status, again.body.error_code], [409, "case_sealed"], JSON.stringify(again.body));
  assert.ok(again.body.error.endsWith(`. ${TAIL}`), again.body.error);
  assert.doesNotMatch(JSON.stringify(again.body), NOTHING);
  assert.equal(has(again.body, "tape_listed"), false, "this request confirmed no listing");
});

test("R-N4 R1 (a): the listing lands, the root write fails, the deadline passes, the same withdrawal is sent again: the second body ends with the tail and never says 'nothing was withdrawn'; the README says when a listing stands and what sending again does", async () => {
  const c = await committedCase("RN4 root fails, then expired");
  gh.forceFailure(PINS, C.casePath(c.id), 1, 502);
  const w = await withdraw(c.id, c.b);
  assert.deepEqual([w.status, w.body.error_code, w.body.error, w.body.tape_listed], [503, "store_error", MAY_NOT_BE_WRITTEN, true], JSON.stringify(w.body));
  assert.equal(gh.has(PINS, withdrawnCommitmentPath(c.b.tape_sha256)), true);
  const again = await withdraw(c.id, c.b, { now: Date.parse(DEADLINE) + 1000 });
  assert.deepEqual([again.status, again.body.error_code], [409, "expired"], JSON.stringify(again.body));
  assert.ok(again.body.error.endsWith(`. ${TAIL}`), again.body.error);
  assert.doesNotMatch(JSON.stringify(again.body), NOTHING);
  // R2: every sentence holds in every state
  const readme = fs.readFileSync(path.join(__dirname, "..", "README.md"), "utf8").replace(/\s+/g, " ");
  for (const s of ["whenever a withdrawal request gets as far as the listing and then does not finish",
    "finishes it only if the case can still be withdrawn",
    "is repaired only by the withdrawer sending the withdrawal again, and until then the tape is not refused",
    "A listing only ever refuses."]) {
    assert.ok(readme.includes(s), s);
  }
});

test("R-N4 R1 sweep: every refusal the withdrawal handler gives, first request and second, never says 'nothing was withdrawn'; one that confirmed no listing claims none and ends with the tail", async (t) => {
  const out = [];
  // kind: "tail" (wrote nothing; ends with the tail), "listing" (the listing
  // not confirmed), "listed" (this request confirmed the listing), "plain"
  // (refused before the case is read: method, body, no such case)
  // the sweep opens some thirty cases with one open key: a fresh budget and
  // a fresh day's open quota for each step (lib/_ratelimit.js, ~30 calls per
  // key per window; THE OPEN QUOTA, twenty a day)
  const ratelimit = require("../lib/_ratelimit.js");
  const drive = async (label, kind, status, code, run) => {
    ratelimit.setStore(null);
    const usage = gh.repos.get(USAGE) || new Map();
    for (const p of [...usage.keys()]) if (p.startsWith("case_opens/")) usage.delete(p);
    const r = await run();
    out.push({ label, kind, r });
    assert.deepEqual([r.status, r.body.error_code], [status, code], `${label}: ${JSON.stringify(r.body).slice(0, 300)}`);
  };
  const raw = async (request) => {
    const res = makeRes();
    await H.handleCaseWithdraw(request, res, { now: NOW + 2000, env: KEYS, keyDocument: DOC });
    return { status: res._status, body: parsed(res) };
  };
  const attemptOf = (k) => ({ ...k, reveal_attempts: [{ event: "attempt",
    commitments: { a: k.commitments.a.commitment_sha256, b: k.commitments.b.commitment_sha256 }, input_sha256: "e".repeat(64), at: C.utcSeconds(NOW + 1000) }] });
  const lockPath = (id) => H._internal.caseLockPath(id);

  // before the case is read
  await drive("method", "plain", 405, "method_not_allowed", () => raw(makeReq({ method: "GET", query: { op: "case-withdraw" }, headers: { "x-forwarded-for": nextIp() } })));
  await drive("body", "plain", 400, "malformed_field",
    () => raw(req("case-withdraw", { case_id: "not hex", role: "b", tape_sha256: "a".repeat(64), salt: "b".repeat(64) })));
  await drive("no such case", "plain", 404, "case_not_found", () => withdraw(sha("RN4 no such case"), { role: "b", tape_sha256: "a".repeat(64), salt: C.newSalt() }));

  // 1. the case
  const c1 = await committedCase("RN4 sweep case read");
  gh.forceGetFailure(PINS, C.casePath(c1.id), 1, 503);
  await drive("case read", "tail", 503, "store_unreachable", () => withdraw(c1.id, c1.b));
  const c2 = await committedCase("RN4 sweep case junk");
  gh.seed(PINS, C.casePath(c2.id), { not: "a case" });
  await drive("case junk", "tail", 503, "case_record_unreadable", () => withdraw(c2.id, c2.b));
  forgetListings();
  const sealed = await sealedCase("RN4 sweep sealed");
  await drive("sealed", "tail", 409, "case_sealed", () => withdraw(sealed.id, sealed.b, { now: REVEAL_AT + 5000 }));
  const gone = await committedCase("RN4 sweep withdrawn");
  assert.equal((await withdraw(gone.id, gone.b)).status, 201);
  await drive("withdrawn, the other role", "tail", 409, "case_withdrawn", () => withdraw(gone.id, gone.a, { now: NOW + 3000 }));
  const tried = await committedCase("RN4 sweep attempted");
  gh.seed(PINS, C.casePath(tried.id), attemptOf(storedCase(tried.id)), { keepHistory: true });
  await drive("attempted", "tail", 409, "reveal_attempted", () => withdraw(tried.id, tried.b));
  const late = await committedCase("RN4 sweep expired");
  await drive("expired", "tail", 409, "expired", () => withdraw(late.id, late.b, { now: Date.parse(DEADLINE) + 1000 }));

  // 2. the registration files, 3. the proof, 4. the signer and the record
  const r1 = await committedCase("RN4 sweep reg read");
  gh.forceGetFailure(PINS, C.registrationPath(r1.id, "a"), 1, 503);
  await drive("registration read", "tail", 503, "store_unreachable", () => withdraw(r1.id, r1.b));
  const r2 = await committedCase("RN4 sweep reg junk");
  gh.seed(PINS, C.registrationPath(r2.id, "b"), { not: "a registration" });
  await drive("registration junk", "tail", 503, "registration_record_unreadable", () => withdraw(r2.id, r2.b));
  const r3 = await committedCase("RN4 sweep reg missing");
  gh.repos.get(PINS).delete(C.registrationPath(r3.id, "a"));
  await drive("registration missing", "tail", 503, "case_record_inconsistent", () => withdraw(r3.id, r3.b));
  const p1 = await committedCase("RN4 sweep proof");
  await drive("proof", "tail", 403, "withdraw_unauthorized", () => withdraw(p1.id, p1.b, { salt: C.newSalt() }));
  const s1 = await committedCase("RN4 sweep signer");
  await drive("signer", "tail", 503, "signer_unavailable", () => withdraw(s1.id, s1.b, { env: {} }));
  const i1 = await committedCase("RN4 sweep record");
  t.mock.method(S, "withdrawnRecord", () => { throw new C.CaseError("malformed_field", "withdrawal", "a record its own schema refuses"); });
  await drive("record", "tail", 500, "internal_error", () => withdraw(i1.id, i1.b));
  S.withdrawnRecord.mock.restore();

  // 5. the lock
  const l1 = await committedCase("RN4 sweep busy");
  gh.seed(USAGE, lockPath(l1.id), { kind: "case-lock", v: 1, case_id: l1.id, holder: "someone-else", op: "commit", acquired_at: C.utcSeconds(NOW),
    expires_at: new Date(NOW + 600000).toISOString(), state: "held" });
  await drive("lock busy", "tail", 503, "case_busy", () => withdraw(l1.id, l1.b));
  const l2 = await committedCase("RN4 sweep lock junk");
  gh.seed(USAGE, lockPath(l2.id), { not: "a lock" });
  await drive("lock junk", "tail", 503, "case_lock_unreadable", () => withdraw(l2.id, l2.b));
  const l3 = await committedCase("RN4 sweep lock read");
  gh.forceGetFailure(USAGE, lockPath(l3.id), 1, 503);
  await drive("lock read", "lock", 503, "case_lock_unreachable", () => withdraw(l3.id, l3.b));

  // 5a. the listing
  const n1 = await committedCase("RN4 sweep listing");
  gh.forceFailure(PINS, withdrawnCommitmentPath(n1.b.tape_sha256), 1, 502);
  await drive("listing", "listing", 503, "withdrawn_commitment_unconfirmed", () => withdraw(n1.id, n1.b));

  // after the listing is confirmed
  const f1 = await committedCase("RN4 sweep root fails");
  gh.forceFailure(PINS, C.casePath(f1.id), 1, 502);
  await drive("root fails", "listed", 503, "store_error", () => withdraw(f1.id, f1.b));
  assert.equal(out[out.length - 1].r.body.error, MAY_NOT_BE_WRITTEN, "R3");
  const moved = await lostAfterListing("RN4 sweep moved", () => ({ not: "a case" }));
  await drive("moved", "listed", 503, "store_error", async () => moved.w);
  forgetListings();
  const first = await sealedFirst("RN4 sweep sealed first");
  await drive("sealed first", "listed", 409, "case_sealed", async () => first.w);
  const signer = S.loadCaseSigner(KEYS, { keyDocument: DOC });
  const byA = await lostAfterListing("RN4 sweep lost to a", (c, k) => S.withdrawnRecord(k, { role: "a", at: C.utcSeconds(NOW + 1000), salt: c.a.salt }, signer));
  await drive("lost to another", "listed", 409, "case_withdrawn", async () => byA.w);
  assert.equal(byA.w.body.error, LOST_TO_ANOTHER, "R7");
  const lostTried = await lostAfterListing("RN4 sweep lost to attempt", (c, k) => attemptOf(k));
  await drive("lost to an attempt", "listed", 409, "reveal_attempted", async () => lostTried.w);
  const lostLate = await lostAfterListing("RN4 sweep lost to deadline", (c, k) => ({ ...k, deadline: C.utcSeconds(NOW + 1000) }));
  await drive("lost to a deadline", "listed", 409, "expired", async () => lostLate.w);

  // the second request
  await drive("again: sealed first", "tail", 409, "case_sealed", () => withdraw(first.c.id, first.c.b, { now: REVEAL_AT + 5000 }));
  await drive("again: root failed, then expired", "tail", 409, "expired", () => withdraw(f1.id, f1.b, { now: Date.parse(DEADLINE) + 1000 }));
  await drive("again: lost to another", "tail", 409, "case_withdrawn", () => withdraw(byA.c.id, byA.c.b, { now: NOW + 5000 }));
  await drive("again: lost to an attempt", "tail", 409, "reveal_attempted", () => withdraw(lostTried.c.id, lostTried.c.b, { now: NOW + 5000 }));
  await drive("again: lost to a deadline", "tail", 409, "expired", () => withdraw(lostLate.c.id, lostLate.c.b, { now: NOW + 5000 }));
  const rt = await committedCase("RN4 sweep retry unconfirmed");
  assert.equal((await withdraw(rt.id, rt.b)).status, 201);
  const rtl = withdrawnCommitmentPath(rt.b.tape_sha256);
  gh.forceConflict(PINS, rtl, 1);
  gh.forceGetFailure(PINS, rtl, 2, 503);
  await drive("again: withdrawn, listing unconfirmed", "plain", 503, "withdrawn_commitment_unconfirmed", () => withdraw(rt.id, rt.b, { now: NOW + 5000 }));

  for (const { label, kind, r } of out) {
    const text = JSON.stringify(r.body);
    assert.doesNotMatch(text, NOTHING, label);
    if (kind !== "listed") {
      assert.doesNotMatch(text, /Your tape digest is (already )?listed/, `${label}: claims no listing it did not confirm`);
      assert.equal(has(r.body, "tape_listed"), false, label);
    }
    if (kind === "tail") assert.ok(r.body.error.endsWith(`. ${TAIL}`), `${label}: ${r.body.error}`);
    if (kind === "listing") assert.equal(r.body.error, LISTING_UNCONFIRMED, label);
    if (kind === "lock") assert.ok(r.body.error.endsWith(`. ${LOCK_TAIL}`), `${label}: ${r.body.error}`);
  }
  assert.ok(out.length >= 30, `driven: ${out.length}`);
});

test("R-N4 R6: the sealer's window, 30 entries five a run: an hourly run reads every entry within 12 runs and a daily run within 28, from every start time sampled, and some start needs all of them; the comment and the README say so", () => {
  const W = S._internal.rotatingWindow;
  const ids = Array.from({ length: 30 }, (_, i) => `id-${i}`);
  const runsToCover = (period, t0) => {
    const seen = new Set();
    for (let k = 0; k < 1000; k += 1) {
      for (const x of W(ids, 5, t0 + k * period)) seen.add(x);
      if (seen.size === ids.length) return k + 1;
    }
    return Infinity;
  };
  const t0 = Date.parse("2026-10-13T00:00:00Z");
  for (const [period, bound, worstAt] of [[3600000, 12, t0 + 997], [86400000, 28, t0]]) {
    assert.equal(runsToCover(period, worstAt), bound, `${period / 60000} minutes: this start needs all ${bound}`);
    let most = 0;
    for (let i = 0; i < 3000; i += 1) most = Math.max(most, runsToCover(period, t0 + i * 60013));
    assert.ok(most <= bound, `${period / 60000} minutes: ${most} runs`);
  }
  const src = fs.readFileSync(path.join(__dirname, "..", "lib", "_case_seal.js"), "utf8").replace(/\s*\/\/\s*/g, " ");
  const readme = fs.readFileSync(path.join(__dirname, "..", "README.md"), "utf8").replace(/\s+/g, " ");
  for (const [where, text] of [["the comment", src], ["the README", readme]]) {
    assert.ok(text.includes("an hourly run reads every entry within 12 runs and a daily run within 28"), where);
  }
});

// =============================================================================
// MUST-FAIL GAP (unit R-N4): the mutants the pass over the lines R-N4 changed
// left alive, each caught here
// =============================================================================

test("MUST-FAIL GAP (W03-W07): the shared readers and the lock keep every other handler's tail as it was: '; ' or ', and ' before a clause", async () => {
  // the commit's lock: busy (the default joiner) and unreachable (", and ")
  const id = await openCase("RN4 gap commit lock");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  gh.seed(USAGE, H._internal.caseLockPath(id), { kind: "case-lock", v: 1, case_id: id, holder: "someone-else", op: "commit",
    acquired_at: C.utcSeconds(NOW), expires_at: new Date(NOW + 600000).toISOString(), state: "held" });
  const busy = await commit(id, a);
  assert.equal(busy.body.error,
    "another request holds this case's lock (a registration or a withdrawal is being written); try again shortly; nothing was registered");
  gh.forceGetFailure(USAGE, H._internal.caseLockPath(id), 1, 503);
  const unreachable = await commit(id, a);
  assert.equal(unreachable.body.error, "this case's lock could not be read or written; this is not a 'no', and nothing was registered");
  // the reference's case read and registration read (", and ")
  const c = await sealedCase("RN4 gap reference reads");
  gh.forceGetFailure(PINS, C.casePath(c.id), 1, 503);
  const caseRead = await reference(c);
  assert.deepEqual([caseRead.status, caseRead.body.error], [503, "the case record could not be read; this is not a 'no', and no row was written"]);
  gh.forceGetFailure(PINS, C.registrationPath(c.id, "a"), 1, 503);
  const regRead = await reference(c);
  assert.deepEqual([regRead.status, regRead.body.error], [503, "a registration record could not be read; this is not a 'no', and no row was written"],
    JSON.stringify(regRead.body));
});

test("MUST-FAIL GAP (W14): the listing's own refusal names its case", async () => {
  const c = await committedCase("RN4 gap listing case id");
  gh.forceFailure(PINS, withdrawnCommitmentPath(c.b.tape_sha256), 1, 502);
  const w = await withdraw(c.id, c.b);
  assert.deepEqual([w.status, w.body.error_code, w.body.error, w.body.case_id], [503, "withdrawn_commitment_unconfirmed", LISTING_UNCONFIRMED, c.id]);
});

// =============================================================================
// THE FOLLOW-UPS FROM THE LAST READ OF R-N4 (f1-f7)
// =============================================================================

test("f1: a withdrawal whose lock could not be read or written (a write that may have landed) ends 'This request wrote nothing to the case record. Try again shortly.'", async () => {
  const w1 = await committedCase("f1 lock write");
  gh.forceFailure(USAGE, H._internal.caseLockPath(w1.id), 1, 502);
  const a = await withdraw(w1.id, w1.b);
  assert.deepEqual([a.status, a.body.error_code], [503, "case_lock_unreachable"], JSON.stringify(a.body));
  assert.equal(a.body.error, `this case's lock could not be read or written; this is not a 'no'. ${LOCK_TAIL}`);
  const w2 = await committedCase("f1 lock read");
  gh.forceGetFailure(USAGE, H._internal.caseLockPath(w2.id), 1, 503);
  const b = await withdraw(w2.id, w2.b);
  assert.equal(b.body.error, `this case's lock could not be read or written; this is not a 'no'. ${LOCK_TAIL}`);
  assert.doesNotMatch(a.body.error + b.body.error, /A tape digest listed by an earlier/);
});

test("f2, f3: the README says the tape is refused usually as 409 consent_withdrawn, that an earlier check can refuse first and an unreadable listing is 503 consent_unreadable, and that a missing listing leaves the tape unrefused on account of this case", () => {
  const readme = fs.readFileSync(path.join(__dirname, "..", "README.md"), "utf8").replace(/\s+/g, " ");
  for (const s of ["refuse that tape, usually as 409 `consent_withdrawn`",
    "An earlier check can refuse first (a sealed case's reveal is `not_committed`)",
    "a listing that cannot be read is 503 `consent_unreadable`",
    "and until then the tape is not refused on account of this case (another case's withdrawal may have listed the same digest)"]) {
    assert.ok(readme.includes(s), s);
  }
});

test("f4: the withdrawer's retry on a WITHDRAWN case whose registration cannot be read (a read failure, not an absence) is 503 'The case is withdrawn. This request could not finish checking it. Send the same withdrawal again.'", async () => {
  const c = await committedCase("f4 retry read fails");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  gh.forceGetFailure(PINS, C.registrationPath(c.id, "b"), 1, 503);
  const r = await withdraw(c.id, c.b, { now: NOW + 5000 });
  assert.deepEqual([r.status, r.body.error_code, r.body.error, r.body.case_id],
    [503, "store_unreachable", "The case is withdrawn. This request could not finish checking it. Send the same withdrawal again.", c.id], JSON.stringify(r.body));
  // sent again once the read works: 200, the record as it stands
  assert.equal((await withdraw(c.id, c.b, { now: NOW + 6000 })).status, 200);
});

test("f6: a reveal_attempts list holding no attempt event does not throw: the case is still refused as reveal_attempted, with no attempt time", () => {
  const ws = H._internal.withdrawStanding;
  const kase = { status: "COMMITTED", deadline: DEADLINE, reveal_attempts: [{ event: "failure", reason: "seal_write_failed", at: C.utcSeconds(NOW) }] };
  const r = ws(kase, NOW, "c".repeat(64));
  assert.deepEqual([r.status, r.code, r.extra.reveal_attempt_at], [409, "reveal_attempted", null]);
  assert.deepEqual([ws({ ...kase, reveal_attempts: [] }, NOW, "c".repeat(64)).code], ["reveal_attempted"]);
});

test("f7: a WITHDRAWN case whose listing is missing: ?op=reconcile compares the tape (not refused on account of this case) until the withdrawer sends the withdrawal again, which writes the listing; then it is refused", async () => {
  const c = await committedCase("f7 listing missing");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const listing = withdrawnCommitmentPath(c.b.tape_sha256);
  gh.repos.get(PINS).delete(listing);
  const before = await reconcileCall(AGENT_TAPE, TOOL_TAPE);
  assert.equal(before.status, 200, JSON.stringify(before.body).slice(0, 300));
  // someone else sending the withdrawal does not repair it
  const other = await withdraw(c.id, c.a, { now: NOW + 4000 });
  assert.deepEqual([other.status, other.body.error_code], [409, "case_withdrawn"]);
  assert.equal(gh.has(PINS, listing), false);
  const retry = await withdraw(c.id, c.b, { now: NOW + 5000 });
  assert.deepEqual([retry.status, retry.body.withdrawn_commitment], [200, "written"], JSON.stringify(retry.body));
  assert.deepEqual(gh.read(PINS, listing), { listed_at: C.utcSeconds(NOW + 5000) });
  const after = await reconcileCall(AGENT_TAPE, TOOL_TAPE);
  assert.deepEqual([after.status, after.body.error_code], [409, "consent_withdrawn"]);
});
