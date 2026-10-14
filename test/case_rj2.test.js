// test/case_rj2.test.js — unit R-J2 (2026-10-13): fixes from the second
// reader's pass over R-J at 64e6abf.
//   B2  the signed row sentence said the row is "listed by the case's next
//       pin", a future event stated as fact: version 3 claims only what the
//       row's commit records, and version 2 was never issued;
//   B1  every conflict was said to "hold another chain": worded by reason;
//   M1  a commit the host does not show yet read as off the branch;
//   M2  the page cache re-served "on this request" for sixty seconds;
//   n1-n8 the minor findings.
// The setup below is test/case_rj.test.js's (its header there).
// Unit R-PIN (2026-10-13) removed the anchor reader, the row commits, the
// sealer's row read-back and the page cache, and with them M2's tests, n1-n4,
// the anchored half of B1 and M1, and the gap tests of that code.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0071:case-test-";
for (const k of ["WITNESS_BATCH_SHADOW", "WITNESS_ADMIN_KEY", "WITNESS_CASE_OPERATOR_KEY", "WITNESS_CASE_SIGNER_KEY",
  "WITNESS_RECONCILE_SIGNER_KEY", "WITNESS_RECONCILE_VERIFIER", "WITNESS_LOG_SIGNER_KEY", "VERCEL_GIT_COMMIT_SHA"]) {
  delete process.env[k];
}

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const REG = require("./helpers/case_registration.js");
const KD = require("./helpers/key_document.js");
const store = require("../lib/_store.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const S = require("../lib/_case_seal.js");
const CP = require("../lib/_case_page.js");
const receipts = require("../lib/_reconcile_receipt.js");
const checkpoint = require("../lib/_checkpoint.js");
const stamp = require("../lib/_stamp.js");
const statusData = require("../lib/_status_data.js");
const reconcileFixtures = require("./fixtures/reconcile/cases.json");

const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const NOW = Date.parse("2026-10-10T08:00:00Z");
const DEADLINE = "2026-10-10T20:00:00Z";
const REVEAL_AT = Date.parse("2026-10-10T09:00:00Z");
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Throwaway keys, made here, written nowhere.
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rj2");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rj2");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rj2");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0071" });
const PINS_URL = `https://github.com/${PINS}`;

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
});
afterEach(() => {
  store._putRetry.sleep = realSleep;
  restore();
});

let ipSeq = 0;
function req(op, body, headers = {}) {
  ipSeq += 1;
  return makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": `10.97.${(ipSeq >> 8) & 255}.${ipSeq & 255}`, ...headers }, body });
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
async function committedCase(scope) {
  const o = makeRes();
  await H.handleCaseOpen(req("case-open", opening(scope), OPEN_AUTH), o, { now: NOW });
  assert.equal(o._status, 201, JSON.stringify(o._body));
  const id = o._body.case_id;
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  for (const p of [a, b]) {
    gh.seed(STAMPS, stamp.stampPath(p.commitment_sha256), { kind: "file-stamp", v: 1, sha256: p.commitment_sha256, size: C.COMMITMENT_BYTES_LENGTH, stamped_at: "2026-10-10T07:45:00.123Z" });
    const r = makeRes();
    await H.handleCaseCommit(req("case-commit", REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 })), r, { now: NOW });
    assert.equal(r._status, 201, JSON.stringify(r._body));
  }
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
async function reveal(c) {
  const res = makeRes();
  await H.handleCaseReveal(req("case-reveal", revealBody(c.id, c.a, c.b)), res, { now: REVEAL_AT, env: KD.deployed(gh, KEYS, DOC), keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
async function sealedCase(scope, { pinFails = false } = {}) {
  const c = await committedCase(scope);
  if (pinFails) gh.forceFailure(PINS, S.pinPaths(c.id).seq, 1, 502);
  const r = await reveal(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  return { ...c, r };
}
// A page view (unit R-PIN: no page cache, so every view reads).
async function casePage(id, { now = REVEAL_AT + 3600000, ip = null } = {}) {

  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": ip || `10.98.0.${(ipSeq += 1) & 255}` } }), res,
    { now, keyDocument: DOC, env: {} });
  return { status: res._status, html: String(res._body) };
}
const storedCase = (id) => gh.read(PINS, C.casePath(id));
const chainOf = (id) => S.caseChain(storedCase(id));
// The commit that wrote the sealed case file: the newest touching it.
const sealCommit = (id) => gh.commitsFor(PINS, C.casePath(id))[0].sha;
// Run `inner` when the first request whose URL includes `match` goes out,
// then let that request through.
function onFirstRequest(match, inner) {
  const viaMock = global.fetch;
  let fired = false;
  global.fetch = async (url, o) => {
    if (!fired && String(url).includes(match)) {
      fired = true;
      await inner();
    }
    return viaMock(url, o);
  };
  return () => { global.fetch = viaMock; };
}
// The case file rewritten in place, in its own commit (a swapped file).
function rewriteCase(id, rec) {
  const p = C.casePath(id);
  gh._repoMap(PINS).get(p).content = JSON.stringify(rec, null, 2) + "\n";
  return gh.addCommit(PINS, p, "mock: the case file rewritten");
}
// A pin for `chain` naming `caseCommit`, written over the case's one pin file.
function plantPin(id, chain, caseCommit) {
  const rec = { ...S._internal.pinRecord(id, chain, REVEAL_AT, caseCommit) };
  if (caseCommit === undefined) delete rec.case_commit;
  gh.seed(PINS, S.pinPaths(id).seq, rec);
  return rec;
}
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0051", url: "https://second-operator.example/cases/0051" });
async function reference(c, role = "a", ref = "row") {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: { ...XREF, reference: ref } }),
    res, { now: REVEAL_AT + 1800000, env: KD.deployedFor(gh, KEYS, DOC), keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
const rowPath = (id, n) => C.referencePath(id, n);
const caseText = (id) => gh._repoMap(PINS).get(C.casePath(id)).content;

const fs = require("node:fs");
const path = require("node:path");
const PAGE_SRC = () => fs.readFileSync(path.join(__dirname, "..", "lib", "_case_page.js"), "utf8");

// =============================================================================
// B2: the signed row sentence (version 3 here; version 4 since unit R-PIN)
// =============================================================================

const V3_NOTE = "This row has no pin of its own. It is recorded by the pins-repository commit that writes it. A later pin of the case may list " +
  "that commit. This row is anchored only if a pin that lists it is, and no anchoring is asserted here.";
const V2_NOTE = "This row has no pin of its own. It is recorded by the pins-repository commit that writes it and listed by the case's next " +
  "pin; it is anchored only when that pin is.";
const V4_NOTE = "This row has no pin of its own. It is recorded by the pins-repository commit that writes it, and no anchoring is asserted here.";

test("B2 (version 4 since unit R-PIN): the signed row carries the version-4 sentence and note_version 4, exactly; the 201 body names no row commit; the README records versions 2 and 3 as never issued", async () => {
  assert.equal(C.REFERENCE_ANCHOR_NOTE, V4_NOTE);
  assert.equal(C.REFERENCE_NOTE_VERSION, 4);
  const c = await sealedCase("RJ2 B2 row");
  const r = await reference(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  const stored = gh.read(PINS, rowPath(c.id, 1));
  assert.deepEqual([stored.anchor_note, stored.note_version], [V4_NOTE, 4]);
  assert.equal((await S.signedUnderReason(stored, "case", DOC)).code, "valid_under_document", "the sentence is under the signature");
  assert.equal(r.body.anchor_note, V4_NOTE);
  assert.equal(Object.prototype.hasOwnProperty.call(r.body, "row_commit_note"), false);
  const readme = fs.readFileSync(path.join(__dirname, "..", "README.md"), "utf8").replace(/\s+/g, " ");
  assert.ok(readme.includes(V4_NOTE), "the README quotes the sentence");
  assert.ok(readme.includes("Versions 2 and 3 of this sentence were never issued"));
  assert.ok(!readme.includes(V3_NOTE));
});

// The architect's ruling on unit R-SIG: note_version must equal 4; a row at
// version 3 keeps its own reading, and any other, or none, is malformed.
test("B2 (since unit R-SIG): a row carrying version 3 reads as row_note_v3; one carrying version 2, or no version, is malformed_field; none is counted", async () => {
  const { id } = await sealedCase("RJ2 B2 versions");
  const signer = S.loadCaseSigner(KEYS, { keyDocument: DOC });
  const good = S.referenceRow({ caseId: id, seq: 1, crossReference: XREF, recordedAt: "2026-10-10T10:00:00Z", appendedBy: "operator", signedUnder: KD.signedUnder(gh, DOC) }, signer);
  const v2 = { ...good, note_version: 2, anchor_note: V2_NOTE };
  // signed as written (since unit R-RVf3, 5c, a version-3 row reads
  // row_note_v3 only when its signature verifies)
  const { sig: _s, signed_by: _b, sig_reason: _r, ...v3body } = { ...good, note_version: 3, anchor_note: V3_NOTE }; // eslint-disable-line no-unused-vars
  const v3 = S.signRecord(v3body, signer);
  const { note_version: _n, ...none } = good;
  const v1 = C.validateReferenceRow(none);
  assert.equal(v1.code, "malformed_field");
  assert.match(v1.error, /note_version must be 4/);
  assert.equal(C.validateReferenceRow(v2).code, "malformed_field");
  assert.equal(C.validateReferenceRow(v3).code, "row_note_v3");
  for (const [row, reason] of [[v2, "reference_malformed_field"], [v3, "row_note_v3"], [none, "reference_malformed_field"]]) {
    gh.seed(PINS, rowPath(id, 1), row);
    const live = await S.liveRecords(storedCase(id), { keyDocument: DOC });
    assert.deepEqual([live.records, live.invalid], [1, [{ seq: 1, reason }]], reason);
  }
  gh.seed(PINS, rowPath(id, 1), good);
  assert.equal((await S.liveRecords(storedCase(id), { keyDocument: DOC })).records, 2, "control: version 4 counts");
});

// =============================================================================
// B1: a conflict is worded by its reason
// =============================================================================

const CONFLICT_WORDS = {
  pin_holds_another_chain: "the pin file under this case's namespace holds another chain",
  pin_at_its_commit_holds_another_chain: "the pin record, read at the commit that wrote it, holds another chain",
  pin_at_its_commit_not_json: "the pin record at the commit that wrote it could not be read as a pin",
};

test("B1: the page says 'holds another chain' only for the two *_holds_another_chain reasons (unit R-PIN: the pin file's and the pin record's at its commit); a record that is not JSON is said as what it is", async () => {
  const fixtures = {
    pin_holds_another_chain: async () => {
      const c = await sealedCase("RJ2 B1 pin file");
      const seq = S.pinPaths(c.id).seq;
      gh.seed(PINS, seq, { ...gh.read(PINS, seq), chain: sha("another chain") }, { keepHistory: true });
      return c;
    },
    pin_at_its_commit_holds_another_chain: async () => {
      const c = await sealedCase("RJ2 B1 at its commit");
      const seq = S.pinPaths(c.id).seq;
      const mine = gh.read(PINS, seq);
      gh.seed(PINS, seq, { ...mine, chain: sha("yet another chain") });
      gh._repoMap(PINS).get(seq).content = JSON.stringify(mine, null, 2) + "\n";
      gh.addCommit(PINS, seq, "mock: put back");
      return c;
    },
    pin_at_its_commit_not_json: async () => {
      const c = await sealedCase("RJ2 B1 at its commit, text");
      gh.commitsFor(PINS, S.pinPaths(c.id).seq).slice(-1)[0].content = "not json\n";
      return c;
    },
  };
  for (const [reason, make] of Object.entries(fixtures)) {
    const c = await make();
    S._internal.clearCommitFiles();
    const st = await S.pinState(c.id, storedCase(c.id));
    assert.deepEqual([st.pin, st.reason], ["conflict", reason], reason);
    const html = (await casePage(c.id)).html;
    assert.ok(html.includes(`conflict: ${esc(CONFLICT_WORDS[reason])} (${reason}).`), `${reason}: ${html.slice(html.indexOf("conflict:"), html.indexOf("conflict:") + 200)}`);
    if (!reason.endsWith("_holds_another_chain")) assert.doesNotMatch(html, /holds another chain/, reason);
  }
});
const esc = (s) => CP._internal.esc(s);

// =============================================================================
// M1: a commit the host does not show yet is could_not_look
// =============================================================================

test("M1: a case_commit the host does not show yet (a compare 404 on a branch that exists) is could_not_look, never a mismatch", async () => {
  const { id } = await sealedCase("RJ2 M1 case");
  const fresh = crypto.createHash("sha1").update("rj2 not shown case").digest("hex");
  gh.seedRaw(PINS, fresh, C.casePath(id), caseText(id));
  plantPin(id, chainOf(id), fresh);
  assert.deepEqual(await S.pinState(id, storedCase(id)), { pin: "could_not_look", reason: "case_commit_not_shown", case_commit: fresh }); // unit R-L (g3)
});

// =============================================================================
// MINORS
// =============================================================================

test("n5: given a chain the case served does not have, pinState answers pin_commit_mismatch before reading the case at the commit", async () => {
  const { id } = await sealedCase("RJ2 n5");
  const other = sha("a chain this case does not have");
  plantPin(id, other, sealCommit(id));
  const r0 = gh.rawLog.length;
  assert.deepEqual(await S.pinState(id, other).then((s) => [s.pin, s.reason]), ["pin_commit_mismatch", "case_served_differs"]);
  assert.ok(!gh.rawLog.slice(r0).some((k) => k.endsWith(`:${C.casePath(id)}`)), "the case file was not read at the commit");
});

test("n6, n7: the page says 'in canonical form (json-c14n:v1)', never 'byte for byte'; a commit off the branch, or one the repository does not have, is not called 'that commit of the pins repository's branch'", async () => {
  assert.doesNotMatch(PAGE_SRC(), /byte for byte/);
  const early = gh.seedText(PINS, "notes/rj2-before.txt", "x\n");
  const { id } = await sealedCase("RJ2 n7");
  // differs: the case file as opened
  plantPin(id, chainOf(id), gh.commitsFor(PINS, C.casePath(id)).slice(-1)[0].sha);
  assert.ok((await casePage(id)).html.includes("the case file at that commit is not this case file in canonical form (json-c14n:v1) (case_at_commit_differs)"));
  for (const [commit, words, reason] of [
    ["f".repeat(40), "that commit is not shown by the repository", "case_commit_not_found"], // unit R-J3 (F2); unit R-L (g4)
    [early, "the pins repository holds no case file at that commit", "case_absent_at_commit"],
  ]) {
    plantPin(id, chainOf(id), commit);
    const html = (await casePage(id)).html;
    assert.ok(html.includes(`${words} (${reason})`), reason);
    assert.doesNotMatch(html, /that commit of the pins repository&#39;s branch|that commit of the pins repository's branch/, reason);
  }
  const side = gh.seedSideCommit(PINS, crypto.createHash("sha1").update("rj2 n7 side").digest("hex"));
  gh.seedRaw(PINS, side, C.casePath(id), caseText(id));
  plantPin(id, chainOf(id), side);
  const off = (await casePage(id)).html;
  assert.ok(off.includes("that commit is not on the published branch of the pins repository (case_commit_off_branch)"));
});

// =============================================================================
// MUST-FAIL GAP (unit R-J2): the mutants the pass over the lines R-J2 changed
// left alive, each caught here
// =============================================================================

test("MUST-FAIL GAP (S07): n5's mismatch names the commit the pin names", async () => {
  const { id } = await sealedCase("RJ2 gap n5 commit");
  plantPin(id, sha("another chain"), sealCommit(id));
  const st = await S.pinState(id, sha("another chain"));
  assert.deepEqual([st.pin, st.reason, st.case_commit], ["pin_commit_mismatch", "case_served_differs", sealCommit(id)]);
});

test("MUST-FAIL GAP (S12, P06): a reason the words do not know claims no chain and no bytes", () => {
  assert.equal(S.conflictWords("some_other_reason"), "a pin under this case's namespace is in conflict with this case");
  assert.equal(CP._internal.mismatchWords("case_served_differs", "case file"), "the case file there is not shown to be this case file in canonical form (json-c14n:v1)");
});

test("MUST-FAIL GAP (P31): a single-party page of an unsealed case says it is past its deadline once the deadline has passed", async () => {
  const c = await committedCase("RJ2 gap single party");
  const k = storedCase(c.id);
  gh.seed(PINS, C.casePath(c.id), { ...k, commitments: { ...k.commitments, b: { ...k.commitments.b, key_id: k.commitments.a.key_id } } }, { keepHistory: true });
  assert.equal(C.singleParty(storedCase(c.id)), true, "fixture: one key id in both commitments");
  const dl = Date.parse(DEADLINE);
  const before = await casePage(c.id, { now: dl - 2000 });
  assert.equal(before.status, 200, before.html.slice(0, 200));
  assert.doesNotMatch(before.html, /past its deadline/);
  const after = await casePage(c.id, { now: dl + 1000 });
  assert.match(after.html, /past its deadline/);
});
