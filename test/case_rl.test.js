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
// L1-L7 are in each test's name. The setup below is test/case_rn.test.js's,
// with a deployment's environment for the commit path (it signs repair
// notes) and a key per role that a test may change.
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
const UNREG = require("../lib/_case_unregister.js");
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
// The commit that wrote the WITHDRAWN case file: nothing writes over it.
const withdrawalCommit = (id) => gh.commitsFor(PINS, C.casePath(id))[0].sha;
// The race lost after the write (the commit's lease ran out and the
// withdrawal took it over). `deleteFails`: the removal refused; `noteFails`:
// every write under the case's removals/ refused while the race runs (since
// unit R-L2, M1, a note's path names the file's blob and creating commit, so
// it is not known before the write); `commitEnv`: the commit path's
// environment. -> the case, the registration as written (its blob, the
// commit that created it, its bytes) and the note path for that file.
async function lostRace(scope, { deleteFails = false, noteFails = false, commitEnv } = {}) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, a);
  plantStamp(b.commitment_sha256);
  const rpath = C.registrationPath(id, "b");
  const late = NOW + 1000 + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000;
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    const method = (o && o.method) || "GET";
    if (deleteFails && method === "DELETE") return { ok: false, status: 500, json: async () => ({}), text: async () => "" };
    if (noteFails && method === "PUT" && String(url).includes(`/contents/removals/${id}/`)) {
      return { ok: false, status: 502, json: async () => ({ message: "mock: refused" }), text: async () => "mock: refused" };
    }
    return viaMock(url, o);
  };
  let r;
  try {
    r = await during(
      (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
      () => withdraw(id, a, { now: late }),
      () => commit(id, b, NOW + 1000, commitEnv ? { env: commitEnv } : {}),
    );
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body));
  assert.equal(r.out.body.error_code, "case_withdrawn", JSON.stringify(r.out.body));
  return { id, a, b, rpath, out: r.out.body, ...asWritten(rpath, id) };
}
// The registration at `rpath` as its write left it: its blob (the mock's
// PUT log), the commit that created it and its bytes (the oldest commit
// touching the path since the newest removal), and the note path for that file.
function asWritten(rpath, id) {
  const list = gh.commitsFor(PINS, rpath).slice().reverse(); // oldest first
  let created = null;
  list.forEach((cm, k) => {
    if (cm.content !== null && (k === 0 || list[k - 1].content === null)) created = cm;
  });
  const blob = gh.putLog.filter((p) => p.path === rpath).at(-1).sha;
  return { blob, created: created.sha, text: created.content, notePath: S.repairNotePath(id, rpath, blob, created.sha) };
}
// The blob a removal named (the mock's DELETE log).
const removedBlob = (p) => (gh.deleteLog.find((d) => d.path === p) || {}).sha;
const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const CLAIM = "Withdrawal before the reveal closes that case; it does not recall a tape a counterparty already holds, and no verdict ever " +
  "binds a key that did not sign in the case that produced it.";
const LEGACY = "Files under withdrawn_commitments/ that a pins repository may hold from before this release are ignored: no code reads " +
  "or writes them.";
const CREATE_ONLY = "This repository is create-only except for removals that carry a signed repair note.";
const REVOCATION = "A key once shown revoked by a valid marker stays revoked. If the marker file is later removed, the answer is that the " +
  "marker cannot be read, never that the key is trusted again.";
const DATES = "Dates in a key document are shown for information and are not enforced; a key is judged by its status in the named document.";
// (since unit R-L2, M1: v 2, keyed on the file, with created_in_commit)
const NOTE_FIELDS = ["kind", "v", "case_id", "removed_path", "removed_blob_sha", "created_in_commit", "removed_file_sha256", "reason", "withdrawal_commit", "at",
  "signed_under", "signed_by", "sig", "sig_reason"];

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
// L3: a signed repair note for every removal
// =============================================================================

test("R-L L3 (a): the lease race: the commit path writes a signed repair note, create-only, then removes the registration", async () => {
  const x = await lostRace("RL L3 note");
  // (since unit R-L2, M1: keyed on the file, its path, blob and creating commit)
  assert.equal(x.notePath, `removals/${x.id}/${sha(`${x.rpath}\n${x.blob}\n${x.created}`)}.json`);
  const note = gh.read(PINS, x.notePath);
  assert.deepEqual(Object.keys(note).sort(), [...NOTE_FIELDS].sort());
  assert.deepEqual([note.kind, note.v, note.case_id, note.removed_path, note.reason], ["case-repair-note", 2, x.id, x.rpath, "registration_after_withdrawal"]);
  assert.equal(note.created_in_commit, x.created);
  assert.equal(note.removed_blob_sha, removedBlob(x.rpath));
  assert.equal(note.removed_file_sha256, sha(x.text));
  assert.equal(note.withdrawal_commit, withdrawalCommit(x.id));
  assert.match(note.at, UTC_SECONDS);
  assert.deepEqual(Object.keys(note.signed_under).sort(), ["document_commit", "document_sha256", "retrieved_at"]);
  assert.equal(note.signed_by, KD.keyIdOf(CASE_KEY));
  assert.equal(note.sig_reason, null);
  assert.deepEqual(await S.verifyRepairNote(note, DOC), { ok: true });
  const order = gh._commitsOf(PINS).map((cm) => cm.path);
  assert.ok(order.indexOf(x.notePath) >= 0 && order.indexOf(x.notePath) < order.lastIndexOf(x.rpath), "the note, then the removal");
  assert.equal(gh.has(PINS, x.rpath), false);
  assert.deepEqual([x.out.registration_removed, x.out.registration_recorded, x.out.repair_note], [true, false, x.notePath]);
  // (since unit R-L2, B1: a note records a removal decided)
  assert.match(x.out.error, /it was removed after a signed repair note was written for it \(a removal of this file was recorded for registration_after_withdrawal\)/);
});

test("R-L L3 (a): a repair note that cannot be written and confirmed removes nothing; no case signer, no note, nothing removed", async () => {
  const x = await lostRace("RL L3 note fails", { noteFails: true });
  assert.equal(gh.has(PINS, x.notePath), false);
  assert.equal(gh.has(PINS, x.rpath), true, "nothing removed");
  assert.equal(gh.deleteLog.length, 0);
  assert.deepEqual([x.out.registration_removed, x.out.registration_recorded, x.out.repair_note], [false, true, null]);
  assert.match(x.out.error, /no repair note could be written and confirmed, so nothing was removed/);
  const y = await lostRace("RL L3 no signer", { commitEnv: KD.deployed(gh, { [receipts.SIGNER_ENV]: RECEIPT_KEY.signer }, DOC) });
  assert.equal(gh.has(PINS, y.notePath), false);
  assert.equal(gh.has(PINS, y.rpath), true);
  assert.equal(y.out.registration_removed, false);
});

test("R-L L3 (a): a removal that fails leaves the note standing, and the sealer's repair completes it without a second note", async () => {
  const x = await lostRace("RL L3 delete fails", { deleteFails: true });
  assert.equal(gh.has(PINS, x.notePath), true, "the note stands");
  assert.equal(gh.has(PINS, x.rpath), true);
  assert.deepEqual([x.out.registration_removed, x.out.repair_note], [false, x.notePath]);
  assert.match(x.out.error, /a signed repair note is written for it \(a removal of this file was recorded for registration_after_withdrawal\), and the removal has not been made/);
  const run = await sealerRun();
  assert.equal(gh.has(PINS, x.rpath), false, "removed by the repair");
  assert.equal(gh.commitsFor(PINS, x.notePath).length, 1, "one note, written once");
  const entry = run.withdrawn_repaired.find((e) => e.case_id === x.id);
  assert.deepEqual([entry.removed, entry.kept], [["b"], ["a"]]);
});

test("R-L L3 (a): the sealer's repair writes the note first, then removes a registration written after the withdrawal", async () => {
  const x = await lostRace("RL L3 repair note", { noteFails: true });
  assert.equal(gh.has(PINS, x.rpath), true, "fixture: the commit path removed nothing");
  gh.forceFailure(PINS, x.notePath, 0, 502); // the note's path takes writes again
  await sealerRun();
  const note = gh.read(PINS, x.notePath);
  assert.deepEqual([note.reason, note.removed_path, note.withdrawal_commit], ["registration_after_withdrawal", x.rpath, withdrawalCommit(x.id)]);
  assert.deepEqual(await S.verifyRepairNote(note, DOC), { ok: true });
  const order = gh._commitsOf(PINS).map((cm) => cm.path);
  assert.ok(order.indexOf(x.notePath) < order.lastIndexOf(x.rpath), "the note, then the removal");
  assert.equal(gh.has(PINS, x.rpath), false);
  // no signer on the sealer's run: nothing removed, said
  const y = await lostRace("RL L3 repair no signer", { noteFails: true });
  gh.forceFailure(PINS, y.notePath, 0, 502);
  const run = await sealerRun(120000, KD.deployed(gh, {}, DOC));
  assert.equal(gh.has(PINS, y.rpath), true);
  const entry = run.withdrawn_repaired.find((e) => e.case_id === y.id);
  assert.deepEqual(entry.unknown, [{ role: "b", reason: "case_key_unset" }]);
});

test("R-L L3 (a): a registration the case could not confirm after its write is removed after a note naming registration_unconfirmed, with no withdrawal commit", async () => {
  const id = await openCase("RL L3 unconfirmed");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const rpath = C.registrationPath(id, "a");
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
    async () => gh.forceGetFailure(PINS, C.casePath(id), 1, 503),
    () => commit(id, a),
  );
  assert.deepEqual([r.out.status, r.out.body.error_code, r.out.body.registration_removed], [503, "registration_unconfirmed", true], JSON.stringify(r.out.body));
  const note = gh.read(PINS, asWritten(rpath, id).notePath);
  assert.deepEqual([note.reason, note.withdrawal_commit, note.removed_path], ["registration_unconfirmed", null, rpath]);
  assert.deepEqual(await S.verifyRepairNote(note, DOC), { ok: true });
  assert.equal(gh.has(PINS, rpath), false);
});

test("R-L L3: the one removal refuses a file no repair note names", async () => {
  const c = await committedCase("RL L3 unregister guard");
  const rpath = C.registrationPath(c.id, "a");
  const blob = gh._repoMap(PINS).get(rpath).sha;
  const created = gh.commitsFor(PINS, rpath)[0].sha;
  await assert.rejects(UNREG.removeRegistrationAfterWithdrawal(rpath, blob, "no note", { createdInCommit: created, keyDocument: DOC }), /repair note/);
  assert.equal(gh.deleteLog.length, 0);
  assert.equal(gh.has(PINS, rpath), true);
});

test("R-L L3 (b), (c): the page lists the case's repair notes with links, each verified under the document it names; a removal with no valid note is a finding", async () => {
  const x = await lostRace("RL L3 page");
  const page = (await casePage(x.id)).html;
  assert.ok(page.includes(`href="https://github.com/${PINS}/blob/main/${x.notePath}"`), "the note, linked");
  assert.ok(page.includes(x.rpath) && page.includes("registration_after_withdrawal"));
  assert.ok(page.includes("verified under the key document it names"), page.slice(page.indexOf("Removals"), page.indexOf("Removals") + 900));
  assert.doesNotMatch(page, /removed without a record/);
  // a note whose bytes changed does not verify, and the removal it records says so (since unit R-L2, B2: not "without a record")
  gh.seed(PINS, x.notePath, { ...gh.read(PINS, x.notePath), reason: "registration_unconfirmed" }, { keepHistory: true });
  const changed = (await casePage(x.id)).html;
  assert.match(changed, /does not verify/);
  assert.ok(changed.includes(esc(`${x.rpath} was removed; its repair note does not verify (malformed_field)`)), changed.slice(changed.indexOf("Removals"), changed.indexOf("Removals") + 900));
  assert.doesNotMatch(changed, /removed without a record/);
  // a registration removed by hand, with no note at all
  const c = await committedCase("RL L3 by hand");
  assert.equal((await withdraw(c.id, c.b)).status, 201);
  const rpath = C.registrationPath(c.id, "a");
  gh._repoMap(PINS).delete(rpath);
  gh.addCommit(PINS, rpath, "mock: removed by hand");
  const hand = (await casePage(c.id)).html;
  assert.ok(hand.includes(`a file under this case was removed without a record: ${rpath}`), hand.slice(hand.indexOf("Removals"), hand.indexOf("Removals") + 600));
});

test("R-L L3 (d): the README states the rule", () => {
  assert.ok(README().includes(CREATE_ONLY));
});

// =============================================================================
// L4: the withdrawal race
// =============================================================================

test("R-L L4: a withdrawal that takes effect in the lease race leaves its signed record, and the removal it causes leaves a signed note: no WITHDRAWN root, and no removal, has only a commit message as its trace", async () => {
  const x = await lostRace("RL L4 won");
  const root = storedCase(x.id);
  assert.equal(root.status, "WITHDRAWN");
  assert.equal(C.validateCase(root).ok, true);
  assert.equal(S.publishedSignatureReason(root, DOC), null, "the withdrawal record, signed");
  assert.equal(gh.has(PINS, C.withdrawnMarkerPath(x.id)), true);
  // every commit that removed a file under this case is named by a valid note
  const removals = gh._commitsOf(PINS).filter((cm) => cm.content === null && cm.path.startsWith(`cases/${x.id}`));
  assert.ok(removals.length >= 1, "fixture: a removal");
  for (const cm of removals) {
    const note = gh.read(PINS, x.notePath);
    assert.deepEqual(await S.verifyRepairNote(note, DOC), { ok: true }, cm.path);
  }
});

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

test("MUST-FAIL GAP (S37, S39): the sealer's other two withdrawn paths (a withdrawn root whose marker failed, with both registration files or with one) remove a registration written after the withdrawal under the run's own key, after its note", async () => {
  // both files, no marker: the root is read among the candidates, and reads WITHDRAWN
  const x = await lostRace("RL gap path one", { noteFails: true });
  gh.forceFailure(PINS, x.notePath, 0, 502);
  gh._repoMap(PINS).delete(C.withdrawnMarkerPath(x.id));
  gh.addCommit(PINS, C.withdrawnMarkerPath(x.id), "mock: the marker gone");
  const one = (await sealerRun()).withdrawn_repaired.find((e) => e.case_id === x.id);
  assert.deepEqual([one.marker, one.removed, one.unknown], ["written", ["b"], []], JSON.stringify(one));
  assert.deepEqual(await S.verifyRepairNote(gh.read(PINS, x.notePath), DOC), { ok: true });
  assert.equal(gh.has(PINS, x.rpath), false);
  // one file, no marker: the root is read in the markerless window
  const y = await lostRace("RL gap path three", { noteFails: true });
  gh.forceFailure(PINS, y.notePath, 0, 502);
  for (const p of [C.withdrawnMarkerPath(y.id), C.registrationPath(y.id, "a")]) {
    gh._repoMap(PINS).delete(p);
    gh.addCommit(PINS, p, "mock: gone");
  }
  const three = (await sealerRun(180000)).withdrawn_repaired.find((e) => e.case_id === y.id);
  assert.deepEqual([three.marker, three.removed, three.unknown], ["written", ["b"], []], JSON.stringify(three));
  assert.deepEqual(await S.verifyRepairNote(gh.read(PINS, y.notePath), DOC), { ok: true });
  assert.equal(gh.has(PINS, y.rpath), false);
});

test("MUST-FAIL GAP (S42, S43): the page's removals panel states the create-only rule word for word; a note path is made only for a case id", async () => {
  const x = await lostRace("RL gap rule on page");
  assert.ok((await casePage(x.id)).html.includes(esc(CREATE_ONLY)));
  assert.throws(() => S.repairNotePath("not-a-case-id", x.rpath, x.blob, x.created));
});

test("MUST-FAIL GAP (S47-S59): a repair note's form is checked field by field, before its signature", async () => {
  const x = await lostRace("RL gap note form");
  const note = gh.read(PINS, x.notePath);
  assert.deepEqual(await S.verifyRepairNote(note, DOC), { ok: true }, "control");
  const { reason: _gone, ...noReason } = note; // eslint-disable-line no-unused-vars
  for (const [rec, want, what] of [
    [{ ...note, extra: 1 }, "unknown_field", "a field outside the list"],
    [noReason, "missing_field", "no reason"],
    [{ ...note, kind: "case-repair" }, "malformed_field", "kind"],
    [{ ...note, reason: "tidying_up", withdrawal_commit: null }, "malformed_field", "a reason outside the list"],
    [{ ...note, removed_path: C.casePath(x.id) }, "malformed_field", "a path that is not a registration"],
    [{ ...note, removed_blob_sha: "x" }, "malformed_field", "blob sha"],
    [{ ...note, removed_file_sha256: note.removed_blob_sha }, "malformed_field", "file sha256"],
    [{ ...note, reason: "registration_unconfirmed" }, "malformed_field", "unconfirmed, with a withdrawal commit"],
    [{ ...note, withdrawal_commit: null }, "malformed_field", "after the withdrawal, with no withdrawal commit"],
    [{ ...note, at: "yesterday" }, "malformed_field", "at"],
    [{ ...note, signed_under: { ...note.signed_under, extra: 1 } }, "malformed_field", "signed_under"],
    [{ ...note, sig: null }, "unsigned", "unsigned"],
    [{ ...note, sig_reason: "x" }, "malformed_field", "sig_reason"],
  ]) {
    assert.equal((await S.verifyRepairNote(rec, DOC)).reason, want, what);
  }
});

test("MUST-FAIL GAP (S60-S67): a repair note verifies only under the document it names, on the published branch, by an active case key whose signature holds, still listed and not revoked in the current document", async () => {
  const x = await lostRace("RL gap note verify");
  const note = gh.read(PINS, x.notePath);
  const fields = { caseId: x.id, removedPath: x.rpath, removedBlobSha: note.removed_blob_sha, createdInCommit: note.created_in_commit,
    removedFileSha256: note.removed_file_sha256, reason: note.reason, withdrawalCommit: note.withdrawal_commit, at: note.at };
  const reasonOf = async (rec, doc = DOC) => (await S.verifyRepairNote(rec, doc)).reason;
  const off = KD.serveOffBranch(gh, DOC, "4".repeat(40));
  assert.equal(await reasonOf({ ...note, signed_under: { ...note.signed_under, document_commit: off } }), "document_not_on_branch");
  assert.equal(await reasonOf({ ...note, signed_under: { ...note.signed_under, document_sha256: "e".repeat(64) } }), "document_sha256_mismatch");
  const byReconcile = S.repairNote({ ...fields, signedUnder: KD.signedUnder(gh, DOC, note.at) }, S.loadReconcileSigner(KEYS, { keyDocument: DOC }));
  assert.equal(await reasonOf(byReconcile), "signer_unpublished", "a reconcile key is not a case key");
  const retired = KD.docWith(KD.entry(CASE_KEY, { status: "retired" }), KD.reconcileEntry(RECEIPT_KEY));
  const underRetired = S.repairNote({ ...fields, signedUnder: KD.signedUnder(gh, retired, note.at) }, S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  assert.equal(await reasonOf(underRetired), "signer_not_active");
  assert.equal(await reasonOf({ ...note, at: C.utcSeconds(NOW) }), "bad_signature");
  assert.equal(await reasonOf(note, { not: "a key document" }), "current_document_unreadable");
  assert.equal(await reasonOf(note, KD.docWith(KD.reconcileEntry(RECEIPT_KEY))), "signer_unlisted");
  assert.equal(await reasonOf(note, KD.docWith(KD.entry(CASE_KEY, { status: "revoked", revokedSince: "2026-10-11" }), KD.reconcileEntry(RECEIPT_KEY))),
    "signer_revoked");
});

// A registration written after its case's withdrawal that the commit path
// could not remove (its note's path refused writes), the path open again.
async function standing(scope) {
  const x = await lostRace(scope, { noteFails: true });
  gh.forceFailure(PINS, x.notePath, 0, 502);
  assert.equal(gh.has(PINS, x.rpath), true, "fixture: the file stands");
  const blob = gh._repoMap(PINS).get(x.rpath).sha;
  const remove = (over = {}) => S.removeRegistration({ caseId: x.id, role: "b", blobSha: blob, createdInCommit: x.created, reason: "registration_after_withdrawal",
    at: C.utcSeconds(NOW + 9000), env: deployedEnv(), keyDocument: DOC, ...over });
  return { ...x, blob, remove };
}

test("MUST-FAIL GAP (S69-S74): no note is written, and nothing removed, without the deployment's document, or when the file cannot be read, is gone, has changed, or the withdrawal's commit cannot be read", async () => {
  const x = await standing("RL gap removal guards");
  const noCommit = { ...deployedEnv() };
  delete noCommit.VERCEL_GIT_COMMIT_SHA;
  const sealing = S.sealingDocument(noCommit, { keyDocument: DOC });
  assert.equal(sealing.ok, false, "fixture: no deployment commit");
  const results = [];
  results.push([await x.remove({ env: noCommit }), sealing.code]);
  gh.forceGetFailure(PINS, x.rpath, 1, 503);
  results.push([await x.remove(), "registration_unreadable"]);
  results.push([await x.remove({ blobSha: "0".repeat(40) }), "registration_changed", S.repairNotePath(x.id, x.rpath, "0".repeat(40), x.created)]);
  gh.forceCommitsFailure(PINS, C.casePath(x.id), 1, 503);
  results.push([await x.remove(), "commits_unreadable"]);
  for (const [r, why, notePath = x.notePath] of results) {
    assert.deepEqual(r, { removed: false, note: "not_written", note_path: notePath, reason: why });
    assert.equal(gh.has(PINS, notePath), false, why);
  }
  gh._repoMap(PINS).delete(x.rpath);
  assert.deepEqual(await x.remove(), { removed: false, note: "not_written", note_path: x.notePath, reason: "registration_absent" });
  assert.equal(gh.has(PINS, x.notePath), false);
});

test("MUST-FAIL GAP (S76-S79): a note that could not be written, one already there for another blob, and one there that does not verify each remove nothing", async () => {
  const x = await standing("RL gap removal notes");
  gh.forceFailure(PINS, x.notePath, 8, 502);
  assert.deepEqual(await x.remove(), { removed: false, note: "failed", note_path: x.notePath, reason: "note_unconfirmed" });
  gh.forceFailure(PINS, x.notePath, 0, 502);
  // a note at this file's path, signed and valid, naming another blob (since unit R-L2, M1, only a note
  // placed there by hand can: a note for another blob is kept at another path)
  const signer = S.loadCaseSigner(KEYS, { keyDocument: DOC });
  const at = C.utcSeconds(NOW + 9000);
  const other = S.repairNote({ caseId: x.id, removedPath: x.rpath, removedBlobSha: "1".repeat(40), createdInCommit: x.created, removedFileSha256: "2".repeat(64),
    reason: "registration_after_withdrawal", withdrawalCommit: withdrawalCommit(x.id), at, signedUnder: KD.signedUnder(gh, DOC, at) }, signer);
  gh.seed(PINS, x.notePath, other);
  assert.deepEqual(await x.remove(), { removed: false, note: "existing", note_path: x.notePath, reason: "note_names_another_file" });
  assert.equal(gh.has(PINS, x.rpath), true);
  // a note there for this blob that does not verify
  const mine = S.repairNote({ caseId: x.id, removedPath: x.rpath, removedBlobSha: x.blob, createdInCommit: x.created, removedFileSha256: sha(x.text),
    reason: "registration_after_withdrawal", withdrawalCommit: withdrawalCommit(x.id), at, signedUnder: KD.signedUnder(gh, DOC, at) }, signer);
  gh.seed(PINS, x.notePath, { ...mine, at: C.utcSeconds(NOW) });
  assert.deepEqual(await x.remove(), { removed: false, note: "existing", note_path: x.notePath, reason: "note_bad_signature" });
  assert.equal(gh.has(PINS, x.rpath), true);
  assert.equal(gh.deleteLog.length, 0, "nothing removed");
  // control: that note, as signed, covers the removal
  gh.seed(PINS, x.notePath, mine);
  assert.deepEqual((await x.remove()).removed, true);
});

test("MUST-FAIL GAP (S82): a page whose read of the case's repair notes fails says so, and is not a page with no removals", async () => {
  const x = await lostRace("RL gap notes unread");
  gh.forceGetFailure(PINS, `removals/${x.id}`, 1, 503);
  const page = await casePage(x.id);
  assert.ok(page.html.includes("Whether a file under this case was removed could not be read when this page was read (repair_notes_unreadable)."),
    page.html.slice(page.html.indexOf("Removals") - 40, page.html.indexOf("Removals") + 300));
});

test("MUST-FAIL GAP (H13, H14): a registration the case could not confirm, removed after its note: the refusal says so, names the note, and says nothing is registered", async () => {
  const id = await openCase("RL gap unconfirmed words");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const rpath = C.registrationPath(id, "a");
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
    async () => gh.forceGetFailure(PINS, C.casePath(id), 1, 503),
    () => commit(id, a),
  );
  assert.deepEqual([r.out.status, r.out.body.repair_note], [503, asWritten(rpath, id).notePath], JSON.stringify(r.out.body));
  // (since unit R-L2, B1: a note records a removal decided; since unit R-L3, rule 3: the one sentence for a write that could not be confirmed)
  assert.equal(r.out.body.error, "The registration was written and could not be confirmed, so a removal of it was recorded. Send the same " +
    "registration again; it will be written fresh.");
  assert.equal(gh.has(PINS, rpath), false);
});

test("MUST-FAIL GAP (S90, S83): a case whose registration files were never removed shows no removals: a role not yet registered is not a removal, and a file under removals/ that is not at a note's name is not a note", async () => {
  const id = await openCase("RL gap never written");
  await register(id, party(id, "a", AGENT_TAPE));
  gh.seed(PINS, `removals/${id}/notes.json`, { not: "a note" });
  const html = (await casePage(id)).html;
  assert.doesNotMatch(html, /Removals|removed without a record/);
});

test("MUST-FAIL GAP (S84, S89, S91b): the page says the removals could not be read when a registration file or a removed file's history could not be read; a note that could not be read leaves its removal not verified (since unit R-L2, B2)", async () => {
  const x = await lostRace("RL gap removals unread");
  const said = (r) => `Whether a file under this case was removed could not be read when this page was read (${r}).`;
  gh.forceGetFailure(PINS, x.notePath, 1, 503);
  assert.ok((await casePage(x.id)).html.includes(esc(`${x.rpath} was removed; its repair note could not be verified when this page was read (repair_note_unreadable)`)));
  gh.forceGetFailure(PINS, C.registrationPath(x.id, "a"), 1, 503);
  assert.ok((await casePage(x.id)).html.includes(said("registration_unreadable")));
  gh.forceCommitsFailure(PINS, x.rpath, 1, 503);
  assert.ok((await casePage(x.id)).html.includes(said("registration_commits_unreadable")));
});

test("MUST-FAIL GAP (S85, S86, S87): a note not at its own name, or of another case, does not verify on the page; a note whose file is still there says so", async () => {
  const x = await lostRace("RL gap note placement", { deleteFails: true });
  const note = gh.read(PINS, x.notePath);
  const html = (await casePage(x.id)).html;
  // (since unit R-L2, B1: what was read at the note's path)
  assert.ok(html.includes("; a repair note is written; the removal has not been made; signed by"), html.slice(html.indexOf("Removals"), html.indexOf("Removals") + 900));
  gh.seed(PINS, `removals/${x.id}/${"f".repeat(64)}.json`, note);
  assert.ok((await casePage(x.id)).html.includes("does not verify (note_not_at_its_path)"));
  const y = await committedCase("RL gap other case");
  gh.seed(PINS, S.repairNotePath(y.id, x.rpath, note.removed_blob_sha, note.created_in_commit), note);
  assert.ok((await casePage(y.id)).html.includes("does not verify (note_of_another_case)"));
});

test("MUST-FAIL GAP (H21, H22): the withdrawal's answer carries the public claim, and says that only the salt's sha256 is kept, in the withdrawal record", async () => {
  const c = await committedCase("RL gap answer notes");
  const w = await withdraw(c.id, c.b);
  assert.equal(w.status, 201);
  assert.equal(w.body.withdrawal_note, CLAIM);
  assert.equal(w.body.preimage_note, "Presenting the preimage spends this commitment: a withdrawn case can never be revealed. Nothing of the preimage " +
    "is kept except the sha256 of the salt, in the withdrawal record.");
});

// A case whose one registration could not be confirmed after its write, and
// was removed after its note (C2): OPEN, with a repair note.
async function unconfirmedRemoval(scope) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const rpath = C.registrationPath(id, "a");
  const r = await during(
    (url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${rpath}`),
    async () => gh.forceGetFailure(PINS, C.casePath(id), 1, 503),
    () => commit(id, a),
  );
  assert.equal(r.out.body.registration_removed, true, "fixture: removed after its note");
  return { id, rpath, notePath: asWritten(rpath, id).notePath };
}
const render = (id, nowMs) => CP._internal.renderCase(storedCase(id), nowMs, DOC);

test("MUST-FAIL GAP (P21, P25-P29): an OPEN and an EXPIRED case show their removals, and a page whose removals could not be read is never kept; nor is a WITHDRAWN one", async () => {
  const u = await unconfirmedRemoval("RL gap open removals");
  const open = await render(u.id, NOW + 5000);
  assert.ok(open.html.includes(`href="https://github.com/${PINS}/blob/main/${u.notePath}"`) && open.html.includes("registration_unconfirmed"));
  assert.equal(open.definite, true, "control: kept");
  const expired = await render(u.id, Date.parse(DEADLINE) + 1000);
  assert.match(expired.html, /EXPIRED/);
  assert.ok(expired.html.includes(`href="https://github.com/${PINS}/blob/main/${u.notePath}"`));
  assert.equal(expired.definite, true, "control: kept");
  gh.forceGetFailure(PINS, u.notePath, 1, 503);
  assert.equal((await render(u.id, NOW + 5000)).definite, false, "OPEN");
  gh.forceGetFailure(PINS, u.notePath, 1, 503);
  assert.equal((await render(u.id, Date.parse(DEADLINE) + 1000)).definite, false, "EXPIRED");
  const x = await lostRace("RL gap withdrawn kept");
  assert.equal((await render(x.id, NOW + 5000)).definite, true, "control: kept");
  gh.forceGetFailure(PINS, x.notePath, 1, 503);
  assert.equal((await render(x.id, NOW + 5000)).definite, false, "WITHDRAWN");
});

test("MUST-FAIL GAP (P22, P30): a sealed page whose removals could not be read is not kept, and neither is a page with a note whose named document could not be read", async () => {
  const c = await sealedCase("RL gap sealed removals");
  const t = REVEAL_AT + 3600000;
  assert.equal((await render(c.id, t)).definite, true, "control: kept");
  gh.forceGetFailure(PINS, `removals/${c.id}`, 1, 503);
  assert.equal((await render(c.id, t)).definite, false, "sealed");
  const x = await lostRace("RL gap note document unread");
  const note = gh.read(PINS, x.notePath);
  gh.seed(PINS, x.notePath, { ...note, signed_under: { ...note.signed_under, document_commit: "5".repeat(40) } });
  const r = await render(x.id, NOW + 5000);
  // (since unit R-L2, B2: a check that could not look is not "does not verify")
  assert.ok(r.html.includes(esc("it could not be verified when this page was read (document_unavailable)")),
    r.html.slice(r.html.indexOf("Removals"), r.html.indexOf("Removals") + 700));
  assert.doesNotMatch(r.html, /does not verify \(document_unavailable\)|removed without a record/);
  assert.equal(r.definite, false);
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

test("MUST-FAIL GAP (U02-U05; since unit R-L2, the note kept for the file, its signature checked): the one removal refuses when the note at the file's path names another case, another file or another blob, and says so when the note could not be read", async () => {
  const c = await committedCase("RL gap unregister fields");
  const rpath = C.registrationPath(c.id, "a");
  const blob = gh._repoMap(PINS).get(rpath).sha;
  const created = gh.commitsFor(PINS, rpath)[0].sha;
  const notePath = S.repairNotePath(c.id, rpath, blob, created);
  const at = C.utcSeconds(NOW + 9000);
  const signed = (over) => S.repairNote({ caseId: c.id, removedPath: rpath, removedBlobSha: blob, createdInCommit: created, removedFileSha256: "2".repeat(64),
    reason: "registration_unconfirmed", withdrawalCommit: null, at, signedUnder: KD.signedUnder(gh, DOC, at), ...over }, S.loadCaseSigner(KEYS, { keyDocument: DOC }));
  const remove = () => UNREG.removeRegistrationAfterWithdrawal(rpath, blob, "x", { createdInCommit: created, keyDocument: DOC });
  for (const [what, n] of [["another case", signed({ caseId: "e".repeat(64) })], ["another file", signed({ removedPath: C.registrationPath(c.id, "b") })],
    ["another blob", signed({ removedBlobSha: "1".repeat(40) })], ["another creating commit", signed({ createdInCommit: "3".repeat(40) })]]) {
    gh.seed(PINS, notePath, n);
    await assert.rejects(remove(), /no repair note names/, what);
  }
  gh.seed(PINS, notePath, signed({}));
  gh.forceGetFailure(PINS, notePath, 1, 503);
  await assert.rejects(remove(), /the repair note for .* could not be read, so nothing was removed/);
  assert.equal(gh.deleteLog.length, 0);
  // control: the note kept for this file, signed, lets the removal through
  await remove();
  assert.equal(gh.has(PINS, rpath), false);
});
