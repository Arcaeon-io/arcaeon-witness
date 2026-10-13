// test/case_rl4c.test.js — unit R-L4c (2026-10-13): the second reader's pass
// over R-L4 at 2b05ee7 found the structural fault ended, and four sentences
// false in reachable states and one design gap:
//   c1 (B1) the confirming read refused a file the case root already
//       projected (two identical sends overlapping, the case sealed in
//       between): the projection is looked at FIRST, and a file the root
//       projects is answered 200 existing:true whatever the case's later
//       state;
//   c2 (B2) "cannot acquire it" was printed at the deadline while a re-send
//       received just before it could still be projected after it: the
//       projection is refused by the server clock read just before its
//       compare-and-swap, and the page says "cannot acquire it" only when
//       the root is terminal or the deadline has passed by the clock at
//       which the page is read;
//   c3 (B4) the public property was false repository-wide: it is scoped to
//       a case's own files;
//   c4 (M1) a refused claim held a role's only path forever: a registration
//       file is keyed by its claim, more than one claim may exist, and the
//       root projects at most one per role (foreman decision, architect to
//       confirm).
// The setup below is test/case_rl4.test.js's.
"use strict";


process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0152:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rl4c");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rl4c");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rl4c");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0152" });

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
const XREF = Object.freeze({ operator: "second-operator.example", reference: "case-ref-0152", url: "https://second-operator.example/cases/0152" });
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
    else if (/\.(js|mjs|cjs)$/.test(e.name)) out.push(rel);
  }
  return out;
}

// The registration file at `rpath` as the pins repository holds it: its
// bytes, and their sha256.
// Role `role`'s registration files, in either layout: the one path of a
// role before unit R-L4c (c4), and the claim-keyed paths after it. A test
// that finds files this way fails before the change for its own reason.
const regFileRe = (id, role) => new RegExp(`^(cases/${id}/commit_${role}\\.json|registrations/${id}/${role}/[0-9a-f]{64}\\.json)$`);
const regFiles = (id, role) => pinsPaths().filter((p) => regFileRe(id, role).test(p)).sort();
const regPut = (id, role) => (url, method) => method === "PUT" &&
  new RegExp(`/repos/${PINS}/contents/(cases/${id}/commit_${role}\\.json|registrations/${id}/${role}/[0-9a-f]{64}\\.json)`).test(url);
const fileText = (rpath) => gh._repoMap(PINS).get(rpath).content;
const fileSha256 = (rpath) => sha(Buffer.from(fileText(rpath), "utf8"));
// The claim of a registration record: the sha256 of the json-c14n:v1 bytes of
// the fields a party supplies (c4), computed here on its own.
const PARTY = ["case_id", "role", "commitment_sha256", "verifier", "key_id", "sig"];
const claimOf = (rec) => sha(canonicalBytes(Object.fromEntries(PARTY.map((k) => [k, rec[k]]))));
// What the case root projects for the file at `rpath`: the registration's
// entry, the sha256 of the file's bytes, and (since c4) the file's claim.
function projectionOf(rpath) {
  const rec = gh.read(PINS, rpath);
  const e = { ...C.commitmentEntry(rec), registration_sha256: fileSha256(rpath) };
  return C.CASE_ENTRY_FIELDS.includes("claim_sha256") ? { ...e, claim_sha256: claimOf(rec) } : e;
}
// How many writes of the case root put role `role` into it.
function projectionsOf(id, role) {
  const list = gh.commitsFor(PINS, C.casePath(id)).slice().reverse(); // oldest first
  let n = 0;
  let before = null;
  for (const cm of list) {
    const k = cm.content === null ? null : JSON.parse(cm.content);
    const now = k && k.commitments ? k.commitments[role] : null;
    if (before === null && now) n += 1;
    before = now || null;
  }
  return n;
}
// Role a's registration written, and the confirming read after it failed:
// a file the root does not project.
async function unconfirmedA(scope, { now = NOW, p = undefined } = {}) {
  const id = await openCase(scope);
  const a = p ? p(id) : party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const r = await during(regPut(id, "a"), async () => gh.forceGetFailure(PINS, C.casePath(id), 1, 503), () => commit(id, a, now));
  assert.equal(r.fired, true);
  assert.equal(r.out.status, 503, JSON.stringify(r.out.body).slice(0, 200));
  const [rpath] = regFiles(id, "a");
  return { id, a, rpath, out: r.out };
}
// The registrations panel of a page, as plain text.
function registrationsOf(html) {
  const i = html.indexOf("<h2>Registrations</h2>");
  if (i < 0) return "";
  return html.slice(i, html.indexOf("</section>", i)).replace(/<[^>]+>/g, " ").replace(/&#39;/g, "'").replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&").replace(/\s+/g, " ");
}
const D = Date.parse(DEADLINE);
// A clock that reads `before` until a registration file of `id` is written,
// and `after` from then on: the server clock moving while a request runs.
const clockOverWrite = (id, before, after) => () => (C.ROLES.some((r) => regFiles(id, r).length) ? after : before);

// THE WORDS, exactly
const LATE_UNCONFIRMED = "the case's deadline has passed, and the registration file written for this request was never confirmed; it has no standing";
const PROPERTY = "No file that belongs to a case is ever deleted. A case's registration files, reference rows, withdrawal record and seal " +
  "are written once and never changed. The case root is the one case file that is updated, and only by a compare-and-swap that every " +
  "reader can follow in the repository's history.";
const IN_PLACE = "Outside any case's own files, the pins repository updates two kinds of file in place: the daily anchor proofs " +
  "(`anchors/<date>-head.txt.ots`, which the anchoring job upgrades once the Bitcoin attestation arrives) and the pin pointers " +
  "(`pins/<namespace>/latest.json`, and a case's `pins/case/<case_id>/latest.json`, which each new pin of that case moves).";
const OLD_PROPERTY = "No file in the pins repository is ever deleted.";

// =============================================================================
// c1 (B1): the projection is looked at first
// =============================================================================

test("R-L4c c1: two identical sends overlap and the case seals between them: the send that finds its own file projected is 200 existing:true with the projected values, never 409 'has no standing'", async () => {
  const id = await openCase("RL4c c1 overlap sealed");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  await register(id, b);
  plantStamp(a.commitment_sha256);
  const late = NOW + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000;
  // the second send arrives once the first's lease has run out: it writes
  // the file, projects it, and the case is sealed, all before the first
  // send's create-only write lands
  const r = await during(regPut(id, "a"), async () => [(await commit(id, a, late)).status, (await reveal({ id, a, b })).status],
    () => commit(id, a, NOW));
  assert.deepEqual(r.inner, [201, 201], "the other send projected the file, and the case sealed");
  const [rpath] = regFiles(id, "a");
  assert.equal(regFiles(id, "a").length, 1, "one file");
  assert.equal(storedCase(id).status, "VERDICT");
  assert.deepEqual([r.out.status, r.out.body.existing, r.out.body.status], [200, true, "VERDICT"], JSON.stringify(r.out.body).slice(0, 300));
  assert.deepEqual(r.out.body.case.commitments.a, projectionOf(rpath));
  assert.deepEqual(r.out.body.registration, gh.read(PINS, rpath));
  assert.equal(projectionsOf(id, "a"), 1);
});

test("R-L4c c1: the same registration sent again after its case is sealed is 200 existing:true with what the root projects; an unprojected registration on the sealed case is still refused", async () => {
  const c = await sealedCase("RL4c c1 resend sealed");
  const again = await commit(c.id, c.a, REVEAL_AT + 1000);
  assert.deepEqual([again.status, again.body.existing, again.body.status], [200, true, "VERDICT"], JSON.stringify(again.body).slice(0, 300));
  assert.deepEqual(again.body.case.commitments.a, storedCase(c.id).commitments.a);
  assert.deepEqual(again.body.projected, []);
  const other = party(c.id, "a", AGENT_TAPE);
  plantStamp(other.commitment_sha256);
  const refused = await commit(c.id, other, REVEAL_AT + 1000);
  assert.deepEqual([refused.status, refused.body.error_code, refused.body.status], [409, "case_not_open", "VERDICT"]);
});

// =============================================================================
// c2 (B2): the server clock before the compare-and-swap, and the page's clock
// =============================================================================

test("R-L4c c2: the projection is judged by the server clock read just before its compare-and-swap: received before the deadline and swapped after it is 409 late_commitment, never projected; a moment earlier is projected", async () => {
  // the clock passes the deadline while the request runs, after the file is written
  const id = await openCase("RL4c c2 boundary late");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const late = await commit(id, a, undefined, { now: undefined, clock: clockOverWrite(id, D - 2000, D) });
  assert.deepEqual([late.status, late.body.error_code, late.body.error, late.body.registration_recorded],
    [409, "late_commitment", LATE_UNCONFIRMED, false], JSON.stringify(late.body).slice(0, 300));
  const [rpath] = regFiles(id, "a");
  assert.ok(rpath, "the file is written");
  assert.equal(gh.read(PINS, rpath).registered_at, C.utcSeconds(D - 2000), "received before the deadline");
  assert.equal(storedCase(id).commitments.a, null, "never projected");
  // and a re-send now cannot project it
  const again = await commit(id, a, D + 1000);
  assert.deepEqual([again.status, again.body.error_code], [409, "late_commitment"]);
  assert.equal(storedCase(id).commitments.a, null);
  // one millisecond before the deadline at the swap: projected
  const ok = await openCase("RL4c c2 boundary in time");
  const b = party(ok, "a", AGENT_TAPE);
  plantStamp(b.commitment_sha256);
  const inTime = await commit(ok, b, undefined, { now: undefined, clock: clockOverWrite(ok, D - 2000, D - 1) });
  assert.equal(inTime.status, 201, JSON.stringify(inTime.body).slice(0, 300));
  assert.deepEqual(storedCase(ok).commitments.a, projectionOf(regFiles(ok, "a")[0]));
});

test("R-L4c c2: a re-send received before the deadline, of a written and unconfirmed file, whose swap would be issued after it is refused 409 late_commitment and never projected", async () => {
  const u = await unconfirmedA("RL4c c2 resend late");
  // the re-send is received before the deadline; the clock passes it once
  // the request has read the file (before its confirming read)
  let reads = 0;
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    if (((o && o.method) || "GET") === "GET" && String(url).includes(`/contents/${u.rpath}`)) reads += 1;
    return viaMock(url, o);
  };
  let late;
  try {
    late = await commit(u.id, u.a, undefined, { now: undefined, clock: () => (reads ? D + 5 : D - 5) });
  } finally {
    global.fetch = viaMock;
  }
  assert.deepEqual([late.status, late.body.error_code, late.body.registration_recorded], [409, "late_commitment", false], JSON.stringify(late.body).slice(0, 300));
  assert.equal(storedCase(u.id).commitments.a, null);
});

// =============================================================================
// c3 (B4): the public property, scoped to what is true
// =============================================================================

test("R-L4c c3: the README states the property of a case's files verbatim, then names the files updated in place outside any case; the repository-wide claim appears nowhere", () => {
  const text = README();
  assert.ok(text.includes(`${PROPERTY} ${IN_PLACE}`), "the property, then the sentence naming what is updated in place");
  const raw = read("README.md");
  assert.equal(raw.includes(OLD_PROPERTY), false);
  for (const f of [...jsFiles("lib"), ...jsFiles("api"), ...jsFiles("tools"), "README.md", "public/PRACTICES.md"]) {
    assert.equal(read(f).replace(/\s+/g, " ").includes(OLD_PROPERTY), false, f);
    assert.doesNotMatch(read(f).replace(/\s+/g, " "), /The case root is the one file that is updated/, f);
  }
});

// =============================================================================
// c4 (M1), as the architect ruled: a registration file is keyed by its
// claim; a file is written only when the root as read shows the case open
// and the role unprojected; the compare-and-swap on the root decides, and a
// lost one re-reads once; the page lists no claim file
// =============================================================================

// The claim path of `p`'s registration under `key` (the role's own key by default).
const claimPathOf = (id, p, key = undefined) => {
  const body = REG.signedBody({ case_id: id, role: p.role, commitment_sha256: p.commitment_sha256 }, p.key || key);
  return `registrations/${id}/${p.role}/${claimOf({ ...body, key_id: REG.keyIdOf(p.key || key || REG.KEYS[p.role]) })}.json`;
};
const NO_REGISTRATION = "no registration is confirmed for this role";

test("R-L4c c4: a registration file is keyed by its claim, registrations/<case_id>/<role>/<sha256 of the party-supplied fields>.json, written once, and the root's entry names the claim", async () => {
  const id = await openCase("RL4c c4 path");
  const a = party(id, "a", AGENT_TAPE);
  await register(id, a);
  const want = claimPathOf(id, a);
  assert.deepEqual(regFiles(id, "a"), [want]);
  assert.equal(gh.commitsFor(PINS, want).length, 1, "written once");
  const rec = gh.read(PINS, want);
  assert.equal(storedCase(id).commitments.a.claim_sha256, claimOf(rec));
  assert.deepEqual(storedCase(id).commitments.a, projectionOf(want));
});

test("R-L4c c4: a different registration for a role the root projects writes no file: 409 role_already_committed naming the projected sha256", async () => {
  const c = await committedCase("RL4c c4 second tuple");
  const projected = storedCase(c.id).commitments.a.registration_sha256;
  const before = gh._commitsOf(PINS).length;
  for (const other of [party(c.id, "a", AGENT_TAPE), { ...c.a, key: REG.KEYS.b }]) {
    plantStamp(other.commitment_sha256);
    const r = await commit(c.id, other, NOW + 1500);
    assert.deepEqual([r.status, r.body.error_code, r.body.projected_sha256], [409, "role_already_committed", projected], JSON.stringify(r.body).slice(0, 300));
  }
  assert.equal(gh._commitsOf(PINS).length, before, "no file written");
  assert.equal(regFiles(c.id, "a").length, 1);
});

test("R-L4c c4: a registration for a withdrawn, sealed or expired case writes no file", async () => {
  const w = await openCase("RL4c c4 none withdrawn");
  const wa = party(w, "a", AGENT_TAPE);
  await register(w, wa);
  assert.equal((await withdraw(w, wa)).status, 201);
  const wb = party(w, "b", TOOL_TAPE);
  plantStamp(wb.commitment_sha256);
  const s = await sealedCase("RL4c c4 none sealed");
  const sa = party(s.id, "a", AGENT_TAPE);
  plantStamp(sa.commitment_sha256);
  const x = await openCase("RL4c c4 none expired");
  const xa = party(x, "a", AGENT_TAPE);
  plantStamp(xa.commitment_sha256);
  for (const [id, p, now, code] of [[w, wb, NOW + 5000, "case_not_open"], [s.id, sa, REVEAL_AT + 1000, "case_not_open"], [x, xa, D, "late_commitment"]]) {
    const before = gh._commitsOf(PINS).length;
    const files = regFiles(id, p.role).length;
    const r = await commit(id, p, now);
    assert.deepEqual([r.status, r.body.error_code], [409, code], JSON.stringify(r.body).slice(0, 200));
    assert.equal(gh._commitsOf(PINS).length, before, `${code}: nothing written`);
    assert.equal(regFiles(id, p.role).length, files);
  }
});

test("R-L4c c4: a claim whose projection was refused does not hold the role: an honest registration for that role is another file, projected, and the case commits", async () => {
  const id = await openCase("RL4c c4 refused claim");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(a.commitment_sha256);
  plantStamp(b.commitment_sha256);
  // role b's send under role a's key, overtaken by role a's own registration
  const r = await during(regPut(id, "b"), () => commit(id, { ...a, key: REG.KEYS.a }, NOW + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000),
    () => commit(id, { ...b, key: REG.KEYS.a }, NOW));
  assert.deepEqual([r.inner.status, r.out.status, r.out.body.error_code], [201, 409, "same_key_both_roles"], JSON.stringify(r.out.body).slice(0, 200));
  assert.equal(regFiles(id, "b").length, 1, "the refused claim's file stays");
  const honest = await commit(id, b, NOW + 2000);
  assert.equal(honest.status, 201, JSON.stringify(honest.body).slice(0, 300));
  assert.equal(regFiles(id, "b").length, 2, "another file");
  assert.equal(storedCase(id).status, "COMMITTED");
  assert.deepEqual(storedCase(id).commitments.b, projectionOf(claimPathOf(id, b)));
});

test("R-L4c c4: no registration_exists: a different claim for a role whose file is written and not projected is another file, and the compare-and-swap decides; the loser re-reads once and is 409 role_already_committed naming the projected sha256", async () => {
  const u = await unconfirmedA("RL4c c4 two claims");
  const other = party(u.id, "a", AGENT_TAPE);
  plantStamp(other.commitment_sha256);
  // the first claim's re-send loses its compare-and-swap to the second claim
  const r = await during((url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(u.id)}`),
    () => commit(u.id, other, NOW + 1000 + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000), () => commit(u.id, u.a, NOW + 1000));
  assert.equal(r.inner.status, 201, JSON.stringify(r.inner.body).slice(0, 300));
  const winner = claimPathOf(u.id, other);
  assert.deepEqual(storedCase(u.id).commitments.a, projectionOf(winner));
  assert.deepEqual([r.out.status, r.out.body.error_code, r.out.body.projected_sha256], [409, "role_already_committed", fileSha256(winner)],
    JSON.stringify(r.out.body).slice(0, 300));
  assert.equal(regFiles(u.id, "a").length, 2, "both claims' files stay");
  assert.equal(projectionsOf(u.id, "a"), 1);
});

test("R-L4c c4: a lost compare-and-swap is never retried: the root moved for the other role, so the answer is 503, the file is written and not confirmed, and the same registration sent again projects it", async () => {
  const id = await openCase("RL4c c4 lost swap");
  const a = party(id, "a", AGENT_TAPE);
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(a.commitment_sha256);
  plantStamp(b.commitment_sha256);
  const r = await during((url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(id)}`),
    () => commit(id, b, NOW + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000), () => commit(id, a, NOW));
  assert.equal(r.inner.status, 201);
  assert.deepEqual([r.out.status, r.out.body.error_code, r.out.body.registration_recorded], [503, "registration_unconfirmed", false],
    JSON.stringify(r.out.body).slice(0, 300));
  assert.equal(storedCase(id).commitments.a, null, "not projected over the moved root");
  assert.equal(r.out.body.registration_path, claimPathOf(id, a), "the answer names the file");
  const again = await commit(id, a, NOW + 2000);
  assert.deepEqual([again.status, again.body.existing, again.body.status], [200, true, "COMMITTED"]);
});

test("R-L4c c4: every answer after a file is written names its path", async () => {
  const u = await unconfirmedA("RL4c c4 path named");
  assert.equal(u.out.body.registration_path, claimPathOf(u.id, u.a));
  const again = await commit(u.id, u.a, NOW + 1500);
  assert.equal(again.body.registration_path, claimPathOf(u.id, u.a));
  const id = await openCase("RL4c c4 path named fresh");
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  const fresh = await commit(id, a);
  assert.deepEqual([fresh.status, fresh.body.registration_path], [201, claimPathOf(id, a)]);
});

test("R-L4c c4: the page says only that no registration is confirmed for a role the root does not project; it lists, counts and links no claim file", async () => {
  const u = await unconfirmedA("RL4c c4 page");
  for (const at of [NOW + 5000, D + 1000]) {
    const html = (await casePage(u.id, at)).html;
    const rows = registrationsOf(html);
    if (at < D) assert.ok(rows.includes(`role a ${NO_REGISTRATION}`), rows);
    assert.equal(html.includes(u.rpath), false, "no claim file named or linked");
    assert.doesNotMatch(html, /written, not confirmed|never confirmed|cannot acquire/);
  }
  const c = await committedCase("RL4c c4 page projected");
  const html = (await casePage(c.id, NOW + 5000)).html;
  assert.ok(html.includes(`https://github.com/${PINS}/commits/main/${claimPathOf(c.id, c.a)}`), "a projected file is linked");
});

test("R-L4c c4: the page never reads the registrations folder: it reads only the files the root projects", async () => {
  const u = await unconfirmedA("RL4c c4 page reads");
  await register(u.id, party(u.id, "b", TOOL_TAPE));
  const projectedB = regFiles(u.id, "b");
  const from = gh.getLog.length;
  await casePage(u.id, NOW + 5000);
  const regReads = gh.getLog.slice(from).filter((p) => p.startsWith(`registrations/${u.id}`) || p.startsWith(`cases/${u.id}/commit_`));
  assert.deepEqual(regReads, projectedB, "role b's projected file alone; no listing, and no read of role a's claim");
});

test("R-L4c c4: registration_exists is gone, and 'cannot acquire it' is printed nowhere", () => {
  for (const f of jsFiles("lib")) {
    assert.equal(read(f).includes("registration_exists"), false, f);
    assert.equal(/cannot acquire it/.test(read(f).replace(/\s+/g, " ")), false, f);
  }
});

// =============================================================================
// MUST-FAIL GAP TESTS: what the must-fail pass over the lines R-L4c changed
// found no test for
// =============================================================================

test("MUST-FAIL GAP (K22, K23): a case root whose claim is not 64 hex is not a valid case record, and no claim path is made from one", async () => {
  const c = await committedCase("RL4c gap claim hex");
  const k = storedCase(c.id);
  const r = C.validateCase({ ...k, commitments: { ...k.commitments, b: { ...k.commitments.b, claim_sha256: "not hex" } } });
  assert.deepEqual([r.ok, r.field], [false, "commitments.b.claim_sha256"]);
  assert.throws(() => C.registrationPath(c.id, "a", "../../cases/x"), (e) => e instanceof C.CaseError && e.field === "claim_sha256");
});

test("MUST-FAIL GAP (H08, H18, H27): the answers name what they say: the loser of the compare-and-swap is not recorded and names its own path; a late re-send and a replay name the path", async () => {
  const u = await unconfirmedA("RL4c gap named");
  const other = party(u.id, "a", AGENT_TAPE);
  plantStamp(other.commitment_sha256);
  const r = await during((url, method) => method === "PUT" && url.includes(`/repos/${PINS}/contents/${C.casePath(u.id)}`),
    () => commit(u.id, other, NOW + 1000 + (H.CASE_LOCK_TTL_SECONDS + 1) * 1000), () => commit(u.id, u.a, NOW + 1000));
  assert.deepEqual([r.out.body.error_code, r.out.body.registration_recorded, r.out.body.registration_path], ["role_already_committed", false, u.rpath]);
  const v = await unconfirmedA("RL4c gap late named");
  const late = await commit(v.id, v.a, D + 1000);
  assert.deepEqual([late.body.error_code, late.body.registration_path], ["late_commitment", v.rpath]);
  const c = await committedCase("RL4c gap replay named");
  const replay = await commit(c.id, c.a, NOW + 1500);
  assert.deepEqual([replay.status, replay.body.registration_path], [200, claimPathOf(c.id, c.a)]);
});

test("MUST-FAIL GAP (S04, S05): a projected file is held to being the registration record of the claim the root names: a file that is not a registration record, or that is at another claim's path, is never taken", async () => {
  // a file that is not a registration record, its sha256 and entry projected by hand
  const c = await committedCase("RL4c gap not a record");
  const apath = regFiles(c.id, "a")[0];
  const junk = JSON.stringify({ ...gh.read(PINS, apath), note: "a field no registration has" }, null, 2) + "\n";
  gh.seedText(PINS, apath, junk);
  const k = storedCase(c.id);
  gh.seed(PINS, C.casePath(c.id), { ...k, commitments: { ...k.commitments, a: { ...k.commitments.a, registration_sha256: sha(Buffer.from(junk, "utf8")) } } },
    { keepHistory: true });
  const r = await reveal(c);
  assert.notEqual(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.deepEqual([r.body.role, r.body.reason], ["a", "projection_differs_from_file"]);
  // the same file, at another claim's path that the root names by hand
  const d = await committedCase("RL4c gap other claim");
  const bpath = regFiles(d.id, "b")[0];
  const otherClaim = "e".repeat(64);
  gh.seedText(PINS, `registrations/${d.id}/b/${otherClaim}.json`, fileText(bpath));
  const kd = storedCase(d.id);
  gh.seed(PINS, C.casePath(d.id), { ...kd, commitments: { ...kd.commitments, b: { ...kd.commitments.b, claim_sha256: otherClaim } } }, { keepHistory: true });
  const s = await reveal(d);
  assert.notEqual(s.status, 201, JSON.stringify(s.body).slice(0, 300));
  assert.deepEqual([s.body.role, s.body.reason], ["b", "projection_differs_from_file"]);
});

test("MUST-FAIL GAP (P06): the single-party page links each registration file at its claim's path", async () => {
  const id = await openCase("RL4c gap single party");
  const a = party(id, "a", AGENT_TAPE);
  await register(id, a);
  const b = party(id, "b", TOOL_TAPE);
  plantStamp(b.commitment_sha256);
  const rec = C.registrationRecord({ case_id: id, role: "b", commitment_sha256: b.commitment_sha256, registered_at: C.utcSeconds(NOW),
    stamp_commit: gh.commitsFor(STAMPS, stamp.stampPath(b.commitment_sha256))[0].sha, stamped_at: "2026-10-10T07:45:00.123Z",
    ...REG.keyFields({ case_id: id, role: "b", commitment_sha256: b.commitment_sha256 }, REG.KEYS.a) });
  const bpath = REG.recordPath(rec);
  gh.seed(PINS, bpath, rec);
  gh.seed(PINS, C.casePath(id), C.applyRegistration(storedCase(id), rec, fileSha256(bpath)), { keepHistory: true });
  assert.equal(C.singleParty(storedCase(id)), true, "fixture: single party");
  const html = (await casePage(id, NOW + 5000)).html;
  for (const p of [regFiles(id, "a")[0], bpath]) assert.ok(html.includes(`https://github.com/${PINS}/commits/main/${p}`), p);
});
