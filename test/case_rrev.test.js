// test/case_rrev.test.js — unit R-REV (2026-10-14): no revocation by commit
// order; two key statuses. The architect confirmed the reversal (Design I,
// I1 and Fable sitting 1 Q3 3a are superseded): the marker walk and the
// "signed before the key was revoked" holding are removed. A seal whose
// signature verifies under the document it names is checked against the
// document this deployment carries: active in its role is
// valid_under_document, revoked is signer_revoked (no verdict shown,
// whenever it was signed), absent is signer_unlisted. No pin and no marker
// is read. Key statuses are active and revoked. The setup below is
// test/case_rpin.test.js's.
"use strict";


process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0161:case-test-";
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-14rrev");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-14rrev");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-14rrev");
const KEYS = Object.freeze({ [S.CASE_SIGNER_ENV]: CASE_KEY.signer, [receipts.SIGNER_ENV]: RECEIPT_KEY.signer, WITNESS_LOG_SIGNER_KEY: LOG_KEY.signer });
const DOC = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.reconcileEntry(RECEIPT_KEY)));
const OPEN_AUTH = Object.freeze({ authorization: "Bearer case-test-open-key-0161" });

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
// UNIT R-REV
// =============================================================================

// The current document, revoking `keys` (a case key and the reconcile key by
// default, each active unless listed).
const docRevoking = ({ caseKey = "active", reconcileKey = "active" } = {}) =>
  KD.docWith(KD.entry(CASE_KEY, { status: caseKey }), KD.reconcileEntry(RECEIPT_KEY, { status: reconcileKey }));
// The page read under `keyDocument`, carried by a deployment built at its own
// commit (V, the commit sealingDocument reports).
async function pageUnder(id, keyDocument, { now = REVEAL_AT + 3600000 } = {}) {
  const env = KD.deployed(gh, {}, keyDocument);
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": nextIp() } }), res,
    { now, keyDocument, env });
  return { status: res._status, html: String(res._body), V: env[S.DEPLOY_COMMIT_ENV] };
}
const REVOKED_SENTENCE = (keyId, V) => `The key that signed this case (${keyId}) is listed as revoked in the key document this service carries ` +
  `(commit ${V.slice(0, 12)}), so this page does not show its verdict, whenever it was signed.`;
const VERDICT_WORDS = /MATCHED|ALTERED|MISSING|class="word pass"|class="word fail"|first divergence/;
// The page's text, every tag dropped.
const textOf = (html) => html.replace(/<style[\s\S]*?<\/style>/g, "").replace(/<[^>]+>/g, "").replace(/&#39;/g, "'").replace(/&quot;/g, '"')
  .replace(/&amp;/g, "&").replace(/\s+/g, " ");
const fingerprintPath = (verifier) => `revocations/${crypto.createHash("sha256").update(checkpoint.parseVerifierKey(verifier).pub).digest("hex")}.json`;

test("R-REV 1: a seal under a key the current document revokes shows no verdict and reads no pins file: SIGNED BY A REVOKED KEY and the one sentence, at 200", async () => {
  const c = await sealedCase("RREV 1 revoked");
  assert.deepEqual(pinTree(c.id), [pinFile(c.id)], "fixture: pinned at the reveal");
  const revoked = docRevoking({ caseKey: "revoked" });
  let page;
  const seen = await spyRequests(async () => { page = await pageUnder(c.id, revoked); });
  assert.equal(page.status, 200);
  assert.match(page.html, /<h1>Case: SIGNED BY A REVOKED KEY<\/h1>/);
  assert.ok(textOf(page.html).includes(REVOKED_SENTENCE(KD.keyIdOf(CASE_KEY), page.V)), textOf(page.html).slice(0, 800));
  assert.doesNotMatch(page.html, VERDICT_WORDS);
  assert.doesNotMatch(page.html, /DOES NOT VERIFY/);
  // a path under pins/ or revocations/, by the contents API, the commits API or the raw host
  const under = /\/contents\/(pins|revocations)\/|[?&]path=(pins|revocations)\/|test-pins\/[0-9a-f]{40}\/(pins|revocations)\//;
  const pinsReads = seen.filter((s) => s.url.includes(PINS) && under.test(s.url));
  assert.ok(seen.some((s) => s.url.includes(`/contents/${C.casePath(c.id)}`)), "fixture: the spy saw the page's reads");
  assert.deepEqual(pinsReads.map((s) => s.url), [], "no read under pins/ or revocations/");
});

test("R-REV 2: a failed read never prints does not verify: with every pins-store read but the case file failing, an active-key seal shows its verdict, and a revoked-key seal the revoked sentence", async () => {
  const c = await sealedCase("RREV 2 reads fail");
  const viaMock = global.fetch;
  global.fetch = async (url, o) => {
    const u = decodeURIComponent(String(url));
    if (u.includes(PINS) && !u.includes(`/contents/${C.casePath(c.id)}`)) {
      return { ok: false, status: 503, json: async () => ({ message: "mock: every pins read fails" }), text: async () => "mock: every pins read fails" };
    }
    return viaMock(url, o);
  };
  let active;
  let revoked;
  try {
    active = await pageUnder(c.id, docRevoking());
    revoked = await pageUnder(c.id, docRevoking({ caseKey: "revoked" }));
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(active.status, 200, active.html.replace(/<style[\s\S]*?<\/style>/, "").slice(0, 1500));
  assert.match(active.html, /<span class="word pass">MATCHED<\/span>/, "the verdict, the reads that failed notwithstanding");
  assert.equal(revoked.status, 200);
  assert.ok(textOf(revoked.html).includes(REVOKED_SENTENCE(KD.keyIdOf(CASE_KEY), revoked.V)), textOf(revoked.html).slice(0, 800));
  for (const p of [active, revoked]) assert.doesNotMatch(p.html, /DOES NOT VERIFY/);
});

test("R-REV 3: a planted marker changes nothing: a valid-looking revocations/<fingerprint>.json for an active key leaves the seal valid_under_document, and nothing reads it", async () => {
  const c = await sealedCase("RREV 3 planted marker");
  const k = storedCase(c.id);
  gh.seed(PINS, fingerprintPath(CASE_KEY.verifier), { kind: "key-revocation", v: 1, key_id: KD.keyIdOf(CASE_KEY),
    key_fingerprint: fingerprintPath(CASE_KEY.verifier).slice("revocations/".length, -".json".length), revoked_in_commit: "a".repeat(40) });
  let answer;
  const seen = await spyRequests(async () => { answer = await S.sealedRecordReason(k, docRevoking()); });
  assert.equal(answer.code, "valid_under_document", JSON.stringify(answer));
  assert.deepEqual(seen.filter((s) => s.url.includes("revocations/")).map((s) => s.url), []);
});

test("R-REV 4: the key document refuses a retired key: status is active or revoked", () => {
  const doc = KD.docWith(KD.entry(CASE_KEY, { status: "retired" }), KD.reconcileEntry(RECEIPT_KEY));
  assert.deepEqual(S.checkKeyDocument(doc), { ok: false, reason: "malformed_field", at: "keys[0].status" });
  assert.equal(S.checkKeyDocument(docRevoking({ caseKey: "revoked" })).ok, true, "revoked, with no date, reads");
});

test("R-REV 5: the key document refuses revoked_since: an unknown field", () => {
  const e = { ...KD.entry(CASE_KEY, { status: "revoked" }), revoked_since: "2026-10-11" };
  assert.deepEqual(S.checkKeyDocument(KD.docWith(e, KD.reconcileEntry(RECEIPT_KEY))), { ok: false, reason: "unknown_field", at: "keys[0].revoked_since" });
});

test("R-REV 6: record_key_revocation is gone, and no lib/ file reads or writes a revocation marker", () => {
  assert.equal(fs.existsSync(path.join(__dirname, "..", "tools", "record_key_revocation.js")), false);
  for (const f of jsFiles("lib")) assert.doesNotMatch(read(f), /revocationMarker|markersWithoutRevocation|REVOCATION_MARKER|pinnedBefore/, f);
});

test("R-REV 7: the reference refuses a revoked-key case 409 signer_revoked and writes no row", async () => {
  const c = await sealedCase("RREV 7 reference");
  const res = makeRes();
  const before = gh.putLog.length;
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role: "a", tape_sha256: c.a.tape_sha256, salt: c.a.salt, cross_reference: XREF }),
    res, { now: REVEAL_AT + 1800000, env: KEYS, keyDocument: docRevoking({ caseKey: "revoked" }) });
  const body = parsed(res);
  assert.deepEqual([res._status, body.error_code, body.reason], [409, "signer_revoked", "case_key_revoked"], JSON.stringify(body).slice(0, 300));
  assert.doesNotMatch(body.error, /pins repository|written before|does not verify/);
  assert.equal(gh.putLog.length, before, "no row, no quota");
});

test("R-REV: the sealer never pins a signer_revoked case: anchorCase answers not_sealed with the reason, and the run counts it not_sealed", async () => {
  const c = await sealedUnpinned("RREV sealer");
  const revoked = docRevoking({ reconcileKey: "revoked" });
  const r = await S.anchorCase(c.id, { now: REVEAL_AT + 60000, keyDocument: revoked });
  assert.deepEqual([r.ok, r.code, r.status, r.reason], [false, "not_sealed", "VERDICT", "signer_revoked"]);
  const run = await S.anchorPending({ now: REVEAL_AT + 120000, keyDocument: revoked, env: KD.deployed(gh, KEYS, revoked) });
  assert.equal(run.not_sealed, 1);
  assert.deepEqual(pinTree(c.id), [], "never pinned");
  for (const gone of ["marker_without_revocation", "markers_unread"]) assert.equal(gone in run, false, gone);
});

test("R-REV: the reconcile key revoked is signer_revoked too, naming that key; signer_since_revoked and pin_unavailable are gone", async () => {
  const c = await sealedCase("RREV reconcile revoked");
  const a = await S.sealedRecordReason(storedCase(c.id), docRevoking({ reconcileKey: "revoked" }));
  assert.deepEqual([a.code, a.reason, a.key_id], ["signer_revoked", "reconcile_key_revoked", KD.keyIdOf(RECEIPT_KEY)]);
  for (const f of jsFiles("lib")) assert.doesNotMatch(read(f), /signer_since_revoked|pin_unavailable/, f);
});

test("R-REV: the could-not-look page for a current document that does not read says what that document lists, and orders nothing", async () => {
  const c = await sealedCase("RREV current unreadable");
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: c.id }, headers: { "x-forwarded-for": nextIp() } }), res,
    { now: REVEAL_AT + 3600000, keyDocument: null, env: {} });
  const html = String(res._body);
  assert.equal(res._status, 503);
  assert.ok(html.includes("the current key document this deployment carries, which lists each key in its role as active or revoked"));
  assert.doesNotMatch(html, /since revoked|still listed/);
});

test("R-REV: the key document's prose says two statuses, and the README says marker files are left in place and ignored", () => {
  const doc = JSON.parse(read("public/.well-known/arcaeon/case-signing-keys.json"));
  assert.deepEqual(doc.status_meaning, {
    active: "Listed for its role. A record this key signed verifies under a document that lists it active.",
    revoked: "Its private half is believed exposed. A record this key signed is not shown as holding, whenever it was signed: this document does not order a signature against a revocation.",
  });
  assert.equal(doc.rotation, "Rotation adds a new key with status active. The previous key stays listed active with a note that it no longer signs, " +
    "so the records it signed keep verifying. A key is marked revoked only if its private half is believed exposed. Dates in this document are " +
    "information and are not enforced. A reader holds a record to the document it names, at a commit on this repository's published branch, and " +
    "each key that signed it must also be listed here, in its role, when the record is read. The service signs only with a key listed here as " +
    "active in its role, and before it seals it confirms that this document is the one at the commit it names.");
  assert.equal(S.checkKeyDocument(doc).ok, true);
  assert.doesNotMatch(JSON.stringify(doc), /revocations\/|retired|revoked_since|marker/);
  assert.ok(README().includes("Revocation marker files (`revocations/<fingerprint>.json`) already in a repository are left in place and ignored: no code reads or writes them."));
  assert.doesNotMatch(README(), /pinned before the revocation|record_key_revocation/);
});

test("R-REV: KEY_DATES_NOTE stays beside the key document a valid seal names", async () => {
  const c = await sealedCase("RREV key dates");
  const page = await pageUnder(c.id, docRevoking());
  assert.ok(page.html.includes("Dates in a key document are shown for information and are not enforced; a key is judged by its status in the named document."));
});

// =============================================================================
// UNIT R-REV, THE MUST-FAIL PASS: tests for the planted defects the tests
// above let through (the ids are the pass's)
// =============================================================================

test("MUST-FAIL GAP (R06): both keys listed revoked: the answer names the case key, which is checked first", async () => {
  const c = await sealedCase("RREV gap both revoked");
  const a = await S.sealedRecordReason(storedCase(c.id), docRevoking({ caseKey: "revoked", reconcileKey: "revoked" }));
  assert.deepEqual(a, { code: "signer_revoked", reason: "case_key_revoked", key_id: KD.keyIdOf(CASE_KEY) });
});

test("MUST-FAIL GAP (R15, R16, R17): status_meaning names exactly the two statuses, each a string, in an object; anything else is malformed_field, never a throw", () => {
  const doc = JSON.parse(read("public/.well-known/arcaeon/case-signing-keys.json"));
  const sm = doc.status_meaning;
  for (const [name, meaning] of [
    ["a third status explained", { ...sm, retired: "rotated out" }],
    ["revoked not explained", { active: sm.active }],
    ["active not a string", { ...sm, active: 1 }],
    ["null", null],
    ["a list", [sm.active, sm.revoked]],
    ["a string", "active or revoked"],
  ]) {
    assert.deepEqual(S.checkKeyDocument({ ...doc, status_meaning: meaning }), { ok: false, reason: "malformed_field", at: "status_meaning" }, name);
  }
  assert.equal(S.checkKeyDocument(doc).ok, true, "control");
});

test("MUST-FAIL GAP (P06): with the reconcile key revoked, the page's one sentence names the reconcile key, never the case key", async () => {
  const c = await sealedCase("RREV gap reconcile page");
  const page = await pageUnder(c.id, docRevoking({ reconcileKey: "revoked" }));
  assert.equal(page.status, 200);
  assert.ok(textOf(page.html).includes(REVOKED_SENTENCE(KD.keyIdOf(RECEIPT_KEY), page.V)), textOf(page.html).slice(0, 800));
});

test("MUST-FAIL GAP (P11): the revoked page's title says SIGNED BY A REVOKED KEY, never VERDICT", async () => {
  const c = await sealedCase("RREV gap title");
  const page = await pageUnder(c.id, docRevoking({ caseKey: "revoked" }));
  assert.ok(page.html.includes(`<title>Case ${c.id.slice(0, 12)}: SIGNED BY A REVOKED KEY`), page.html.slice(0, 600));
  assert.doesNotMatch(page.html, /<title>[^<]*VERDICT/);
});
