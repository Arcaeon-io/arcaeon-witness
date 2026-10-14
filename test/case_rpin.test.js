// test/case_rpin.test.js — unit R-PIN (2026-10-13): one pin per case, no
// pointer, no "anchored", no pin gate. A sealed case has exactly one pin,
// pins/case/<case_id>/00000001.json, written create-only by the sealer (or
// the reveal) after the seal, and nothing else is ever written under its
// pin namespace; no code reads or writes a pointer latest.json. The pin read
// (pinState) answers not_pinned, pinned, pin_commit_mismatch, conflict,
// unreadable or could_not_look, and nothing says "anchored". A reference row
// reads no pin and no anchor. The sealer's candidates are the case roots
// with no pin file; the status row has no pending count; the page is
// rendered on every request.
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-13rpin");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-13rpin");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-13rpin");
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

test("R-PIN 1: a sealed case writes exactly one file under its pin namespace: the sealer three times, two reference rows, and the sealer again", async () => {
  const c = await sealedCase("RPIN one pin");
  for (let i = 0; i < 3; i += 1) await sealerRun(60000 * (i + 1));
  assert.equal((await reference(c, { role: "a" })).status, 201);
  assert.equal((await reference(c, { role: "b" })).status, 201);
  await sealerRun(600000);
  assert.deepEqual(pinTree(c.id), [pinFile(c.id)]);
});

test("R-PIN 2: no code path updates any pins file except the case root, over a whole case life", async () => {
  let c;
  const seen = await spyRequests(async () => {
    c = await committedCase("RPIN no update");
    assert.equal((await reveal(c)).status, 201);
    for (let i = 0; i < 3; i += 1) await sealerRun(60000 * (i + 1));
    assert.equal((await reference(c, { role: "a" })).status, 201);
    assert.equal((await reference(c, { role: "b" })).status, 201);
    await sealerRun(600000);
    assert.equal((await casePage(c.id)).status, 200);
  });
  const updates = seen.filter((s) => s.method === "PUT" && s.ok && s.update && s.url.includes(`/repos/${PINS}/contents/`))
    .map((s) => s.url.replace(/^.*\/contents\//, "").replace(/\?.*$/, ""));
  assert.ok(updates.length > 0, "fixture: the case root is updated");
  assert.deepEqual([...new Set(updates)], [C.casePath(c.id)]);
});

test("R-PIN 3: the page never prints \"anchored\", even beside a daily anchor record naming the pin's head, and prints the fixed ots verify sentence once", async () => {
  const c = await sealedCase("RPIN no anchored");
  dailyAnchor(DAY(c.id));
  const page = await casePage(c.id);
  assert.equal(page.status, 200);
  assert.doesNotMatch(page.html, /anchored/i);
  const plain = pagePlain(page.html);
  assert.equal(plain.split(OTS).length - 1, 1, plain.slice(0, 3000));
});

test("R-PIN 4: a reference row is written on a sealed case that is not pinned", async () => {
  const c = await sealedUnpinned("RPIN row unpinned");
  const r = await reference(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
});

test("R-PIN 5: a reference row is written when a daily anchor record conflicts with the pin", async () => {
  const c = await sealedCase("RPIN row anchor conflict");
  const p = pinFile(c.id);
  const ours = gh.read(PINS, p);
  const set = (rec) => {
    gh._repoMap(PINS).get(p).content = JSON.stringify(rec, null, 2) + "\n";
    return gh.addCommit(PINS, p, "mock: the pin record rewritten");
  };
  const other = set({ ...ours, chain: sha("another chain") });
  dailyAnchor(DAY(c.id), other);
  set(ours);
  const r = await reference(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.equal("row_commit" in r.body, false, "the row's answer carries no row_commit");
});

test("R-PIN 6: a reference request reads no pin and no anchor path", async () => {
  const c = await sealedCase("RPIN row reads");
  dailyAnchor(DAY(c.id));
  const seen = await spyRequests(async () => {
    assert.equal((await reference(c)).status, 201);
  });
  const touched = seen.filter((s) => s.url.includes("pins/case/") || s.url.includes("anchors"));
  assert.deepEqual(touched.map((s) => `${s.method} ${s.url}`), []);
});

test("R-PIN 7: a pin without case_commit is unreadable", async () => {
  const c = await sealedCase("RPIN no case commit");
  const p = pinFile(c.id);
  const { case_commit, ...rest } = gh.read(PINS, p);
  assert.match(case_commit, /^[0-9a-f]{40}$/, "fixture");
  gh.seed(PINS, p, rest, { keepHistory: true });
  const st = await pinRead(c.id, storedCase(c.id));
  assert.equal(st.pin, "unreadable", JSON.stringify(st));
});

test("R-PIN 8: the sealer's candidates are the case roots with no pin file; registration files make no candidate", async () => {
  const id = "a".repeat(64);
  const pinned = "b".repeat(64);
  const files = "c".repeat(64);
  const entries = [
    { path: C.casePath(id), type: "blob" },
    { path: C.casePath(pinned), type: "blob" }, { path: pinFile(pinned), type: "blob" },
    { path: `registrations/${files}/a/${"1".repeat(64)}.json`, type: "blob" }, { path: `registrations/${files}/b/${"2".repeat(64)}.json`, type: "blob" },
    { path: `cases/${files}/commit_a.json`, type: "blob" }, { path: `cases/${files}/commit_b.json`, type: "blob" },
  ];
  assert.deepEqual(S.caseTreeIndex(entries).candidates, [id]);
});

test("R-PIN 9: the status row has no pending count", () => {
  const sum = S.caseAnchorSummary([{ path: C.casePath("a".repeat(64)), type: "blob" }]);
  assert.equal("pending" in sum, false, JSON.stringify(sum));
  assert.deepEqual(sum, { case_files: 1, pinned: 0, withdrawn: 0, partial: false });
});

test("R-PIN 10: two page requests read the store twice", async () => {
  const c = await sealedCase("RPIN page reads");
  const count = async () => {
    const from = gh.getLog.length;
    const page = await casePage(c.id);
    assert.equal(page.status, 200);
    return gh.getLog.length - from;
  };
  const first = await count();
  const second = await count();
  assert.ok(first > 1, `fixture: a page reads more than the case file (${first})`);
  assert.equal(second, first, "the second page is not served from a cache");
});

// =============================================================================
// MUST-FAIL GAP (unit R-PIN): the planted defects the suite above let through
// =============================================================================

test("MUST-FAIL GAP (S02): only pins/case/<id>/00000001.json is a case's pin: a root with only a preview's latest.json or 00000002.json is a candidate, never counted pinned", () => {
  const id = "d".repeat(64);
  const entries = [{ path: C.casePath(id), type: "blob" },
    { path: `pins/case/${id}/latest.json`, type: "blob" }, { path: `pins/case/${id}/00000002.json`, type: "blob" }];
  const idx = S.caseTreeIndex(entries);
  assert.deepEqual([idx.candidates, [...idx.pinned]], [[id], []]);
  assert.equal(S.caseAnchorSummary(entries).pinned, 0);
});

test("MUST-FAIL GAP (S10): pinChain writes no pin for a case commit that is not 40 lowercase hex", async () => {
  const c = await sealedUnpinned("RPIN gap commit not hex");
  const chain = S.caseChain(storedCase(c.id));
  for (const bad of ["c".repeat(39), "C".repeat(40), `${"c".repeat(40)}\n`]) {
    assert.deepEqual(await S.pinChain(c.id, chain, REVEAL_AT, bad), { pin: "commit_unrecorded", reason: "case_commit_unknown" }, JSON.stringify(bad));
  }
  assert.deepEqual(pinTree(c.id), [], "no pin written");
});

test("MUST-FAIL GAP (S24): the sealer's candidates are sorted, whatever order the tree lists them in", () => {
  const ids = ["f", "1", "a"].map((x) => x.repeat(64));
  assert.deepEqual(S.caseTreeIndex(ids.map((id) => ({ path: C.casePath(id), type: "blob" }))).candidates, ids.slice().sort());
});

test("MUST-FAIL GAP (S25, S29): a root with the withdrawn marker is counted withdrawn and never pinned, by the sealer's run and by the status row, a pin file beside it notwithstanding", async () => {
  const id = "e".repeat(64);
  const entries = [{ path: C.casePath(id), type: "blob" }, { path: pinFile(id), type: "blob" }, { path: C.withdrawnMarkerPath(id), type: "blob" }];
  assert.deepEqual([S.caseAnchorSummary(entries).pinned, S.caseAnchorSummary(entries).withdrawn], [0, 1]);
  for (const e of entries) gh.seed(PINS, e.path, { planted: e.path });
  const run = await sealerRun();
  assert.deepEqual([run.candidates, run.pinned, run.withdrawn_skipped], [0, 0, 1]);
});

test("MUST-FAIL GAP (P02): a reference row's link is the history of its file, which names the commit that wrote it", async () => {
  const c = await sealedCase("RPIN gap row link");
  assert.equal((await reference(c)).status, 201);
  const html = (await casePage(c.id)).html;
  assert.ok(html.includes(`href="https://github.com/${PINS}/commits/${store.BRANCH}/${C.referencePath(c.id, 1)}"`), "the row's history");
  assert.ok(!html.includes(`/blob/${store.BRANCH}/${C.referencePath(c.id, 1)}`));
});

test("MUST-FAIL GAP (P03): a pin commit the repository gave no time for says so, never an empty time", () => {
  const html = CP._internal.cells.pin({ pin: "pinned", pin_commit: { sha: "a".repeat(40), date: null }, case_commit: "b".repeat(40) });
  assert.ok(html.includes("(the pins repository&#39;s commit time, a time the repository did not give)"), html);
});

test("MUST-FAIL GAP (A02): a tree that cannot be read fills the status page's case row across its three count columns", async () => {
  const statusHandler = require("../api/status.js");
  gh.treeStatus = 502;
  const res = makeRes();
  await statusHandler(makeReq({ method: "GET", headers: { "x-forwarded-for": nextIp() } }), res);
  const page = String(res._body);
  assert.match(page, /<th>where<\/th><th>case files<\/th><th>pin files<\/th><th>withdrawal markers<\/th>/);
  assert.match(page, /<td><code>pins\/case\/<\/code><\/td><td colspan="3">case anchors not counted: /);
});

// =============================================================================
// UNIT R-PINf: two follow-ups from R-PIN's reader
// =============================================================================

test("R-PINf f1: a pin create the store answers 409 on every attempt, with no file at the path on the re-read, is commit_unrecorded, never conflict: the reveal answers 201 with pin commit_unrecorded, and no pin file exists", async () => {
  const attempts = store._putRetry.maxAttempts;
  const c = await committedCase("RPINf f1 reveal");
  gh.forceConflict(PINS, pinFile(c.id), attempts);
  const r = await reveal(c);
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.deepEqual([r.body.pin, r.body.pin_commit], ["commit_unrecorded", null]);
  assert.deepEqual(pinTree(c.id), [], "no pin file");
  // pinChain itself, on a sealed case its reveal did not pin
  const u = await sealedUnpinned("RPINf f1 pinChain");
  gh.forceConflict(PINS, pinFile(u.id), attempts);
  assert.deepEqual(await S.pinChain(u.id, S.caseChain(storedCase(u.id)), REVEAL_AT, gh.commitsFor(PINS, C.casePath(u.id))[0].sha),
    { pin: "commit_unrecorded", reason: "store_conflict" });
  assert.deepEqual(pinTree(u.id), []);
});

test("R-PINf f2: the fixed sentence is printed once, directly under the pin line, in the pin's own cell", async () => {
  const c = await sealedCase("RPINf f2 sentence");
  const html = (await casePage(c.id)).html;
  const cell = /<tr><th>pin<\/th><td>([\s\S]*?)<\/td><\/tr>/.exec(html);
  assert.ok(cell, "the pin row");
  assert.match(cell[1], /^Pinned at commit <a [^>]+>[0-9a-f]{12}<\/a> \(the pins repository&#39;s commit time, [^)]+\)<br><span class="muted">/);
  assert.equal(pagePlain(cell[1]).includes(OTS), true, pagePlain(cell[1]));
  assert.equal(pagePlain(html).split(OTS).length - 1, 1, "printed once");
});

test("R-PINf f2: a pin found already written is held as the page holds it: a pin naming another commit for the case file is pin_commit_mismatch, never pinned; one naming the right commit is pinned, naming the commit that wrote it", async () => {
  const u = await sealedUnpinned("RPINf f2 found");
  const chain = S.caseChain(storedCase(u.id));
  const opened = gh.commitsFor(PINS, C.casePath(u.id)).slice(-1)[0].sha; // the case file as opened
  gh.seed(PINS, pinFile(u.id), S._internal.pinRecord(u.id, chain, REVEAL_AT, opened));
  const p = await S.pinChain(u.id, chain, REVEAL_AT + 60000, gh.commitsFor(PINS, C.casePath(u.id))[0].sha);
  assert.deepEqual([p.pin, p.reason, p.case_commit], ["pin_commit_mismatch", "case_at_commit_differs", opened], JSON.stringify(p)); // MUST-FAIL GAP F06
  const run = await S.anchorCase(u.id, { now: REVEAL_AT + 60000, keyDocument: DOC });
  assert.deepEqual([run.ok, run.code, run.reason], [false, "pin_commit_mismatch", "case_at_commit_differs"]);
  // the right commit
  const sealedAt = gh.commitsFor(PINS, C.casePath(u.id))[0].sha;
  gh.seed(PINS, pinFile(u.id), S._internal.pinRecord(u.id, chain, REVEAL_AT, sealedAt));
  const ok = await S.pinChain(u.id, chain, REVEAL_AT + 120000, sealedAt);
  assert.deepEqual([ok.pin, ok.existing, ok.written, ok.pin_commit], ["pinned", true, false, gh.commitsFor(PINS, pinFile(u.id)).slice(-1)[0].sha]);
});

test("R-PINf f2: the status page and the README claim no more than the tree shows: pin files and withdrawal markers are counted by path, and a sealed case has at most one pin", async () => {
  const statusHandler = require("../api/status.js");
  const res = makeRes();
  await statusHandler(makeReq({ method: "GET", headers: { "x-forwarded-for": nextIp() } }), res);
  const page = String(res._body).replace(/\s+/g, " ");
  assert.ok(page.includes("<thead><tr><th>where</th><th>case files</th><th>pin files</th><th>withdrawal markers</th></tr></thead>"), "the column heads");
  assert.ok(page.includes("<em>pin files</em> counts the case files whose pin file, <code>pins/case/&lt;case_id&gt;/00000001.json</code>, the tree lists; " +
    "whether a pin holds its case, only the case's own page reads."), "pin files");
  assert.ok(page.includes("<em>withdrawal markers</em> counts the case files whose withdrawal marker the tree lists."), "markers");
  for (const said of ["is pinned by its own pin", "<em>Pinned</em> means", "cases carry the withdrawal marker"]) assert.equal(page.includes(said), false, said);
  assert.equal(S.ANCHOR_NOTE, "A sealed case's pin, when it has one, is pins/case/<case_id>/00000001.json, written once by this service. It is its own " +
    "record, not a log-tree leaf: the witness log's v1 leaves are pins/<namespace>/<seq>.json one level deep.");
  const readme = README();
  assert.ok(readme.includes("A sealed case has at most one pin, `pins/case/<case_id>/00000001.json`, written once"), "at most one");
  assert.ok(readme.includes("This service writes nothing else under a case's pin namespace"));
  for (const said of ["A sealed case has exactly one pin", "Nothing else is ever written under a case's pin"]) assert.equal(readme.includes(said), false, said);
});

test("MUST-FAIL GAP (F05, unit R-PINf): a pin found, and not found when it is read again, is commit_unrecorded (pin_not_found), never not_pinned", async () => {
  const u = await sealedUnpinned("RPINf gap vanished");
  const chain = S.caseChain(storedCase(u.id));
  const sealedAt = gh.commitsFor(PINS, C.casePath(u.id))[0].sha;
  gh.seed(PINS, pinFile(u.id), S._internal.pinRecord(u.id, chain, REVEAL_AT, sealedAt));
  // the second read of the pin file (pinState's) answers 404
  const viaMock = global.fetch;
  let reads = 0;
  global.fetch = async (url, o) => {
    if (((o && o.method) || "GET") === "GET" && String(url).includes(`/contents/${pinFile(u.id)}`) && ++reads === 2) {
      return { ok: false, status: 404, json: async () => ({ message: "Not Found" }), text: async () => "Not Found" };
    }
    return viaMock(url, o);
  };
  let p;
  try {
    p = await S.pinChain(u.id, chain, REVEAL_AT + 60000, sealedAt);
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(reads, 2, "fixture: found, then read again");
  assert.deepEqual(p, { pin: "commit_unrecorded", reason: "pin_not_found" });
});
