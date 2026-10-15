// test/case_rpage.test.js — unit R-PAGE (2026-10-15; the architect's
// rulings): the case page prints only what the record proves and names what
// it did not check: a code on every refusal page (P1), where the record is
// recorded (P2), when the page was read (P3), the stored status of an
// expired case (P4), the bytes read and a JSON twin (P5), the operator's
// contact and relative times (P6), what presence in the record means (P7),
// and the checks that ran on this request (P8). Each test fails on
// 0869c9d. The setup below is test/case_rfg.test.js's.
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
const CASE_KEY = checkpoint.generateKey("arcaeon.io/case-test/2026-10-15rwide");
const RECEIPT_KEY = checkpoint.generateKey("arcaeon.io/reconcile-test/2026-10-15rwide");
const LOG_KEY = checkpoint.generateKey("arcaeon.io/log-test/2026-10-15rwide");
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
  return `10.95.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
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
async function withdraw(id, p, { now = NOW + 2000, env = KEYS, salt = p.salt, reason } = {}) {
  const res = makeRes();
  const body = { case_id: id, role: p.role, tape_sha256: p.tape_sha256, salt, ...(reason === undefined ? {} : { reason }) };
  await H.handleCaseWithdraw(req("case-withdraw", body), res, { now, env: KD.deployed(gh, env, DOC), keyDocument: DOC });
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
async function reference(c, { role = "a", env = KEYS, now = REVEAL_AT + 1800000, deploy = true } = {}) {
  const p = c[role];
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, role, tape_sha256: p.tape_sha256, salt: p.salt, cross_reference: XREF }),
    res, { now, env: deploy ? KD.deployed(gh, env, DOC) : env, keyDocument: DOC });
  return { status: res._status, body: parsed(res) };
}
// The operator's reference (no proof; the operator's bearer key).
const OPERATOR_KEY = "case-operator-key-0171-rwide";
async function operatorReference(c, { now = REVEAL_AT + 1800000 } = {}) {
  const res = makeRes();
  await H.handleCaseReference(req("case-reference", { case_id: c.id, cross_reference: { ...XREF, reference: "operator-ref" } },
    { authorization: `Bearer ${OPERATOR_KEY}` }), res, { now, env: KD.deployed(gh, { ...KEYS, [H.OPERATOR_KEY_ENV]: OPERATOR_KEY }, DOC), keyDocument: DOC });
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
// UNIT R-SIG
// =============================================================================

const checkRecord = require("../lib/_check_record.js");
const LATER = checkpoint.generateKey("arcaeon.io/case-test/2026-10-15rwide-later");
// The current document lists a case key that the document a record names
// did not: one published only later.
const CURRENT = Object.freeze(KD.docWith(KD.entry(CASE_KEY), KD.entry(LATER), KD.reconcileEntry(RECEIPT_KEY)));
const suOf = (doc) => ({ document_sha256: KD.sha256(canonicalBytes(doc)), document_commit: KD.serve(gh, doc) });
const laterSigner = () => {
  const signer = S.loadCaseSigner({ ...KEYS, [S.CASE_SIGNER_ENV]: LATER.signer }, { keyDocument: CURRENT });
  assert.equal(signer.ok, true, JSON.stringify(signer));
  return signer;
};
// A record signed by hand as the service signs one: signed_by, sig_reason
// null, and the signature over the record minus sig.
function signByHand(unsigned, signer) {
  const rec = { ...unsigned, signed_by: signer.keyId, sig_reason: null, sig: null };
  rec.sig = crypto.sign(null, checkRecord.preimage(rec), signer.privateKey).toString("base64");
  return rec;
}
function withoutSig(rec) {
  const { sig: _s, signed_by: _b, sig_reason: _r, ...rest } = rec; // eslint-disable-line no-unused-vars
  return rest;
}
const flipSig = (rec) => {
  const b = Buffer.from(rec.sig, "base64");
  b[10] ^= 1;
  return { ...rec, sig: b.toString("base64") };
};
async function pageUnder(id, doc, now = REVEAL_AT + 3600000) {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id }, headers: { "x-forwarded-for": nextIp() } }), res,
    { now, keyDocument: doc, env: {} });
  return { status: res._status, html: String(res._body) };
}
const cell = (html, name) => {
  const m = html.match(new RegExp(`<tr><th>${name}</th><td>(.*?)</td></tr>`));
  return m ? m[1] : null;
};
const statusHandler = require("../api/status.js");

const NO_RECONCILE = Object.freeze(KD.docWith(KD.entry(CASE_KEY)));
async function withdrawnBy(scope, role) {
  const c = await committedCase(scope);
  assert.equal((await withdraw(c.id, c[role])).status, 201);
  return c;
}
async function statusHtml() {
  const res = makeRes();
  await statusHandler(makeReq({ method: "GET", query: {}, headers: { "x-forwarded-for": nextIp() } }), res);
  return String(res._body);
}
// The deployment's own commit off the published branch, for the status page.
async function withDeployCommit(commit, fn) {
  const before = process.env[S.DEPLOY_COMMIT_ENV];
  process.env[S.DEPLOY_COMMIT_ENV] = commit;
  try {
    return await fn();
  } finally {
    if (before === undefined) delete process.env[S.DEPLOY_COMMIT_ENV];
    else process.env[S.DEPLOY_COMMIT_ENV] = before;
  }
}



// =============================================================================
// UNIT R-PAGE
// =============================================================================

const ratelimit = require("../lib/_ratelimit.js");
const AT = REVEAL_AT + 3600000; // casePage's clock: 2026-10-10T10:00:00Z
const iso = (ms) => new Date(ms).toISOString();
const OWNER = PINS.split("/")[0];
const caseBlob = (id) => gh._repoMap(PINS).get(C.casePath(id));
const caseBytes = (id) => Buffer.from(caseBlob(id).content, "utf8");
async function viewAs(id, { now = AT, format, doc = DOC, cache } = {}) {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: id, ...(format ? { format } : {}) }, headers: { "x-forwarded-for": nextIp() } }), res,
    { now, keyDocument: doc, env: {}, ...(cache ? { cache } : {}) });
  return { status: res._status, body: res._body, html: typeof res._body === "string" ? res._body : null, headers: res._headers };
}
async function limited(fn) {
  const real = ratelimit.check;
  ratelimit.check = async () => ({ limited: true, retryAfterSeconds: 7, limit: 60, windowSeconds: 600 });
  try {
    return await fn();
  } finally {
    ratelimit.check = real;
  }
}
// The "Where this is recorded" table's body rows, each cell's text.
function whereRows(html) {
  const at = html.indexOf("<h2>Where this is recorded</h2>");
  if (at < 0) return null;
  const sec = html.slice(at, html.indexOf("</section>", at));
  return [...sec.matchAll(/<tr>(.*?)<\/tr>/g)].map((m) => [...m[1].matchAll(/<td>(.*?)<\/td>/g)].map((c) => c[1].replace(/<[^>]+>/g, ""))).filter((r) => r.length);
}
// The "The following checks were performed on this record:" list: each
// line's text and its code.
function checkLines(html) {
  const at = html.indexOf("The following checks were performed on this record:");
  if (at < 0) return null;
  const list = html.slice(at, html.indexOf("</ul>", at));
  return [...list.matchAll(/<li>(.*?)<\/li>/g)].map((m) => ({ text: m[1].replace(/<[^>]+>/g, ""), code: (m[1].match(/<code>([^<]*)<\/code>$/) || [])[1] }));
}
const CONTACT = "Report a problem with this case to the operator: <a href=\"mailto:hello@arcaeon.io\" rel=\"nofollow noopener noreferrer\">hello@arcaeon.io</a>";
const readAt = (ms) => `This page was read at <time datetime="${iso(ms)}">${iso(ms)}</time> (UTC)`;
const EXPIRED_BY_CLOCK = "(EXPIRED by this service&#39;s clock)";

test("R-PAGE P1: every refusal page names its code: not_a_case_id, rate_limited, no_such_case, could_not_look, case_unreadable, and the case states' document_unavailable and signer_revoked", async () => {
  const has = (r, status, code) => {
    assert.equal(r.status, status, code);
    assert.ok(r.html.includes(`<code>${code}</code>`), `${code}: ${r.html.slice(r.html.indexOf("<h1>"), r.html.indexOf("<h1>") + 300)}`);
  };
  has(await viewAs("not-a-case-id"), 400, "not_a_case_id");
  has(await limited(() => viewAs("a".repeat(64))), 429, "rate_limited");
  has(await viewAs("b".repeat(64)), 404, "no_such_case");
  gh.forceGetFailure(PINS, C.casePath("c".repeat(64)), 1, 502);
  has(await viewAs("c".repeat(64)), 503, "could_not_look");
  gh.seed(PINS, C.casePath("d".repeat(64)), { not: "a case" });
  has(await viewAs("d".repeat(64)), 503, "case_unreadable");
  // a sealed case whose named document cannot be read, and one a revoked key signed
  const s = await sealedCase("RPAGE P1 states");
  S._internal.clearDocumentCache();
  gh.forceRawFailure(1000, 503);
  let r;
  try {
    r = await viewAs(s.id);
  } finally {
    gh.forceRawFailure(0);
  }
  has(r, 503, "document_unavailable");
  S._internal.clearDocumentCache();
  has(await viewAs(s.id, { doc: KD.docWith(KD.entry(CASE_KEY, { status: "revoked" }), KD.reconcileEntry(RECEIPT_KEY)) }), 200, "signer_revoked");
});

test("R-PAGE P1: GET /status rate limited answers 429 {ok: false, error_code: rate_limited, retry_after_seconds}, codes only", async () => {
  const res = makeRes();
  await limited(() => statusHandler(makeReq({ method: "GET", query: {}, headers: { "x-forwarded-for": nextIp() } }), res));
  assert.deepEqual([res._status, res._body], [429, { ok: false, error_code: "rate_limited", retry_after_seconds: 7 }]);
  assert.equal(res._headers["retry-after"], "7");
});

// A sealed case the reveal pinned, with its pin file taken out of the mock
// store: the page reads not_pinned (nothing is removed from any repository).
const unpinned = (id) => gh._repoMap(PINS).delete(pinFile(id));

test("R-PAGE P2: the sealed page's 'Where this is recorded' table: the case file, the pin once pinned, and each role's stamp; no anchor row (the page reads no anchor) and no new read", async () => {
  const c = await sealedCase("RPAGE P2");
  const kase = storedCase(c.id);
  const stampRow = (k, r) => [esc(`stamps repository: role ${r}'s stamp`), `commit ${k.commitments[r].stamp_commit.slice(0, 12)}`,
    `${k.commitments[r].stamped_at} as the case record has it`, `${OWNER} on GitHub`, "the stamp commit"];
  const pin = await pinRead(c.id, kase);
  assert.equal(pin.pin, "pinned");
  const g0 = gh.getLog.length;
  const r0 = gh.rawLog.length;
  const html = (await viewAs(c.id)).html;
  assert.deepEqual(whereRows(html), [
    // "time not given" since unit R-PAGEf (m1): the file was read, and the read gives no time
    ["pins repository: the case file", `commit ${pin.case_commit.slice(0, 12)}, named by the pin`, "time not given", `${OWNER} on GitHub`, "the case file"],
    ["pins repository: the pin", `commit ${pin.pin_commit.sha.slice(0, 12)}`, `${pin.pin_commit.date} (the pins repository&#39;s commit time)`, `${OWNER} on GitHub`, "the pin commit"],
    stampRow(kase, "a"), stampRow(kase, "b"),
  ]);
  // the page's reads are the ones it made before R-PAGE: the case file, the
  // two registration files, the pin file and the rows listing, and (raw) the
  // pin and the case file at their commits; no anchor
  assert.deepEqual(gh.getLog.slice(g0).map((p) => p.replace(c.id, "ID").replace(/[0-9a-f]{64}/g, "H")),
    ["cases/ID.json", "registrations/ID/a/H.json", "registrations/ID/b/H.json", "pins/case/ID/00000001.json", "cases/ID/references"]);
  // (raw reads at a commit are kept per instance, so the test's own pin read
  // above may have made them; none is an anchor's)
  for (const k of gh.rawLog.slice(r0)) assert.match(k.replace(c.id, "ID"), new RegExp(`^${PINS}@[0-9a-f]{40}:(pins/case/ID/00000001\\.json|cases/ID\\.json)$`), k);
  assert.doesNotMatch(html, /<td>[^<]*anchor[^<]*<\/td>/i);
  for (const row of whereRows(html)) for (const v of row) assert.ok(v.trim() !== "", "no empty cell");
  // no pin: the case file as read on the branch, no pin row, nothing empty
  const u = await sealedCase("RPAGE P2 no pin");
  unpinned(u.id);
  const uk = storedCase(u.id);
  const rows = whereRows((await viewAs(u.id)).html);
  assert.deepEqual(rows, [
    ["pins repository: the case file", `blob ${caseBlob(u.id).sha.slice(0, 12)} on main, the bytes this page read`, "time not given", `${OWNER} on GitHub`, "the case file"],
    stampRow(uk, "a"), stampRow(uk, "b"),
  ]);
  for (const row of rows) for (const v of row) assert.ok(v.trim() !== "", "no empty cell");
});

test("R-PAGE P3: the footer prints when the page was read, as the status page prints when it was rendered; the pin row and the key-document row say when they were last read", async () => {
  const c = await sealedCase("RPAGE P3");
  // (since unit R-PAGEf, B2, the key-document row prints when the document
  // was read: the reveal kept it, so the page reads it again only once the
  // instance's cache is cleared)
  S._internal.clearDocumentCache();
  const html = (await viewAs(c.id)).html;
  assert.ok(html.includes(`may be up to 60 seconds old &middot; ${readAt(AT)}`), html.slice(html.indexOf("<footer>")));
  assert.ok(cell(html, "pin").endsWith(`<span class="muted">last read ${iso(AT)}</span>`), cell(html, "pin"));
  assert.ok(cell(html, "key document").endsWith(`<span class="muted">last read ${iso(AT)}</span>`), cell(html, "key document"));
  // a refusal page too
  assert.ok((await viewAs("e".repeat(64), { now: AT + 5000 })).html.includes(readAt(AT + 5000)));
});

test("R-PAGE P4: an expired case keeps its stored status: COMMITTED (EXPIRED by this service's clock), OPEN likewise, never EXPIRED alone; the pending sentence for COMMITTED only", async () => {
  const late = Date.parse(DEADLINE) + 3600000;
  const committed = await committedCase("RPAGE P4 committed");
  const open = await openCase("RPAGE P4 open");
  for (const [id, stored] of [[committed.id, "COMMITTED"], [open, "OPEN"]]) {
    const html = (await viewAs(id, { now: late })).html;
    assert.equal(cell(html, "status"), `<span class="word">${stored}</span> ${EXPIRED_BY_CLOCK}`, stored);
    assert.ok(html.includes(`<h1>Case: ${stored} ${EXPIRED_BY_CLOCK}</h1>`), stored);
    assert.doesNotMatch(html, /<span class="word">EXPIRED<\/span>|Case: EXPIRED</, stored);
    assert.equal(html.includes(esc("this page cannot tell whether one is pending.")), stored === "COMMITTED", stored);
  }
});

test("R-PAGE P5: the page prints the sha256 of the case file's bytes it read and links the raw file; ?format=json answers the same state, status, counts and codes", async () => {
  const c = await sealedCase("RPAGE P5");
  const v = await viewAs(c.id);
  const h = sha(caseBytes(c.id));
  assert.ok(v.html.includes(`<code>${h}</code>`), "the hash");
  assert.ok(v.html.includes(`href="https://raw.githubusercontent.com/${PINS}/main/${C.casePath(c.id)}"`), "the raw link");
  const j = await viewAs(c.id, { format: "json" });
  assert.equal(j.status, v.status);
  assert.match(String(j.headers["content-type"]), /^application\/json/);
  assert.equal(j.body.case_sha256, h);
  assert.deepEqual([j.body.ok, j.body.case_id, j.body.state, j.body.status_as_stored, j.body.read_at], [true, c.id, "VERDICT", "VERDICT", iso(AT)]);
  assert.equal(j.body.verdict, "MATCHED");
  assert.deepEqual(j.body.records, { valid: 0, invalid: 0, unreadable: 0, unread: 0, at_row_limit: false });
  assert.equal(v.html.includes(esc("no reference row was appended")), true);
  const pin = await pinRead(c.id, storedCase(c.id));
  assert.deepEqual(j.body.pin, { state: "pinned", pin_commit: pin.pin_commit.sha, case_commit: pin.case_commit });
  assert.ok(v.html.includes(`Pinned at commit <a href="https://github.com/${PINS}/commit/${pin.pin_commit.sha}"`), "the page says pinned too");
  assert.deepEqual(j.body.checks.map((x) => x.code), checkLines(v.html).map((x) => x.code));
  // a refusal answers its code
  const miss = await viewAs("f".repeat(64), { format: "json" });
  assert.deepEqual([miss.status, miss.body], [404, { ok: false, error_code: "no_such_case", read_at: iso(AT) }]);
  const bad = await viewAs("nope", { format: "json" });
  assert.deepEqual([bad.status, bad.body], [400, { ok: false, error_code: "not_a_case_id", read_at: iso(AT) }]);
});

test("R-PAGE P6: every page, a refusal too, says where to report a problem; a time row prints relative and absolute", async () => {
  const c = await sealedCase("RPAGE P6");
  const w = await withdrawnBy("RPAGE P6 withdrawn", "a");
  const pages = [await viewAs(c.id), await viewAs(w.id), await viewAs(await openCase("RPAGE P6 open")), await viewAs("nope"), await viewAs("9".repeat(64)),
    await limited(() => viewAs("8".repeat(64))), await viewAs((await committedCase("RPAGE P6 expired")).id, { now: Date.parse(DEADLINE) + 1000 })];
  for (const p of pages) assert.ok(p.html.includes(CONTACT), p.html.slice(p.html.indexOf("<h1>"), p.html.indexOf("<h1>") + 80));
  const html = pages[0].html;
  assert.equal(cell(html, "opened at"), "2 hours ago (2026-10-10T07:30:00Z) <span class=\"muted\">(the opener's clock, an assertion)</span>");
  assert.equal(cell(html, "deadline"), "in 10 hours (2026-10-10T20:00:00Z)");
  assert.equal(cell(html, "revealed at"), "1 hour ago (2026-10-10T09:00:00Z)");
  // the contact is the one PRACTICES.md publishes
  assert.ok(read("public/PRACTICES.md").includes("hello@arcaeon.io"));
});

test("R-PAGE P7: next to 'Labels are recorded, not verified.', the page and the README say what presence in the record is", async () => {
  const PRESENCE = "Presence in this record is not meaning: a public record keeps what was submitted to it.";
  const html = (await viewAs((await committedCase("RPAGE P7")).id)).html;
  assert.ok(html.includes(`${esc(CP.LABELS_SENTENCE)} ${esc(PRESENCE)}`), "the page");
  assert.ok(README().includes(`${CP.LABELS_SENTENCE} ${PRESENCE}`), "the README");
});

test("R-PAGE P8: the checks that ran on this request, each from its result and bound to the bytes it covers; a check that did not run has no line, a failed one its code", async () => {
  const c = await sealedCase("RPAGE P8");
  const kase = storedCase(c.id);
  const H = sha(caseBytes(c.id));
  const X = kase.signed_under.document_commit;
  const regSha = (r) => {
    const e = kase.commitments[r];
    return sha(Buffer.from(gh._repoMap(PINS).get(C.registrationPath(c.id, r, e.claim_sha256)).content, "utf8"));
  };
  const pin = await pinRead(c.id, kase);
  const lines = checkLines((await viewAs(c.id)).html);
  assert.deepEqual(lines, [
    { text: `the sealed record: the case file this page read (sha256 ${H}) verifies under the key document at commit ${X}, and each key that signed it is listed in its role in the key document this service carries valid_under_document`, code: "valid_under_document" },
    { text: `role a&#39;s registration file: read, the file the case projects (sha256 ${regSha("a")}) matches_projection`, code: "matches_projection" },
    { text: `role b&#39;s registration file: read, the file the case projects (sha256 ${regSha("b")}) matches_projection`, code: "matches_projection" },
    { text: `the pin: this case&#39;s pin file, written at commit ${pin.pin_commit.sha}, names commit ${pin.case_commit}, where the case file is this case in canonical form (json-c14n:v1) pinned`, code: "pinned" },
    { text: "the reference rows: 0 listed, 0 read, 0 valid read", code: "read" },
  ]);
  assert.ok(!lines.some((l) => /anchor|stamp/.test(l.text)), "no anchor or stamp check ran");
  // no pin file: the pin line from the pin read, never "found" from the status
  unpinned(c.id);
  const none = checkLines((await viewAs(c.id)).html).find((l) => l.text.startsWith("the pin:"));
  assert.deepEqual(none, { text: "the pin: no pin file is present under this case&#39;s namespace not_pinned", code: "not_pinned" });
  // a withdrawn case: its record's check alone (no pin, row or registration read)
  const w = await withdrawnBy("RPAGE P8 withdrawn", "b");
  const wk = storedCase(w.id);
  assert.deepEqual(checkLines((await viewAs(w.id)).html), [
    { text: `the withdrawal record: the case file this page read (sha256 ${sha(caseBytes(w.id))}) verifies under the key document at commit ${wk.signed_under.document_commit} valid_under_document`, code: "valid_under_document" },
  ]);
  // a sealed record that does not verify: listed with its code; the pin and rows were not read, so no line
  const t = await sealedCase("RPAGE P8 tampered");
  const tk = storedCase(t.id);
  gh.seed(PINS, C.casePath(t.id), flipSig(tk));
  const tl = checkLines((await viewAs(t.id)).html);
  assert.equal(tl[0].code, "signature_invalid");
  assert.ok(tl[0].text.startsWith("the sealed record: does not verify ("), tl[0].text);
  assert.ok(!tl.some((l) => /^the (pin|reference rows):/.test(l.text)), JSON.stringify(tl));
});

// R-PAGE's must-fail gap tests: each fails with its planted defect
test("MUST-FAIL GAP (PG29): a page kept in the page cache answers ?format=json from the cache too, the same twin", async () => {
  const c = await sealedCase("RPAGE gap cache");
  const cache = CP.pageCache({ clock: () => AT });
  const first = await viewAs(c.id, { cache, format: "json" });
  const g0 = gh.getLog.length;
  const again = await viewAs(c.id, { cache, format: "json" });
  assert.equal(gh.getLog.length, g0, "fixture: the second view is the cache's");
  assert.deepEqual([again.status, again.body], [first.status, first.body]);
  assert.equal(again.body.case_sha256, sha(caseBytes(c.id)));
});

test("MUST-FAIL GAP (PG30): a case file that is not JSON is case_unreadable (a record is there), never could_not_look", async () => {
  const id = "7".repeat(64);
  gh._repoMap(PINS).set(C.casePath(id), { content: "not json\n", sha: "e".repeat(40) });
  const r = await viewAs(id);
  assert.equal(r.status, 503);
  assert.ok(r.html.includes("<code>case_unreadable</code>") && r.html.includes("(not_json)"), r.html.slice(r.html.indexOf("<h1>"), r.html.indexOf("<h1>") + 400));
  assert.deepEqual((await viewAs(id, { format: "json" })).body, { ok: false, error_code: "case_unreadable", read_at: iso(AT) });
});

test("MUST-FAIL GAP (PG38): a registration time row prints relative and absolute", async () => {
  const c = await committedCase("RPAGE gap registered");
  const html = (await viewAs(c.id)).html;
  const at = storedCase(c.id).commitments.a.registered_at;
  assert.ok(cell(html, "role a registered at").startsWith(`2 hours ago (${at}) <span class="muted">(stamped `), cell(html, "role a registered at"));
});

test("MUST-FAIL GAP (PG47): the reference rows line counts an invalid row as read and not valid", async () => {
  const c = await sealedCase("RPAGE gap rows");
  gh.seed(PINS, C.referencePath(c.id, 1), { planted: 1 });
  const line = checkLines((await viewAs(c.id)).html).find((l) => l.text.startsWith("the reference rows:"));
  assert.deepEqual(line, { text: "the reference rows: 1 listed, 1 read, 0 valid read", code: "read" });
});

test("MUST-FAIL GAP (PG52): the README names the JSON twin", () => {
  assert.ok(README().includes("`/case/<case_id>?format=json` (`op=case-page&format=json`) answers the same facts as JSON."));
});

test("MUST-FAIL GAP (PG24, PG51): the sha256 the page prints is of the bytes it read, not of their text re-encoded: a case file with a byte that is not UTF-8 in it", async () => {
  const c = await sealedCase("RPAGE gap bytes");
  const rec = caseBlob(c.id);
  // the receipt's claim with one byte that is not UTF-8: the bytes read and
  // their text re-encoded differ (the record no longer verifies)
  const text = rec.content;
  const at = text.indexOf("compared like this at this time.");
  assert.ok(at > 0, "fixture: the receipt's claim");
  const bytes = Buffer.concat([Buffer.from(text.slice(0, at), "utf8"), Buffer.from([0xff]), Buffer.from(text.slice(at), "utf8")]);
  gh.seedBytes(PINS, C.casePath(c.id), bytes);
  const html = (await viewAs(c.id)).html;
  assert.notEqual(sha(bytes), sha(Buffer.from(bytes.toString("utf8"), "utf8")), "fixture: the two differ");
  assert.ok(html.includes(`<code>${sha(bytes)}</code>`), html.slice(html.indexOf("<h1>"), html.indexOf("<h1>") + 300));
});

test("MUST-FAIL GAP (PG31): the JSON twin's pin state is the pin read's: a sealed case with no pin file is not_pinned", async () => {
  const c = await sealedCase("RPAGE gap json pin");
  unpinned(c.id);
  const j = await viewAs(c.id, { format: "json" });
  assert.deepEqual(j.body.pin, { state: "not_pinned" });
  assert.equal(j.body.checks.find((x) => x.check === "pin").code, "not_pinned");
});

// =============================================================================
// UNIT R-PAGEf (2026-10-15; the architect's rulings on the R-PAGE reader's
// findings). Each test fails on 81b4da8.
// =============================================================================

const REVOKED = Object.freeze(KD.docWith(KD.entry(CASE_KEY, { status: "revoked" }), KD.reconcileEntry(RECEIPT_KEY)));
// A case one key registered both roles of (test/case_fix_mutation_gaps.test.js
// racedSingleParty's fixture): role a registers while role b's request reads
// its stamp, and the root is written by hand over the race's files.
async function singlePartyCase(scope) {
  const id = await openCase(scope);
  const a = party(id, "a", AGENT_TAPE, REG.KEYS.a);
  const b = party(id, "b", TOOL_TAPE, REG.KEYS.a);
  plantStamp(a.commitment_sha256);
  plantStamp(b.commitment_sha256);
  const stampGet = (u, m) => m === "GET" && decodeURIComponent(u).includes(`/repos/${STAMPS}/contents/${stamp.stampPath(b.commitment_sha256)}`);
  const r = await during(stampGet, () => commit(id, a), () => commit(id, b));
  assert.equal(r.inner.status, 201, "fixture: a registers");
  const text = gh._repoMap(PINS).get(REG.pathOf(gh, id, "b")).content;
  gh.seed(PINS, C.casePath(id), C.applyRegistration(storedCase(id), JSON.parse(text), sha(Buffer.from(text, "utf8"))), { keepHistory: true });
  assert.equal(C.singleParty(storedCase(id)), true, "fixture: single party");
  return { id, a, b };
}
// The page and its JSON twin, each read with `arm` run first (a read made
// to fail, a cache cleared) and undone after.
async function bothViews(id, { opts = {}, arm = () => {}, disarm = () => {} } = {}) {
  const one = async (format) => {
    S._internal.clearDocumentCache();
    arm();
    try {
      return await viewAs(id, { ...opts, ...(format ? { format } : {}) });
    } finally {
      disarm();
    }
  };
  const h = await one(null);
  const j = await one("json");
  return { status: h.status, html: h.html, jsonStatus: j.status, json: j.body };
}
const BYTES_PANEL = "<h2>The record this page read</h2>";

// EVERY PAGE STATE (unit R-PAGEf, B1; since unit R-PAGEg, m2, both
// document_off_branch pages at 200 and the unread page on a case that is not
// single party, COMMITTED and VERDICT): {name, prints (the page prints the
// bytes read), id, view (bothViews' arm and opts)}.
const caseSigner = () => S.loadCaseSigner(KEYS, { keyDocument: DOC });
async function pageStates() {
  const docDown = { arm: () => gh.forceRawFailure(1000, 503), disarm: () => gh.forceRawFailure(0) };
  const unreadA = (id) => {
    const ra = REG.pathOf(gh, id, "a");
    return { arm: () => gh.forceGetFailure(PINS, ra, 1, 503), disarm: () => gh.forceGetFailure(PINS, ra, 0) };
  };
  const states = [];
  const add = async (name, prints, id, view = {}) => states.push({ name, prints, id, view });
  await add("OPEN", true, await openCase("RPAGEf B1 open"));
  await add("COMMITTED", true, (await committedCase("RPAGEf B1 committed")).id);
  await add("EXPIRED", true, (await committedCase("RPAGEf B1 expired")).id, { opts: { now: Date.parse(DEADLINE) + 1000 } });
  const s = await sealedCase("RPAGEf B1 sealed");
  await add("VERDICT", true, s.id);
  await add("COULD NOT LOOK (the sealed record)", true, s.id, docDown);
  await add("SIGNED BY A REVOKED KEY (verdict)", false, s.id, { opts: { doc: REVOKED } });
  const w = await withdrawnBy("RPAGEf B1 withdrawn", "a");
  await add("WITHDRAWN", true, w.id);
  await add("COULD NOT LOOK (the withdrawal record)", true, w.id, docDown);
  await add("SIGNED BY A REVOKED KEY (withdrawal record)", false, w.id, { opts: { doc: REVOKED } });
  const wt = await withdrawnBy("RPAGEf B1 withdrawal tampered", "b");
  gh.seed(PINS, C.casePath(wt.id), flipSig(storedCase(wt.id)), { keepHistory: true });
  await add("WITHDRAWAL RECORD DOES NOT VERIFY", false, wt.id);
  const t = await sealedCase("RPAGEf B1 tampered");
  gh.seed(PINS, C.casePath(t.id), flipSig(storedCase(t.id)), { keepHistory: true });
  await add("SEALED RECORD DOES NOT VERIFY", true, t.id);
  const inc = await committedCase("RPAGEf B1 inconsistent");
  gh._repoMap(PINS).delete(REG.pathOf(gh, inc.id, "b"));
  await add("case_record_inconsistent", false, inc.id);
  const sp = await singlePartyCase("RPAGEf B1 single party");
  await add("SINGLE PARTY", false, sp.id);
  const ur = await singlePartyCase("RPAGEf B1 unread");
  const ra = REG.pathOf(gh, ur.id, "a");
  await add("could_not_look (a registration file unread)", false, ur.id, { arm: () => gh.forceGetFailure(PINS, ra, 1, 503), disarm: () => gh.forceGetFailure(PINS, ra, 0) });
  // unit R-PAGEg, m2: both document_off_branch pages, at 200
  const side = KD.serveOffBranch(gh, DOC, "7".repeat(40));
  const offSealed = await sealedCase("RPAGEg m2 off branch sealed");
  const os = storedCase(offSealed.id);
  gh.seed(PINS, C.casePath(offSealed.id), signByHand({ ...withoutSig(os), signed_under: { ...os.signed_under, document_commit: side } }, caseSigner()), { keepHistory: true });
  await add("COULD NOT LOOK, off the branch (the sealed record)", true, offSealed.id);
  const offWithdrawn = await withdrawnBy("RPAGEg m2 off branch withdrawn", "a");
  const ow = storedCase(offWithdrawn.id);
  gh.seed(PINS, C.casePath(offWithdrawn.id), signByHand({ ...withoutSig(ow), signed_under: { ...ow.signed_under, document_commit: side } }, caseSigner()), { keepHistory: true });
  await add("COULD NOT LOOK, off the branch (the withdrawal record)", true, offWithdrawn.id);
  // unit R-PAGEg, m2: role a's file unread on a case that is not single party
  const uc = await committedCase("RPAGEg m2 unread committed");
  await add("COMMITTED, role a's file unread", true, uc.id, unreadA(uc.id));
  const uv = await sealedCase("RPAGEg m2 unread verdict");
  await add("VERDICT, role a's file unread", true, uv.id, unreadA(uv.id));
  return states;
}

test("R-PAGEf B1: the JSON twin carries case_sha256 exactly on the states whose page prints the bytes read; nothing on a refusal page", async () => {
  // (since unit R-PAGEg, m2: the states are pageStates(), above)
  const states = await pageStates();
  for (const st of states) {
    const v = await bothViews(st.id, st.view);
    assert.equal(v.jsonStatus, v.status, st.name);
    if (/off the branch/.test(st.name)) assert.equal(v.status, 200, `${st.name}: a refusal, not a 503`);
    assert.equal(v.html.includes(BYTES_PANEL), st.prints, `${st.name}: the page ${st.prints ? "prints" : "does not print"} the bytes read`);
    assert.equal(v.json.case_sha256 !== undefined, st.prints, `${st.name}: ${JSON.stringify(v.json).slice(0, 200)}`);
  }
});

test("R-PAGEf B1: on a signer_revoked page every field of the JSON twin is on the page, field by field", async () => {
  const s = await sealedCase("RPAGEf B1 revoked fields");
  const v = await bothViews(s.id, { opts: { doc: REVOKED } });
  assert.equal(v.json.error_code, "signer_revoked");
  for (const [k, val] of Object.entries(v.json)) {
    if (k === "ok") continue;
    assert.ok(v.html.includes(esc(String(val))), `${k}: ${val} is not on the page`);
  }
});

// R-L4e's rule (a case_record_inconsistent body is the one code) reaches the
// twin: B1's states drove it to JSON for the first time, and the every-body
// audit read it with the case id and the read time in it.
test("R-PAGEf B1 (R-L4e): the JSON twin of a case_record_inconsistent page is the code only, at 503", async () => {
  const inc = await committedCase("RPAGEf B1 inconsistent twin");
  gh._repoMap(PINS).delete(REG.pathOf(gh, inc.id, "b"));
  const v = await bothViews(inc.id);
  assert.deepEqual([v.status, v.jsonStatus], [503, 503]);
  assert.ok(v.html.includes("<code>case_record_inconsistent</code>"));
  assert.deepEqual(v.json, { ok: false, error_code: "case_record_inconsistent" });
});

test("R-PAGEf B2: the key-document row prints when the document was read, and says so when it came from this instance's cache", async () => {
  const c1 = await sealedCase("RPAGEf B2 one");
  const c2 = await sealedCase("RPAGEf B2 two");
  assert.equal(storedCase(c1.id).signed_under.document_commit, storedCase(c2.id).signed_under.document_commit, "fixture: one commit");
  S._internal.clearDocumentCache();
  const T1 = AT;
  const T2 = AT + 4 * 3600000;
  const first = cell((await viewAs(c1.id, { now: T1 })).html, "key document");
  assert.ok(first.endsWith(`<span class="muted">last read ${iso(T1)}</span>`), first);
  const second = cell((await viewAs(c2.id, { now: T2 })).html, "key document");
  assert.ok(second.endsWith(`<span class="muted">from cache, last read ${iso(T1)}</span>`), second);
  assert.ok(!second.includes(`last read ${iso(T2)}`));
});

test("R-PAGEf M1: a registration file is held to its projection by the sha256 of its bytes: the projected bytes that are not a registration are projection_differs_from_file, never registration_file_differs; the projection answers the bytes' sha256", async () => {
  const c = await committedCase("RPAGEf M1");
  const p = REG.pathOf(gh, c.id, "a");
  const text = gh._repoMap(PINS).get(p).content;
  const at = text.indexOf(c.id);
  const bytes = Buffer.concat([Buffer.from(text.slice(0, at), "utf8"), Buffer.from([0xff]), Buffer.from(text.slice(at), "utf8")]);
  assert.notEqual(sha(bytes), sha(Buffer.from(bytes.toString("utf8"), "utf8")), "fixture: the planted text's sha256 is not the bytes'");
  gh.seedBytes(PINS, p, bytes);
  // the (unsigned, COMMITTED) root projects exactly those bytes
  const k = storedCase(c.id);
  gh.seed(PINS, C.casePath(c.id), { ...k, commitments: { ...k.commitments, a: { ...k.commitments.a, registration_sha256: sha(bytes) } } }, { keepHistory: true });
  const proj = await S.projectedRegistrations(storedCase(c.id));
  assert.deepEqual([proj.ok, proj.role, proj.reason], [false, "a", "projection_differs_from_file"]);
  // an honest case: the projection answers each file's bytes' sha256
  const h = await committedCase("RPAGEf M1 honest");
  const hk = storedCase(h.id);
  const honest = await S.projectedRegistrations(hk);
  for (const r of ["a", "b"]) {
    assert.equal(honest.shas[r], sha(Buffer.from(gh._repoMap(PINS).get(REG.pathOf(gh, h.id, r)).content, "utf8")), r);
    assert.equal(honest.shas[r], hk.commitments[r].registration_sha256, r);
  }
});

test("R-PAGEf M2: a row listed but read 404 is read again on the next attempt: the sender's own row, missed on attempt 1, is found on attempt 2, and no second row is written", async () => {
  const c = await sealedCase("RPAGEf M2");
  const first = await reference(c);
  assert.deepEqual([first.status, first.body.seq], [201, 1]);
  const p1 = C.referencePath(c.id, 1);
  const p2 = C.referencePath(c.id, 2);
  // attempt 1: seq 1 reads 404 (a replica behind the listing), and the write
  // at seq 2 loses to another sender's row
  gh.forceGetFailure(PINS, p1, 1, 404);
  gh.forceConflict(PINS, p2, 1);
  const viaMock = global.fetch;
  let raced = false;
  global.fetch = async (url, o) => {
    if (!raced && ((o && o.method) || "GET") === "PUT" && decodeURIComponent(String(url)).endsWith(`/contents/${p2}`)) {
      raced = true;
      gh.seed(PINS, p2, { planted: 2, appended_by: "preimage:b", cross_reference: { ...XREF, reference: "the other sender's row" } });
    }
    return viaMock(url, o);
  };
  let again;
  try {
    again = await reference(c);
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(raced, true, "fixture: attempt 1 wrote at seq 2 and lost it");
  assert.deepEqual([again.status, again.body.existing, again.body.seq], [200, true, 1], JSON.stringify(again.body).slice(0, 300));
  assert.equal(gh.has(PINS, C.referencePath(c.id, 3)), false, "no second row");
});

test("R-PAGEf m2: the withdrawal's time, each stamped time and each recorded time print relative and absolute", async () => {
  const w = await withdrawnBy("RPAGEf m2 withdrawn", "a");
  const at = storedCase(w.id).withdrawal.at;
  assert.equal(cell((await viewAs(w.id)).html, "withdrawal"), `${esc("withdrawn on presentation of role a's commitment preimage, ")}1 hour ago (${at})`);
  const c = await sealedCase("RPAGEf m2 sealed");
  assert.equal((await reference(c)).status, 201);
  const html = (await viewAs(c.id)).html;
  const k = storedCase(c.id);
  assert.ok(cell(html, "role a registered at").startsWith(`2 hours ago (${k.commitments.a.registered_at}) <span class="muted">(stamped 2 hours ago (${k.commitments.a.stamped_at}))</span>`), cell(html, "role a registered at"));
  const row = gh.read(PINS, C.referencePath(c.id, 1));
  assert.ok(cell(html, "reference row 1").includes(`<span class="muted">(recorded 30 minutes ago (${row.recorded_at}), `), cell(html, "reference row 1"));
});

test("R-PAGEf m4: a case page asked for with another method is 405 method_not_allowed, codes only", async () => {
  const res = makeRes();
  await CP.handleCasePage(makeReq({ method: "POST", query: { op: "case-page", case_id: "1".repeat(64) }, headers: { "x-forwarded-for": nextIp() } }), res, { now: AT });
  assert.deepEqual([res._status, res._body, res._headers.allow], [405, { ok: false, error_code: "method_not_allowed" }, "GET, HEAD"]);
});

// R-PAGEf's must-fail gap tests: each fails with its planted defect
// A registration file whose record still validates with a byte that is not
// UTF-8 in it: a duplicate "kind" key first, holding `b` (JSON.parse keeps a
// duplicate key's last value, so the record is the same record). The honest
// form holds EF BF BD (U+FFFD) where the planted one holds 0xFF: the two
// decode to the same text, and their bytes differ.
function dupKindBytes(text, b) {
  const at = text.indexOf("{") + 1;
  return Buffer.concat([Buffer.from(text.slice(0, at), "utf8"), Buffer.from('"kind":"', "utf8"), Buffer.from(b), Buffer.from('",', "utf8"), Buffer.from(text.slice(at), "utf8")]);
}
function projectBytes(id, role, bytes) {
  const k = storedCase(id);
  gh.seed(PINS, C.casePath(id), { ...k, commitments: { ...k.commitments, [role]: { ...k.commitments[role], registration_sha256: sha(bytes) } } }, { keepHistory: true });
}

test("MUST-FAIL GAP (PF11): a registration that validates with a byte that is not UTF-8 in it: the projection answers its bytes' sha256, and a file whose text is the projected file's but whose bytes are not is not the file projected", async () => {
  const c = await committedCase("RPAGEf gap shas");
  const p = REG.pathOf(gh, c.id, "a");
  const text = gh._repoMap(PINS).get(p).content;
  const planted = dupKindBytes(text, [0xff]);
  assert.notEqual(sha(planted), sha(Buffer.from(planted.toString("utf8"), "utf8")), "fixture: the bytes' sha256 is not the text's");
  gh.seedBytes(PINS, p, planted);
  projectBytes(c.id, "a", planted);
  const proj = await S.projectedRegistrations(storedCase(c.id));
  assert.equal(proj.ok, true, JSON.stringify(proj));
  assert.equal(proj.shas.a, sha(planted));
  // the brief's case: the root projects the honest bytes (EF BF BD), the
  // file read holds 0xFF; their texts are the same
  const honest = dupKindBytes(text, [0xef, 0xbf, 0xbd]);
  assert.equal(honest.toString("utf8"), planted.toString("utf8"), "fixture: the same text");
  projectBytes(c.id, "a", honest);
  const differs = await S.projectedRegistrations(storedCase(c.id));
  assert.deepEqual([differs.ok, differs.role, differs.reason], [false, "a", "registration_file_differs"]);
});

test("MUST-FAIL GAP (PF13): the page's registration check line prints the sha256 of the file's bytes, not of its text re-encoded", async () => {
  const c = await sealedCase("RPAGEf gap check line");
  const p = REG.pathOf(gh, c.id, "a");
  const planted = dupKindBytes(gh._repoMap(PINS).get(p).content, [0xff]);
  gh.seedBytes(PINS, p, planted);
  projectBytes(c.id, "a", planted);
  const html = (await viewAs(c.id)).html;
  const line = checkLines(html).find((l) => l.text.startsWith(esc("role a's registration file")));
  assert.ok(line, JSON.stringify(checkLines(html)));
  assert.ok(line.text.includes(`sha256 ${sha(planted)}`), line.text);
});

test("MUST-FAIL GAP (PF40): the README says the withdrawal time prints relative and absolute", () => {
  assert.ok(README().replace(/\s+/g, " ").includes("withdrawn on presentation of role a's commitment preimage (or b's), then the time written, relative and absolute"));
});

test("MUST-FAIL GAP (PF20): the cross-reference sent with the reveal prints its recorded time relative and absolute", async () => {
  const c = await committedCase("RPAGEf gap xref recorded");
  const r = await reveal(c, { body: { ...revealBody(c.id, c.a, c.b), cross_reference: XREF } });
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  const x = storedCase(c.id).cross_reference;
  assert.equal(typeof x.recorded_at, "string", "fixture: the reveal recorded it");
  const row = cell((await viewAs(c.id)).html, "with the reveal");
  assert.ok(row.endsWith(`<span class="muted">(recorded 1 hour ago (${x.recorded_at}))</span>`), row);
});

// =============================================================================
// UNIT R-PAGEg (2026-10-15; the architect's rulings on the R-PAGEf reader's
// findings). Each test fails on a94c96d.
// =============================================================================

// B1. A writer and its readers hash the same bytes: the commit path projects
// the sha256 of the bytes of the file at the claim's path, however it came
// to be there.
test("R-PAGEg B1: a registration file at its claim's path, not projected, that validates with a byte that is not UTF-8 in it: the re-send projects the sha256 of its bytes and answers 200, and the page reads the case (not 503); a fresh write projects the bytes it wrote", async () => {
  const id = await openCase("RPAGEg B1 held");
  const before = storedCase(id);
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  // the fresh write projects the sha256 of the bytes it wrote
  assert.equal((await commit(id, a)).status, 201);
  const rpath = REG.pathOf(gh, id, "a");
  const written = Buffer.from(gh._repoMap(PINS).get(rpath).content, "utf8");
  assert.equal(storedCase(id).commitments.a.registration_sha256, sha(written));
  // the root as it stood before the projection, and the file at the claim's
  // path holding 0xFF in a duplicate key (the record is the same record)
  const planted = dupKindBytes(written.toString("utf8"), [0xff]);
  assert.notEqual(sha(planted), sha(Buffer.from(planted.toString("utf8"), "utf8")), "fixture: the text's sha256 is not the bytes'");
  gh.seed(PINS, C.casePath(id), before, { keepHistory: true });
  gh.seedBytes(PINS, rpath, planted);
  const again = await commit(id, a);
  assert.equal(again.status, 200, JSON.stringify(again.body).slice(0, 300));
  assert.equal(storedCase(id).commitments.a.registration_sha256, sha(planted));
  const p = await viewAs(id);
  assert.equal(p.status, 200, p.html.slice(p.html.indexOf("<h1>"), p.html.indexOf("<h1>") + 300));
  assert.ok(cell(p.html, "role a registered at"), "role a's row, from its read");
});

test("R-PAGEg B1: the lost create-only race: the file that landed first at the claim's path validates with a byte that is not UTF-8 in it; the projection is the sha256 of its bytes, and the page reads the case", async () => {
  const id = await openCase("RPAGEg B1 won");
  const before = storedCase(id);
  const a = party(id, "a", AGENT_TAPE);
  plantStamp(a.commitment_sha256);
  assert.equal((await commit(id, a)).status, 201);
  const rpath = REG.pathOf(gh, id, "a");
  const planted = dupKindBytes(gh._repoMap(PINS).get(rpath).content, [0xff]);
  // the root before the projection and no file at the claim's path: the
  // next write loses to one that lands first, holding the planted bytes
  gh.seed(PINS, C.casePath(id), before, { keepHistory: true });
  gh._repoMap(PINS).delete(rpath);
  const viaMock = global.fetch;
  let raced = false;
  global.fetch = async (url, o) => {
    if (!raced && ((o && o.method) || "GET") === "PUT" && decodeURIComponent(String(url)).endsWith(`/contents/${rpath}`)) {
      raced = true;
      gh.seedBytes(PINS, rpath, planted);
      gh.forceConflict(PINS, rpath, 1);
    }
    return viaMock(url, o);
  };
  let r;
  try {
    r = await commit(id, a);
  } finally {
    global.fetch = viaMock;
  }
  assert.equal(raced, true, "fixture: the write lost the race");
  assert.equal(r.status, 200, JSON.stringify(r.body).slice(0, 300));
  assert.equal(storedCase(id).commitments.a.registration_sha256, sha(planted));
  assert.equal((await viewAs(id)).status, 200);
});

// B2. THE TWIN, FIELD BY FIELD: each string or number the JSON twin carries,
// with its path. `ok`, a check's kind (`check`) and a role's letter (`role`,
// `by_role`) are the twin's structure, not facts the page prints in those
// words, and a boolean is not a word.
function twinLeaves(v, at = "") {
  if (v === null || v === undefined || typeof v === "boolean") return [];
  if (typeof v === "string" || typeof v === "number") return [[at, v]];
  if (Array.isArray(v)) return v.flatMap((x, i) => twinLeaves(x, `${at}[${i}]`));
  return Object.entries(v).flatMap(([k, x]) => (["ok", "check", "role", "by_role"].includes(k) ? [] : twinLeaves(x, at ? `${at}.${k}` : k)));
}
test("R-PAGEg B2: on every page state every field of the JSON twin is on the page, field by field; a role whose registration file could not be read has no registered_at in the twin", async () => {
  const states = await pageStates();
  assert.ok(states.some((st) => /role a's file unread/.test(st.name)), "fixture: the unread states");
  let unreadRows = 0;
  for (const st of states) {
    const v = await bothViews(st.id, st.view);
    for (const [k, val] of twinLeaves(v.json)) assert.ok(v.html.includes(esc(String(val))), `${st.name}: ${k} = ${val} is not on the page`);
    for (const r of ["a", "b"]) {
      const row = cell(v.html, `role ${r}`);
      if (!row || !row.includes("could not be read")) continue;
      unreadRows += 1;
      if (v.json.registered_at === undefined) continue;
      assert.equal(v.json.registered_at[r], null, `${st.name}: role ${r}'s file was not read, and the twin gives its time`);
    }
  }
  assert.ok(unreadRows >= 2, "the unread rows were among the states");
});

// M1. Every role read before the page prints a row of it.
test("R-PAGEg M1: role a's registration file unread, role b's readable: the page reads b's file and prints b's row from that read; a's row says it could not be read, with no time; the checks list both reads; the twin matches", async () => {
  const c = await sealedCase("RPAGEg M1");
  const ra = REG.pathOf(gh, c.id, "a");
  const rb = REG.pathOf(gh, c.id, "b");
  const k = storedCase(c.id);
  const g0 = gh.getLog.length;
  const v = await bothViews(c.id, { arm: () => gh.forceGetFailure(PINS, ra, 1, 503), disarm: () => gh.forceGetFailure(PINS, ra, 0) });
  assert.equal(gh.getLog.slice(g0).filter((p) => p === rb).length, 2, "role b's file read on each view");
  assert.equal(v.status, 200);
  assert.equal(cell(v.html, "role a"), esc("its registration file could not be read when this page was read (registration_unreadable)"));
  assert.equal(cell(v.html, "role a registered at"), null);
  const rowB = cell(v.html, "role b registered at");
  assert.ok(rowB && rowB.includes(`(${k.commitments.b.registered_at})`) && rowB.includes("stamp commit"), rowB);
  const reg = checkLines(v.html).filter((l) => l.text.startsWith(esc("role ")));
  assert.deepEqual(reg.map((l) => l.code), ["registration_unreadable", "matches_projection"], JSON.stringify(reg));
  assert.ok(reg[1].text.includes(`sha256 ${k.commitments.b.registration_sha256}`), reg[1].text);
  assert.deepEqual(v.json.registered_at, { a: null, b: k.commitments.b.registered_at });
  assert.deepEqual(v.json.checks.filter((x) => x.check === "registration_file").map((x) => [x.role, x.code, x.sha256 || null]),
    [["a", "registration_unreadable", null], ["b", "matches_projection", k.commitments.b.registration_sha256]]);
});

test("R-PAGEg M1: a row whose file this page did not read says 'not checked by this page', with no time and no link, and the twin gives no time for it", async () => {
  const c = await committedCase("RPAGEg M1 unchecked");
  const real = S.projectedRegistrations;
  // a reader that read role a's file and skipped role b's
  S.projectedRegistrations = async (kase) => {
    const p = await real(kase);
    return { ...p, texts: { ...p.texts, b: null }, shas: { ...p.shas, b: null } };
  };
  let v;
  try {
    v = await bothViews(c.id);
  } finally {
    S.projectedRegistrations = real;
  }
  const row = cell(v.html, "role b");
  assert.ok(row && row.includes("not checked by this page") && !row.includes("<a "), row);
  assert.equal(cell(v.html, "role b registered at"), null);
  assert.ok(cell(v.html, "role a registered at"), "role a's row, from its read");
  assert.deepEqual(v.json.registered_at, { a: storedCase(c.id).commitments.a.registered_at, b: null });
});

// m1. On the real clock the read time is taken when the read completes.
test("R-PAGEg m1: on the real clock the key document's read time is taken when its read completes, not when the page began", async () => {
  const c = await sealedCase("RPAGEg m1");
  S._internal.clearDocumentCache();
  const realNow = Date.now;
  const viaMock = global.fetch;
  let clock = AT;
  Date.now = () => clock;
  global.fetch = async (url, o) => {
    // the key document's read takes five seconds
    if (String(url).startsWith(`https://raw.githubusercontent.com/${S.KEY_DOCUMENT_REPO}/`)) clock += 5000;
    return viaMock(url, o);
  };
  let html;
  try {
    const res = makeRes();
    await CP.handleCasePage(makeReq({ method: "GET", query: { op: "case-page", case_id: c.id }, headers: { "x-forwarded-for": nextIp() } }), res, { keyDocument: DOC, env: {} });
    html = String(res._body);
  } finally {
    Date.now = realNow;
    global.fetch = viaMock;
  }
  assert.ok(html.includes(readAt(AT)), "the page began at AT");
  const row = cell(html, "key document");
  assert.ok(row && row.endsWith(`<span class="muted">last read ${iso(AT + 5000)}</span>`), row);
});
