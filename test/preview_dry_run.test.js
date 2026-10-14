// test/preview_dry_run.test.js — tools/preview_dry_run.js (case protocol item
// 3a), run against an in-process stand-in for a preview
// (test/helpers/vercel_preview.js: a real http server running this
// checkout's api/*.js over the mock store, test/helpers/mock_store.js). The
// tool reaches it over HTTP, as it reaches a preview.
//
// Every check runs against the mock, and each is planted both ways: the
// stand-in behaving as this checkout should (VERIFIED) and misbehaving in the
// way the check exists to catch (BROKEN), plus the ways it cannot look
// (COULD NOT LOOK, never VERIFIED):
//   (a) a document that differs by one byte, and one not served;
//   (b) a preview without the rewrite, a checkout without it, a page that
//       does not name the case;
//   (c) no --exhaust-quota, a key that opened earlier today, the per-IP
//       limiter's 429, a quota counter written nowhere, a key that is not
//       valid;
//   (d) a commit history that does not show the stamp yet, one that names
//       another commit, one that cannot be read;
//   (e) a platform that loses a chunked body, one that wants a length;
//   (f) no --pin-token, a pins store that does not hold the preview's case,
//       a pass that refuses a case, a pin that failed at the reveal;
//   (g) a deployment serving the whole root.
// And Vercel Authentication in front of the whole preview, both ways: the
// right bypass secret and the checks run; a wrong or missing one and every
// check is COULD NOT LOOK after one request, saying which; a 401 that is not
// Vercel's SSO page left to the checks, as before.
// What cannot run against the mock is the live preview itself: Vercel's own
// body parser, its static serving, its real SSO page and bypass, and
// GitHub's read-after-write. The stand-in plants each one's two behaviours;
// the real answer is the dry run's to read.
// And the CLI: seven lines on stdout and nothing else, exit 0/2/3 (3 wins
// over 2), usage 1, the bypass from VERCEL_AUTOMATION_BYPASS_SECRET when the
// flag is absent, and no key, bypass, operator key or pin token on either
// stream, nor the operator key or pin token in any request the preview
// received.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
// The issued key the dry run opens with.
process.env.WITNESS_KEYS = "dry-run-issued-key-0001:dry-run-";
for (const k of ["WITNESS_CASE_SIGNER_KEY", "WITNESS_RECONCILE_SIGNER_KEY", "WITNESS_LOG_SIGNER_KEY", "WITNESS_CASE_OPERATOR_KEY",
  "WITNESS_ADMIN_KEY", "WITNESS_BATCH_SHADOW", "KV_REST_API_URL", "KV_REST_API_TOKEN", "UPSTASH_REDIS_REST_URL", "UPSTASH_REDIS_REST_TOKEN"]) {
  delete process.env[k];
}

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const { spawn } = require("node:child_process");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const REG = require("./helpers/case_registration.js");
const { startPreview, readVercel, vercelBody } = require("./helpers/vercel_preview.js");
const store = require("../lib/_store.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const S = require("../lib/_case_seal.js");
const checkpoint = require("../lib/_checkpoint.js");
const tool = require("../tools/preview_dry_run.js");
const KD = require("./helpers/key_document.js");

const ROOT = path.join(__dirname, "..");
const TOOL = path.join(ROOT, "tools", "preview_dry_run.js");
const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const USAGE = process.env.GITHUB_USAGE_REPO;
const KEY = "dry-run-issued-key-0001";
const OPERATOR_KEY = "dry-run-operator-key-0001-never-sent";
const PIN_TOKEN = "dry-run-pin-token-0001-never-sent";
const BYPASS = "dry-run-bypass-secret-0001-right";
const WRONG_BYPASS = "dry-run-bypass-secret-0002-wrong";
const SECRETS = [KEY, OPERATOR_KEY, PIN_TOKEN, BYPASS, WRONG_BYPASS];

// A deployment with its case signer installed and published (item 3b's
// end state): throwaway keys, made here, written nowhere, and the committed
// key document with an active entry for the case key. The stand-in seals
// with them, and the dry run judges (e) and (f) against that document,
// unless a test says otherwise. The CLI runs keep the committed document.
const CASE_KEY = checkpoint.generateKey("test.example/dry-run-case");
// The deployment's reconcile signer (red-team fix B: without one the
// stand-in compares nothing), one throwaway key: in SIGNING_ENV, and in this
// process's environment, which the stand-in's api/verify.js reads. The dry
// run is told its public verifier: in process, through this environment
// (lib/_reconcile_receipt.js expectedVerifier), and in a CLI run through
// WITNESS_RECONCILE_VERIFIER (runCli).
const RECONCILE_KEY = checkpoint.generateKey("test.example/dry-run-reconcile");
process.env.WITNESS_RECONCILE_SIGNER_KEY = RECONCILE_KEY.signer;
const SIGNING_ENV = Object.freeze({
  [S.CASE_SIGNER_ENV]: CASE_KEY.signer,
  WITNESS_RECONCILE_SIGNER_KEY: RECONCILE_KEY.signer,
  WITNESS_LOG_SIGNER_KEY: checkpoint.generateKey("test.example/dry-run-log").signer,
});
const COMMITTED_DOC = JSON.parse(fs.readFileSync(path.join(ROOT, ...S.CASE_KEYS_FILE.split("/")), "utf8"));
const CASE_ENTRY = S.keyDocumentEntry({ keyId: CASE_KEY.verifier.split("+").slice(0, 2).join("+"), verifier: CASE_KEY.verifier },
  { since: "2026-10-10", note: "the dry-run tests' case key" });
// Since Design I the document lists the reconcile key too, as a reconcile
// entry, and the deployment is built at the commit that holds it
// (VERCEL_GIT_COMMIT_SHA; test/helpers/key_document.js commitOf), where the
// mock serves it for readers (beforeEach).
const TEST_DOC = { ...COMMITTED_DOC, keys: [...COMMITTED_DOC.keys, CASE_ENTRY, KD.reconcileEntry(RECONCILE_KEY)] };
const SIGNER = Object.freeze({ env: { ...SIGNING_ENV, [S.DEPLOY_COMMIT_ENV]: KD.commitOf(TEST_DOC) }, keyDocument: TEST_DOC });

let gh;
let restore;
let realSleep;
beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
  // the seal module's per-instance caches start empty for each test (unit
  // R-I2: one test's kept reads never answer for another's mock)
  S._internal.clearDocumentCache();
  S._internal.clearCommitFiles();
  KD.serve(gh, TEST_DOC);
  realSleep = store._putRetry.sleep;
  store._putRetry.sleep = async () => {};
});
afterEach(() => {
  store._putRetry.sleep = realSleep;
  restore();
});

// A store answer in the mock's own shape.
function answer(status, body) {
  const text = JSON.stringify(body);
  return { status, ok: status >= 200 && status < 300, json: async () => body, text: async () => text };
}
// Stand `fn` in front of the mock: a store answer to give instead, or
// undefined to let the mock answer.
function intercept(fn) {
  const real = gh.handleFetch.bind(gh);
  gh.handleFetch = async (url, opts) => (await fn(new URL(String(url)), opts || {})) || real(url, opts);
}
// A wrapper for the stand-in that answers one op itself.
function onOp(op, handle) {
  return (fn) => async (req, res) => ((req.query || {}).op === op ? handle(req, res, fn) : fn(req, res));
}

// Rewrite the reveal's 201 answer on its way out (the seal stands in the store).
function rewriteReveal(mutate) {
  return onOp("case-reveal", (req, res, fn) => {
    const realSend = res.send;
    res.send = (b) => {
      const j = JSON.parse(String(b));
      if (res.statusCode === 201) mutate(j);
      return realSend.call(res, JSON.stringify(j));
    };
    return fn(req, res);
  });
}

async function dryRun(t, { preview = {}, ...opts } = {}) {
  const p = await startPreview({ signer: SIGNER, ...preview });
  t.after(() => p.close());
  const out = [];
  const err = [];
  const r = await tool.run({ base: p.base, key: KEY, keyDocument: TEST_DOC, stdout: (l) => out.push(l), stderr: (l) => err.push(l), ...opts });
  const by = Object.fromEntries(r.results.map((x) => [x.id, x]));
  const show = out.join("\n");
  // Every run: seven lines, in order, each a verdict word; no secret anywhere;
  // neither the operator key nor the pin token reaches the preview, and the
  // issued key goes only to case-open and the stamps.
  assert.equal(out.length, 7, show);
  assert.deepEqual(r.results.map((x) => x.id), ["a", "b", "c", "d", "e", "f", "g"]);
  out.forEach((l, i) => assert.match(l, new RegExp(`^(VERIFIED|BROKEN|COULD NOT LOOK) \\(${"abcdefg"[i]}\\) `), l));
  for (const s of SECRETS) {
    for (const l of [...out, ...err]) assert.equal(l.includes(s), false, `a secret was printed: ${l.slice(0, 120)}`);
  }
  for (const q of p.requests) {
    const sent = JSON.stringify(q.headers);
    assert.equal(sent.includes(OPERATOR_KEY), false, "the operator key reached the preview");
    assert.equal(sent.includes(PIN_TOKEN), false, "the pin token reached the preview");
    if (sent.includes(KEY)) assert.ok(/op=case-open/.test(q.search) || q.path === "/api/stamp", `the issued key went to ${q.path}${q.search}`);
  }
  return { ...r, out, err, by, show, preview: p };
}
const word = (r, id) => r.by[id].word;
const today = () => new Date().toISOString().slice(0, 10);

// =============================================================================
// the whole run
// =============================================================================

test("ALL VERIFIED: against a preview that behaves, with --exhaust-quota and --pin-token, every check is VERIFIED and the exit is 0", async (t) => {
  const r = await dryRun(t, { exhaustQuota: true, pinToken: PIN_TOKEN, operatorKey: OPERATOR_KEY });
  for (const id of "abcdefg") assert.equal(word(r, id), "VERIFIED", r.show);
  assert.equal(r.code, 0);

  const doc = fs.readFileSync(path.join(ROOT, ...S.CASE_KEYS_FILE.split("/")));
  assert.match(r.by.a.line, new RegExp(`HTTP 200, ${doc.length} bytes, sha256 ${crypto.createHash("sha256").update(doc).digest("hex")}`));
  const id = /case_id ([0-9a-f]{64})/.exec(r.by.b.line)[1];
  assert.match(r.by.b.line, /rewrites \/case\/:case_id to \/api\/verify\?op=case-page/);
  assert.match(r.by.c.line, /opens 1-20 answered HTTP 201 and open 21 was refused HTTP 429 open_quota_exceeded/);
  assert.equal(gh.read(USAGE, H._internal.openQuotaPath(KEY, today())).count, 20, "the real counter, in the usage repository");
  const commit = /commit ([0-9a-f]{40})/.exec(r.by.d.line)[1];
  assert.match(r.by.d.line, new RegExp(`read stamp_commit ${commit}, the same commit`));
  assert.equal(gh.read(PINS, REG.pathOf(gh, id, "a")).stamp_commit, commit);
  const sealed = gh.read(PINS, C.casePath(id));
  assert.equal(sealed.status, "VERDICT");
  assert.equal(sealed.signed_by, CASE_ENTRY.key_id, "the stand-in signs with the published case key");
  assert.match(r.by.e.line, new RegExp(`no content-length answered HTTP 201 VERDICT for case_id ${id}, verdict MATCHED: signed by ` +
    `${CASE_ENTRY.key_id.replace(/[.+/]/g, "\\$&")}, verified under its active entry in public/\\.well-known/arcaeon/case-signing-keys\\.json, ` +
    `the document it names at commit ${KD.commitOf(TEST_DOC)}; ` +
    `chain ${S.caseChain(sealed)}, the case's own, pin pinned$`));
  assert.match(r.by.f.line, new RegExp(`case ${id} is pinned at commit [0-9a-f]{40}, chain ${S.caseChain(gh.read(PINS, C.casePath(id)))} \\(pinned at its reveal\\)$`));
  assert.match(r.by.g.line, /README\.md, package\.json, package-lock\.json, lib\/ \d+, tools\/ \d+, test\/ \d+\): every one answered HTTP 404/);

  // The reveal really went out chunked, with no content-length.
  const reveals = r.preview.requests.filter((q) => /op=case-reveal/.test(q.search));
  assert.equal(reveals.length, 1);
  assert.equal(reveals[0].headers["transfer-encoding"], "chunked");
  assert.equal(Object.prototype.hasOwnProperty.call(reveals[0].headers, "content-length"), false);
  // The pin token was set for the pass alone.
  assert.equal(process.env.GITHUB_PIN_TOKEN, "test-token");
});

test("DEFAULT RUN: without --exhaust-quota and --pin-token, (c) and (f) are COULD NOT LOOK and say why, the rest VERIFIED, exit 3", async (t) => {
  const r = await dryRun(t);
  assert.equal(r.code, 3);
  for (const id of "abdeg") assert.equal(word(r, id), "VERIFIED", r.show);
  assert.equal(word(r, "c"), "COULD NOT LOOK");
  assert.match(r.by.c.line, /case-open 1 with the issued key answered HTTP 201 \(case_id [0-9a-f]{64}\); the 21st open of the day was not tried: --exhaust-quota was not given/);
  assert.equal(word(r, "f"), "COULD NOT LOOK");
  assert.match(r.by.f.line, /needs the pins token: --pin-token was not given/);
  assert.equal(r.preview.requests.filter((q) => /op=case-open/.test(q.search)).length, 1, "one open without the flag");
});

// =============================================================================
// (a) the key document
// =============================================================================

test("(a) BROKEN when the served document differs by one byte or is not served; the evidence carries both digests", async (t) => {
  const doc = fs.readFileSync(path.join(ROOT, ...S.CASE_KEYS_FILE.split("/")));
  const altered = Buffer.concat([doc, Buffer.from(" ")]);
  const r = await dryRun(t, { preview: { files: { [`/${S.CASE_KEYS_DOC}`]: altered } } });
  assert.equal(word(r, "a"), "BROKEN");
  const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
  assert.match(r.by.a.line, new RegExp(`HTTP 200, ${altered.length} bytes, sha256 ${sha(altered)}; the committed file is ${doc.length} bytes, sha256 ${sha(doc)}`));

  const gone = await dryRun(t, { preview: { serves: (rel) => rel === "favicon.svg" } });
  assert.equal(word(gone, "a"), "BROKEN");
  assert.match(gone.by.a.line, /HTTP 404, not served/);
});

// =============================================================================
// (b) the case page
// =============================================================================

test("(b) BROKEN when the preview lacks the rewrite, when this checkout lacks it, and when the page does not name the case", async (t) => {
  const real = readVercel();
  const without = { ...real, rewrites: real.rewrites.filter((x) => x.source !== "/case/:case_id") };

  const preview = await dryRun(t, { preview: { vercel: without } });
  assert.equal(word(preview, "b"), "BROKEN");
  assert.match(preview.by.b.line, /GET \/case\/[0-9a-f]{64}: HTTP 404/);

  const checkout = await dryRun(t, { vercel: without });
  assert.equal(word(checkout, "b"), "BROKEN");
  assert.match(checkout.by.b.line, /this checkout's vercel\.json has no rewrite for \/case\/:case_id; GET \/case\/[0-9a-f]{64}: HTTP 200/);

  const blank = await dryRun(t, { preview: { wrap: onOp("case-page", (req, res) => res.status(200).send("<!doctype html><h1>Case: OPEN</h1>")) } });
  assert.equal(word(blank, "b"), "BROKEN");
  assert.match(blank.by.b.line, /the page does not name this case_id/);
});

// =============================================================================
// (c) the open and its quota
// =============================================================================

test("(c) COULD NOT LOOK, never VERIFIED, when the key opened earlier today or the per-IP limiter answers 429; BROKEN when no quota refuses the 21st or the key is not valid", async (t) => {
  const day = today();
  // A key that opened 15 cases earlier today: refused at open 6 of this run.
  gh.seed(USAGE, H._internal.openQuotaPath(KEY, day), { kind: "case-open-quota", v: 1, day, count: 15 });
  const earlier = await dryRun(t, { exhaustQuota: true });
  assert.equal(word(earlier, "c"), "COULD NOT LOOK");
  assert.match(earlier.by.c.line, /open 6 of this run was refused HTTP 429 open_quota_exceeded after 5 accepted: this key had opened cases earlier today/);

  // The per-IP limiter's 429 is not the quota.
  gh = new MockGitHubStore();
  restore();
  restore = install(gh);
  let opens = 0;
  const limited = await dryRun(t, { exhaustQuota: true, preview: { wrap: onOp("case-open", (req, res, fn) => {
    opens += 1;
    if (opens === 5) return res.status(429).json({ ok: false, error_code: "rate_limited", error: "rate limit exceeded" });
    return fn(req, res);
  }) } });
  assert.equal(word(limited, "c"), "COULD NOT LOOK");
  assert.match(limited.by.c.line, /open 5 was refused HTTP 429 rate_limited by the per-IP limiter, not by the open quota/);

  // A counter written nowhere: every open reads zero, and the 21st is accepted.
  gh = new MockGitHubStore();
  restore();
  restore = install(gh);
  intercept((u, opts) => {
    if (!u.pathname.startsWith(`/repos/${USAGE}/contents/case_opens/`)) return undefined;
    return (opts.method || "GET") === "PUT" ? answer(200, { content: { sha: "0".repeat(40) }, commit: { sha: "1".repeat(40) } }) : answer(404, { message: "Not Found" });
  });
  const unlimited = await dryRun(t, { exhaustQuota: true });
  assert.equal(word(unlimited, "c"), "BROKEN");
  assert.match(unlimited.by.c.line, /open 21 of this run was accepted HTTP 201 \(case_id [0-9a-f]{64}\): no open quota refused it after 20/);

  // A key the preview does not hold: the open itself is BROKEN, and what needs a case cannot look.
  const invalid = await dryRun(t, { key: "not-an-issued-key-0001" });
  assert.equal(word(invalid, "c"), "BROKEN");
  assert.match(invalid.by.c.line, /case-open 1 with the issued key answered HTTP 401 key_invalid, not 201/);
  for (const id of "bdef") assert.equal(word(invalid, id), "COULD NOT LOOK", invalid.show);
  assert.equal(invalid.code, 3);
});

// =============================================================================
// (d) the stamp and the immediate read of its commit
// =============================================================================

test("(d) BROKEN when the immediate read does not see the stamp's commit, or reads another; COULD NOT LOOK when the history cannot be read", async (t) => {
  const commitsOfStamps = (u) => u.pathname === `/repos/${STAMPS}/commits`;

  intercept((u) => (commitsOfStamps(u) ? answer(200, []) : undefined));
  const unseen = await dryRun(t);
  assert.equal(word(unseen, "d"), "BROKEN");
  assert.match(unseen.by.d.line, /HTTP 503 stamp_history_unreadable \(no_commit_touches_path\): the read did not see the stamp's commit/);
  assert.equal(word(unseen, "e"), "COULD NOT LOOK");
  assert.match(unseen.by.e.line, /role a was not registered in \(d\)/);

  gh = new MockGitHubStore();
  restore();
  restore = install(gh);
  const other = "f".repeat(40);
  intercept((u) => (commitsOfStamps(u) ? answer(200, [{ sha: other, commit: { message: "m", author: { date: "2026-10-10T00:00:00Z" }, committer: { date: "2026-10-10T00:00:00Z" } } }]) : undefined));
  const another = await dryRun(t);
  assert.equal(word(another, "d"), "BROKEN");
  assert.match(another.by.d.line, new RegExp(`read stamp_commit ${other}, another commit`));

  gh = new MockGitHubStore();
  restore();
  restore = install(gh);
  intercept((u) => (commitsOfStamps(u) ? answer(500, { message: "mock: forced commits read failure" }) : undefined));
  const unread = await dryRun(t);
  assert.equal(word(unread, "d"), "COULD NOT LOOK");
  assert.match(unread.by.d.line, /HTTP 503 stamp_history_unreachable/);
});

// =============================================================================
// (e) the chunked reveal
// =============================================================================

test("(e) BROKEN when the platform loses a chunked JSON body, or asks for a length; the case stays COMMITTED", async (t) => {
  const losesChunked = (req, raw) => (req.headers["transfer-encoding"] === "chunked" ? "" : vercelBody(req, raw));
  const lost = await dryRun(t, { preview: { bodyParser: losesChunked } });
  assert.equal(word(lost, "e"), "BROKEN");
  assert.match(lost.by.e.line, /sent in 4 chunks with no content-length answered HTTP 400 malformed_json, not 201/);
  const id = /case_id ([0-9a-f]{64})/.exec(lost.by.b.line)[1];
  assert.equal(gh.read(PINS, C.casePath(id)).status, "COMMITTED");

  const wantsLength = await dryRun(t, { preview: { wrap: onOp("case-reveal", (req, res, fn) => (req.headers["content-length"] === undefined
    ? res.status(411).json({ ok: false, error_code: "length_required", error: "send a content-length" }) : fn(req, res))) } });
  assert.equal(word(wantsLength, "e"), "BROKEN");
  assert.match(wantsLength.by.e.line, /answered HTTP 411 length_required/);
});

test("(e) REVIEW FIX 1: a reveal answering 201 VERDICT with sig null and signed_by null is BROKEN, never VERIFIED; so is any seal the published key does not confirm, and any chain that is not the case's own", async (t) => {
  // The planted test: the answer says 201 VERDICT, unsigned.
  const planted = await dryRun(t, { preview: { wrap: rewriteReveal((j) => {
    j.case.sig = null;
    j.case.signed_by = null;
  }) } });
  assert.equal(word(planted, "e"), "BROKEN", planted.show);
  assert.match(planted.by.e.line, /answered HTTP 201 VERDICT for case_id [0-9a-f]{64}, but the seal is unsigned \(signed_by null, sig null\): the published case signer is not installed$/);

  // A deployment with no case signer installed seals nothing (the one
  // signature rule), and says why.
  const { [S.CASE_SIGNER_ENV]: _caseKey, ...noCaseKey } = SIGNER.env; // eslint-disable-line no-unused-vars
  const bare = await dryRun(t, { preview: { signer: { env: noCaseKey, keyDocument: TEST_DOC } } });
  assert.equal(word(bare, "e"), "BROKEN");
  assert.match(bare.by.e.line, /answered HTTP 503 case_signer_unavailable \(case_key_unset\): the published case signer is not installed, so the preview seals nothing$/);
  const id = /case_id ([0-9a-f]{64})/.exec(bare.by.b.line)[1];
  assert.equal(gh.read(PINS, C.casePath(id)).status, "COMMITTED", "it really sealed nothing");

  // Sealed under another document than this checkout's: one that does not
  // list the key, or lists it revoked (Design I: the seal names its document;
  // since unit R-REV there is no retired status).
  const sealedElsewhere = /it was sealed under the key document [0-9a-f]{64} at commit [0-9a-f]{40}, not this checkout's public\/\.well-known\/arcaeon\/case-signing-keys\.json \([0-9a-f]{64}\)$/;
  const unlisted = await dryRun(t, { keyDocument: COMMITTED_DOC });
  assert.equal(word(unlisted, "e"), "BROKEN");
  assert.match(unlisted.by.e.line, sealedElsewhere);
  const revoked = await dryRun(t, { keyDocument: { ...TEST_DOC, keys: TEST_DOC.keys.map((e) => (e.key_id === CASE_ENTRY.key_id ? { ...e, status: "revoked" } : e)) } });
  assert.equal(word(revoked, "e"), "BROKEN");
  assert.match(revoked.by.e.line, sealedElsewhere);

  // The answer altered on its way out.
  const arms = [
    ["signed_by missing", (j) => { delete j.case.signed_by; }, /the seal is unsigned \(signed_by missing, sig set\)/],
    ["sig missing", (j) => { delete j.case.sig; }, /the seal is unsigned \(signed_by set, sig missing\)/],
    ["sig invalid", (j) => { j.case.sig = Buffer.alloc(64, 7).toString("base64"); }, /\(case_signature_invalid: bad_signature\)/],
    ["chain not hex", (j) => { j.chain = "not-a-chain"; }, /its chain "not-a-chain" is not 64 hex/],
    ["chain missing", (j) => { delete j.chain; }, /its chain undefined is not 64 hex/],
    ["chain another", (j) => { j.chain = "0".repeat(64); }, /its chain 0{64} is not the sealed case's own \([0-9a-f]{64}\)/],
  ];
  for (const [name, mutate, want] of arms) {
    const r = await dryRun(t, { preview: { wrap: rewriteReveal(mutate) } });
    assert.equal(word(r, "e"), "BROKEN", `${name}: ${r.by.e.line}`);
    assert.match(r.by.e.line, want, name);
  }
});

test("TIMEOUTS: an answer that stalls mid-body, one that trickles forever, and one that never starts each end the request with an error in bounded time", async (t) => {
  const server = http.createServer((req, res) => {
    if (req.url === "/stall") {
      res.writeHead(200, { "content-length": "100" });
      res.write("0123456789");
    } else if (req.url === "/trickle") {
      res.writeHead(200, { "content-type": "text/plain" });
      const timer = setInterval(() => res.write("."), 50);
      res.on("close", () => clearInterval(timer));
    }
    // "/silent": never answered
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  }));
  const base = `http://127.0.0.1:${server.address().port}`;
  // Each clock ends its own case: the answer's idle timer the stall, the
  // deadline the trickle, the request's the silence. Unit R-I2 (a file-level
  // failure in 1 of 5 parallel runs): each case sets the OTHER clock far out
  // (30s), so under load the two can never fire in the other order; the
  // trickle writes every 50ms against a 10s idle timer.
  for (const [p, opts, want] of [
    ["/stall", { timeoutMs: 400, deadlineMs: 30000 }, /^the answer stalled mid-body \(nothing for 0\.4s\)$/],
    ["/trickle", { timeoutMs: 10000, deadlineMs: 1600 }, /^no complete answer in 1\.6s$/],
    ["/silent", { timeoutMs: 400, deadlineMs: 30000 }, /^no answer in 0\.4s$/],
  ]) {
    const t0 = Date.now();
    let guard;
    const r = await Promise.race([
      tool._internal.request(base, "GET", p, opts),
      new Promise((resolve) => {
        guard = setTimeout(() => resolve({ error: "the request never ended" }), 20000);
      }),
    ]);
    clearTimeout(guard);
    assert.match(String(r.error), want, `${p}: ${JSON.stringify(r).slice(0, 200)}`);
    assert.ok(Date.now() - t0 < 10000, `${p} ended in ${Date.now() - t0} ms`);
  }
});

// =============================================================================
// (f) the sealer's case pass
// =============================================================================

test("(f) VERIFIED when the pass pins a case whose pin failed at the reveal; BROKEN when it refuses a case; COULD NOT LOOK when the store is not the preview's", async (t) => {
  // The reveal's first write of the numbered pin fails: the reveal answers
  // pin pending, and the pass pins it.
  let failed = 0;
  intercept((u, opts) => {
    if ((opts.method || "GET") === "PUT" && /^\/repos\/test-owner\/test-pins\/contents\/pins\/case\/[0-9a-f]{64}\/00000001\.json$/.test(u.pathname) && failed === 0) {
      failed += 1;
      return answer(500, { message: "mock: the reveal's pin write fails" });
    }
    return undefined;
  });
  const healed = await dryRun(t, { pinToken: PIN_TOKEN });
  assert.equal(failed, 1);
  assert.match(healed.by.e.line, /pin commit_unrecorded/);
  assert.equal(word(healed, "f"), "VERIFIED", healed.show);
  assert.match(healed.by.f.line, /pinned 1, already 0[^;]*; case [0-9a-f]{64} is pinned at commit [0-9a-f]{40}, chain [0-9a-f]{64} \(pinned by this pass\)$/);

  // A sealable case whose file does not read: the pass refuses it.
  gh = new MockGitHubStore();
  restore();
  restore = install(gh);
  const bad = "ab".repeat(32);
  gh.seed(PINS, C.casePath(bad), { not: "a case" });
  const refused = await dryRun(t, { pinToken: PIN_TOKEN });
  assert.equal(word(refused, "f"), "BROKEN");
  assert.match(refused.by.f.line, new RegExp(`refused ${bad} \\(case_record_unreadable\\)`));

  // The store the environment names does not hold the case the preview
  // opened: not the preview's store, and the pass does not run.
  gh = new MockGitHubStore();
  restore();
  restore = install(gh);
  let sealed = false;
  intercept((u, opts) => (sealed && (opts.method || "GET") === "GET" && /^\/repos\/test-owner\/test-pins\/contents\/cases\/[0-9a-f]{64}\.json$/.test(u.pathname)
    ? answer(404, { message: "Not Found" }) : undefined));
  const elsewhere = await dryRun(t, { pinToken: PIN_TOKEN, preview: { wrap: onOp("case-reveal", async (req, res, fn) => {
    await fn(req, res);
    sealed = true;
  }) } });
  assert.equal(word(elsewhere, "f"), "COULD NOT LOOK");
  assert.match(elsewhere.by.f.line, /does not hold case [0-9a-f]{64}, which this run opened on the preview, so it is not the preview's pins store/);
  assert.equal(gh.putLog.some((w) => w.path.startsWith("pins/case/") && w.path.endsWith("/00000001.json") && w.repo === PINS), true, "only the reveal pinned");
  assert.equal(process.env.GITHUB_PIN_TOKEN, "test-token", "the pin token is put back");
});

test("(e), (f) RED-TEAM FIX B AND DESIGN I: (e) holds the receipt's signer to the reconcile key WITNESS_RECONCILE_VERIFIER names (another key is BROKEN, none is COULD NOT LOOK); (f) holds each case to the document it names, needing no verifier; a named document that cannot be read is COULD NOT LOOK", async (t) => {
  // The preview's receipts are RECONCILE_KEY's; the dry run is told another key.
  const other = checkpoint.generateKey("test.example/dry-run-other-reconcile");
  const wrong = await dryRun(t, { receiptVerifier: other.verifier, pinToken: PIN_TOKEN });
  assert.equal(word(wrong, "e"), "BROKEN", wrong.show);
  assert.match(wrong.by.e.line, new RegExp(`its receipt is signed by ${RECONCILE_KEY.verifier.replace(/[.+/]/g, "\\$&")}, not the reconcile key WITNESS_RECONCILE_VERIFIER names$`));
  // (f) needs no verifier: the case holds under the document it names.
  const sealedId = /case_id ([0-9a-f]{64})/.exec(wrong.by.e.line)[1];
  assert.equal(gh.read(PINS, C.casePath(sealedId)).status, "VERDICT", "fixture: the preview sealed it");
  assert.equal(word(wrong, "f"), "COULD NOT LOOK", wrong.show);
  assert.match(wrong.by.f.line, /no case was sealed in \(e\)/, "(e) did not verify a seal, so (f) has none of this run's to look for");
  // Told no verifier at all.
  const none = await dryRun(t, { receiptVerifier: null, pinToken: PIN_TOKEN });
  assert.equal(word(none, "e"), "COULD NOT LOOK", none.show);
  assert.match(none.by.e.line, /no reconcile verifier is known here \(set WITNESS_RECONCILE_VERIFIER to the public verifier of the preview's WITNESS_RECONCILE_SIGNER_KEY\), so the receipt's signer cannot be checked$/);
  assert.equal(none.code, 3);
  // control: told the preview's own verifier, both hold
  const right = await dryRun(t, { receiptVerifier: RECONCILE_KEY.verifier, pinToken: PIN_TOKEN });
  assert.equal(word(right, "e"), "VERIFIED", right.show);
  assert.equal(word(right, "f"), "VERIFIED", right.show);
  // The named document cannot be read from the public repository: since
  // unit R-I (I2) the preview's own reveal reads it before it seals, so the
  // reveal answers 503 document_unavailable and (e) could not look.
  gh.raw.clear();
  S._internal.clearDocumentCache();
  const unread = await dryRun(t, { pinToken: PIN_TOKEN });
  assert.equal(word(unread, "e"), "COULD NOT LOOK", unread.show);
  assert.match(unread.by.e.line, /HTTP 503 document_unavailable: the preview could not answer this request/);
});

test("T06, T07 (f) DESIGN I: a pass that could not read the key document this run's sealed case names is COULD NOT LOOK, saying so, and the summary counts it", async (t) => {
  // The reveal's pin write fails, so the case is a candidate (unit R-PIN: a
  // pinned root is none), and the pass reports it as could_not_look (its
  // named document did not read), and nothing pinned.
  let failed = 0;
  intercept((u, opts) => {
    if ((opts.method || "GET") === "PUT" && /^\/repos\/test-owner\/test-pins\/contents\/pins\/case\/[0-9a-f]{64}\/00000001\.json$/.test(u.pathname) && failed === 0) {
      failed += 1;
      return answer(500, { message: "mock: the reveal's pin write fails" });
    }
    return undefined;
  });
  const real = S.anchorPending;
  t.mock.method(S, "anchorPending", async (o) => {
    const rep = await real(o);
    const ids = [...rep.newly_pinned, ...rep.already];
    return { ...rep, newly_pinned: [], already: [], could_not_look: ids.map((case_id) => ({ case_id, reason: "http_404" })) };
  });
  const r = await dryRun(t, { pinToken: PIN_TOKEN });
  assert.equal(word(r, "e"), "VERIFIED", r.show);
  assert.equal(word(r, "f"), "COULD NOT LOOK", r.show);
  assert.match(r.by.f.line, /, could not look 1; the key document case [0-9a-f]{64} names could not be read \(http_404\), so the pass did not pin it$/);
});

test("(f) REVIEW FIX 3: a pinned state counts only under the reveal's own chain; a pin read under another chain is BROKEN (unit R-PIN: no anchored state)", async (t) => {
  const real = S.pinState;
  S.pinState = async () => ({ pin: "pinned", record: { chain: "0".repeat(64) }, pin_commit: { sha: "1".repeat(40), date: null } });
  t.after(() => {
    S.pinState = real;
  });
  const r = await dryRun(t, { pinToken: PIN_TOKEN });
  S.pinState = real;
  assert.equal(word(r, "e"), "VERIFIED", r.show);
  assert.equal(word(r, "f"), "BROKEN", r.show);
  assert.match(r.by.f.line, /case [0-9a-f]{64} reads pinned under chain "0{64}", not the reveal's chain [0-9a-f]{64}$/);
});

// =============================================================================
// (g) root-file exposure
// =============================================================================

test("(g) BROKEN with the paths when the whole root is served, and (REVIEW FIX 2) for any answer but a 404, redirects and a 403 included; COULD NOT LOOK only for no answer; the paths asked are every lib/, tools/ and test/ file of this checkout", async (t) => {
  // The raw tree served as-is (a deployment that ignores vercel.json's
  // outputDirectory, the first real preview's shape): the source is exposed,
  // and the key document sits at /public/.well-known/..., not where readers
  // fetch it, so (a) is BROKEN too.
  const r = await dryRun(t, { preview: { rawTree: true } });
  assert.equal(word(r, "g"), "BROKEN");
  assert.match(r.by.g.line, /answered other than 404: README\.md \(HTTP 200, \d+ bytes\), package\.json \(HTTP 200, \d+ bytes\), lib\//);
  assert.equal(r.by.g.line.includes("package-lock.json ("), false, "a file this checkout does not have is not served");
  assert.equal(word(r, "a"), "BROKEN");
  assert.match(r.by.a.line, /HTTP 404, not served/);

  // REVIEW FIX 2: any answer but a 404 is BROKEN, redirects and a 403
  // included, each with its path; a request that got no answer alone is
  // COULD NOT LOOK.
  const odd = {
    "/README.md": { status: 301, headers: { location: "/readme" } },
    "/package.json": { status: 302, headers: { location: "https://elsewhere.example/package.json" } },
    "/lib/_case.js": { status: 307, headers: { location: "/lib/case" } },
    "/tools/mint_case_key.js": { status: 308, headers: { location: "/tools/mint" } },
    "/test/helpers/mock_store.js": { status: 403 },
  };
  const moved = await dryRun(t, { preview: { answers: odd } });
  assert.equal(word(moved, "g"), "BROKEN", moved.show);
  assert.match(moved.by.g.line, /5 of \d+ paths \([^)]*\) answered other than 404: /);
  for (const [p, a] of Object.entries(odd)) {
    const to = a.headers ? ` to ${a.headers.location}` : "";
    assert.ok(moved.by.g.line.includes(`${p.slice(1)} (HTTP ${a.status}${to}, `), `${p} in: ${moved.by.g.line}`);
  }
  const dropped = await dryRun(t, { preview: { answers: { "/README.md": { drop: true }, "/lib/_case.js": { drop: true } } } });
  assert.equal(word(dropped, "g"), "COULD NOT LOOK", dropped.show);
  assert.match(dropped.by.g.line, /2 of \d+ paths \([^)]*\) got no answer: README\.md \(no answer \(ECONNRESET\)\), lib\/_case\.js/);
  const both = await dryRun(t, { preview: { answers: { "/README.md": { drop: true }, "/package.json": { status: 403 } } } });
  assert.equal(word(both, "g"), "BROKEN", "an answer that is not a 404 outranks a path that got none");

  const { paths } = tool.exposurePaths(ROOT);
  for (const p of ["README.md", "package.json", "package-lock.json", "lib/_case_seal.js", "tools/preview_dry_run.js", "test/helpers/mock_store.js",
    "test/fixtures/reconcile/cases.json"]) {
    assert.ok(paths.includes(p), p);
  }
  for (const d of ["lib", "tools", "test"]) {
    const walk = (dir) => fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(`${dir}/${e.name}`) : [`${dir}/${e.name}`]));
    assert.deepEqual(paths.filter((p) => p.startsWith(`${d}/`)), walk(d).sort(), d);
  }
});

// =============================================================================
// a protected preview: Vercel Authentication and the automation bypass
// =============================================================================

test("PROTECTED, RIGHT BYPASS: the checks run (all VERIFIED with both flags); every request carries the secret and none asks for the bypass cookie, which the stand-in answers with Vercel's 307 handshake", async (t) => {
  const r = await dryRun(t, { bypass: BYPASS, exhaustQuota: true, pinToken: PIN_TOKEN, preview: { protect: { secret: BYPASS } } });
  for (const id of "abcdefg") assert.equal(word(r, id), "VERIFIED", r.show);
  assert.equal(r.code, 0);
  const qs = r.preview.requests;
  assert.ok(qs.length > 150, `the whole run went through: ${qs.length} requests`);
  for (const q of qs) assert.equal(q.headers["x-vercel-protection-bypass"], BYPASS, `${q.method} ${q.path}${q.search}`);
  assert.equal(qs[0].path, `/${S.CASE_KEYS_DOC}`, "the first request is (a)'s GET");
  assert.equal(qs.some((q) => Object.prototype.hasOwnProperty.call(q.headers, "x-vercel-set-bypass-cookie")), false, "no request asks for the cookie");

  // The handshake the tool must not trigger is live in the stand-in, as the
  // first real dry run saw it: with the cookie header, a 307 to the same URL;
  // with the bypass alone, the document.
  const doc = fs.readFileSync(path.join(ROOT, ...S.CASE_KEYS_FILE.split("/")));
  const handshake = await tool._internal.request(r.preview.base, "GET", `/${S.CASE_KEYS_DOC}`,
    { headers: { "x-vercel-protection-bypass": BYPASS, "x-vercel-set-bypass-cookie": "true" } });
  assert.equal(handshake.status, 307);
  assert.equal(handshake.headers.location, `/${S.CASE_KEYS_DOC}`);
  const plain = await tool._internal.request(r.preview.base, "GET", `/${S.CASE_KEYS_DOC}`, { headers: { "x-vercel-protection-bypass": BYPASS } });
  assert.equal(plain.status, 200);
  assert.ok(plain.body.equals(doc));

  // A bypass sent to a preview that is not protected changes nothing (a
  // fresh store: the arm above spent the key's opens for today).
  gh = new MockGitHubStore();
  restore();
  restore = install(gh);
  const open = await dryRun(t, { bypass: BYPASS });
  for (const id of "abdeg") assert.equal(word(open, id), "VERIFIED", open.show);
});

test("PROTECTED, NO BYPASS OR A WRONG ONE: Vercel's SSO 401 on the first request makes every check COULD NOT LOOK, saying which; nothing more is asked or written; exit 3", async (t) => {
  const none = await dryRun(t, { exhaustQuota: true, pinToken: PIN_TOKEN, preview: { protect: { secret: BYPASS } } });
  for (const id of "abcdefg") {
    assert.equal(word(none, id), "COULD NOT LOOK", none.show);
    assert.match(none.by[id].line, new RegExp(`^COULD NOT LOOK \\(${id}\\) [^:]+: protected preview, no bypass given \\(the first request, ` +
      "GET /\\.well-known/arcaeon/case-signing-keys\\.json, answered HTTP 401 with Vercel's SSO page; give --bypass or set VERCEL_AUTOMATION_BYPASS_SECRET\\)$"));
  }
  assert.equal(none.code, 3);
  assert.equal(none.preview.requests.length, 1, "one request, then nothing");
  assert.equal(Object.prototype.hasOwnProperty.call(none.preview.requests[0].headers, "x-vercel-protection-bypass"), false);

  const wrong = await dryRun(t, { bypass: WRONG_BYPASS, exhaustQuota: true, pinToken: PIN_TOKEN, preview: { protect: { secret: BYPASS } } });
  for (const id of "abcdefg") assert.match(wrong.by[id].line, new RegExp(`^COULD NOT LOOK \\(${id}\\) [^:]+: protected preview, the bypass given was refused `), wrong.show);
  assert.equal(wrong.code, 3);
  assert.equal(wrong.preview.requests.length, 1);
  assert.equal(gh.putLog.length, 0, "no case, stamp or counter was written");
});

test("A 401 THAT IS NOT VERCEL'S SSO PAGE is left to the checks: (a) to (f) read it as COULD NOT LOOK, never VERIFIED; (g) reads any answer but a 404 as BROKEN", async (t) => {
  const r = await dryRun(t, { exhaustQuota: true, pinToken: PIN_TOKEN, preview: { protect: { page: "plain" } } });
  for (const id of "abcdef") assert.equal(word(r, id), "COULD NOT LOOK", r.show);
  assert.match(r.by.a.line, /HTTP 401 before any function answered/);
  assert.equal(r.by.a.line.includes("protected preview"), false);
  assert.equal(word(r, "g"), "BROKEN");
  assert.match(r.by.g.line, /answered other than 404: README\.md \(HTTP 401, /);
  assert.equal(r.code, 3);
});

test("vercelSso: Vercel's page is told by its sso-api link, its nonce cookie, or its title served by Vercel; a bare 401, another server's page or a 200 is not it", () => {
  const ans = (status, html, headers = {}) => ({ status, headers, body: Buffer.from(html) });
  assert.equal(tool.vercelSso(ans(401, '<a href="https://vercel.com/sso-api?url=x&nonce=y">')), true);
  assert.equal(tool.vercelSso(ans(401, "", { "set-cookie": ["_vercel_sso_nonce=abc; Path=/"] })), true);
  assert.equal(tool.vercelSso(ans(401, "<title>Authentication Required</title>", { server: "Vercel" })), true);
  assert.equal(tool.vercelSso(ans(401, "Unauthorized")), false);
  assert.equal(tool.vercelSso(ans(401, "<title>Authentication Required</title>", { server: "nginx" })), false);
  assert.equal(tool.vercelSso(ans(200, '<a href="https://vercel.com/sso-api?url=x">')), false);
  assert.equal(tool.vercelSso({ error: "no answer (ECONNREFUSED)" }), false);
});

test("REDACTION: a preview that echoes the bearer key and the bypass secret in its refusal code is printed with [redacted], never either", async (t) => {
  const r = await dryRun(t, { bypass: BYPASS, preview: { wrap: onOp("case-open", (req, res) =>
    res.status(401).json({ ok: false, error_code: `echo ${String(req.headers.authorization).slice(7)} ${req.headers["x-vercel-protection-bypass"]}`, error: "echoed" })) } });
  assert.equal(word(r, "c"), "BROKEN");
  assert.match(r.by.c.line, /answered HTTP 401 echo \[redacted\] \[redacted\], not 201/);
});

// =============================================================================
// exit codes and the CLI
// =============================================================================

test("EXIT CODES: 0 all VERIFIED, 2 a BROKEN with nothing unlooked, 3 when anything COULD NOT LOOK, even beside a BROKEN", async (t) => {
  const w = (word) => ({ word });
  assert.equal(tool.exitCodeOf([w("VERIFIED"), w("VERIFIED")]), 0);
  assert.equal(tool.exitCodeOf([w("VERIFIED"), w("BROKEN")]), 2);
  assert.equal(tool.exitCodeOf([w("BROKEN"), w("COULD NOT LOOK")]), 3);
  assert.equal(tool.exitCodeOf([w("COULD NOT LOOK"), w("BROKEN")]), 3);

  const two = await dryRun(t, { exhaustQuota: true, pinToken: PIN_TOKEN, preview: { answers: { "/README.md": { status: 200, body: "served" } } } });
  assert.deepEqual(two.results.map((x) => x.word), ["VERIFIED", "VERIFIED", "VERIFIED", "VERIFIED", "VERIFIED", "VERIFIED", "BROKEN"], two.show);
  assert.equal(two.code, 2);
  const three = await dryRun(t, { preview: { rawTree: true } });
  assert.equal(word(three, "g"), "BROKEN");
  assert.equal(three.code, 3);
});

// What (e) says in a child-process run against the stand-in: the stand-in is
// this checkout's api/ carrying the committed key document, with no
// VERCEL_GIT_COMMIT_SHA in its environment, so since Design I its reveal
// cannot name the document it would seal under and seals nothing (503
// document_unavailable), which the dry run reads as COULD NOT LOOK.
const UNSEALED_E = /^COULD NOT LOOK \(e\) chunked case-reveal: case-reveal with .*: HTTP 503 document_unavailable: the preview could not answer this request$/;

function runCli(args, extraEnv = {}) {
  return new Promise((resolve) => {
    const env = { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(GITHUB_|STAMP_|WITNESS_|VERCEL_)/.test(k))),
      WITNESS_RECONCILE_VERIFIER: RECONCILE_KEY.verifier, ...extraEnv };
    const child = spawn(process.execPath, [TOOL, ...args], { env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => { stdout += c; });
    child.stderr.on("data", (c) => { stderr += c; });
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

function closedPort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

test("CLI: seven lines on stdout and nothing else, in order; no key, operator key or pin token on either stream; exit 3 without the two flags", async (t) => {
  const p = await startPreview();
  t.after(() => p.close());
  const r = await runCli(["--base", p.base, "--key", KEY, "--operator-key", OPERATOR_KEY]);
  const lines = r.stdout.split("\n");
  assert.equal(lines.pop(), "", "stdout ends with a newline");
  assert.equal(lines.length, 7, r.stdout);
  assert.deepEqual(lines.map((l) => /^(VERIFIED|BROKEN|COULD NOT LOOK) \(([a-g])\)/.exec(l)).map((m) => m && `${m[1]} ${m[2]}`),
    ["VERIFIED a", "VERIFIED b", "COULD NOT LOOK c", "VERIFIED d", "COULD NOT LOOK e", "COULD NOT LOOK f", "VERIFIED g"], r.stdout);
  // (e) could not look: the stand-in (this checkout's api/, carrying the
  // committed document, built at no named commit) seals nothing.
  assert.match(lines[4], UNSEALED_E);
  assert.equal(r.code, 3);
  for (const s of SECRETS) {
    assert.equal(r.stdout.includes(s), false);
    assert.equal(r.stderr.includes(s), false);
  }
  assert.match(r.stderr, /^dry run: preview http:\/\/127\.0\.0\.1:\d+, run [0-9a-f]{16}, without a protection bypass$/m, "progress goes to stderr");

  // Nothing listening: every check that needs the preview COULD NOT LOOK, and the pin token is still never printed.
  const port = await closedPort();
  const dead = await runCli(["--base", `http://127.0.0.1:${port}`, "--key", KEY, "--operator-key", OPERATOR_KEY, "--pin-token", PIN_TOKEN, "--exhaust-quota"]);
  assert.equal(dead.code, 3);
  const deadLines = dead.stdout.trim().split("\n");
  assert.equal(deadLines.length, 7);
  for (const l of deadLines) assert.match(l, /^COULD NOT LOOK \([a-g]\) /, l);
  for (const s of SECRETS) assert.equal((dead.stdout + dead.stderr).includes(s), false);
});

test("CLI, PROTECTED: the bypass is read from VERCEL_AUTOMATION_BYPASS_SECRET when the flag is absent, the flag wins over it, an empty variable is no bypass; never printed", async (t) => {
  const p = await startPreview({ protect: { secret: BYPASS } });
  t.after(() => p.close());
  const words = (r) => r.stdout.trim().split("\n").map((l) => /^(VERIFIED|BROKEN|COULD NOT LOOK) \(([a-g])\)/.exec(l)).map((m) => m && `${m[1]} ${m[2]}`);

  const fromEnv = await runCli(["--base", p.base, "--key", KEY], { VERCEL_AUTOMATION_BYPASS_SECRET: BYPASS });
  assert.deepEqual(words(fromEnv), ["VERIFIED a", "VERIFIED b", "COULD NOT LOOK c", "VERIFIED d", "COULD NOT LOOK e", "COULD NOT LOOK f", "VERIFIED g"], fromEnv.stdout);
  assert.match(fromEnv.stdout.trim().split("\n")[4], UNSEALED_E, "(e) could not look, as in the CLI test above");
  assert.equal(fromEnv.code, 3);
  assert.match(fromEnv.stderr, /, with a protection bypass$/m);
  const seen = p.requests.length;
  assert.ok(seen > 130, `the whole run went through: ${seen} requests`);
  assert.ok(p.requests.every((q) => q.headers["x-vercel-protection-bypass"] === BYPASS));

  const flagWins = await runCli(["--base", p.base, "--key", KEY, "--bypass", WRONG_BYPASS], { VERCEL_AUTOMATION_BYPASS_SECRET: BYPASS });
  for (const l of flagWins.stdout.trim().split("\n")) assert.match(l, /^COULD NOT LOOK \([a-g]\) [^:]+: protected preview, the bypass given was refused /, l);
  assert.equal(flagWins.code, 3);
  assert.equal(p.requests.length, seen + 1, "one request, then nothing");

  for (const env of [{}, { VERCEL_AUTOMATION_BYPASS_SECRET: "" }]) {
    const none = await runCli(["--base", p.base, "--key", KEY], env);
    const lines = none.stdout.trim().split("\n");
    assert.equal(lines.length, 7);
    for (const l of lines) assert.match(l, /^COULD NOT LOOK \([a-g]\) [^:]+: protected preview, no bypass given /, l);
    assert.equal(none.code, 3);
  }
  for (const r of [fromEnv, flagWins]) for (const s of SECRETS) assert.equal((r.stdout + r.stderr).includes(s), false);
});

test("CLI usage: --base and --key are required, --base is an origin, no flag is empty, an unknown flag is refused (exit 1, nothing on stdout); --help prints the header", async () => {
  for (const args of [[], ["--base", "https://x.example"], ["--key", KEY], ["--base", "not a url", "--key", KEY],
    ["--base", "https://x.example/some/path", "--key", KEY], ["--base", "https://x.example?q=1", "--key", KEY], ["--base", "ftp://x.example", "--key", KEY],
    ["--base", "https://x.example", "--key", " "], ["--base", "https://x.example", "--key", KEY, "--pin-token", ""], ["--base", "https://x.example", "--key", KEY, "--what"],
    ["--base", "https://x.example", "--key"], ["--base", "https://x.example", "--key", KEY, "--bypass", ""], ["--base", "https://x.example", "--key", KEY, "--bypass"]]) {
    const r = await runCli(args);
    assert.equal(r.code, 1, JSON.stringify(args));
    assert.equal(r.stdout, "", JSON.stringify(args));
  }
  const h = await runCli(["--help"]);
  assert.equal(h.code, 0);
  assert.match(h.stdout, /^tools\/preview_dry_run\.js — a dry run of the case protocol/);
  assert.match(h.stdout, /EXIT CODES: 0 every check VERIFIED; 2 a check BROKEN; 3 a check COULD NOT/);
  assert.match(h.stdout, /\[--bypass <secret>\] \[--operator-key <k>\] \[--pin-token <t>\] \[--exhaust-quota\]/);
  assert.match(h.stdout, /VERCEL_AUTOMATION_BYPASS_SECRET/);
});

test("T03 (f) DESIGN J: a case still not pinned after the pass, its pin write failing at the reveal and in the pass, is COULD NOT LOOK with the pass's reason, never BROKEN", async (t) => {
  // every write of the numbered pin fails: at the reveal and in the pass
  let failed = 0;
  intercept((u, opts) => {
    if ((opts.method || "GET") === "PUT" && /^\/repos\/test-owner\/test-pins\/contents\/pins\/case\/[0-9a-f]{64}\/00000001\.json$/.test(u.pathname)) {
      failed += 1;
      return answer(500, { message: "mock: every pin write fails" });
    }
    return undefined;
  });
  const waiting = await dryRun(t, { pinToken: PIN_TOKEN });
  assert.ok(failed >= 2, "fixture: the reveal's write and the pass's both failed");
  assert.equal(word(waiting, "f"), "COULD NOT LOOK", waiting.show);
  assert.match(waiting.by.f.line, /; case [0-9a-f]{64} is not pinned yet \(store_error\)$/);
});

test("T05 (f) DESIGN J: a pin the reader could not read is COULD NOT LOOK, naming why", async (t) => {
  const real = S.pinState;
  S.pinState = async () => ({ pin: "could_not_look", reason: "pin_commit_unreadable" });
  t.after(() => {
    S.pinState = real;
  });
  const r = await dryRun(t, { pinToken: PIN_TOKEN });
  assert.equal(word(r, "f"), "COULD NOT LOOK", r.show);
  assert.match(r.by.f.line, /; the pin of case [0-9a-f]{64} could not be read \(pin_commit_unreadable\)$/);
});

test("MUST-FAIL GAP (T04, unit R-PIN): a case the pass did not pin, not pending and with no candidate deferred, reads not_pinned and is BROKEN, never 'fell outside this run's window'", async (t) => {
  const real = S.pinState;
  S.pinState = async () => ({ pin: "not_pinned" });
  t.after(() => {
    S.pinState = real;
  });
  const r = await dryRun(t, { pinToken: PIN_TOKEN });
  S.pinState = real;
  assert.equal(word(r, "f"), "BROKEN", r.show);
  assert.match(r.by.f.line, /\(0 deferred\)[^;]*; case [0-9a-f]{64} reads pin not_pinned, not pinned under the reveal's chain$/);
});

test("MUST-FAIL GAP (PD01, unit R-I): a preview whose reveal says its bundled key document is not the one at its commit, or that its commit is off its branch, is BROKEN in (e), saying so; a document it could not read stays COULD NOT LOOK", async (t) => {
  const other = { ...TEST_DOC, keys: TEST_DOC.keys.map((e) => ({ ...e, note: `${e.note} (another copy)` })) };
  for (const [commit, reason] of [[KD.serve(gh, other), "bundled_document_differs"], [KD.serveOffBranch(gh, TEST_DOC, "4".repeat(40)), "commit_not_on_branch"]]) {
    const r = await dryRun(t, { preview: { signer: { env: { ...SIGNER.env, [S.DEPLOY_COMMIT_ENV]: commit }, keyDocument: TEST_DOC } } });
    assert.equal(word(r, "e"), "BROKEN", r.show);
    assert.match(r.by.e.line, new RegExp(`answered HTTP 503 document_unavailable \\(${reason}\\): the preview's key document is not the one at the commit it names on its published branch, so the preview seals nothing$`));
  }
});
