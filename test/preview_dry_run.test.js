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
//   (g) a deployment serving the whole root, and deployment protection.
// What cannot run against the mock is the live preview itself: Vercel's own
// body parser, its static serving, its deployment protection and GitHub's
// read-after-write. The stand-in plants each one's two behaviours; the real
// answer is the dry run's to read.
// And the CLI: seven lines on stdout and nothing else, exit 0/2/3 (3 wins
// over 2), usage 1, and no key, operator key or pin token on either stream,
// nor the operator key or pin token in any request the preview received.
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
const net = require("node:net");
const path = require("node:path");
const { spawn } = require("node:child_process");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { startPreview, readVercel, vercelBody } = require("./helpers/vercel_preview.js");
const store = require("../lib/_store.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const S = require("../lib/_case_seal.js");
const tool = require("../tools/preview_dry_run.js");

const ROOT = path.join(__dirname, "..");
const TOOL = path.join(ROOT, "tools", "preview_dry_run.js");
const PINS = process.env.GITHUB_PIN_REPO;
const STAMPS = process.env.STAMP_REPO;
const USAGE = process.env.GITHUB_USAGE_REPO;
const KEY = "dry-run-issued-key-0001";
const OPERATOR_KEY = "dry-run-operator-key-0001-never-sent";
const PIN_TOKEN = "dry-run-pin-token-0001-never-sent";
const SECRETS = [KEY, OPERATOR_KEY, PIN_TOKEN];

let gh;
let restore;
let realSleep;
beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
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

async function dryRun(t, { preview = {}, ...opts } = {}) {
  const p = await startPreview(preview);
  t.after(() => p.close());
  const out = [];
  const err = [];
  const r = await tool.run({ base: p.base, key: KEY, stdout: (l) => out.push(l), stderr: (l) => err.push(l), ...opts });
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

  const doc = fs.readFileSync(path.join(ROOT, ...S.CASE_KEYS_DOC.split("/")));
  assert.match(r.by.a.line, new RegExp(`HTTP 200, ${doc.length} bytes, sha256 ${crypto.createHash("sha256").update(doc).digest("hex")}`));
  const id = /case_id ([0-9a-f]{64})/.exec(r.by.b.line)[1];
  assert.match(r.by.b.line, /rewrites \/case\/:case_id to \/api\/verify\?op=case-page/);
  assert.match(r.by.c.line, /opens 1-20 answered HTTP 201 and open 21 was refused HTTP 429 open_quota_exceeded/);
  assert.equal(gh.read(USAGE, H._internal.openQuotaPath(KEY, today())).count, 20, "the real counter, in the usage repository");
  const commit = /commit ([0-9a-f]{40})/.exec(r.by.d.line)[1];
  assert.match(r.by.d.line, new RegExp(`read stamp_commit ${commit}, the same commit`));
  assert.equal(gh.read(PINS, C.registrationPath(id, "a")).stamp_commit, commit);
  assert.match(r.by.e.line, new RegExp(`no content-length answered HTTP 201: case_id ${id} sealed VERDICT, verdict MATCHED, pin anchored`));
  assert.equal(gh.read(PINS, C.casePath(id)).status, "VERDICT");
  assert.match(r.by.f.line, new RegExp(`case ${id} is anchored, chain ${S.caseChain(gh.read(PINS, C.casePath(id)))} \\(pinned at its reveal\\)`));
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
  const doc = fs.readFileSync(path.join(ROOT, ...S.CASE_KEYS_DOC.split("/")));
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
  assert.match(healed.by.e.line, /pin pending/);
  assert.equal(word(healed, "f"), "VERIFIED", healed.show);
  assert.match(healed.by.f.line, /anchored 1, already 0[^;]*; case [0-9a-f]{64} is anchored, chain [0-9a-f]{64} \(pinned by this pass\)/);

  // A sealable case whose file does not read: the pass refuses it.
  gh = new MockGitHubStore();
  restore();
  restore = install(gh);
  const bad = "ab".repeat(32);
  gh.seed(PINS, C.casePath(bad), { not: "a case" });
  gh.seed(PINS, C.registrationPath(bad, "a"), {});
  gh.seed(PINS, C.registrationPath(bad, "b"), {});
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
  assert.equal(gh.putLog.some((w) => w.path.startsWith("pins/case/") && w.path.endsWith("latest.json") && w.repo === PINS), true, "only the reveal pinned");
  assert.equal(process.env.GITHUB_PIN_TOKEN, "test-token", "the pin token is put back");
});

// =============================================================================
// (g) root-file exposure, and deployment protection
// =============================================================================

test("(g) BROKEN with the paths when the whole root is served; the paths asked are every lib/, tools/ and test/ file of this checkout", async (t) => {
  const r = await dryRun(t, { preview: { serves: () => true } });
  assert.equal(word(r, "g"), "BROKEN");
  assert.match(r.by.g.line, /are served: README\.md \(HTTP 200, \d+ bytes\), package\.json \(HTTP 200, \d+ bytes\), lib\//);
  assert.equal(r.by.g.line.includes("package-lock.json ("), false, "a file this checkout does not have is not served");

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

test("DEPLOYMENT PROTECTION: a preview that answers 401 before any function makes every check COULD NOT LOOK, never BROKEN or VERIFIED", async (t) => {
  const r = await dryRun(t, { exhaustQuota: true, pinToken: PIN_TOKEN, preview: { protect: true } });
  for (const id of "abcdefg") assert.equal(word(r, id), "COULD NOT LOOK", r.show);
  assert.match(r.by.a.line, /HTTP 401 before any function answered/);
  assert.equal(r.code, 3);
});

test("REDACTION: a preview that echoes the bearer key in its refusal code is printed with [redacted], never the key", async (t) => {
  const r = await dryRun(t, { preview: { wrap: onOp("case-open", (req, res) =>
    res.status(401).json({ ok: false, error_code: `echo ${String(req.headers.authorization).slice(7)}`, error: "echoed" })) } });
  assert.equal(word(r, "c"), "BROKEN");
  assert.match(r.by.c.line, /answered HTTP 401 echo \[redacted\], not 201/);
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

  const two = await dryRun(t, { exhaustQuota: true, pinToken: PIN_TOKEN, preview: { serves: () => true } });
  assert.deepEqual(two.results.map((x) => x.word), ["VERIFIED", "VERIFIED", "VERIFIED", "VERIFIED", "VERIFIED", "VERIFIED", "BROKEN"], two.show);
  assert.equal(two.code, 2);
  const three = await dryRun(t, { preview: { serves: () => true } });
  assert.equal(word(three, "g"), "BROKEN");
  assert.equal(three.code, 3);
});

function runCli(args) {
  return new Promise((resolve) => {
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(GITHUB_|STAMP_|WITNESS_)/.test(k)));
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
    ["VERIFIED a", "VERIFIED b", "COULD NOT LOOK c", "VERIFIED d", "VERIFIED e", "COULD NOT LOOK f", "VERIFIED g"], r.stdout);
  assert.equal(r.code, 3);
  for (const s of SECRETS) {
    assert.equal(r.stdout.includes(s), false);
    assert.equal(r.stderr.includes(s), false);
  }
  assert.match(r.stderr, /^dry run: preview http:\/\/127\.0\.0\.1:\d+, run [0-9a-f]{16}$/m, "progress goes to stderr");

  // Nothing listening: every check that needs the preview COULD NOT LOOK, and the pin token is still never printed.
  const port = await closedPort();
  const dead = await runCli(["--base", `http://127.0.0.1:${port}`, "--key", KEY, "--operator-key", OPERATOR_KEY, "--pin-token", PIN_TOKEN, "--exhaust-quota"]);
  assert.equal(dead.code, 3);
  const deadLines = dead.stdout.trim().split("\n");
  assert.equal(deadLines.length, 7);
  for (const l of deadLines) assert.match(l, /^COULD NOT LOOK \([a-g]\) /, l);
  for (const s of SECRETS) assert.equal((dead.stdout + dead.stderr).includes(s), false);
});

test("CLI usage: --base and --key are required, --base is an origin, no flag is empty, an unknown flag is refused (exit 1, nothing on stdout); --help prints the header", async () => {
  for (const args of [[], ["--base", "https://x.example"], ["--key", KEY], ["--base", "not a url", "--key", KEY],
    ["--base", "https://x.example/some/path", "--key", KEY], ["--base", "https://x.example?q=1", "--key", KEY], ["--base", "ftp://x.example", "--key", KEY],
    ["--base", "https://x.example", "--key", " "], ["--base", "https://x.example", "--key", KEY, "--pin-token", ""], ["--base", "https://x.example", "--key", KEY, "--what"],
    ["--base", "https://x.example", "--key"]]) {
    const r = await runCli(args);
    assert.equal(r.code, 1, JSON.stringify(args));
    assert.equal(r.stdout, "", JSON.stringify(args));
  }
  const h = await runCli(["--help"]);
  assert.equal(h.code, 0);
  assert.match(h.stdout, /^tools\/preview_dry_run\.js — a dry run of the case protocol/);
  assert.match(h.stdout, /EXIT CODES: 0 every check VERIFIED; 2 a check BROKEN; 3 a check COULD NOT/);
});
