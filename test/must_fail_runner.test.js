// test/must_fail_runner.test.js — unit R-ABf (2026-10-15): the planted-defect
// runner, test/must_fail/run.js. A defect is CAUGHT only when the suite
// exits non-zero and at least one test failed; a suite killed at its
// timeout is its own result, timeout, and one that exits non-zero with no
// failing test (it did not start, say) is error; neither is ever printed as
// caught (M1). A defect's file is a relative path inside the repository
// (m-d). The ledger records, for a re-seed that catches a defect its first
// run missed, the gap test that failed, and the table prints that record
// (m-e). An interrupted run removes its copies (m-d). Unit R-WIDE (B4,
// B5): the runner plants only over a clean checkout whose unplanted suite
// passes, records the commit and each defect's sha256, counts a catch only
// on exit code 1 with a failing test, runs the suite with no secret in its
// environment and no network, prints a gap test the defects file names as
// "named, not verified" until a catch failed it, and on Windows kills the
// suite's tree with taskkill. The runner's own process tests run against a
// tiny fixture repository, never this one.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");

const RUN = path.join(__dirname, "must_fail", "run.js");
const R = require("./must_fail/run.js");

test("R-ABf M1: caught only on a non-zero exit with a failing test; a timeout is timeout and an exit with no failing test is error, never caught", () => {
  assert.equal(R.classify({ code: 1, timedOut: false, failing: ["a test"] }), "caught");
  assert.equal(R.classify({ code: 0, timedOut: false, failing: [] }), "survived");
  assert.equal(R.classify({ code: null, timedOut: true, failing: [] }), "timeout");
  assert.equal(R.classify({ code: null, timedOut: true, failing: ["a test that failed before the kill"] }), "timeout");
  assert.equal(R.classify({ code: 1, timedOut: false, failing: [] }), "error");
  assert.equal(R.classify({ code: null, timedOut: false, failing: [] }), "error");
});

// Since unit R-WIDEf (F2-c) a run with no head prints "pre-B4, not
// vouched": the table tests below give their runs the commit a run of the
// fixed runner records (HEAD_OF), except the one that reads an old ledger.
const HEAD_OF = { head: "c".repeat(40), porcelain: "", defect_sha256: "d".repeat(64) };
test("R-ABf M1: the table prints a timeout and an error as such, with no date of a catch", () => {
  const defects = [{ id: "X1", file: "lib/x.js", what: "a defect" }, { id: "X2", file: "lib/x.js", what: "another" }];
  const ledger = {
    X1: { runs: [{ date: "2026-10-15", result: "timeout", exit: null, failing: 0, failing_tests: [], ...HEAD_OF }] },
    X2: { runs: [{ date: "2026-10-15", result: "error", exit: 1, failing: 0, failing_tests: [], ...HEAD_OF }] },
  };
  const t = R.table(defects, ledger);
  assert.ok(t.includes("| X1 | `lib/x.js` | a defect | timeout | never |"), t);
  assert.ok(t.includes("| X2 | `lib/x.js` | another | error (exit 1) | never |"), t);
  assert.doesNotMatch(t.split("\n").slice(2).join("\n"), /caught/, "no row says caught");
});

test("R-ABf M1: no run in a committed ledger is recorded caught with no failing test", () => {
  const dir = path.join(__dirname, "must_fail");
  const ledgers = fs.readdirSync(dir).filter((f) => f.endsWith(".ledger.json"));
  assert.ok(ledgers.length >= 1);
  for (const f of ledgers) {
    for (const [id, e] of Object.entries(JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")))) {
      for (const r of e.runs) {
        const caught = r.result ? r.result === "caught" : r.caught;
        if (caught) assert.ok(r.failing > 0, `${f} ${id} ${r.date}`);
      }
    }
  }
});

test("R-ABf m-d: a defect's file must be a relative path inside the repository: an absolute path or a '..' segment is refused before anything is planted", () => {
  const ok = { id: "OK", file: "README.md", find: "# ", replace: "#  ", what: "x" };
  assert.throws(() => R.checkDefects([{ ...ok, file: "/etc/passwd" }]), /OK: file must be a relative path inside the repository/);
  assert.throws(() => R.checkDefects([{ ...ok, file: "../outside.js" }]), /file must be a relative path inside the repository/);
  assert.throws(() => R.checkDefects([{ ...ok, file: "lib/../../outside.js" }]), /file must be a relative path inside the repository/);
  assert.throws(() => R.checkDefects([{ ...ok, file: "lib\\..\\..\\outside.js" }]), /file must be a relative path inside the repository/);
});

test("R-ABf m-e: a re-seed that catches a defect its earlier run missed records the gap test that failed; the table prints the record's words, and a first-run catch records none", () => {
  const survived = R.runRecord([], { code: 0, timedOut: false, failing: [] }, "2026-10-14");
  assert.equal(survived.result, "survived");
  assert.equal("caught_by" in survived, false);
  const reseed = R.runRecord([survived], { code: 1, timedOut: false, failing: ["MUST-FAIL GAP (X1): the gap test", "R-N2 B2 (since unit R-N3): the body audit"] },
    "2026-10-15");
  assert.deepEqual([reseed.result, reseed.caught_by], ["caught", ["MUST-FAIL GAP (X1): the gap test"]]);
  const first = R.runRecord([], { code: 1, timedOut: false, failing: ["a test"] }, "2026-10-15");
  assert.equal("caught_by" in first, false);
  const t = R.table([{ id: "X1", file: "lib/x.js", what: "a defect" }], { X1: { runs: [{ ...survived, ...HEAD_OF }, { ...reseed, ...HEAD_OF }] } });
  assert.ok(t.includes("| X1 | `lib/x.js` | a defect | survived; caught on re-seed by MUST-FAIL GAP (X1): the gap test | 2026-10-15 |"), t);
  assert.equal(R.table.length, 2, "the table takes the defects and the ledger, and no operator's words");
});

test("R-ABf m-e: the table reads a ledger written before unit R-ABf (caught, first_failing) the same way", () => {
  const ledger = { K07: { runs: [{ date: "2026-10-14", caught: false, failing: 0, first_failing: [] },
    { date: "2026-10-14", caught: true, failing: 2, first_failing: ["MUST-FAIL GAP (K07): singleParty", "R-N2 B2: the body audit"] }] } };
  const t = R.table([{ id: "K07", file: "lib/_case.js", what: "a guard" }], ledger);
  // and, recording no head, as a run before unit R-WIDE, B4 (R-WIDEf, F2-c)
  assert.ok(t.includes("| K07 | `lib/_case.js` | a guard | survived (pre-B4, not vouched); caught on re-seed by MUST-FAIL GAP (K07): singleParty | 2026-10-14 (pre-B4, not vouched) |"), t);
});

// The interrupt tests send SIGINT, which Windows does not deliver to a
// handler: there they skip, saying why (unit R-WIDE, B5); the taskkill path
// is asserted below on every platform.
const ON_WINDOWS = process.platform === "win32" ? "Windows delivers no SIGINT to a handler and has no process groups; the taskkill path is asserted by R-WIDE B5" : false;
// A fixture repository whose suite is test/must_fail/slow_suite.fixture.js.
const slowFixture = () => fixtureRepo({ suite: fs.readFileSync(path.join(__dirname, "must_fail", "slow_suite.fixture.js"), "utf8") });

test("R-ABf m-d: an interrupted run (SIGINT) removes its copies of the tree", { skip: ON_WINDOWS }, async () => {
  const fx = slowFixture();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "must-fail-sigint-"));
  const work = path.join(tmp, "work");
  fs.mkdirSync(work);
  // the suite it runs waits a minute (the run is interrupted while its
  // unplanted suite runs), not the suite this test is part of
  const env = { ...process.env, TMPDIR: work };
  delete env.NODE_TEST_CONTEXT;
  const child = spawn(process.execPath, [RUN, fx.defects, "--root", fx.root, "--workers", "1"], { env, stdio: "ignore" });
  const copies = () => fs.readdirSync(work).filter((f) => f.startsWith("must-fail-"));
  try {
    for (let i = 0; i < 400 && copies().length === 0; i += 1) await new Promise((r) => setTimeout(r, 50));
    assert.equal(copies().length, 1, "fixture: the run made its copy");
    await new Promise((r) => setTimeout(r, 1500));
    assert.equal(child.exitCode, null, "fixture: the run is still running");
    const ended = new Promise((r) => child.on("exit", (code, signal) => r({ code, signal })));
    child.kill("SIGINT");
    const end = await ended;
    assert.ok(end.code === 130 || end.signal === "SIGINT", JSON.stringify(end));
    assert.deepEqual(copies(), [], "no copy left");
    assert.equal(fs.existsSync(fx.defects.replace(/\.json$/, ".ledger.json")), false, "no run recorded");
  } finally {
    child.kill("SIGKILL");
    fs.rmSync(tmp, { recursive: true, force: true });
    fs.rmSync(fx.root, { recursive: true, force: true });
  }
});

// R-ABf's must-fail gap tests (the runner): each fails with its planted defect
test("MUST-FAIL GAP (RN8, RN9): a runner started with NODE_TEST_CONTEXT set (as from a test) still runs its suite, and an interrupt kills the suite's test processes, not only the suite", { skip: ON_WINDOWS }, async () => {
  const fx = slowFixture();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "must-fail-sigint-"));
  const work = path.join(tmp, "work");
  fs.mkdirSync(work);
  const pidFile = path.join(tmp, "fixture.pid");
  const env = { ...process.env, TMPDIR: work, NODE_TEST_CONTEXT: "child", MUST_FAIL_FIXTURE_PID_FILE: pidFile };
  const child = spawn(process.execPath, [RUN, fx.defects, "--root", fx.root, "--workers", "1"], { env, stdio: "ignore" });
  const alive = (pid) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  };
  let pid = null;
  try {
    for (let i = 0; i < 400 && !fs.existsSync(pidFile); i += 1) await new Promise((r) => setTimeout(r, 50));
    assert.equal(fs.existsSync(pidFile), true, "the suite ran its test (NODE_TEST_CONTEXT did not end it at once)");
    pid = Number(fs.readFileSync(pidFile, "utf8"));
    assert.equal(child.exitCode, null, "the run is still running");
    const ended = new Promise((r) => child.on("exit", (code, signal) => r({ code, signal })));
    child.kill("SIGINT");
    await ended;
    for (let i = 0; i < 40 && alive(pid); i += 1) await new Promise((r) => setTimeout(r, 50));
    assert.equal(alive(pid), false, "the suite's test process was killed with it");
  } finally {
    child.kill("SIGKILL");
    if (pid && alive(pid)) process.kill(pid, "SIGKILL");
    fs.rmSync(tmp, { recursive: true, force: true });
    fs.rmSync(fx.root, { recursive: true, force: true });
  }
});

// =============================================================================
// UNIT R-WIDE, B4 and B5: the runner vouches only for a catch that happened
// =============================================================================

// A tiny repository: lib/x.js, a suite that passes against it, and a
// defects file, committed. `suite` is the test file's text; `extra` more
// files. -> {root, defects}.
function fixtureRepo({ suite, extra = {}, defects } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "must-fail-fixture-"));
  const files = {
    "lib/x.js": "\"use strict\";\nmodule.exports = (a) => a + 1;\n",
    "test/x.test.js": suite || "\"use strict\";\nconst { test } = require(\"node:test\");\nconst assert = require(\"node:assert/strict\");\n" +
      "test(\"x adds one\", () => assert.equal(require(\"../lib/x.js\")(1), 2));\n",
    "defects.json": JSON.stringify(defects || [{ id: "F1", file: "lib/x.js", find: "a + 1", replace: "a + 2", what: "x adds two" }]),
    ...extra,
  };
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), text);
  }
  const git = (...a) => {
    const r = spawnSync("git", ["-C", root, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", ...a], { encoding: "utf8" });
    assert.equal(r.status, 0, `git ${a.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  git("init", "-q");
  git("add", "-A");
  git("commit", "-q", "-m", "fixture");
  return { root, defects: path.join(root, "defects.json"), head: git("rev-parse", "HEAD"), git };
}
// The runner over a fixture, to its end. -> {code, stderr, ledger}.
function runOver(fx, { env = {}, argv = [] } = {}) {
  const childEnv = { ...process.env, ...env };
  delete childEnv.NODE_TEST_CONTEXT;
  const r = spawnSync(process.execPath, [RUN, fx.defects, "--root", fx.root, "--workers", "1", ...argv], { env: childEnv, encoding: "utf8", timeout: 120000 });
  let ledger = null;
  try {
    ledger = JSON.parse(fs.readFileSync(fx.defects.replace(/\.json$/, ".ledger.json"), "utf8"));
  } catch {
    ledger = null;
  }
  return { code: r.status, stderr: String(r.stderr), ledger };
}

test("R-WIDE B4: the runner refuses to plant unless the unplanted suite exits 0 with no failing test; nothing is planted and no ledger is written", (t) => {
  const failing = "\"use strict\";\nconst { test } = require(\"node:test\");\nconst assert = require(\"node:assert/strict\");\n" +
    "test(\"x adds one\", () => assert.equal(require(\"../lib/x.js\")(1), 2));\ntest(\"already broken\", () => assert.equal(1, 2));\n";
  const fx = fixtureRepo({ suite: failing });
  t.after(() => fs.rmSync(fx.root, { recursive: true, force: true }));
  const r = runOver(fx);
  assert.equal(r.code, 1, r.stderr);
  assert.match(r.stderr, /the unplanted suite does not pass \(exit 1, 1 failing: already broken\).*Nothing was planted\./);
  assert.equal(r.ledger, null, "no ledger written");
  // control: the passing suite plants, and the defect is caught
  const ok = fixtureRepo();
  t.after(() => fs.rmSync(ok.root, { recursive: true, force: true }));
  const g = runOver(ok);
  assert.equal(g.code, 0, g.stderr);
  assert.equal(g.ledger.F1.runs[0].result, "caught", JSON.stringify(g.ledger));
});

test("R-WIDE B4: caught only when the suite exits with code 1 and a test failed: another exit code with failing tests is error", () => {
  const R = require("./must_fail/run.js");
  assert.equal(R.classify({ code: 1, timedOut: false, failing: ["a test"] }), "caught");
  assert.equal(R.classify({ code: 2, timedOut: false, failing: ["a test"] }), "error");
  assert.equal(R.classify({ code: 7, timedOut: false, failing: ["a test"] }), "error");
  assert.equal(R.classify({ code: null, timedOut: false, failing: ["a test"] }), "error");
});

test("R-WIDE B4: the runner refuses a tree that is not clean, and every ledger run records the commit, the clean status and the sha256 of the defect's {find, replace}", (t) => {
  const fx = fixtureRepo();
  t.after(() => fs.rmSync(fx.root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(fx.root, "lib", "y.js"), "// not committed\n");
  const dirty = runOver(fx);
  assert.equal(dirty.code, 1);
  assert.match(dirty.stderr, /is not clean \(git status --porcelain prints 1 line\(s\)\).*Nothing was planted\./);
  assert.equal(dirty.ledger, null);
  fs.rmSync(path.join(fx.root, "lib", "y.js"));
  const r = runOver(fx);
  assert.equal(r.code, 0, r.stderr);
  const run = r.ledger.F1.runs[0];
  const sha = crypto.createHash("sha256").update(JSON.stringify({ find: "a + 1", replace: "a + 2" })).digest("hex");
  assert.deepEqual([run.head, run.porcelain, run.defect_sha256], [fx.head, "", sha]);
  assert.equal(R.defectSha256({ id: "F1", find: "a + 1", replace: "a + 2", what: "x" }), sha);
});

test("R-WIDE B4: the table prints a gap test the defects file names as 'named, not verified' unless the latest catch failed it", () => {
  const d = { id: "G1", file: "lib/x.js", what: "a defect", gap: "MUST-FAIL GAP (G1): the gap test" };
  const survived = { date: "2026-10-15", result: "survived", exit: 0, failing: 0, failing_tests: [], ...HEAD_OF };
  const caughtOther = { date: "2026-10-15", result: "caught", exit: 1, failing: 1, failing_tests: ["another test"], caught_by: ["another test"], ...HEAD_OF };
  const caughtGap = { date: "2026-10-16", result: "caught", exit: 1, failing: 1, failing_tests: ["MUST-FAIL GAP (G1): the gap test"], caught_by: ["MUST-FAIL GAP (G1): the gap test"], ...HEAD_OF };
  assert.ok(R.table([d], { G1: { runs: [survived] } }).includes("| survived; MUST-FAIL GAP (G1): the gap test (named, not verified) | never |"));
  assert.ok(R.table([d], { G1: { runs: [survived, caughtOther] } }).includes("survived; caught on re-seed by another test; MUST-FAIL GAP (G1): the gap test (named, not verified) |"));
  const v = R.table([d], { G1: { runs: [survived, caughtOther, caughtGap] } });
  assert.ok(v.includes("| survived; caught on re-seed by MUST-FAIL GAP (G1): the gap test | 2026-10-16 |"), v);
  assert.doesNotMatch(v, /not verified/);
});

test("R-WIDE B4: the suite runs with no WITNESS_* variable, no GITHUB_* variable and no token, and with fetch refused to every host but this machine's", (t) => {
  const probe = "\"use strict\";\nconst { test } = require(\"node:test\");\nconst assert = require(\"node:assert/strict\");\n" +
    "test(\"x adds one\", () => assert.equal(require(\"../lib/x.js\")(1), 2));\n" +
    "test(\"no secret in the environment\", () => assert.deepEqual(Object.keys(process.env).filter((k) => /^(WITNESS_|GITHUB_)|_TOKEN$|_SECRET$/.test(k)), []));\n" +
    "test(\"no network\", async () => { await assert.rejects(fetch(\"https://api.github.com/\"), /must-fail run: no network \\(api\\.github\\.com\\)/); });\n";
  const fx = fixtureRepo({ suite: probe });
  t.after(() => fs.rmSync(fx.root, { recursive: true, force: true }));
  const r = runOver(fx, { env: { WITNESS_CASE_SIGNER_KEY: "x", GITHUB_PIN_TOKEN: "y", GITHUB_PIN_REPO: "a/b", STAMP_TOKEN: "z", SOME_SECRET: "w" } });
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.ledger.F1.runs[0].result, "caught", JSON.stringify(r.ledger));
  assert.deepEqual(Object.keys(R.scrubbedEnv({ WITNESS_X: "1", GITHUB_REPO: "a", A_TOKEN: "t", B_SECRET: "s", PATH: "/bin", NODE_TEST_CONTEXT: "child" })).sort(), ["NODE_OPTIONS", "PATH"]);
});

test("R-WIDE B5: on Windows the runner kills the suite's process tree with taskkill /T /F; elsewhere its process group", () => {
  const calls = [];
  R.killGroup({ pid: 4242, kill: () => calls.push("kill") }, { platform: "win32", run: (cmd, argv) => calls.push([cmd, ...argv]) });
  assert.deepEqual(calls, [["taskkill", "/pid", "4242", "/T", "/F"]]);
  const killed = [];
  const real = process.kill;
  process.kill = (pid, sig) => killed.push([pid, sig]);
  try {
    R.killGroup({ pid: 4242, kill: () => killed.push("kill") }, { platform: "linux", run: () => assert.fail("no taskkill off Windows") });
  } finally {
    process.kill = real;
  }
  assert.deepEqual(killed, [[-4242, "SIGKILL"]]);
});

// R-WIDE Group B's must-fail gap tests (the runner): each fails with its planted defect
test("MUST-FAIL GAP (WB34, WB40): a file changed in the tree while the run is going is never planted against: every copy is taken before the unplanted suite runs, and each defect is read from its copy", (t) => {
  // the unplanted suite edits the repository's lib/x.js once, as an operator might mid-run
  const editing = "\"use strict\";\nconst fs = require(\"node:fs\");\nconst path = require(\"node:path\");\nconst { test } = require(\"node:test\");\n" +
    "const assert = require(\"node:assert/strict\");\n" +
    "test(\"x adds one\", () => assert.equal(require(\"../lib/x.js\")(1), 2));\n" +
    "test(\"an edit in the tree mid-run\", () => {\n" +
    "  const root = process.env.MUST_FAIL_FIXTURE_ROOT;\n" +
    "  const mark = path.join(root, \".edited\");\n" +
    "  if (root && !fs.existsSync(mark)) {\n" +
    "    fs.writeFileSync(path.join(root, \"lib\", \"x.js\"), \"\\\"use strict\\\";\\nmodule.exports = (a) => 1 + a;\\n\");\n" +
    "    fs.writeFileSync(mark, \"\");\n" +
    "  }\n" +
    "});\n";
  const fx = fixtureRepo({ suite: editing });
  t.after(() => fs.rmSync(fx.root, { recursive: true, force: true }));
  const r = runOver(fx, { env: { MUST_FAIL_FIXTURE_ROOT: fx.root } });
  assert.equal(r.code, 0, r.stderr);
  assert.equal(fs.existsSync(path.join(fx.root, ".edited")), true, "fixture: the tree was edited during the run");
  assert.equal(r.ledger.F1.runs[0].result, "caught", JSON.stringify(r.ledger.F1.runs[0]));
});

test("MUST-FAIL GAP (WB37): the suite's fetch reaches this machine: a fixture that serves itself on 127.0.0.1 passes unplanted", (t) => {
  const loopback = "\"use strict\";\nconst http = require(\"node:http\");\nconst { test } = require(\"node:test\");\nconst assert = require(\"node:assert/strict\");\n" +
    "test(\"x adds one\", () => assert.equal(require(\"../lib/x.js\")(1), 2));\n" +
    "test(\"this machine answers\", async () => {\n" +
    "  const server = http.createServer((req, res) => res.end(\"here\"));\n" +
    "  await new Promise((r) => server.listen(0, \"127.0.0.1\", r));\n" +
    "  try {\n" +
    "    const got = await fetch(`http://127.0.0.1:${server.address().port}/`);\n" +
    "    assert.equal(await got.text(), \"here\");\n" +
    "  } finally {\n" +
    "    server.close();\n" +
    "  }\n" +
    "});\n";
  const fx = fixtureRepo({ suite: loopback });
  t.after(() => fs.rmSync(fx.root, { recursive: true, force: true }));
  const r = runOver(fx);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.ledger.F1.runs[0].result, "caught");
});

test("MUST-FAIL GAP (WB38, WB39): the suite's only preload is the runner's own no-network shim: an inherited NODE_OPTIONS is not carried", () => {
  const env = R.scrubbedEnv({ NODE_OPTIONS: "--require /somewhere/else.js", PATH: "/bin" });
  assert.equal(env.NODE_OPTIONS, `--require ${JSON.stringify(path.join(__dirname, "must_fail", "no_network.js"))}`);
});

// unit R-WIDE (C16): R-ABf called RN3 (the absolute-path check removed)
// equivalent; it is not, since an absolute path inside the repository passes
// the inside-the-repository check that follows
test("MUST-FAIL GAP (RN3): an absolute path inside the repository is refused by name, before the inside-the-repository check", () => {
  const ROOT_DIR = path.join(__dirname, "..");
  const inside = { id: "IN", file: path.join(ROOT_DIR, "README.md"), find: "# ", replace: "#  ", what: "x" };
  assert.equal(path.isAbsolute(inside.file), true, "fixture: absolute");
  assert.equal(path.resolve(ROOT_DIR, inside.file).startsWith(path.resolve(ROOT_DIR) + path.sep), true, "fixture: and inside the repository");
  assert.throws(() => R.checkDefects([inside], ROOT_DIR), /IN: file must be a relative path inside the repository/);
});

// =============================================================================
// UNIT R-WIDEf, F2: the runner reads the reporter it asked for
// =============================================================================

// A fixture whose suite has one passing and one failing test, not a git
// checkout: runSuite needs only a directory.
function failingSuiteDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "must-fail-reporter-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, "test"));
  fs.writeFileSync(path.join(dir, "test", "x.test.js"), "\"use strict\";\nconst { test } = require(\"node:test\");\nconst assert = require(\"node:assert/strict\");\n" +
    "test(\"passes\", () => {});\ntest(\"fails\", () => assert.equal(1, 2));\n");
  return dir;
}

test("R-WIDEf F2-a: runSuite asks for the tap reporter on stdout by name, so a failing test is counted whatever reporter the node it runs under defaults to (spec, as Node 24 does on a pipe)", async (t) => {
  const argv = R.suiteArgs("test/*.test.js");
  assert.ok(argv.includes("--test-reporter=tap"), argv.join(" "));
  assert.ok(argv.includes("--test-reporter-destination=stdout"), argv.join(" "));
  assert.equal(argv[argv.length - 1], "test/*.test.js");
  const dir = failingSuiteDir(t);
  // a node whose default reporter is spec on stdout: NODE_OPTIONS names it
  const base = R.scrubbedEnv();
  const specDefault = { ...base, NODE_OPTIONS: `${base.NODE_OPTIONS} --test-reporter=spec --test-reporter-destination=stdout` };
  const fixture = spawnSync(process.execPath, ["--test", "test/x.test.js"], { cwd: dir, env: specDefault, encoding: "utf8" });
  assert.equal(fixture.status, 1, "fixture: the suite fails");
  assert.equal(fixture.stdout.split("\n").filter((l) => /^\s*not ok /.test(l)).length, 0, "fixture: under spec, no line says not ok");
  const out = await R.runSuite(dir, "test/x.test.js", { env: specDefault });
  assert.deepEqual([out.code, out.failing], [1, ["fails"]], out.stderr);
  assert.equal(R.classify(out), "caught");
});

test("R-WIDEf F2-b: an error run keeps the last 30 lines of the suite's stderr as stderr_tail, and the table prints its first line; a catch or a survival keeps none", async (t) => {
  const lines = Array.from({ length: 40 }, (_, i) => `line ${i + 1}`);
  const err = R.runRecord([], { code: 2, timedOut: false, failing: [], stderr: `${lines.join("\n")}\n` }, "2026-10-15");
  assert.equal(err.result, "error");
  assert.deepEqual(err.stderr_tail, lines.slice(10));
  const caught = R.runRecord([], { code: 1, timedOut: false, failing: ["a test"], stderr: "noise\n" }, "2026-10-15");
  assert.equal("stderr_tail" in caught, false);
  const survived = R.runRecord([], { code: 0, timedOut: false, failing: [], stderr: "noise\n" }, "2026-10-15");
  assert.equal("stderr_tail" in survived, false);
  const tbl = R.table([{ id: "E1", file: "lib/x.js", what: "a defect" }], { E1: { runs: [{ ...err, head: "a".repeat(40) }] } });
  assert.ok(tbl.includes("| E1 | `lib/x.js` | a defect | error (exit 2): line 11 | never |"), tbl);
  // runSuite hands the stderr on: a suite that cannot start
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "must-fail-stderr-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const out = await R.runSuite(dir, "--no-such-node-flag-r-widef");
  assert.notEqual(out.code, 0);
  assert.match(out.stderr, /no-such-node-flag-r-widef/);
});

test("R-WIDEf F2-c: the table prints a run with no head (a run of the runner before unit R-WIDE, B4) as 'pre-B4, not vouched'", () => {
  const d = [{ id: "P1", file: "lib/x.js", what: "a defect" }, { id: "P2", file: "lib/x.js", what: "another" }];
  const old = { date: "2026-10-15", result: "caught", exit: 1, failing: 2, failing_tests: ["a", "b"] };
  const survivedOld = { date: "2026-10-15", result: "survived", exit: 0, failing: 0, failing_tests: [] };
  const reseedOld = { date: "2026-10-15", result: "caught", exit: 1, failing: 1, failing_tests: ["MUST-FAIL GAP (P2): x"], caught_by: ["MUST-FAIL GAP (P2): x"] };
  const tbl = R.table(d, { P1: { runs: [old] }, P2: { runs: [survivedOld, reseedOld] } });
  assert.ok(tbl.includes("| P1 | `lib/x.js` | a defect | caught (2 failing) (pre-B4, not vouched) | 2026-10-15 (pre-B4, not vouched) |"), tbl);
  assert.ok(tbl.includes("| P2 | `lib/x.js` | another | survived (pre-B4, not vouched); caught on re-seed by MUST-FAIL GAP (P2): x | 2026-10-15 (pre-B4, not vouched) |"), tbl);
  // a run with its head is vouched for
  const now = R.table([d[0]], { P1: { runs: [{ ...old, head: "a".repeat(40), porcelain: "", defect_sha256: "b".repeat(64) }] } });
  assert.doesNotMatch(now, /not vouched/);
});

test("R-WIDEf F2-d: the suite's environment drops every name ending _KEY as well (STRIPE_SECRET_KEY, *_API_KEY)", () => {
  const env = R.scrubbedEnv({ STRIPE_SECRET_KEY: "sk", OPENAI_API_KEY: "k", WITNESS_ADMIN_KEY: "a", SOME_KEY: "x", PATH: "/bin", KEYBOARD: "us" });
  assert.deepEqual(Object.keys(env).sort(), ["KEYBOARD", "NODE_OPTIONS", "PATH"]);
});

// A probe's environment: this process's, with no NODE_OPTIONS preload.
function probeEnv() {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  return env;
}
test("R-WIDEf F2-d: the no-network preload refuses http.request, https.request, net.connect and tls.connect to any host but this machine's, and lets this machine through", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "must-fail-shim-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const probe = path.join(dir, "probe.js");
  fs.writeFileSync(probe, `"use strict";
const http = require("node:http"); const https = require("node:https"); const net = require("node:net"); const tls = require("node:tls");
const refused = (fn) => { try { fn(); return "allowed"; } catch (e) { return /must-fail run: no network/.test(e.message) ? "refused" : "other: " + e.message; } };
const out = {
  https_request: refused(() => https.request("https://api.github.com/").on("error", () => {})),
  https_get: refused(() => https.get({ host: "api.github.com", path: "/" }).on("error", () => {})),
  http_request: refused(() => http.request({ hostname: "example.com", path: "/" }).on("error", () => {})),
  net_connect: refused(() => net.connect(443, "93.184.216.34").on("error", () => {})),
  net_create: refused(() => net.createConnection({ host: "api.github.com", port: 443 }).on("error", () => {})),
  tls_connect: refused(() => tls.connect({ host: "api.github.com", port: 443 }).on("error", () => {})),
};
const server = http.createServer((q, r) => r.end("here"));
server.listen(0, "127.0.0.1", () => {
  const port = server.address().port;
  http.get({ host: "127.0.0.1", port, path: "/" }, (r) => {
    let b = ""; r.on("data", (d) => { b += d; });
    r.on("end", () => {
      out.loopback_http = b;
      const s = net.connect(port, "localhost", () => { out.loopback_net = "connected"; s.destroy(); server.close(); console.log(JSON.stringify(out)); });
    });
  }).on("error", (e) => { out.loopback_http = "error: " + e.message; server.close(); console.log(JSON.stringify(out)); });
});
`);
  // the probe loads this tree's shim and no other: under the runner the
  // suite's NODE_OPTIONS preloads the runner's own, which would answer for a
  // planted one (found by this unit's pass: WF21 to WF31 survived)
  const r = spawnSync(process.execPath, ["--require", path.join(__dirname, "must_fail", "no_network.js"), probe], { encoding: "utf8", timeout: 20000, env: probeEnv() });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), {
    https_request: "refused", https_get: "refused", http_request: "refused", net_connect: "refused", net_create: "refused", tls_connect: "refused",
    loopback_http: "here", loopback_net: "connected",
  });
});

// R-WIDEf's must-fail gap tests (the runner): each fails with its planted defect
test("MUST-FAIL GAP (WF11): runSuite runs the suite in the environment it is handed", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "must-fail-env-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, "test"));
  fs.writeFileSync(path.join(dir, "test", "x.test.js"), "\"use strict\";\nconst { test } = require(\"node:test\");\nconst assert = require(\"node:assert/strict\");\n" +
    "test(\"the handed environment\", () => assert.equal(process.env.MUST_FAIL_HANDED, \"yes\"));\n");
  const out = await R.runSuite(dir, "test/x.test.js", { env: { ...R.scrubbedEnv(), MUST_FAIL_HANDED: "yes" } });
  assert.deepEqual([out.code, out.failing], [0, []], out.stderr);
});

test("MUST-FAIL GAP (WF30, WF31): the no-network preload lets a Unix socket or a named pipe through (a path is this machine's)", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "must-fail-socket-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const sock = process.platform === "win32" ? `\\\\.\\pipe\\must-fail-${process.pid}-${Date.now()}` : path.join(dir, "s.sock");
  const probe = path.join(dir, "probe.js");
  fs.writeFileSync(probe, `"use strict";
const http = require("node:http"); const net = require("node:net");
const sock = ${JSON.stringify(sock)};
const out = {};
const server = http.createServer((q, r) => r.end("here"));
server.listen(sock, () => {
  http.get({ socketPath: sock, path: "/" }, (r) => {
    let b = ""; r.on("data", (d) => { b += d; });
    r.on("end", () => {
      out.request = b;
      const s = net.connect({ path: sock }, () => { out.connect = "connected"; s.destroy(); server.close(); console.log(JSON.stringify(out)); });
      s.on("error", (e) => { out.connect = "error: " + e.message; server.close(); console.log(JSON.stringify(out)); });
    });
  }).on("error", (e) => { out.request = "error: " + e.message; server.close(); console.log(JSON.stringify(out)); });
});
`);
  let r;
  try {
    r = spawnSync(process.execPath, ["--require", path.join(__dirname, "must_fail", "no_network.js"), probe], { encoding: "utf8", timeout: 20000, env: probeEnv() });
  } catch (e) {
    assert.fail(String(e));
  }
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), { request: "here", connect: "connected" });
});

test("MUST-FAIL GAP (WF21, WF26, WF27): a request whose connection the caller makes itself (createConnection, no net or tls socket) is refused by the request's own guard, read from its hostname or host option", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "must-fail-own-conn-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const probe = path.join(dir, "probe.js");
  fs.writeFileSync(probe, `"use strict";
const http = require("node:http"); const https = require("node:https"); const { PassThrough } = require("node:stream");
const own = () => new PassThrough();
const tried = (fn) => { try { const q = fn(); q.on("error", () => {}); q.destroy(); return "allowed"; } catch (e) { return /must-fail run: no network/.test(e.message) ? "refused" : "other: " + e.message; } };
console.log(JSON.stringify({
  http_hostname: tried(() => http.request({ hostname: "example.com", path: "/", createConnection: own })),
  https_host: tried(() => https.request({ host: "api.github.com", path: "/", createConnection: own })),
  http_loopback: tried(() => http.request({ hostname: "127.0.0.1", path: "/", createConnection: own })),
}));
`);
  const r = spawnSync(process.execPath, ["--require", path.join(__dirname, "must_fail", "no_network.js"), probe], { encoding: "utf8", timeout: 20000, env: probeEnv() });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), { http_hostname: "refused", https_host: "refused", http_loopback: "allowed" });
});
