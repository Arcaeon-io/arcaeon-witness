// test/must_fail_runner.test.js — unit R-ABf (2026-10-15): the planted-defect
// runner, test/must_fail/run.js. A defect is CAUGHT only when the suite
// exits non-zero and at least one test failed; a suite killed at its
// timeout is its own result, timeout, and one that exits non-zero with no
// failing test (it did not start, say) is error; neither is ever printed as
// caught (M1). A defect's file is a relative path inside the repository
// (m-d). The ledger records, for a re-seed that catches a defect its first
// run missed, the gap test that failed, and the table prints that record
// (m-e). An interrupted run removes its copies (m-d).
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

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

test("R-ABf M1: the table prints a timeout and an error as such, with no date of a catch", () => {
  const defects = [{ id: "X1", file: "lib/x.js", what: "a defect" }, { id: "X2", file: "lib/x.js", what: "another" }];
  const ledger = {
    X1: { runs: [{ date: "2026-10-15", result: "timeout", exit: null, failing: 0, failing_tests: [] }] },
    X2: { runs: [{ date: "2026-10-15", result: "error", exit: 1, failing: 0, failing_tests: [] }] },
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
  const t = R.table([{ id: "X1", file: "lib/x.js", what: "a defect" }], { X1: { runs: [survived, reseed] } });
  assert.ok(t.includes("| X1 | `lib/x.js` | a defect | survived; caught on re-seed by MUST-FAIL GAP (X1): the gap test | 2026-10-15 |"), t);
  assert.equal(R.table.length, 2, "the table takes the defects and the ledger, and no operator's words");
});

test("R-ABf m-e: the table reads a ledger written before unit R-ABf (caught, first_failing) the same way", () => {
  const ledger = { K07: { runs: [{ date: "2026-10-14", caught: false, failing: 0, first_failing: [] },
    { date: "2026-10-14", caught: true, failing: 2, first_failing: ["MUST-FAIL GAP (K07): singleParty", "R-N2 B2: the body audit"] }] } };
  const t = R.table([{ id: "K07", file: "lib/_case.js", what: "a guard" }], ledger);
  assert.ok(t.includes("| K07 | `lib/_case.js` | a guard | survived; caught on re-seed by MUST-FAIL GAP (K07): singleParty | 2026-10-14 |"), t);
});

test("R-ABf m-d: an interrupted run (SIGINT) removes its copies of the tree", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "must-fail-sigint-"));
  const defects = path.join(tmp, "one.json");
  const readme = fs.readFileSync(path.join(__dirname, "..", "README.md"), "utf8");
  const line = readme.split("\n").find((l) => l.length > 20 && readme.split(l).length === 2);
  fs.writeFileSync(defects, JSON.stringify([{ id: "S1", file: "README.md", find: line, replace: `${line} (planted)`, what: "a planted line" }]));
  const work = path.join(tmp, "work");
  fs.mkdirSync(work);
  // the suite it runs is a fixture that waits a minute (the run is
  // interrupted while it runs), not the suite this test is part of
  const env = { ...process.env, TMPDIR: work };
  delete env.NODE_TEST_CONTEXT;
  const child = spawn(process.execPath, [RUN, defects, "--workers", "1", "--suite", "test/must_fail/slow_suite.fixture.js"], { env, stdio: "ignore" });
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
    assert.equal(fs.existsSync(path.join(tmp, "one.ledger.json")), false, "no run recorded");
  } finally {
    child.kill("SIGKILL");
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
