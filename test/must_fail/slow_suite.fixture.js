// test/must_fail/slow_suite.fixture.js — a suite that runs for a minute and
// fails nothing: test/must_fail_runner.test.js hands it to the runner
// (--suite) to interrupt a run while its suite is running. Its test process
// writes its pid to MUST_FAIL_FIXTURE_PID_FILE when that is set, so the
// test can see it killed. Not one of the suite's own files
// (test/*.test.js).
"use strict";

const fs = require("node:fs");
const { test } = require("node:test");

test("a test that waits a minute", async () => {
  if (process.env.MUST_FAIL_FIXTURE_PID_FILE) fs.writeFileSync(process.env.MUST_FAIL_FIXTURE_PID_FILE, String(process.pid));
  await new Promise((r) => setTimeout(r, 60000));
});
