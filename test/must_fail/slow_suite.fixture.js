// test/must_fail/slow_suite.fixture.js — a suite that runs for a minute and
// fails nothing: test/must_fail_runner.test.js hands it to the runner
// (--suite) to interrupt a run while its suite is running. Not one of the
// suite's own files (test/*.test.js).
"use strict";

const { test } = require("node:test");

test("a test that waits a minute", async () => {
  await new Promise((r) => setTimeout(r, 60000));
});
