// test/proof_no_hang.test.js — a proof checker must ANSWER, whatever sizes it
// is handed. With 32-bit bitwise arithmetic, an old size of 2^32 made
// `fn = first - 1` read as -1, and `while (lsb(fn)) fn >>= 1` never ended
// (-1 >> 1 is -1): tools/follow.js, the stranger's checker, spun forever on
// a crafted checkpoint pair instead of saying BROKEN. Each checker runs here
// in a child process with a time limit, so a hang fails this test instead of
// hanging the suite. See test/proof_large_trees.test.js for the arithmetic.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");

function answersWithin(ms, script) {
  const r = spawnSync(process.execPath, ["-e", script], { cwd: ROOT, encoding: "utf8", timeout: ms });
  return { timedOut: Boolean(r.error && r.error.code === "ETIMEDOUT"), status: r.status, stdout: r.stdout, stderr: r.stderr };
}

const X = "11".repeat(32);
const L = "22".repeat(32);

for (const [what, call] of [
  ["tools/follow.js verifyConsistency", `require("./tools/follow.js").verifyConsistency(2**32, 2**32 + 1, Buffer.from("${X}","hex"), Buffer.from("${X}","hex"), ["${L}"])`],
  ["lib/_logtree.js verifyConsistency", `require("./lib/_logtree.js").verifyConsistency({ old_size: 2**32, new_size: 2**32 + 1, old_root: "${X}", new_root: "${X}", path: ["${L}"] })`],
  ["lib/_logtree.js verifyInclusion", `require("./lib/_logtree.js").verifyInclusion({ leaf_index: 2**32 - 1, tree_size: 2**33, leaf_hash: "${L}", path: ["${X}"], root: "${X}" })`],
]) {
  test(`NO HANG: ${what} answers within 5 seconds for sizes past 2^32`, () => {
    const r = answersWithin(5000, `process.stdout.write(JSON.stringify(${call}))`);
    assert.equal(r.timedOut, false, `${what} did not answer within 5 seconds`);
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout);
    assert.equal(typeof out.ok, "boolean");
  });
}
