// test/loadtest.test.js — tools/loadtest.js (owner job 19): the numbers it
// reports hold together. Small runs, so the suite stays quick; the 100
// pinner figures are in LOAD_TEST.md.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const loadtest = require("../tools/loadtest.js");

const ENV = ["GITHUB_PIN_REPO", "GITHUB_PIN_BRANCH", "GITHUB_USAGE_REPO", "GITHUB_PIN_TOKEN", "WITNESS_KEYS", "WITNESS_PLANS", "WITNESS_BATCH_SHADOW"];
async function quiet(fn) {
  const saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  try {
    return await fn();
  } finally {
    for (const k of ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  }
}

test("SHADOW OFF: every pin accepted, exactly 2 public and 1 private write each, no lost race", async () => {
  const r = await quiet(() => loadtest.run({ pinners: 12, pins: 3, delayMs: 2 }));
  assert.deepEqual(r.answers, { 201: 36 });
  assert.deepEqual(r.writes_per_accepted_pin, { public: 2, private: 1, total: 3 });
  assert.equal(r.put_conflicts, 0);
  assert.equal(r.put_attempts, r.writes.total);
  assert.ok(r.latency_ms.p50 <= r.latency_ms.p95 && r.latency_ms.p95 <= r.latency_ms.max);
});

test("SHADOW ON: every pin still accepted; each one's leaf is either in the pending batch or counted as dropped", async () => {
  const r = await quiet(() => loadtest.run({ pinners: 12, pins: 3, delayMs: 2, shadow: true }));
  assert.deepEqual(r.answers, { 201: 36 });
  assert.equal(r.writes_per_accepted_pin.public, 2, "the public record is never short");
  assert.equal(r.pending_leaves + r.leaves_dropped, r.accepted, "no leaf goes unaccounted for");
  assert.equal(r.put_attempts, r.writes.total + r.put_conflicts);
  assert.equal(r.other_errors_logged, 0);
});

test("500 PINNERS, SHADOW OFF: every pin accepted at exactly 3 writes, no lost race (queue item 40)", async () => {
  const r = await quiet(() => loadtest.run({ pinners: 500, pins: 1, delayMs: 1 }));
  assert.deepEqual(r.answers, { 201: 500 });
  assert.deepEqual(r.writes_per_accepted_pin, { public: 2, private: 1, total: 3 });
  assert.equal(r.put_conflicts, 0);
});

test("500 PINNERS, SHADOW ON: every pin accepted and every leaf accounted for, kept or dropped", async () => {
  const r = await quiet(() => loadtest.run({ pinners: 500, pins: 1, delayMs: 1, shadow: true }));
  assert.deepEqual(r.answers, { 201: 500 });
  assert.equal(r.writes_per_accepted_pin.public, 2);
  assert.equal(r.pending_leaves + r.leaves_dropped, r.accepted);
  assert.equal(r.other_errors_logged, 0);
});

test("CLI: bad numbers are refused, a run prints its summary", async () => {
  const out = [];
  assert.equal(await loadtest.main(["--pinners", "0"], (l) => out.push(l)), 2);
  assert.equal(await loadtest.main(["--bogus"], (l) => out.push(l)), 2);
  const code = await quiet(() => loadtest.main(["--pinners", "3", "--pins", "1", "--json"], (l) => out.push(l)));
  assert.equal(code, 0);
  assert.equal(JSON.parse(out[out.length - 1]).accepted, 3);
});
