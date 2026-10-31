// test/monitor.test.js — tools/monitor.js (owner job 11): a monitor that
// follows the public checkpoints over time and reports any split or rollback.
// Every source here is a fixture in memory; nothing reaches a network.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const lt = require("../lib/_logtree.js");
const cp = require("../lib/_checkpoint.js");
const monitor = require("../tools/monitor.js");

const KEY = cp.generateKey("arcaeon.io/witness-pins/log");
const leaves = (n, salt = "") => Array.from({ length: n }, (_, i) => crypto.createHash("sha256").update(`leaf ${salt}${i}`).digest());
const LOG = leaves(40);
const SRC = "https://pins.test.invalid";
const SRC2 = "https://mirror.test.invalid";

function checkpointText(hashes, size, key = KEY) {
  const tree = lt.buildTree(hashes.slice(0, size));
  const text = cp.formatCheckpoint({ size, root: tree.root });
  return key ? cp.signCheckpoint(text, key.signer) : text;
}
function proofText(hashes, m, n) {
  const tree = lt.buildTree(hashes.slice(0, n));
  return JSON.stringify(lt.consistencyProofDocument({
    old_size: m, old_root: tree.rootAt(m), new_size: n, new_root: tree.root, path: tree.consistencyProof(m, n) }));
}

// A source: {"<base>/checkpoints/<day>.txt": text, ...}; a missing path is a 404.
function fetcher(files, { down = new Set() } = {}) {
  const calls = [];
  const f = async (url) => {
    calls.push(url);
    for (const d of down) if (url.startsWith(d)) throw new Error("down");
    if (!(url in files)) return { status: 404, ok: false, text: async () => "" };
    return { status: 200, ok: true, text: async () => files[url] };
  };
  f.calls = calls;
  return f;
}
function publish(files, day, size, { hashes = LOG, prev = null, base = SRC, key = KEY } = {}) {
  files[`${base}/checkpoints/${day}.txt`] = checkpointText(hashes, size, key);
  if (prev !== null) files[`${base}/proofs/${day}-consistency.json`] = proofText(hashes, prev, size);
}
const opts = (extra) => ({ sources: [SRC], key: KEY.verifier, ...extra });

test("FIRST RUN, THEN LATER RUNS: every new checkpoint is checked against the last one kept", async () => {
  const files = {};
  publish(files, "2026-10-01", 3);
  publish(files, "2026-10-03", 8, { prev: 3 });
  const r1 = await monitor.run(opts({ state: null, since: "2026-10-01", today: "2026-10-03", fetchImpl: fetcher(files) }));
  assert.equal(r1.verdict, "VERIFIED", JSON.stringify(r1));
  assert.deepEqual(r1.state.seen.map((s) => s.size), [3, 8]);
  publish(files, "2026-10-05", 20, { prev: 8 });
  const r2 = await monitor.run(opts({ state: r1.state, today: "2026-10-06", fetchImpl: fetcher(files) }));
  assert.equal(r2.verdict, "VERIFIED", JSON.stringify(r2));
  assert.equal(r2.state.last.day, "2026-10-05");
  assert.deepEqual(r2.state.seen.map((s) => s.size), [3, 8, 20]);
  // Nothing new: still VERIFIED, nothing changes.
  const r3 = await monitor.run(opts({ state: r2.state, today: "2026-10-07", fetchImpl: fetcher(files) }));
  assert.equal(r3.verdict, "VERIFIED");
  assert.deepEqual(r3.state, r2.state);
});

async function kept(files) {
  publish(files, "2026-10-01", 5);
  publish(files, "2026-10-02", 10, { prev: 5 });
  const r = await monitor.run(opts({ state: null, since: "2026-10-01", today: "2026-10-02", fetchImpl: fetcher(files) }));
  assert.equal(r.verdict, "VERIFIED");
  return r.state;
}

test("ROLLBACK: a smaller checkpoint after a larger one is BROKEN, and the state does not move", async () => {
  const files = {};
  const state = await kept(files);
  publish(files, "2026-10-03", 7);
  files[`${SRC}/proofs/2026-10-03-consistency.json`] = proofText(LOG, 7, 10);
  const r = await monitor.run(opts({ state, today: "2026-10-03", fetchImpl: fetcher(files) }));
  assert.equal(r.verdict, "BROKEN");
  assert.equal(r.reason, "rollback");
  assert.equal(r.code, 1);
  assert.deepEqual(r.state, state);
});

test("SPLIT: the same size with another root is BROKEN", async () => {
  const files = {};
  const state = await kept(files);
  publish(files, "2026-10-03", 10, { hashes: leaves(40, "other ") });
  const r = await monitor.run(opts({ state, today: "2026-10-03", fetchImpl: fetcher(files) }));
  assert.equal(r.reason, "split");
  assert.equal(r.code, 1);
});

test("SPLIT: a fork that grows from another history fails its proof and is BROKEN", async () => {
  const files = {};
  const state = await kept(files);
  const forked = LOG.slice(0, 9).concat(leaves(30, "fork "));
  publish(files, "2026-10-03", 15, { hashes: forked });
  // The proof is honest for the forked log, from a size 10 checkpoint the monitor never saw.
  files[`${SRC}/proofs/2026-10-03-consistency.json`] = (() => {
    const t = lt.buildTree(forked.slice(0, 15));
    const doc = lt.consistencyProofDocument({ old_size: 10, old_root: lt.buildTree(LOG.slice(0, 10)).root, new_size: 15,
      new_root: t.root, path: t.consistencyProof(10, 15) });
    return JSON.stringify(doc);
  })();
  const r = await monitor.run(opts({ state, today: "2026-10-03", fetchImpl: fetcher(files) }));
  assert.equal(r.verdict, "BROKEN", JSON.stringify(r));
  assert.deepEqual(r.state, state);
});

test("SPLIT BETWEEN SOURCES: two mirrors serving different checkpoints for one day is BROKEN", async () => {
  const files = {};
  publish(files, "2026-10-01", 5);
  publish(files, "2026-10-01", 5, { base: SRC2, hashes: leaves(40, "mirror ") });
  const r = await monitor.run({ state: null, sources: [SRC, SRC2], key: KEY.verifier, since: "2026-10-01",
    today: "2026-10-01", fetchImpl: fetcher(files) });
  assert.equal(r.reason, "split");
  assert.match(r.detail, /mirror\.test\.invalid/);
});

test("CHANGED: a checkpoint already kept that now reads differently is BROKEN", async () => {
  const files = {};
  const state = await kept(files);
  publish(files, "2026-10-02", 10, { hashes: leaves(40, "rewritten ") });
  const r = await monitor.run(opts({ state, today: "2026-10-03", fetchImpl: fetcher(files) }));
  assert.equal(r.reason, "changed");
  assert.equal(r.code, 1);
});

test("NOT CHANGED: a signature line added to a kept checkpoint later is not a change", async () => {
  const files = {};
  const state = await kept(files);
  const other = cp.generateKey("arcaeon.io/witness-pins/receipts");
  files[`${SRC}/checkpoints/2026-10-02.txt`] = cp.signCheckpoint(files[`${SRC}/checkpoints/2026-10-02.txt`], other.signer);
  const r = await monitor.run(opts({ state, today: "2026-10-03", fetchImpl: fetcher(files) }));
  assert.equal(r.verdict, "VERIFIED", JSON.stringify(r));
});

test("A BAD PROOF: a changed proof hash is BROKEN", async () => {
  const files = {};
  const state = await kept(files);
  publish(files, "2026-10-03", 20, { prev: 10 });
  const doc = JSON.parse(files[`${SRC}/proofs/2026-10-03-consistency.json`]);
  doc.path[0] = "00".repeat(32);
  files[`${SRC}/proofs/2026-10-03-consistency.json`] = JSON.stringify(doc);
  const r = await monitor.run(opts({ state, today: "2026-10-03", fetchImpl: fetcher(files) }));
  assert.equal(r.verdict, "BROKEN", JSON.stringify(r));
});

test("COULD NOT LOOK: no proof, a proof from an unseen checkpoint, a source down; the state never moves", async () => {
  const files = {};
  const state = await kept(files);
  publish(files, "2026-10-03", 20);
  let r = await monitor.run(opts({ state, today: "2026-10-03", fetchImpl: fetcher(files) }));
  assert.equal(r.reason, "no_proof");
  files[`${SRC}/proofs/2026-10-03-consistency.json`] = proofText(LOG, 12, 20);
  r = await monitor.run(opts({ state, today: "2026-10-03", fetchImpl: fetcher(files) }));
  assert.equal(r.reason, "proof_from_unseen_checkpoint");
  r = await monitor.run(opts({ state, today: "2026-10-03", fetchImpl: fetcher(files, { down: new Set([SRC]) }) }));
  assert.equal(r.reason, "source_unreadable");
  for (const x of [r]) { assert.equal(x.code, 2); assert.deepEqual(x.state, state); }
});

test("SIGNATURES: an unsigned checkpoint with a key given cannot be attributed; a forged one is BROKEN", async () => {
  const files = {};
  publish(files, "2026-10-01", 5, { key: null });
  let r = await monitor.run(opts({ state: null, since: "2026-10-01", today: "2026-10-01", fetchImpl: fetcher(files) }));
  assert.equal(r.verdict, "COULD NOT LOOK");
  const forger = cp.generateKey("arcaeon.io/witness-pins/log");
  publish(files, "2026-10-01", 5, { key: forger });
  // Same name, another key: its line does not carry this key's hash, so it cannot be attributed.
  r = await monitor.run(opts({ state: null, since: "2026-10-01", today: "2026-10-01", fetchImpl: fetcher(files) }));
  assert.notEqual(r.verdict, "VERIFIED");
  r = await monitor.run({ state: null, sources: [SRC], allowUnsigned: true, since: "2026-10-01", today: "2026-10-01",
    fetchImpl: fetcher(files) });
  assert.equal(r.verdict, "VERIFIED");
});

test("CLI: the state file is written on VERIFIED only, and the exit code is the verdict's", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mon-"));
  const stateFile = path.join(dir, "state.json");
  const files = {};
  publish(files, "2026-10-01", 5);
  const out = [];
  const print = (l) => out.push(l);
  let code = await monitor.main(["--state", stateFile, "--key", KEY.verifier, "--source", SRC, "--since", "2026-10-01",
    "--today", "2026-10-01"], { fetchImpl: fetcher(files), print });
  assert.equal(code, 0, out.join("\n"));
  const before = fs.readFileSync(stateFile, "utf8");
  publish(files, "2026-10-02", 3);
  code = await monitor.main(["--state", stateFile, "--key", KEY.verifier, "--source", SRC, "--today", "2026-10-02"],
    { fetchImpl: fetcher(files), print });
  assert.equal(code, 1);
  assert.match(out[out.length - 1], /^BROKEN: rollback/);
  assert.equal(fs.readFileSync(stateFile, "utf8"), before, "a BROKEN run leaves the state file as it was");
  assert.equal(await monitor.main(["--state", stateFile], { fetchImpl: fetcher(files), print }), 2);
});

test("CLI: a first run that is not VERIFIED writes no state file at all", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mon-"));
  const stateFile = path.join(dir, "state.json");
  const files = {};
  publish(files, "2026-10-01", 5, { key: null });
  const code = await monitor.main(["--state", stateFile, "--key", KEY.verifier, "--source", SRC, "--since", "2026-10-01",
    "--today", "2026-10-01"], { fetchImpl: fetcher(files), print: () => {} });
  assert.equal(code, 2);
  assert.equal(fs.existsSync(stateFile), false);
});

test("SPLIT: a checkpoint naming another log is BROKEN, not a pass", async () => {
  const files = {};
  const state = await kept(files);
  const tree = lt.buildTree(LOG.slice(0, 12));
  files[`${SRC}/checkpoints/2026-10-03.txt`] = cp.signCheckpoint(
    cp.formatCheckpoint({ origin: "arcaeon.io/witness-pins/other-log", size: 12, root: tree.root }), KEY.signer);
  const r = await monitor.run(opts({ state, today: "2026-10-03", fetchImpl: fetcher(files) }));
  assert.equal(r.verdict, "BROKEN", JSON.stringify(r));
  assert.equal(r.reason, "split");
});
