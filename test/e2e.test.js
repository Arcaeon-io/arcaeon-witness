// test/e2e.test.js — the whole path in one process, with fakes (owner job 15):
//
//   pin -> signed receipt -> fold (the Merkle batch the sealer publishes)
//       -> checkpoint (the log over every record) -> monitor
//
// One fake GitHub store holds the public pin repo and the private usage repo.
// The checkpoint is built the way tools/publish_checkpoint.js builds it: every
// eligible record, in the order its path was first written, each leaf an
// envelope of its committed bytes; here the "commit" that introduced a path is
// a fixed id per write, since there is no git. The monitor reads the published
// checkpoints and proofs from an in memory source. Nothing reaches a network.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_KEYS = "keyA:demo-a,keyB:demo-b";
delete process.env.WITNESS_PLANS;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const receipts = require("../lib/_receipt.js");
const merkle = require("../lib/_merkle.js");
const lt = require("../lib/_logtree.js");
const cp = require("../lib/_checkpoint.js");
const sealer = require("../lib/_sealer.js");
const pending = require("../lib/_pending.js");
const monitor = require("../tools/monitor.js");
const follow = require("../tools/follow.js");

const PIN_REPO = process.env.GITHUB_PIN_REPO;
const SOURCE = "https://public.test.invalid";
const LOG_KEY = cp.generateKey("arcaeon.io/witness-pins/log");
const ENV = ["WITNESS_RECEIPTS", "WITNESS_RECEIPT_KEY", "WITNESS_RECEIPT_STARTED_AT", "WITNESS_BATCH_SHADOW"];

let gh, restore, saved;
const realPutSleep = store._putRetry.sleep;
beforeEach(() => {
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  process.env.WITNESS_RECEIPTS = "on";
  process.env.WITNESS_RECEIPT_KEY = crypto.randomBytes(32).toString("hex"); // a throwaway key per run
  process.env.WITNESS_RECEIPT_STARTED_AT = "2026-10-31T00:00:00Z";
  process.env.WITNESS_BATCH_SHADOW = "on";
  gh = new MockGitHubStore();
  restore = install(gh);
  store._putRetry.sleep = async () => {};
});
afterEach(() => {
  store._putRetry.sleep = realPutSleep;
  restore();
  for (const k of ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
});

const head = (s) => crypto.createHash("sha256").update(s).digest("hex");
async function pin(key, namespace, rows, chain) {
  const res = makeRes();
  await require("../api/pin.js")(makeReq({ method: "POST", headers: { authorization: `Bearer ${key}` }, body: { namespace, rows, chain } }), res);
  assert.equal(res._status, 201, JSON.stringify(res._body));
  return res._body;
}
async function keyDoc() {
  const res = makeRes();
  await require("../api/verify.js")(makeReq({ method: "GET", query: { op: "witness-key" } }), res);
  assert.equal(res._status, 200);
  return res._body;
}

// The log's leaves, as tools/publish_checkpoint.js makes them: eligible paths
// in the order they were first written, each with its committed bytes.
function logLeaves() {
  const seen = new Set();
  const leaves = [];
  gh.putLog.forEach((p, i) => {
    if (p.repo !== PIN_REPO || seen.has(p.path) || !lt.kindOfPath(p.path)) return;
    seen.add(p.path);
    const bytes = Buffer.from(gh.repos.get(PIN_REPO).get(p.path).content, "utf-8");
    const commit = crypto.createHash("sha1").update(`fake commit ${i}`).digest("hex");
    leaves.push({ path: p.path, hash: lt.logLeafHash(lt.makeEnvelope({ path: p.path, fileBytes: bytes, introducedByCommit: commit })) });
  });
  return leaves;
}

// Publish a checkpoint over the leaves (and the proof from the last one),
// signed by the log key and by the receipt key.
function publishCheckpoint(files, day, hashes, prevSize = null) {
  const tree = lt.buildTree(hashes);
  let text = cp.formatCheckpoint({ size: tree.size, root: tree.root });
  text = cp.signCheckpoint(text, LOG_KEY.signer);
  text = cp.signCheckpoint(text, receipts.checkpointKeys().signer);
  files[`${SOURCE}/checkpoints/${day}.txt`] = text;
  if (prevSize !== null) {
    files[`${SOURCE}/proofs/${day}-consistency.json`] = JSON.stringify(lt.consistencyProofDocument({
      old_size: prevSize, old_root: tree.rootAt(prevSize), new_size: tree.size, new_root: tree.root,
      path: tree.consistencyProof(prevSize) }));
  }
  return tree;
}
function source(files) {
  return async (url) => (url in files
    ? { status: 200, ok: true, text: async () => files[url] }
    : { status: 404, ok: false, text: async () => "" });
}

test("END TO END: pins get receipts, a fold seals them, checkpoints cover them, and the monitor follows", async () => {
  // --- pin, and the signed receipt ---
  const doc = await keyDoc();
  const pub = Buffer.from(doc.public_key, "hex");
  const answers = [
    await pin("keyA", "demo-a", 3, head("a3")),
    await pin("keyB", "demo-b", 7, head("b7")),
    await pin("keyA", "demo-a", 5, head("a5")),
  ];
  for (const a of answers) {
    assert.deepEqual(receipts.verify(a.receipt, pub), { ok: true });
    assert.equal(a.receipt.key_id, doc.key_id);
    assert.equal(a.receipt.witness_seq, a.pin.seq);
  }
  assert.equal(doc.witness_statement.key_id, doc.key_id, "the statement names the same key");

  // --- the fold: the shadow run's pending batch, sealed into one root ---
  const open = gh.read(process.env.GITHUB_USAGE_REPO, pending.PENDING_PATH);
  assert.equal(open.open.leaves.length, 3);
  const sealed = await sealer.sealOnce({ now: new Date(Date.parse(open.open.opened_at) + 61_000) });
  assert.equal(sealed.sealed, true, JSON.stringify(sealed));
  assert.equal(sealed.tree_size, 3);
  for (const proof of sealed.proofs) {
    assert.equal(merkle.verifyInclusion(proof).ok, true, "every pin's leaf is under the published root");
  }

  // --- checkpoint 1: the log over every record so far ---
  const files = {};
  const leaves1 = logLeaves();
  assert.equal(leaves1.length, 3, "three pin records");
  const tree1 = publishCheckpoint(files, "2026-10-31", leaves1.map((l) => l.hash));
  // A pin's own record is in the checkpoint: its inclusion proof holds.
  const i = leaves1.findIndex((l) => l.path === "pins/demo-b/00000001.json");
  assert.equal(lt.verifyInclusion({ leaf_index: i, tree_size: tree1.size, leaf_hash: leaves1[i].hash,
    path: tree1.inclusionProof(i), root: tree1.root }).ok, true);
  // The receipt key's line on the checkpoint checks with the key document's verifier key.
  assert.equal(cp.verifyCheckpointSignature(files[`${SOURCE}/checkpoints/2026-10-31.txt`], doc.checkpoint_verifier_key).ok, true);

  // --- monitor, first run ---
  const m1 = await monitor.run({ state: null, sources: [SOURCE], key: LOG_KEY.verifier, since: "2026-10-31",
    today: "2026-10-31", fetchImpl: source(files) });
  assert.equal(m1.verdict, "VERIFIED", JSON.stringify(m1));

  // --- more pins, checkpoint 2 with its consistency proof, monitor again ---
  await pin("keyB", "demo-b", 9, head("b9"));
  await pin("keyA", "demo-a", 8, head("a8"));
  const leaves2 = logLeaves();
  assert.deepEqual(leaves2.slice(0, 3).map((l) => l.hash), leaves1.map((l) => l.hash), "the log only grows");
  publishCheckpoint(files, "2026-11-01", leaves2.map((l) => l.hash), tree1.size);
  const m2 = await monitor.run({ state: m1.state, sources: [SOURCE], key: LOG_KEY.verifier, today: "2026-11-01",
    fetchImpl: source(files) });
  assert.equal(m2.verdict, "VERIFIED", JSON.stringify(m2));
  assert.deepEqual(m2.state.seen.map((s) => s.size), [3, 5]);

  // --- an insider rewrites an early record; the next checkpoint cannot extend the last ---
  const victim = "pins/demo-a/00000001.json";
  const rec = gh.read(PIN_REPO, victim);
  gh.seed(PIN_REPO, victim, { ...rec, chain: head("forged") });
  await pin("keyB", "demo-b", 11, head("b11"));
  // The store now holds the forged bytes, so the log built from it is the rewritten one.
  const rewritten = logLeaves().map((l) => l.hash);
  assert.notEqual(rewritten[0].toString("hex"), leaves2[0].hash.toString("hex"));
  const tree3 = lt.buildTree(rewritten);
  const text3 = cp.signCheckpoint(cp.formatCheckpoint({ size: tree3.size, root: tree3.root }), LOG_KEY.signer);
  files[`${SOURCE}/checkpoints/2026-11-02.txt`] = text3;
  // The best the insider can publish: a proof that claims to start at the last
  // checkpoint the monitor kept, with the rewritten log's path.
  files[`${SOURCE}/proofs/2026-11-02-consistency.json`] = JSON.stringify(lt.consistencyProofDocument({
    old_size: 5, old_root: lt.buildTree(leaves2.map((l) => l.hash)).root, new_size: tree3.size, new_root: tree3.root,
    path: tree3.consistencyProof(5) }));
  const m3 = await monitor.run({ state: m2.state, sources: [SOURCE], key: LOG_KEY.verifier, today: "2026-11-02",
    fetchImpl: source(files) });
  assert.equal(m3.verdict, "BROKEN", JSON.stringify(m3));
  assert.deepEqual(m3.state, m2.state, "the monitor keeps the last good checkpoint");

  // And the receipt the witness signed for that record still names the head it saw, not the forged one.
  assert.equal(answers[0].receipt.head.chain, head("a3"));
  assert.notEqual(gh.read(PIN_REPO, victim).chain, answers[0].receipt.head.chain);
});

test("END TO END: the two checkers agree; follow.js on the published pair says what the monitor said", async () => {
  await pin("keyA", "demo-a", 1, head("x1"));
  const files = {};
  const t1 = publishCheckpoint(files, "2026-10-31", logLeaves().map((l) => l.hash));
  await pin("keyA", "demo-a", 2, head("x2"));
  publishCheckpoint(files, "2026-11-01", logLeaves().map((l) => l.hash), t1.size);
  const f = follow.follow({ oldText: files[`${SOURCE}/checkpoints/2026-10-31.txt`], newText: files[`${SOURCE}/checkpoints/2026-11-01.txt`],
    proofText: files[`${SOURCE}/proofs/2026-11-01-consistency.json`], key: LOG_KEY.verifier });
  assert.equal(f.verdict, "VERIFIED", JSON.stringify(f));
  const m = await monitor.run({ state: null, sources: [SOURCE], key: LOG_KEY.verifier, since: "2026-10-31",
    today: "2026-11-01", fetchImpl: source(files) });
  assert.equal(m.verdict, "VERIFIED");
});
