// test/proof_large_trees.test.js — the proof checkers must be right for every
// tree size their own parsers accept, not only below 2^31.
//
// Found reading another log verifier (notes kept outside this repo):
// it walks inclusion proofs in
// arbitrary precision. Ours walked them with JavaScript's bitwise operators (`>>=`, `&`),
// which cut every value to a 32-bit signed integer. parseCheckpoint accepts a
// size of up to 15 digits, so above 2^31 - 1 leaves the walk silently went
// wrong: valid proofs were refused, and in lib/_merkle.js a forged proof could
// pass the walk.
//
// No big tree is built here. A proof is only hashes, so the proofs below are
// written by hand from RFC 9162 section 2.1 for trees whose size is just past
// a power of two: the old tree (or the left subtree) is one opaque hash X, and
// the new leaf is one hash L.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const lt = require("../lib/_logtree.js");
const merkle = require("../lib/_merkle.js");
const follow = require("../tools/follow.js");

const X = crypto.createHash("sha256").update("left subtree of 2^k leaves").digest();
const L = crypto.createHash("sha256").update("the one leaf after it").digest();
const node = (a, b) => lt.nodeHash(a, b);

// Sizes: just past 2^31 (the int32 edge), past 2^32, and near 2^52.
const POWERS = [31, 32, 40, 52];

for (const p of POWERS) {
  const m = 2 ** p;

  test(`CONSISTENCY (lib/_logtree.js): a valid proof from ${m} to ${m + 1} leaves is consistent`, () => {
    // first = 2^p is a power of two, so the RFC proof is [MTH(D[m:m+1])] = [L].
    const r = lt.verifyConsistency({ old_size: m, new_size: m + 1, old_root: X, new_root: node(X, L), path: [L] });
    assert.deepEqual(r.ok && r.reason, "consistent", JSON.stringify(r));
  });

  test(`CONSISTENCY (lib/_logtree.js): a wrong new root at ${m + 1} leaves is still refused`, () => {
    const r = lt.verifyConsistency({ old_size: m, new_size: m + 1, old_root: X, new_root: node(L, X), path: [L] });
    assert.equal(r.ok, false);
  });

  test(`CONSISTENCY (tools/follow.js): the stranger's checker agrees at ${m} -> ${m + 1}`, () => {
    const r = follow.verifyConsistency(m, m + 1, X, node(X, L), [L.toString("hex")]);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(follow.verifyConsistency(m, m + 1, X, node(L, X), [L.toString("hex")]).ok, false);
  });

  test(`INCLUSION (lib/_logtree.js): leaf ${m} of ${m + 1} with the path [X] is included`, () => {
    const r = lt.verifyInclusion({ leaf_index: m, tree_size: m + 1, leaf_hash: L, path: [X], root: node(X, L) });
    assert.equal(r.ok, true, JSON.stringify(r));
  });

  test(`INCLUSION (lib/_logtree.js): leaf 0 of ${m + 1} with a one-hash path is refused (it needs ${p + 1})`, () => {
    // A 1-hop proof for leaf 0 of a 2^p+1 tree is too short; with 32-bit
    // arithmetic sn collapsed to 0 and the short path was walked as complete.
    const r = lt.verifyInclusion({ leaf_index: 0, tree_size: m + 1, leaf_hash: L, path: [X], root: node(L, X) });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "path_too_short");
  });
}

// lib/_merkle.js (the batch trees) promotes an odd last node; its walk had the
// same 32-bit operators on a tree_size the proof itself claims.
const LEAF = { namespace: "demo-big", rows: 1, chain: "ab".repeat(16), seq: 1 };
const lab = (buf) => merkle.labelled(merkle.MERKLE_RECIPE, buf);

for (const p of [31, 32, 52]) {
  const n = 2 ** p + 1;

  test(`BATCH INCLUSION (lib/_merkle.js): the last leaf of ${n} with the path [X] is included`, () => {
    const h = merkle.leafHash(LEAF);
    const r = merkle.verifyInclusion({ tree_size: n, leaf_index: n - 1, leaf: LEAF, path: [lab(X)], root: lab(merkle.nodeHash(X, h)) });
    assert.equal(r.ok, true, JSON.stringify(r));
  });

  test(`BATCH INCLUSION (lib/_merkle.js): a forged empty path claiming the leaf is the root of ${n} leaves is refused`, () => {
    // With `size = (size + 1) >> 1` the size went negative after one step, the
    // walk stopped, and an empty path "proved" the leaf hash was the root of a
    // tree of 2^p + 1 leaves.
    const h = merkle.leafHash(LEAF);
    const r = merkle.verifyInclusion({ tree_size: n, leaf_index: n - 1, leaf: LEAF, path: [], root: lab(h) });
    assert.equal(r.ok, false, JSON.stringify(r));
    assert.equal(r.reason, "path_too_short");
  });
}

test("SIZES past 2^53 - 1 cannot be computed exactly and are refused as malformed, not walked", () => {
  const big = 2 ** 53 + 2; // an integer to Number.isInteger, but not a safe one
  assert.equal(lt.verifyConsistency({ old_size: 2 ** 53, new_size: big, old_root: X, new_root: X, path: [L] }).reason, "malformed_proof");
  assert.equal(lt.verifyInclusion({ leaf_index: 0, tree_size: big, leaf_hash: L, path: [X], root: X }).reason, "malformed_proof");
  assert.equal(follow.verifyConsistency(2 ** 53, big, X, X, [L.toString("hex")]).reason, "malformed_proof");
  const r = merkle.verifyInclusion({ tree_size: big, leaf_index: 0, leaf: LEAF, path: [lab(X)], root: lab(X) });
  assert.equal(r.reason, "malformed_proof");
});
