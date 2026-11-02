#!/usr/bin/env node
// tools/verify_store_proof.js — a store checks its own batch proof, offline.
//
//   node tools/verify_store_proof.js --proof my_proof.json [--store-id ID] [--head HEX] [--entry entry.json]
//
// --proof   one element of the `proofs` array POST /api/pin-batch answered
//           with ({store_id, proof, entry_path}), saved by the store.
// --entry   the public entry file at entry_path, if the store has fetched or
//           kept it. With it, the root and the leaf count are checked against
//           what was published; without it, only inclusion under the root.
// --store-id, --head  what the store itself knows; checked against the leaf.
//
// No network, no key, nothing of ours: lib/_store_batch.js verifyStoreProof
// over lib/_merkle.js, which reach for no store. Exit 0 included, 1 not, 2 usage.

"use strict";

const fs = require("fs");
const { verifyStoreProof } = require("../lib/_store_batch.js");

function arg(name) {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : undefined;
}

function readJson(path, what) {
  try {
    return JSON.parse(fs.readFileSync(path, "utf-8"));
  } catch (e) {
    process.stderr.write(`cannot read ${what} ${path}: ${e.message}\n`);
    process.exit(2);
  }
}

const proofPath = arg("--proof");
if (!proofPath) {
  process.stderr.write("usage: verify_store_proof.js --proof FILE [--store-id ID] [--head HEX] [--entry FILE]\n");
  process.exit(2);
}
const bundle = readJson(proofPath, "proof");
const entryPath = arg("--entry");
const entry = entryPath ? readJson(entryPath, "entry") : null;
const expect = {};
if (arg("--store-id") !== undefined) expect.store_id = arg("--store-id");
if (arg("--head") !== undefined) expect.head = arg("--head");

const r = verifyStoreProof(bundle, expect, entry);
process.stdout.write(JSON.stringify(r, null, 2) + "\n");
if (r.ok && !entry) {
  process.stdout.write("included under the root in this proof; pass --entry to check the root against the public entry\n");
}
process.exit(r.ok ? 0 : 1);
