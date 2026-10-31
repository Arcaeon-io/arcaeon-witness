#!/usr/bin/env node
// tools/export_namespace.js — everything one person pinned, their namespace,
// as one bundle anyone can check offline (owner job 18). The check is
// tools/verify_namespace_bundle.js.
//
//   node tools/export_namespace.js --clone <pins repo clone> --namespace <ns> \
//        --checkpoint <published checkpoint file> --out <bundle.json> [--branch main]
//
// The bundle holds, for every numbered record of the namespace that the
// checkpoint covers, its committed bytes, the commit that introduced it and an
// inclusion proof into the checkpoint, plus the checkpoint itself:
//
//   {"kind": "arcaeon_namespace_bundle", "v": 1, "namespace", "checkpoint": "<the note, as published>",
//    "tree_size", "records": [{"path", "seq", "bytes_b64", "introduced_by_commit", "leaf_index", "path_hashes"}],
//    "not_yet_in_checkpoint": [paths], "observations": [paths]}
//
// The log is built from the clone exactly as tools/publish_checkpoint.js
// builds it (the same git walk, the same envelopes), and the export is
// REFUSED unless the checkpoint given has the very root the clone gives at its
// size: then every leaf in the bundle is a leaf of the published log, not of
// some other history. Records written after that checkpoint are listed by
// path, not proven; the next checkpoint covers them.
//
// It only reads the clone and writes the one --out file, which must not exist.
// Exit 0 written, 1 usage, 2 refused (and nothing written).

"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const logtree = require("../lib/_logtree.js");
const checkpoint = require("../lib/_checkpoint.js");
const { introducingCommits, blobBytes } = require("./publish_checkpoint.js");

const NS_RE = /^[a-z0-9-]{1,64}$/;

function git(clone, args) {
  const r = spawnSync("git", ["-C", clone, ...args], { encoding: "utf8", maxBuffer: 1 << 28 });
  if (r.status !== 0) throw new Error(`git ${args[0]} failed: ${String(r.stderr).trim()}`);
  return r.stdout;
}

// -> {ok:true, bundle} | {ok:false, reason, detail}
function buildBundle({ clone, namespace, checkpointText, branch = "main" }) {
  const refuse = (reason, detail) => ({ ok: false, reason, detail });
  if (!NS_RE.test(namespace)) return refuse("namespace", "must match [a-z0-9-]{1,64}");
  const cpParsed = checkpoint.parseCheckpoint(checkpointText);
  if (!cpParsed.ok) return refuse("checkpoint", `cannot be read: ${cpParsed.reason}`);
  let commit;
  try {
    commit = git(clone, ["rev-parse", "--verify", `${branch}^{commit}`]).trim();
  } catch (e) {
    return refuse("clone", e.message);
  }
  const { order, dup } = introducingCommits(clone, commit);
  if (dup.length) return refuse("clone", `a path was added more than once: ${dup[0].path}`);
  const ordered = [];
  for (const c of order) for (const p of c.paths) ordered.push({ commit: c.commit, path: p });
  const intro = blobBytes(clone, ordered.map((l) => `${l.commit}:${l.path}`));
  const now = blobBytes(clone, ordered.map((l) => `${commit}:${l.path}`));
  const envelopes = ordered.map((l) => {
    const b = intro.get(`${l.commit}:${l.path}`);
    const n = now.get(`${commit}:${l.path}`);
    if (!b || !n || !b.equals(n)) throw Object.assign(new Error(`${l.path} changed after it was written`), { refuse: true });
    return { ...l, bytes: b, envelope: logtree.makeEnvelope({ path: l.path, fileBytes: b, introducedByCommit: l.commit }) };
  });
  const size = cpParsed.size;
  if (size > envelopes.length) return refuse("checkpoint", `size ${size} is more than the ${envelopes.length} records the clone holds`);
  const tree = logtree.buildTree(envelopes.map((e) => logtree.logLeafHash(e.envelope)));
  if (!tree.rootAt(size).equals(cpParsed.root)) {
    return refuse("checkpoint", "its root is not the root this clone gives at its size; this is not the published log, or not this checkpoint's");
  }
  const mine = new RegExp(`^pins/${namespace}/([0-9]{8})\\.json$`);
  const records = [];
  const later = [];
  envelopes.forEach((e, i) => {
    const m = mine.exec(e.path);
    if (!m) return;
    if (i >= size) { later.push(e.path); return; }
    records.push({ path: e.path, seq: Number(m[1]), bytes_b64: e.bytes.toString("base64"), introduced_by_commit: e.commit,
      leaf_index: i, path_hashes: tree.inclusionProof(i, size).map((h) => h.toString("hex")) });
  });
  if (records.length === 0 && later.length === 0) return refuse("namespace", `the clone holds no record of ${namespace}`);
  const observations = envelopes.filter((e) => e.path.startsWith(`observations/${namespace}/`)).map((e) => e.path);
  return { ok: true, bundle: { kind: "arcaeon_namespace_bundle", v: 1, namespace, checkpoint: checkpointText, tree_size: size,
    records, not_yet_in_checkpoint: later, observations } };
}

function main(argv = process.argv.slice(2), print = console.log) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (["--clone", "--namespace", "--checkpoint", "--out", "--branch"].includes(k)) a[k.slice(2)] = argv[++i];
    else { print(`usage: unknown argument ${k}`); return 1; }
  }
  if (!a.clone || !a.namespace || !a.checkpoint || !a.out) {
    print("usage: --clone <dir> --namespace <ns> --checkpoint <file> --out <file> [--branch main]");
    return 1;
  }
  if (fs.existsSync(a.out)) { print(`refused: field out: ${a.out} already exists`); return 2; }
  let text;
  try { text = fs.readFileSync(a.checkpoint, "utf8"); } catch { print("refused: field checkpoint: cannot be read"); return 2; }
  let r;
  try {
    r = buildBundle({ clone: path.resolve(a.clone), namespace: a.namespace, checkpointText: text, branch: a.branch || "main" });
  } catch (e) {
    print(`refused: field clone: ${e.message}`);
    return 2;
  }
  if (!r.ok) { print(`refused: field ${r.reason}: ${r.detail}`); return 2; }
  fs.writeFileSync(a.out, JSON.stringify(r.bundle, null, 1) + "\n", { flag: "wx" });
  print(`exported ${r.bundle.records.length} records of ${a.namespace}, proven into a checkpoint of size ${r.bundle.tree_size}` +
    (r.bundle.not_yet_in_checkpoint.length ? `; ${r.bundle.not_yet_in_checkpoint.length} newer records listed, not yet covered` : ""));
  return 0;
}

if (require.main === module) process.exit(main());

module.exports = { buildBundle, main };
