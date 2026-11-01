#!/usr/bin/env node
// tools/verify_namespace_bundle.js — check a namespace bundle from
// tools/export_namespace.js, offline (owner job 18).
//
//   node tools/verify_namespace_bundle.js <bundle.json> --key "<the log's verifier key>" [--allow-unsigned]
//
// One word and its exit code, as tools/follow.js answers:
//   VERIFIED        0  every record is in the log under the signed checkpoint, the namespace's
//                      records run 1, 2, 3 ... with none missing, and its head never went backward
//   BROKEN          1  a record not under the checkpoint's root, a record missing from the run,
//                      a record of another namespace or seq than its path, rows going backward,
//                      or the same rows with another chain; or a signature by the key that fails
//   COULD NOT LOOK  2  the file or the checkpoint cannot be read, or no signature by the key
//
// With --exhibit <file.txt> (OWNER.md queue item 41), and only when the answer
// is VERIFIED under a key given with --key, it also writes a plain text
// exhibit for a court or anyone else: the bundle file's SHA-256, the key, the
// checkpoint, every record checked, what that proves and what it does not,
// and how to check it again. Every line of it is built from what this check
// read and proved, never copied from text inside the bundle. It is written
// only where nothing is yet; any other answer writes no exhibit.
//
// What VERIFIED does not say: that the log is the one everybody else sees
// (compare checkpoints with others, tools/monitor.js), or anything about
// records written after this checkpoint, which the bundle only lists.

"use strict";

const fs = require("fs");
const logtree = require("../lib/_logtree.js");
const checkpoint = require("../lib/_checkpoint.js");

function verifyBundle(bundle, { key = null, allowUnsigned = false } = {}) {
  const cnl = (reason, detail) => ({ verdict: "COULD NOT LOOK", code: 2, reason, detail });
  const broken = (reason, detail) => ({ verdict: "BROKEN", code: 1, reason, detail });
  if (!bundle || bundle.kind !== "arcaeon_namespace_bundle" || bundle.v !== 1) return cnl("not_a_bundle");
  const ns = bundle.namespace;
  if (typeof ns !== "string" || !/^[a-z0-9-]{1,64}$/.test(ns)) return cnl("namespace");
  const cp = checkpoint.parseCheckpoint(bundle.checkpoint);
  if (!cp.ok) return cnl("checkpoint_unreadable", cp.reason);
  if (cp.size !== bundle.tree_size) return broken("tree_size", `the bundle says ${bundle.tree_size}, its checkpoint ${cp.size}`);
  if (key) {
    const s = checkpoint.verifyCheckpointSignature(bundle.checkpoint, key);
    if (!s.ok) {
      return s.reason === "no_signature_for_key" ? cnl("no_signature_for_key") : broken("bad_signature", s.reason);
    }
  } else if (!allowUnsigned) {
    return cnl("no_key_given", "pass --key, or --allow-unsigned to check against the checkpoint as it is");
  }
  if (!Array.isArray(bundle.records)) return cnl("records");
  const mine = new RegExp(`^pins/${ns}/([0-9]{8})\\.json$`);
  let expectSeq = 1;
  let last = null;
  const checked = [];
  for (const r of bundle.records) {
    const where = r && r.path;
    const m = typeof where === "string" ? mine.exec(where) : null;
    if (!m) return broken("path", `${where} is not a record of ${ns}`);
    const seq = Number(m[1]);
    if (seq !== expectSeq) return broken("missing_record", `record ${expectSeq} of ${ns} is not in the bundle (found ${seq})`);
    let bytes, env, hash;
    try {
      bytes = Buffer.from(r.bytes_b64, "base64");
      if (bytes.toString("base64") !== r.bytes_b64) throw new Error("not base64");
      env = logtree.makeEnvelope({ path: where, fileBytes: bytes, introducedByCommit: r.introduced_by_commit });
      hash = logtree.logLeafHash(env);
    } catch (e) {
      return broken("record_unreadable", `${where}: ${e.message}`);
    }
    const inc = logtree.verifyInclusion({ leaf_index: r.leaf_index, tree_size: cp.size, leaf_hash: hash,
      path: Array.isArray(r.path_hashes) ? r.path_hashes : [], root: cp.root });
    if (!inc.ok) return broken("not_in_checkpoint", `${where} is not under the checkpoint's root (${inc.reason})`);
    let rec;
    try { rec = JSON.parse(bytes.toString("utf8")); } catch { return broken("record_unreadable", `${where} is not JSON`); }
    if (rec.namespace !== ns || rec.seq !== seq) return broken("record_mismatch", `${where} holds namespace ${rec.namespace} seq ${rec.seq}`);
    if (!Number.isSafeInteger(rec.rows) || typeof rec.chain !== "string") return broken("record_unreadable", `${where} has no rows or chain`);
    if (last) {
      if (rec.rows < last.rows) return broken("went_backward", `${where}: rows ${rec.rows} after ${last.rows}`);
      if (rec.rows === last.rows && rec.chain.toLowerCase() !== last.chain.toLowerCase()) {
        return broken("chain_changed", `${where}: rows ${rec.rows} with another chain than record ${seq - 1}`);
      }
    }
    last = rec;
    checked.push({ seq, rows: rec.rows, chain: rec.chain.toLowerCase(),
      pinned_at: typeof rec.pinned_at === "string" ? rec.pinned_at : null,
      commit: typeof r.introduced_by_commit === "string" ? r.introduced_by_commit : null, leaf_index: r.leaf_index });
    expectSeq++;
  }
  const n = bundle.records.length;
  return { verdict: "VERIFIED", code: 0, reason: "consistent", signed: !!key,
    checked: { namespace: ns, origin: cp.origin, size: cp.size, root_hex: Buffer.from(cp.root).toString("hex"),
      records: checked,
      newer: Array.isArray(bundle.not_yet_in_checkpoint) ? bundle.not_yet_in_checkpoint.length : 0 },
    detail: `${n} record${n === 1 ? "" : "s"} of ${ns}, 1 to ${n}, every one under the checkpoint of size ${cp.size}` +
      (last ? `; the head at the checkpoint is rows ${last.rows}` : "") +
      (Array.isArray(bundle.not_yet_in_checkpoint) && bundle.not_yet_in_checkpoint.length
        ? `; ${bundle.not_yet_in_checkpoint.length} newer records listed, not yet covered by a checkpoint` : "") };
}

// The exhibit, as lines, from a VERIFIED result signed under key. bundleSha
// is the SHA-256 of the bundle file's bytes; now is the time of the check.
function exhibitLines(result, { bundleFile, bundleSha, key, now }) {
  const c = result.checked;
  const out = [
    "EXHIBIT: the witnessed history of one record in the Arcaeon public pin log",
    "",
    `Namespace: ${c.namespace}`,
    `Bundle file: ${bundleFile}`,
    `Bundle SHA-256: ${bundleSha}`,
    `Checked at: ${now} (the checking computer's clock)`,
    `Answer: VERIFIED`,
    "",
    "The log's signed checkpoint the bundle is checked against:",
    `  origin: ${c.origin}`,
    `  size: ${c.size} entries`,
    `  root: ${c.root_hex}`,
    `  signed by the verifier key: ${key}`,
    "",
    `Records of this namespace, all ${c.records.length}, each proven to be an entry of that log:`,
  ];
  for (const r of c.records) {
    out.push(`  record ${r.seq}: rows ${r.rows}, chain ${r.chain}` +
      (r.pinned_at ? `, received ${r.pinned_at} by the witness's clock` : "") +
      `, entry ${r.leaf_index} of the log` + (r.commit ? `, commit ${r.commit}` : ""));
  }
  out.push(
    "",
    "What this proves:",
    "  1. Each record above is, byte for byte, an entry of the log whose signed checkpoint is given, under the",
    "     verifier key given. The inclusion proof of each was checked against the checkpoint's root.",
    "  2. The records run 1 to " + c.records.length + " with none missing, each names this namespace and its own number.",
    "  3. The record's head never went backward: rows never fell, and the same rows never carried another chain.",
    "",
    "What this does not prove:",
    "  1. Anything about the content behind a head. The log holds digests and counts only, never content.",
    "  2. That this log is the one everybody else sees. That needs this checkpoint compared with others,",
    "     for example by the log's monitor or by outside cosigners.",
    "  3. Anything after this checkpoint." + (c.newer ? ` The bundle lists ${c.newer} newer record${c.newer === 1 ? "" : "s"}, not yet covered.` : ""),
    "  4. Who sent each pin. The hosted witness takes pins under bearer keys, not signatures.",
    "",
    "To check it again, with the same bundle file and the log's verifier key, published by the witness:",
    `  node tools/verify_namespace_bundle.js ${bundleFile} --key "<the verifier key above>"`,
    "The same bundle gives the same answer on any computer. The SHA-256 above names the bundle file exactly.",
    "",
  );
  return out;
}

function main(argv = process.argv.slice(2), print = console.log, now = () => new Date().toISOString()) {
  let file = null, key = null, allowUnsigned = false, exhibit = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--key") key = argv[++i];
    else if (argv[i] === "--exhibit") exhibit = argv[++i];
    else if (argv[i] === "--allow-unsigned") allowUnsigned = true;
    else if (!file) file = argv[i];
    else { print(`usage: unknown argument ${argv[i]}`); return 2; }
  }
  if (!file) { print("usage: verify_namespace_bundle.js <bundle.json> --key <verifier key>"); return 2; }
  if (exhibit !== null && (typeof exhibit !== "string" || exhibit === "")) {
    print("usage: --exhibit needs a file name"); return 2;
  }
  let raw, bundle;
  try {
    raw = fs.readFileSync(file);
    bundle = JSON.parse(raw.toString("utf8"));
  } catch { print("COULD NOT LOOK: the bundle cannot be read"); return 2; }
  const r = verifyBundle(bundle, { key, allowUnsigned });
  print(`${r.verdict}: ${r.reason}${r.detail ? `: ${r.detail}` : ""}`);
  if (exhibit !== null) {
    if (r.verdict !== "VERIFIED" || !r.signed) {
      print(`no exhibit written: field exhibit: an exhibit is written only for a bundle VERIFIED under a key given with --key`);
      return r.code === 0 ? 2 : r.code;
    }
    const sha = require("crypto").createHash("sha256").update(raw).digest("hex");
    const text = exhibitLines(r, { bundleFile: require("path").basename(file), bundleSha: sha, key, now: now() }).join("\n");
    try {
      fs.writeFileSync(exhibit, text, { flag: "wx" });
    } catch (e) {
      print(`no exhibit written: field exhibit: ${e.code === "EEXIST" ? "a file is already there; an exhibit never replaces one" : "the file cannot be written"}`);
      return 2;
    }
    print(`exhibit written: ${exhibit}`);
  }
  return r.code;
}

if (require.main === module) process.exit(main());

module.exports = { verifyBundle, exhibitLines, main };
