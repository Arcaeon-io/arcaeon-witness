#!/usr/bin/env node
// tools/verify_namespace_bundle.js — check a namespace bundle from
// tools/export_namespace.js, offline (owner job 18).
//
//   node tools/verify_namespace_bundle.js <bundle.json> --key "<the log's verifier key>" [--allow-unsigned]
//
// One word and its exit code, as tools/follow.js answers:
//   VERIFIED        0  the bundle's log envelopes rebuild the signed checkpoint's root, so they are
//                      every entry of the log up to its size; the bundle's records are exactly this
//                      namespace's entries among them, none left out at the start, middle or end;
//                      they run 1, 2, 3 ... with none missing, and the head never went backward
//   BROKEN          1  envelopes that do not give the root, a record of the namespace in the log but
//                      not in the bundle (anywhere, the last ones too), a record not under the root,
//                      a gap in the run, a record of another namespace or seq than its path, rows
//                      going backward, or the same rows with another chain; or a bad signature
//   COULD NOT LOOK  2  the file or the checkpoint cannot be read, a checkpoint of another log than
//                      this witness's (unknown_origin), no signature by the key, no record of the
//                      namespace under the checkpoint at all, or no key given (unsigned, below)
//
// Unsigned: with --allow-unsigned and no key, every check above is run, and a
// bundle that fails one is still BROKEN, but one that passes them all is never
// VERIFIED. It is COULD NOT LOOK, reason unsigned, exit 2. Without a signature
// nothing ties the checkpoint to the witness: anyone can cut records off the
// end, drop their envelopes, rebuild the root and write a new checkpoint for
// it, and every other check passes. Only a signature by the key shows the
// checkpoint is the witness's. (tools/follow.js marks the same case UNSIGNED.)
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
  if (!bundle || bundle.kind !== "arcaeon_namespace_bundle" || bundle.v !== 2) return cnl("not_a_bundle", "not a version 2 namespace bundle; version 1 carried no log envelopes and cannot show it is whole");
  const ns = bundle.namespace;
  if (typeof ns !== "string" || !/^[a-z0-9-]{1,64}$/.test(ns)) return cnl("namespace");
  const cp = checkpoint.parseCheckpoint(bundle.checkpoint);
  if (!cp.ok) return cnl("checkpoint_unreadable", cp.reason);
  if (cp.origin !== logtree.LOG_ORIGIN) return cnl("unknown_origin", `the checkpoint is of ${cp.origin}, not of this witness's log ${logtree.LOG_ORIGIN}`);
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
  // Completeness: the envelopes must be the whole log up to the signed size,
  // proven by giving its root. Then this namespace's entries among them are
  // all its records under the checkpoint, and the bundle must hold each one.
  const envs = bundle.log_envelopes;
  if (!Array.isArray(envs)) return cnl("log_envelopes", "the bundle carries no log envelopes, so nothing shows its records are all of them");
  if (envs.length !== cp.size) return broken("log_envelopes", `${envs.length} envelopes for a checkpoint of size ${cp.size}`);
  let hashes;
  try {
    hashes = envs.map((e, i) => {
      const c = logtree.checkEnvelope(e);
      if (!c.ok) throw new Error(`envelope ${i}: ${c.reason}`);
      return logtree.logLeafHash(e);
    });
  } catch (e) {
    return broken("log_envelopes", e.message);
  }
  if (!logtree.buildTree(hashes).rootAt(cp.size).equals(cp.root)) {
    return broken("log_envelopes", "the envelopes do not give the checkpoint's root");
  }
  const mine = new RegExp(`^pins/${ns}/([0-9]{8})\\.json$`);
  for (const r of bundle.records) {
    const where = r && r.path;
    if (typeof where !== "string" || !mine.test(where)) return broken("path", `${where} is not a record of ${ns}`);
  }
  const inLog = [];
  envs.forEach((e, i) => { if (mine.test(e.path)) inLog.push({ index: i, env: e }); });
  if (inLog.length === 0) return cnl("no_records", `the log holds no record of ${ns} under this checkpoint`);
  for (let i = 0; i < inLog.length; i++) {
    const want = inLog[i];
    const r = bundle.records[i];
    if (!r || r.path !== want.env.path || r.leaf_index !== want.index) {
      return broken("missing_record", `${want.env.path}, entry ${want.index} of the log, is not in the bundle where it belongs`);
    }
  }
  if (bundle.records.length !== inLog.length) {
    return broken("path", `the bundle holds ${bundle.records.length} records, the log ${inLog.length} of ${ns}`);
  }
  const obsPrefix = `observations/${ns}/`;
  if (bundle.observations !== undefined && !Array.isArray(bundle.observations)) return broken("observation_unknown", "the bundle's observations are not a list");
  const listedObs = new Set(Array.isArray(bundle.observations) ? bundle.observations : []);
  const missingObs = envs.find((e) => e.path.startsWith(obsPrefix) && !listedObs.has(e.path));
  if (missingObs) return broken("observation_missing", `${missingObs.path} is in the log but not listed in the bundle`);
  // And the other way: every observation listed is one of this namespace's
  // entries in the log under the checkpoint, none made up, none from after it.
  const logObs = new Set(envs.filter((e) => e.path.startsWith(obsPrefix)).map((e) => e.path));
  for (const o of listedObs) {
    if (!logObs.has(o)) return broken("observation_unknown", `${o} is listed in the bundle but is not an observation of ${ns} in the log under the checkpoint`);
  }
  let expectSeq = 1;
  let last = null;
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
    const env0 = envs[r.leaf_index];
    if (env.file_sha256 !== env0.file_sha256 || env.introduced_by_commit !== env0.introduced_by_commit) {
      return broken("not_in_checkpoint", `${where} is not the entry the log holds at ${r.leaf_index}`);
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
    expectSeq++;
  }
  const n = bundle.records.length;
  if (!key) {
    return cnl("unsigned", `the bundle agrees with its own checkpoint (${n} record${n === 1 ? "" : "s"} of ${ns}, size ${cp.size}), ` +
      "but no signature was checked, so nothing shows the checkpoint is the witness's: one rebuilt after records were cut " +
      "would agree just as well. Pass --key with the log's verifier key");
  }
  return { verdict: "VERIFIED", code: 0, reason: "consistent",
    detail: `${n} record${n === 1 ? "" : "s"} of ${ns}, 1 to ${n}, all the log holds of it under the checkpoint of size ${cp.size}` +
      (last ? `; the head at the checkpoint is rows ${last.rows}` : "") +
      (Array.isArray(bundle.not_yet_in_checkpoint) && bundle.not_yet_in_checkpoint.length
        ? `; ${bundle.not_yet_in_checkpoint.length} newer records listed, not yet covered by a checkpoint` : "") };
}

function main(argv = process.argv.slice(2), print = console.log) {
  let file = null, key = null, allowUnsigned = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--key") key = argv[++i];
    else if (argv[i] === "--allow-unsigned") allowUnsigned = true;
    else if (!file) file = argv[i];
    else { print(`usage: unknown argument ${argv[i]}`); return 2; }
  }
  if (!file) { print("usage: verify_namespace_bundle.js <bundle.json> --key <verifier key>"); return 2; }
  let bundle;
  try { bundle = JSON.parse(fs.readFileSync(file, "utf8")); } catch { print("COULD NOT LOOK: the bundle cannot be read"); return 2; }
  const r = verifyBundle(bundle, { key, allowUnsigned });
  print(`${r.verdict}: ${r.reason}${r.detail ? `: ${r.detail}` : ""}`);
  return r.code;
}

if (require.main === module) process.exit(main());

module.exports = { verifyBundle, main };
