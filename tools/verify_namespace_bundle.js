#!/usr/bin/env node
// tools/verify_namespace_bundle.js — check a namespace bundle from
// tools/export_namespace.js, offline (owner job 18).
//
//   node tools/verify_namespace_bundle.js <bundle.json> --key "<published key>" [--allow-unsigned]
//
// The witness's published verifier key is listed in docs/LOGTREE_KEY_RUNBOOK.md
// ("current verifier", and section 5 for where else it is published).
//
// One word and its exit code, as tools/follow.js answers:
//   VERIFIED        0  the bundle's log envelopes rebuild the root of the checkpoint signed by the key
//                      given (the witness's own only if that is its published key, above), so they are
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
// The key: any key can be given with --key, and a key someone made for a log
// of their own checks that log just as well. So the answer says which it was:
// one of the witness's published verifier keys (PUBLISHED_VERIFIER_KEYS below,
// the same list as docs/LOGTREE_KEY_RUNBOOK.md and log/checkpoints/KEYS.md in
// the pins repo), or only "the key you supplied".
//
// With --exhibit <file.txt> (OWNER.md queue item 41), and only when the answer
// is VERIFIED under one of the witness's published keys, it also writes a
// plain text exhibit: the bundle file's SHA-256, the key, the checkpoint, every
// record checked, what that proves and what it does not, and how to check it
// again. The checkpoint carries no time, so what it proves is only that each
// record is unchanged since the checkpoint of that size was signed. The time
// each record gives in its own pinned_at field is shown apart, as what the
// witness says, not as something proven. It does not say that a court or anyone
// else will accept it. Every line is built from what this check read and
// proved; the values taken from the bundle are the namespace, the checkpoint's
// origin, size and root (regex, equality and signature checked), each record's
// rows, chain, pinned_at, commit and leaf_index, and the number of newer records listed.
// The commit is 40 lowercase hex and the one the log's own envelope at that
// place names; the leaf_index is the very place the log holds the record; each
// newer record listed is a path pins/<ns>/<8 digits>.json. The exhibit is
// written only when each chain is 8 to 64 hex characters (the shape
// lib/_store.js enforces), each pinned_at an ISO time as the witness writes it,
// and the bundle file's name (printed too) is 1 to 128 of A-Z a-z 0-9 . _ -,
// so neither a bundle nor its file name can carry words of its own into it.
// It is written only where nothing is yet; any other answer, a key that is
// not one the witness publishes, or a field of the wrong shape writes no exhibit.
//
// What VERIFIED does not say: that the log is the one everybody else sees
// (compare checkpoints with others, tools/monitor.js), or anything about
// records written after this checkpoint, which the bundle only lists.

"use strict";

const fs = require("fs");
const logtree = require("../lib/_logtree.js");
const checkpoint = require("../lib/_checkpoint.js");

// The shapes the witness writes (lib/_store.js CHAIN_RE; pinned_at is
// Date.toISOString()). A value of another shape is never printed in an exhibit.
const CHAIN_SHAPE = /^[0-9a-fA-F]{8,64}$/;
const COMMIT_SHAPE = /^[0-9a-f]{40}$/;
// The bundle file's name, printed in the exhibit: no newline, space or other
// character that could add a line or words of its own.
const BUNDLE_FILE_SHAPE = /^[A-Za-z0-9._-]{1,128}$/;
const ISO_SHAPE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
function isIsoTime(s) {
  if (typeof s !== "string" || !ISO_SHAPE.test(s)) return false;
  const d = new Date(s);
  return !Number.isNaN(d.getTime()) && d.toISOString() === s;
}
// The first field of a checked result that may not go into an exhibit, or null.
function exhibitFieldProblem(c) {
  if (c.origin !== logtree.LOG_ORIGIN) return { field: "origin", detail: "the checkpoint is not of this witness's log" };
  for (const r of c.records) {
    if (!CHAIN_SHAPE.test(r.chain)) return { field: "chain", detail: `record ${r.seq}'s chain is not 8 to 64 hex characters, the shape the witness writes` };
    if (r.pinned_at !== null && !isIsoTime(r.pinned_at)) return { field: "pinned_at", detail: `record ${r.seq}'s pinned_at is not an ISO time as the witness writes it` };
    if (!Number.isSafeInteger(r.rows) || r.rows < 0) return { field: "rows", detail: `record ${r.seq}'s rows is not a whole number` };
    if (r.commit !== null && !COMMIT_SHAPE.test(r.commit)) return { field: "commit", detail: `record ${r.seq}'s commit is not 40 lowercase hex characters` };
    if (!Number.isSafeInteger(r.leaf_index) || r.leaf_index < 0) return { field: "leaf_index", detail: `record ${r.seq}'s place in the log is not a whole number` };
  }
  if (!Number.isSafeInteger(c.newer) || c.newer < 0) return { field: "newer", detail: "the count of newer records is not a whole number" };
  return null;
}
// Is the bundle file's name one that may be printed in an exhibit? null if so.
function bundleFileProblem(name) {
  if (typeof name === "string" && BUNDLE_FILE_SHAPE.test(name)) return null;
  return { field: "bundle_file", detail: "the bundle file's name is not 1 to 128 of the characters A-Z a-z 0-9 . _ -, so it is not printed; rename the file and check again" };
}

// The witness log's verifier keys as the witness publishes them (public halves
// only). On a rotation the new key is added here and the old one stays, as in
// KEYS.md: old checkpoints stay checkable under the old key.
const PUBLISHED_VERIFIER_KEYS = Object.freeze([
  "arcaeon.io/witness-log/2026-09-22+09765dec+AdKhx0P0WL2jig0oBbA5OC4I/Yu7dyiA54ju7lcMgQ07",
]);

// Is key one of the published ones? Compared by name, key hash and public key
// bytes, not by spelling.
function isPublishedKey(key, published = PUBLISHED_VERIFIER_KEYS) {
  const k = checkpoint.parseVerifierKey(key);
  if (!k.ok) return false;
  return published.some((p) => {
    const q = checkpoint.parseVerifierKey(p);
    return q.ok && q.name === k.name && q.hash === k.hash && q.pub.equals(k.pub);
  });
}

function verifyBundle(bundle, { key = null, allowUnsigned = false, publishedKeys = PUBLISHED_VERIFIER_KEYS } = {}) {
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
  // Observations after the checkpoint are only listed, not proven; each must
  // still be the path of an observation of this namespace, nothing else.
  const laterObs = bundle.observations_not_yet_in_checkpoint;
  if (laterObs !== undefined) {
    if (!Array.isArray(laterObs)) return broken("observation_later", "the bundle's later observations are not a list");
    const obsShape = new RegExp(`^observations/${ns}/[A-Za-z0-9._-]{1,128}\\.json$`);
    const odd = laterObs.find((o) => typeof o !== "string" || !obsShape.test(o));
    if (odd !== undefined) return broken("observation_later", `${JSON.stringify(odd)} is listed as a later observation but is not a path under ${obsPrefix}`);
  }
  // Records after the checkpoint are only listed, not proven, and only counted
  // in the exhibit; each must still be the path of a record of this namespace.
  const later = bundle.not_yet_in_checkpoint;
  if (later !== undefined) {
    if (!Array.isArray(later)) return broken("record_later", "the bundle's later records are not a list");
    const oddRec = later.find((p) => typeof p !== "string" || !mine.test(p));
    if (oddRec !== undefined) return broken("record_later", `${JSON.stringify(oddRec)} is listed as a later record but is not a path pins/${ns}/<8 digits>.json`);
  }
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
    checked.push({ seq, rows: rec.rows, chain: rec.chain.toLowerCase(),
      pinned_at: rec.pinned_at === undefined ? null : rec.pinned_at,
      commit: typeof r.introduced_by_commit === "string" ? r.introduced_by_commit : null, leaf_index: r.leaf_index });
    expectSeq++;
  }
  const n = bundle.records.length;
  if (!key) {
    return cnl("unsigned", `the bundle agrees with its own checkpoint (${n} record${n === 1 ? "" : "s"} of ${ns}, size ${cp.size}), ` +
      "but no signature was checked, so nothing shows the checkpoint is the witness's: one rebuilt after records were cut " +
      "would agree just as well. Pass --key with the log's verifier key");
  }
  const published = isPublishedKey(key, publishedKeys);
  const keyWords = published ? "; signed by the witness's published verifier key"
      : "; signed by the key you supplied, which is not one the witness publishes: this shows only that the bundle agrees with that key";
  return { verdict: "VERIFIED", code: 0, reason: "consistent", signed: true, published_key: published,
    checked: { namespace: ns, origin: cp.origin, size: cp.size, root_hex: Buffer.from(cp.root).toString("hex"),
      records: checked,
      newer: Array.isArray(bundle.not_yet_in_checkpoint) ? bundle.not_yet_in_checkpoint.length : 0 },
    detail: `${n} record${n === 1 ? "" : "s"} of ${ns}, 1 to ${n}, all the log holds of it under the checkpoint of size ${cp.size}` +
      (last ? `; the head at the checkpoint is rows ${last.rows}` : "") +
      (Array.isArray(bundle.not_yet_in_checkpoint) && bundle.not_yet_in_checkpoint.length
        ? `; ${bundle.not_yet_in_checkpoint.length} newer records listed, not yet covered by a checkpoint` : "") + keyWords };
}

// The exhibit, as lines, from a VERIFIED result signed under key, which main
// has already found among the witness's published keys. bundleSha
// is the SHA-256 of the bundle file's bytes; now is the time of the check.
function exhibitLines(result, { bundleFile, bundleSha, key, now }) {
  const c = result.checked;
  const bad = exhibitFieldProblem(c) || bundleFileProblem(bundleFile);
  if (bad) throw new TypeError(`exhibit: field ${bad.field}: ${bad.detail}`);
  const out = [
    "EXHIBIT: the witnessed history of one namespace in the Arcaeon public pin log",
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
    `  signed by the witness's published verifier key: ${key}`,
    "  (the key is checked against the list in this tool, the same as docs/LOGTREE_KEY_RUNBOOK.md",
    "  and log/checkpoints/KEYS.md in the pins repo)",
    "",
    `Records of this namespace under that checkpoint: ${c.records.length}. Every entry of the log up to its size was`,
    "checked, so no record of this namespace under the checkpoint is left out:",
  ];
  for (const r of c.records) {
    out.push(`  record ${r.seq}: rows ${r.rows}, chain ${r.chain}` +
      `, entry ${r.leaf_index} of the log` + (r.commit ? `, commit ${r.commit}` : ""));
  }
  out.push(
    "",
    "What this proves:",
    `  1. Each record above is, byte for byte, an entry of the log of size ${c.size} whose checkpoint is signed by`,
    "     the witness's published key. So each record is unchanged since that checkpoint was signed. The",
    "     inclusion proof of each was checked against the checkpoint's root.",
    "  2. These are all the records of this namespace under the checkpoint: the log's entries up to its size",
    "     give its root, and the records run 1 to " + c.records.length + " among them, each naming this namespace and its own number.",
    "  3. The head never went backward: rows never fell, and the same rows never carried another chain.",
    "",
    "What the witness says (its own statement, not proven by this check):",
  );
  const timed = c.records.filter((r) => r.pinned_at !== null);
  if (timed.length === 0) out.push("  The records carry no time of receipt.");
  for (const r of timed) out.push(`  record ${r.seq}: received ${r.pinned_at} by the witness's own clock, as its pinned_at field says.`);
  out.push(
    "",
    "What this does not prove:",
    "  1. When the checkpoint was signed, or when any record was received. The checkpoint carries no time;",
    "     the times above are the witness's own word, written in each record.",
    "  2. Anything about the content behind a head. The log holds digests and counts only, never content.",
    "  3. That this log is the one everybody else sees. That needs this checkpoint compared with others,",
    "     for example by the log's monitor or by outside cosigners.",
    "  4. Anything after this checkpoint." + (c.newer ? ` The bundle lists ${c.newer} newer record${c.newer === 1 ? "" : "s"}, not yet covered.` : ""),
    "  5. Who sent each pin. The hosted witness takes pins under bearer keys, not signatures.",
    "  6. That any court or other body will accept this. It says what was checked and nothing more.",
    "",
    "To check it again, with the same bundle file and the witness's published verifier key above:",
    `  node tools/verify_namespace_bundle.js ${bundleFile} --key "<the verifier key above>"`,
    "The same bundle gives the same answer on any computer. The SHA-256 above names the bundle file exactly.",
    "",
  );
  return out;
}

function main(argv = process.argv.slice(2), print = console.log, now = () => new Date().toISOString(),
  { publishedKeys = PUBLISHED_VERIFIER_KEYS } = {}) {
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
  const r = verifyBundle(bundle, { key, allowUnsigned, publishedKeys });
  print(`${r.verdict}: ${r.reason}${r.detail ? `: ${r.detail}` : ""}`);
  if (exhibit !== null) {
    if (r.verdict !== "VERIFIED" || !r.signed) {
      print(`no exhibit written: field exhibit: an exhibit is written only for a bundle VERIFIED under a key given with --key`);
      return r.code === 0 ? 2 : r.code;
    }
    if (!r.published_key) {
      print("no exhibit written: field key: the key you supplied is not one the witness publishes; " +
        "anyone can make a log and a key of their own, so an exhibit under it would show nothing about the witness");
      return 2;
    }
    const bundleFile = require("path").basename(file);
    const bad = exhibitFieldProblem(r.checked) || bundleFileProblem(bundleFile);
    if (bad) {
      print(`no exhibit written: field ${bad.field}: ${bad.detail}`);
      return 2;
    }
    const sha = require("crypto").createHash("sha256").update(raw).digest("hex");
    const text = exhibitLines(r, { bundleFile, bundleSha: sha, key, now: now() }).join("\n");
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

module.exports = { verifyBundle, exhibitLines, exhibitFieldProblem, bundleFileProblem, isIsoTime, isPublishedKey, PUBLISHED_VERIFIER_KEYS, main };
