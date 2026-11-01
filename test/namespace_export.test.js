// test/namespace_export.test.js — owner job 18: everything one namespace
// pinned, as one bundle anyone can check offline (tools/export_namespace.js,
// tools/verify_namespace_bundle.js). The checkpoint is made by the real
// tools/publish_checkpoint.js over a real git fixture, so the exporter and
// the publisher must agree leaf for leaf.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const cp = require("../lib/_checkpoint.js");
const exporter = require("../tools/export_namespace.js");
const checker = require("../tools/verify_namespace_bundle.js");
const logtree = require("../lib/_logtree.js");

const PUBLISH = path.join(__dirname, "..", "tools", "publish_checkpoint.js");
const KEY = cp.generateKey("arcaeon.io/witness-pins/log");

function git(repo, args) {
  const r = spawnSync("git", ["-C", repo, "-c", "user.name=f", "-c", "user.email=f@example.invalid", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout;
}
function commit(repo, files, msg) {
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(repo, rel)), { recursive: true });
    fs.writeFileSync(path.join(repo, rel), content);
  }
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", msg]);
}
// Chains as the witness writes them (8 to 64 hex): "aa" stands for "aaaaaaaa". pinned_at as Date.toISOString.
const rec = (ns, seq, rows, chain) => JSON.stringify({ namespace: ns, rows, chain: chain.repeat(4), seq,
  pinned_at: `2026-10-31T0${seq}:00:00.000Z` }) + "\n";

function fixture() {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "ns-export-"));
  git(repo, ["init", "-q", "-b", "main"]);
  commit(repo, { "pins/demo-a/00000001.json": rec("demo-a", 1, 3, "aa"), "pins/demo-a/latest.json": "{}\n" }, "a1");
  commit(repo, { "pins/demo-b/00000001.json": rec("demo-b", 1, 9, "bb") }, "b1");
  commit(repo, { "pins/demo-a/00000002.json": rec("demo-a", 2, 5, "cc") }, "a2");
  commit(repo, { "observations/demo-a/2026-10-31T00-00-00-000Z.json": '{"verdict":"head-conflict"}\n' }, "obs");
  commit(repo, { "pins/demo-a/00000003.json": rec("demo-a", 3, 5, "cc") }, "a3 heartbeat");
  return repo;
}
function publish(repo, extra = []) {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "ns-cp-"));
  const r = spawnSync(process.execPath, [PUBLISH, "--clone", repo, "--out", out, "--date", "2026-10-31", "--key-env", "CP_KEY", "--write", ...extra],
    { encoding: "utf8", env: { ...process.env, CP_KEY: KEY.signer } });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  return fs.readFileSync(path.join(out, "checkpoints", "2026-10-31.txt"), "utf8");
}

test("EXPORT AND CHECK: every record of the namespace, proven into the published checkpoint, VERIFIED", () => {
  const repo = fixture();
  const text = publish(repo);
  const r = exporter.buildBundle({ clone: repo, namespace: "demo-a", checkpointText: text });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual(r.bundle.records.map((x) => x.seq), [1, 2, 3]);
  assert.deepEqual(r.bundle.observations, ["observations/demo-a/2026-10-31T00-00-00-000Z.json"]);
  assert.ok(!JSON.stringify(r.bundle.records).includes("demo-b"), "only this namespace's records");
  const v = checker.verifyBundle(r.bundle, { key: KEY.verifier });
  assert.equal(v.verdict, "VERIFIED", JSON.stringify(v));
  assert.match(v.detail, /3 records of demo-a, 1 to 3/);
});

test("NEWER RECORDS: written after the checkpoint, they are listed, not proven", () => {
  const repo = fixture();
  const text = publish(repo);
  commit(repo, { "pins/demo-a/00000004.json": rec("demo-a", 4, 8, "dd") }, "a4");
  const r = exporter.buildBundle({ clone: repo, namespace: "demo-a", checkpointText: text });
  assert.equal(r.ok, true);
  assert.deepEqual(r.bundle.not_yet_in_checkpoint, ["pins/demo-a/00000004.json"]);
  assert.equal(checker.verifyBundle(r.bundle, { key: KEY.verifier }).verdict, "VERIFIED");
});

test("REFUSED: a checkpoint this clone does not reproduce, an unknown namespace", () => {
  const repo = fixture();
  // Another history of the same size: the same paths, one record's bytes other.
  const other = fs.mkdtempSync(path.join(os.tmpdir(), "ns-other-"));
  git(other, ["init", "-q", "-b", "main"]);
  commit(other, { "pins/demo-a/00000001.json": rec("demo-a", 1, 3, "aa"), "pins/demo-a/latest.json": "{}\n" }, "a1");
  commit(other, { "pins/demo-b/00000001.json": rec("demo-b", 1, 9, "bb") }, "b1");
  commit(other, { "pins/demo-a/00000002.json": rec("demo-a", 2, 5, "cc") }, "a2");
  commit(other, { "observations/demo-a/2026-10-31T00-00-00-000Z.json": '{"verdict":"head-conflict"}\n' }, "obs");
  commit(other, { "pins/demo-a/00000003.json": rec("demo-a", 3, 5, "ff") }, "a3 other");
  const r = exporter.buildBundle({ clone: repo, namespace: "demo-a", checkpointText: publish(other) });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "checkpoint");
  assert.match(r.detail, /not the root this clone gives/);
  assert.equal(exporter.buildBundle({ clone: repo, namespace: "demo-zz", checkpointText: publish(repo) }).reason, "namespace");
});

function bundle() {
  const repo = fixture();
  return exporter.buildBundle({ clone: repo, namespace: "demo-a", checkpointText: publish(repo) }).bundle;
}
const clone = (x) => JSON.parse(JSON.stringify(x));

test("BROKEN: a changed record, a dropped record, a moved head, a record of another namespace", () => {
  const b = bundle();
  const changed = clone(b);
  changed.records[1].bytes_b64 = Buffer.from(rec("demo-a", 2, 6, "cc")).toString("base64");
  assert.equal(checker.verifyBundle(changed, { key: KEY.verifier }).reason, "not_in_checkpoint");
  const dropped = clone(b);
  dropped.records.splice(1, 1);
  assert.equal(checker.verifyBundle(dropped, { key: KEY.verifier }).reason, "missing_record");
  const wrongPath = clone(b);
  wrongPath.records[0].path = "pins/demo-b/00000001.json";
  assert.equal(checker.verifyBundle(wrongPath, { key: KEY.verifier }).reason, "path");
  const proof = clone(b);
  proof.records[0].path_hashes[0] = "00".repeat(32);
  assert.equal(checker.verifyBundle(proof, { key: KEY.verifier }).reason, "not_in_checkpoint");
  const size = clone(b);
  size.tree_size = 99;
  assert.equal(checker.verifyBundle(size, { key: KEY.verifier }).verdict, "BROKEN");
});

test("BROKEN: a log that went backward or changed its chain at the same rows is caught even when every record is in the log", () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "ns-back-"));
  git(repo, ["init", "-q", "-b", "main"]);
  commit(repo, { "pins/demo-a/00000001.json": rec("demo-a", 1, 5, "aa") }, "1");
  commit(repo, { "pins/demo-a/00000002.json": rec("demo-a", 2, 4, "bb") }, "2 backward");
  let r = exporter.buildBundle({ clone: repo, namespace: "demo-a", checkpointText: publish(repo) });
  assert.equal(checker.verifyBundle(r.bundle, { key: KEY.verifier }).reason, "went_backward");
  const repo2 = fs.mkdtempSync(path.join(os.tmpdir(), "ns-chain-"));
  git(repo2, ["init", "-q", "-b", "main"]);
  commit(repo2, { "pins/demo-a/00000001.json": rec("demo-a", 1, 5, "aa") }, "1");
  commit(repo2, { "pins/demo-a/00000002.json": rec("demo-a", 2, 5, "bb") }, "2 other chain");
  r = exporter.buildBundle({ clone: repo2, namespace: "demo-a", checkpointText: publish(repo2) });
  assert.equal(checker.verifyBundle(r.bundle, { key: KEY.verifier }).reason, "chain_changed");
});

test("SIGNATURE: no key line cannot be attributed; another key's line does not pass; --allow-unsigned checks the rest but is never VERIFIED", () => {
  const b = bundle();
  const other = cp.generateKey("arcaeon.io/witness-pins/log");
  assert.equal(checker.verifyBundle(b, { key: other.verifier }).verdict, "COULD NOT LOOK");
  assert.equal(checker.verifyBundle(b, {}).reason, "no_key_given");
  const u = checker.verifyBundle(b, { allowUnsigned: true });
  assert.equal(u.verdict, "COULD NOT LOOK", JSON.stringify(u));
  assert.equal(u.reason, "unsigned");
  assert.equal(u.code, 2);
  // A bundle that fails a check is still BROKEN without a key.
  const changed = clone(b);
  changed.records[1].bytes_b64 = Buffer.from(rec("demo-a", 2, 6, "cc")).toString("base64");
  assert.equal(checker.verifyBundle(changed, { allowUnsigned: true }).verdict, "BROKEN");
});

test("UNSIGNED: a tail cut with the root and checkpoint rebuilt passes every other check, and is still not VERIFIED", () => {
  const b = bundle();
  const forged = clone(b);
  // The attacker drops the last record and its envelope, rebuilds the root and
  // the proofs over what is left, and writes a fresh checkpoint for it.
  const lastIdx = forged.records.pop().leaf_index;
  forged.log_envelopes.splice(lastIdx, 1);
  const tree = logtree.buildTree(forged.log_envelopes.map((e) => logtree.logLeafHash(e)));
  const size = forged.log_envelopes.length;
  for (const r of forged.records) {
    r.leaf_index = forged.log_envelopes.findIndex((e) => e.path === r.path);
    r.path_hashes = tree.inclusionProof(r.leaf_index, size).map((h) => h.toString("hex"));
  }
  forged.observations = forged.observations.filter((o) => forged.log_envelopes.some((e) => e.path === o));
  forged.tree_size = size;
  forged.checkpoint = cp.formatCheckpoint({ origin: logtree.LOG_ORIGIN, size, root: tree.rootAt(size) });
  const u = checker.verifyBundle(forged, { allowUnsigned: true });
  assert.notEqual(u.verdict, "VERIFIED");
  assert.equal(u.reason, "unsigned", JSON.stringify(u));
  assert.equal(u.code, 2);
  // With the key, the forged checkpoint carries no signature by it.
  assert.equal(checker.verifyBundle(forged, { key: KEY.verifier }).reason, "no_signature_for_key");
  // The CLI answers the same: COULD NOT LOOK, exit 2.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ns-forged-"));
  fs.writeFileSync(path.join(dir, "f.json"), JSON.stringify(forged));
  const said = [];
  assert.equal(checker.main([path.join(dir, "f.json"), "--allow-unsigned"], (l) => said.push(l)), 2);
  assert.match(said.join(" | "), /^COULD NOT LOOK: unsigned/);
});

test("ORIGIN: a checkpoint of another log, even signed by the key, is COULD NOT LOOK unknown_origin", () => {
  const b = bundle();
  const p = cp.parseCheckpoint(b.checkpoint);
  const otherText = cp.signCheckpoint(cp.formatCheckpoint({ origin: "example.invalid/another-log/v1", size: p.size, root: p.root }), KEY.signer);
  const other = clone(b);
  other.checkpoint = otherText;
  const v = checker.verifyBundle(other, { key: KEY.verifier });
  assert.equal(v.verdict, "COULD NOT LOOK", JSON.stringify(v));
  assert.equal(v.reason, "unknown_origin");
  assert.equal(checker.verifyBundle(other, { allowUnsigned: true }).reason, "unknown_origin");
});

test("OBSERVATIONS: one listed that is not in the log, or is after the checkpoint, is BROKEN", () => {
  const b = bundle();
  const madeUp = clone(b);
  madeUp.observations.push("observations/demo-a/2026-10-31T09-09-09-000Z.json");
  assert.equal(checker.verifyBundle(madeUp, { key: KEY.verifier }).reason, "observation_unknown");
  // After the checkpoint: the exporter lists it apart, and listed as under the checkpoint it is refused.
  const repo = fixture();
  const text = publish(repo);
  commit(repo, { "observations/demo-a/2026-11-01T00-00-00-000Z.json": '{"verdict":"head-conflict"}\n' }, "obs later");
  const r = exporter.buildBundle({ clone: repo, namespace: "demo-a", checkpointText: text });
  assert.equal(r.ok, true);
  assert.deepEqual(r.bundle.observations, ["observations/demo-a/2026-10-31T00-00-00-000Z.json"]);
  assert.deepEqual(r.bundle.observations_not_yet_in_checkpoint, ["observations/demo-a/2026-11-01T00-00-00-000Z.json"]);
  assert.equal(checker.verifyBundle(r.bundle, { key: KEY.verifier }).verdict, "VERIFIED");
  const late = clone(r.bundle);
  late.observations.push("observations/demo-a/2026-11-01T00-00-00-000Z.json");
  assert.equal(checker.verifyBundle(late, { key: KEY.verifier }).reason, "observation_unknown");
  const notList = clone(b);
  notList.observations = "observations/demo-a/2026-10-31T00-00-00-000Z.json";
  assert.equal(checker.verifyBundle(notList, { key: KEY.verifier }).verdict, "BROKEN");
});

test("CLI: writes once, refuses to overwrite, and the checker's exit code is its verdict", () => {
  const repo = fixture();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ns-cli-"));
  fs.writeFileSync(path.join(dir, "cp.txt"), publish(repo));
  const out = path.join(dir, "bundle.json");
  const args = ["--clone", repo, "--namespace", "demo-a", "--checkpoint", path.join(dir, "cp.txt"), "--out", out];
  assert.equal(exporter.main(args, () => {}), 0);
  assert.equal(exporter.main(args, () => {}), 2, "the out file is never written over");
  assert.equal(checker.main([out, "--key", KEY.verifier], () => {}), 0);
  const b = JSON.parse(fs.readFileSync(out, "utf8"));
  b.records.pop();
  b.records.shift();
  fs.writeFileSync(out + ".bad", JSON.stringify(b));
  assert.equal(checker.main([out + ".bad", "--key", KEY.verifier], () => {}), 1);
});

test("BROKEN: a record whose content names another namespace or seq than its path", () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "ns-mis-"));
  git(repo, ["init", "-q", "-b", "main"]);
  commit(repo, { "pins/demo-a/00000001.json": rec("demo-b", 1, 5, "aa") }, "1");
  const r = exporter.buildBundle({ clone: repo, namespace: "demo-a", checkpointText: publish(repo) });
  assert.equal(checker.verifyBundle(r.bundle, { key: KEY.verifier }).reason, "record_mismatch");
});

test("WHOLE: a bundle with its last records cut off, or with none, is not VERIFIED", () => {
  const b = bundle();
  const tail = clone(b);
  tail.records.pop();
  let v = checker.verifyBundle(tail, { key: KEY.verifier });
  assert.equal(v.verdict, "BROKEN", JSON.stringify(v));
  assert.equal(v.reason, "missing_record");
  assert.match(v.detail, /00000003\.json/);
  const tail2 = clone(b);
  tail2.records.splice(1);
  assert.equal(checker.verifyBundle(tail2, { key: KEY.verifier }).reason, "missing_record");
  const empty = clone(b);
  empty.records = [];
  v = checker.verifyBundle(empty, { key: KEY.verifier });
  assert.equal(v.verdict, "BROKEN", JSON.stringify(v));
  assert.equal(v.reason, "missing_record");
  // The same cuts without a key, against the original checkpoint: its root no
  // longer matches the records, so BROKEN missing_record. (An attacker who also
  // rebuilds the root and checkpoint is the UNSIGNED test below.)
  assert.equal(checker.verifyBundle(tail, { allowUnsigned: true }).reason, "missing_record");
  assert.notEqual(checker.verifyBundle(tail, { allowUnsigned: true }).verdict, "VERIFIED");
  assert.notEqual(checker.verifyBundle(empty, { allowUnsigned: true }).verdict, "VERIFIED");
});

test("WHOLE: the envelopes cannot be trimmed or edited to hide a record", () => {
  const b = bundle();
  // Cut the last record and its envelope too: the envelopes no longer give the root.
  const both = clone(b);
  const lastIdx = both.records.pop().leaf_index;
  both.log_envelopes.splice(lastIdx, 1);
  assert.equal(checker.verifyBundle(both, { key: KEY.verifier }).reason, "log_envelopes");
  // Rename the last record's envelope so it no longer reads as this namespace's.
  const renamed = clone(b);
  renamed.records.pop();
  renamed.log_envelopes[lastIdx].path = "pins/demo-b/00000002.json";
  assert.equal(checker.verifyBundle(renamed, { key: KEY.verifier }).reason, "log_envelopes");
  // No envelopes at all: nothing shows the bundle is whole.
  const none = clone(b);
  delete none.log_envelopes;
  assert.equal(checker.verifyBundle(none, { key: KEY.verifier }).verdict, "COULD NOT LOOK");
  // A version 1 bundle (no envelopes) is not taken.
  const v1 = clone(b);
  v1.v = 1;
  assert.equal(checker.verifyBundle(v1, { key: KEY.verifier }).verdict, "COULD NOT LOOK");
  // An observation in the log but left off the list.
  const obs = clone(b);
  obs.observations = [];
  assert.equal(checker.verifyBundle(obs, { key: KEY.verifier }).reason, "observation_missing");
  // The envelopes hold no other namespace's bytes, only paths and digests.
  assert.ok(!JSON.stringify(b.log_envelopes).includes(Buffer.from(rec("demo-b", 1, 9, "bb")).toString("base64")));
});

test("WHOLE: a namespace with no record under the checkpoint yet is refused at export", () => {
  const repo = fixture();
  const text = publish(repo);
  commit(repo, { "pins/demo-c/00000001.json": rec("demo-c", 1, 1, "aa") }, "c1");
  const r = exporter.buildBundle({ clone: repo, namespace: "demo-c", checkpointText: text });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "namespace");
});

// ---- The exhibit (OWNER.md queue item 41) ----
// The fixture key stands in for the witness's published key, passed the way main takes the list.
const AS_PUBLISHED = { publishedKeys: [KEY.verifier] };

function bundleFile(repo) {
  const text = publish(repo);
  const r = exporter.buildBundle({ clone: repo, namespace: "demo-a", checkpointText: text });
  assert.equal(r.ok, true);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ns-exhibit-"));
  const file = path.join(dir, "demo-a.bundle.json");
  // Indented, as a person might save it: the SHA-256 is of these exact bytes.
  fs.writeFileSync(file, JSON.stringify(r.bundle, null, 2) + "\n");
  return { dir, file, bundle: r.bundle };
}

test("EXHIBIT: written for a VERIFIED bundle under a key, from what was checked, naming the bundle's SHA-256", () => {
  const { dir, file } = bundleFile(fixture());
  const out = path.join(dir, "exhibit.txt");
  const said = [];
  const code = checker.main([file, "--key", KEY.verifier, "--exhibit", out], (l) => said.push(l), () => "2026-11-01T08:00:00.000Z", AS_PUBLISHED);
  assert.equal(code, 0, said.join("\n"));
  const text = fs.readFileSync(out, "utf8");
  const sha = require("crypto").createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  assert.ok(text.includes(`Bundle SHA-256: ${sha}`));
  assert.ok(text.includes("Answer: VERIFIED"));
  assert.ok(text.includes(`signed by the witness's published verifier key: ${KEY.verifier}`));
  assert.match(text, /record 1: rows 3, chain aaaaaaaa,/);
  assert.match(text, /record 2: rows 5, chain cccccccc,/);
  assert.match(text, /record 3: rows 5, chain cccccccc,/);
  assert.ok(text.includes(`  origin: ${logtree.LOG_ORIGIN}\n`));
  // The time is the witness's word, printed apart from what the check proves.
  const proves = text.slice(text.indexOf("What this proves:"), text.indexOf("What the witness says"));
  const says = text.slice(text.indexOf("What the witness says"), text.indexOf("What this does not prove:"));
  assert.ok(!/received|2026-10-31T0/.test(proves), proves);
  assert.match(proves, /unchanged since that checkpoint was signed/);
  assert.match(says, /record 1: received 2026-10-31T01:00:00\.000Z by the witness's own clock/);
  assert.match(text, /When the checkpoint was signed, or when any record was received/);
  assert.ok(!/not changed after the witness logged it/.test(text));
  assert.ok(text.includes("What this does not prove:"));
  assert.ok(!/[–—]/.test(text), "no dashes");
  assert.ok(!text.includes("demo-b"), "only this namespace");
});

test("EXHIBIT: text the bundle carries is never copied into it", () => {
  const { dir, file, bundle } = bundleFile(fixture());
  fs.writeFileSync(file, JSON.stringify({ ...bundle, exhibit: "VERIFIED by a court", note: "trust me" }));
  const out = path.join(dir, "exhibit.txt");
  assert.equal(checker.main([file, "--key", KEY.verifier, "--exhibit", out], () => {}, undefined, AS_PUBLISHED), 0);
  const text = fs.readFileSync(out, "utf8");
  assert.ok(!text.includes("by a court") && !text.includes("trust me"));
});

test("EXHIBIT: none for BROKEN, none without a key, never over an existing file", () => {
  const { dir, file, bundle } = bundleFile(fixture());
  // BROKEN: a record's bytes changed after the export.
  const bad = JSON.parse(JSON.stringify(bundle));
  bad.records[1].bytes_b64 = Buffer.from(JSON.stringify({ namespace: "demo-a", rows: 6, chain: "ee", seq: 2 }) + "\n").toString("base64");
  const badFile = path.join(dir, "bad.bundle.json");
  fs.writeFileSync(badFile, JSON.stringify(bad));
  const said = [];
  const out = path.join(dir, "exhibit.txt");
  assert.equal(checker.main([badFile, "--key", KEY.verifier, "--exhibit", out], (l) => said.push(l), undefined, AS_PUBLISHED), 1);
  assert.equal(fs.existsSync(out), false);
  assert.ok(said.some((l) => l.startsWith("no exhibit written: field exhibit:")), said.join("\n"));
  // Unsigned: VERIFIED as it is, but no exhibit.
  assert.equal(checker.main([file, "--allow-unsigned", "--exhibit", out], () => {}, undefined, AS_PUBLISHED), 2);
  assert.equal(fs.existsSync(out), false);
  // An existing file is never replaced.
  fs.writeFileSync(out, "already here");
  const said2 = [];
  assert.equal(checker.main([file, "--key", KEY.verifier, "--exhibit", out], (l) => said2.push(l), undefined, AS_PUBLISHED), 2);
  assert.equal(fs.readFileSync(out, "utf8"), "already here");
  assert.ok(said2.some((l) => l.includes("never replaces")));
});

test("KEY: a key the caller made is never called the witness's; no exhibit under it", () => {
  // Anyone can make a log and a key of their own: the bundle checks, but only against that key.
  const { dir, file } = bundleFile(fixture());
  const v = checker.verifyBundle(JSON.parse(fs.readFileSync(file, "utf8")), { key: KEY.verifier });
  assert.equal(v.verdict, "VERIFIED");
  assert.equal(v.published_key, false);
  assert.match(v.detail, /the key you supplied, which is not one the witness publishes/);
  assert.ok(!/witness's published verifier key/.test(v.detail));
  const said = [];
  const out = path.join(dir, "exhibit.txt");
  assert.equal(checker.main([file, "--key", KEY.verifier, "--exhibit", out], (l) => said.push(l)), 2);
  assert.equal(fs.existsSync(out), false);
  assert.ok(said.some((l) => l.startsWith("no exhibit written: field key:")), said.join("\n"));
  // Under the published list, the same key is named as the witness's.
  const p = checker.verifyBundle(JSON.parse(fs.readFileSync(file, "utf8")), { key: KEY.verifier, ...AS_PUBLISHED });
  assert.equal(p.published_key, true);
  assert.match(p.detail, /signed by the witness's published verifier key/);
});

test("KEY: the pinned published key is well formed, matches the runbook, and a look-alike does not pass", () => {
  assert.ok(checker.PUBLISHED_VERIFIER_KEYS.length >= 1);
  const runbook = fs.readFileSync(path.join(__dirname, "..", "docs", "LOGTREE_KEY_RUNBOOK.md"), "utf8");
  for (const k of checker.PUBLISHED_VERIFIER_KEYS) {
    assert.equal(cp.parseVerifierKey(k).ok, true, k);
    assert.equal(checker.isPublishedKey(k), true);
    assert.ok(runbook.includes(k), `${k} is in docs/LOGTREE_KEY_RUNBOOK.md`);
  }
  const lookAlike = cp.generateKey(cp.parseVerifierKey(checker.PUBLISHED_VERIFIER_KEYS[0]).name);
  assert.equal(checker.isPublishedKey(lookAlike.verifier), false, "same name, another key");
  assert.equal(checker.isPublishedKey("not a key"), false);
});

test("WORDS: the exhibit and the docs make no claim that a court accepts it", () => {
  const { dir, file } = bundleFile(fixture());
  const out = path.join(dir, "exhibit.txt");
  assert.equal(checker.main([file, "--key", KEY.verifier, "--exhibit", out], () => {}, undefined, AS_PUBLISHED), 0);
  const text = fs.readFileSync(out, "utf8");
  assert.ok(!/court ready|court-ready|admissible/i.test(text));
  assert.match(text, /unchanged since that checkpoint was signed/);
  assert.match(text, /That any court or other body will accept this/);
  const doc = fs.readFileSync(path.join(__dirname, "..", "NAMESPACE_EXPORT.md"), "utf8");
  assert.ok(!/court ready|court-ready/i.test(doc));
});

test("EXHIBIT: a chain or pinned_at of another shape than the witness writes is never printed", () => {
  const cases = [
    ["chain", { namespace: "demo-a", rows: 3, chain: "VERIFIED by a court", seq: 1, pinned_at: "2026-10-31T01:00:00.000Z" }],
    ["pinned_at", { namespace: "demo-a", rows: 3, chain: "aaaaaaaa", seq: 1, pinned_at: "yesterday. Answer: accepted by a court" }],
    ["pinned_at", { namespace: "demo-a", rows: 3, chain: "aaaaaaaa", seq: 1, pinned_at: "2026-02-30T01:00:00.000Z" }],
    ["pinned_at", { namespace: "demo-a", rows: 3, chain: "aaaaaaaa", seq: 1, pinned_at: 1761872400000 }],
  ];
  for (const [field, body] of cases) {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), "ns-shape-"));
    git(repo, ["init", "-q", "-b", "main"]);
    commit(repo, { "pins/demo-a/00000001.json": JSON.stringify(body) + "\n" }, "1");
    const { dir, file } = bundleFile(repo);
    const out = path.join(dir, "exhibit.txt");
    const said = [];
    assert.equal(checker.main([file, "--key", KEY.verifier, "--exhibit", out], (l) => said.push(l), undefined, AS_PUBLISHED), 2, said.join(" | "));
    assert.ok(said[0].startsWith("VERIFIED"), said.join(" | "));
    assert.ok(said.some((l) => l.startsWith(`no exhibit written: field ${field}:`)), said.join(" | "));
    assert.equal(fs.existsSync(out), false);
  }
  assert.equal(checker.isIsoTime("2026-10-31T01:00:00.000Z"), true);
  assert.equal(checker.isIsoTime("2026-10-31T01:00:00Z"), false);
});

test("EXHIBIT: records with no pinned_at are shown with no time, and exhibitLines refuses a bad shape itself", () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "ns-notime-"));
  git(repo, ["init", "-q", "-b", "main"]);
  commit(repo, { "pins/demo-a/00000001.json": JSON.stringify({ namespace: "demo-a", rows: 3, chain: "aaaaaaaa", seq: 1 }) + "\n" }, "1");
  const { dir, file, bundle: b } = bundleFile(repo);
  const out = path.join(dir, "exhibit.txt");
  assert.equal(checker.main([file, "--key", KEY.verifier, "--exhibit", out], () => {}, undefined, AS_PUBLISHED), 0);
  assert.match(fs.readFileSync(out, "utf8"), /The records carry no time of receipt\./);
  const v = checker.verifyBundle(b, { key: KEY.verifier, ...AS_PUBLISHED });
  v.checked.records[0].chain = "not hex at all";
  assert.throws(() => checker.exhibitLines(v, { bundleFile: "x", bundleSha: "y", key: KEY.verifier, now: "z" }), /field chain/);
});
