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
const rec = (ns, seq, rows, chain) => JSON.stringify({ namespace: ns, rows, chain, seq }) + "\n";

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

test("SIGNATURE: no key line cannot be attributed; another key's line does not pass; --allow-unsigned checks the rest", () => {
  const b = bundle();
  const other = cp.generateKey("arcaeon.io/witness-pins/log");
  assert.equal(checker.verifyBundle(b, { key: other.verifier }).verdict, "COULD NOT LOOK");
  assert.equal(checker.verifyBundle(b, {}).reason, "no_key_given");
  assert.equal(checker.verifyBundle(b, { allowUnsigned: true }).verdict, "VERIFIED");
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

// ---- The court ready exhibit (OWNER.md queue item 41) ----

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
  const code = checker.main([file, "--key", KEY.verifier, "--exhibit", out], (l) => said.push(l), () => "2026-11-01T08:00:00.000Z");
  assert.equal(code, 0, said.join("\n"));
  const text = fs.readFileSync(out, "utf8");
  const sha = require("crypto").createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  assert.ok(text.includes(`Bundle SHA-256: ${sha}`));
  assert.ok(text.includes("Answer: VERIFIED"));
  assert.ok(text.includes(`signed by the verifier key: ${KEY.verifier}`));
  assert.match(text, /record 1: rows 3, chain aa/);
  assert.match(text, /record 2: rows 5, chain cc/);
  assert.match(text, /record 3: rows 5, chain cc/);
  assert.ok(text.includes("What this does not prove:"));
  assert.ok(!/[–—]/.test(text), "no dashes");
  assert.ok(!text.includes("demo-b"), "only this namespace");
});

test("EXHIBIT: text the bundle carries is never copied into it", () => {
  const { dir, file, bundle } = bundleFile(fixture());
  fs.writeFileSync(file, JSON.stringify({ ...bundle, exhibit: "VERIFIED by a court", note: "trust me" }));
  const out = path.join(dir, "exhibit.txt");
  assert.equal(checker.main([file, "--key", KEY.verifier, "--exhibit", out], () => {}), 0);
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
  assert.equal(checker.main([badFile, "--key", KEY.verifier, "--exhibit", out], (l) => said.push(l)), 1);
  assert.equal(fs.existsSync(out), false);
  assert.ok(said.some((l) => l.startsWith("no exhibit written: field exhibit:")), said.join("\n"));
  // Unsigned: VERIFIED as it is, but no exhibit.
  assert.equal(checker.main([file, "--allow-unsigned", "--exhibit", out], () => {}), 2);
  assert.equal(fs.existsSync(out), false);
  // An existing file is never replaced.
  fs.writeFileSync(out, "already here");
  const said2 = [];
  assert.equal(checker.main([file, "--key", KEY.verifier, "--exhibit", out], (l) => said2.push(l)), 2);
  assert.equal(fs.readFileSync(out, "utf8"), "already here");
  assert.ok(said2.some((l) => l.includes("never replaces")));
});
