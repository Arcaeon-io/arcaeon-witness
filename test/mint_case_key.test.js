// test/mint_case_key.test.js — tools/mint_case_key.js (case protocol item
// 3a): the private half goes to --out and NOWHERE else (not stdout, not
// stderr), stdout is exactly the public document entry, that entry passes
// lib/_case_seal.js checkKeyDocument inside a copy of the committed
// public/.well-known/arcaeon/case-signing-keys.json, loadCaseSigner given the file
// resolves the same key_id and verifier (key_unpublished against the
// committed document, which does not list it; loaded once the copy with the
// entry is handed to it), and an existing file is refused and left
// byte-identical.
// BREAK ARMS: an entry whose key_id or verifier does not match the key is
// refused by the same checkKeyDocument; the entry listed revoked, or another
// key's entry, does not load the key; another key resolves another key_id; a
// signature by another key does not verify under the printed verifier.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const cp = require("../lib/_checkpoint.js");
const S = require("../lib/_case_seal.js");

const TOOL = path.join(__dirname, "..", "tools", "mint_case_key.js");
const DOC = path.join(__dirname, "..", ...S.CASE_KEYS_FILE.split("/"));
// The child never sees a real signing key from the environment it runs in.
const CLEAN_ENV = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/SIGNER_KEY$/.test(k)));
const run = (args) => spawnSync(process.execPath, [TOOL, ...args], { encoding: "utf8", env: CLEAN_ENV });
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "mint-case-key-"));
const committedDoc = () => JSON.parse(fs.readFileSync(DOC, "utf8"));
// loadCaseSigner signs only when the case key can be shown different from
// the log key and the reconcile key, so it is given two throwaway ones.
const envFor = (signer) => ({
  [S.CASE_SIGNER_ENV]: signer,
  WITNESS_LOG_SIGNER_KEY: cp.generateKey("test.example/log").signer,
  WITNESS_RECONCILE_SIGNER_KEY: cp.generateKey("test.example/reconcile").signer,
});
// Every form the private half could leak in.
function privateForms(signer) {
  const k = cp.parseSignerKey(signer);
  const seedB64 = signer.split("+").slice(4).join("+");
  const seed = Buffer.from(seedB64, "base64").subarray(1);
  const pem = k.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  return ["PRIVATE", seedB64, seed.toString("base64"), seed.toString("hex"), pem.split("\n")[1]];
}

test("mints to a temp path: stdout is only the entry, which passes checkKeyDocument in a copy of the committed document", () => {
  const dir = tmp();
  const out = path.join(dir, "case.signer.key");
  const r = run(["--out", out, "--name", "test.example/case-k1", "--note", "the test's case key"]);
  assert.equal(r.status, 0, r.stderr);
  const entry = JSON.parse(r.stdout);
  assert.deepEqual(Object.keys(entry), ["key_id", "verifier", "since", "note", "status"]);
  assert.equal(r.stdout, JSON.stringify(entry, null, 2) + "\n", "nothing but the entry on stdout");
  assert.equal(entry.status, "active");
  assert.equal(entry.note, "the test's case key");
  assert.equal(entry.since, new Date().toISOString().slice(0, 10));
  assert.match(entry.key_id, /^test\.example\/case-k1\+[0-9a-f]{8}$/);

  const doc = committedDoc();
  const withKey = { ...doc, keys: [...doc.keys, entry] };
  const checked = S.checkKeyDocument(withKey);
  assert.equal(checked.ok, true, JSON.stringify(checked));
  assert.deepEqual(S.publishedEntry(withKey, entry.key_id), entry);

  // The file is the private half in the signer-string shape, mode 0600, no newline.
  const signer = fs.readFileSync(out, "utf8");
  assert.match(signer, /^PRIVATE\+KEY\+test\.example\/case-k1\+[0-9a-f]{8}\+/);
  assert.equal(signer.includes("\n"), false, "no trailing newline: the file IS the env value");
  if (process.platform !== "win32") assert.equal(fs.statSync(out).mode & 0o777, 0o600);

  // BREAK ARMS: the same checker refuses an entry that does not match its key.
  const other = cp.generateKey("test.example/other");
  assert.equal(S.checkKeyDocument({ ...doc, keys: [{ ...entry, key_id: "test.example/case-k1+00000000" }] }).reason, "key_id_mismatch");
  assert.equal(S.checkKeyDocument({ ...doc, keys: [{ ...entry, verifier: other.verifier }] }).reason, "key_id_mismatch");
  assert.equal(S.checkKeyDocument({ ...doc, keys: [entry, entry] }).reason, "duplicate_key_id");
});

test("loadCaseSigner given the minted private string resolves the same key_id and verifier, and its signatures verify under the printed verifier", () => {
  const dir = tmp();
  const out = path.join(dir, "case.signer.key");
  const r = run(["--out", out]);
  assert.equal(r.status, 0, r.stderr);
  const entry = JSON.parse(r.stdout);
  assert.match(entry.key_id, /^arcaeon\.io\/case-signing\/\d{4}-\d{2}-\d{2}\+[0-9a-f]{8}$/, "the default name");
  assert.ok(entry.note.trim(), "a default note");
  const env = envFor(fs.readFileSync(out, "utf8"));

  // Against the committed document the key is not listed yet: key_unpublished,
  // with the same public half (PUBLICATION FAILS CLOSED).
  const pending = S.loadCaseSigner(env);
  assert.equal(pending.ok, false);
  assert.equal(pending.code, "key_unpublished");
  assert.equal(pending.keyId, entry.key_id);
  assert.equal(pending.verifier, entry.verifier);
  assert.equal(Object.prototype.hasOwnProperty.call(pending, "privateKey"), false);

  // With the entry inserted into a copy of the committed document, it loads.
  const doc = committedDoc();
  const withKey = { ...doc, keys: [...doc.keys, entry] };
  const signer = S.loadCaseSigner(env, { keyDocument: withKey });
  assert.equal(signer.ok, true, JSON.stringify(signer));
  assert.equal(signer.keyId, entry.key_id);
  assert.equal(signer.verifier, entry.verifier);
  assert.deepEqual(signer.entry, entry);
  assert.deepEqual(S.keyDocumentEntry(signer, { since: entry.since, note: entry.note }), entry);

  const msg = Buffer.from("a sealed case's signed bytes stand in here");
  const sig = crypto.sign(null, msg, signer.privateKey);
  const vk = cp.parseVerifierKey(entry.verifier);
  assert.equal(vk.ok, true);
  assert.equal(crypto.verify(null, msg, vk.publicKey, sig), true);

  // BREAK ARMS: listed revoked, or only another key listed, the key is not
  // used; another key is another key id, and its signature does not verify here.
  assert.equal(S.loadCaseSigner(env, { keyDocument: { ...doc, keys: [{ ...entry, status: "revoked" }] } }).code, "key_unpublished");
  const otherKey = cp.generateKey("test.example/other");
  const otherEntry = S.keyDocumentEntry({ keyId: otherKey.verifier.split("+").slice(0, 2).join("+"), verifier: otherKey.verifier }, { since: entry.since, note: "other" });
  assert.equal(S.loadCaseSigner(env, { keyDocument: { ...doc, keys: [otherEntry] } }).code, "key_unpublished");
  const other = S.loadCaseSigner(envFor(otherKey.signer), { keyDocument: { ...doc, keys: [otherEntry] } });
  assert.equal(other.ok, true);
  assert.notEqual(other.keyId, entry.key_id);
  assert.equal(crypto.verify(null, msg, vk.publicKey, crypto.sign(null, msg, other.privateKey)), false);
});

test("stdout and stderr carry no private material, in any form", () => {
  const dir = tmp();
  for (const args of [["--name", "test.example/leak-k1"], []]) {
    const out = path.join(dir, `${crypto.randomBytes(4).toString("hex")}.signer.key`);
    const r = run(["--out", out, ...args]);
    assert.equal(r.status, 0, r.stderr);
    const signer = fs.readFileSync(out, "utf8");
    for (const [name, stream] of [["stdout", r.stdout], ["stderr", r.stderr]]) {
      assert.equal(stream.includes(signer), false, `${name} holds the signer string`);
      for (const form of privateForms(signer)) assert.equal(stream.includes(form), false, `${name} holds ${form.slice(0, 12)}...`);
    }
    // Everything on stdout is public: the entry, and only the entry.
    const entry = JSON.parse(r.stdout);
    assert.equal(r.stdout.replace(entry.verifier, "").replace(entry.key_id, "").includes("+"), false, "no other key string on stdout");
  }
});

test("a self-check that fails (a committed key document that does not read) refuses: exit 2, the file removed, nothing on stdout", () => {
  // A scratch copy of the tool, lib/ and the document, the document with a
  // top-level field checkKeyDocument refuses.
  const root = tmp();
  const repo = path.join(__dirname, "..");
  fs.mkdirSync(path.join(root, "tools"));
  fs.copyFileSync(TOOL, path.join(root, "tools", "mint_case_key.js"));
  fs.cpSync(path.join(repo, "lib"), path.join(root, "lib"), { recursive: true });
  const docPath = path.join(root, ...S.CASE_KEYS_FILE.split("/"));
  fs.mkdirSync(path.dirname(docPath), { recursive: true });
  fs.writeFileSync(docPath, JSON.stringify({ ...committedDoc(), private_note: "a field nobody checks" }, null, 2));
  const out = path.join(root, "case.signer.key");
  const r = spawnSync(process.execPath, [path.join(root, "tools", "mint_case_key.js"), "--out", out], { encoding: "utf8", env: CLEAN_ENV });
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /REFUSED: self-check failed: the committed key document does not read \(unknown_field at private_note\); file removed/);
  assert.equal(r.stdout, "");
  assert.equal(fs.existsSync(out), false, "the private half is removed");
});

test("refuses: an existing file (exit nonzero, left byte-identical, nothing on stdout), a path .gitignore would not cover, a bad name or note, no --out", () => {
  const dir = tmp();
  const out = path.join(dir, "case.signer.key");
  const first = run(["--out", out]);
  assert.equal(first.status, 0, first.stderr);
  const before = fs.readFileSync(out);
  const again = run(["--out", out]);
  assert.equal(again.status, 2);
  assert.match(again.stderr, /already exists/);
  assert.equal(again.stdout, "", "a refused mint prints no entry");
  assert.ok(fs.readFileSync(out).equals(before), "the existing key is untouched");

  const plain = path.join(dir, "case.key");
  const r = run(["--out", plain]);
  assert.equal(r.status, 2);
  assert.equal(r.stdout, "");
  assert.equal(fs.existsSync(plain), false);

  assert.equal(run(["--out", path.join(dir, "n.signer.key"), "--name", "has space"]).status, 1);
  assert.equal(run(["--out", path.join(dir, "p.signer.key"), "--name", "a+b"]).status, 1);
  assert.equal(run(["--out", path.join(dir, "e.signer.key"), "--note", "  "]).status, 1);
  assert.equal(fs.existsSync(path.join(dir, "e.signer.key")), false);
  assert.equal(run([]).status, 1);
  assert.equal(run(["--out"]).status, 1);
});

// unit R-WIDE (C12): on Windows a key file whose access could not be
// restricted is removed, and the tool exits 2 printing no entry
test("R-WIDE C12: when the Windows ACL step fails (icacls refuses, or USERNAME is unset) the tool exits 2, removes the key file and prints no entry", (t) => {
  const tool = require("../tools/mint_case_key.js");
  const dir = tmp();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const err = [];
  const out = [];
  t.mock.method(process.stderr, "write", (s) => { err.push(String(s)); return true; });
  t.mock.method(process.stdout, "write", (s) => { out.push(String(s)); return true; });
  const cases = [
    ["icacls refuses", { platform: "win32", env: { USERNAME: "someone" }, run: () => ({ status: 5, stderr: "Access is denied." }) }, /Access is denied\./],
    ["USERNAME unset", { platform: "win32", env: {}, run: () => assert.fail("icacls is not run without a user") }, /USERNAME unset/],
  ];
  try {
    for (const [what, opts, why] of cases) {
      const file = path.join(dir, `${what.replace(/\W+/g, "-")}${tool.REQUIRED_SUFFIX}`);
      err.length = 0;
      out.length = 0;
      const code = tool.main(["--out", file], opts);
      assert.equal(code, 2, `${what}: ${err.join("")}`);
      assert.equal(fs.existsSync(file), false, `${what}: the file is removed`);
      assert.match(err.join(""), /REFUSED: the key file's access could not be restricted on Windows \(/, what);
      assert.match(err.join(""), why, what);
      assert.equal(out.join(""), "", `${what}: no entry printed`);
    }
    // control: icacls succeeds, the file stays and the entry is printed
    const file = path.join(dir, `granted${tool.REQUIRED_SUFFIX}`);
    out.length = 0;
    assert.equal(tool.main(["--out", file], { platform: "win32", env: { USERNAME: "someone" }, run: () => ({ status: 0 }) }), 0);
    assert.equal(fs.existsSync(file), true);
    assert.ok(out.join("").includes("\"key_id\""));
  } finally {
    process.stderr.write.mock.restore();
    process.stdout.write.mock.restore();
  }
});
