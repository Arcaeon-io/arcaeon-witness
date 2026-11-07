// test/cosign.test.js: the outside witness step (lib/_cosign.js and the
// --cosign-config / --cosign-send flags of tools/publish_checkpoint.js)
// against a FAKE witness that behaves as the public witness protocol says:
// it checks the log's signature and the consistency proof from the size it
// holds, answers 409 with its size when "old" is wrong, 404 for a log it does
// not know, and signs a cosignature/v1 line. Nothing here talks to a real
// witness: every URL is a function in this file or 127.0.0.1.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

const lt = require("../lib/_logtree.js");
const cp = require("../lib/_checkpoint.js");
const cs = require("../lib/_cosign.js");

const TOOL = path.join(__dirname, "..", "tools", "publish_checkpoint.js");
const SPKI = Buffer.from("302a300506032b6570032100", "hex");

// ---- a fake witness ----

function witnessKey(name) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(SPKI.length);
  const id = cs.cosignKeyId(name, pub);
  return { name, privateKey, id, vkey: `${name}+${id.toString("hex")}+${Buffer.concat([Buffer.from([4]), pub]).toString("base64")}` };
}

function fakeWitness({ name = "witness.test.invalid", logVkey, knows = true, held = { size: 0, root: null } } = {}) {
  const key = witnessKey(name);
  const state = { size: held.size, root: held.root };
  const calls = [];
  function answer(body) {
    calls.push(body);
    if (!knows) return { status: 404, type: "text/plain", body: "unknown log\n" };
    const m = /^old (0|[1-9][0-9]*)\n((?:[A-Za-z0-9+/=]+\n)*)\n([\s\S]*)$/.exec(body);
    if (!m) return { status: 400, type: "text/plain", body: "bad request\n" };
    const old = Number(m[1]);
    const proof = m[2].split("\n").filter(Boolean).map((b) => Buffer.from(b, "base64"));
    const note = m[3];
    const v = cp.verifyCheckpointSignature(note, logVkey);
    if (!v.ok) return { status: 403, type: "text/plain", body: v.reason + "\n" };
    if (old !== state.size) return { status: 409, type: cs.SIZE_TYPE, body: `${state.size}\n` };
    if (old > 0) {
      const c = lt.verifyConsistency({ old_size: old, new_size: v.size, old_root: state.root, new_root: v.root, path: proof });
      if (!c.ok) return { status: 422, type: "text/plain", body: c.reason + "\n" };
    }
    state.size = v.size;
    state.root = v.root;
    const text = cp.parseCheckpoint(note).text;
    const t = 1794000000;
    const sig = crypto.sign(null, cs.cosignatureMessage(String(t), text), key.privateKey);
    const ts = Buffer.alloc(8);
    ts.writeBigUInt64BE(BigInt(t));
    const line = `\u2014 ${name} ${Buffer.concat([key.id, ts, sig]).toString("base64")}\n`;
    // An unrelated line under another key comes first: it must be passed over.
    const other = `\u2014 ${name} ${Buffer.concat([Buffer.from("deadbeef", "hex"), crypto.randomBytes(72)]).toString("base64")}\n`;
    return { status: 200, type: "text/plain", body: other + line };
  }
  return { key, state, calls, answer, entry: { name, url: "https://witness.test.invalid", vkey: key.vkey } };
}

function logOf(n) {
  const leaves = Array.from({ length: n }, (_, i) => crypto.createHash("sha256").update(`leaf ${i}`).digest());
  return lt.buildTree(leaves);
}

function signedAt(tree, size, logKey) {
  return cp.signCheckpoint(cp.formatCheckpoint({ origin: lt.LOG_ORIGIN, size, root: tree.rootAt(size) }), logKey.signer);
}

function witnessesFrom(entries) {
  const c = cs.loadWitnessConfig(JSON.stringify({ witnesses: entries }));
  assert.ok(c.ok, JSON.stringify(c));
  return c.witnesses;
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "cosign-"));

// ---- the library ----

test("cosigned: proof from the previous size, the line verifies, kept beside the checkpoint, checkpoint untouched", async () => {
  const logKey = cp.generateKey("arcaeon.io/witness-log/test");
  const tree = logOf(9);
  const w = fakeWitness({ logVkey: logKey.verifier, held: { size: 5, root: tree.rootAt(5) } });
  const note = signedAt(tree, 9, logKey);
  const dir = tmp();
  const txt = path.join(dir, "2026-11-07.txt");
  fs.writeFileSync(txt, note);
  const out = path.join(dir, "2026-11-07.cosignatures");
  const r = await cs.cosignCheckpoint({
    signedNote: note, witnesses: witnessesFrom([w.entry]), prevSize: 5,
    proofFrom: (old) => (old === 0 ? [] : tree.consistencyProof(old, 9)),
    post: async (url, body) => (assert.equal(url, "https://witness.test.invalid/add-checkpoint"), w.answer(body)),
    send: true, outFile: out, now: 1794000000,
  });
  assert.equal(r.ok, true);
  assert.equal(r.results[0].result, "cosigned", JSON.stringify(r.results[0]));
  assert.equal(w.calls.length, 1);
  const lines = fs.readFileSync(out, "utf8").split("\n").filter(Boolean);
  assert.equal(lines.length, 1);
  const chk = cs.checkAnswer(lines[0] + "\n", cp.parseCheckpoint(note).text, witnessesFrom([w.entry])[0], 1794000000);
  assert.equal(chk.ok, true);
  assert.equal(fs.readFileSync(txt, "utf8"), note);
});

test("409: the proof is rebuilt from the witness's own size and sent again", async () => {
  const logKey = cp.generateKey("arcaeon.io/witness-log/test");
  const tree = logOf(12);
  const w = fakeWitness({ logVkey: logKey.verifier, held: { size: 3, root: tree.rootAt(3) } });
  const r = await cs.cosignCheckpoint({
    signedNote: signedAt(tree, 12, logKey), witnesses: witnessesFrom([w.entry]), prevSize: 7,
    proofFrom: (old) => (old === 0 ? [] : tree.consistencyProof(old, 12)),
    post: async (_u, b) => w.answer(b), send: true, now: 1794000000,
  });
  assert.equal(r.results[0].result, "cosigned");
  assert.equal(r.results[0].old, 3);
  assert.equal(w.calls.length, 2);
});

test("a first contact from 0 sends an empty proof and is cosigned", async () => {
  const logKey = cp.generateKey("arcaeon.io/witness-log/test");
  const tree = logOf(4);
  const w = fakeWitness({ logVkey: logKey.verifier, held: { size: 0, root: null } });
  const r = await cs.cosignCheckpoint({
    signedNote: signedAt(tree, 4, logKey), witnesses: witnessesFrom([w.entry]), prevSize: 0,
    proofFrom: (old) => (old === 0 ? [] : tree.consistencyProof(old, 4)), post: async (_u, b) => w.answer(b), send: true, now: 1794000000,
  });
  assert.equal(r.results[0].result, "cosigned");
  assert.match(w.calls[0], /^old 0\n\n/);
});

test("refusals, an unlisted log, and an unreachable witness are results with a field, never thrown, and nothing is kept", async () => {
  const logKey = cp.generateKey("arcaeon.io/witness-log/test");
  const tree = logOf(6);
  const note = signedAt(tree, 6, logKey);
  const proofFrom = (old) => (old === 0 ? [] : tree.consistencyProof(old, 6));
  const dir = tmp();
  const out = path.join(dir, "x.cosignatures");
  const good = fakeWitness({ name: "good.test.invalid", logVkey: logKey.verifier, held: { size: 0, root: null } });
  const unlisted = fakeWitness({ name: "unlisted.test.invalid", logVkey: logKey.verifier, knows: false });
  const forged = fakeWitness({ name: "forged.test.invalid", logVkey: logKey.verifier, held: { size: 0, root: null } });
  const down = fakeWitness({ name: "down.test.invalid", logVkey: logKey.verifier });
  const wrongLog = fakeWitness({ name: "wronglog.test.invalid", logVkey: cp.generateKey("someone.else/log").verifier, held: { size: 0, root: null } });
  const entries = [good, unlisted, forged, down, wrongLog].map((w) => ({ ...w.entry, url: `https://${w.key.name}` }));
  const by = { "good.test.invalid": good, "unlisted.test.invalid": unlisted, "forged.test.invalid": forged, "wronglog.test.invalid": wrongLog };
  const post = async (url, body) => {
    const host = new URL(url).hostname;
    if (host === "down.test.invalid") throw new Error("connect ECONNREFUSED");
    const a = by[host].answer(body);
    if (host === "forged.test.invalid" && a.status === 200) {
      // flip one byte of the signature on the line under the configured key
      const lines = a.body.split("\n");
      const b = Buffer.from(lines[1].split(" ")[2], "base64");
      b[b.length - 1] ^= 1;
      lines[1] = `\u2014 forged.test.invalid ${b.toString("base64")}`;
      return { ...a, body: lines.join("\n") };
    }
    return a;
  };
  const r = await cs.cosignCheckpoint({ signedNote: note, witnesses: witnessesFrom(entries), proofFrom, post, send: true, outFile: out, now: 1794000000 });
  const got = Object.fromEntries(r.results.map((x) => [x.witness.split("+")[0], [x.result, x.field]]));
  assert.deepEqual(got, {
    "good.test.invalid": ["cosigned", null],
    "unlisted.test.invalid": ["not_listed", "origin"],
    "forged.test.invalid": ["refused", "cosignature"],
    "down.test.invalid": ["unreachable", "url"],
    "wronglog.test.invalid": ["refused", "signature"],
  });
  const kept = fs.readFileSync(out, "utf8").split("\n").filter(Boolean);
  assert.equal(kept.length, 1);
  assert.match(kept[0], /^\u2014 good\.test\.invalid /);
});

test("add only: a second run keeps the old line byte for byte and adds no duplicate for the same key", () => {
  const dir = tmp();
  const f = path.join(dir, "d.cosignatures");
  const a = `\u2014 a.test ${Buffer.concat([Buffer.from("01020304", "hex"), Buffer.alloc(72, 1)]).toString("base64")}`;
  const a2 = `\u2014 a.test ${Buffer.concat([Buffer.from("01020304", "hex"), Buffer.alloc(72, 2)]).toString("base64")}`;
  const b = `\u2014 b.test ${Buffer.concat([Buffer.from("05060708", "hex"), Buffer.alloc(72, 3)]).toString("base64")}`;
  assert.deepEqual(cs.appendCosignatures(f, [a]), [a]);
  assert.deepEqual(cs.appendCosignatures(f, [a2, b]), [b]);
  assert.equal(fs.readFileSync(f, "utf8"), `${a}\n${b}\n`);
});

test("dry run sends nothing; an unsigned checkpoint is not offered to any witness", async () => {
  const logKey = cp.generateKey("arcaeon.io/witness-log/test");
  const tree = logOf(3);
  const w = fakeWitness({ logVkey: logKey.verifier });
  let posts = 0;
  const post = async () => (posts++, { status: 500, type: "", body: "" });
  const proofFrom = (old) => (old === 0 ? [] : tree.consistencyProof(old, 3));
  const dry = await cs.cosignCheckpoint({ signedNote: signedAt(tree, 3, logKey), witnesses: witnessesFrom([w.entry]), proofFrom, post, send: false });
  assert.equal(dry.results[0].result, "would_send");
  const unsigned = await cs.cosignCheckpoint({ signedNote: cp.formatCheckpoint({ origin: lt.LOG_ORIGIN, size: 3, root: tree.root }), witnesses: witnessesFrom([w.entry]), proofFrom, post, send: true });
  assert.equal(unsigned.ok, false);
  assert.equal(unsigned.field, "checkpoint");
  assert.equal(posts, 0);
});

test("config: refused naming the field for a log key (0x01), a name that is not the vkey's, plain http to a public host", () => {
  const w = witnessKey("w.test");
  const logKey = cp.generateKey("w.test");
  assert.equal(cs.loadWitnessConfig(JSON.stringify({ witnesses: [{ name: "w.test", url: "https://w.test", vkey: logKey.verifier }] })).field, "witnesses[0].vkey");
  assert.equal(cs.loadWitnessConfig(JSON.stringify({ witnesses: [{ name: "other", url: "https://w.test", vkey: w.vkey }] })).field, "witnesses[0].name");
  assert.equal(cs.loadWitnessConfig(JSON.stringify({ witnesses: [{ name: "w.test", url: "http://w.test", vkey: w.vkey }] })).field, "witnesses[0].url");
  const shipped = cs.loadWitnessConfig(fs.readFileSync(path.join(__dirname, "..", "config", "outside_witnesses.json"), "utf8"));
  assert.equal(shipped.ok, true, JSON.stringify(shipped));
});

// ---- the daily job: publish_checkpoint.js end to end against a local fake witness ----

function git(repo, args) {
  const r = spawnSync("git", ["-C", repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout;
}
function repoWith(n) {
  const repo = tmp();
  git(repo, ["init", "-q", "-b", "main"]);
  for (let i = 1; i <= n; i++) {
    const p = path.join(repo, "pins", "z", `${String(i).padStart(8, "0")}.json`);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, `{"namespace":"z","rows":${i},"chain":"c${i}","seq":${i}}\n`);
    git(repo, ["add", "-A"]);
    git(repo, ["commit", "-q", "-m", `pin ${i}`]);
  }
  return repo;
}
function runTool(args, env) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [TOOL, ...args], { env: { ...process.env, ...env } });
    let stdout = "";
    let stderr = "";
    c.stdout.on("data", (d) => (stdout += d));
    c.stderr.on("data", (d) => (stderr += d));
    c.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

test("daily job: --write --cosign-send writes the checkpoint, then a verified line in <date>.cosignatures; a down witness is logged, exit stays 0; dry run posts nothing", async () => {
  const logKey = cp.generateKey("arcaeon.io/witness-log/test");
  const w = fakeWitness({ name: "local.test.invalid", logVkey: logKey.verifier, held: { size: 0, root: null } });
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      const a = req.url === "/add-checkpoint" ? w.answer(body) : { status: 404, type: "text/plain", body: "no\n" };
      res.writeHead(a.status, { "content-type": a.type });
      res.end(a.body);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  try {
    const dead = witnessKey("dead.test.invalid");
    const cfg = path.join(tmp(), "witnesses.json");
    fs.writeFileSync(cfg, JSON.stringify({ witnesses: [
      { name: "local.test.invalid", url: `http://127.0.0.1:${port}`, vkey: w.key.vkey },
      { name: "dead.test.invalid", url: "http://127.0.0.1:1", vkey: dead.vkey },
    ] }));
    const repo = repoWith(5);
    const env = { TEST_LOG_KEY: logKey.signer };

    const dryOut = tmp();
    const dry = await runTool(["--clone", repo, "--out", dryOut, "--date", "2026-11-07", "--key-env", "TEST_LOG_KEY", "--cosign-config", cfg, "--json"], env);
    assert.equal(dry.status, 0, dry.stderr);
    assert.deepEqual(JSON.parse(dry.stdout).cosign.results.map((r) => r.result), ["would_send", "would_send"]);
    assert.equal(w.calls.length, 0);
    assert.equal(fs.readdirSync(dryOut).length, 0);

    const out = tmp();
    const r = await runTool(["--clone", repo, "--out", out, "--date", "2026-11-07", "--key-env", "TEST_LOG_KEY", "--write", "--cosign-config", cfg, "--cosign-send", "--json"], env);
    assert.equal(r.status, 0, r.stderr);
    const s = JSON.parse(r.stdout);
    assert.deepEqual(s.cosign.results.map((x) => x.result), ["cosigned", "unreachable"]);
    assert.match(r.stderr, /COSIGN: dead\.test\.invalid\+[0-9a-f]{8} unreachable: field url/);
    const note = fs.readFileSync(path.join(out, "checkpoints", "2026-11-07.txt"), "utf8");
    assert.equal(cp.verifyCheckpointSignature(note, logKey.verifier).ok, true);
    const kept = fs.readFileSync(path.join(out, "checkpoints", "2026-11-07.cosignatures"), "utf8");
    assert.equal(kept.split("\n").filter(Boolean).length, 1);
    assert.equal(cs.checkAnswer(kept, cp.parseCheckpoint(note).text, witnessesFrom([{ name: "local.test.invalid", url: "https://x.invalid", vkey: w.key.vkey }])[0], 1794000000).ok, true);

    assert.equal((await runTool(["--clone", repo, "--out", tmp(), "--cosign-config", cfg, "--cosign-send"], env)).status, 1);
  } finally {
    server.close();
  }
});

test("a line with the configured key id but another name is passed over, never kept under the wrong name", async () => {
  const logKey = cp.generateKey("arcaeon.io/witness-log/test");
  const tree = logOf(2);
  const w = fakeWitness({ logVkey: logKey.verifier, held: { size: 0, root: null } });
  const note = signedAt(tree, 2, logKey);
  const a = w.answer(`old 0\n\n${note}`);
  const renamed = a.body.split("\n").map((l) => l.replace(/^\u2014 witness\.test\.invalid /, "\u2014 impostor.test.invalid ")).join("\n");
  const c = cs.checkAnswer(renamed, cp.parseCheckpoint(note).text, witnessesFrom([w.entry])[0], 1794000000);
  assert.equal(c.ok, false);
  assert.equal(c.field, "cosignature");
});
