// test/restore_proof.test.js — tools/restore_proof.js: restore a backup of the
// pins repo onto a SCRATCH copy, pin once, and show the pin lands at the next
// sequence number and that the whole chain reads back through the public
// check (api/verify.js).
//
// The backups here are made by the REAL api/pin.js against the mock store and
// dumped to a directory exactly as files sit in a clone of the pins repo, so
// the tool reads what a real backup holds, not a hand-written imitation.
// The tool itself runs as a child process (the way a person runs it), with
// its --json summary parsed.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
// Each fixture backup is made with its own test-only key (fixtureKey below):
// api/pin.js's per-key hourly limiter has no reset hook, and one shared key
// would run out part way through this file. The built-in "internal" plan
// counts the pins without the free tier's 10 a month.
process.env.WITNESS_KEYS = "";
process.env.WITNESS_PLANS = "{}";
delete process.env.WITNESS_CADENCE;

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const pinHandler = require("../api/pin.js");

const TOOL = path.join(__dirname, "..", "tools", "restore_proof.js");
const PIN_REPO = process.env.GITHUB_PIN_REPO;

function tmpDir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `restore-proof-${tag}-`));
}

// Pin `heads` ([[rows, chain], ...]) per namespace through the real handler,
// then write the pin repo's files under `dir` as a clone would hold them.
let fixtureCount = 0;
function fixtureKey() {
  fixtureCount += 1;
  const key = `backupkey${fixtureCount}`;
  process.env.WITNESS_KEYS = [process.env.WITNESS_KEYS, `${key}:demo-`].filter(Boolean).join(",");
  const plans = JSON.parse(process.env.WITNESS_PLANS);
  plans[crypto.createHash("sha256").update(key).digest("hex")] = { plan: "internal" };
  process.env.WITNESS_PLANS = JSON.stringify(plans);
  return key;
}

async function makeBackup(byNamespace) {
  const key = fixtureKey();
  const gh = new MockGitHubStore();
  const restore = install(gh);
  const realSleep = store._putRetry.sleep;
  store._putRetry.sleep = async () => {};
  try {
    for (const [namespace, heads] of Object.entries(byNamespace)) {
      for (const [rows, chain] of heads) {
        const req = makeReq({
          method: "POST",
          headers: { authorization: `Bearer ${key}` },
          body: { namespace, rows, chain },
        });
        const res = makeRes();
        await pinHandler(req, res);
        assert.ok([200, 201].includes(res._status), `fixture pin failed: ${JSON.stringify(res._body)}`);
      }
    }
  } finally {
    store._putRetry.sleep = realSleep;
    restore();
  }
  const dir = tmpDir("backup");
  for (const [p, rec] of gh._repoMap(PIN_REPO)) {
    const full = path.join(dir, ...p.split("/"));
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, rec.content);
  }
  // A clone carries .git; the tool must skip it rather than read it as records.
  fs.mkdirSync(path.join(dir, ".git"), { recursive: true });
  fs.writeFileSync(path.join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
  return dir;
}

function hashTree(dir) {
  const h = crypto.createHash("sha256");
  const walk = (d) => {
    for (const name of fs.readdirSync(d).sort()) {
      const full = path.join(d, name);
      if (fs.statSync(full).isDirectory()) walk(full);
      else h.update(path.relative(dir, full)).update("\0").update(fs.readFileSync(full));
    }
  };
  walk(dir);
  return h.digest("hex");
}

function run(args, env = {}) {
  // A clean environment on purpose: the tool must not need (or read) any of
  // the witness's real settings, and must refuse the network on its own.
  const r = spawnSync(process.execPath, [TOOL, ...args, "--json"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, ...env },
  });
  let summary = null;
  try { summary = JSON.parse(r.stdout); } catch (_) { /* reported below */ }
  return { status: r.status, summary, stdout: r.stdout, stderr: r.stderr };
}

const THREE = [[10, "aa".repeat(16)], [20, "bb".repeat(16)], [35, "cc".repeat(16)]];

test("RESTORE: the next pin on a restored copy lands at seq N+1 and the whole chain reads back", async () => {
  const backup = await makeBackup({ "demo-restore": THREE });
  const r = run(["--backup", backup]);
  assert.equal(r.status, 0, r.stderr || r.stdout);
  const s = r.summary;
  assert.equal(s.verdict, "PROVEN");
  assert.equal(s.namespaces.length, 1);
  const ns = s.namespaces[0];
  assert.equal(ns.namespace, "demo-restore");
  assert.equal(ns.restored_seq, 3, "the backup's head is seq 3");
  assert.equal(ns.new_pin.seq, 4, "the next pin lands at seq 4");
  assert.equal(ns.new_pin.status, 201);
  assert.equal(ns.chain_after.length, 4, "every record 1..4 is read back");
  assert.deepEqual(ns.chain_after.map((c) => c.seq), [1, 2, 3, 4]);
  for (const c of ns.chain_after) {
    assert.equal(c.verify.witnessed, true, `seq ${c.seq} reads back as witnessed through api/verify.js`);
  }
});

test("RESTORE: every namespace in the backup is proven on its own sequence", async () => {
  const backup = await makeBackup({
    "demo-one": THREE,
    "demo-two": [[5, "dd".repeat(16)]],
  });
  const r = run(["--backup", backup]);
  assert.equal(r.status, 0, r.stderr || r.stdout);
  const byNs = Object.fromEntries(r.summary.namespaces.map((n) => [n.namespace, n]));
  assert.equal(byNs["demo-one"].new_pin.seq, 4);
  assert.equal(byNs["demo-two"].new_pin.seq, 2);
});

test("RESTORE: --namespace limits the proof to one namespace", async () => {
  const backup = await makeBackup({ "demo-one": THREE, "demo-two": [[5, "dd".repeat(16)]] });
  const r = run(["--backup", backup, "--namespace", "demo-two"]);
  assert.equal(r.status, 0, r.stderr || r.stdout);
  assert.deepEqual(r.summary.namespaces.map((n) => n.namespace), ["demo-two"]);
});

test("SCRATCH: the backup directory is byte-for-byte unchanged, and the tool can run again with the same answer", async () => {
  const backup = await makeBackup({ "demo-restore": THREE });
  const before = hashTree(backup);
  const first = run(["--backup", backup]);
  const second = run(["--backup", backup]);
  assert.equal(hashTree(backup), before, "the backup is never written");
  assert.equal(first.status, 0);
  assert.equal(second.status, 0);
  assert.equal(second.summary.namespaces[0].new_pin.seq, 4, "a second run restores afresh and lands at 4 again");
});

test("SCRATCH: --out writes the restored copy plus the new pin, outside the backup", async () => {
  const backup = await makeBackup({ "demo-restore": THREE });
  const out = path.join(tmpDir("out"), "scratch");
  const r = run(["--backup", backup, "--out", out]);
  assert.equal(r.status, 0, r.stderr || r.stdout);
  const rec = JSON.parse(fs.readFileSync(path.join(out, "pins", "demo-restore", "00000004.json"), "utf8"));
  assert.equal(rec.seq, 4);
  const latest = JSON.parse(fs.readFileSync(path.join(out, "pins", "demo-restore", "latest.json"), "utf8"));
  assert.equal(latest.seq, 4);
  assert.ok(!fs.existsSync(path.join(backup, "pins", "demo-restore", "00000004.json")));
});

test("SCRATCH: --out inside the backup is refused before anything is written", async () => {
  const backup = await makeBackup({ "demo-restore": THREE });
  const before = hashTree(backup);
  const r = run(["--backup", backup, "--out", path.join(backup, "scratch")]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /inside the backup/);
  assert.equal(hashTree(backup), before);
});

test("NETWORK: the tool reaches nothing outside the scratch copy, even with live-looking settings in its environment", async () => {
  const backup = await makeBackup({ "demo-restore": THREE });
  const r = run(["--backup", backup], {
    GITHUB_PIN_REPO: "dan8433-user/arcaeon-witness-pins",
    GITHUB_PIN_TOKEN: "ghp_should_never_be_sent",
    WITNESS_KEYS: "realkey:demo-",
    WITNESS_BATCH_SHADOW: "on",
  });
  assert.equal(r.status, 0, r.stderr || r.stdout);
  assert.equal(r.summary.network_requests_refused, 0, "nothing even tried to leave");
  assert.equal(r.summary.scratch_repo.startsWith("scratch/"), true);
  assert.ok(!r.stdout.includes("ghp_should_never_be_sent"));
});

test("BOUND: records older than api/verify.js's 50-record scan are read and checked here, and listed as beyond its bound", async () => {
  const heads = [];
  for (let i = 1; i <= 52; i++) heads.push([i * 10, crypto.createHash("sha256").update(`h${i}`).digest("hex").slice(0, 32)]);
  const backup = await makeBackup({ "demo-long": heads });
  const r = run(["--backup", backup]);
  assert.equal(r.status, 0, r.stderr || r.stdout);
  const ns = r.summary.namespaces[0];
  assert.equal(ns.new_pin.seq, 53);
  assert.equal(ns.chain_after.length, 53, "every record is still read");
  assert.equal(r.summary.verify_scan_bound, 50);
  assert.equal(ns.records_beyond_verify_bound, 3, "seq 1..3 sit 50 or more records behind the head (53)");
  assert.deepEqual(ns.chain_after.filter((c) => c.beyond_verify_bound).map((c) => c.seq), [1, 2, 3]);
  for (const c of ns.chain_after.filter((x) => !x.beyond_verify_bound)) assert.equal(c.verify.witnessed, true);
});

// ---- a broken backup is named, never proven ----

test("BROKEN: a record missing from the middle of the chain is named and nothing is proven", async () => {
  const backup = await makeBackup({ "demo-restore": THREE });
  fs.rmSync(path.join(backup, "pins", "demo-restore", "00000002.json"));
  const r = run(["--backup", backup]);
  assert.equal(r.status, 2);
  assert.equal(r.summary.verdict, "FAILED");
  const ns = r.summary.namespaces[0];
  assert.equal(ns.verdict, "FAILED");
  assert.match(ns.problems.join("\n"), /seq 2 .*missing/);
  assert.equal(ns.new_pin, null, "no pin is attempted on a chain that is not whole");
});

test("BROKEN: a latest.json that disagrees with the newest record is named", async () => {
  const backup = await makeBackup({ "demo-restore": THREE });
  const p = path.join(backup, "pins", "demo-restore", "latest.json");
  const latest = JSON.parse(fs.readFileSync(p, "utf8"));
  latest.seq = 2;
  fs.writeFileSync(p, JSON.stringify(latest, null, 2) + "\n");
  const r = run(["--backup", backup]);
  assert.equal(r.status, 2);
  assert.match(r.summary.namespaces[0].problems.join("\n"), /latest\.json/);
});

test("BROKEN: rows going backward inside the chain is named", async () => {
  const backup = await makeBackup({ "demo-restore": THREE });
  const p = path.join(backup, "pins", "demo-restore", "00000002.json");
  const rec = JSON.parse(fs.readFileSync(p, "utf8"));
  rec.rows = 5; // below seq 1's 10
  fs.writeFileSync(p, JSON.stringify(rec, null, 2) + "\n");
  const r = run(["--backup", backup]);
  assert.equal(r.status, 2);
  assert.match(r.summary.namespaces[0].problems.join("\n"), /rows .*backward/);
});

test("BROKEN: a record whose seq field disagrees with its file name is named", async () => {
  const backup = await makeBackup({ "demo-restore": THREE });
  const p = path.join(backup, "pins", "demo-restore", "00000003.json");
  const rec = JSON.parse(fs.readFileSync(p, "utf8"));
  rec.seq = 9;
  fs.writeFileSync(p, JSON.stringify(rec, null, 2) + "\n");
  const r = run(["--backup", backup]);
  assert.equal(r.status, 2);
  assert.match(r.summary.namespaces[0].problems.join("\n"), /00000003\.json.*seq 9/);
});

test("BROKEN: a record that names another namespace is named", async () => {
  const backup = await makeBackup({ "demo-restore": THREE });
  const p = path.join(backup, "pins", "demo-restore", "00000002.json");
  const rec = JSON.parse(fs.readFileSync(p, "utf8"));
  rec.namespace = "demo-elsewhere";
  fs.writeFileSync(p, JSON.stringify(rec, null, 2) + "\n");
  const r = run(["--backup", backup]);
  assert.equal(r.status, 2);
  assert.match(r.summary.namespaces[0].problems.join("\n"), /00000002\.json says namespace "demo-elsewhere"/);
  assert.equal(r.summary.namespaces[0].new_pin, null);
});

test("BROKEN: a record that is not JSON is named, not skipped", async () => {
  const backup = await makeBackup({ "demo-restore": THREE });
  fs.writeFileSync(path.join(backup, "pins", "demo-restore", "00000002.json"), "{not json");
  const r = run(["--backup", backup]);
  assert.equal(r.status, 2);
  assert.match(r.summary.namespaces[0].problems.join("\n"), /00000002\.json.*not JSON/);
});

test("USAGE: a missing backup, a backup with no pins, and an unknown namespace are each a clear refusal", async () => {
  const missing = run(["--backup", path.join(os.tmpdir(), "no-such-backup-dir-xyz")]);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /not a directory/);

  const empty = tmpDir("empty");
  const none = run(["--backup", empty]);
  assert.equal(none.status, 1);
  assert.match(none.stderr, /no pins\//);

  const backup = await makeBackup({ "demo-restore": THREE });
  const unknown = run(["--backup", backup, "--namespace", "demo-nope"]);
  assert.equal(unknown.status, 1);
  assert.match(unknown.stderr, /demo-nope/);

  const noArgs = run([]);
  assert.equal(noArgs.status, 1);
});
