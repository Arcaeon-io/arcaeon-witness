#!/usr/bin/env node
// tools/restore_proof.js — restore a backup of the public pins repo onto a
// SCRATCH copy and prove, on that copy, that the witness would carry on where
// the backup left off:
//
//   1. the chain in the backup is whole: for each namespace, every numbered
//      record 1..N is present, is JSON, says its own seq and namespace, and
//      rows never go backward; latest.json names the newest record (seq N,
//      same rows and chain);
//   2. the next pin, made through the REAL api/pin.js handler with a
//      throwaway key, lands at seq N+1 (and latest.json moves to N+1);
//   3. the whole chain 1..N+1 reads back: the tool reads every record, and
//      asks the public check (api/verify.js, the same handler behind
//      GET /api/verify) about every record's (rows, chain).
//
// WHAT IT NEVER DOES. It never writes into the backup, never reaches the
// network, and never reads a real key or token. Before any handler is
// loaded it deletes every GITHUB_* and WITNESS_* setting from its own
// environment and sets scratch values (repo names under scratch/, a token
// that is not one, a random key per namespace that exists only in this
// process). Every fetch is answered by the in-memory scratch store; a fetch
// to anything else is refused and counted (network_requests_refused). With
// --out it writes a copy of the backup plus the new pin's files into a
// directory you name, which must not be inside the backup.
//
// WHAT A BACKUP IS. A directory holding the pins repo's files at their repo
// paths: a `git clone` of dan8433-user/arcaeon-witness-pins (its .git is
// skipped), or an unpacked archive of one. Files are read as they sit on
// disk. A clone checked out with core.autocrlf rewrites line endings; that
// does not change what this tool checks (it parses JSON), but it does change
// file hashes, so use a clean clone for anything that hashes bytes
// (tools/publish_checkpoint.js reads git objects for that reason).
//
// WHAT IT DOES NOT PROVE. That the backup is the same as the live repo (compare
// a checkpoint for that: tools/follow.js), that any pin is true, or anything
// about records older than api/verify.js's backward scan reaches
// (MAX_HISTORY_SCAN, 50 records behind the head): those records are still read
// and checked by this tool, and are listed as beyond the public check's bound
// rather than counted as checked by it.
//
// USAGE
//   node tools/restore_proof.js --backup <dir> [--namespace <ns>] [--out <dir>] [--json]
//
// EXIT CODES
//   0  PROVEN for every namespace checked
//   1  usage error (nothing checked)
//   2  FAILED: a finding about the backup or the restored copy, named per namespace
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const SCRATCH_PIN_REPO = "scratch/restore-pins";
const SCRATCH_USAGE_REPO = "scratch/restore-usage";
const SEQ_FILE_RE = /^(\d{8})\.json$/;

function usage(msg) {
  if (msg) process.stderr.write(`restore_proof: ${msg}\n`);
  process.stderr.write(
    "usage: node tools/restore_proof.js --backup <dir> [--namespace <ns>] [--out <dir>] [--json]\n"
  );
  process.exit(1);
}

function parseArgs(argv) {
  const out = { backup: null, namespace: null, out: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) usage(`${a} needs a value`);
      return argv[++i];
    };
    if (a === "--backup") out.backup = next();
    else if (a === "--namespace") out.namespace = next();
    else if (a === "--out") out.out = next();
    else if (a === "--json") out.json = true;
    else if (a === "--help" || a === "-h") usage();
    else usage(`unknown argument ${a}`);
  }
  if (!out.backup) usage("--backup is required");
  return out;
}

function isInside(child, parent) {
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

// Every file under dir (except .git), as [repo path, utf-8 text].
function readBackup(dir) {
  const files = [];
  const walk = (d) => {
    for (const name of fs.readdirSync(d).sort()) {
      if (name === ".git") continue;
      const full = path.join(d, name);
      const st = fs.statSync(full);
      if (st.isDirectory()) walk(full);
      else if (st.isFile()) files.push([path.relative(dir, full).split(path.sep).join("/"), fs.readFileSync(full, "utf8")]);
    }
  };
  walk(dir);
  return files;
}

// ---- the scratch environment, set BEFORE any handler module is loaded ----
function isolateEnvironment(namespaces) {
  for (const k of Object.keys(process.env)) {
    if (k.startsWith("GITHUB_") || k.startsWith("WITNESS_")) delete process.env[k];
  }
  process.env.GITHUB_PIN_REPO = SCRATCH_PIN_REPO;
  process.env.GITHUB_PIN_BRANCH = "main";
  process.env.GITHUB_USAGE_REPO = SCRATCH_USAGE_REPO;
  process.env.GITHUB_USAGE_BRANCH = "main";
  process.env.GITHUB_PIN_TOKEN = "scratch-not-a-token";
  const keys = {};
  for (const ns of namespaces) keys[ns] = `scratch-${crypto.randomBytes(16).toString("hex")}`;
  process.env.WITNESS_KEYS = namespaces.map((ns) => `${keys[ns]}:${ns}`).join(",");
  return keys;
}

function installScratchFetch(scratch, counters) {
  global.fetch = async (url, opts) => {
    let u;
    try { u = new URL(String(url)); } catch (_) { u = null; }
    const m = u && u.hostname === "api.github.com" && u.pathname.match(/^\/repos\/([^/]+\/[^/]+)\//);
    if (m && m[1].startsWith("scratch/")) return scratch.handleFetch(url, opts);
    counters.refused += 1;
    throw new Error(`restore_proof: refused a network request to ${u ? u.host : "an unparseable URL"} (scratch copy only)`);
  };
}

// ---- reading one namespace's chain off the scratch store ----
async function readChain(store, ns) {
  const problems = [];
  let latest = null;
  const latestFile = await store.getFile(`pins/${ns}/latest.json`).catch((err) => {
    problems.push(`pins/${ns}/latest.json could not be read: ${err.message}`);
    return null;
  });
  if (latestFile) {
    latest = latestFile.json;
    if (!latest || typeof latest !== "object" || !Number.isInteger(latest.seq) || latest.seq < 1) {
      problems.push(`pins/${ns}/latest.json carries no usable seq`);
      latest = null;
    }
  } else if (!problems.length) {
    problems.push(`pins/${ns}/latest.json is missing`);
  }
  return { latest, problems };
}

function checkChain(ns, files, latest, problems) {
  // files: Map(seq -> {name, text})
  const maxOnDisk = files.size ? Math.max(...files.keys()) : 0;
  const head = latest ? latest.seq : maxOnDisk;
  const records = [];
  let prevRows = null;
  for (let s = 1; s <= Math.max(head, maxOnDisk); s++) {
    const name = `${String(s).padStart(8, "0")}.json`;
    const f = files.get(s);
    if (!f) {
      problems.push(`seq ${s} (pins/${ns}/${name}) is missing from the chain`);
      continue;
    }
    let rec;
    try {
      rec = JSON.parse(f.text);
    } catch (_) {
      problems.push(`pins/${ns}/${name} is not JSON`);
      continue;
    }
    if (!rec || typeof rec !== "object") {
      problems.push(`pins/${ns}/${name} is not a JSON object`);
      continue;
    }
    if (rec.seq !== s) problems.push(`pins/${ns}/${name} says seq ${JSON.stringify(rec.seq)}, not ${s}`);
    if (rec.namespace !== ns) problems.push(`pins/${ns}/${name} says namespace ${JSON.stringify(rec.namespace)}`);
    if (!Number.isSafeInteger(rec.rows) || rec.rows < 1) {
      problems.push(`pins/${ns}/${name} carries no usable rows`);
    } else {
      if (prevRows !== null && rec.rows < prevRows) {
        problems.push(`rows go backward at seq ${s} (${prevRows} -> ${rec.rows})`);
      }
      prevRows = rec.rows;
    }
    if (typeof rec.chain !== "string" || !/^[0-9a-fA-F]{8,64}$/.test(rec.chain)) {
      problems.push(`pins/${ns}/${name} carries no usable chain`);
    }
    records.push({ seq: s, rows: rec.rows, chain: typeof rec.chain === "string" ? rec.chain.toLowerCase() : rec.chain });
  }
  if (latest) {
    if (maxOnDisk > latest.seq) {
      problems.push(`latest.json says seq ${latest.seq} but numbered records run to seq ${maxOnDisk}`);
    }
    const newest = records.find((r) => r.seq === latest.seq);
    if (newest && (newest.rows !== latest.rows || newest.chain !== String(latest.chain).toLowerCase())) {
      problems.push(`latest.json (rows ${latest.rows}) does not match its own seq ${latest.seq} record (rows ${newest.rows})`);
    }
  }
  return { head, records };
}

function seqFiles(scratch, ns) {
  const files = new Map();
  for (const [p, rec] of scratch._repoMap(SCRATCH_PIN_REPO)) {
    const prefix = `pins/${ns}/`;
    if (!p.startsWith(prefix)) continue;
    const m = p.slice(prefix.length).match(SEQ_FILE_RE);
    if (m) files.set(Number(m[1]), { name: m[0], text: rec.content });
  }
  return files;
}

async function askVerify(verifyHandler, makeReq, makeRes, ns, rec) {
  // The public per-address limiter (lib/_ratelimit.js, 30 reads per 10
  // minutes) protects the hosted service; it is not part of the check. This
  // process holds its own in-memory limiter and reads one record per call,
  // so it is reset before each read, or a chain longer than 30 records would
  // read as 429 rather than as what verify says.
  require("../lib/_ratelimit.js")._resetForTests();
  const req = makeReq({ query: { ns, rows: String(rec.rows), chain: rec.chain } });
  const res = makeRes();
  await verifyHandler(req, res);
  const b = res._body || {};
  return { status: res._status, witnessed: b.witnessed === undefined ? null : b.witnessed, reason: b.reason || null };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const backup = path.resolve(args.backup);
  if (!fs.existsSync(backup) || !fs.statSync(backup).isDirectory()) usage(`--backup ${args.backup} is not a directory`);
  const outDir = args.out ? path.resolve(args.out) : null;
  if (outDir && isInside(outDir, backup)) usage(`--out ${args.out} is inside the backup; the backup is never written`);
  if (outDir && fs.existsSync(outDir) && fs.readdirSync(outDir).length) usage(`--out ${args.out} exists and is not empty`);

  const files = readBackup(backup);
  const namespacesInBackup = [...new Set(
    files.map(([p]) => p.match(/^pins\/([^/]+)\//)).filter(Boolean).map((m) => m[1])
  )].sort();
  if (!namespacesInBackup.length) usage(`the backup has no pins/ records: ${args.backup}`);
  if (args.namespace && !namespacesInBackup.includes(args.namespace)) {
    usage(`namespace ${args.namespace} is not in the backup`);
  }
  const namespaces = args.namespace ? [args.namespace] : namespacesInBackup;

  // Isolate first, then load anything that reads settings.
  const keys = isolateEnvironment(namespaces);
  const { MockGitHubStore } = require("../test/helpers/mock_store.js");
  const scratch = new MockGitHubStore();
  const counters = { refused: 0 };
  installScratchFetch(scratch, counters);
  const map = scratch._repoMap(SCRATCH_PIN_REPO);
  for (const [p, text] of files) map.set(p, { content: text, sha: crypto.randomBytes(20).toString("hex") });

  const store = require("../lib/_store.js");
  store._putRetry.sleep = async () => {};
  const pinHandler = require("../api/pin.js");
  const verifyHandler = require("../api/verify.js");
  const { makeReq, makeRes } = require("../test/helpers/http_mocks.js");
  const verifyBound = 50; // api/verify.js MAX_HISTORY_SCAN

  const results = [];
  for (const ns of namespaces) {
    const { latest, problems } = await readChain(store, ns);
    const before = checkChain(ns, seqFiles(scratch, ns), latest, problems);
    const entry = {
      namespace: ns,
      verdict: "FAILED",
      restored_seq: latest ? latest.seq : null,
      problems,
      new_pin: null,
      chain_after: [],
      records_beyond_verify_bound: 0,
    };
    results.push(entry);
    if (problems.length) continue; // never pin onto a chain that is not whole

    // The next pin: one row past the head, a fresh chain value.
    const rows = latest.rows + 1;
    const chain = crypto.randomBytes(16).toString("hex");
    const req = makeReq({
      method: "POST",
      headers: { authorization: `Bearer ${keys[ns]}` },
      body: { namespace: ns, rows, chain },
    });
    const res = makeRes();
    await pinHandler(req, res);
    const expected = before.head + 1;
    const newFile = await store.getFile(`pins/${ns}/${String(expected).padStart(8, "0")}.json`).catch(() => null);
    const newLatest = await store.getFile(`pins/${ns}/latest.json`).catch(() => null);
    entry.new_pin = {
      status: res._status,
      seq: newFile && newFile.json ? newFile.json.seq : null,
      expected_seq: expected,
      rows,
      chain,
      latest_seq_after: newLatest && newLatest.json ? newLatest.json.seq : null,
    };
    if (res._status !== 201) {
      problems.push(`the new pin was answered ${res._status}: ${JSON.stringify(res._body).slice(0, 300)}`);
      continue;
    }
    if (entry.new_pin.seq !== expected) problems.push(`the new pin did not land at seq ${expected}`);
    if (entry.new_pin.latest_seq_after !== expected) problems.push(`latest.json did not move to seq ${expected}`);

    // The whole chain, read back: every record, and the public check on each.
    const afterLatest = newLatest ? newLatest.json : null;
    const after = checkChain(ns, seqFiles(scratch, ns), afterLatest, problems);
    for (const rec of after.records) {
      const behind = after.head - rec.seq;
      const v = await askVerify(verifyHandler, makeReq, makeRes, ns, rec);
      const row = { seq: rec.seq, rows: rec.rows, chain: rec.chain, verify: v };
      // Two records can share rows (a heartbeat restates its head); verify
      // answers for the newest record with those rows, which is still this
      // exact (rows, chain) when the chains agree.
      if (behind >= verifyBound) {
        row.beyond_verify_bound = true;
        entry.records_beyond_verify_bound += 1;
      } else if (v.witnessed !== true) {
        problems.push(`api/verify.js does not answer witnessed for seq ${rec.seq} (${v.status} ${v.reason || v.witnessed})`);
      }
      entry.chain_after.push(row);
    }
    if (!problems.length) entry.verdict = "PROVEN";
  }

  if (outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    fs.cpSync(backup, outDir, { recursive: true, filter: (src) => path.basename(src) !== ".git" });
    const original = new Map(files);
    for (const [p, rec] of map) {
      if (original.get(p) === rec.content) continue; // untouched: keep the backup's own bytes
      const full = path.join(outDir, ...p.split("/"));
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, rec.content);
    }
  }

  const summary = {
    verdict: results.every((r) => r.verdict === "PROVEN") ? "PROVEN" : "FAILED",
    backup,
    scratch_repo: SCRATCH_PIN_REPO,
    out: outDir,
    network_requests_refused: counters.refused,
    verify_scan_bound: verifyBound,
    namespaces: results,
  };

  if (args.json) {
    process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
  } else {
    const lines = [`restore proof: ${summary.verdict} (backup ${backup}, scratch copy only)`];
    for (const r of results) {
      if (r.verdict === "PROVEN") {
        lines.push(
          `  ${r.namespace}: restored at seq ${r.restored_seq}; next pin landed at seq ${r.new_pin.seq}; ` +
            `chain 1..${r.new_pin.seq} read back, ${r.chain_after.length - r.records_beyond_verify_bound} records ` +
            `witnessed through api/verify.js` +
            (r.records_beyond_verify_bound ? `, ${r.records_beyond_verify_bound} older than its ${verifyBound}-record scan (read and checked here)` : "")
        );
      } else {
        lines.push(`  ${r.namespace}: FAILED`);
        for (const p of r.problems) lines.push(`    - ${p}`);
      }
    }
    if (counters.refused) lines.push(`  ${counters.refused} network request(s) refused`);
    if (outDir) lines.push(`  restored copy with the new pin written to ${outDir}`);
    process.stdout.write(lines.join("\n") + "\n");
  }
  process.exit(summary.verdict === "PROVEN" ? 0 : 2);
}

main().catch((err) => {
  process.stderr.write(`restore_proof: ${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
