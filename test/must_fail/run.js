#!/usr/bin/env node
// test/must_fail/run.js — the planted-defect runner (since unit R-AB; until
// then a script outside the repository). Each defect in a defects file is
// planted alone in a copy of the working tree, the whole suite
// (`node --test test/*.test.js`) runs there, and the defect is CAUGHT when
// any test fails. Every run is recorded in the defects file's ledger,
// <name>.ledger.json beside it, with its UTC date, so a must-fail table says,
// for each defect, the date it was last re-seeded and caught: a stranger can
// tell a defect caught on the day its fix was exercised from one whose
// catch was never run again.
//
// A defects file is a JSON array of {id, file, find, replace, what}: in
// `file` (relative to the repository root), the one occurrence of `find` is
// replaced by `replace`; `what` names the defect in words. A `find` that
// does not occur exactly once stops the run before anything is planted.
//
//   node test/must_fail/run.js <defects.json> [--only ID,ID] [--workers N]
//       plant and run; the ledger gains one entry per defect run
//   node test/must_fail/run.js <defects.json> --table [--gap ID=TEST,...]
//       print the must-fail table from the ledger: one row per defect,
//       its first run's result, and the date it was last re-seeded and
//       caught (the latest run that caught it; "never" if none did)
//
// The copies are made under the system's temporary directory and removed
// when the run ends. Nothing in the repository is changed but the ledger.
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const ROOT = path.join(__dirname, "..", "..");
const SUITE_TIMEOUT_MS = 300000;

function args(argv) {
  const out = { file: null, only: null, workers: 3, table: false, gap: {} };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--only") out.only = argv[++i].split(",");
    else if (a === "--workers") out.workers = Number(argv[++i]);
    else if (a === "--table") out.table = true;
    else if (a === "--gap") for (const kv of argv[++i].split(",")) out.gap[kv.split("=")[0]] = kv.split("=").slice(1).join("=");
    else out.file = a;
  }
  if (!out.file) {
    process.stderr.write("usage: node test/must_fail/run.js <defects.json> [--only ID,ID] [--workers N] | --table [--gap ID=TEST,...]\n");
    process.exit(2);
  }
  return out;
}

const ledgerPath = (file) => file.replace(/\.json$/, "") + ".ledger.json";
function readLedger(file) {
  try {
    return JSON.parse(fs.readFileSync(ledgerPath(file), "utf8"));
  } catch {
    return {};
  }
}
function writeLedger(file, ledger) {
  fs.writeFileSync(ledgerPath(file), `${JSON.stringify(ledger, null, 2)}\n`);
}
const today = () => new Date().toISOString().slice(0, 10);

function runSuite(dir) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, ["--test", "test/*.test.js"], { cwd: dir, env: { ...process.env } });
    let out = "";
    p.stdout.on("data", (d) => { out += d; });
    p.stderr.on("data", () => {});
    const t = setTimeout(() => p.kill("SIGKILL"), SUITE_TIMEOUT_MS);
    p.on("close", (code) => {
      clearTimeout(t);
      const failing = out.split("\n").filter((l) => /^\s*not ok /.test(l) && !/# TODO/.test(l)).map((l) => l.trim().replace(/^not ok \d+ - /, "").slice(0, 160));
      resolve({ code, failing: [...new Set(failing)] });
    });
  });
}

async function plantAll(opts) {
  const defects = JSON.parse(fs.readFileSync(opts.file, "utf8")).filter((d) => !opts.only || opts.only.includes(d.id));
  for (const d of defects) {
    const src = fs.readFileSync(path.join(ROOT, d.file), "utf8");
    const n = src.split(d.find).length - 1;
    if (n !== 1) throw new Error(`${d.id}: find occurs ${n} times in ${d.file}`);
    if (d.find === d.replace) throw new Error(`${d.id}: no change`);
  }
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "must-fail-"));
  const cleanup = () => fs.rmSync(base, { recursive: true, force: true });
  process.on("exit", cleanup);
  const queue = defects.slice();
  const ledger = readLedger(opts.file);
  async function worker(w) {
    const dir = path.join(base, `w${w}`);
    fs.cpSync(ROOT, dir, { recursive: true, filter: (s) => path.basename(s) !== ".git" });
    for (;;) {
      const d = queue.shift();
      if (!d) return;
      const target = path.join(dir, d.file);
      const orig = fs.readFileSync(path.join(ROOT, d.file), "utf8");
      fs.writeFileSync(target, orig.replace(d.find, () => d.replace));
      const r = await runSuite(dir);
      fs.writeFileSync(target, orig);
      const caught = r.code !== 0;
      const entry = ledger[d.id] || { runs: [] };
      entry.runs.push({ date: today(), caught, failing: r.failing.length, first_failing: r.failing.slice(0, 3) });
      ledger[d.id] = entry;
      writeLedger(opts.file, ledger);
      process.stderr.write(`${d.id} ${caught ? "CAUGHT" : "SURVIVED"} (${r.failing.length} failing)\n`);
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(opts.workers, defects.length)) }, (_, i) => worker(i)));
  cleanup();
  const missed = defects.filter((d) => !ledger[d.id].runs[ledger[d.id].runs.length - 1].caught).map((d) => d.id);
  process.stderr.write(`\n${defects.length} planted, ${defects.length - missed.length} caught, ${missed.length} survived${missed.length ? `: ${missed.join(", ")}` : ""}\n`);
}

// The must-fail table: the first run's result, and the date the defect was
// last re-seeded and caught. `gap` names, for a defect whose first run
// survived, the gap test that catches it.
function table(opts) {
  const defects = JSON.parse(fs.readFileSync(opts.file, "utf8"));
  const ledger = readLedger(opts.file);
  const rows = ["| id | file | planted defect | first run | last re-seeded and caught |", "|---|---|---|---|---|"];
  for (const d of defects) {
    const runs = (ledger[d.id] || { runs: [] }).runs;
    if (!runs.length) {
      rows.push(`| ${d.id} | \`${d.file}\` | ${d.what} | never run | never |`);
      continue;
    }
    const first = runs[0];
    const lastCaught = runs.filter((r) => r.caught).pop();
    const latest = runs[runs.length - 1];
    const result = first.caught ? `caught (${first.failing} failing)`
      : `survived; ${opts.gap[d.id] ? `caught by the gap test ${opts.gap[d.id]}` : "no gap test"}`;
    const when = !lastCaught ? "never" : latest.caught ? lastCaught.date : `${lastCaught.date} (survived ${latest.date})`;
    rows.push(`| ${d.id} | \`${d.file}\` | ${d.what.replace(/\|/g, "\\|")} | ${result} | ${when} |`);
  }
  process.stdout.write(`${rows.join("\n")}\n`);
}

if (require.main === module) {
  const opts = args(process.argv.slice(2));
  if (opts.table) table(opts);
  else plantAll(opts).catch((e) => {
    process.stderr.write(`${e.message}\n`);
    process.exit(1);
  });
}
