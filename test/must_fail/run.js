#!/usr/bin/env node
// test/must_fail/run.js — the planted-defect runner (since unit R-AB; until
// then a script outside the repository). Each defect in a defects file is
// planted alone in a copy of the working tree, the whole suite
// (`node --test test/*.test.js`) runs there, and every run is recorded in
// the defects file's ledger, <name>.ledger.json beside it, with its UTC
// date, so a must-fail table says, for each defect, the date it was last
// re-seeded and caught: a stranger can tell a defect caught on the day its
// fix was exercised from one whose catch was never run again.
//
// A run's RESULT (unit R-ABf, M1, the architect's ruling) is one of:
//   caught    the suite exited non-zero AND at least one test failed;
//   survived  the suite exited zero;
//   timeout   the suite was killed at its timeout (whatever it had printed);
//   error     the suite exited non-zero, or was killed, with no failing test
//             (it did not start, say).
// Only `caught` is a catch; a timeout or an error is never printed as one.
//
// A defects file is a JSON array of {id, file, find, replace, what}: in
// `file`, a relative path inside the repository (never absolute, never
// with a '..' segment; unit R-ABf, m-d), the one occurrence of `find` is
// replaced by `replace`; `what` names the defect in words. A defect that
// breaks either rule stops the run before anything is planted.
//
//   node test/must_fail/run.js <defects.json> [--only ID,ID] [--workers N] [--suite GLOB]
//       plant and run; the ledger gains one entry per defect run. --suite
//       names the test files the suite runs (test/*.test.js unless given)
//   node test/must_fail/run.js <defects.json> --table
//       print the must-fail table from the ledger: one row per defect, its
//       first run's result, and the date it was last re-seeded and caught
//       (the latest run that caught it; "never" if none did)
//
// A RE-SEED that catches a defect its earlier runs did not (a survivor,
// after its gap test was written) records, as `caught_by`, the failing
// tests named MUST-FAIL GAP (all failing tests when none is), and the
// table prints those names: the record's words, not the operator's (unit
// R-ABf, m-e).
//
// The copies are made under the system's temporary directory and removed
// when the run ends, or is interrupted (SIGINT, SIGTERM; unit R-ABf, m-d).
// Each suite runs in its own process group, without the NODE_TEST_CONTEXT a
// runner started from a test inherits (a node --test that inherits it
// exits at once, its tests unrun); a timeout or an interrupt kills the whole
// group, the test files' processes with it. Nothing in the repository is
// changed but the ledger.
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const ROOT = path.join(__dirname, "..", "..");
const SUITE_TIMEOUT_MS = 300000;
const GAP_PREFIX = "MUST-FAIL GAP";

function args(argv) {
  const out = { file: null, only: null, workers: 3, table: false, suite: "test/*.test.js" };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--only") out.only = argv[++i].split(",");
    else if (a === "--workers") out.workers = Number(argv[++i]);
    else if (a === "--table") out.table = true;
    else if (a === "--suite") out.suite = argv[++i];
    else out.file = a;
  }
  if (!out.file) {
    process.stderr.write("usage: node test/must_fail/run.js <defects.json> [--only ID,ID] [--workers N] | --table\n");
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

// RESULT, above. -> "caught" | "survived" | "timeout" | "error"
function classify({ code, timedOut, failing }) {
  if (timedOut) return "timeout";
  if (code === 0) return "survived";
  return code !== null && code !== undefined && failing.length > 0 ? "caught" : "error";
}

// A defect's file: relative, inside the repository, no '..' segment; and
// its `find` in that file exactly once, changed by `replace`.
function checkDefects(defects, root = ROOT) {
  for (const d of defects) {
    if (typeof d.file !== "string" || !d.file || path.isAbsolute(d.file) || /^[A-Za-z]:/.test(d.file) ||
      d.file.split(/[\\/]/).includes("..") || !path.resolve(root, d.file).startsWith(path.resolve(root) + path.sep)) {
      throw new Error(`${d.id}: file must be a relative path inside the repository (${d.file})`);
    }
  }
  for (const d of defects) {
    const src = fs.readFileSync(path.join(root, d.file), "utf8");
    const n = src.split(d.find).length - 1;
    if (n !== 1) throw new Error(`${d.id}: find occurs ${n} times in ${d.file}`);
    if (d.find === d.replace) throw new Error(`${d.id}: no change`);
  }
}

// One run's ledger entry, after the defect's earlier runs `prev`.
function runRecord(prev, outcome, date = today()) {
  const result = classify(outcome);
  const rec = { date, result, exit: outcome.timedOut ? null : outcome.code, failing: outcome.failing.length, failing_tests: outcome.failing.slice() };
  const last = prev.length ? resultOf(prev[prev.length - 1]) : null;
  if (result === "caught" && last !== null && last !== "caught") {
    const gap = outcome.failing.filter((t) => t.startsWith(GAP_PREFIX));
    rec.caught_by = gap.length ? gap : outcome.failing.slice();
  }
  return rec;
}
// A ledger entry's result and failing tests, in either form (before unit
// R-ABf an entry carried `caught` and `first_failing`).
const resultOf = (r) => r.result || (r.caught ? "caught" : "survived");
const testsOf = (r) => r.failing_tests || r.first_failing || [];
const caughtByOf = (r) => r.caught_by || (testsOf(r).some((t) => t.startsWith(GAP_PREFIX)) ? testsOf(r).filter((t) => t.startsWith(GAP_PREFIX)) : testsOf(r));

// The must-fail table, from the defects and their ledger, and nothing else.
function table(defects, ledger) {
  const rows = ["| id | file | planted defect | first run | last re-seeded and caught |", "|---|---|---|---|---|"];
  for (const d of defects) {
    const runs = (ledger[d.id] || { runs: [] }).runs;
    const what = String(d.what).replace(/\|/g, "\\|");
    if (!runs.length) {
      rows.push(`| ${d.id} | \`${d.file}\` | ${what} | never run | never |`);
      continue;
    }
    const first = runs[0];
    const caughtRuns = runs.filter((r) => resultOf(r) === "caught");
    const lastCaught = caughtRuns[caughtRuns.length - 1];
    const latest = runs[runs.length - 1];
    let result;
    switch (resultOf(first)) {
      case "caught": result = `caught (${first.failing} failing)`; break;
      case "timeout": result = "timeout"; break;
      case "error": result = `error (exit ${first.exit})`; break;
      default: result = lastCaught ? `survived; caught on re-seed by ${caughtByOf(lastCaught).join("; ").replace(/\|/g, "\\|")}` : "survived";
    }
    if (resultOf(first) !== "caught" && resultOf(first) !== "survived" && lastCaught) {
      result += `; caught on re-seed by ${caughtByOf(lastCaught).join("; ").replace(/\|/g, "\\|")}`;
    }
    const when = !lastCaught ? "never" : resultOf(latest) === "caught" ? lastCaught.date : `${lastCaught.date} (then ${resultOf(latest)} ${latest.date})`;
    rows.push(`| ${d.id} | \`${d.file}\` | ${what} | ${result} | ${when} |`);
  }
  return `${rows.join("\n")}\n`;
}

const children = new Set();
// The suite and every process it started (its own group).
function killGroup(p) {
  try {
    process.kill(-p.pid, "SIGKILL");
  } catch {
    p.kill("SIGKILL");
  }
}
function runSuite(dir, suite = "test/*.test.js") {
  return new Promise((resolve) => {
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    const p = spawn(process.execPath, ["--test", suite], { cwd: dir, env, detached: true });
    children.add(p);
    let out = "";
    let timedOut = false;
    p.stdout.on("data", (d) => { out += d; });
    p.stderr.on("data", () => {});
    const t = setTimeout(() => {
      timedOut = true;
      killGroup(p);
    }, SUITE_TIMEOUT_MS);
    p.on("close", (code) => {
      clearTimeout(t);
      children.delete(p);
      const failing = out.split("\n").filter((l) => /^\s*not ok /.test(l) && !/# TODO/.test(l)).map((l) => l.trim().replace(/^not ok \d+ - /, "").slice(0, 160));
      resolve({ code, timedOut, failing: [...new Set(failing)] });
    });
  });
}

async function plantAll(opts) {
  const defects = JSON.parse(fs.readFileSync(opts.file, "utf8")).filter((d) => !opts.only || opts.only.includes(d.id));
  checkDefects(defects);
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "must-fail-"));
  const cleanup = () => {
    for (const c of children) killGroup(c);
    fs.rmSync(base, { recursive: true, force: true });
  };
  process.on("exit", cleanup);
  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => {
      cleanup();
      process.exit(130);
    });
  }
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
      const outcome = await runSuite(dir, opts.suite);
      fs.writeFileSync(target, orig);
      const entry = ledger[d.id] || { runs: [] };
      const rec = runRecord(entry.runs, outcome);
      entry.runs.push(rec);
      ledger[d.id] = entry;
      writeLedger(opts.file, ledger);
      process.stderr.write(`${d.id} ${rec.result.toUpperCase()} (${rec.failing} failing)\n`);
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(opts.workers, defects.length)) }, (_, i) => worker(i)));
  cleanup();
  const missed = defects.filter((d) => resultOf(ledger[d.id].runs[ledger[d.id].runs.length - 1]) !== "caught").map((d) => d.id);
  process.stderr.write(`\n${defects.length} planted, ${defects.length - missed.length} caught, ${missed.length} not caught${missed.length ? `: ${missed.join(", ")}` : ""}\n`);
}

if (require.main === module) {
  const opts = args(process.argv.slice(2));
  if (opts.table) process.stdout.write(table(JSON.parse(fs.readFileSync(opts.file, "utf8")), readLedger(opts.file)));
  else plantAll(opts).catch((e) => {
    process.stderr.write(`${e.message}\n`);
    process.exit(1);
  });
}

module.exports = { classify, checkDefects, runRecord, table };
