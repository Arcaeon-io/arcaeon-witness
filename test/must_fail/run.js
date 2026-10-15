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
// A run's RESULT (unit R-ABf, M1; since unit R-WIDE, B4, the architect's
// ruling) is one of:
//   caught    the suite exited with code 1 AND at least one test failed;
//   survived  the suite exited zero;
//   timeout   the suite was killed at its timeout (whatever it had printed);
//   error     anything else: another exit code, or a kill, or code 1 with no
//             failing test (it did not start, say).
// Only `caught` is a catch; a timeout or an error is never printed as one.
//
// BEFORE ANYTHING IS PLANTED (unit R-WIDE, B4): the tree is a clean
// checkout (`git status --porcelain` prints nothing, so the commit names
// every byte planted against), and the unplanted suite, run the same way,
// exits 0 with no failing test. Otherwise the runner refuses and plants
// nothing: a defect "caught" by a suite that already fails proves nothing.
// Every ledger run records that commit (`head`), the clean status
// (`porcelain`, ""), and `defect_sha256`, the sha256 of the json bytes of
// {find, replace}, so a later change to a defect's text is a different
// defect.
//
// THE SUITE'S ENVIRONMENT (unit R-WIDE, B4): no WITNESS_* or GITHUB_*
// variable, and nothing named *_TOKEN, *_SECRET or (unit R-WIDEf, F2-d)
// *_KEY, reaches it, and every test process loads
// test/must_fail/no_network.js first, which refuses a fetch, an http or
// https request, and a net or tls connection to any host that is not this
// machine's: a test's own mock replaces fetch, and a test that would have
// reached the network fails instead.
//
// THE REPORTER IS NAMED (unit R-WIDEf, F2-a, the architect's ruling): the
// suite runs with --test-reporter=tap --test-reporter-destination=stdout,
// and its failing tests are read from those `not ok` lines. The parse never
// depends on node's default reporter, which on Node 24 is spec even on a
// pipe: there it printed no `not ok` line, every exit 1 read as error, and
// no catch could be counted. An `error` run keeps the last 30 lines of the
// suite's stderr (`stderr_tail`, F2-b), and the table prints the first. A
// run recorded with no `head` (the runner before unit R-WIDE, B4) is printed
// "pre-B4, not vouched" (F2-c).
//
// A defects file is a JSON array of {id, file, find, replace, what[, gap]}:
// in `file`, a relative path inside the repository (never absolute, never
// with a '..' segment; unit R-ABf, m-d), the one occurrence of `find` is
// replaced by `replace`; `what` names the defect in words; `gap`, for a
// defect that survived, names the gap test written for it. A defect that
// breaks either rule stops the run before anything is planted.
//
//   node test/must_fail/run.js <defects.json> [--only ID,ID] [--workers N] [--suite GLOB] [--root DIR]
//       plant and run; the ledger gains one entry per defect run. --suite
//       names the test files the suite runs (test/*.test.js unless given);
//       --root the repository (this one unless given)
//   node test/must_fail/run.js <defects.json> --table
//       print the must-fail table from the ledger: one row per defect, its
//       first run's result, and the date it was last re-seeded and caught
//       (the latest run that caught it; "never" if none did)
//
// A RE-SEED that catches a defect its earlier runs did not (a survivor,
// after its gap test was written) records, as `caught_by`, the failing
// tests named MUST-FAIL GAP (all failing tests when none is), and the
// table prints those names: the record's words, not the operator's (unit
// R-ABf, m-e). A `gap` the defects file names is printed as "named, not
// verified" unless that test is among the failing tests of the defect's
// latest catch (unit R-WIDE, B4).
//
// The copies are made under the system's temporary directory and removed
// when the run ends, or is interrupted (SIGINT, SIGTERM; unit R-ABf, m-d).
// Every copy is taken right after the clean-tree check, before the
// unplanted suite runs, and each defect is planted into its worker's own
// copy, read from that copy: nothing changed in the tree during a run is
// planted against.
// Each suite runs in its own process group, without the NODE_TEST_CONTEXT a
// runner started from a test inherits (a node --test that inherits it
// exits at once, its tests unrun); a timeout or an interrupt kills the whole
// group, the test files' processes with it: on Windows, which has no
// process groups, `taskkill /T /F` kills the tree (unit R-WIDE, B5).
// Nothing in the repository is changed but the ledger.
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..", "..");
const SUITE_TIMEOUT_MS = 300000;
const GAP_PREFIX = "MUST-FAIL GAP";
const STDERR_TAIL_LINES = 30;
const NO_NETWORK = path.join(__dirname, "no_network.js");

function args(argv) {
  const out = { file: null, only: null, workers: 3, table: false, suite: "test/*.test.js", root: ROOT };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--only") out.only = argv[++i].split(",");
    else if (a === "--workers") out.workers = Number(argv[++i]);
    else if (a === "--table") out.table = true;
    else if (a === "--suite") out.suite = argv[++i];
    else if (a === "--root") out.root = path.resolve(argv[++i]);
    else out.file = a;
  }
  if (!out.file) {
    process.stderr.write("usage: node test/must_fail/run.js <defects.json> [--only ID,ID] [--workers N] [--suite GLOB] [--root DIR] | --table\n");
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
  return code === 1 && failing.length > 0 ? "caught" : "error";
}

// A defect's file: relative, inside the repository, no '..' segment; and
// its `find` in that file exactly once, changed by `replace`. An absolute
// path is refused by name (unit R-WIDE, C16): one inside the repository
// passes the inside-the-repository check.
function checkDefects(defects, root = ROOT) {
  for (const d of defects) {
    if (typeof d.file !== "string" || !d.file || path.isAbsolute(d.file) || /^[A-Za-z]:/.test(d.file) || d.file.startsWith("\\") ||
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

// The sha256 of a defect's text (unit R-WIDE, B4).
function defectSha256(d) {
  return crypto.createHash("sha256").update(JSON.stringify({ find: d.find, replace: d.replace })).digest("hex");
}

// The commit the tree is, and whether it is clean. -> {head, porcelain}, or
// throws when `root` is not a git checkout.
function treeState(root) {
  const git = (...a) => {
    const r = spawnSync("git", ["-C", root, ...a], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`git ${a.join(" ")} failed in ${root}: ${String(r.stderr || r.error || "").trim()}`);
    return r.stdout;
  };
  return { head: git("rev-parse", "HEAD").trim(), porcelain: git("status", "--porcelain").trim() };
}

// One run's ledger entry, after the defect's earlier runs `prev`.
function runRecord(prev, outcome, date = today(), extra = {}) {
  const result = classify(outcome);
  const rec = { date, result, exit: outcome.timedOut ? null : outcome.code, failing: outcome.failing.length, failing_tests: outcome.failing.slice(), ...extra };
  // an error says why only on stderr: its last lines are kept (F2-b)
  if (result === "error") rec.stderr_tail = tailLines(outcome.stderr, STDERR_TAIL_LINES);
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
// A failing test's name as the ledger keeps it: at most 160 characters.
const kept = (name) => String(name).slice(0, 160);
// The last `n` lines of `text`, trailing blank lines dropped.
function tailLines(text, n) {
  const lines = String(text || "").split(/\r?\n/);
  while (lines.length && lines[lines.length - 1].trim() === "") lines.pop();
  return lines.slice(-n);
}
// A run is vouched for only when it records the commit it planted against.
const vouched = (r) => typeof r.head === "string" && r.head !== "";
const PRE_B4 = " (pre-B4, not vouched)";

// The must-fail table, from the defects and their ledger, and nothing else.
function table(defects, ledger) {
  const rows = ["| id | file | planted defect | first run | last re-seeded and caught |", "|---|---|---|---|---|"];
  const cellText = (s) => String(s).replace(/\|/g, "\\|");
  for (const d of defects) {
    const runs = (ledger[d.id] || { runs: [] }).runs;
    const what = cellText(d.what);
    if (!runs.length) {
      rows.push(`| ${d.id} | \`${d.file}\` | ${what} | never run | never |`);
      continue;
    }
    const first = runs[0];
    const caughtRuns = runs.filter((r) => resultOf(r) === "caught");
    const lastCaught = caughtRuns[caughtRuns.length - 1];
    const latest = runs[runs.length - 1];
    let result;
    const preB4 = vouched(first) ? "" : PRE_B4;
    switch (resultOf(first)) {
      case "caught": result = `caught (${first.failing} failing)${preB4}`; break;
      case "timeout": result = `timeout${preB4}`; break;
      case "error": {
        const why = (first.stderr_tail || []).find((l) => l.trim() !== "");
        result = `error (exit ${first.exit})${why ? `: ${cellText(why.trim())}` : ""}${preB4}`;
        break;
      }
      default: result = lastCaught ? `survived${preB4}; caught on re-seed by ${cellText(caughtByOf(lastCaught).join("; "))}` : `survived${preB4}`;
    }
    if (resultOf(first) !== "caught" && resultOf(first) !== "survived" && lastCaught) {
      result += `; caught on re-seed by ${cellText(caughtByOf(lastCaught).join("; "))}`;
    }
    // A gap test the defects file names counts only once the latest catch
    // failed it (unit R-WIDE, B4).
    if (typeof d.gap === "string" && d.gap) {
      const verified = lastCaught && testsOf(lastCaught).map(kept).includes(kept(d.gap));
      if (!verified) result += `; ${cellText(d.gap)} (named, not verified)`;
    }
    const caughtOn = lastCaught ? `${lastCaught.date}${vouched(lastCaught) ? "" : PRE_B4}` : null;
    const when = !lastCaught ? "never" : resultOf(latest) === "caught" ? caughtOn : `${caughtOn} (then ${resultOf(latest)} ${latest.date})`;
    rows.push(`| ${d.id} | \`${d.file}\` | ${what} | ${result} | ${when} |`);
  }
  return `${rows.join("\n")}\n`;
}

// THE SUITE'S ENVIRONMENT, above: `env` without the names a suite must not
// see, and with the no-network preload as its only NODE_OPTIONS (an
// inherited preload, a runner's own among them, is not carried: it would
// run before this one and could answer for it).
function scrubbedEnv(env = process.env) {
  const out = {};
  for (const [k, v] of Object.entries(env)) {
    if (k === "NODE_TEST_CONTEXT" || /^(WITNESS_|GITHUB_)/.test(k) || /(_TOKEN|_SECRET|_KEY)$/.test(k)) continue;
    out[k] = v;
  }
  out.NODE_OPTIONS = `--require ${JSON.stringify(NO_NETWORK)}`;
  return out;
}

const children = new Set();
// The suite and every process it started: its own group, or on Windows,
// which has none, its process tree (unit R-WIDE, B5).
function killGroup(p, { platform = process.platform, run = spawnSync } = {}) {
  if (platform === "win32") {
    run("taskkill", ["/pid", String(p.pid), "/T", "/F"], { stdio: "ignore" });
    return;
  }
  try {
    process.kill(-p.pid, "SIGKILL");
  } catch {
    p.kill("SIGKILL");
  }
}
// The suite's command line: the reporter named, never node's default (F2-a).
const suiteArgs = (suite) => ["--test", "--test-reporter=tap", "--test-reporter-destination=stdout", suite];
// -> {code, timedOut, failing, stderr}. `env` is the scrubbed environment
// unless a test hands another.
function runSuite(dir, suite = "test/*.test.js", { env = scrubbedEnv() } = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, suiteArgs(suite), { cwd: dir, env, detached: true });
    children.add(p);
    let out = "";
    let err = "";
    let timedOut = false;
    p.stdout.on("data", (d) => { out += d; });
    p.stderr.on("data", (d) => { err += d; });
    const t = setTimeout(() => {
      timedOut = true;
      killGroup(p);
    }, SUITE_TIMEOUT_MS);
    p.on("close", (code) => {
      clearTimeout(t);
      children.delete(p);
      const failing = out.split("\n").filter((l) => /^\s*not ok /.test(l) && !/# TODO/.test(l)).map((l) => kept(l.trim().replace(/^not ok \d+ - /, "")));
      resolve({ code, timedOut, failing: [...new Set(failing)], stderr: err });
    });
  });
}

async function plantAll(opts) {
  const root = opts.root || ROOT;
  const defects = JSON.parse(fs.readFileSync(opts.file, "utf8")).filter((d) => !opts.only || opts.only.includes(d.id));
  checkDefects(defects, root);
  const tree = treeState(root);
  if (tree.porcelain) {
    throw new Error(`the tree at ${root} is not clean (git status --porcelain prints ${tree.porcelain.split("\n").length} line(s)); ` +
      "commit it first, so the ledger's commit names what was planted against. Nothing was planted.");
  }
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
  const copy = (name) => {
    const dir = path.join(base, name);
    fs.cpSync(root, dir, { recursive: true, filter: (s) => path.basename(s) !== ".git" });
    return dir;
  };
  // Every copy is taken now, from the clean tree the commit names, before
  // anything runs: a file changed in the tree during the run is never
  // planted against (found by this unit's own pass).
  const nWorkers = Math.max(1, Math.min(opts.workers, defects.length));
  const unplanted = copy("unplanted");
  const dirs = Array.from({ length: nWorkers }, (_, w) => copy(`w${w}`));
  // THE UNPLANTED SUITE FIRST (above)
  const baseline = await runSuite(unplanted, opts.suite);
  if (baseline.timedOut || baseline.code !== 0 || baseline.failing.length) {
    cleanup();
    throw new Error(`the unplanted suite does not pass (${baseline.timedOut ? "timed out" : `exit ${baseline.code}`}, ${baseline.failing.length} failing` +
      `${baseline.failing.length ? `: ${baseline.failing.slice(0, 3).join("; ")}` : ""}), so no catch would mean anything. Nothing was planted.`);
  }
  const queue = defects.slice();
  const ledger = readLedger(opts.file);
  async function worker(w) {
    const dir = dirs[w];
    for (;;) {
      const d = queue.shift();
      if (!d) return;
      const target = path.join(dir, d.file);
      const orig = fs.readFileSync(target, "utf8");
      fs.writeFileSync(target, orig.replace(d.find, () => d.replace));
      const outcome = await runSuite(dir, opts.suite);
      fs.writeFileSync(target, orig);
      const entry = ledger[d.id] || { runs: [] };
      const rec = runRecord(entry.runs, outcome, today(), { head: tree.head, porcelain: tree.porcelain, defect_sha256: defectSha256(d) });
      entry.runs.push(rec);
      ledger[d.id] = entry;
      writeLedger(opts.file, ledger);
      process.stderr.write(`${d.id} ${rec.result.toUpperCase()} (${rec.failing} failing)\n`);
    }
  }
  await Promise.all(dirs.map((_, i) => worker(i)));
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

module.exports = { classify, checkDefects, runRecord, table, defectSha256, scrubbedEnv, killGroup, treeState, runSuite, suiteArgs };
