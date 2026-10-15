// test/reconcile_live_python.test.js — a live differential check: fresh
// mutations the fixture has never seen, judged by the real reconcile.py in a
// subprocess, compared with the port byte for byte.
//
// Needs a Python and an arcaeon-ledger checkout (ARCAEON_LEDGER_REPO, else a
// sibling arcaeon-ledger-rel080 / arcaeon-ledger carrying the same
// reconcile.py the port names). Without them it SKIPS and says why; the
// committed fixture (reconcile_conformance.test.js) still runs everywhere.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const T = require("../lib/_reconcile_tapes.js");
const fixtures = require("./fixtures/reconcile/cases.json");
const { inPythonWords } = require("./helpers/reconcile_words.js");

function lfSha(p) {
  return crypto.createHash("sha256").update(fs.readFileSync(p).toString("latin1").replace(/\r\n/g, "\n"), "latin1").digest("hex");
}

function findLedger() {
  const root = path.join(__dirname, "..", "..");
  const cands = [process.env.ARCAEON_LEDGER_REPO, path.join(root, "arcaeon-ledger-rel080"), path.join(root, "arcaeon-ledger")];
  for (const c of cands) {
    if (!c) continue;
    const p = path.join(c, "arcaeon_ledger", "reconcile.py");
    if (fs.existsSync(p) && lfSha(p) === T.REFERENCE.reconcile_sha256) return c;
  }
  return null;
}

function findPython() {
  const cands = process.env.ARCAEON_PYTHON ? [process.env.ARCAEON_PYTHON] : ["py", "python3", "python"];
  for (const exe of cands) {
    const r = spawnSync(exe, ["-c", "import sys; print(sys.version_info[0])"], { timeout: 8000, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    if (r.status === 0 && String(r.stdout).trim() === "3") return exe;
  }
  return null;
}

const LEDGER = findLedger();
const PY = LEDGER ? findPython() : null;
const skip = !LEDGER ? "no arcaeon-ledger checkout with the reconcile.py this port names (set ARCAEON_LEDGER_REPO)"
  : !PY ? "no Python 3 found (set ARCAEON_PYTHON)" : false;

const SCRIPT = `
import json, sys
sys.path.insert(0, sys.argv[1])
import arcaeon_ledger.reconcile as R
out = []
for a, b in json.load(open(sys.argv[2], encoding="utf-8")):
    try:
        d = R.reconcile(a, b).to_dict()
        out.append(json.dumps(d, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
    except Exception as e:
        out.append("RAISES " + type(e).__name__)
json.dump(out, open(sys.argv[3], "w", encoding="utf-8"))
`;

test("LIVE DIFFERENTIAL: 150 fresh byte-level mutations, judged by reconcile.py in a subprocess, match the port", { skip }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "reconcile-live-"));
  try {
    let seed = Number(process.env.RECONCILE_LIVE_SEED || 424242);
    const rnd = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32);
    const base = fixtures.cases.filter((c) => c.source === "crossrepo" && c.python && /agent vs tool$/.test(c.name));
    const pairs = [];
    const bufs = [];
    for (let i = 0; i < 150; i++) {
      const c = base[Math.floor(rnd() * base.length)];
      let a = Buffer.from(c.a_b64, "base64");
      let b = Buffer.from(c.b_b64, "base64");
      const hit = (buf) => {
        if (!buf.length) return buf;
        const op = Math.floor(rnd() * 6);
        const k = Math.floor(rnd() * buf.length);
        if (op === 0) return buf.subarray(0, k);                                   // truncate
        if (op === 1) return Buffer.concat([buf.subarray(0, k), buf.subarray(k + 1)]); // delete a byte
        if (op === 2) { const x = Buffer.from(buf); x[k] = Math.floor(rnd() * 256); return x; } // flip a byte
        if (op === 3) { const ls = buf.toString("latin1").split("\n"); const j = Math.floor(rnd() * ls.length); ls.splice(j, 1); return Buffer.from(ls.join("\n"), "latin1"); }
        if (op === 4) { const ls = buf.toString("latin1").split("\n"); const j = Math.floor(rnd() * ls.length); ls.splice(j, 0, ls[j]); return Buffer.from(ls.join("\n"), "latin1"); }
        return buf;
      };
      if (rnd() < 0.7) a = hit(a);
      if (rnd() < 0.7) b = hit(b);
      const pa = path.join(dir, `a${i}.jsonl`);
      const pb = path.join(dir, `b${i}.jsonl`);
      fs.writeFileSync(pa, a);
      fs.writeFileSync(pb, b);
      pairs.push([pa, pb]);
      bufs.push([a, b]);
    }
    fs.writeFileSync(path.join(dir, "pairs.json"), JSON.stringify(pairs));
    fs.writeFileSync(path.join(dir, "run.py"), SCRIPT);
    const r = spawnSync(PY, [path.join(dir, "run.py"), LEDGER, path.join(dir, "pairs.json"), path.join(dir, "out.json")],
      { timeout: 120000, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(fs.readFileSync(path.join(dir, "out.json"), "utf8"));
    let compared = 0;
    for (let i = 0; i < pairs.length; i++) {
      const mine = T.reconcileTapes(bufs[i][0], bufs[i][1]);
      // The hardened reconcile.py never raises; if it does, that is a bug in
      // the reference to report, not a case to excuse.
      assert.ok(!out[i].startsWith("RAISES "), `case ${i}: reconcile.py ${out[i]}`);
      if (out[i].includes(dir.replace(/\\/g, "\\\\")) || out[i].includes("jsonl")) continue; // names a local path
      // THE SECOND DIVERGENCE (unit R-FGf, M1): test/helpers/reconcile_words.js
      assert.equal(inPythonWords(T.conformanceJson(mine), out[i]), out[i], `case ${i}`);
      compared += 1;
    }
    assert.ok(compared > 100, `only ${compared} compared`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
