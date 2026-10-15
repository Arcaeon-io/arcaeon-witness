// test/response_bodies.test.js — unit R-N2 (2026-10-13), B2: no response
// body names an environment variable. The second reader's pass over R-N
// found four that did (the reveal's signer_unavailable and
// document_unavailable reasons, ?op=reconcile's signer_unavailable reason,
// and operator_key_not_configured's words). Every body carries a CODE; the
// detailed reason goes to the server log.
//
// ONE TEST, the whole reachable surface: it runs the case and reconcile
// suites again with the body audit on (test/helpers/http_mocks.js
// ARCAEON_BODY_AUDIT), so every refusal those suites drive is recorded, each
// 5xx and each signer or config refusal among them, and it reads every
// recorded body for an environment-style name: WITNESS_, VERCEL_, GITHUB_,
// or any NAME_LIKE_THIS that is not a documented reason code.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

// NAME_LIKE_THIS words a body may carry that are not environment variables:
// the verdict word reconcile.py and lib/_reconcile_tapes.js answer with.
const DOCUMENTED = Object.freeze(["COULD_NOT_LOOK"]);
const ENV_LIKE = /\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b/g;
// R-N2 B2's suites: the case and reconcile suites
const CASE_OR_RECONCILE = /^(case_.+|reconcile_endpoint)\.test\.js$/;
// unit R-FGf (M1): the suites the audit runs since then, every one but this
// file, the runner's own tests (they run suites of their own) and the live
// Python check (it skips without a Python and drives no body)
const NOT_AUDITED = new Set(["response_bodies.test.js", "must_fail_runner.test.js", "reconcile_live_python.test.js"]);

// ONE CHILD RUN for both tests below: every audited suite, with the body
// audit on. The audit file is large (every body the suites drive): removed
// after the read.
let audited = null;
function auditRows() {
  if (audited) return audited;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bodies-"));
  try {
    const out = path.join(dir, "bodies.jsonl");
    const names = fs.readdirSync(__dirname).filter((f) => /\.test\.js$/.test(f) && !NOT_AUDITED.has(f)).sort();
    assert.ok(names.filter((f) => CASE_OR_RECONCILE.test(f)).length >= 15, `the case and reconcile suites: ${names.length}`);
    const env = { ...process.env, ARCAEON_BODY_AUDIT: out };
    delete env.NODE_TEST_CONTEXT;
    const run = spawnSync(process.execPath, ["--test", ...names.map((f) => path.join(__dirname, f))], { env, encoding: "utf8", maxBuffer: 1 << 28, timeout: 600000 });
    assert.ok(fs.existsSync(out), `the audit file: ${run.stderr.slice(0, 400)}`);
    // unit R-N3 (N8): the child run itself passed, so every body it drove is the suite's own
    assert.equal(run.status, 0, `the child run: ${(run.stdout.match(/^not ok .*$/gm) || []).filter((l) => !/# TODO/.test(l)).join("\n").slice(0, 600)}`);
    const rows = fs.readFileSync(out, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    audited = { names, rows };
    return audited;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("R-N2 B2 (since unit R-N3, N8, every body): every response the case and reconcile suites reach, 2xx included, each 5xx and each signer or config refusal among them, carries no environment-style name in its body", () => {
  // (since unit R-FGf the child run audits every suite; this test reads the
  // case and reconcile suites' bodies, as it did)
  const rows = auditRows().rows.filter((r) => CASE_OR_RECONCILE.test(r.file));
  const offenders = [];
  for (const r of rows) {
    const hits = (r.body.match(ENV_LIKE) || []).filter((h) => !DOCUMENTED.includes(h));
    if (hits.length) offenders.push(`${r.file} ${r.status}: ${[...new Set(hits)].join(", ")} in ${r.body.slice(0, 160)}`);
  }
  assert.deepEqual([...new Set(offenders)], [], "no body names an environment variable");
  // what was driven: the four bodies the reader named, and the 5xx at large
  const codeOf = (r) => {
    try {
      return JSON.parse(r.body).error_code;
    } catch {
      return "html";
    }
  };
  const fivexx = rows.filter((r) => r.status >= 500);
  const codes = new Set(fivexx.map(codeOf));
  // (unit R-L, L1: consent_unreadable is gone with the withdrawn-tape listing)
  for (const c of ["signer_unavailable", "document_unavailable", "operator_key_not_configured", "case_signer_unavailable",
    "store_unreachable", "store_error", "internal_error", "case_lock_unreachable", "key_store_unreachable"]) {
    assert.ok(codes.has(c), `driven: ${c}`);
  }
  assert.ok(fivexx.length > 100, `5xx bodies read: ${fivexx.length}`);
  // unit R-L4e: a case_record_inconsistent body is the one error code: no
  // sentence, no reason code, no role
  const inconsistent = rows.filter((r) => codeOf(r) === "case_record_inconsistent");
  assert.ok(inconsistent.length > 0, "driven: case_record_inconsistent");
  for (const r of inconsistent) assert.deepEqual(JSON.parse(r.body), { ok: false, error_code: "case_record_inconsistent" }, `${r.file}: ${r.body.slice(0, 200)}`);
  // unit R-N3 (N8): the four bodies the reader named, each by the path that sends it, not by its code alone
  const driven = (handler, code) => rows.some((r) => r.handler === handler && r.status === 503 && codeOf(r) === code);
  for (const [handler, code] of [["handleCaseReveal", "signer_unavailable"], ["handleReconcile", "signer_unavailable"],
    ["handleCaseReveal", "document_unavailable"], ["handleCaseReference", "operator_key_not_configured"]]) {
    assert.ok(driven(handler, code), `driven: ${code} by ${handler}`);
  }
  // unit R-REVf: one revoked reason, key_revoked, with key_id; the role-named reasons are in no body
  const roleNamed = rows.filter((r) => /case_key_revoked|reconcile_key_revoked/.test(r.body));
  assert.deepEqual(roleNamed.map((r) => `${r.file} ${r.status}`), [], "no body names a revoked key's role");
  const revoked = rows.filter((r) => r.handler === "handleCaseReference" && codeOf(r) === "signer_revoked");
  assert.ok(revoked.length > 0, "driven: signer_revoked by handleCaseReference");
  for (const r of revoked) assert.equal(JSON.parse(r.body).reason, "key_revoked", r.body.slice(0, 200));
  // and the 2xx bodies are read too
  assert.ok(rows.filter((r) => r.status >= 200 && r.status < 300).length > 200, "2xx bodies read");
});

// =============================================================================
// UNIT R-FGf (M1, the architect's ruling): "served" is anything this service
// returns to a stranger, HTML, JSON or a file. None of it says "holds" or
// "holding" (\bhold(s|ing)\b, any case), or "second operator".
// Comments and identifiers are not sent and are exempt: sealHolds and the
// codes pin_holds_another_chain and anchor_holds_another_chain are not
// split by a word boundary, and a comment is never in a body.
// =============================================================================
const REFUSED = /\bhold(s|ing)\b|second operator/i;
const { stringLiterals } = require("./helpers/js_strings.js");

test("R-FGf M1: no body any audited suite drives, 2xx, 4xx or 5xx, HTML or JSON, says holds, holding or second operator; the bodies that said it are among those read", () => {
  const { names, rows } = auditRows();
  assert.ok(names.length > 60, `the suites: ${names.length}`);
  const offenders = [];
  for (const r of rows) {
    const m = REFUSED.exec(r.body);
    if (m) offenders.push(`${r.file} ${r.status} ${r.handler}: ...${r.body.slice(Math.max(0, m.index - 80), m.index + 40)}...`);
  }
  assert.deepEqual([...new Set(offenders)].slice(0, 10), [], `${offenders.length} bodies`);
  // the check read each body that said it at 6c385cb (the words around
  // the reworded one, which did not change)
  const drove = (handler, words) => rows.some((r) => (handler === null || r.handler === handler) && r.body.includes(words));
  for (const [handler, words] of [
    ["handleCaseOpen", "Compute a commitment with the role your party"],
    [null, "this case's lock (a registration or a withdrawal is being written)"],
    ["handleCaseWithdraw", "so it does not show that the caller"],
    ["handleCaseOpen", "a Unicode format character (category Cf)"],
    ["handleCaseReveal", "a control character"],
    ["handleReconcile", "a duplicate key and does not parse [duplicate_key_unparseable]"],
    ["handleReconcile", "a lone surrogate from a tape"],
    ["handleStamp", "no later than the time of the public commit"],
    [null, "a key bound to this namespace prefix"],
    [null, "latest pointer moved during this write"],
    [null, "the bound key can still renew"],
    [null, "the case protocol's seal anchors"],
  ]) {
    assert.ok(drove(handler, words), `driven: ${words} (${handler || "any handler"})`);
  }
});

test("R-FGf M1: no string literal in lib/ or api/, and no file under public/, says holds, holding or second operator; comments and identifiers are exempt, and the scan tells them apart", () => {
  // the scan: a string literal is read, a comment, an identifier and a
  // regular expression literal are not
  const probe = "const sealHolds = 1; // it holds\n/* holding */ const code = \"pin_holds_another_chain\";\n" +
    "const r = /holds/; const x = a / b / c; const s = 'it holds'; const t = `${sealHolds} keeps ${\"inner holding\"} holds`;\n";
  assert.deepEqual(stringLiterals(probe).filter((x) => REFUSED.test(x.text)).map((x) => [x.line, x.text]),
    [[3, "it holds"], [3, "inner holding"], [3, " holds"]]);
  const root = path.join(__dirname, "..");
  const files = (dir) => {
    const out = [];
    for (const e of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
      const rel = `${dir}/${e.name}`;
      if (e.isDirectory()) out.push(...files(rel));
      else out.push(rel);
    }
    return out;
  };
  const hits = [];
  for (const f of files("lib").concat(files("api")).filter((x) => /\.(js|mjs|cjs)$/.test(x))) {
    for (const s of stringLiterals(fs.readFileSync(path.join(root, f), "utf8"))) if (REFUSED.test(s.text)) hits.push(`${f}:${s.line}: ${s.text.slice(0, 120)}`);
  }
  // a file under public/ is served whole, its comments included
  const served = files("public");
  assert.ok(served.includes("public/.well-known/arcaeon/case-signing-keys.json"), "the key document is among them");
  for (const f of served) {
    const text = fs.readFileSync(path.join(root, f), "utf8");
    text.split("\n").forEach((l, i) => {
      if (REFUSED.test(l)) hits.push(`${f}:${i + 1}: ${l.trim().slice(0, 120)}`);
    });
  }
  assert.deepEqual(hits, []);
});
