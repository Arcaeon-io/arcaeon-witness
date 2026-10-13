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

// NAME_LIKE_THIS words a body may carry that are not environment variables.
const DOCUMENTED = Object.freeze([]);
const ENV_LIKE = /\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b/g;

test("R-N2 B2: every refusal the case and reconcile suites reach, each 5xx and each signer or config refusal among them, carries no environment-style name in its body", () => {
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "bodies-")), "bodies.jsonl");
  const files = fs.readdirSync(__dirname).filter((f) => /^(case_.+|reconcile_endpoint)\.test\.js$/.test(f)).sort().map((f) => path.join(__dirname, f));
  assert.ok(files.length >= 15, `the suites: ${files.length}`);
  const env = { ...process.env, ARCAEON_BODY_AUDIT: out };
  delete env.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, ["--test", ...files], { env, encoding: "utf8", maxBuffer: 1 << 28, timeout: 600000 });
  assert.ok(fs.existsSync(out), `the audit file: ${run.stderr.slice(0, 400)}`);
  const rows = fs.readFileSync(out, "utf8").trim().split("\n").map((l) => JSON.parse(l));
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
  for (const c of ["signer_unavailable", "document_unavailable", "operator_key_not_configured", "case_signer_unavailable", "consent_unreadable",
    "store_unreachable", "store_error", "internal_error", "case_lock_unreachable", "key_store_unreachable"]) {
    assert.ok(codes.has(c), `driven: ${c}`);
  }
  assert.ok(fivexx.length > 100, `5xx bodies read: ${fivexx.length}`);
});
