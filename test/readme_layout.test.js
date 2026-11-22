// test/readme_layout.test.js — README.md must match the tree it describes.
//
// The README's Layout section already says it drifted once ("regenerate this
// block from `ls api/ lib/` rather than hand-maintaining it, since that is
// exactly how it drifted the first time"), and by 2026-11-22 it had drifted
// again: three paths named api/_meter.js, api/_balance.js and
// api/_status_data.js (all three live in lib/), and the Layout block named
// none of 16 lib/ modules or any tools/ script. These two checks keep it
// honest in both directions.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const README = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");

test("README: every repo path it names in backticks exists (a line saying a file never existed is the one exception)", () => {
  const missing = [];
  for (const line of README.split("\n")) {
    if (/never existed|has never existed/.test(line)) continue;
    for (const m of line.matchAll(/`((?:api|lib|tools|docs|test)\/[A-Za-z0-9_./-]+)`/g)) {
      if (!fs.existsSync(path.join(ROOT, m[1]))) missing.push(m[1]);
    }
  }
  assert.deepEqual(missing, [], `README names paths that are not in the tree: ${missing.join(", ")}`);
});

test("README: the Layout block names every file in api/, lib/ and tools/", () => {
  const start = README.indexOf("## Layout");
  assert.ok(start >= 0, "README has a Layout section");
  const end = README.indexOf("\n## ", start + 1);
  const layout = README.slice(start, end < 0 ? undefined : end);
  const unnamed = [];
  for (const dir of ["api", "lib", "tools"]) {
    for (const f of fs.readdirSync(path.join(ROOT, dir)).filter((n) => n.endsWith(".js")).sort()) {
      if (!layout.includes(`${dir}/${f}`)) unnamed.push(`${dir}/${f}`);
    }
  }
  assert.deepEqual(unnamed, [], `the Layout block does not name: ${unnamed.join(", ")}`);
});

// Product documents say "the user", "the agent" or a person's name or role,
// never he or she (house rule). Words, not substrings: "the", "here", "shell"
// and "other" are fine.
test("DOCS: no product document refers to a person as he or she", () => {
  const docs = fs.readdirSync(ROOT).filter((n) => n.endsWith(".md"))
    .concat(fs.readdirSync(path.join(ROOT, "docs")).filter((n) => n.endsWith(".md")).map((n) => `docs/${n}`));
  const hits = [];
  for (const d of docs) {
    fs.readFileSync(path.join(ROOT, d), "utf8").split("\n").forEach((line, i) => {
      if (/\b(he|she|him|his|her|hers|himself|herself)\b/i.test(line)) hits.push(`${d}:${i + 1}`);
    });
  }
  assert.deepEqual(hits, [], `he/she in: ${hits.join(", ")}`);
});
