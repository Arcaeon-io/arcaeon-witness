// test/deploy_shape.test.js — the deploy shape is declared in the
// repository (README "Deploy shape"), not decided by whoever deploys.
//
// The first real deployments showed why: production went out prebuilt with
// no static file at all, so it answered 404 for the case key document; a
// preview went out as the raw tree and served lib/, test/ and CHANGELOG.md.
// Nothing in the repository said which was right. Now vercel.json's
// outputDirectory is public/, and this file holds the repository to it:
//   - public/ holds exactly the files the domain serves, and none of them is
//     left at the repository root;
//   - every function whose require graph reaches the case key document
//     names public/.well-known/** in its includeFiles, so its bundle carries
//     the bytes the domain serves, and no function names anything else;
//   - every root-relative static link the pages carry names a file public/
//     serves;
//   - the README's list is exactly public/'s files;
//   - api/ is 12 files.
// BREAK ARMS: a function that loads the document without includeFiles, a
// file outside the list in public/, a page link public/ does not serve, a
// README list that drifts, a missing outputDirectory: each is named.
// LINE ENDINGS: a checkout with core.autocrlf true (Windows) has CRLF text
// files, and a line-anchored regex (/^...$/m) never matches a line that ends
// in a carriage return. So every text file read here goes through readText,
// CRLF to LF right after the read, and a planted arm reads a CRLF README.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

// A text file as the parsers below expect it: LF line ends, whatever the checkout.
const readText = (p) => fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");

const S = require("../lib/_case_seal.js");

const ROOT = path.join(__dirname, "..");
const INCLUDE = "public/.well-known/**";
// What the domain serves statically, exactly (README "Deploy shape").
const SERVED = Object.freeze(["/.well-known/arcaeon/case-signing-keys.json", "/PRACTICES.md", "/favicon.svg"]);

function filesUnder(dir, rel = "") {
  const out = [];
  for (const e of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
    const p = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...filesUnder(dir, p));
    else if (e.isFile()) out.push(p);
  }
  return out.sort();
}

// The local files a module reaches through require("./...") or
// require("../..."), transitively, as repository-relative paths.
function requireGraph(file, seen = new Set()) {
  for (const m of fs.readFileSync(file, "utf8").matchAll(/require\(\s*["'](\.{1,2}\/[^"']+)["']\s*\)/g)) {
    let p = path.resolve(path.dirname(file), m[1]);
    if (!fs.existsSync(p) && fs.existsSync(`${p}.js`)) p = `${p}.js`;
    const rel = path.relative(ROOT, p).split(path.sep).join("/");
    if (seen.has(rel)) continue;
    seen.add(rel);
    if (p.endsWith(".js")) requireGraph(p, seen);
  }
  return seen;
}

function readmeServed(readme) {
  const section = readme.split(/^## Deploy shape$/m)[1];
  if (section === undefined) return null;
  const body = section.split(/^## /m)[0];
  const list = body.split(/^Served statically, exactly these, and nothing more:$/m)[1];
  if (list === undefined) return null;
  const items = [];
  for (const line of list.replace(/^\n+/, "").split("\n")) {
    const m = /^- `(\/[^`]+)`$/.exec(line);
    if (!m) break;
    items.push(m[1]);
  }
  return items.sort();
}

// Everything wrong with a shape, by name. -> [problem, ...]
function shapeProblems({ vercel, publicFiles, rootEntries, graphs, links, readme, apiFiles }) {
  const problems = [];
  if (!vercel || vercel.outputDirectory !== "public") problems.push("outputDirectory is not public");
  const served = publicFiles.map((f) => `/${f}`).sort();
  if (JSON.stringify(served) !== JSON.stringify([...SERVED].sort())) problems.push(`public/ holds ${served.join(", ")}`);
  for (const f of ["favicon.svg", "PRACTICES.md", ".well-known"]) if (rootEntries.includes(f)) problems.push(`${f} is left at the repository root`);
  const fns = (vercel && vercel.functions) || {};
  for (const [fn, reached] of Object.entries(graphs)) {
    const loads = reached.has(S.CASE_KEYS_FILE);
    const inc = fns[fn] && fns[fn].includeFiles;
    if (loads && inc !== INCLUDE) problems.push(`${fn} loads the key document and its includeFiles is ${JSON.stringify(inc)}`);
    if (!loads && inc !== undefined) problems.push(`${fn} names includeFiles ${JSON.stringify(inc)} and loads no key document`);
  }
  for (const fn of Object.keys(fns)) if (!Object.prototype.hasOwnProperty.call(graphs, fn)) problems.push(`vercel.json configures ${fn}, which is not a function`);
  for (const l of links) if (!SERVED.includes(l)) problems.push(`a page links ${l}, which public/ does not serve`);
  const listed = readmeServed(readme);
  if (JSON.stringify(listed) !== JSON.stringify([...SERVED].sort())) problems.push(`the README lists ${JSON.stringify(listed)}`);
  if (apiFiles.length !== 12) problems.push(`api/ holds ${apiFiles.length} files`);
  return problems;
}

function theRepository() {
  const vercel = JSON.parse(fs.readFileSync(path.join(ROOT, "vercel.json"), "utf8"));
  const apiFiles = fs.readdirSync(path.join(ROOT, "api")).filter((f) => f.endsWith(".js")).sort();
  const graphs = Object.fromEntries(apiFiles.map((f) => [`api/${f}`, requireGraph(path.join(ROOT, "api", f))]));
  // Root-relative links to a static file, in every page source.
  const links = new Set();
  for (const dir of ["api", "lib"]) {
    for (const f of fs.readdirSync(path.join(ROOT, dir)).filter((x) => x.endsWith(".js"))) {
      const src = readText(path.join(ROOT, dir, f));
      for (const m of src.matchAll(/(?:href|src)=["'](\/[A-Za-z0-9_./-]+\.(?:md|json|svg|txt|png|ico|html|css|xml|webmanifest))["']/g)) links.add(m[1]);
    }
  }
  return {
    vercel,
    publicFiles: filesUnder(path.join(ROOT, "public")),
    rootEntries: fs.readdirSync(ROOT),
    graphs,
    links: [...links].sort(),
    readme: readText(path.join(ROOT, "README.md")),
    apiFiles,
  };
}

test("DEPLOY SHAPE: outputDirectory public/, exactly the served files in it, includeFiles on every function that loads the key document, every page link served, the README's list, api/ at 12", () => {
  const repo = theRepository();
  assert.deepEqual(shapeProblems(repo), []);
  // What the walk found, stated: the three functions that load the document.
  const loaders = Object.entries(repo.graphs).filter(([, g]) => g.has(S.CASE_KEYS_FILE)).map(([fn]) => fn).sort();
  assert.deepEqual(loaders, ["api/badge.js", "api/status.js", "api/verify.js"]);
  assert.deepEqual(repo.links, ["/PRACTICES.md", "/favicon.svg"], "the pages' own static links");
  assert.equal(repo.vercel.functions["api/verify.js"].maxDuration, 30, "the existing function config is kept");
  assert.equal(repo.vercel.functions["api/pin.js"].maxDuration, 30);
  // The document the module loaded is the committed file, byte for byte.
  assert.deepEqual(S.PUBLISHED_KEYS, JSON.parse(fs.readFileSync(path.join(ROOT, ...S.CASE_KEYS_FILE.split("/")), "utf8")));
});

test("DEPLOY SHAPE, CRLF: a README checked out with CRLF line ends (core.autocrlf true) reads through readText to the same served list", () => {
  const lf = readText(path.join(ROOT, "README.md"));
  const want = readmeServed(lf);
  assert.deepEqual(want, [...SERVED].sort());
  // The planted arm: the README as a CRLF checkout holds it, on disk.
  const crlf = lf.replace(/\n/g, "\r\n");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "deploy-shape-crlf-"));
  const file = path.join(dir, "README.md");
  fs.writeFileSync(file, crlf);
  assert.ok(fs.readFileSync(file, "utf8").includes("## Deploy shape\r\n"), "the planted file really is CRLF");
  assert.deepEqual(readmeServed(readText(file)), want);
  assert.deepEqual(shapeProblems({ ...theRepository(), readme: readText(file) }), [], "the whole shape holds on a CRLF checkout");
  // MUST-FAIL ARM: the same bytes read without the normalization are the
  // failure seen on Windows, "the README lists []". (JavaScript's /m counts
  // a lone \r as a line end, so the headings split; the list's lines keep
  // their \r and none matches /^- `...`$/.)
  assert.deepEqual(readmeServed(fs.readFileSync(file, "utf8")), []);
  assert.deepEqual(shapeProblems({ ...theRepository(), readme: fs.readFileSync(file, "utf8") }), ["the README lists []"]);
});

test("DEPLOY SHAPE, BREAK ARMS: each drift is named", () => {
  const repo = theRepository();
  const drop = (o, k) => Object.fromEntries(Object.entries(o).filter(([x]) => x !== k));
  const arms = [
    ["no outputDirectory", { ...repo, vercel: drop(repo.vercel, "outputDirectory") }, /outputDirectory is not public/],
    ["a loader without includeFiles", { ...repo, vercel: { ...repo.vercel, functions: drop(repo.vercel.functions, "api/badge.js") } },
      /api\/badge\.js loads the key document and its includeFiles is undefined/],
    ["includeFiles on a function that loads nothing", { ...repo, vercel: { ...repo.vercel, functions: { ...repo.vercel.functions, "api/pin.js": { maxDuration: 30, includeFiles: INCLUDE } } } },
      /api\/pin\.js names includeFiles/],
    ["an extra file in public/", { ...repo, publicFiles: [...repo.publicFiles, "lib/_store.js"].sort() }, /public\/ holds /],
    ["the favicon left at the root", { ...repo, rootEntries: [...repo.rootEntries, "favicon.svg"] }, /favicon\.svg is left at the repository root/],
    ["a page link public/ does not serve", { ...repo, links: [...repo.links, "/CHANGELOG.md"] }, /a page links \/CHANGELOG\.md, which public\/ does not serve/],
    ["a README list that drifts", { ...repo, readme: repo.readme.replace("- `/PRACTICES.md`\n", "") }, /the README lists /],
    ["a thirteenth function", { ...repo, apiFiles: [...repo.apiFiles, "case.js"] }, /api\/ holds 13 files/],
  ];
  for (const [name, shape, want] of arms) {
    const problems = shapeProblems(shape);
    assert.ok(problems.some((p) => want.test(p)), `${name}: ${JSON.stringify(problems)}`);
  }
});
