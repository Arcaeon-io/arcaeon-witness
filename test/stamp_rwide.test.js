// test/stamp_rwide.test.js — unit R-WIDE, Group D (2026-10-15): stamps, as
// the architect ruled. D1: a stamp is {sha256, stamped_at} (no size is
// stored, whatever the request sends), and its scope says the stamper's
// statements about the bytes are not checked. D2: the price, 0.25 credit per
// stamp past the free allowance, is ratified; the comment says so, and the
// README has a stamp section. D3: api/verify.js's header and the README's
// Layout row name every ?op= mode and which ones write or charge. Each test
// fails on the code before Group D.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.STAMP_DAILY_CAP = "50";
process.env.STAMP_FREE_PER_DAY = "1000";

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const stamp = require("../lib/_stamp.js");

const REPO = process.env.STAMP_REPO;
const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);
const pathOf = (sha) => `stamps/${sha.slice(0, 2)}/${sha}.json`;
const read = (rel) => fs.readFileSync(path.join(__dirname, "..", rel), "utf8");
const README = () => read("README.md").replace(/\s+/g, " ");

let gh;
let restore;
let realSleep;
beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
  stamp._resetLimiterForTests();
  realSleep = store._putRetry.sleep;
  store._putRetry.sleep = async () => {};
});
afterEach(() => {
  store._putRetry.sleep = realSleep;
  restore();
});

let ip = 0;
async function post(body) {
  ip += 1;
  const res = makeRes();
  await stamp.handleStamp(makeReq({ method: "POST", body, headers: { "x-forwarded-for": `198.51.100.${ip}` } }), res);
  return res;
}

test("R-WIDE D1: a stamp stores {kind, v, sha256, stamped_at} and no size, whatever size the request sends; the answer carries none", async () => {
  for (const [sha, body] of [[SHA_A, { sha256: SHA_A, size: 1234 }], [SHA_B, { sha256: SHA_B }]]) {
    const res = await post(body);
    assert.equal(res._status, 201, JSON.stringify(res._body));
    const rec = gh.read(REPO, pathOf(sha));
    assert.deepEqual(Object.keys(rec).sort(), ["kind", "sha256", "stamped_at", "v"], JSON.stringify(rec));
    assert.equal(JSON.stringify(res._body).includes("\"size\""), false, JSON.stringify(res._body));
  }
  // the refusal of an extra field says what a stamp stores, and names no size
  const extra = await post({ sha256: SHA_A, name: "x.pdf" });
  assert.equal(extra._status, 400);
  assert.match(extra._body.error, /A stamp stores a fingerprint and the time, nothing else; the store is public\.$/);
});

test("R-WIDE D1: the scope's does_not_prove says the stamper's statements about the bytes are not checked", async () => {
  assert.ok(stamp.SCOPE.does_not_prove.endsWith("The stamper's statements about the bytes are not checked."), stamp.SCOPE.does_not_prove);
  const res = await post({ sha256: SHA_A });
  assert.equal(res._body.scope.does_not_prove, stamp.SCOPE.does_not_prove);
});

test("R-WIDE D2: the price, 0.25 credit per stamp past the free allowance, is ratified in the code's comment; the README has a stamp section with the price, the free tier, the shared balance, and what a stamp proves and does not", () => {
  assert.equal(stamp.STAMP_PRICE_CREDITS, 0.25);
  const src = read("lib/_stamp.js");
  const price = src.slice(src.indexOf("// ---- THE PRICE. ONE CONSTANT."), src.indexOf("const STAMP_PRICE_CREDITS"));
  assert.doesNotMatch(price, /PLACEHOLDER|NOT RATIFIED/);
  assert.match(price, /RATIFIED \(2026-10-15, the architect\)/);
  assert.match(read("README.md"), /^### Stamps$/m);
  const r = README();
  for (const s of [
    "A stamp costs 0.25 credit, after the free allowance: 3 stamps per address per UTC day (STAMP_FREE_PER_DAY), past which a stamp needs a witness key.",
    "The credit comes from the same prepaid balance the pins spend: one balance per key, shared by pins and stamps.",
    `What a stamp proves: ${stamp.SCOPE.proves}`,
    `What it does not prove: ${stamp.SCOPE.does_not_prove}`,
    "A stamp records the fingerprint and the time, and nothing else: no size, no filename, no label.",
  ]) assert.ok(r.includes(s), s);
});

// Every ?op= api/verify.js dispatches, read from its code.
function opsOf(src) {
  const ops = new Set();
  for (const m of src.matchAll(/op \|\| ""\)+ === "([a-z-]+)"|op === "([a-z-]+)"/g)) ops.add(m[1] || m[2]);
  return [...ops].sort();
}
const WRITES = ["case-commit", "case-open", "case-reference", "case-reveal", "case-withdraw", "stamp"];
test("R-WIDE D3: api/verify.js's header and the README's Layout row name every ?op= mode it dispatches, and which ones write and which one charges", () => {
  const src = read("api/verify.js");
  const ops = opsOf(src);
  assert.deepEqual(ops, ["bulk", "case-commit", "case-open", "case-page", "case-reference", "case-reveal", "case-withdraw", "reconcile", "reconcile-page", "stamp"]);
  const header = src.slice(0, src.indexOf("\"use strict\""));
  const modes = header.slice(header.indexOf("// THE MODES"));
  const readme = read("README.md");
  const row = readme.slice(readme.indexOf("api/verify.js "), readme.indexOf("api/health.js "));
  for (const op of ops) {
    const line = modes.split("\n").find((l) => l.includes(`op=${op} `));
    assert.ok(line, `the header names op=${op}`);
    assert.equal(/WRITES/.test(line), WRITES.includes(op), `header, op=${op}: ${line}`);
    const rline = row.split("\n").find((l) => l.includes(`op=${op} `));
    assert.ok(rline, `the README's Layout row names op=${op}`);
    assert.equal(/WRITES/.test(rline), WRITES.includes(op), `README, op=${op}: ${rline}`);
  }
  const charging = modes.split("\n").filter((l) => /CHARGES/.test(l));
  assert.equal(charging.length, 1, charging.join("\n"));
  assert.match(charging[0], /op=stamp /);
  assert.equal(row.split("\n").filter((l) => /CHARGES/.test(l)).length, 1);
});
