// test/status_promises.test.js — the status page shows the merge delay promise
// and the capacity view in plain words (owner job 12), the page and its JSON
// twin alike.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const plain = require("../lib/_plain_promises.js");
const statusHandler = require("../api/status.js");

const REPO = process.env.GITHUB_PIN_REPO;
const ENV = ["WITNESS_MERGE_DELAY_HOURS", "WITNESS_MERGE_DELAY_LABEL", "WITNESS_WRITE_BUDGET_PER_HOUR", "WITNESS_WRITE_BUDGET_LABEL"];
let gh, restore, saved, ip = 0;

beforeEach(() => {
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  for (const k of ENV) delete process.env[k];
  gh = new MockGitHubStore();
  restore = install(gh);
  gh.seed(REPO, "pins/acme-prod/latest.json", { namespace: "acme-prod", rows: 4, chain: "cafebabe", seq: 1,
    pinned_at: new Date().toISOString(), cadence_hours: 24, next_pin_due_by: new Date(Date.now() + 3600e3).toISOString() });
});
afterEach(() => {
  restore();
  for (const k of ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
});

async function page(query = {}) {
  const res = makeRes();
  ip += 1;
  await statusHandler(makeReq({ method: "GET", query, headers: { "x-forwarded-for": `10.30.0.${ip}` } }), res);
  const b = res._body !== undefined ? res._body : res._text;
  return { res, text: typeof b === "string" ? b : JSON.stringify(b), body: b };
}

test("PAGE: with a promise and a budget set, both read in plain words", async () => {
  process.env.WITNESS_MERGE_DELAY_HOURS = "36";
  process.env.WITNESS_MERGE_DELAY_LABEL = "checkpoints are published once a day";
  process.env.WITNESS_WRITE_BUDGET_PER_HOUR = "500";
  process.env.WITNESS_WRITE_BUDGET_LABEL = "the owner's reading of the write limit";
  const { res, text } = await page();
  assert.equal(res._status, 200);
  assert.match(text, /Promises and capacity/);
  assert.match(text, /in a signed checkpoint of its log within 36 hours\. \(checkpoints are published once a day\)/);
  assert.match(text, /In the last hour this witness made 0 GitHub writes: 0 to the public record and 0 to its private bookkeeping\./);
  assert.match(text, /Against a budget of 500 an hour \(the owner&#39;s reading of the write limit\)|Against a budget of 500 an hour \(the owner's reading of the write limit\)/);
});

test("PAGE: unset, it says no promise and no budget, and promises nothing", async () => {
  const { text } = await page();
  assert.match(text, /publishes no merge delay promise/);
  assert.match(text, /No write budget is set, so no headroom is given\./);
});

test("JSON: the twin carries the same facts and the same words", async () => {
  process.env.WITNESS_MERGE_DELAY_HOURS = "48";
  const { body } = await page({ format: "json" });
  const j = typeof body === "string" ? JSON.parse(body) : body;
  assert.deepEqual({ set: j.merge_delay_promise.set, hours: j.merge_delay_promise.hours }, { set: true, hours: 48 });
  assert.equal(j.merge_delay_promise.words, plain.promiseWords(plain.promiseFromEnv()));
  assert.equal(j.capacity.complete, true);
  assert.match(j.capacity.words, /0 GitHub writes/);
});

test("WORDS: a bad promise setting promises nothing and names the setting", () => {
  for (const bad of ["0", "-3", "1.5", "lots", "9000"]) {
    const p = plain.promiseFromEnv({ WITNESS_MERGE_DELAY_HOURS: bad });
    assert.equal(p.set, false, bad);
    assert.match(plain.promiseWords(p), /cannot be read \(WITNESS_MERGE_DELAY_HOURS\), so this witness promises nothing/);
  }
  assert.match(plain.promiseWords(plain.promiseFromEnv({ WITNESS_MERGE_DELAY_HOURS: "1" })), /within 1 hour\./);
});

test("WORDS: a count that could not be read is never a 0, and no headroom is given then", () => {
  const w = plain.capacityWords({ complete: false, could_not_count: { public: "http_502" }, writes: { public: null, private: 3, total: null },
    budget: { set: true, per_hour: 100, label: "x" }, used_fraction: null, headroom: null });
  assert.match(w, /the public write count could not be read, so no total is given/);
  assert.doesNotMatch(w, /\b0 GitHub writes|percent/);
  assert.match(plain.capacityWords(null), /could not be gathered/);
  const ok = plain.capacityWords({ complete: true, writes: { public: 30, private: 20, total: 50 },
    budget: { set: true, per_hour: 200, label: "budget" }, used_fraction: 0.25, headroom: 150 });
  assert.match(ok, /50 GitHub writes: 30 to the public record and 20 to its private bookkeeping\. Against a budget of 200 an hour \(budget\), that is 25 percent, leaving 150\./);
  const bad = plain.capacityWords({ complete: true, writes: { public: 1, private: 0, total: 1 },
    budget: { set: false, error: "e", field: "WITNESS_WRITE_BUDGET_PER_HOUR" } });
  assert.match(bad, /1 GitHub write: .*cannot be read \(WITNESS_WRITE_BUDGET_PER_HOUR\)/);
});
