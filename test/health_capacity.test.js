// test/health_capacity.test.js — GET /api/health?view=capacity: GitHub writes
// in the last hour against a labelled budget (lib/_capacity.js).
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_KEYS = "testkeyA:demo-";
delete process.env.WITNESS_PLANS;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const capacity = require("../lib/_capacity.js");
const healthHandler = require("../api/health.js");
const pinHandler = require("../api/pin.js");

let gh, restore, ip = 0;
const realPutSleep = store._putRetry.sleep;
beforeEach(() => {
  delete process.env.WITNESS_WRITE_BUDGET_PER_HOUR;
  delete process.env.WITNESS_WRITE_BUDGET_LABEL;
  gh = new MockGitHubStore();
  // repoReachable reads GET /repos/<repo>; the mock answers 404 for paths it
  // does not know, so give it the one it needs.
  const inner = gh.handleFetch.bind(gh);
  gh.handleFetch = async (url, opts) =>
    /\/repos\/[^/]+\/[^/]+$/.test(new URL(String(url)).pathname)
      ? { status: 200, ok: true, json: async () => ({}), text: async () => "{}", headers: { get: () => null } }
      : inner(url, opts);
  restore = install(gh);
  store._putRetry.sleep = async () => {};
});
afterEach(() => {
  delete process.env.WITNESS_WRITE_BUDGET_PER_HOUR;
  delete process.env.WITNESS_WRITE_BUDGET_LABEL;
  store._putRetry.sleep = realPutSleep;
  restore();
});

async function health(query = { view: "capacity" }) {
  const res = makeRes();
  ip += 1;
  await healthHandler(makeReq({ method: "GET", query, headers: { "x-forwarded-for": `10.9.0.${ip}` } }), res);
  return res;
}
async function pins(n, ns = "demo-cap") {
  for (let i = 1; i <= n; i++) {
    const res = makeRes();
    await pinHandler(makeReq({ method: "POST", headers: { authorization: "Bearer testkeyA" },
      body: { namespace: ns, rows: i, chain: `0000000${i}`.slice(-8) } }), res);
    assert.equal(res._status, 201);
  }
}

test("COUNTED: writes in the last hour are the real commits, public and private apart", async () => {
  await pins(3);
  const pub = gh.putLog.filter((p) => p.repo === "test-owner/test-pins").length;
  const priv = gh.putLog.filter((p) => p.repo === "test-owner/test-usage").length;
  const res = await health();
  assert.equal(res._status, 200);
  const c = res._body.capacity;
  assert.equal(c.writes.public, pub);
  assert.equal(c.writes.private, priv);
  assert.equal(c.writes.total, pub + priv);
  assert.equal(c.complete, true);
});

test("WINDOW: a write older than an hour is not counted", async () => {
  const t = Date.now();
  gh.now = () => t - 3600_000 - 5000;
  await pins(2);
  gh.now = () => t;
  await pins(1, "demo-cap2");
  const res = await health();
  const recent = gh.putLog.filter((p) => p.at >= t - 3600_000).length;
  assert.equal(res._body.capacity.writes.total, recent);
  assert.ok(recent < gh.putLog.length);
});

test("BUDGET: a labelled budget gives used fraction and headroom", async () => {
  process.env.WITNESS_WRITE_BUDGET_PER_HOUR = "500";
  process.env.WITNESS_WRITE_BUDGET_LABEL = "owner's reading of the content write limit, Oct 2026";
  await pins(2);
  const c = (await health())._body.capacity;
  assert.deepEqual(c.budget, { set: true, per_hour: 500, label: "owner's reading of the content write limit, Oct 2026", source: "WITNESS_WRITE_BUDGET_PER_HOUR" });
  assert.equal(c.headroom, 500 - c.writes.total);
  assert.equal(c.used_fraction, Math.round((c.writes.total / 500) * 1000) / 1000);
});

test("BUDGET: unset says so, and nothing is made up", async () => {
  const c = (await health())._body.capacity;
  assert.equal(c.budget.set, false);
  assert.equal(c.used_fraction, null);
  assert.equal(c.headroom, null);
});

test("BUDGET: a budget without a label is shown as unlabelled", async () => {
  process.env.WITNESS_WRITE_BUDGET_PER_HOUR = "100";
  const c = (await health())._body.capacity;
  assert.match(c.budget.label, /^unlabelled/);
});

test("BUDGET: a bad budget is refused by name and not used", async () => {
  for (const bad of ["0", "-5", "12.5", "lots"]) {
    process.env.WITNESS_WRITE_BUDGET_PER_HOUR = bad;
    const c = (await health())._body.capacity;
    assert.equal(c.budget.set, false, bad);
    assert.equal(c.budget.field, "WITNESS_WRITE_BUDGET_PER_HOUR");
    assert.equal(c.headroom, null);
  }
});

test("COULD NOT COUNT: a failed count is null with a reason, never 0, and no fraction is given", async () => {
  process.env.WITNESS_WRITE_BUDGET_PER_HOUR = "100";
  await pins(1);
  gh.commitsStatus = 502;
  const c = (await health())._body.capacity;
  assert.equal(c.writes.public, null);
  assert.equal(c.writes.total, null);
  assert.equal(c.complete, false);
  assert.equal(c.could_not_count.public, "http_502");
  assert.equal(c.used_fraction, null);
  assert.equal(c.headroom, null);
});

test("ZERO: no commits in the window is a counted 0, and complete", async () => {
  const c = (await health())._body.capacity;
  assert.equal(c.writes.total, 0);
  assert.equal(c.complete, true);
});

test("PLAIN HEALTH UNCHANGED: without view there is no capacity block and no commits call", async () => {
  const res = await health({});
  assert.equal(res._status, 200);
  assert.equal(res._body.capacity, undefined);
  assert.equal(res._body.ok, true);
});

test("UNKNOWN VIEW: refused 400 naming the field", async () => {
  const res = await health({ view: "everything" });
  assert.equal(res._status, 400);
  assert.equal(res._body.field, "view");
});

test("LINK HEADER: the count is the last page number", () => {
  assert.equal(capacity.lastPage('<https://x/commits?per_page=1&page=2>; rel="next", <https://x/commits?per_page=1&page=37>; rel="last"'), 37);
  assert.equal(capacity.lastPage(null), null);
  assert.equal(capacity.lastPage('<https://x?page=2>; rel="next"'), null);
});
