// test/ratelimit_shared.test.js — lib/_ratelimit.js checkShared (owner job
// 16): the per IP limit on the public read endpoints, one count shared by
// every instance with WITNESS_USAGE_STORE=postgres, per instance otherwise.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const { MockGitHubStore } = require("./helpers/mock_store.js");
const { MockPostgrest, installBoth, PG_URL } = require("./helpers/mock_postgrest.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");

const ENV = ["WITNESS_USAGE_STORE", "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"];
let gh, pg, restore, saved;
const T0 = Date.UTC(2026, 9, 31, 10, 0, 0);

function flagOn() {
  process.env.WITNESS_USAGE_STORE = "postgres";
  process.env.SUPABASE_URL = PG_URL;
  process.env.SUPABASE_SERVICE_ROLE_KEY = "srk";
}
// A fresh copy of the limiter is what another warm instance is: its own Map.
function instance() {
  delete require.cache[require.resolve("../lib/_ratelimit.js")];
  return require("../lib/_ratelimit.js");
}
const req = (ip) => makeReq({ method: "GET", headers: { "x-forwarded-for": ip } });

beforeEach(() => {
  saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  for (const k of ENV) delete process.env[k];
  gh = new MockGitHubStore();
  pg = new MockPostgrest();
  restore = installBoth(gh, pg);
});
afterEach(() => {
  restore();
  for (const k of ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
});

test("SHARED: three instances share one count per IP; the call past the limit is refused wherever it lands", async () => {
  flagOn();
  const inst = [instance(), instance(), instance()];
  const limit = inst[0].LIMIT;
  for (let i = 0; i < limit; i++) {
    const r = await inst[i % 3].checkShared(req("10.1.1.1"), 1, { now: T0 + i });
    assert.equal(r.limited, false, `call ${i + 1}`);
    assert.equal(r.shared, true);
  }
  for (const r of inst) assert.equal((await r.checkShared(req("10.1.1.1"), 1, { now: T0 + 999 })).limited, true);
  assert.equal((await inst[0].checkShared(req("10.1.1.2"), 1, { now: T0 })).limited, false, "another IP has its own count");
});

test("SHARED: a weighted call spends its weight from the same count, and a new slot starts fresh", async () => {
  flagOn();
  const r = instance();
  const limit = r.LIMIT;
  assert.equal((await r.checkShared(req("10.2.2.2"), limit, { now: T0 })).limited, false);
  assert.equal((await r.checkShared(req("10.2.2.2"), 1, { now: T0 + 1 })).limited, true);
  assert.equal((await r.checkShared(req("10.2.2.2"), 1, { now: T0 + r.WINDOW_MS })).limited, false);
});

test("SHARED: only a hash of the IP reaches the database", async () => {
  flagOn();
  await instance().checkShared(req("203.0.113.7"), 1, { now: T0 });
  const call = pg.rpcLog.find((c) => c.fn === "ip_rate_hit");
  assert.ok(!JSON.stringify(call).includes("203.0.113.7"));
  assert.equal(call.args.p_ip_hash, crypto.createHash("sha256").update("ip-rate:v1\n203.0.113.7").digest("hex"));
  assert.equal(call.args.p_window_start, new Date(T0).toISOString());
});

test("FALLBACK: the database down limits per instance, never not at all", async () => {
  flagOn();
  const r = instance();
  const logs = [];
  const orig = console.error;
  console.error = (...a) => logs.push(a.join(" "));
  try {
    pg.failNext(1000, 503);
    let last;
    for (let i = 0; i <= r.LIMIT; i++) last = await r.checkShared(req("10.3.3.3"), 1, { now: T0 });
    assert.equal(last.limited, true, "the local count still limits");
    assert.equal(last.shared, false);
    assert.ok(logs.some((l) => l.includes("limited per instance")));
  } finally {
    console.error = orig;
  }
});

test("FLAG OFF: it is the old per instance check, and makes no database call", async () => {
  const a = instance();
  const b = instance();
  for (let i = 0; i <= a.LIMIT; i++) await a.checkShared(req("10.4.4.4"));
  assert.equal((await a.checkShared(req("10.4.4.4"))).limited, true);
  assert.equal((await b.checkShared(req("10.4.4.4"))).limited, false, "another instance counts alone");
  assert.equal(pg.rpcLog.length, 0);
});

test("ENDPOINTS: the read endpoints use the shared count", async () => {
  flagOn();
  for (const [name, handler, query] of [["latest", "../api/latest.js", { ns: "demo-x" }], ["health", "../api/health.js", {}],
    ["badge", "../api/badge.js", { ns: "demo-x" }], ["verify", "../api/verify.js", { ns: "demo-x", rows: "1", chain: "ab".repeat(32) }]]) {
    const before = pg.rpcLog.length;
    const res = makeRes();
    await require(handler)(makeReq({ method: "GET", query, headers: { "x-forwarded-for": `10.9.9.${before % 250}` } }), res);
    assert.ok(pg.rpcLog.slice(before).some((c) => c.fn === "ip_rate_hit"), `${name} asked the shared count`);
  }
});
