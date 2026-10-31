// test/pin_ratelimit.test.js — lib/_pin_ratelimit.js: 60 pins per key per
// clock hour, one shared count across warm instances when
// WITNESS_USAGE_STORE=postgres, per instance otherwise.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_KEYS = "testkeyA:demo-,testkeyB:demo-";
process.env.WITNESS_PLANS = "{}";
delete process.env.WITNESS_CADENCE;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const { MockGitHubStore } = require("./helpers/mock_store.js");
const { MockPostgrest, installBoth, PG_URL } = require("./helpers/mock_postgrest.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const pinRate = require("../lib/_pin_ratelimit.js");

const ENV_KEYS = ["WITNESS_USAGE_STORE", "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "WITNESS_BATCH_SHADOW"];
let gh, pg, restore, saved;
const realPutSleep = store._putRetry.sleep;
const HOUR = 3600_000;
const T0 = Date.UTC(2026, 9, 31, 10, 0, 0);

function flagOn() {
  process.env.WITNESS_USAGE_STORE = "postgres";
  process.env.SUPABASE_URL = PG_URL;
  process.env.SUPABASE_SERVICE_ROLE_KEY = "srk";
}

// A fresh copy of the modules is what a second warm instance is: its own
// module scope, its own Map, the same database.
function freshInstance() {
  for (const m of ["../lib/_pin_ratelimit.js", "../api/pin.js"]) delete require.cache[require.resolve(m)];
  return { rate: require("../lib/_pin_ratelimit.js"), pin: require("../api/pin.js") };
}

beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  gh = new MockGitHubStore();
  pg = new MockPostgrest();
  restore = installBoth(gh, pg);
  store._putRetry.sleep = async () => {};
  pinRate._buckets.clear();
});

afterEach(() => {
  store._putRetry.sleep = realPutSleep;
  restore();
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

test("THE NUMBER: 60 per key per clock hour", () => {
  assert.equal(pinRate.RATE_LIMIT, 60);
  assert.equal(pinRate.WINDOW_MS, HOUR);
});

test("SHARED: three instances share one count; the 61st pin in the hour is refused wherever it lands", async () => {
  flagOn();
  const inst = [freshInstance().rate, freshInstance().rate, freshInstance().rate];
  for (let i = 0; i < 60; i++) {
    const r = await inst[i % 3].check("testkeyA", { now: T0 + i * 1000 });
    assert.equal(r.limited, false, `pin ${i + 1}`);
    assert.equal(r.shared, true);
  }
  for (const r of inst) {
    const over = await r.check("testkeyA", { now: T0 + 61_000 });
    assert.equal(over.limited, true);
    assert.ok(over.retryAfterSeconds > 0 && over.retryAfterSeconds <= 3600);
  }
});

test("PER INSTANCE (flag off): each instance counts alone, as documented", async () => {
  const a = freshInstance().rate;
  const b = freshInstance().rate;
  for (let i = 0; i < 60; i++) await a.check("testkeyA", { now: T0 });
  assert.equal((await a.check("testkeyA", { now: T0 })).limited, true);
  const onB = await b.check("testkeyA", { now: T0 });
  assert.equal(onB.limited, false, "the other instance has its own count");
  assert.equal(onB.shared, false);
  assert.equal(pg.rpcLog.length, 0, "no database call with the flag off");
});

test("WINDOW: a new clock hour starts a new count, in both modes", async () => {
  for (const mode of ["off", "on"]) {
    if (mode === "on") flagOn();
    const r = freshInstance().rate;
    for (let i = 0; i < 61; i++) await r.check("testkeyB", { now: T0 + HOUR - 61_000 + i * 1000 });
    assert.equal((await r.check("testkeyB", { now: T0 + HOUR - 1 })).limited, true, mode);
    assert.equal((await r.check("testkeyB", { now: T0 + HOUR })).limited, false, mode);
  }
});

test("KEYS: one key's count never touches another's, and only the key's hash reaches the database", async () => {
  flagOn();
  const r = freshInstance().rate;
  for (let i = 0; i < 61; i++) await r.check("testkeyA", { now: T0 });
  assert.equal((await r.check("testkeyB", { now: T0 })).limited, false);
  const hashA = crypto.createHash("sha256").update("testkeyA").digest("hex");
  assert.ok(pg.rpcLog.every((c) => !JSON.stringify(c).includes("testkeyA")));
  assert.equal(pg.rpcLog[0].args.p_key_hash, hashA);
  assert.equal(pg.rpcLog[0].args.p_window_start, new Date(T0).toISOString());
});

test("FAIL CLOSED: an unreadable count refuses, it is never read as under the limit", async () => {
  flagOn();
  const r = freshInstance().rate;
  pg.failNext(1, 500);
  assert.equal((await r.check("testkeyA")).error, true);
  for (const bad of [null, 0, -1, "5", 1.5, [], {}]) {
    pg.handleFetch = async () => ({ status: 200, ok: true, json: async () => bad, text: async () => JSON.stringify(bad) });
    const out = await r.check("testkeyA");
    assert.equal(out.error, true, `answer ${JSON.stringify(bad)}`);
    assert.equal(out.reason, "rate_limit_store_unreachable");
  }
});

test("HANDLER: the 61st pin is a 429 naming the limit and the window, with Retry-After, and writes nothing", async () => {
  flagOn();
  const { pin } = freshInstance();
  const hashA = crypto.createHash("sha256").update("testkeyA").digest("hex");
  const start = new Date(pinRate.windowStart(Date.now())).toISOString();
  pg.rateWindows.set(`${hashA}|${start}`, 60); // 60 pins already, on other instances
  const before = gh.putLog.length;
  const res = makeRes();
  await pin(makeReq({ method: "POST", headers: { authorization: "Bearer testkeyA" },
    body: { namespace: "demo-rl", rows: 1, chain: "aaaaaaaa" } }), res);
  assert.equal(res._status, 429);
  assert.equal(res._body.reason, "key_rate_limited");
  assert.equal(res._body.limit, 60);
  assert.equal(res._body.window_seconds, 3600);
  assert.equal(res._body.shared_across_instances, true);
  assert.ok(Number(res._headers["retry-after"] || res._headers["Retry-After"]) > 0);
  assert.equal(gh.putLog.length, before);
  assert.equal(pg.writeLog.length, 0, "not metered");
});

test("HANDLER: under the limit the pin goes through, flag on and flag off", async () => {
  for (const mode of ["off", "on"]) {
    if (mode === "on") flagOn();
    const { pin } = freshInstance();
    const res = makeRes();
    await pin(makeReq({ method: "POST", headers: { authorization: "Bearer testkeyA" },
      body: { namespace: `demo-ok${mode}`, rows: 1, chain: "aaaaaaaa" } }), res);
    assert.equal(res._status, 201, mode + " " + JSON.stringify(res._body));
  }
});
