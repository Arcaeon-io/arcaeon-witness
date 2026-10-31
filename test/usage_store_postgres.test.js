// test/usage_store_postgres.test.js — WITNESS_USAGE_STORE=postgres: the meter,
// the pending batch and the seal claim live in the usage_docs table instead of
// the private GitHub repo (WITNESS_METER_OFF_GITHUB.md).
//
// The headline numbers are the WRITES PER PIN tests: the same pins, counted on
// the same store fakes, once with the flag off and once with it on.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_KEYS = "testkeyA:demo-";
delete process.env.WITNESS_PLANS;
delete process.env.WITNESS_CADENCE;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const { MockGitHubStore } = require("./helpers/mock_store.js");
const { MockPostgrest, installBoth, PG_URL } = require("./helpers/mock_postgrest.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const usageStore = require("../lib/_usage_store.js");
const meter = require("../lib/_meter.js");
const pending = require("../lib/_pending.js");
const sealer = require("../lib/_sealer.js");
const batch = require("../lib/_batch.js");
const pinHandler = require("../api/pin.js");

const PIN_REPO = process.env.GITHUB_PIN_REPO;
const USAGE_REPO = process.env.GITHUB_USAGE_REPO;
const SECRET = "service-role-secret-do-not-print";

let gh;
let pg;
let restore;
const realPutSleep = store._putRetry.sleep;
const ENV_KEYS = ["WITNESS_USAGE_STORE", "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "WITNESS_BATCH_SHADOW"];
let savedEnv;

function flagOn() {
  process.env.WITNESS_USAGE_STORE = "postgres";
  process.env.SUPABASE_URL = PG_URL;
  process.env.SUPABASE_SERVICE_ROLE_KEY = SECRET;
}

beforeEach(() => {
  savedEnv = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  gh = new MockGitHubStore();
  pg = new MockPostgrest();
  restore = installBoth(gh, pg);
  store._putRetry.sleep = async () => {};
});

afterEach(() => {
  store._putRetry.sleep = realPutSleep;
  restore();
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

function pinReq(namespace, rows, chain) {
  return makeReq({ method: "POST", headers: { authorization: "Bearer testkeyA" }, body: { namespace, rows, chain } });
}

async function pinOk(namespace, rows, chain) {
  const res = makeRes();
  await pinHandler(pinReq(namespace, rows, chain), res);
  assert.equal(res._status, 201, JSON.stringify(res._body));
  return res;
}

function count(repo) {
  return gh.putLog.filter((p) => p.repo === repo).length;
}

// Writes taken by a run of pins on a namespace already past its first pin
// (the first pin also binds the deadline owner, a one time public write).
async function writesForPins(n) {
  await pinOk("demo-count", 1, "00000001");
  const before = { pub: count(PIN_REPO), priv: count(USAGE_REPO), pg: pg.writeLog.length };
  for (let i = 2; i < 2 + n; i++) await pinOk("demo-count", i, `0000000${i}`.slice(-8));
  return {
    pub: count(PIN_REPO) - before.pub,
    priv: count(USAGE_REPO) - before.priv,
    pg: pg.writeLog.length - before.pg,
  };
}

// ---------------------------------------------------------------------------
// WRITES PER PIN, before and after
// ---------------------------------------------------------------------------

test("WRITES PER PIN, flag off (before): 2 public + 2 private GitHub writes, 0 database writes", async () => {
  process.env.WITNESS_BATCH_SHADOW = "on";
  const w = await writesForPins(5);
  assert.deepEqual(w, { pub: 10, priv: 10, pg: 0 }, "per pin: seq record + latest.json public, meter + pending private");
});

test("WRITES PER PIN, flag on (after): 2 public GitHub writes, 0 private GitHub writes, 2 database writes", async () => {
  process.env.WITNESS_BATCH_SHADOW = "on";
  flagOn();
  const w = await writesForPins(5);
  assert.deepEqual(w, { pub: 10, priv: 0, pg: 10 }, "a pin costs only its public writes on GitHub");
});

test("WRITES PER PIN, flag on, shadow run off: 2 public, 0 private, 1 database write (the meter)", async () => {
  flagOn();
  const w = await writesForPins(3);
  assert.deepEqual(w, { pub: 6, priv: 0, pg: 3 });
});

test("the public record of a pin is byte for byte the same with the flag on or off", async () => {
  await pinOk("demo-same", 7, "abcdef01");
  const off = gh.read(PIN_REPO, "pins/demo-same/latest.json");
  gh = new MockGitHubStore();
  restore();
  restore = installBoth(gh, pg);
  flagOn();
  await pinOk("demo-same", 7, "abcdef01");
  const on = gh.read(PIN_REPO, "pins/demo-same/latest.json");
  // Only the clock differs between the two runs.
  const strip = (r) => JSON.stringify(r).replace(/\d{4}-\d\d-\d\dT[0-9:.]+Z/g, "T");
  assert.equal(strip(on), strip(off));
});

// ---------------------------------------------------------------------------
// The meter on Postgres
// ---------------------------------------------------------------------------

test("METER: the cap holds on Postgres, a denial writes nothing, and the count is in the table", async () => {
  flagOn();
  process.env.WITNESS_PLANS = JSON.stringify({ [meter.keyHash("k")]: { plan: "free", monthly_cap: 2 } });
  try {
    assert.equal((await meter.check("k")).used, 1);
    assert.equal((await meter.check("k")).used, 2);
    const writes = pg.writeLog.length;
    const denied = await meter.check("k");
    assert.equal(denied.ok, false);
    assert.equal(denied.reason, "over_cap");
    assert.equal(pg.writeLog.length, writes, "a denial never writes");
    const path = `usage/${meter.keyHash("k")}/${meter.utcMonth()}.json`;
    assert.equal(pg.read(path).used, 2);
    assert.equal(gh.putLog.length, 0, "nothing reached GitHub");
    assert.equal((await meter.peek("k")).used, 2);
  } finally {
    delete process.env.WITNESS_PLANS;
  }
});

test("METER: a lost update race re-reads and counts once; two lost races fail rather than drop the count", async () => {
  flagOn();
  await meter.check("racer"); // row exists at version 1
  const path = `usage/${meter.keyHash("racer")}/${meter.utcMonth()}.json`;
  pg.raceNext(1);
  const r = await meter.check("racer");
  assert.equal(r.ok, true);
  pg.raceNext(2);
  await assert.rejects(() => meter.check("racer"), (e) => e.conflict === true);
  assert.equal(pg.read(path).used, 2);
});

test("METER: a damaged row fails closed, it never reads as nothing used", async () => {
  flagOn();
  const path = `usage/${meter.keyHash("dmg")}/${meter.utcMonth()}.json`;
  pg.seed(path, { used: "lots" });
  await assert.rejects(() => meter.check("dmg"));
  assert.deepEqual(pg.read(path), { used: "lots" }, "not overwritten");
});

test("FAIL CLOSED: database down means the pin is refused 502 and nothing public is written", async () => {
  flagOn();
  pg.failNext(1, 503);
  const res = makeRes();
  await pinHandler(pinReq("demo-down", 3, "aaaaaaaa"), res);
  assert.equal(res._status, 502);
  assert.match(res._body.error, /metering store error: meter store read failed \(503\)/);
  assert.equal(count(PIN_REPO), 0, "the meter is checked before any public write");
  assert.equal(gh.has(PIN_REPO, "pins/demo-down/latest.json"), false);
  assert.equal(gh.has(PIN_REPO, "pins/demo-down/000001.json"), false);
});

test("FAIL CLOSED: flag on with no database configured refuses the pin, never falls back to GitHub", async () => {
  process.env.WITNESS_USAGE_STORE = "postgres";
  const res = makeRes();
  await pinHandler(pinReq("demo-nocfg", 3, "aaaaaaaa"), res);
  assert.equal(res._status, 502);
  assert.match(res._body.error, /not configured/);
  assert.equal(count(USAGE_REPO), 0);
  assert.equal(gh.has(PIN_REPO, "pins/demo-nocfg/latest.json"), false);
});

test("FAIL CLOSED: an unknown WITNESS_USAGE_STORE value is refused, not read as github", async () => {
  process.env.WITNESS_USAGE_STORE = "sqlite";
  assert.throws(() => usageStore.backend(), /must be github or postgres/);
  const res = makeRes();
  await pinHandler(pinReq("demo-typo", 3, "aaaaaaaa"), res);
  assert.equal(res._status, 502);
  assert.equal(count(USAGE_REPO), 0);
});

// ---------------------------------------------------------------------------
// The store contract itself
// ---------------------------------------------------------------------------

test("CONTRACT: create if absent, update if unchanged, both races flagged as conflict", async () => {
  flagOn();
  assert.equal(await usageStore.read("pending/x.json"), null);
  await usageStore.write("pending/x.json", { a: 1 }, undefined, "create");
  await assert.rejects(() => usageStore.write("pending/x.json", { a: 2 }, undefined, "create again"),
    (e) => e.conflict === true);
  const cur = await usageStore.read("pending/x.json");
  assert.deepEqual(cur, { json: { a: 1 }, sha: "pg:1" });
  await usageStore.write("pending/x.json", { a: 3 }, cur.sha, "update");
  await assert.rejects(() => usageStore.write("pending/x.json", { a: 4 }, cur.sha, "stale"),
    (e) => e.conflict === true);
  assert.deepEqual(await usageStore.read("pending/x.json"), { json: { a: 3 }, sha: "pg:2" });
});

test("CONTRACT: a GitHub sha is never written over a Postgres row", async () => {
  flagOn();
  await usageStore.write("pending/y.json", { a: 1 }, undefined, "create");
  await assert.rejects(() => usageStore.write("pending/y.json", { a: 2 }, "0123abcd", "wrong backend"),
    (e) => e.conflict !== true && /not a postgres version/.test(e.message));
  assert.deepEqual(pg.read("pending/y.json"), { a: 1 });
});

test("CONTRACT: an unreadable store throws unreadable; it never answers absent", async () => {
  flagOn();
  pg.failNext(1, 500);
  await assert.rejects(() => usageStore.read("pending/z.json"), (e) => e.unreadable === true);
  pg.seed("pending/v.json", { a: 1 }, 0);
  await assert.rejects(() => usageStore.read("pending/v.json"), (e) => e.unreadable === true);
});

test("SECRET: the service role key goes in headers only, never in an error, a return or a log", async () => {
  flagOn();
  const logs = [];
  const realErr = console.error;
  console.error = (...a) => logs.push(a.join(" "));
  const seen = [];
  try {
    seen.push(JSON.stringify(await usageStore.write("pending/s.json", { a: 1 }, undefined, "m")));
    pg.failNext(3, 500);
    for (const f of [
      () => usageStore.read("pending/s.json"),
      () => usageStore.write("pending/s.json", { a: 1 }, "pg:1", "m"),
      () => usageStore.write("pending/t.json", { a: 1 }, undefined, "m"),
    ]) {
      try { await f(); } catch (e) { seen.push(e.message); }
    }
  } finally {
    console.error = realErr;
  }
  for (const s of [...seen, ...logs]) assert.ok(!s.includes(SECRET), `leaked in: ${s}`);
  assert.ok(pg.requests.every((r) => r.headers.apikey === SECRET), "the key is sent as apikey");
});

test("PRIVACY: an error message never carries the meter's key hash path", async () => {
  flagOn();
  pg.failNext(1, 500);
  const res = makeRes();
  await pinHandler(pinReq("demo-priv", 3, "aaaaaaaa"), res);
  assert.equal(res._status, 502);
  assert.ok(!JSON.stringify(res._body).includes(meter.keyHash("testkeyA")));
});

// ---------------------------------------------------------------------------
// The pending batch and the sealer on Postgres
// ---------------------------------------------------------------------------

test("SEALER: leaves accumulate in Postgres, the seal publishes one root on GitHub, the claim lives in Postgres", async () => {
  process.env.WITNESS_BATCH_SHADOW = "on";
  flagOn();
  await pinOk("demo-sa", 10, "aaaaaaaa");
  await pinOk("demo-sb", 20, "bbbbbbbb");
  const doc = pg.read(pending.PENDING_PATH);
  assert.equal(doc.open.leaves.length, 2);
  assert.equal(gh.has(USAGE_REPO, pending.PENDING_PATH), false);

  const opened = Date.parse(doc.open.opened_at);
  const r = await sealer.sealOnce({ now: new Date(opened + 61_000) });
  assert.equal(r.sealed, true, JSON.stringify(r));
  assert.equal(r.tree_size, 2);
  assert.ok(gh.has(PIN_REPO, batch.rootPath(1)));
  assert.equal(count(USAGE_REPO), 0, "no private GitHub write during the seal either");
  assert.ok(pg.read("pending/seal_claim.json"), "the claim was taken in Postgres");
  const after = pg.read(pending.PENDING_PATH);
  assert.equal(after.open.batch_id, 2);
  assert.equal(after.sealing, null);
});

test("SEALER: Postgres unreadable means the sealer refuses and writes nothing", async () => {
  flagOn();
  pg.failNext(1, 500);
  const r = await sealer.sealOnce({ now: new Date() });
  assert.equal(r.sealed, false);
  assert.equal(r.reason, "pending_head_unreadable");
  assert.equal(gh.putLog.length, 0);
});

test("PENDING: a conflicting leaf is refused from the tree on Postgres too", async () => {
  process.env.WITNESS_BATCH_SHADOW = "on";
  flagOn();
  await pinOk("demo-pc", 5, "aaaaaaaa");
  assert.equal(pg.read(pending.PENDING_PATH).open.leaves.length, 1);
  // The same rows with another chain, as a second instance with a stale view
  // of the committed record would hand it over.
  const real = gh.read(PIN_REPO, "pins/demo-pc/latest.json");
  const b = await pending.recordAccepted({ ...real, chain: "bbbbbbbb", seq: real.seq + 1 });
  assert.equal(b.refused, true);
  assert.equal(b.reason, "pending_head_conflict");
  assert.equal(pg.read(pending.PENDING_PATH).open.leaves.length, 1);
});

// ---------------------------------------------------------------------------
// The cutover: the flag turns on mid month
// ---------------------------------------------------------------------------

test("CUTOVER: this month's GitHub count is adopted, not reset; GitHub is read, never written", async () => {
  const path = `usage/${meter.keyHash("testkeyA")}/${meter.utcMonth()}.json`;
  gh.seed(USAGE_REPO, path, { used: 7, month: meter.utcMonth(), plan: "free" });
  flagOn();
  const r = await meter.check("testkeyA");
  assert.equal(r.used, 8, "counts on from 7, never from 0");
  assert.equal(pg.read(path).used, 8);
  assert.equal(gh.read(USAGE_REPO, path).used, 7, "the old file is left as it was");
  assert.equal(count(USAGE_REPO), 0);
});

test("CUTOVER: a key at its cap on GitHub stays at its cap after the flag turns on", async () => {
  process.env.WITNESS_PLANS = JSON.stringify({ [meter.keyHash("full")]: { plan: "free", monthly_cap: 3 } });
  try {
    gh.seed(USAGE_REPO, `usage/${meter.keyHash("full")}/${meter.utcMonth()}.json`, { used: 3 });
    flagOn();
    const r = await meter.check("full");
    assert.equal(r.ok, false);
    assert.equal(r.reason, "over_cap");
  } finally {
    delete process.env.WITNESS_PLANS;
  }
});

test("CUTOVER: two first pins at once adopt one row and count twice", async () => {
  const path = `usage/${meter.keyHash("pair")}/${meter.utcMonth()}.json`;
  gh.seed(USAGE_REPO, path, { used: 7 });
  flagOn();
  const rs = await Promise.all([meter.check("pair"), meter.check("pair")]);
  assert.ok(rs.every((r) => r.ok));
  assert.equal(pg.read(path).used, 9);
});

test("CUTOVER: the old store unreadable at cutover refuses the pin, it never counts from zero", async () => {
  const path = `usage/${meter.keyHash("testkeyA")}/${meter.utcMonth()}.json`;
  gh.seed(USAGE_REPO, path, { used: 7 });
  gh.handleFetch = async () => ({ status: 500, ok: false, json: async () => ({}), text: async () => "" });
  flagOn();
  await assert.rejects(() => meter.check("testkeyA"), (e) => e.unreadable === true);
  assert.equal(pg.read(path), null);
});

test("CUTOVER: an open batch on GitHub is adopted with its leaves and sealed from Postgres", async () => {
  process.env.WITNESS_BATCH_SHADOW = "on";
  await pinOk("demo-cut", 4, "cccccccc"); // flag off: the leaf lands on GitHub
  assert.equal(gh.read(USAGE_REPO, pending.PENDING_PATH).open.leaves.length, 1);
  flagOn();
  await pinOk("demo-cut", 5, "dddddddd");
  const doc = pg.read(pending.PENDING_PATH);
  assert.equal(doc.open.leaves.length, 2, "the GitHub leaf came along");
  const r = await sealer.sealOnce({ now: new Date(Date.parse(doc.open.opened_at) + 61_000) });
  assert.equal(r.sealed, true, JSON.stringify(r));
  assert.equal(r.tree_size, 2);
});
