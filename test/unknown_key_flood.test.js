// test/unknown_key_flood.test.js: red hunt 2026-11-02, finding H1 (round 2).
//
// Any bearer value that missed WITNESS_KEYS reached lib/_keys.js
// issuedKeyPrefix: one GitHub contents read per guess, on GITHUB_PIN_TOKEN,
// the one token every paid pin, meter increment and credit debit use, and it
// ran BEFORE api/pin.js's own per key limiter. A stranger with no key could
// run the token's hourly quota down and every paying pin answered 502.
//
// These tests pin the fence AND the promise the fence must keep (review,
// round 2): a valid key always gets through once this instance has seen it,
// a never-seen valid key from an address over the cap waits at most a minute,
// a repeated bad key costs one read, the cap counts distinct guesses even
// under concurrency, the instance spends at most GLOBAL_READS_PER_MIN reads a
// minute whatever the addresses, and a flood of fresh addresses cannot evict
// the over-cap buckets doing the work.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_KEYS = "flood-env-key:env-";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.STAMP_FREE_PER_DAY = "0"; // every stamp needs a key: the paid path resolves the key
delete process.env.WITNESS_PLANS;
delete process.env.WITNESS_CADENCE;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const keys = require("../lib/_keys.js");
const stamp = require("../lib/_stamp.js");
const pinHandler = require("../api/pin.js");
const balanceHandler = require("../api/balance.js");

const USAGE = process.env.GITHUB_USAGE_REPO;
const ISSUED_KEY = "wk_" + "ab".repeat(24);
const ISSUED_KEY_2 = "wk_" + "cd".repeat(24);

let gh;
let restore;
let realPutSleep;
let ipCounter = 0;
function freshIp() {
  ipCounter += 1;
  return `198.51.100.${(ipCounter % 250) + 1}`;
}

// A controllable clock: the grace read, the caches and the global minute all
// read keys._clock.now(), so a test can move time without sleeping.
let fakeNow;
function advance(ms) {
  fakeNow += ms;
}

function seedIssued(key, prefix) {
  const hash = keys.keyHash(key);
  gh.seed(USAGE, `keys/${hash}.json`, {
    key_hash: hash, key_id: hash.slice(0, 12), namespace_prefix: prefix,
    plan: "free", org: null, pool_id: "pool_0000000000000000", source: "stripe-fulfill",
  });
}

beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
  keys._resetMissLimiterForTests();
  // The address-cap cases below need more than GLOBAL_READS_PER_MIN reads in
  // one fake minute; the instance-cap cases set the real value themselves.
  keys._setGlobalReadsPerMinForTests(1000);
  stamp._resetLimiterForTests();
  fakeNow = Date.now();
  keys._clock.now = () => fakeNow;
  realPutSleep = store._putRetry.sleep;
  store._putRetry.sleep = async () => {};
  seedIssued(ISSUED_KEY, "acme-");
  seedIssued(ISSUED_KEY_2, "zed-");
});

afterEach(() => {
  keys._clock.now = () => Date.now();
  store._putRetry.sleep = realPutSleep;
  restore();
});

function keyReads() {
  return gh.getLog.filter((p) => p.startsWith("keys/")).length;
}

async function pin(ip, key, over = {}) {
  const res = makeRes();
  await pinHandler(makeReq({
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "x-forwarded-for": ip },
    body: { namespace: over.namespace || "acme-main", rows: over.rows || 1, chain: over.chain || "a1b2c3d4" },
  }), res);
  return res;
}

async function balanceJson(ip, key) {
  const res = makeRes();
  await balanceHandler(makeReq({ method: "GET", headers: { authorization: `Bearer ${key}`, "x-forwarded-for": ip } }), res);
  return res;
}

let guessCounter = 0;
function guess() {
  guessCounter += 1;
  return `bogus-key-${guessCounter}`;
}

async function flood(ip, n) {
  const out = [];
  for (let i = 0; i < n; i++) out.push(await balanceJson(ip, guess()));
  return out;
}

// Puts an address over the cap AND spends its grace read, so the next
// never-seen key from it is refused.
async function exhaust(ip) {
  await flood(ip, keys.MISS_LIMIT + 1);
}

test("H1: MISS_LIMIT distinct unknown keys from one address each cost one read (401); the next is the grace read; then 429 with no read", async () => {
  const ip = freshIp();
  const first = await flood(ip, keys.MISS_LIMIT);
  for (const r of first) assert.equal(r._status, 401, "an unknown key is a plain 401 while under the cap");
  assert.equal(keyReads(), keys.MISS_LIMIT, "exactly one store read per distinct unknown key");

  const grace = await balanceJson(ip, guess());
  assert.equal(grace._status, 401, "over the cap, the first never-seen key in a minute is still looked up (the grace read)");
  assert.equal(keyReads(), keys.MISS_LIMIT + 1);

  const after = await flood(ip, 4);
  for (const r of after) {
    assert.equal(r._status, 429);
    assert.equal(r._body.reason, "unknown_key_rate_limited");
    assert.match(r._body.error, /if your key is valid, retry in about a minute, or send from another address/);
    assert.ok(Number.isInteger(r._body.retry_after_seconds) && r._body.retry_after_seconds > 0);
    assert.ok(r._body.retry_after_seconds <= keys.GRACE_READ_MS / 1000, "Retry-After is the grace minute, not the window end");
    assert.ok(r._headers["retry-after"], "Retry-After header set");
  }
  assert.equal(keyReads(), keys.MISS_LIMIT + 1, "a refused guess costs the store nothing");
});

test("H1 BLOCKER: a valid issued key from an address over the cap is served (positive cache), with no store read", async () => {
  const ip = freshIp();
  const seen = await balanceJson(ip, ISSUED_KEY);
  assert.equal(seen._status, 200);
  const readsAfterSeen = keyReads();
  await exhaust(ip);
  assert.equal((await balanceJson(ip, guess()))._status, 429, "the address is over the cap and its grace read is spent");

  const res = await balanceJson(ip, ISSUED_KEY);
  assert.equal(res._status, 200, "the customer's own valid key still works from the over-cap address");
  const pinned = await pin(ip, ISSUED_KEY, { namespace: "acme-main" });
  assert.equal(pinned._status, 201);
  assert.equal(keyReads(), readsAfterSeen + keys.MISS_LIMIT + 1, "no read for the cached valid key");
});

test("H1 BLOCKER: a valid key this instance has NEVER seen, from an over-cap address, gets the one grace read a minute: refused inside the minute, served after it", async () => {
  const ip = freshIp();
  await exhaust(ip); // over the cap, grace spent at fakeNow

  // Inside the grace minute: refused. This is the protection and the cost it
  // carries: a never-seen valid key behind a flooding address waits up to a
  // minute (never the full 10 minute window), and the body says so.
  const refused = await balanceJson(ip, ISSUED_KEY_2);
  assert.equal(refused._status, 429);
  assert.match(refused._body.error, /if your key is valid, retry in about a minute/);
  assert.ok(refused._body.retry_after_seconds <= 60, `Retry-After ${refused._body.retry_after_seconds} must be the grace minute, not the 10 minute window`);
  assert.equal(String(refused._headers["retry-after"]), String(refused._body.retry_after_seconds));

  advance(keys.GRACE_READ_MS + 1);
  const served = await balanceJson(ip, ISSUED_KEY_2);
  assert.equal(served._status, 200, "the grace read found the valid key");
  // And from then on it is cached: the address is still over the cap, the key still works.
  assert.equal((await balanceJson(ip, guess()))._status, 429);
  assert.equal((await pin(ip, ISSUED_KEY_2, { namespace: "zed-main" }))._status, 201);
});

test("H1: a REPEATED bad key costs one read and one count (negative cache), and the cap counts distinct guesses", async () => {
  const ip = freshIp();
  const same = "bogus-repeated-key";
  for (let i = 0; i < keys.MISS_LIMIT * 2; i++) {
    const r = await balanceJson(ip, same);
    assert.equal(r._status, 401, "a retried wrong key stays a plain 401, never 429");
  }
  assert.equal(keyReads(), 1, "one read for forty retries of one bad key");
  // Only one distinct guess has been counted: the address is nowhere near the cap.
  const fresh = await balanceJson(ip, guess());
  assert.equal(fresh._status, 401);
  assert.equal(keyReads(), 2);
});

test("H1: an env key from an over-cap address still pins (the env lookup never touches the store)", async () => {
  const ip = freshIp();
  await exhaust(ip);
  const reads = keyReads();
  const res = await pin(ip, "flood-env-key", { namespace: "env-main" });
  assert.equal(res._status, 201);
  assert.equal(keyReads(), reads, "no keys/ read for an env key");
});

test("H1: a valid issued key never spends a count; MISS_LIMIT+5 reads from one address all succeed and the next unknown key is still looked up", async () => {
  const ip = freshIp();
  for (let i = 0; i < keys.MISS_LIMIT + 5; i++) {
    const res = await balanceJson(ip, ISSUED_KEY);
    assert.equal(res._status, 200, `read ${i + 1} with a valid issued key is 200`);
  }
  assert.equal(keyReads(), 1, "the valid key was read once and cached");
  const res = await balanceJson(ip, guess());
  assert.equal(res._status, 401, "the address is under the cap: unknown keys are still looked up");
});

test("H1 MAJOR 2: concurrent distinct guesses cannot slip under the cap; the slot is reserved before the store read", async () => {
  const ip = freshIp();
  const real = global.fetch;
  global.fetch = async (url, opts) => {
    if (String(url).includes("/contents/keys/")) await new Promise((r) => setTimeout(r, 15));
    return real(url, opts);
  };
  try {
    const n = keys.MISS_LIMIT + 10;
    const results = await Promise.all(Array.from({ length: n }, () => balanceJson(ip, guess())));
    const refused = results.filter((r) => r._status === 429).length;
    const looked = results.filter((r) => r._status === 401).length;
    assert.equal(looked, keys.MISS_LIMIT + 1, "MISS_LIMIT reserved slots plus the one grace read reach the store");
    assert.equal(refused, n - (keys.MISS_LIMIT + 1));
    assert.equal(keyReads(), keys.MISS_LIMIT + 1);
  } finally {
    global.fetch = real;
  }
});

test("H1 ROUND 3: a bad key that arrived through the grace read is counted too, so its retry is a 401, not a 429", async () => {
  const ip = freshIp();
  await flood(ip, keys.MISS_LIMIT); // at the cap, grace unspent
  const viaGrace = guess();
  assert.equal((await balanceJson(ip, viaGrace))._status, 401, "the grace read");
  const reads = keyReads();
  for (let i = 0; i < 5; i++) {
    const r = await balanceJson(ip, viaGrace);
    assert.equal(r._status, 401, "a retry of the key the grace read already answered is a plain 401");
  }
  assert.equal(keyReads(), reads, "and costs no read");
  assert.equal((await balanceJson(ip, guess()))._status, 429, "a NEW key inside the grace minute is still refused");
});

test("H1 ROUND 3 (serve stale): a key seen valid once, past its fresh TTL, is still served when the instance read budget is gone", async () => {
  keys._setGlobalReadsPerMinForTests(keys.GLOBAL_READS_PER_MIN);
  assert.equal((await balanceJson(freshIp(), ISSUED_KEY))._status, 200, "seen valid once");
  advance(keys.CACHE_TTL_MS + 1); // fresh entry expired, last-seen-valid kept
  for (let i = 0; i < keys.GLOBAL_READS_PER_MIN; i++) {
    assert.equal((await balanceJson(freshIp(), guess()))._status, 401);
  }
  assert.equal((await balanceJson(freshIp(), guess()))._status, 429, "the instance read budget is gone");
  const reads = keyReads();
  const res = await balanceJson(freshIp(), ISSUED_KEY);
  assert.equal(res._status, 200, "served from last-seen-valid instead of 429");
  assert.equal(keyReads(), reads, "without a read");
  assert.equal((await pin(freshIp(), ISSUED_KEY, { namespace: "acme-main" }))._status, 201);

  // Past STALE_KEEP_MS the memory is gone: with the budget still exhausted in
  // this new minute, the key is refused like any never-seen key would be.
  advance(keys.STALE_KEEP_MS + 1);
  for (let i = 0; i < keys.GLOBAL_READS_PER_MIN; i++) await balanceJson(freshIp(), guess());
  assert.equal((await balanceJson(freshIp(), ISSUED_KEY))._status, 429);
});

test("H1 MAJOR 3: the instance makes at most GLOBAL_READS_PER_MIN unknown-key store reads a minute over ALL addresses; cached valid keys still pass; the minute turns", async () => {
  keys._setGlobalReadsPerMinForTests(keys.GLOBAL_READS_PER_MIN);
  assert.equal(keys.GLOBAL_READS_PER_MIN, 15, "15 a minute per instance until PR 15's cross instance limiter ships");
  for (let i = 0; i < keys.GLOBAL_READS_PER_MIN; i++) {
    const r = await balanceJson(freshIp(), guess());
    assert.equal(r._status, 401);
  }
  assert.equal(keyReads(), keys.GLOBAL_READS_PER_MIN);
  const over = await balanceJson(freshIp(), guess());
  assert.equal(over._status, 429);
  assert.equal(over._body.reason, "unknown_key_lookups_exhausted");
  assert.match(over._body.error, /if your key is valid, wait a minute and retry/);
  assert.ok(over._headers["retry-after"]);
  assert.equal(keyReads(), keys.GLOBAL_READS_PER_MIN, "no read past the instance cap");

  advance(60 * 1000 + 1);
  const next = await balanceJson(freshIp(), guess());
  assert.equal(next._status, 401, "a new minute, reads resume");
  // A read that finds a VALID key gives its slot back: valid keys do not eat the budget.
  const before = keys._missStateForTests().globalReads;
  assert.equal((await balanceJson(freshIp(), ISSUED_KEY))._status, 200);
  assert.equal(keys._missStateForTests().globalReads, before);
});

test("H1 MAJOR 3: a flood of fresh addresses evicts under-cap buckets first; an over-cap bucket keeps its count", async () => {
  keys._setMissMaxBucketsForTests(3);
  const hot = freshIp();
  await exhaust(hot); // over the cap, grace spent
  const b1 = freshIp();
  const b2 = freshIp();
  await balanceJson(b1, guess());
  await balanceJson(b2, guess());
  assert.equal(keys._missStateForTests().buckets, 3);
  // Three more fresh addresses: each insert evicts one, and the hot bucket must not be the one.
  for (let i = 0; i < 3; i++) await balanceJson(freshIp(), guess());
  assert.equal(keys._missStateForTests().buckets, 3);
  const r = await balanceJson(hot, guess());
  assert.equal(r._status, 429, "the over-cap address is still over the cap after the churn");
  assert.equal(r._body.reason, "unknown_key_rate_limited");
});

test("H1: a miss limited address is refused on /api/balance (JSON and the HTML form) and the stamp paid path, and the key is never echoed", async () => {
  const ip = freshIp();
  await exhaust(ip);
  const reads = keyReads();

  const json = await balanceJson(ip, guess());
  assert.equal(json._status, 429);
  assert.equal(json._body.reason, "unknown_key_rate_limited");

  const attempted = "wk_bogus_html_key_1234567890";
  const html = makeRes();
  await balanceHandler(makeReq({
    method: "POST", headers: { accept: "text/html", "x-forwarded-for": ip }, body: { key: attempted },
  }), html);
  assert.equal(html._status, 429);
  assert.ok(String(html._body).includes('<form method="post"'), "the form comes back");
  assert.ok(String(html._body).includes("if your key is valid"), "the page speaks to the holder of a good key");
  assert.ok(!String(html._body).includes(attempted), "the attempted key is never echoed");

  const st = makeRes();
  await stamp.handleStamp(makeReq({
    method: "POST",
    headers: { authorization: `Bearer ${guess()}`, "x-forwarded-for": ip },
    body: { sha256: "c".repeat(64) },
  }), st);
  assert.equal(st._status, 429);
  assert.equal(st._body.reason, "unknown_key_rate_limited");

  assert.equal(keyReads(), reads, "none of the refusals read the store");
});

test("H1: an overlong bearer value is refused 401 without any store read", async () => {
  const ip = freshIp();
  const res = await pin(ip, "x".repeat(keys.MAX_KEY_LEN + 1));
  assert.equal(res._status, 401);
  assert.equal(keyReads(), 0);
});

test("H1: a store FAILURE is 502, is not counted against the address, and is not cached as unknown", async () => {
  const ip = freshIp();
  const real = global.fetch;
  global.fetch = async (url, opts) => {
    if (String(url).includes("/contents/keys/")) {
      return { status: 500, ok: false, json: async () => ({}), text: async () => "mock: down" };
    }
    return real(url, opts);
  };
  const guesses = Array.from({ length: keys.MISS_LIMIT + 3 }, () => guess());
  try {
    for (const g of guesses) {
      const res = await balanceJson(ip, g);
      assert.equal(res._status, 502, "a store failure is a 502, never a 401 and never a 429");
    }
    // The valid key during the outage: 502 too, and nothing remembered about it.
    assert.equal((await balanceJson(ip, ISSUED_KEY))._status, 502);
  } finally {
    global.fetch = real;
  }
  assert.equal(keys._missStateForTests().unknown, 0, "nothing was cached as unknown during the outage");
  // The outage counted for nothing: the next unknown key is looked up, the valid key is found.
  assert.equal((await balanceJson(ip, guess()))._status, 401);
  assert.equal((await balanceJson(ip, ISSUED_KEY))._status, 200);
  assert.equal((await balanceJson(ip, guesses[0]))._status, 401, "a key that only ever failed is looked up again, not refused from a cache");
});
