// test/ratelimit.test.js — lib/_ratelimit.js: per-IP fixed-window limiter
// backing the public read endpoints' rate limit. Since B079 the count lives in
// a shared store; these tests use the in-memory store stub, never a network.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const ratelimit = require("../lib/_ratelimit.js");

// Every test below uses its OWN fake IP so tests never interfere with each
// other's bucket state (the module holds one process-wide limiter on purpose;
// that's the real behavior under test, not something to work around).
let ipCounter = 0;
function freshReq(overrides) {
  ipCounter += 1;
  return Object.assign(
    {
      method: "GET",
      headers: { "x-forwarded-for": `203.0.113.${ipCounter}` },
      socket: { remoteAddress: "unused" },
    },
    overrides
  );
}

test("CONTRACT: allows exactly LIMIT calls from one IP, then blocks the next", async () => {
  const req = freshReq();
  for (let i = 0; i < ratelimit.LIMIT; i++) {
    const r = await ratelimit.check(req);
    assert.equal(r.limited, false, `call ${i + 1} of ${ratelimit.LIMIT} should be allowed`);
  }
  const blocked = await ratelimit.check(req);
  assert.equal(blocked.limited, true, "the call past LIMIT must be blocked");
  assert.ok(
    Number.isInteger(blocked.retryAfterSeconds) && blocked.retryAfterSeconds > 0 && blocked.retryAfterSeconds <= ratelimit.WINDOW_MS / 1000,
    "retryAfterSeconds must be a positive integer no larger than the window"
  );
});

test("CONTRACT: two different IPs get two independent buckets", async () => {
  const reqA = freshReq();
  const reqB = freshReq();
  for (let i = 0; i < ratelimit.LIMIT; i++) await ratelimit.check(reqA);
  const blockedA = await ratelimit.check(reqA);
  const okB = await ratelimit.check(reqB);
  assert.equal(blockedA.limited, true, "IP A is over its own limit");
  assert.equal(okB.limited, false, "IP B's budget must be untouched by IP A's usage");
});

test("CONTRACT: x-forwarded-for with multiple hops uses the leftmost (original client)", () => {
  const req = { headers: { "x-forwarded-for": "198.51.100.7, 10.0.0.1, 10.0.0.2" } };
  assert.equal(ratelimit.callerIp(req), "198.51.100.7");
});

test("CONTRACT: falls back to socket.remoteAddress when x-forwarded-for is absent", () => {
  const req = { headers: {}, socket: { remoteAddress: "192.0.2.55" } };
  assert.equal(ratelimit.callerIp(req), "192.0.2.55");
});

test("CONTRACT: with neither header nor socket address, every such caller collapses onto ONE shared bucket (fails toward blocking, never toward unlimited)", () => {
  const reqX = { headers: {} };
  const reqY = { headers: {} };
  assert.equal(ratelimit.callerIp(reqX), "unknown");
  assert.equal(ratelimit.callerIp(reqY), "unknown");
});

test("REGRESSION: a caller exactly at LIMIT is still allowed (off-by-one — the 429 must trigger on the (LIMIT+1)th call, not the LIMIT-th)", async () => {
  const req = freshReq();
  let last;
  for (let i = 0; i < ratelimit.LIMIT; i++) last = await ratelimit.check(req);
  assert.equal(last.limited, false, "the LIMIT-th call itself must still be allowed");
});

// ---- B079: the count lives in the shared store, not per instance ----

// Fire `n` calls from one IP, alternating between the given limiters (two
// warm instances taking one burst between them), concurrently.
async function burst(limiters, req, n) {
  const calls = [];
  for (let i = 0; i < n; i++) calls.push(limiters[i % limiters.length].check(req));
  const results = await Promise.all(calls);
  return results.filter((r) => !r.limited).length;
}

test("SHARED: a burst split across two instances on one shared store is held to LIMIT in total", async () => {
  const shared = ratelimit.memoryStore(); // the in-memory stub standing in for the shared store
  const a = ratelimit.createLimiter({ store: shared });
  const b = ratelimit.createLimiter({ store: shared });
  const admitted = await burst([a, b], freshReq(), ratelimit.LIMIT * 2);
  assert.equal(admitted, ratelimit.LIMIT, "two instances sharing a store must admit LIMIT calls, not 2 x LIMIT");
});

test("MUST-FAIL ARM: the pre-B079 shape (each instance its own count) lets the same burst through twice", async () => {
  const a = ratelimit.createLimiter({ store: null }); // own memory fallback
  const b = ratelimit.createLimiter({ store: null }); // a second, independent one
  const admitted = await burst([a, b], freshReq(), ratelimit.LIMIT * 2);
  assert.equal(admitted, ratelimit.LIMIT * 2,
    "per-instance counting must admit 2 x LIMIT here; if it does not, the SHARED test above does not discriminate");
});

test("SHARED: a store failure degrades to this instance's own count, never to unlimited", async () => {
  const broken = { kind: "kv", async hit() { throw new Error("store down"); } };
  const errors = [];
  const lim = ratelimit.createLimiter({ store: broken, onStoreError: (e) => errors.push(e.message) });
  const req = freshReq();
  let admitted = 0;
  for (let i = 0; i < ratelimit.LIMIT + 5; i++) if (!(await lim.check(req)).limited) admitted++;
  assert.equal(admitted, ratelimit.LIMIT, "fallback count must still cap at LIMIT");
  assert.equal(errors.length, ratelimit.LIMIT + 5, "every store failure is reported to onStoreError");
});

test("KV STORE: one pipelined INCRBY + PEXPIRE on a window-aligned key; the count comes from the store", async () => {
  const seen = [];
  const counts = new Map();
  const fakeFetch = async (url, init) => {
    const cmds = JSON.parse(init.body);
    seen.push({ url, auth: init.headers.authorization, cmds });
    const [[op, key, by]] = cmds;
    assert.equal(op, "INCRBY");
    counts.set(key, (counts.get(key) || 0) + Number(by));
    return { ok: true, json: async () => [{ result: counts.get(key) }, { result: 1 }] };
  };
  const store = ratelimit.kvStore({ url: "https://kv.example/", token: "t0k", fetchImpl: fakeFetch });
  const now = 1_700_000_123_456;
  const r1 = await store.hit("198.51.100.9", 1, now);
  const r2 = await store.hit("198.51.100.9", 4, now + 1000);
  assert.equal(r1.count, 1);
  assert.equal(r2.count, 5, "the second hit sees the first: the count lives in the store");
  const windowStart = Math.floor(now / ratelimit.WINDOW_MS) * ratelimit.WINDOW_MS;
  assert.equal(r1.windowStart, windowStart);
  assert.equal(seen[0].url, "https://kv.example/pipeline");
  assert.equal(seen[0].auth, "Bearer t0k");
  assert.deepEqual(seen[0].cmds, [
    ["INCRBY", `rl:198.51.100.9:${windowStart}`, "1"],
    ["PEXPIRE", `rl:198.51.100.9:${windowStart}`, String(ratelimit.WINDOW_MS * 2)],
  ]);
});

test("KV STORE: a non-2xx or countless reply throws, so the limiter falls back instead of trusting it", async () => {
  const bad = ratelimit.kvStore({ url: "https://kv.example", token: "x", fetchImpl: async () => ({ ok: false, status: 500 }) });
  await assert.rejects(bad.hit("a", 1, Date.now()), /500/);
  const empty = ratelimit.kvStore({ url: "https://kv.example", token: "x", fetchImpl: async () => ({ ok: true, json: async () => [{ error: "ERR" }] }) });
  await assert.rejects(empty.hit("a", 1, Date.now()), /no count/);
});

test("ENV: the shared store is chosen only when both URL and token are set (Vercel KV or Upstash names)", () => {
  assert.equal(ratelimit.storeFromEnv({}), null);
  assert.equal(ratelimit.storeFromEnv({ KV_REST_API_URL: "https://x" }), null);
  assert.equal(ratelimit.storeFromEnv({ KV_REST_API_URL: "https://x", KV_REST_API_TOKEN: "t" }).kind, "kv");
  assert.equal(ratelimit.storeFromEnv({ UPSTASH_REDIS_REST_URL: "https://x", UPSTASH_REDIS_REST_TOKEN: "t" }).kind, "kv");
});

// ---- PER-KEY BUCKETS (FIX F, 2026-10-12): checkKey(keyHash) ----

const crypto = require("node:crypto");
const hashOf = (s) => crypto.createHash("sha256").update(s).digest("hex");

test("PER-KEY: a key's bucket holds LIMIT calls, apart from every address's bucket and every other key's", async () => {
  const lim = ratelimit.createLimiter();
  const h1 = hashOf("per-key one");
  const h2 = hashOf("per-key two");
  const req = freshReq();
  for (let i = 0; i < ratelimit.LIMIT; i++) {
    assert.equal((await lim.checkKey(h1)).limited, false, `key call ${i + 1} of ${ratelimit.LIMIT}`);
  }
  const blocked = await lim.checkKey(h1);
  assert.equal(blocked.limited, true, "the key's call past LIMIT is blocked");
  assert.ok(blocked.retryAfterSeconds > 0 && blocked.retryAfterSeconds <= ratelimit.WINDOW_MS / 1000);
  assert.equal((await lim.checkKey(h2)).limited, false, "another key's bucket is untouched");
  assert.equal((await lim.check(req)).limited, false, "an address's bucket is untouched");
  for (let i = 0; i < ratelimit.LIMIT; i++) await lim.check(req);
  assert.equal((await lim.check(req)).limited, true, "control: the address is now over its own limit");
  assert.equal((await lim.checkKey(h2)).limited, false, "and that spends no key's bucket");
  assert.equal((await lim.checkKey(hashOf("per-key three"), ratelimit.LIMIT + 1)).limited, true, "cost is charged on a key's bucket too");
});

test("PER-KEY: the bucket is named \"key,\" + the key's sha256, and no address a caller can forge names it", async () => {
  const named = [];
  const spy = ratelimit.memoryStore();
  const lim = ratelimit.createLimiter({ store: { kind: "spy", hit: (k, c, t) => { named.push(k); return spy.hit(k, c, t); } } });
  const h = hashOf("per-key forged");
  await lim.checkKey(h);
  assert.deepEqual(named, [`key,${h}`]);
  for (const forged of [h, `key,${h}`, `key:${h}`, `key${h}`, `key;${h}`, `key/${h}`, ` key,${h}`, `key,${h}, 10.0.0.1`]) {
    const req = { headers: { "x-forwarded-for": forged } };
    for (let i = 0; i <= ratelimit.LIMIT; i++) await lim.check(req);
    assert.notEqual(ratelimit.callerIp(req), `key,${h}`, forged);
  }
  assert.equal((await lim.checkKey(h)).limited, false, "no forged address spent the key's bucket");
});

test("PER-KEY: checkKey takes a sha256 and nothing else, so a raw key never names a bucket", async () => {
  const named = [];
  const lim = ratelimit.createLimiter({ store: { kind: "spy", hit: async (k) => { named.push(k); return { count: 1, windowStart: 0 }; } } });
  const h = hashOf("per-key shape");
  for (const bad of ["case-test-open-key-0021", h.toUpperCase(), `${h}0`, `0${h}`, h.slice(1), `${h}\n`, "", undefined, null, 42]) {
    await assert.rejects(lim.checkKey(bad), TypeError, String(bad));
  }
  await assert.rejects(ratelimit.checkKey("case-test-open-key-0021"), TypeError, "the module-level checkKey too");
  assert.deepEqual(named, [], "nothing reached the store");
});
