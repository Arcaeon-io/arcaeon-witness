// test/ratelimit_shared.test.js — lib/_ratelimit.js checkShared (owner job
// 16): the per IP limit on the public read endpoints, one count shared by
// every instance with WITNESS_USAGE_STORE=postgres and WITNESS_IP_RATE_SECRET,
// per instance otherwise. The local check runs first and refuses without a
// database call; the database call has a deadline and falls back to local.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";

const { test, beforeEach, afterEach, mock } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const { MockGitHubStore } = require("./helpers/mock_store.js");
const { MockPostgrest, installBoth, PG_URL } = require("./helpers/mock_postgrest.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");

const ENV = ["WITNESS_USAGE_STORE", "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "WITNESS_IP_RATE_SECRET"];
const SECRET = "test-ip-rate-secret-0123456789abcdef";
let gh, pg, restore, saved;
const T0 = Date.UTC(2026, 9, 31, 10, 0, 0);

function flagOn() {
  process.env.WITNESS_USAGE_STORE = "postgres";
  process.env.SUPABASE_URL = PG_URL;
  process.env.SUPABASE_SERVICE_ROLE_KEY = "srk";
  process.env.WITNESS_IP_RATE_SECRET = SECRET;
}
function quietErrors() {
  const logs = [];
  const orig = console.error;
  console.error = (...a) => logs.push(a.join(" "));
  return { logs, done: () => { console.error = orig; } };
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

test("HMAC: only an HMAC of the IP under the server secret reaches the database, never the IP or an unsalted hash", async () => {
  flagOn();
  await instance().checkShared(req("203.0.113.7"), 1, { now: T0 });
  const call = pg.rpcLog.find((c) => c.fn === "ip_rate_hit");
  const sent = JSON.stringify(pg.requests) + JSON.stringify(pg.rpcLog);
  assert.ok(!sent.includes("203.0.113.7"), "no raw IP");
  for (const pre of ["", "ip-rate:v1\n", "ip-rate:v2\n"]) {
    const plain = crypto.createHash("sha256").update(pre + "203.0.113.7").digest("hex");
    assert.ok(!sent.includes(plain), `no unsalted sha256 (${JSON.stringify(pre)})`);
  }
  assert.equal(call.args.p_ip_hash, crypto.createHmac("sha256", SECRET).update("ip-rate:v2\n203.0.113.7").digest("hex"));
  assert.match(call.args.p_ip_hash, /^[0-9a-f]{64}$/);
  assert.equal(call.args.p_window_start, new Date(T0).toISOString());
  process.env.WITNESS_IP_RATE_SECRET = SECRET + "-other";
  await instance().checkShared(req("203.0.113.7"), 1, { now: T0 });
  const second = pg.rpcLog.filter((c) => c.fn === "ip_rate_hit")[1];
  assert.notEqual(second.args.p_ip_hash, call.args.p_ip_hash, "the value depends on the secret");
});

test("NO SECRET: store on but no WITNESS_IP_RATE_SECRET (or a short one) stays local and writes nothing about IPs", async () => {
  for (const secret of [undefined, "short"]) {
    flagOn();
    if (secret === undefined) delete process.env.WITNESS_IP_RATE_SECRET; else process.env.WITNESS_IP_RATE_SECRET = secret;
    const q = quietErrors();
    try {
      const r = instance();
      let last;
      for (let i = 0; i <= r.LIMIT; i++) last = await r.checkShared(req("10.6.6.6"), 1, { now: T0 });
      assert.equal(last.limited, true, "the local limit still holds");
      assert.equal(pg.requests.length, 0, "no database request at all");
      assert.ok(q.logs.some((l) => l.includes("WITNESS_IP_RATE_SECRET")));
    } finally {
      q.done();
    }
  }
});

test("LOCAL FIRST: a caller over the local limit is refused with zero database calls", async () => {
  flagOn();
  const r = instance();
  for (let i = 0; i < r.LIMIT; i++) assert.equal((await r.checkShared(req("10.7.7.7"), 1, { now: T0 })).limited, false);
  const before = pg.requests.length;
  assert.equal(before, r.LIMIT, "one database call per admitted call");
  for (let i = 0; i < 500; i++) {
    const out = await r.checkShared(req("10.7.7.7"), 1, { now: T0 });
    assert.equal(out.limited, true);
    assert.equal(out.shared, false);
  }
  assert.equal(pg.requests.length, before, "a flood past the local limit makes no database call");
  const big = instance();
  assert.equal((await big.checkShared(req("10.7.7.8"), big.LIMIT + 1, { now: T0 })).limited, true);
  assert.equal(pg.requests.length, before, "a single call whose cost is over the limit never reaches the database");
});

test("NO CLEANUP PER REQUEST: the request path calls only ip_rate_hit, and the migration's ip_rate_hit deletes nothing", async () => {
  flagOn();
  const r = instance();
  for (let i = 0; i < 5; i++) await r.checkShared(req("10.8.8.8"), 1, { now: T0 + i });
  assert.deepEqual([...new Set(pg.rpcLog.map((c) => c.fn))], ["ip_rate_hit"]);
  const sql = require("fs").readFileSync(require("path").join(__dirname, "..", "supabase", "migrations", "2026_10_31_ip_rate.sql"), "utf8");
  const hit = sql.slice(sql.indexOf("function public.ip_rate_hit"), sql.indexOf("revoke all on function public.ip_rate_hit"));
  assert.ok(hit.length > 0 && !/delete/i.test(hit), "ip_rate_hit has no delete");
  assert.match(sql, /function public\.ip_rate_sweep\(\)/);
  assert.match(sql, /cron\.schedule\('ip_rate_sweep'/);
});

test("TIMEOUT: a slow database falls back to the local count after the deadline, never open", async () => {
  flagOn();
  const r = instance();
  const q = quietErrors();
  try {
    pg.hangIpRate(1000);
    const t = Date.now();
    const first = await r.checkShared(req("10.5.5.5"), 1, { now: T0, timeoutMs: 30 });
    assert.ok(Date.now() - t < 1000, "answered at the deadline, not hung");
    assert.equal(first.limited, false);
    assert.equal(first.shared, false);
    let last;
    for (let i = 1; i < r.LIMIT; i++) last = await r.checkShared(req("10.5.5.5"), 1, { now: T0, timeoutMs: 5 });
    assert.equal(last.limited, false, "the local count is charged once per call, not twice");
    last = await r.checkShared(req("10.5.5.5"), 1, { now: T0, timeoutMs: 5 });
    assert.equal(last.limited, true, "the local count limits");
    assert.equal(last.shared, false);
    assert.ok(q.logs.some((l) => l.includes("limited per instance")));
    assert.ok(r.SHARED_TIMEOUT_MS <= 500, "the default deadline is short");
  } finally {
    q.done();
  }
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

// ---- the database budget (review blocker): many IPs, one /64, breaker, cap ----

const ipHits = () => pg.rpcLog.filter((c) => c.fn === "ip_rate_hit").length;
const ipCalls = () => pg.requests.filter((c) => c.url.includes("/rpc/ip_rate_hit")).length;

test("FLOOD: 1000 distinct IPv4s in one second make at most MAX_PER_SECOND shared calls; the rest use the local count", async () => {
  flagOn();
  const r = instance();
  const outs = [];
  for (let i = 0; i < 1000; i++) outs.push(await r.checkShared(req(`198.18.${i >> 8}.${i & 255}`), 1, { now: T0 }));
  assert.equal(ipHits(), r.MAX_PER_SECOND, "shared calls bounded by the per second cap");
  assert.ok(outs.every((o) => o.limited === false), "each IP is under its own limit, so all admitted");
  assert.equal(outs.filter((o) => o.shared === false).length, 1000 - r.MAX_PER_SECOND, "over the cap: the local count decides");
  await r.checkShared(req("198.19.0.1"), 1, { now: T0 + 1000 });
  assert.equal(ipHits(), r.MAX_PER_SECOND + 1, "the next second has a fresh budget");
});

test("FLOOD: 1000 distinct IPv4s over 10 seconds make at most MAX_PER_SECOND shared calls in each second", async () => {
  flagOn();
  const r = instance();
  for (let i = 0; i < 1000; i++) await r.checkShared(req(`198.20.${i >> 8}.${i & 255}`), 1, { now: T0 + Math.floor(i / 100) * 1000 });
  assert.equal(ipHits(), 10 * r.MAX_PER_SECOND, "100 offered per second, MAX_PER_SECOND taken in each of 10 seconds");
});

test("CAP: a concurrent flood never has more than MAX_IN_FLIGHT shared calls outstanding, and the slots come back", async () => {
  flagOn();
  const r = instance();
  const q = quietErrors();
  try {
    pg.hangIpRate(100000);
    const all = [];
    for (let i = 0; i < 500; i++) all.push(r.checkShared(req(`198.18.1.${i & 255}`), 1, { now: T0 + 2000, timeoutMs: 40 }));
    await new Promise((res) => setImmediate(res));
    assert.ok(r._sharedState().inFlight <= r.MAX_IN_FLIGHT, `in flight ${r._sharedState().inFlight}`);
    const outs = await Promise.all(all);
    assert.equal(ipHits(), r.MAX_IN_FLIGHT, "only MAX_IN_FLIGHT calls reached the database");
    assert.ok(outs.every((o) => o.shared === false && o.limited === false), "timed out or over the cap: the local count decides");
    await new Promise((res) => setImmediate(res));
    assert.equal(r._sharedState().inFlight, 0, "slots released when the calls settle");
  } finally {
    q.done();
  }
});

test("FLOOD: 1000 addresses in one IPv6 /64 are one caller: one shared key, at most LIMIT shared calls", async () => {
  flagOn();
  const r = instance();
  let limited = 0;
  for (let i = 0; i < 1000; i++) {
    const out = await r.checkShared(req(`2001:db8:aa:bb:${((i * 7919) % 65536).toString(16)}:${i.toString(16)}::1`), 1, { now: T0 + i });
    if (out.limited) limited += 1;
  }
  assert.equal(ipHits(), r.LIMIT, "the local count for the /64 stops it before the database");
  assert.equal(limited, 1000 - r.LIMIT);
  const keys = new Set(pg.rpcLog.filter((c) => c.fn === "ip_rate_hit").map((c) => c.args.p_ip_hash));
  assert.equal(keys.size, 1, "one shared key for the whole /64");
  assert.equal((await r.checkShared(req("2001:db8:aa:bc::1"), 1, { now: T0 + 2000 })).limited, false, "the next /64 has its own count");
});

test("BREAKER: N failures within T open it; no shared call while open; after M a failed probe reopens, a good probe closes", async () => {
  flagOn();
  const r = instance();
  const q = quietErrors();
  try {
    pg.failNext(100000, 503);
    for (let i = 0; i < r.BREAKER_FAILURES - 1; i++) await r.checkShared(req(`10.20.0.${i}`), 1, { now: T0 + i });
    assert.equal(r._sharedState().breakerOpenUntil, 0, "N-1 failures: still closed");
    await r.checkShared(req("10.20.0.99"), 1, { now: T0 + 50 });
    assert.ok(r._sharedState().breakerOpenUntil > 0, "open after N failures");
    const atOpen = ipCalls();
    assert.equal(atOpen, r.BREAKER_FAILURES);
    for (let i = 0; i < 200; i++) {
      const out = await r.checkShared(req(`10.20.1.${i}`), 1, { now: T0 + 1000 + i * 10 });
      assert.equal(out.shared, false);
      assert.equal(out.limited, false, "under the local count: admitted");
    }
    assert.equal(ipCalls(), atOpen, "no database call while open");
    let last;
    for (let i = 0; i <= r.LIMIT; i++) last = await r.checkShared(req("10.20.2.2"), 1, { now: T0 + 5000 });
    assert.equal(last.limited, true, "the local limit still holds while open (never open to everything)");
    assert.equal(ipCalls(), atOpen);

    const after = T0 + 50 + r.BREAKER_OPEN_MS;
    await r.checkShared(req("10.20.3.1"), 1, { now: after });
    assert.equal(ipCalls(), atOpen + 1, "exactly one probe after M");
    assert.ok(r._sharedState().breakerOpenUntil > after, "a failed probe reopens it");
    await r.checkShared(req("10.20.3.2"), 1, { now: after + 1 });
    assert.equal(ipCalls(), atOpen + 1, "reopened: no call");

    pg.failNext(0);
    const later = after + r.BREAKER_OPEN_MS;
    const probe = await r.checkShared(req("10.20.4.1"), 1, { now: later });
    assert.equal(probe.shared, true, "the probe got the shared count");
    assert.equal(r._sharedState().breakerOpenUntil, 0, "closed");
    assert.equal((await r.checkShared(req("10.20.4.2"), 1, { now: later + 1 })).shared, true, "shared counting resumes");
  } finally {
    q.done();
  }
});

test("BREAKER: only one probe at a time while half open; the rest use the local count", async () => {
  flagOn();
  const r = instance();
  const q = quietErrors();
  try {
    pg.failNext(r.BREAKER_FAILURES, 503);
    for (let i = 0; i < r.BREAKER_FAILURES; i++) await r.checkShared(req(`10.25.0.${i}`), 1, { now: T0 + i });
    const n = ipHits();
    pg.hangIpRate(1);
    const at = T0 + r.BREAKER_OPEN_MS + 10;
    const outs = await Promise.all(Array.from({ length: 20 }, (_, i) => r.checkShared(req(`10.25.1.${i}`), 1, { now: at, timeoutMs: 20 })));
    assert.equal(ipHits(), n + 1, "one probe");
    assert.ok(outs.every((o) => o.shared === false));
    assert.ok(r._sharedState().breakerOpenUntil > at, "the probe timed out, so it is open again");
  } finally {
    q.done();
  }
});

test("BREAKER: failures spread wider than T do not open it", async () => {
  flagOn();
  const r = instance();
  const q = quietErrors();
  try {
    pg.failNext(100000, 503);
    for (let i = 0; i < r.BREAKER_FAILURES * 3; i++) await r.checkShared(req(`10.21.0.${i}`), 1, { now: T0 + i * r.BREAKER_WINDOW_MS });
    assert.equal(r._sharedState().breakerOpenUntil, 0);
    assert.equal(ipCalls(), r.BREAKER_FAILURES * 3);
  } finally {
    q.done();
  }
});

test("BREAKER: timeouts count as failures", async () => {
  flagOn();
  const r = instance();
  const q = quietErrors();
  try {
    pg.hangIpRate(100000);
    for (let i = 0; i < r.BREAKER_FAILURES; i++) await r.checkShared(req(`10.22.0.${i}`), 1, { now: T0 + i, timeoutMs: 5 });
    assert.ok(r._sharedState().breakerOpenUntil > 0);
    const n = ipHits();
    await r.checkShared(req("10.22.1.1"), 1, { now: T0 + 100, timeoutMs: 5 });
    assert.equal(ipHits(), n, "open: no call");
  } finally {
    q.done();
  }
});

test("LOG: a database outage logs the outage line once per window, not once per request", async () => {
  flagOn();
  const r = instance();
  const q = quietErrors();
  try {
    pg.failNext(100000, 503);
    // 300 requests over 300 seconds, inside one 10 minute slot; the breaker's probes fail too.
    for (let i = 0; i < 300; i++) await r.checkShared(req(`10.23.${i >> 8}.${i & 255}`), 1, { now: T0 + i * 1000 });
    const count = () => q.logs.filter((l) => l.includes("[ratelimit] shared count")).length;
    assert.equal(count(), 1, "one line in the window");
    assert.ok(q.logs.some((l) => l.includes("limited per instance")));
    await r.checkShared(req("10.23.9.9"), 1, { now: T0 + r.WINDOW_MS + 2 * r.BREAKER_OPEN_MS });
    assert.equal(count(), 2, "a new window may log again");
  } finally {
    q.done();
  }
});

test("CAP: env overrides set the cap and breaker; an invalid value keeps the default", async () => {
  const keys = ["WITNESS_IP_RATE_MAX_PER_SECOND", "WITNESS_IP_RATE_MAX_IN_FLIGHT", "WITNESS_IP_RATE_BREAKER_FAILURES"];
  try {
    process.env.WITNESS_IP_RATE_MAX_PER_SECOND = "3";
    process.env.WITNESS_IP_RATE_MAX_IN_FLIGHT = "2";
    process.env.WITNESS_IP_RATE_BREAKER_FAILURES = "-1";
    flagOn();
    const r = instance();
    assert.equal(r.MAX_PER_SECOND, 3);
    assert.equal(r.MAX_IN_FLIGHT, 2);
    assert.equal(r.BREAKER_FAILURES, 5, "invalid override ignored");
    for (let i = 0; i < 20; i++) await r.checkShared(req(`10.24.0.${i}`), 1, { now: T0 });
    assert.equal(ipHits(), 3);
  } finally {
    for (const k of keys) delete process.env[k];
    instance();
  }
});

test("IPV6: callerIp groups by /64 and handles ::, brackets, ports, zones and IPv4 mapped; IPv4 is unchanged", () => {
  const { callerIp } = instance();
  const ip = (v) => callerIp({ headers: { "x-forwarded-for": v } });
  assert.equal(ip("203.0.113.9"), "203.0.113.9");
  assert.equal(ip("203.0.113.9, 10.0.0.1"), "203.0.113.9");
  assert.equal(ip("2001:db8:0:1:aaaa:bbbb:cccc:dddd"), "2001:db8:0:1::/64");
  assert.equal(ip("2001:DB8:0:1::ffff"), "2001:db8:0:1::/64", "case, and :: inside the host part");
  assert.equal(ip("2001:0db8:0000:0001:0:0:0:1"), "2001:db8:0:1::/64", "leading zeros");
  assert.equal(ip("2001:db8::1"), "2001:db8:0:0::/64", ":: inside the prefix");
  assert.equal(ip("2001:db8:1:2::"), "2001:db8:1:2::/64", "trailing ::");
  assert.equal(ip("::1"), "0:0:0:0::/64");
  assert.equal(ip("[2001:db8:1:2::5]:443"), "2001:db8:1:2::/64", "brackets and a port");
  assert.equal(ip("fe80::1%eth0"), "fe80:0:0:0::/64", "zone id dropped");
  assert.equal(ip("::ffff:192.0.2.1"), "192.0.2.1", "IPv4 mapped is the IPv4 address");
  assert.equal(ip("::FFFF:c000:0201"), "192.0.2.1", "hex IPv4 mapped too");
  assert.equal(ip("2001:db8:1:2:3:4:1.2.3.4"), "2001:db8:1:2::/64", "embedded IPv4 tail");
  assert.equal(ip("not-an-ip"), "unknown", "unparseable falls back (no socket address here: unknown)");
  assert.equal(callerIp({ headers: {}, socket: { remoteAddress: "::ffff:127.0.0.1" } }), "127.0.0.1");
  assert.equal(callerIp({ headers: {}, socket: { remoteAddress: "2001:db8:5:6::9" } }), "2001:db8:5:6::/64");
  assert.equal(ip("2001:db8:0:1::a"), ip("2001:db8:0:1:ffff:ffff:ffff:fffe"), "same /64, same key");
  assert.notEqual(ip("2001:db8:0:1::a"), ip("2001:db8:0:2::a"), "different /64, different key");
});

// ---- follow ups: forwarded-for parsing, the bucket cap, the hard release ----

test("CALLER IP: an unparseable or overlong forwarded-for value falls back to the socket address", () => {
  const { callerIp, MAX_IP_LEN } = instance();
  const sock = "192.0.2.77";
  const ip = (v, remoteAddress = sock) => callerIp({ headers: { "x-forwarded-for": v }, socket: { remoteAddress } });
  for (const bad of ["not-an-ip", "999.1.1.1", "1.2.3", "", "   ", ", 203.0.113.9", "2001:db8::zz", `203.0.113.9${" ".repeat(MAX_IP_LEN)}x`]) {
    assert.equal(ip(bad), sock, `bad value ${JSON.stringify(bad.slice(0, 20))} uses the socket`);
  }
  // Overlong: a value over MAX_IP_LEN is refused even if its head looks like an address.
  assert.equal(ip("1".repeat(MAX_IP_LEN + 1)), sock);
  assert.equal(ip("a".repeat(100000) + ", 203.0.113.9"), sock, "a huge header is cut, not parsed");
  // A good leftmost entry still wins, with or without an IPv4 port.
  assert.equal(ip("203.0.113.9, 10.0.0.1"), "203.0.113.9");
  assert.equal(ip("203.0.113.9:4431"), "203.0.113.9");
  // Socket checked the same way: unusable there too means the one shared "unknown" bucket.
  assert.equal(ip("not-an-ip", "garbage"), "unknown");
  assert.equal(ip("not-an-ip", null), "unknown");
  // Garbage values do not each get a fresh budget: they all land on the socket's bucket.
  const r = instance();
  for (let i = 0; i < r.LIMIT; i++) {
    assert.equal(r.check({ headers: { "x-forwarded-for": `junk-${i}` }, socket: { remoteAddress: sock } }).limited, false);
  }
  assert.equal(r.check({ headers: { "x-forwarded-for": "junk-new" }, socket: { remoteAddress: sock } }).limited, true);
});

test("BUCKET CAP: the local Map never exceeds MAX_BUCKETS; the oldest bucket is evicted first", () => {
  try {
    process.env.WITNESS_IP_RATE_MAX_BUCKETS = "50";
    const r = instance();
    assert.equal(r.MAX_BUCKETS, 50);
    const at = (i) => ({ headers: { "x-forwarded-for": `198.51.${i >> 8}.${i & 255}` } });
    const t = T0;
    // The first IP spends its whole budget.
    for (let i = 0; i < r.LIMIT; i++) r.check(at(0), 1, { now: t });
    assert.equal(r.check(at(0), 1, { now: t }).limited, true);
    for (let i = 1; i < 500; i++) {
      r.check(at(i), 1, { now: t + i });
      assert.ok(r._sharedState().buckets <= 50, `size ${r._sharedState().buckets} at ${i}`);
    }
    assert.equal(r._sharedState().buckets, 50);
    // IP 0 was the oldest, so it was evicted; the newest 50 remain.
    assert.equal(r.check(at(0), 1, { now: t + 600 }).limited, false, "evicted: a fresh bucket");
    assert.equal(r._sharedState().buckets, 50);
    // A recent bucket survived: IP 499 still has its count (1 spent).
    for (let i = 0; i < r.LIMIT - 1; i++) assert.equal(r.check(at(499), 1, { now: t + 601 }).limited, false);
    assert.equal(r.check(at(499), 1, { now: t + 601 }).limited, true, "a recent bucket kept its count");
  } finally {
    delete process.env.WITNESS_IP_RATE_MAX_BUCKETS;
    instance();
  }
});

test("RELEASE: after the 2 s hard release a late real completion frees nothing (no double decrement)", async () => {
  process.env.WITNESS_IP_RATE_MAX_IN_FLIGHT = "1";
  flagOn();
  const r = instance();
  const q = quietErrors();
  mock.timers.enable({ apis: ["setTimeout"] });
  const flush = async () => { for (let i = 0; i < 20; i++) await new Promise((res) => setImmediate(res)); };
  try {
    assert.equal(r.MAX_IN_FLIGHT, 1);
    assert.equal(r.RELEASE_AFTER_MS, 2000);
    pg.holdIpRate(2);
    // A: its database call ignores the abort and stays out past the deadline.
    const a = r.checkShared(req("10.30.0.1"), 1, { now: T0, timeoutMs: 20 });
    await flush();
    assert.equal(r._sharedState().inFlight, 1);
    mock.timers.tick(20);
    const outA = await a;
    assert.deepEqual([outA.limited, outA.shared], [false, false], "deadline passed: the local count decides");
    assert.equal(r._sharedState().inFlight, 1, "the slot is held while the real call is still out");
    mock.timers.tick(r.RELEASE_AFTER_MS - 21);
    await flush();
    assert.equal(r._sharedState().inFlight, 1, "not yet released before 2 s");
    mock.timers.tick(1);
    await flush();
    assert.equal(r._sharedState().inFlight, 0, "hard release at 2 s");
    // B takes the only slot.
    const b = r.checkShared(req("10.30.0.2"), 1, { now: T0 + 5000, timeoutMs: 20 });
    await flush();
    assert.equal(r._sharedState().inFlight, 1, "B holds the one slot");
    assert.equal(ipHits(), 2);
    // A's real call completes now, late. It was already released: nothing changes.
    pg.finishHeld(1);
    await flush();
    assert.equal(r._sharedState().inFlight, 1, "A's late completion must not free B's slot");
    const c = await r.checkShared(req("10.30.0.3"), 1, { now: T0 + 5001, timeoutMs: 20 });
    assert.equal(c.shared, false, "the cap is still full");
    assert.equal(ipHits(), 2, "so C makes no database call");
    // B completes in time; the count comes back to zero, never below.
    pg.finishHeld(1);
    const outB = await b;
    assert.equal(outB.shared, true);
    await flush();
    assert.equal(r._sharedState().inFlight, 0);
    mock.timers.tick(10 * r.RELEASE_AFTER_MS);
    await flush();
    assert.equal(r._sharedState().inFlight, 0, "no stray release drives it negative");
  } finally {
    mock.timers.reset();
    q.done();
    delete process.env.WITNESS_IP_RATE_MAX_IN_FLIGHT;
    instance();
  }
});
