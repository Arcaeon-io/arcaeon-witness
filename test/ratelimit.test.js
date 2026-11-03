// test/ratelimit.test.js — api/_ratelimit.js: naive per-IP fixed-window
// limiter backing /api/verify's rate limit (Stage-0, per-instance).
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const ratelimit = require("../lib/_ratelimit.js");

// Every test below uses its OWN fake IP so tests never interfere with each
// other's bucket state (the module holds one process-wide Map on purpose —
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

test("CONTRACT: allows exactly LIMIT calls from one IP, then blocks the next", () => {
  const req = freshReq();
  for (let i = 0; i < ratelimit.LIMIT; i++) {
    const r = ratelimit.check(req);
    assert.equal(r.limited, false, `call ${i + 1} of ${ratelimit.LIMIT} should be allowed`);
  }
  const blocked = ratelimit.check(req);
  assert.equal(blocked.limited, true, "the call past LIMIT must be blocked");
  assert.ok(
    Number.isInteger(blocked.retryAfterSeconds) && blocked.retryAfterSeconds > 0 && blocked.retryAfterSeconds <= ratelimit.WINDOW_MS / 1000,
    "retryAfterSeconds must be a positive integer no larger than the window"
  );
});

test("CONTRACT: two different IPs get two independent buckets", () => {
  const reqA = freshReq();
  const reqB = freshReq();
  for (let i = 0; i < ratelimit.LIMIT; i++) ratelimit.check(reqA);
  const blockedA = ratelimit.check(reqA);
  const okB = ratelimit.check(reqB);
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

test("REGRESSION: a caller exactly at LIMIT is still allowed (off-by-one — the 429 must trigger on the (LIMIT+1)th call, not the LIMIT-th)", () => {
  const req = freshReq();
  let last;
  for (let i = 0; i < ratelimit.LIMIT; i++) last = ratelimit.check(req);
  assert.equal(last.limited, false, "the LIMIT-th call itself must still be allowed");
});

// ---------------------------------------------------------------------
// Red hunt 2026-11-02: IPv6 is one budget per /64, the Map is bounded,
// and an endpoint can ask for its own bucket.
// ---------------------------------------------------------------------

test("RED HUNT: every address in one IPv6 /64 shares ONE bucket (an attacker's /64 is not 2^64 budgets)", () => {
  const base = "2001:db8:abcd:1";
  for (let i = 0; i < ratelimit.LIMIT; i++) {
    const r = ratelimit.check({ headers: { "x-forwarded-for": `${base}::${(i + 1).toString(16)}` } });
    assert.equal(r.limited, false, `call ${i + 1} from a fresh host in the /64 is still under the shared budget`);
  }
  const blocked = ratelimit.check({ headers: { "x-forwarded-for": `${base}:ffff:ffff:ffff:ffff` } });
  assert.equal(blocked.limited, true, "the (LIMIT+1)th host in the same /64 is blocked");
  const other = ratelimit.check({ headers: { "x-forwarded-for": "2001:db8:abcd:2::1" } });
  assert.equal(other.limited, false, "a different /64 is a different budget");
});

test("RED HUNT: IPv6 normalisation handles compression, brackets with a port, a zone id, and IPv4 mapped addresses", () => {
  assert.equal(ratelimit.callerIp({ headers: { "x-forwarded-for": "2001:db8::1" } }), "2001:db8:0:0::/64");
  assert.equal(ratelimit.callerIp({ headers: { "x-forwarded-for": "[2001:db8:0:1::7]:8443" } }), "2001:db8:0:1::/64");
  assert.equal(ratelimit.callerIp({ headers: { "x-forwarded-for": "fe80::1%eth0" } }), "fe80:0:0:0::/64");
  assert.equal(ratelimit.callerIp({ headers: { "x-forwarded-for": "::ffff:203.0.113.9" } }), "203.0.113.9");
  assert.equal(ratelimit.callerIp({ headers: { "x-forwarded-for": "203.0.113.9:51234" } }), "203.0.113.9");
  // Junk is not a budget of its own: it collapses onto the shared unknown bucket.
  assert.equal(ratelimit.callerIp({ headers: { "x-forwarded-for": "not-an-address" } }), "unknown");
  // A value already written as a prefix is not an address: it must not become
  // a second, non canonical key beside the real /64 bucket (review, round 2).
  assert.equal(ratelimit.callerIp({ headers: { "x-forwarded-for": "2001:DB8::/64" } }), "unknown");
  assert.equal(ratelimit.callerIp({ headers: { "x-forwarded-for": "2001:db8:0:0::/64" } }), "unknown");
  assert.equal(ratelimit.parseIp("203.0.113.9/32"), null);
  assert.equal(ratelimit.callerIp({ headers: { "x-forwarded-for": "x".repeat(200) } }), "unknown");
});

test("RED HUNT: the bucket Map never exceeds MAX_BUCKETS, whatever the flood of distinct addresses", () => {
  ratelimit._resetForTests();
  const n = ratelimit.MAX_BUCKETS + 500;
  for (let i = 0; i < n; i++) {
    ratelimit.check({ headers: { "x-forwarded-for": `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}` } });
  }
  assert.ok(ratelimit._bucketCount() <= ratelimit.MAX_BUCKETS, `bucket count ${ratelimit._bucketCount()} must stay at or under ${ratelimit.MAX_BUCKETS}`);
  ratelimit._resetForTests();
});

test("RED HUNT: a scoped bucket is its own budget, independent of the default read bucket for the same IP", () => {
  const req = freshReq();
  for (let i = 0; i < ratelimit.LIMIT; i++) ratelimit.check(req);
  assert.equal(ratelimit.check(req).limited, true, "the default bucket is spent");
  const scoped = ratelimit.check(req, 1, { scope: "fulfill" });
  assert.equal(scoped.limited, false, "the fulfill bucket for the same IP is untouched");
  for (let i = 0; i < ratelimit.LIMIT - 1; i++) ratelimit.check(req, 1, { scope: "fulfill" });
  assert.equal(ratelimit.check(req, 1, { scope: "fulfill" }).limited, true, "the scoped bucket has the same LIMIT");
});
