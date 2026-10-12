// test/case_budgets.test.js — what spends which budget on the case ops.
//
// FIX F (2026-10-12; GPT-5.6 §1.5, test/case_redteam.test.js): ?op=case-open
// reads its bearer key BEFORE any rate budget is spent. A valid key draws on
// its own bucket (lib/_ratelimit.js checkKey), never its address's; anything
// else (no key, a key that is not valid) draws on the per-IP bucket and past
// it is 429 before its 401. The keyless ops stay per-IP.
// Every store is the in-memory mock; every budget is the process's limiter,
// fresh for each test (test/helpers/mock_store.js install).
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.WITNESS_KEYS = "case-test-open-key-0031:case-test-,case-test-open-key-0032:case-test2-";
delete process.env.WITNESS_BATCH_SHADOW;
delete process.env.WITNESS_ADMIN_KEY;
delete process.env.WITNESS_CASE_OPERATOR_KEY;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const C = require("../lib/_case.js");
const H = require("../lib/_case_http.js");
const ratelimit = require("../lib/_ratelimit.js");

const NOW = Date.parse("2026-10-10T08:00:00Z");
const KEY = "case-test-open-key-0031";
const OTHER_KEY = "case-test-open-key-0032";
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const bearer = (k) => ({ authorization: `Bearer ${k}` });

let gh;
let restore;
let realSleep;
beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
  realSleep = store._putRetry.sleep;
  store._putRetry.sleep = async () => {};
});
afterEach(() => {
  store._putRetry.sleep = realSleep;
  restore();
});

let ipSeq = 0;
function freshIp() {
  ipSeq += 1;
  return `10.75.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
}
function opening(over = {}) {
  return {
    protocol_version: "case/1",
    policy_version: C.SUPPORTED_POLICY_VERSION,
    scope_digest: sha("the scope manifest both parties agreed"),
    party_a: { side: "agent", label: "agent-operator@example.com" },
    party_b: { side: "tool", label: "tool-operator@example.com" },
    opened_at: "2026-10-10T07:30:00Z",
    deadline: "2026-10-10T20:00:00Z",
    ...over,
  };
}
async function call(handler, op, body, { headers = {}, ip = freshIp(), now = NOW } = {}) {
  const res = makeRes();
  await handler(makeReq({ method: "POST", query: { op }, headers: { "content-type": "application/json", "x-forwarded-for": ip, ...headers }, body }), res, { now });
  return res;
}
const open = (over, o) => call(H.handleCaseOpen, "case-open", opening(over), o);
// A body the schema refuses (400) after admit() has let it in: spends one unit, writes nothing.
const spend = (handler, op, o) => call(handler, op, { not: "a case body" }, o);

// =============================================================================
// FIX F: the key first, then the budget it draws on
// =============================================================================

test("FIX F: a valid key's opens draw on the key's own budget: from one address, its LIMIT+1th is 429 with the per-key note, while that address's budget and another key's stay unspent", async () => {
  const ip = freshIp();
  for (let i = 0; i < ratelimit.LIMIT; i += 1) {
    const r = await spend(H.handleCaseOpen, "case-open", { headers: bearer(KEY), ip });
    assert.equal(r._status, 400, `keyed call ${i + 1}: ${JSON.stringify(r._body)}`);
  }
  const over = await open({ scope_digest: sha("past the key's budget") }, { headers: bearer(KEY), ip: freshIp() });
  assert.equal(over._status, 429, JSON.stringify(over._body));
  assert.equal(over._body.error_code, "rate_limited");
  assert.match(over._body.note, /^per-key limiter: ~30 calls per key per 10 minutes/);
  assert.ok(Number(over._headers["retry-after"]) > 0);
  assert.equal(gh.putLog.length, 0, "nothing written");
  // the key's budget is the key's alone: not the address's, not another key's
  const other = await open({ scope_digest: sha("another key, same address") }, { headers: bearer(OTHER_KEY), ip });
  assert.equal(other._status, 201, JSON.stringify(other._body));
  const bare = await open({ scope_digest: sha("no key, same address") }, { headers: {}, ip });
  assert.equal(bare._status, 401, `the keyed calls spent nothing of the address's budget: ${JSON.stringify(bare._body)}`);
  assert.equal(bare._body.error_code, "key_required");
});

test("FIX F: an open whose key is not valid draws on the address's budget, and past it is 429 (the per-IP note) before its 401; a valid key from that address still opens", async () => {
  const ip = freshIp();
  for (let i = 0; i < ratelimit.LIMIT; i += 1) {
    const r = await open({ scope_digest: sha(`bad key ${i}`) }, { headers: bearer(`${KEY}x`), ip });
    assert.equal(r._status, 401, JSON.stringify(r._body));
    assert.equal(r._body.error_code, "key_invalid");
  }
  const over = await open({ scope_digest: sha("bad key, over") }, { headers: bearer(`${KEY}x`), ip });
  assert.equal(over._status, 429, JSON.stringify(over._body));
  assert.equal(over._body.error_code, "rate_limited");
  assert.match(over._body.note, /^naive per-IP limiter/);
  assert.equal(over._headers["www-authenticate"], undefined, "the 429 is answered, not the 401");
  const valid = await open({ scope_digest: sha("the key holder at that address") }, { headers: bearer(KEY), ip });
  assert.equal(valid._status, 201, JSON.stringify(valid._body));
});

test("FIX F: the keyless ops stay per-IP, and a bearer key on one of them does not move it to the key's budget", async () => {
  for (const [handler, op] of [[H.handleCaseCommit, "case-commit"], [H.handleCaseWithdraw, "case-withdraw"], [H.handleCaseReference, "case-reference"]]) {
    const ip = freshIp();
    for (let i = 0; i < ratelimit.LIMIT; i += 1) {
      assert.equal((await spend(handler, op, { headers: bearer(KEY), ip }))._status, 400, `${op} ${i + 1}`);
    }
    const over = await spend(handler, op, { headers: bearer(KEY), ip });
    assert.equal(over._status, 429, `${op}: ${JSON.stringify(over._body)}`);
    assert.match(over._body.note, /^naive per-IP limiter/);
  }
  const keyed = await open({ scope_digest: sha("the key's budget is untouched") }, { headers: bearer(KEY) });
  assert.equal(keyed._status, 201, JSON.stringify(keyed._body));
});
