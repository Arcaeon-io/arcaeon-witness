// test/store_batch.test.js — POST /api/pin?op=batch_stores: many stores, one
// public entry, a proof per store that verifies offline (BATCH_PINS_FOR_STORES.md).
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_KEYS = "testkeyA:demo-,testkeyB:other-";
delete process.env.WITNESS_PLANS;
delete process.env.WITNESS_CADENCE;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const path = require("path");
const { execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const meter = require("../lib/_meter.js");
const sb = require("../lib/_store_batch.js");
const merkle = require("../lib/_merkle.js");
const pinHandler = require("../api/pin.js");
const pinRate = require("../lib/_pin_ratelimit.js");

const PIN_REPO = process.env.GITHUB_PIN_REPO;
const USAGE_REPO = process.env.GITHUB_USAGE_REPO;
let gh, restore;
const realPutSleep = store._putRetry.sleep;

beforeEach(() => {
  process.env.WITNESS_STORE_BATCH = "on";
  process.env.WITNESS_STORE_BATCH_PRICE = "one_pin_per_batch";
  pinRate._buckets.clear();
  gh = new MockGitHubStore();
  restore = install(gh);
  store._putRetry.sleep = async () => {};
});
afterEach(() => {
  delete process.env.WITNESS_STORE_BATCH;
  delete process.env.WITNESS_STORE_BATCH_PRICE;
  store._putRetry.sleep = realPutSleep;
  restore();
});

const head = (s) => crypto.createHash("sha256").update(s).digest("hex");
function stores(n) {
  return Array.from({ length: n }, (_, i) => ({ store_id: `memory-${i}`, head: head(`folder ${i}`) }));
}
async function post(body, key = "testkeyA", op = "batch_stores") {
  const res = makeRes();
  await pinHandler(makeReq({ method: "POST", headers: { authorization: `Bearer ${key}` }, body, query: { op } }), res);
  return res;
}

test("ONE ENTRY: 250 stores make one public write, and every store's proof verifies offline against it", async () => {
  const entries = stores(250);
  const pubBefore = gh.putLog.filter((p) => p.repo === PIN_REPO).length;
  const res = await post({ namespace: "demo-mem", entries });
  assert.equal(res._status, 201, JSON.stringify(res._body));
  const pub = gh.putLog.filter((p) => p.repo === PIN_REPO);
  assert.equal(pub.length - pubBefore, 1, "one public write for the whole batch");
  const published = gh.read(PIN_REPO, res._body.entry_path);
  assert.equal(published.tree_size, 250);
  assert.equal(res._body.proofs.length, 250);
  for (const [i, p] of res._body.proofs.entries()) {
    const r = sb.verifyStoreProof(p, { store_id: entries[i].store_id, head: entries[i].head, namespace: "demo-mem" }, published);
    assert.equal(r.ok, true, `store ${i}: ${JSON.stringify(r)}`);
    assert.equal(r.tree_size_bound, true);
  }
});

test("PRIVACY: the public entry carries no store id and no head, only the root and the count", async () => {
  const entries = stores(5);
  const res = await post({ namespace: "demo-priv", entries });
  const text = JSON.stringify(gh.read(PIN_REPO, res._body.entry_path));
  for (const e of entries) {
    assert.ok(!text.includes(e.store_id), "store id is not public");
    assert.ok(!text.includes(e.head), "head is not public");
  }
  assert.deepEqual(Object.keys(gh.read(PIN_REPO, res._body.entry_path)).sort(),
    ["accepted_at", "kind", "leaf_recipe", "namespace", "note", "root", "tree_size"]);
});

test("METER: a batch is charged as one pin, a refused batch as none", async () => {
  const p = `usage/${meter.keyHash("testkeyA")}/${meter.utcMonth()}.json`;
  await post({ namespace: "demo-m", entries: stores(40) });
  assert.equal(gh.read(USAGE_REPO, p).used, 1);
  await post({ namespace: "demo-m", entries: [{ store_id: "x", head: "nothex" }] });
  assert.equal(gh.read(USAGE_REPO, p).used, 1);
});

test("OFFLINE TOOL: tools/verify_store_proof.js exits 0 on a good proof and 1 on a changed head", async () => {
  const entries = stores(3);
  const res = await post({ namespace: "demo-tool", entries });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbp-"));
  const pf = path.join(dir, "p.json");
  const ef = path.join(dir, "e.json");
  fs.writeFileSync(pf, JSON.stringify(res._body.proofs[1]));
  fs.writeFileSync(ef, JSON.stringify(gh.read(PIN_REPO, res._body.entry_path)));
  const tool = path.join(__dirname, "..", "tools", "verify_store_proof.js");
  execFileSync(process.execPath, [tool, "--proof", pf, "--entry", ef, "--store-id", "memory-1", "--head", entries[1].head]);
  let code = 0;
  try {
    execFileSync(process.execPath, [tool, "--proof", pf, "--entry", ef, "--head", entries[0].head], { stdio: "pipe" });
  } catch (e) {
    code = e.status;
  }
  assert.equal(code, 1);
});

// --- attacks on a proof ---

async function oneProof() {
  const res = await post({ namespace: "demo-atk", entries: stores(7) });
  return { bundle: res._body.proofs[3], entry: gh.read(PIN_REPO, res._body.entry_path) };
}
const clone = (x) => JSON.parse(JSON.stringify(x));

test("ATTACK: a changed head, store id, namespace or time in the leaf fails", async () => {
  const { bundle, entry } = await oneProof();
  for (const [f, v] of [["head", head("other")], ["store_id", "memory-9"], ["namespace", "demo-x"], ["accepted_at", "2020-01-01T00:00:00.000Z"]]) {
    const b = clone(bundle);
    b.proof.leaf[f] = v;
    delete b.proof.leaf_hash;
    delete b.store_id;
    const r = sb.verifyStoreProof(b, {}, entry);
    assert.equal(r.ok, false, f);
  }
});

test("ATTACK: a proof against another batch's entry, or with a resized tree, fails", async () => {
  const a = await oneProof();
  const b = await post({ namespace: "demo-atk", entries: stores(7).map((e) => ({ ...e, head: head(e.head) })) });
  const otherEntry = gh.read(PIN_REPO, b._body.entry_path);
  assert.equal(sb.verifyStoreProof(a.bundle, {}, otherEntry).ok, false);
  const resized = clone(a.bundle);
  resized.proof.tree_size = 8;
  assert.equal(sb.verifyStoreProof(resized, {}, a.entry).ok, false);
  const lied = clone(a.entry);
  lied.tree_size = 8;
  assert.equal(sb.verifyStoreProof(a.bundle, {}, lied).ok, false);
});

test("ATTACK: a pin leaf cannot pose as a store leaf, nor a store leaf as a pin leaf", async () => {
  const { bundle } = await oneProof();
  const b = clone(bundle);
  b.proof.leaf.leaf_kind = "pin";
  assert.equal(sb.verifyStoreProof(b, {}).reason, "not_a_store_leaf");
  assert.throws(() => merkle.leafObjectFromPin(bundle.proof.leaf), /missing leaf field/);
});

test("ATTACK: a stranger's key cannot batch into another namespace", async () => {
  const res = await post({ namespace: "demo-mine", entries: stores(2) }, "testkeyB");
  assert.equal(res._status, 403);
  assert.equal(res._body.field, "namespace");
  assert.equal(gh.putLog.filter((p) => p.repo === PIN_REPO).length, 0);
});

test("ATTACK: the entry is create only; an existing entry is never replaced", async () => {
  const fixed = new Date("2026-10-31T08:00:00.000Z");
  const entries = stores(3);
  const a = sb.build("demo-same", entries, fixed.toISOString());
  gh.seed(PIN_REPO, a.path, { kind: "something else" });
  const res = makeRes();
  await sb.handle(makeReq({ method: "POST", body: { namespace: "demo-same", entries } }), res, {
    key: "testkeyA", prefix: "demo-", rateCheck: async () => ({ limited: false }),
    meterAndCharge: async () => ({ ok: true, source: "free", headers: {} }),
    refundFailedWrite: async () => {}, applyHeaders: () => {}, now: () => fixed,
  });
  assert.equal(res._status, 409);
  assert.equal(res._body.reason, "entry_exists");
  assert.deepEqual(gh.read(PIN_REPO, a.path), { kind: "something else" });
});

// --- refusals name a field ---

test("REFUSALS: every bad request is a 400 naming the field, and writes nothing", async () => {
  const cases = [
    [null, "body"],
    [{ entries: stores(1) }, "namespace"],
    [{ namespace: "demo-r" }, "entries"],
    [{ namespace: "demo-r", entries: [] }, "entries"],
    [{ namespace: "demo-r", entries: stores(1001) }, "entries"],
    [{ namespace: "demo-r", entries: ["x"] }, "entries[0]"],
    [{ namespace: "demo-r", entries: [{ store_id: "a", head: head("a"), note: "my diary" }] }, "entries[0].note"],
    [{ namespace: "demo-r", entries: [{ store_id: "a b", head: head("a") }] }, "entries[0].store_id"],
    [{ namespace: "demo-r", entries: [{ store_id: "a", head: "ABC" }] }, "entries[0].head"],
    [{ namespace: "demo-r", entries: [{ store_id: "a", head: head("a") }, { store_id: "a", head: head("b") }] }, "entries[1].store_id"],
  ];
  for (const [body, field] of cases) {
    const res = await post(body);
    assert.equal(res._status, 400, JSON.stringify(body));
    assert.equal(res._body.field, field);
    assert.ok(res._body.reason && res._body.error);
  }
  assert.equal(gh.putLog.length, 0);
});

test("FLAG: off by default, a 404 naming the reason, and nothing written", async () => {
  delete process.env.WITNESS_STORE_BATCH;
  const res = await post({ namespace: "demo-off", entries: stores(2) });
  assert.equal(res._status, 404);
  assert.equal(res._body.reason, "not_enabled");
  assert.equal(gh.putLog.length, 0);
});

test("AUTH: no key is a 401 before anything else", async () => {
  const res = makeRes();
  await pinHandler(makeReq({ method: "POST", body: { namespace: "demo-a", entries: stores(1) }, query: { op: "batch_stores" } }), res);
  assert.equal(res._status, 401);
});

test("STORE FAILURE: a failed public write answers 502 named, and a credit charge would be refunded", async () => {
  const fixed = new Date("2026-10-31T09:00:00.000Z");
  const entries = stores(2);
  const { path: p } = sb.build("demo-fail", entries, fixed.toISOString());
  gh.forceFailure(PIN_REPO, p, 5, 500);
  const refunds = [];
  const res = makeRes();
  await sb.handle(makeReq({ method: "POST", body: { namespace: "demo-fail", entries } }), res, {
    key: "testkeyA", prefix: "demo-", rateCheck: async () => ({ limited: false }),
    meterAndCharge: async () => ({ ok: true, source: "credit", headers: {} }),
    refundFailedWrite: async (...a) => refunds.push(a), applyHeaders: () => {}, now: () => fixed,
  });
  assert.equal(res._status, 502);
  assert.equal(res._body.reason, "store_error");
  assert.equal(refunds.length, 1);
  assert.equal(refunds[0][1], "credit");
});

test("PLAIN PINS UNCHANGED: without op the handler is the single pin path", async () => {
  const res = makeRes();
  await pinHandler(makeReq({ method: "POST", headers: { authorization: "Bearer testkeyA" },
    body: { namespace: "demo-plain", rows: 3, chain: "aaaaaaaa" } }), res);
  assert.equal(res._status, 201);
});

test("ONE STORE: a batch of one is a real tree; its proof has an empty path and verifies", async () => {
  const res = await post({ namespace: "demo-one", entries: stores(1) });
  const p = res._body.proofs[0];
  assert.deepEqual(p.proof.path, []);
  assert.equal(sb.verifyStoreProof(p, {}, gh.read(PIN_REPO, res._body.entry_path)).ok, true);
});

test("ATTACK: an edited public entry, its time or namespace changed and the root kept, fails the proof", async () => {
  const { bundle, entry } = await oneProof();
  const backdated = { ...entry, accepted_at: "2026-01-01T00:00:00.000Z" };
  assert.equal(sb.verifyStoreProof(bundle, {}, backdated).reason, "accepted_at_mismatch");
  const moved = { ...entry, namespace: "demo-other" };
  assert.equal(sb.verifyStoreProof(bundle, {}, moved).reason, "namespace_mismatch");
  const notOurs = { ...entry, kind: "pin" };
  assert.equal(sb.verifyStoreProof(bundle, {}, notOurs).reason, "not_a_store_batch_entry");
});

test("METER: a key over its cap gets the meter's refusal and nothing is written", async () => {
  process.env.WITNESS_PLANS = JSON.stringify({ [meter.keyHash("testkeyA")]: { plan: "free", monthly_cap: 1 } });
  try {
    assert.equal((await post({ namespace: "demo-cap", entries: stores(2) }))._status, 201);
    const before = gh.putLog.filter((p) => p.repo === PIN_REPO).length;
    const res = await post({ namespace: "demo-cap", entries: stores(2) });
    assert.equal(res._status, 429);
    assert.equal(res._body.reason, "over_cap");
    assert.equal(gh.putLog.filter((p) => p.repo === PIN_REPO).length, before);
  } finally {
    delete process.env.WITNESS_PLANS;
  }
});

// --- with PR 4's shared limiter present (lib/_pin_ratelimit.js) ---

const usagePath = () => `usage/${meter.keyHash("testkeyA")}/${meter.utcMonth()}.json`;

test("PR 4 LIMITER: ?op=batch_stores through api/pin.js works with the shared limiter and counts one hit", async () => {
  const res = await post({ namespace: "demo-rl", entries: stores(5) });
  assert.equal(res._status, 201, JSON.stringify(res._body));
  assert.equal(res._body.proofs.length, 5);
  assert.equal(pinRate._buckets.get("testkeyA").count, 1, "a batch is one hit on the key's count");
});

test("PR 4 LIMITER: single pins and batches share one count; the 61st hit is the named 429 with Retry-After, nothing written or charged", async () => {
  for (let i = 0; i < pinRate.RATE_LIMIT - 1; i++) await pinRate.check("testkeyA");
  const single = makeRes();
  await pinHandler(makeReq({ method: "POST", headers: { authorization: "Bearer testkeyA" },
    body: { namespace: "demo-rl2", rows: 3, chain: "aaaaaaaa" } }), single);
  assert.equal(single._status, 201, JSON.stringify(single._body));
  const pubBefore = gh.putLog.filter((p) => p.repo === PIN_REPO).length;
  const usedBefore = gh.read(USAGE_REPO, usagePath()).used;
  const res = await post({ namespace: "demo-rl2", entries: stores(3) });
  assert.equal(res._status, 429, JSON.stringify(res._body));
  assert.equal(res._body.reason, "key_rate_limited");
  assert.equal(res._body.limit, 60);
  assert.equal(res._body.window_seconds, 3600);
  assert.equal(res._body.shared_across_instances, false);
  assert.ok(Number(res._headers["retry-after"]) >= 1);
  assert.equal(res._body.retry_after_seconds, Number(res._headers["retry-after"]));
  assert.equal(gh.putLog.filter((p) => p.repo === PIN_REPO).length, pubBefore);
  assert.equal(gh.read(USAGE_REPO, usagePath()).used, usedBefore);
  assert.equal((await post({ namespace: "demo-rl2", entries: stores(1) }, "testkeyB"))._status, 403,
    "another key is not limited by testkeyA's count (403 is its own namespace refusal)");
});

test("PR 4 LIMITER: an unreadable shared count refuses the batch 503 before any charge or write", async () => {
  let charged = 0;
  const res = makeRes();
  await sb.handle(makeReq({ method: "POST", body: { namespace: "demo-rl3", entries: stores(2) } }), res, {
    key: "testkeyA", prefix: "demo-",
    rateCheck: async () => ({ error: true, reason: "rate_limit_store_unreachable" }),
    meterAndCharge: async () => { charged++; return { ok: true, source: "free", headers: {} }; },
    refundFailedWrite: async () => {}, applyHeaders: () => {},
  });
  assert.equal(res._status, 503);
  assert.equal(res._body.reason, "rate_limit_store_unreachable");
  assert.equal(res._body.retry_safe, true);
  assert.equal(charged, 0);
  assert.equal(gh.putLog.length, 0);
});

// --- pricing guard: the flag alone cannot switch batches on ---

test("PRICE GUARD: flag on without WITNESS_STORE_BATCH_PRICE is a 503 batch_price_not_set; nothing written, charged or counted", async () => {
  delete process.env.WITNESS_STORE_BATCH_PRICE;
  for (const v of [undefined, "", "  "]) {
    if (v !== undefined) process.env.WITNESS_STORE_BATCH_PRICE = v;
    const res = await post({ namespace: "demo-price", entries: stores(2) });
    assert.equal(res._status, 503, JSON.stringify(res._body));
    assert.equal(res._body.reason, "batch_price_not_set");
    assert.equal(res._body.field, "WITNESS_STORE_BATCH_PRICE");
  }
  assert.equal(gh.putLog.length, 0);
  assert.equal(gh.read(USAGE_REPO, usagePath()), null);
  assert.equal(pinRate._buckets.size, 0);
});

test("PRICE GUARD: a pricing that is not built (per_store, capped, anything else) is refused, never served at one pin per batch", async () => {
  for (const v of ["per_store", "per_batch", "capped", "ONE_PIN_PER_BATCH", "1"]) {
    process.env.WITNESS_STORE_BATCH_PRICE = v;
    const res = await post({ namespace: "demo-price2", entries: stores(2) });
    assert.equal(res._status, 503, v);
    assert.equal(res._body.reason, "batch_price_not_implemented", v);
  }
  assert.equal(gh.putLog.length, 0);
  assert.deepEqual(sb.PRICE_SETTINGS, ["one_pin_per_batch"]);
  assert.equal(sb.priceProblem({ WITNESS_STORE_BATCH_PRICE: "one_pin_per_batch" }), null);
});
