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

const PIN_REPO = process.env.GITHUB_PIN_REPO;
const USAGE_REPO = process.env.GITHUB_USAGE_REPO;
let gh, restore;
const realPutSleep = store._putRetry.sleep;

beforeEach(() => {
  process.env.WITNESS_STORE_BATCH = "on";
  gh = new MockGitHubStore();
  restore = install(gh);
  store._putRetry.sleep = async () => {};
});
afterEach(() => {
  delete process.env.WITNESS_STORE_BATCH;
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
    key: "testkeyA", prefix: "demo-", rateLimited: () => false,
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
    key: "testkeyA", prefix: "demo-", rateLimited: () => false,
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

// --- job 9: the per store latest ---

let ipN = 0;
async function lookup(query) {
  const res = makeRes();
  ipN += 1;
  await pinHandler(makeReq({ method: "GET", headers: { "x-forwarded-for": `10.20.${ipN >> 8}.${ipN & 255}` },
    query: { op: "batch_stores", ...query } }), res);
  return res;
}

test("LATEST: a store asks with its store_id and gets its latest entry, leaf index and leaf", async () => {
  const first = await post({ namespace: "demo-lat", entries: stores(3) });
  const res = await lookup({ namespace: "demo-lat", store_id: "memory-1" });
  assert.equal(res._status, 200, JSON.stringify(res._body));
  assert.equal(res._body.entry_path, first._body.entry_path);
  assert.equal(res._body.leaf_index, 1);
  assert.deepEqual(res._body.leaf, first._body.proofs[1].proof.leaf);
  // A later batch moves the pointer for the stores it names, and only those.
  const second = await post({ namespace: "demo-lat", entries: [{ store_id: "memory-1", head: head("new") }] });
  const now1 = await lookup({ namespace: "demo-lat", store_id: "memory-1" });
  assert.equal(now1._body.entry_path, second._body.entry_path);
  assert.equal(now1._body.leaf.head, head("new"));
  const still = await lookup({ namespace: "demo-lat", store_id: "memory-2" });
  assert.equal(still._body.entry_path, first._body.entry_path);
});

test("LATEST: a lost local proof is noticed, the answer lets the store check its own proof against it", async () => {
  const r = await post({ namespace: "demo-lost", entries: stores(4) });
  const kept = r._body.proofs[2];
  const ans = await lookup({ namespace: "demo-lost", store_id: "memory-2" });
  // The store compares: same entry and leaf as its proof, so nothing is missing.
  assert.equal(ans._body.entry_path, kept.entry_path);
  assert.deepEqual(ans._body.leaf, kept.proof.leaf);
  // After a batch it never saw (its proof was deleted), the answer differs.
  await post({ namespace: "demo-lost", entries: [{ store_id: "memory-2", head: head("unseen") }] });
  const later = await lookup({ namespace: "demo-lost", store_id: "memory-2" });
  assert.notEqual(later._body.entry_path, kept.entry_path);
});

test("LATEST: no listing; an unknown store and an unknown namespace get the same 404", async () => {
  await post({ namespace: "demo-hid", entries: stores(2) });
  const a = await lookup({ namespace: "demo-hid", store_id: "memory-9" });
  const b = await lookup({ namespace: "demo-none", store_id: "memory-0" });
  assert.equal(a._status, 404);
  assert.deepEqual(a._body, b._body);
  assert.equal(a._body.field, "store_id");
});

test("LATEST: the index is private, one write per batch whatever its size, and never in the public repo", async () => {
  const before = gh.putLog.filter((p) => p.repo === USAGE_REPO).length;
  await post({ namespace: "demo-one-write", entries: stores(300) });
  const priv = gh.putLog.filter((p) => p.repo === USAGE_REPO).slice(before).map((p) => p.path);
  assert.equal(priv.filter((p) => p.startsWith("store_latest/")).length, 1);
  assert.ok(gh.has(USAGE_REPO, "store_latest/demo-one-write.json"));
  assert.ok(!gh.putLog.some((p) => p.repo === PIN_REPO && p.path.startsWith("store_latest/")));
  const idx = gh.read(USAGE_REPO, "store_latest/demo-one-write.json");
  assert.equal(Object.keys(idx.stores).length, 300);
  assert.ok(Object.keys(idx.stores).every((k) => /^[0-9a-f]{64}$/.test(k)), "keyed by hash, not by store_id");
});

test("LATEST: an older batch never moves a pointer back over a newer one", async () => {
  const entries = [{ store_id: "memory-0", head: head("x") }];
  const call = async (when, h) => {
    const res = makeRes();
    await sb.handle(makeReq({ method: "POST", body: { namespace: "demo-order", entries: [{ ...entries[0], head: h }] } }), res, {
      key: "testkeyA", prefix: "demo-", rateLimited: () => false,
      meterAndCharge: async () => ({ ok: true, source: "free", headers: {} }),
      refundFailedWrite: async () => {}, applyHeaders: () => {}, now: () => new Date(when),
    });
    return res;
  };
  const newer = await call("2026-10-31T10:00:00.000Z", head("new"));
  await call("2026-10-31T09:00:00.000Z", head("old"));
  const ans = await lookup({ namespace: "demo-order", store_id: "memory-0" });
  assert.equal(ans._body.entry_path, newer._body.entry_path);
});

test("LATEST: an index that cannot be written leaves the batch standing and says so", async () => {
  gh.forceFailure(USAGE_REPO, "store_latest/demo-behind.json", 5, 500);
  const res = await post({ namespace: "demo-behind", entries: stores(2) });
  assert.equal(res._status, 201);
  assert.equal(res._body.latest_index, "not_updated");
  assert.ok(gh.has(PIN_REPO, res._body.entry_path));
});

test("LATEST: something that is not an index is never written over", async () => {
  gh.seed(USAGE_REPO, "store_latest/demo-odd.json", { not: "an index" });
  const res = await post({ namespace: "demo-odd", entries: stores(1) });
  assert.equal(res._body.latest_index, "not_updated");
  assert.deepEqual(gh.read(USAGE_REPO, "store_latest/demo-odd.json"), { not: "an index" });
});

test("LATEST: refusals name the field; flag off is not_enabled; the per IP limit applies", async () => {
  assert.equal((await lookup({ namespace: "BAD", store_id: "a" }))._body.field, "namespace");
  const badId = await lookup({ namespace: "demo-x", store_id: "a b" });
  assert.equal(badId._status, 400);
  assert.equal(badId._body.reason, "bad_store_id");
  delete process.env.WITNESS_STORE_BATCH;
  assert.equal((await lookup({ namespace: "demo-x", store_id: "a" }))._body.reason, "not_enabled");
  process.env.WITNESS_STORE_BATCH = "on";
  let last;
  for (let i = 0; i < 40; i++) {
    const res = makeRes();
    await pinHandler(makeReq({ method: "GET", headers: { "x-forwarded-for": "10.99.0.1" },
      query: { op: "batch_stores", namespace: "demo-x", store_id: "a" } }), res);
    last = res;
  }
  assert.equal(last._status, 429);
});

test("LATEST: a lost race on the index re-reads and lands", async () => {
  gh.forceConflict(USAGE_REPO, "store_latest/demo-race.json", 1);
  const res = await post({ namespace: "demo-race", entries: stores(2) });
  assert.equal(res._body.latest_index, "updated");
  assert.equal((await lookup({ namespace: "demo-race", store_id: "memory-0" }))._status, 200);
});

test("LATEST: an index entry whose leaf names another store is not answered", async () => {
  await post({ namespace: "demo-tamper", entries: stores(2) });
  const idx = gh.read(USAGE_REPO, "store_latest/demo-tamper.json");
  const k0 = sb.storeKey("demo-tamper", "memory-0");
  const k1 = sb.storeKey("demo-tamper", "memory-1");
  idx.stores[k0] = idx.stores[k1];
  gh.seed(USAGE_REPO, "store_latest/demo-tamper.json", idx);
  assert.equal((await lookup({ namespace: "demo-tamper", store_id: "memory-0" }))._status, 404);
});

test("LATEST: two batches at the very same time, the later write wins", async () => {
  const when = new Date("2026-10-31T11:00:00.000Z");
  const call = async (h) => {
    const res = makeRes();
    await sb.handle(makeReq({ method: "POST", body: { namespace: "demo-same-ms", entries: [{ store_id: "s", head: h }] } }), res, {
      key: "testkeyA", prefix: "demo-", rateLimited: () => false,
      meterAndCharge: async () => ({ ok: true, source: "free", headers: {} }),
      refundFailedWrite: async () => {}, applyHeaders: () => {}, now: () => when,
    });
    return res;
  };
  await call(head("first"));
  const second = await call(head("second"));
  const ans = await lookup({ namespace: "demo-same-ms", store_id: "s" });
  assert.equal(ans._body.entry_path, second._body.entry_path);
});
