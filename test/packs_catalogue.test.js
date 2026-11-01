// test/packs_catalogue.test.js — the 2026-11-03 pack catalogue (pins_200 $5,
// pins_1000 $20), the shared resolver, and the out-of-pins bodies.
"use strict";

process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
delete process.env.WITNESS_PLANS;
delete process.env.WITNESS_STRIPE_PRICE_MAP;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const balance = require("../lib/_balance.js");
const meter = require("../lib/_meter.js");
const pin = require("../api/pin.js");
const distill = require("../api/distill.js");

let gh;
let restore;
beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
});
afterEach(() => restore());

test("PACKS is the current catalogue only; retired packs live in LEGACY_PACKS", () => {
  assert.deepEqual(Object.keys(balance.PACKS).sort(), ["pins_1000", "pins_200"]);
  assert.deepEqual(balance.PACKS.pins_200, { price_usd: 5, pins: 200 });
  assert.deepEqual(balance.PACKS.pins_1000, { price_usd: 20, pins: 1000 });
  assert.deepEqual(Object.keys(balance.LEGACY_PACKS).sort(), ["bulk", "mini", "standard", "starter"]);
  assert.equal(balance.lookupPack("mini").pins, 1000);
  assert.equal(balance.lookupPack("constructor"), null);
  assert.equal(balance.lookupPack("__proto__"), null);
});

test("no amount-based matching exists: packForAmount is gone", () => {
  assert.equal(balance.packForAmount, undefined);
});

test("resolvePack: credited only when named; disagreement refused; the webhook mode ignores the price map", () => {
  process.env.WITNESS_STRIPE_PRICE_MAP = JSON.stringify({ price_a: "pins_1000", price_old: "mini" });
  try {
    const li = (id) => ({ data: [{ price: { id } }] });
    assert.deepEqual(balance.resolvePack({ line_items: li("price_a"), amount_total: 2000, currency: "usd" }), { pack: "pins_1000", source: "price_map" });
    assert.deepEqual(balance.resolvePack({ line_items: li("price_old"), amount_total: 500, currency: "usd" }), { pack: "mini", source: "price_map" });
    assert.deepEqual(balance.resolvePack({ metadata: { pack: " Mini " }, amount_total: 500, currency: "usd" }), { pack: "mini", source: "metadata" });
    assert.deepEqual(balance.resolvePack({ line_items: li("price_old"), metadata: { pack: "mini" } }), { pack: "mini", source: "price_map" });
    for (const cents of [500, 2000, 1500]) {
      assert.equal(balance.resolvePack({ metadata: {}, amount_total: cents, currency: "usd" }).reason, "not_named");
    }
    assert.equal(balance.resolvePack({ metadata: { pack: "pins_500" } }).reason, "unknown_pack");
    assert.equal(balance.resolvePack({ line_items: li("price_old"), metadata: { pack: "pins_200" } }).reason, "pack_conflict");
    assert.equal(balance.resolvePack({ line_items: { data: [{ price: { id: "price_a" } }, { price: { id: "price_old" } }] } }).reason, "pack_conflict");
    assert.equal(balance.resolvePack({ line_items: li("price_old") }, { priceMap: false }).reason, "not_named");
    assert.equal(balance.resolvePack(null).reason, "not_named");
  } finally {
    delete process.env.WITNESS_STRIPE_PRICE_MAP;
  }
});

test("publicPacks: current packs, price and pins only, fresh objects", () => {
  const p = balance.publicPacks();
  assert.deepEqual(p, { pins_200: { price_usd: 5, pins: 200 }, pins_1000: { price_usd: 20, pins: 1000 } });
  p.pins_200.pins = 1;
  assert.equal(balance.PACKS.pins_200.pins, 200);
});

for (const [name, mod] of [["pin", pin], ["distill", distill]]) {
  test(`${name}: a free key past its 10 gets a 429 that says the allowance is now 10 and how to get more`, async () => {
    const key = `over-cap-${name}-key`;
    assert.equal(meter.PLAN_CAPS.free, 10);
    for (let i = 0; i < 10; i++) {
      const r = await mod.meterAndCharge(key);
      assert.equal(r.ok, true, `call ${i + 1} within the free 10`);
    }
    const r = await mod.meterAndCharge(key);
    assert.equal(r.deny.status, 429);
    const b = r.deny.body;
    assert.equal(b.reason, "over_cap");
    assert.equal(b.cap, 10);
    assert.deepEqual(b.packs, balance.publicPacks(), "current packs only, no internal fields");
    assert.ok(!("mini" in b.packs));
    assert.match(b.message, /free allowance is now 10 pins a month/);
    assert.doesNotMatch(b.message, /it was 100/);
    assert.doesNotMatch(b.message, /https?:/, "no buy link while PACK_BUY_URL is empty");
    assert.match(b.message, /buy a pin pack: 200 pins for \$5 or 1,000 pins for \$20/);
    assert.match(b.message, /never expire/);
    assert.doesNotMatch(b.message, /[–—]/, "no en/em dashes");
  });

  test(`${name}: a spent-out buyer gets a 402 listing current packs only`, async () => {
    const key = `spent-${name}-key`;
    const hash = balance.keyHash(key);
    // A buyer who has purchased before and has nothing left.
    await balance.creditPack(hash, "pins_200", `evt-spent-${name}`, "test");
    await balance.debitCredits(key, 200, "test spend");
    for (let i = 0; i < 10; i++) await mod.meterAndCharge(key);
    const r = await mod.meterAndCharge(key);
    assert.equal(r.deny.status, 402, JSON.stringify(r));
    assert.deepEqual(r.deny.body.packs, balance.publicPacks());
  });
}

test("overCapMessage: a buy URL, when set, is named; empty means no link", () => {
  assert.equal(balance.PACK_BUY_URL, "");
  assert.ok(balance.overCapMessage("free", 10, "https://example.test/buy").includes(" at https://example.test/buy. "));
  assert.ok(!balance.overCapMessage("free", 10, "").includes(" at "));
});
