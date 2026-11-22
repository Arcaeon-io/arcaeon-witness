// test/hardening_money.test.js — guards on the money and account-forward
// paths that no test held (2026-11-22 sweep, second part of the code).
//
// Method: every early `if (...) return/throw` in lib/_balance.js,
// lib/_meter.js and lib/_accounts_forward.js was disabled in turn and the
// whole suite run. Three survived; each test here fails with its guard gone.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const balance = require("../lib/_balance.js");
const forward = require("../lib/_accounts_forward.js");

function withEnv(name, value, fn) {
  const saved = process.env[name];
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
  try {
    return fn();
  } finally {
    if (saved === undefined) delete process.env[name];
    else process.env[name] = saved;
  }
}

function captureErrors(fn) {
  const lines = [];
  const saved = console.error;
  console.error = (...a) => lines.push(a.join(" "));
  try {
    fn();
  } finally {
    console.error = saved;
  }
  return lines;
}

test("PACK LINKS: a WITNESS_PACK_LINKS that is valid JSON but not an object (null, an array, a number, a string) gives no links and never throws", () => {
  for (const raw of ["null", "[]", '["https://buy.stripe.com/x"]', "5", '"https://buy.stripe.com/x"', "true"]) {
    withEnv("WITNESS_PACK_LINKS", raw, () => {
      let links;
      assert.doesNotThrow(() => { links = balance.loadPackLinks(); }, `WITNESS_PACK_LINKS=${raw}`);
      assert.deepEqual(links, {}, `WITNESS_PACK_LINKS=${raw}`);
      // buyFor is what every out-of-pins answer (402 and 429) calls; a throw
      // here would turn each of them into a 500.
      let b;
      assert.doesNotThrow(() => { b = balance.buyFor("some-key"); }, `buyFor with WITNESS_PACK_LINKS=${raw}`);
      assert.equal(b.buy, null);
      assert.equal(typeof b.buy_url, "string");
    });
  }
});

test("PACK LINKS: a dropped link is logged once per pack id per instance, not on every out-of-pins answer", () => {
  // A pack id no other test drops, so this instance has not warned about it yet.
  const id = Object.keys(balance.PACKS).find(Boolean);
  const bad = JSON.stringify({ [id]: "https://evil.example.com/pay" });
  const lines = captureErrors(() => withEnv("WITNESS_PACK_LINKS", bad, () => {
    for (let i = 0; i < 5; i++) balance.buyFor("k");
  }));
  const mine = lines.filter((l) => l.includes(`WITNESS_PACK_LINKS.${id} `));
  assert.ok(mine.length <= 1, `logged ${mine.length} times: ${JSON.stringify(mine)}`);
  // And it was logged at least once in this process (by this test or an earlier one).
  const again = captureErrors(() => withEnv("WITNESS_PACK_LINKS", bad, () => balance.buyFor("k")));
  assert.equal(again.filter((l) => l.includes(`WITNESS_PACK_LINKS.${id} `)).length, 0, "the sixth call logs nothing");
});

test("ACCOUNTS URL: an unset or empty WITNESS_ACCOUNTS_URL says it is not set (not that it is not an address)", () => {
  for (const base of [undefined, "", null, 0]) {
    const r = forward.checkoutUrl(base);
    assert.equal(r.url, null);
    assert.equal(r.reason, "WITNESS_ACCOUNTS_URL is not set", `base=${JSON.stringify(base)}`);
  }
  assert.equal(forward.checkoutUrl("not a url").reason, "WITNESS_ACCOUNTS_URL is not an address");
  assert.equal(forward.checkoutUrl("https://accounts.example.org").url, `https://accounts.example.org${forward.PATH}`);
});
