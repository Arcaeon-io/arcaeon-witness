// test/stripe_webhook.test.js — api/stripe-webhook.js: POST /api/stripe-webhook.
"use strict";

process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_STRIPE_WEBHOOK_SECRET = "whsec_test_secret_123";
delete process.env.WITNESS_STRIPE_LIVEMODE; // default: expects live (true)

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeRawReq, makeRes } = require("./helpers/http_mocks.js");
const { stripeSigHeader } = require("./helpers/stripe_sign.js");
const balance = require("../lib/_balance.js");
const webhook = require("../api/stripe-webhook.js");

const SECRET = process.env.WITNESS_STRIPE_WEBHOOK_SECRET;

let gh;
let restore;

beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
});

afterEach(() => {
  restore();
});

const PACK_CENTS = { mini: 500, starter: 1500, standard: 5000, bulk: 15000 };
function checkoutEvent({
  id = "evt-default", hash, pack, paymentStatus = "paid", livemode = true,
  amountTotal, currency = "usd", type = "checkout.session.completed", sessionId,
}) {
  // default amount to the correct price for the pack so existing happy-path
  // tests stay valid; H1 regression tests override amountTotal explicitly.
  const amt = amountTotal === undefined ? (PACK_CENTS[pack] ?? 0) : amountTotal;
  return {
    id,
    type,
    livemode,
    data: {
      object: {
        id: sessionId,
        payment_status: paymentStatus,
        client_reference_id: hash,
        metadata: { pack },
        amount_total: amt,
        currency,
      },
    },
  };
}

async function post(event, { badSignature = false, noSignature = false, wrongSecret = false } = {}) {
  const rawBody = Buffer.from(JSON.stringify(event), "utf8");
  const headers = {};
  if (!noSignature) {
    const secretToSign = wrongSecret ? "whsec_wrong_secret" : SECRET;
    headers["stripe-signature"] = stripeSigHeader(secretToSign, badSignature ? Buffer.from("tampered") : rawBody);
  }
  const req = makeRawReq({ headers, rawBody });
  const res = makeRes();
  await webhook(req, res);
  return res;
}

// ---------------------------------------------------------------------
// CONTRACT: webhook signature required (unit-level, via the real dispatch path)
// ---------------------------------------------------------------------

test("CONTRACT: request with NO stripe-signature header is rejected 400 (the verify function refuses unsigned)", async () => {
  const hash = balance.keyHash("sig-missing-secret");
  const event = checkoutEvent({ id: "evt-sig-1", hash, pack: "mini" });
  const res = await post(event, { noSignature: true });
  assert.equal(res._status, 400);
  assert.ok(res._body.error.includes("signature verification failed"));
  const bal = await balance.readBalance(hash);
  assert.equal(bal.balance, 0, "an unsigned request must credit nothing");
});

test("CONTRACT: a signature computed with the WRONG secret is rejected 400 (mismatch)", async () => {
  const hash = balance.keyHash("sig-wrong-secret");
  const event = checkoutEvent({ id: "evt-sig-2", hash, pack: "mini" });
  const res = await post(event, { wrongSecret: true });
  assert.equal(res._status, 400);
  assert.ok(res._body.error.includes("signature verification failed"));
  const bal = await balance.readBalance(hash);
  assert.equal(bal.balance, 0);
});

test("CONTRACT: a signature computed over a DIFFERENT body than what's sent is rejected 400 (tamper)", async () => {
  const hash = balance.keyHash("sig-tampered-secret");
  const event = checkoutEvent({ id: "evt-sig-3", hash, pack: "mini" });
  const res = await post(event, { badSignature: true });
  assert.equal(res._status, 400);
  const bal = await balance.readBalance(hash);
  assert.equal(bal.balance, 0);
});

// ---------------------------------------------------------------------
// CONTRACT: valid delivery credits the right pack
// ---------------------------------------------------------------------

test("CONTRACT: a valid, signed, paid, live event credits the declared pack", async () => {
  const hash = balance.keyHash("valid-delivery-secret");
  const event = checkoutEvent({ id: "evt-valid-1", hash, pack: "mini" });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.equal(res._body.credited, true);
  assert.equal(res._body.balance_after, balance.LEGACY_PACKS.mini.pins);

  const bal = await balance.readBalance(hash);
  assert.equal(bal.balance, balance.LEGACY_PACKS.mini.pins);
});

// ---------------------------------------------------------------------
// CONTRACT: metadata.pack unknown -> no grant
// ---------------------------------------------------------------------

test("CONTRACT: metadata.pack unknown or missing skips crediting, never grants", async () => {
  const hash = balance.keyHash("unknown-pack-webhook-secret");
  const event = checkoutEvent({ id: "evt-unkpack-1", hash, pack: "totally-not-a-pack" });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.ok(res._body.skipped.includes("pack missing or unknown"));

  const bal = await balance.readBalance(hash);
  assert.equal(bal.balance, 0);
  assert.equal(bal.ever_purchased, false);
});

test("CONTRACT: missing client_reference_id skips crediting (nothing to credit)", async () => {
  const event = checkoutEvent({ id: "evt-nohash-1", hash: undefined, pack: "mini" });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.ok(res._body.skipped.includes("client_reference_id"));
});

// ---------------------------------------------------------------------
// CONTRACT: payment + livemode gates
// ---------------------------------------------------------------------

test("CONTRACT: an unpaid session is skipped, not credited (async payment methods aren't money yet)", async () => {
  const hash = balance.keyHash("unpaid-secret");
  const event = checkoutEvent({ id: "evt-unpaid-1", hash, pack: "mini", paymentStatus: "unpaid" });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.ok(res._body.skipped.includes("not paid"));
  const bal = await balance.readBalance(hash);
  assert.equal(bal.balance, 0);
});

test("CONTRACT: a test-mode (livemode:false) event never credits the live balance", async () => {
  const hash = balance.keyHash("livemode-mismatch-secret");
  const event = checkoutEvent({ id: "evt-livemode-1", hash, pack: "mini", livemode: false });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.ok(res._body.skipped.includes("livemode mismatch"));
  const bal = await balance.readBalance(hash);
  assert.equal(bal.balance, 0);
});

test("CONTRACT: an unhandled event type is a no-op 200, not an error (Stripe would otherwise retry forever)", async () => {
  const event = { id: "evt-other-1", type: "customer.created", data: { object: {} } };
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.ok(res._body.skipped.includes("unhandled event type"));
});

// ---------------------------------------------------------------------
// REGRESSION: idempotency end-to-end through the real webhook dispatch path
// (ties the balance-layer money-bug fix to the actual HTTP entry point)
// ---------------------------------------------------------------------

test("REGRESSION (money bug, end-to-end via webhook): a duplicate Stripe delivery of the same event never double-credits", async () => {
  const hash = balance.keyHash("webhook-dup-secret");
  const event = checkoutEvent({ id: "evt-webhook-dup-1", hash, pack: "starter" });

  const first = await post(event);
  assert.equal(first._status, 200);
  assert.equal(first._body.credited, true);

  const retry = await post(event); // Stripe redelivering the identical event
  assert.equal(retry._status, 200);
  assert.equal(retry._body.credited, false);
  assert.equal(retry._body.already_credited, true);
  assert.equal(retry._body.balance_after, balance.LEGACY_PACKS.starter.pins);

  const bal = await balance.readBalance(hash);
  assert.equal(bal.balance, balance.LEGACY_PACKS.starter.pins, "two deliveries of one event must credit the pack exactly once");
});

// ---------------------------------------------------------------------------
// H1 REGRESSION (quad-check 2026-08-16): the money path must VERIFY the money.
// The handler previously read only who-to-credit + the metadata pack name and
// NEVER read amount_total — a signed $5 event with pack=bulk granted 40,000
// pins. These pin the amount cross-check + the H3 normalization fix.
// ---------------------------------------------------------------------------

test("H1 REGRESSION: $5.00 paid with metadata.pack=bulk must NOT grant 40,000 pins", async () => {
  const hash = balance.keyHash("h1-underpay-secret");
  const event = checkoutEvent({ id: "evt-underpay", hash, pack: "bulk", amountTotal: 500 });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.match(res._body.skipped || "", /does not match|not credited/i);
  const bal = await balance.readBalance(hash);
  assert.equal(bal.balance, 0, "no pins for an underpaid bulk claim");
});

test("H1 REGRESSION: amount_total=0 and absent both refuse to credit", async () => {
  for (const kind of ["zero", "absent"]) {
    const hash = balance.keyHash("h1-zero-" + kind);
    const event = checkoutEvent({ id: "evt-zero-" + kind, hash, pack: "starter", amountTotal: 0 });
    if (kind === "absent") delete event.data.object.amount_total;
    const res = await post(event);
    assert.equal(res._status, 200);
    assert.match(res._body.skipped || "", /does not match|not credited/i);
    const bal = await balance.readBalance(hash);
    assert.equal(bal.balance, 0);
  }
});

test("H1: correct amount for the pack still credits (happy path unbroken)", async () => {
  const hash = balance.keyHash("h1-correct-secret");
  const event = checkoutEvent({ id: "evt-correct", hash, pack: "mini", amountTotal: 500 });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.equal(res._body.credited, true);
  const bal = await balance.readBalance(hash);
  assert.equal(bal.balance, balance.LEGACY_PACKS.mini.pins);
});

test("H3 REGRESSION: uppercase hash + ' Mini ' pack normalize and credit, not silent no-op", async () => {
  const canonical = balance.keyHash("h3-normalize-secret");
  const event = checkoutEvent({ id: "evt-caps", hash: canonical.toUpperCase(), pack: " Mini ", amountTotal: 500 });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.equal(res._body.credited, true, "normalized caps/spacing must credit, not skip");
  const bal = await balance.readBalance(canonical);
  assert.equal(bal.balance, balance.LEGACY_PACKS.mini.pins);
});

// ---------------------------------------------------------------------------
// H2 REGRESSION (quad-check 2026-08-16): async payment methods (ACH, Klarna)
// collect money and never got credited. checkout.session.completed fires
// first with payment_status=unpaid (correctly skipped), and the ACTUAL
// money-cleared signal, checkout.session.async_payment_succeeded, used to be
// discarded as "unhandled event type" — a real $150 ACH clear credited zero
// pins, silently, with a 200 both times (no Stripe retry).
// ---------------------------------------------------------------------------

test("H2 REGRESSION: the ACH/Klarna sequence — unpaid `completed` then a real `async_payment_succeeded` — credits exactly once", async () => {
  const hash = balance.keyHash("h2-async-secret");
  const sessionId = "cs_test_async_1";

  // 1) checkout.session.completed fires first; async methods aren't cleared
  // yet, so payment_status is unpaid. Correctly skipped, credits nothing.
  const completed = checkoutEvent({
    id: "evt-async-completed-1", hash, pack: "starter",
    paymentStatus: "unpaid", sessionId,
  });
  const res1 = await post(completed);
  assert.equal(res1._status, 200);
  assert.match(res1._body.skipped || "", /not paid/i);
  assert.equal((await balance.readBalance(hash)).balance, 0);

  // 2) Days later, the ACH debit clears: checkout.session.async_payment_succeeded
  // fires with payment_status=paid. This is the event the old code discarded.
  const asyncSucceeded = checkoutEvent({
    id: "evt-async-succeeded-1", hash, pack: "starter",
    paymentStatus: "paid", sessionId,
  });
  asyncSucceeded.type = "checkout.session.async_payment_succeeded";
  const res2 = await post(asyncSucceeded);
  assert.equal(res2._status, 200);
  assert.equal(res2._body.credited, true, "a cleared async payment must actually credit the pack");
  assert.equal(res2._body.balance_after, balance.LEGACY_PACKS.starter.pins);

  const bal = await balance.readBalance(hash);
  assert.equal(bal.balance, balance.LEGACY_PACKS.starter.pins, "the buyer's cleared ACH payment must be credited exactly once");
});

test("H2 REGRESSION: checkout.session.async_payment_failed is logged and skipped, never credited", async () => {
  const hash = balance.keyHash("h2-async-failed-secret");
  const event = checkoutEvent({
    id: "evt-async-failed-1", hash, pack: "starter", paymentStatus: "unpaid",
  });
  event.type = "checkout.session.async_payment_failed";
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.match(res._body.skipped || "", /async payment failed/i);
  assert.equal((await balance.readBalance(hash)).balance, 0);
});

// ---------------------------------------------------------------------------
// H2's "subtle one" — traced mechanically against Stripe's own fulfillment
// guidance (docs.stripe.com/checkout/fulfillment: "your fulfill_checkout
// function might be called multiple times, possibly concurrently, for the
// same Checkout Session" — their reference handler dedupes on the SESSION id,
// not the event id, for exactly this reason). Two DIFFERENT event ids for the
// SAME session, both carrying payment_status=paid, must still credit only
// once — applied_events keyed on event.id alone cannot catch this; keying on
// session.id does.
// ---------------------------------------------------------------------------

test("H2 REGRESSION: two different event ids reporting paid for the SAME session never double-credit", async () => {
  const hash = balance.keyHash("h2-cross-event-secret");
  const sessionId = "cs_test_cross_event_1";

  // A `checkout.session.completed` delivery that is ALREADY paid (a
  // synchronous method, or a redelivered/duplicated completed event).
  const completedPaid = checkoutEvent({
    id: "evt-cross-a", hash, pack: "standard", paymentStatus: "paid", sessionId,
  });
  const res1 = await post(completedPaid);
  assert.equal(res1._status, 200);
  assert.equal(res1._body.credited, true);
  assert.equal(res1._body.balance_after, balance.LEGACY_PACKS.standard.pins);

  // A SEPARATE event id, async_payment_succeeded, also paid, for the SAME
  // session — the exact shape Stripe's own docs warn a fulfillment handler
  // must survive without double-fulfilling.
  const asyncSucceeded = checkoutEvent({
    id: "evt-cross-b", hash, pack: "standard", paymentStatus: "paid", sessionId,
  });
  asyncSucceeded.type = "checkout.session.async_payment_succeeded";
  const res2 = await post(asyncSucceeded);
  assert.equal(res2._status, 200);
  assert.equal(res2._body.credited, false, "a second event id for the same session must not grant a second time");
  assert.equal(res2._body.already_credited, true);
  assert.equal(res2._body.balance_after, balance.LEGACY_PACKS.standard.pins);

  const bal = await balance.readBalance(hash);
  assert.equal(bal.balance, balance.LEGACY_PACKS.standard.pins, "one real purchase, reported by two event ids, must credit exactly once");
});

// ---------------------------------------------------------------------------
// SITE #26 (VERDICT_SURVEY.md): the currency clause was a conjunction,
// `(currency && currency !== "usd")`. A MISSING currency made it false, so a
// signature-valid, paid, correct-amount session with no currency at all was
// credited. Damage switched off the check that should have caught it.
// ---------------------------------------------------------------------------

test("SITE #26 REGRESSION: a signed, paid session with NO currency is NOT credited", async () => {
  for (const kind of ["absent", "null", "empty"]) {
    const hash = balance.keyHash("site26-no-currency-" + kind);
    const event = checkoutEvent({ id: "evt-nocur-" + kind, hash, pack: "mini", amountTotal: 500 });
    if (kind === "absent") delete event.data.object.currency;
    if (kind === "null") event.data.object.currency = null;
    if (kind === "empty") event.data.object.currency = "";
    const res = await post(event);
    assert.equal(res._status, 200, `currency ${kind}: answered ${res._status}`);
    assert.notEqual(res._body.credited, true, `currency ${kind}: a session of unknown currency was credited: ${JSON.stringify(res._body)}`);
    assert.match(res._body.skipped || "", /does not match|not credited/i);
    const bal = await balance.readBalance(hash);
    assert.equal(bal.balance, 0, `currency ${kind}: pins granted without a stated currency`);
  }
});

test("SITE #26: a non-USD currency still refuses, and upper-case USD still credits", async () => {
  const eurHash = balance.keyHash("site26-eur");
  const eur = await post(checkoutEvent({ id: "evt-eur", hash: eurHash, pack: "mini", amountTotal: 500, currency: "eur" }));
  assert.match(eur._body.skipped || "", /not credited/i);
  assert.equal((await balance.readBalance(eurHash)).balance, 0);

  const usdHash = balance.keyHash("site26-USD");
  const usd = await post(checkoutEvent({ id: "evt-USD", hash: usdHash, pack: "mini", amountTotal: 500, currency: "USD" }));
  assert.equal(usd._body.credited, true);
  assert.equal((await balance.readBalance(usdHash)).balance, balance.LEGACY_PACKS.mini.pins);
});

// ---------------------------------------------------------------------------
// 2026-11-01 review fix: the webhook resolves the pack with the SAME function
// as /api/fulfill (lib/_balance.js resolvePack), still checking the money.
// ---------------------------------------------------------------------------

test("webhook: both NEW packs credit by metadata.pack (pins_200 -> 200, pins_1000 -> 1,000)", async () => {
  for (const [pack, cents, pins] of [["pins_200", 500, 200], ["pins_1000", 2000, 1000]]) {
    const hash = balance.keyHash("wh-new-meta-" + pack);
    const res = await post(checkoutEvent({ id: "evt-new-meta-" + pack, sessionId: "cs_live_meta_" + pack, hash, pack, amountTotal: cents }));
    assert.equal(res._status, 200);
    assert.equal(res._body.credited, true, JSON.stringify(res._body));
    assert.equal(res._body.pack, pack);
    assert.equal((await balance.readBalance(hash)).balance, pins);
  }
});

test("webhook: no metadata.pack -> logged and skipped (200, no credit), even for exactly $5 or $20", async () => {
  for (const cents of [500, 2000]) {
    const hash = balance.keyHash("wh-no-meta-" + cents);
    const res = await post(checkoutEvent({ id: "evt-no-meta-" + cents, sessionId: "cs_live_nometa_" + cents, hash, pack: undefined, amountTotal: cents }));
    assert.equal(res._status, 200);
    assert.notEqual(res._body.credited, true, JSON.stringify(res._body));
    assert.match(res._body.skipped || "", /pack missing or unknown/);
    assert.equal((await balance.readBalance(hash)).balance, 0);
  }
});

test("webhook: never uses the price map, even if a payload carried line_items (metadata.pack only)", async () => {
  const saved = process.env.WITNESS_STRIPE_PRICE_MAP;
  process.env.WITNESS_STRIPE_PRICE_MAP = JSON.stringify({ price_wh_1000: "pins_1000" });
  try {
    const hash = balance.keyHash("wh-price-map");
    const ev = checkoutEvent({ id: "evt-pmap", sessionId: "cs_live_pmap", hash, pack: undefined, amountTotal: 2000 });
    ev.data.object.line_items = { data: [{ price: { id: "price_wh_1000" } }] };
    const res = await post(ev);
    assert.notEqual(res._body.credited, true, JSON.stringify(res._body));
    assert.equal((await balance.readBalance(hash)).balance, 0);
  } finally {
    if (saved === undefined) delete process.env.WITNESS_STRIPE_PRICE_MAP; else process.env.WITNESS_STRIPE_PRICE_MAP = saved;
  }
});

test("webhook: unmappable amount, retired pack price with no name, and a named unknown pack all credit nothing", async () => {
  const cases = [
    { pack: undefined, amountTotal: 1000 },     // no current pack costs $10
    { pack: undefined, amountTotal: 1500 },     // starter's price, but starter is not named
    { pack: "pins_500", amountTotal: 500 },     // named unknown
  ];
  for (const [i, c] of cases.entries()) {
    const hash = balance.keyHash("wh-unmapped-" + i);
    const res = await post(checkoutEvent({ id: "evt-unmapped-" + i, sessionId: "cs_live_unm_" + i, hash, ...c }));
    assert.equal(res._status, 200);
    assert.notEqual(res._body.credited, true, JSON.stringify(res._body));
    assert.match(res._body.skipped || "", /pack missing or unknown/);
    assert.equal((await balance.readBalance(hash)).balance, 0);
  }
});

test("webhook: underpay of a new pack credits nothing ($4.99 for pins_200; $5 named pins_1000)", async () => {
  for (const [i, c] of [{ pack: "pins_200", amountTotal: 499 }, { pack: "pins_1000", amountTotal: 500 }].entries()) {
    const hash = balance.keyHash("wh-underpay-new-" + i);
    const res = await post(checkoutEvent({ id: "evt-underpay-new-" + i, sessionId: "cs_live_up_" + i, hash, ...c }));
    assert.equal(res._status, 200);
    assert.notEqual(res._body.credited, true);
    assert.match(res._body.skipped || "", /does not match/);
    assert.equal((await balance.readBalance(hash)).balance, 0);
  }
});
