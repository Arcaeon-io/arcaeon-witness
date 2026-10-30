// test/cross_path_credit.test.js — one purchase, one credit, one target.
//
// pins_200 and pins_1000 are the SAME Stripe prices on two paths:
//   - bare key: a Payment Link (session carries payment_link) redirects to
//     /api/fulfill, which mints a key (or tops up the key named by a sha256
//     client_reference_id); the legacy webhook path credits that same key for
//     a top-up. Both are keyed on the session id (lib/_balance.js).
//   - account: POST /api/account/checkout makes the session on the account's
//     own customer with metadata.account_id / account_ref and a signed
//     client_reference_id; the account webhook branch credits the account
//     (account_packs.purchase_ref = the session id).
// Every place that credits pins from a Stripe session is driven here with the
// same session: api/fulfill.js (mint and top-up), api/stripe-webhook.js
// (legacy branch and account branch), on checkout.session.completed and
// checkout.session.async_payment_succeeded, replayed and redelivered.
// No live calls: Stripe's GET session is mocked, the key store is the mock
// GitHub store, the account store is the in-memory one.
"use strict";

process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_STRIPE_SECRET_KEY = "sk_test_cross_path_mock_only"; // test-only literal, not a real credential
process.env.WITNESS_STRIPE_WEBHOOK_SECRET = "whsec_test_cross_path_only"; // test-only literal
process.env.WITNESS_STRIPE_LIVEMODE = "false"; // fixtures are cs_test_ / livemode:false
// The same price ids serve both paths: that is the whole risk under test.
process.env.WITNESS_STRIPE_PRICE_MAP = JSON.stringify({ price_pins_200_test: "pins_200", price_pins_1000_test: "pins_1000" });
delete process.env.WITNESS_KEYS;
delete process.env.WITNESS_PLANS;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const { MockGitHubStore } = require("./helpers/mock_store.js");
const { makeReq, makeRawReq, makeRes } = require("./helpers/http_mocks.js");
const { stripeSigHeader } = require("./helpers/stripe_sign.js");
const ev = require("./helpers/account_events.js"); // sets a test ACCOUNT_REF_SECRET
const balance = require("../lib/_balance.js");
const billing = require("../lib/_account_billing.js");
const accountdb = require("../lib/_accountdb.js");
const fulfill = require("../api/fulfill.js");
const webhook = require("../api/stripe-webhook.js");

const USAGE = process.env.GITHUB_USAGE_REPO;
const SECRET = process.env.WITNESS_STRIPE_WEBHOOK_SECRET;
const T0 = Date.UTC(2026, 10, 2, 12);
const CENTS = { pins_200: 500, pins_1000: 2000 };
const PINS = { pins_200: 200, pins_1000: 1000 };

// ---------------------------------------------------------------- harness

class MockStripe {
  constructor() { this.sessions = new Map(); }
  seed(s) { this.sessions.set(s.id, s); }
  async handle(url, opts) {
    const u = new URL(String(url));
    const m = u.pathname.match(/^\/v1\/checkout\/sessions\/([^/]+)$/);
    const auth = (opts && opts.headers && opts.headers.authorization) || "";
    const s = m && auth === `Bearer ${process.env.WITNESS_STRIPE_SECRET_KEY}` ? this.sessions.get(decodeURIComponent(m[1])) : null;
    const status = s ? 200 : 404;
    const body = s || { error: { type: "invalid_request_error" } };
    return { status, ok: status === 200, json: async () => body, text: async () => JSON.stringify(body) };
  }
}

let gh, stripe, store, restoreFetch;

beforeEach(() => {
  gh = new MockGitHubStore();
  stripe = new MockStripe();
  store = accountdb.memoryStore();
  billing.deps.getStore = () => store;
  billing.deps.now = () => T0 + 60 * 1000;
  const original = global.fetch;
  global.fetch = (url, opts) => (String(url).startsWith("https://api.stripe.com/") ? stripe.handle(url, opts) : gh.handleFetch(url, opts));
  restoreFetch = () => { global.fetch = original; };
});

afterEach(() => restoreFetch());

let n = 0;
const sid = () => `cs_test_${String(++n).padStart(4, "0")}${"x".repeat(24)}`;

// What the server makes in lib/_account_checkout.js (mode payment, a pack):
// our customer, the signed ref in client_reference_id and metadata, the pack
// id in metadata, no payment_link.
function accountSession({ account, customer, pack = "pins_200", id = sid(), payment_status = "paid" }) {
  const ref = billing.mintAccountRef(account, T0);
  return {
    id, object: "checkout.session", livemode: false, created: Math.floor(T0 / 1000),
    mode: "payment", status: "complete", payment_status, payment_link: null,
    amount_total: CENTS[pack], currency: "usd", customer, client_reference_id: ref,
    payment_intent: `pi_${id.slice(8, 30)}`,
    metadata: { account_id: account, account_ref: ref, pack },
    customer_details: { email: "owner@example.com" },
    line_items: { data: [{ price: { id: `price_${pack}_test` } }] },
  };
}

// What a per-key Payment Link makes: Stripe's payment_link id, a customer of
// Stripe's own making (or none), the link's metadata.pack, and whatever
// client_reference_id the URL carried (null, a key's sha256, or anything).
function linkSession({ pack = "pins_200", cref = null, id = sid() }) {
  return {
    id, object: "checkout.session", livemode: false, created: Math.floor(T0 / 1000),
    mode: "payment", status: "complete", payment_status: "paid", payment_link: `plink_test_${pack}`,
    amount_total: CENTS[pack], currency: "usd", customer: null, client_reference_id: cref,
    payment_intent: `pi_${id.slice(8, 30)}`,
    metadata: { pack },
    customer_details: { email: "buyer@example.com" },
    line_items: { data: [{ price: { id: `price_${pack}_test` } }] },
  };
}

let evtN = 0;
function eventOf(session, type = "checkout.session.completed", id) {
  // A webhook event carries the session without expanded line_items.
  const { line_items, ...obj } = session;
  return { id: id || `evt_test${++evtN}cross`, type, created: Math.floor(T0 / 1000) + evtN, livemode: false, data: { object: obj } };
}

async function postWebhook(event) {
  const rawBody = Buffer.from(JSON.stringify(event), "utf8");
  const req = makeRawReq({ headers: { "stripe-signature": stripeSigHeader(SECRET, rawBody) }, rawBody });
  const res = makeRes();
  await webhook(req, res);
  return res;
}

async function getFulfill(id, { json = true, prefix } = {}) {
  const query = { session_id: id };
  if (prefix !== undefined) query.prefix = prefix;
  const req = makeReq({ method: "GET", headers: json ? { accept: "application/json" } : { accept: "text/html" }, query });
  const res = makeRes();
  await fulfill(req, res);
  return res;
}

async function postFulfillForm(id, prefix) {
  const req = makeReq({ method: "POST", headers: { accept: "text/html" }, body: { session_id: id, prefix }, query: {} });
  const res = makeRes();
  await fulfill(req, res);
  return res;
}

// Every key credit the key store holds, and every grant made for one session.
function usagePaths() { return [...gh._repoMap(USAGE).keys()]; }
function keyCreditsTotal() {
  let total = 0;
  for (const p of usagePaths()) if (p.startsWith("balance/")) total += Number(gh.read(USAGE, p).balance) || 0;
  return total;
}
function keyGrantsFor(id) { return usagePaths().filter((p) => p.startsWith("ledger/") && p.endsWith(`/grant-${id}.json`)).length; }
function fulfillmentsFor(id) { return usagePaths().filter((p) => p.includes(id) && !p.startsWith("ledger/")).length; }

async function accountWithCustomer(cus) {
  const a = await store._createAccount();
  const set = await store.setStripeCustomer({ account_id: a, customer_id: cus });
  assert.equal(set.ok, true);
  return a;
}
async function accountPacks(a) {
  const st = await store.pinStatus({ account_id: a, now: T0 + 120 * 1000 });
  return { pack_balance: Number(st.pack_balance), packs: (await store.listPacks(a)).length };
}

// ------------------------------------------------------------- the classifier

test("CLASSIFY: the server's account session is an account session; a one-time Payment Link session never is, whatever its client_reference_id", () => {
  const a = "11111111-1111-4111-8111-111111111111";
  assert.equal(billing.isAccountCheckoutSession(accountSession({ account: a, customer: "cus_own1" })), true);
  assert.equal(billing.isAccountCheckoutSession(linkSession({})), false);
  assert.equal(billing.isAccountCheckoutSession(linkSession({ cref: "a".repeat(64) })), false);
  const leaked = billing.mintAccountRef(a, T0);
  assert.equal(billing.isAccountCheckoutSession(linkSession({ cref: leaked })), false);
  assert.equal(billing.isAccountCheckoutSession({ ...linkSession({ cref: leaked }), payment_link: { id: "plink_test_obj" } }), false);
  assert.equal(billing.isAccountEvent(eventOf(linkSession({ cref: leaked }))), false);
  assert.equal(billing.factFromEvent(eventOf(linkSession({ cref: leaked }))).kind, "ignore");
  // Subscription mode keeps the account branch (the customer rule refuses there).
  assert.equal(billing.isAccountCheckoutSession({ ...linkSession({}), mode: "subscription" }), true);
});

// ------------------------- (a) an account session hitting /api/fulfill

for (const pack of ["pins_200", "pins_1000"]) {
  test(`(a) an account ${pack} session at /api/fulfill mints no key and credits nothing (JSON, ?prefix=, HTML picker, form POST)`, async () => {
    const a = await accountWithCustomer("cus_owna1");
    const s = accountSession({ account: a, customer: "cus_owna1", pack });
    stripe.seed(s);
    for (const res of [await getFulfill(s.id), await getFulfill(s.id, { prefix: "owner-" }),
      await getFulfill(s.id, { json: false }), await postFulfillForm(s.id, "owner-")]) {
      assert.equal(res._status, 409);
      if (res._body && typeof res._body === "object") {
        assert.equal(res._body.reason, "account_session");
        assert.equal(res._body.key, undefined);
      }
    }
    assert.equal(keyCreditsTotal(), 0);
    assert.equal(keyGrantsFor(s.id), 0);
    assert.equal(fulfillmentsFor(s.id), 0, "no fulfillment record, no key");
    assert.deepEqual(await accountPacks(a), { pack_balance: 0, packs: 0 }, "fulfill never credits an account either");
  });
}

test("(a) an account session at /api/fulfill is refused even before it is paid, and even when only metadata.account_id marks it", async () => {
  const a = await accountWithCustomer("cus_owna2");
  const unpaid = accountSession({ account: a, customer: "cus_owna2", payment_status: "unpaid" });
  stripe.seed(unpaid);
  assert.equal((await getFulfill(unpaid.id))._body.reason, "account_session");
  const onlyMeta = { ...accountSession({ account: a, customer: "cus_owna2" }), client_reference_id: null };
  delete onlyMeta.metadata.account_ref;
  stripe.seed(onlyMeta);
  assert.equal((await getFulfill(onlyMeta.id))._body.reason, "account_session");
  assert.equal(keyCreditsTotal(), 0);
});

// ------------------- (b) a Payment Link session at the account webhook path

test("(b) a Payment Link pins_200 session carrying a leaked signed account ref credits no account; the key gets it once via /api/fulfill", async () => {
  const a = await accountWithCustomer("cus_ownb1");
  const leaked = billing.mintAccountRef(a, T0);
  const s = { ...linkSession({ pack: "pins_200", cref: leaked }), metadata: { pack: "pins_200", account_ref: leaked } };
  stripe.seed(s);
  const w = await postWebhook(eventOf(s));
  assert.equal(w._status, 200);
  assert.equal(w._body.credited, undefined, "legacy path: no sha256 reference, nothing to credit there");
  const w2 = await postWebhook(eventOf(s, "checkout.session.async_payment_succeeded"));
  assert.equal(w2._status, 200);
  assert.deepEqual(await accountPacks(a), { pack_balance: 0, packs: 0 });
  assert.equal(store._stripeEvents().length, 0, "the account branch never saw it");
  const f = await getFulfill(s.id);
  assert.equal(f._status, 200);
  assert.equal(f._body.mode, "new_key");
  assert.equal(f._body.credit_balance, 200);
  assert.equal(keyCreditsTotal(), 200);
  assert.deepEqual(await accountPacks(a), { pack_balance: 0, packs: 0 });
});

test("(b) a plain Payment Link session (no reference) never reaches the account branch; fulfill mints once", async () => {
  const s = linkSession({ pack: "pins_1000" });
  stripe.seed(s);
  const w = await postWebhook(eventOf(s));
  assert.equal(w._status, 200);
  assert.match(String(w._body.skipped), /client_reference_id/);
  assert.equal(store._stripeEvents().length, 0);
  const f = await getFulfill(s.id);
  assert.equal(f._body.credit_balance, 1000);
  assert.equal(keyCreditsTotal(), 1000);
});

// --------------------- (c) the same session replayed through both paths

test("(c) an account session: webhook completed + async_succeeded + redelivery + fulfill twice = the account credited 200 once, no key", async () => {
  const a = await accountWithCustomer("cus_ownc1");
  const s = accountSession({ account: a, customer: "cus_ownc1", pack: "pins_200" });
  stripe.seed(s);
  const e1 = eventOf(s);
  assert.equal((await getFulfill(s.id))._status, 409); // fulfill first (someone holding the id)
  const r1 = await postWebhook(e1);
  assert.equal(r1._status, 200);
  assert.equal(r1._body.outcome, "pack_credited");
  assert.equal((await postWebhook(e1))._body.duplicate, true); // Stripe redelivery
  const r3 = await postWebhook(eventOf(s, "checkout.session.async_payment_succeeded"));
  assert.equal(r3._body.outcome, "already_credited");
  assert.equal((await getFulfill(s.id))._status, 409); // fulfill after
  assert.deepEqual(await accountPacks(a), { pack_balance: 200, packs: 1 });
  assert.equal(keyCreditsTotal(), 0);
  assert.equal(keyGrantsFor(s.id), 0);
});

test("(c) a Payment Link top-up (sha256 of a key): webhook twice (both types) + fulfill twice = that key credited 1,000 once, no account", async () => {
  const hash = balance.keyHash("wk_cross_path_existing_key");
  const a = await accountWithCustomer("cus_ownc2");
  const s = linkSession({ pack: "pins_1000", cref: hash });
  stripe.seed(s);
  const w1 = await postWebhook(eventOf(s));
  assert.equal(w1._body.credited, true);
  const f1 = await getFulfill(s.id);
  assert.equal(f1._body.mode, "topup");
  assert.equal(f1._body.already_credited, true);
  const w2 = await postWebhook(eventOf(s, "checkout.session.async_payment_succeeded"));
  assert.equal(w2._body.already_credited, true);
  await getFulfill(s.id);
  assert.equal((await balance.readBalance(hash)).balance, 1000);
  assert.equal(keyCreditsTotal(), 1000);
  assert.equal(keyGrantsFor(s.id), 1);
  assert.deepEqual(await accountPacks(a), { pack_balance: 0, packs: 0 });
});

test("(c) a Payment Link new-key purchase: fulfill (JSON, then HTML revisit) + both webhook types = one key, 200 once", async () => {
  const s = linkSession({ pack: "pins_200" });
  stripe.seed(s);
  const f1 = await getFulfill(s.id);
  await postWebhook(eventOf(s));
  await postWebhook(eventOf(s, "checkout.session.async_payment_succeeded"));
  const f2 = await getFulfill(s.id, { json: false });
  const f3 = await getFulfill(s.id);
  assert.equal(f2._status, 200);
  assert.equal(f3._body.key, f1._body.key);
  assert.equal(f3._body.already_fulfilled, true);
  assert.equal(keyCreditsTotal(), 200);
  assert.equal(keyGrantsFor(s.id), 1);
  assert.equal(store._stripeEvents().length, 0);
});

// ------------------------------------------- (d) idempotency across both

test("(d) concurrent: an account session's webhook deliveries and fulfill visits all at once still credit the account once and no key", async () => {
  const a = await accountWithCustomer("cus_ownd1");
  const s = accountSession({ account: a, customer: "cus_ownd1", pack: "pins_1000" });
  stripe.seed(s);
  const e1 = eventOf(s);
  const results = await Promise.all([
    postWebhook(e1), postWebhook(e1), postWebhook(eventOf(s, "checkout.session.async_payment_succeeded")),
    getFulfill(s.id), getFulfill(s.id, { prefix: "racer-" }), postFulfillForm(s.id, "racer-"),
  ]);
  for (const r of results.slice(3)) assert.equal(r._status, 409);
  assert.equal(results.slice(0, 3).filter((r) => r._body.outcome === "pack_credited").length, 1);
  assert.deepEqual(await accountPacks(a), { pack_balance: 1000, packs: 1 });
  assert.equal(keyCreditsTotal(), 0);
});

test("(d) concurrent: a Payment Link top-up's webhook deliveries and fulfill visits at once credit the key once", async () => {
  const hash = balance.keyHash("wk_cross_path_concurrent_key");
  const s = linkSession({ pack: "pins_200", cref: hash });
  stripe.seed(s);
  await Promise.all([
    postWebhook(eventOf(s)), postWebhook(eventOf(s, "checkout.session.async_payment_succeeded")),
    getFulfill(s.id), getFulfill(s.id),
  ]);
  assert.equal((await balance.readBalance(hash)).balance, 200);
  assert.equal(keyGrantsFor(s.id), 1);
  assert.equal(store._stripeEvents().length, 0);
});

test("(d) two account sessions for the same pack on the same account are two purchases: 400, each once, still no key", async () => {
  const a = await accountWithCustomer("cus_ownd3");
  const s1 = accountSession({ account: a, customer: "cus_ownd3" });
  const s2 = accountSession({ account: a, customer: "cus_ownd3" });
  for (const s of [s1, s2]) {
    stripe.seed(s);
    await postWebhook(eventOf(s));
    await postWebhook(eventOf(s));
    await getFulfill(s.id);
  }
  assert.deepEqual(await accountPacks(a), { pack_balance: 400, packs: 2 });
  assert.equal(keyCreditsTotal(), 0);
});

test("NUMBERS: free 10 a month per key and per no-plan account; packs 200/1,000 the same on both paths; account plans 3,000 a month", () => {
  assert.equal(require("../lib/_meter.js").PLAN_CAPS.free, 10);
  assert.equal(billing.FREE_MONTHLY_PINS, 10);
  assert.equal(billing.PAID_MONTHLY_PINS, 3000);
  for (const id of ["pins_200", "pins_1000"]) {
    assert.equal(balance.PACKS[id].pins, PINS[id]);
    assert.equal(billing.ACCOUNT_PACKS[id].pins, PINS[id]);
    assert.equal(balance.PACKS[id].price_usd * 100, CENTS[id]);
    assert.equal(billing.ACCOUNT_PACKS[id].price_usd * 100, CENTS[id]);
    assert.equal(balance.PACKS[id].by_id_only, true);
  }
});
