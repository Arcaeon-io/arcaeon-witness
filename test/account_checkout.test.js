// test/account_checkout.test.js — POST /api/account/checkout: the server
// makes the Stripe Checkout Session for an authenticated account, on the
// account's OWN Stripe customer (made once, stored, reused), with the signed
// reference set server-side. Whoever pays the session URL pays for this
// account and this customer; nobody's own customer is ever linked by paying.
// The Stripe API is the double in test/helpers/stripe_api_mock.js: no network.
"use strict";

process.env.WITNESS_STRIPE_WEBHOOK_SECRET = process.env.WITNESS_STRIPE_WEBHOOK_SECRET || "whsec_test_secret_123";
delete process.env.WITNESS_STRIPE_LIVEMODE;

const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const billing = require("../lib/_account_billing.js");
const accountdb = require("../lib/_accountdb.js");
const accountApi = require("../lib/_account_api.js");
const webhook = require("../api/stripe-webhook.js");
const { makeReq, makeRawReq, makeRes } = require("./helpers/http_mocks.js");
const { stripeSigHeader } = require("./helpers/stripe_sign.js");
const ev = require("./helpers/account_events.js");
const { MockStripeApi } = require("./helpers/stripe_api_mock.js");
const { T0 } = require("./helpers/account_billing_scenarios.js");

const SK = "sk_test_mock_only_not_a_real_key"; // test-only literal
const PRICES = { account_monthly: "price_mock_monthly", account_yearly: "price_mock_yearly", pins_200: "price_mock_p200", pins_1000: "price_mock_p1000" };
const HOUR = 60 * 60 * 1000;
const WH = process.env.WITNESS_STRIPE_WEBHOOK_SECRET;

function setup({ prices = PRICES, env = {} } = {}) {
  const store = accountdb.memoryStore();
  const clock = { t: T0 };
  const stripe = new MockStripeApi({ secret: SK, prices, now: () => clock.t });
  const api = accountApi.createAccountApi({
    getStore: () => store,
    now: () => clock.t,
    env: { WITNESS_STRIPE_SECRET_KEY: SK, WITNESS_BASE_URL: "https://witness.test", ACCOUNT_REF_SECRET: process.env.ACCOUNT_REF_SECRET,
      ACCOUNT_CHECKOUT_ENABLED: "true", ...env },
    fetchImpl: stripe.handle,
  });
  return { store, clock, stripe, api };
}

async function newKey(store) {
  const account_id = await store._createAccount();
  const { api_key } = await store.issueApiKey({ account_id });
  return { account_id, api_key };
}

let ipN = 0;
async function checkout(api, { key, body, method = "POST" }) {
  const res = makeRes();
  ipN += 1; // a fresh address per call: the per-IP limiter is not what is under test here
  const headers = { "x-forwarded-for": `203.0.${Math.floor(ipN / 250)}.${(ipN % 250) + 1}` };
  if (key) headers.authorization = `Bearer ${key}`;
  await api.checkout(makeReq({ method, headers, body }), res);
  return res;
}

let restoreDeps = null;
afterEach(() => { if (restoreDeps) { restoreDeps(); restoreDeps = null; } });
function useStore(store, now) {
  const prev = { ...billing.deps };
  billing.deps.getStore = () => store;
  billing.deps.now = now;
  restoreDeps = () => Object.assign(billing.deps, prev);
}
async function deliver(event) {
  const raw = Buffer.from(JSON.stringify(event), "utf8");
  const res = makeRes();
  await webhook(makeRawReq({ headers: { "stripe-signature": stripeSigHeader(WH, raw) }, rawBody: raw }), res);
  return res;
}

// ------------------------------------------------------------- the route

test("CHECKOUT REFUSED: no bearer is 401 and Stripe is never called; an unknown key is 401; GET is 405", async () => {
  const { api, stripe, store } = setup();
  const none = await checkout(api, { body: { plan: "monthly" } });
  assert.equal(none._status, 401);
  assert.equal(none._body.reason, "missing_api_key");
  const bad = await checkout(api, { key: "ak_" + "x".repeat(43), body: { plan: "monthly" } });
  assert.equal(bad._status, 401);
  assert.equal(bad._body.reason, "unknown_api_key");
  const { api_key } = await newKey(store);
  const get = await checkout(api, { key: api_key, body: null, method: "GET" });
  assert.equal(get._status, 405);
  assert.equal(stripe.calls.length, 0, "nothing reached Stripe");
});

test("CHECKOUT: a monthly plan makes the account's customer once, then a subscription session on THAT customer with the signed ref set server-side", async () => {
  const { api, stripe, store, clock } = setup();
  const { account_id, api_key } = await newKey(store);
  const res = await checkout(api, { key: api_key, body: { plan: "monthly" } });
  assert.equal(res._status, 201, JSON.stringify(res._body));
  assert.equal(res._body.ok, true);
  assert.match(res._body.session_id, /^cs_test_/);
  assert.match(res._body.url, /^https:\/\/checkout\.stripe\.com\//);
  assert.equal(res._body.plan, "monthly");
  assert.equal(res._body.mode, "subscription");
  assert.equal(res._headers["cache-control"], "no-store");
  // One customer, carrying our account id, made under an idempotency key.
  assert.equal(stripe.countOf("POST", "/v1/customers"), 1);
  const cusCall = stripe.calls.find((c) => c.path === "/v1/customers");
  assert.equal(cusCall.form.get("metadata[account_id]"), account_id);
  assert.ok(cusCall.idempotencyKey && cusCall.idempotencyKey.includes(account_id), "idempotency key bound to the account");
  const cus = store._account(account_id).stripe_customer_id;
  assert.match(cus, /^cus_/);
  assert.equal(res._body.customer_id, cus);
  // The session: our customer, our price, our signed reference, 2-hour expiry.
  const sess = stripe.calls.find((c) => c.path === "/v1/checkout/sessions");
  assert.equal(sess.form.get("customer"), cus);
  assert.equal(sess.form.get("mode"), "subscription");
  assert.equal(sess.form.get("line_items[0][price]"), PRICES.account_monthly);
  assert.equal(sess.form.get("line_items[0][quantity]"), "1");
  const ref = sess.form.get("client_reference_id");
  assert.equal(billing.verifyAccountRef(ref, Math.floor(clock.t / 1000)), account_id);
  assert.equal(sess.form.get("metadata[account_ref]"), ref);
  assert.equal(sess.form.get("metadata[account_id]"), account_id);
  assert.equal(sess.form.get("subscription_data[metadata][account_ref]"), ref, "renewal events can name the account");
  assert.equal(Number(sess.form.get("expires_at")), Math.floor(clock.t / 1000) + billing.REF_TTL_S, "the session dies with the ref");
  assert.match(sess.form.get("success_url"), /^https:\/\/witness\.test\//);
  assert.match(sess.form.get("cancel_url"), /^https:\/\/witness\.test\//);
  assert.equal(res._body.expires_at, new Date(clock.t + 2 * HOUR).toISOString());
  // The price was found by lookup key, never typed in.
  const price = stripe.calls.find((c) => c.path === "/v1/prices");
  assert.deepEqual(price.search.getAll("lookup_keys[]"), ["account_monthly"]);
  assert.equal(price.search.get("active"), "true");
});

test("CHECKOUT IDEMPOTENT: a second checkout (a pack) reuses the stored customer: one POST /v1/customers in total; two concurrent first calls still make one", async () => {
  const { api, stripe, store } = setup();
  const { account_id, api_key } = await newKey(store);
  const r1 = await checkout(api, { key: api_key, body: { plan: "yearly" } });
  const r2 = await checkout(api, { key: api_key, body: { pack: "pins_200" } });
  assert.equal(r1._status, 201);
  assert.equal(r2._status, 201);
  assert.equal(r2._body.pack, "pins_200");
  assert.equal(r2._body.mode, "payment");
  assert.equal(r1._body.customer_id, r2._body.customer_id);
  assert.equal(stripe.countOf("POST", "/v1/customers"), 1, "the customer is made once and stored");
  assert.equal(stripe.countOf("POST", "/v1/checkout/sessions"), 2);
  const packSess = stripe.calls.filter((c) => c.path === "/v1/checkout/sessions")[1];
  assert.equal(packSess.form.get("mode"), "payment");
  assert.equal(packSess.form.get("metadata[pack]"), "pins_200");
  assert.equal(packSess.form.get("line_items[0][price]"), PRICES.pins_200);
  assert.equal(packSess.form.get("customer"), store._account(account_id).stripe_customer_id);

  // Two first calls at once on a fresh account: the Stripe idempotency key
  // and the store's set-if-null leave exactly one customer on the account.
  const fresh = await newKey(store);
  const [a, b] = await Promise.all([
    checkout(api, { key: fresh.api_key, body: { plan: "monthly" } }),
    checkout(api, { key: fresh.api_key, body: { pack: "pins_1000" } }),
  ]);
  assert.equal(a._status, 201);
  assert.equal(b._status, 201);
  assert.equal(a._body.customer_id, b._body.customer_id);
  assert.equal(stripe.customers.size, 2, "two accounts, two customers, however many calls");
  assert.equal(store._account(fresh.account_id).stripe_customer_id, a._body.customer_id);
});

test("CHECKOUT REFUSED: bad bodies are 400; both plan and pack is 400; nothing is made at Stripe", async () => {
  const { api, stripe, store } = setup();
  const { api_key } = await newKey(store);
  for (const body of [null, "x", {}, { plan: "weekly" }, { pack: "mini" }, { plan: "monthly", pack: "pins_200" }, { plan: 7 }]) {
    const r = await checkout(api, { key: api_key, body });
    assert.equal(r._status, 400, JSON.stringify(body));
    assert.match(r._body.reason, /^bad_/);
  }
  assert.equal(stripe.calls.length, 0);
});

// What a caller may never read in a refusal (round 2, item 6): our env var
// names, Stripe lookup keys, or other operator detail.
const OPERATOR_DETAIL = /WITNESS_|ACCOUNT_REF_SECRET|ACCOUNT_CHECKOUT_ENABLED|SUPABASE|STRIPE_SECRET|lookup|account_monthly|account_yearly|price_mock|\/v1\//i;

async function capturingErrors(fn) {
  const lines = [];
  const prev = console.error;
  console.error = (...a) => { lines.push(a.join(" ")); };
  try {
    return { out: await fn(), lines };
  } finally {
    console.error = prev;
  }
}

test("CHECKOUT FAILS CLOSED: no WITNESS_STRIPE_SECRET_KEY is 503 (no bare STRIPE_SECRET_KEY fallback); no ACCOUNT_REF_SECRET is 503; a missing price is 503", async () => {
  const noKey = setup({ env: { WITNESS_STRIPE_SECRET_KEY: "", STRIPE_SECRET_KEY: "sk_other_product" } });
  let k = await newKey(noKey.store);
  let r = await checkout(noKey.api, { key: k.api_key, body: { plan: "monthly" } });
  assert.equal(r._status, 503);
  assert.equal(r._body.reason, "stripe_not_configured");
  assert.equal(noKey.stripe.calls.length, 0);

  const noRef = setup({ env: { ACCOUNT_REF_SECRET: "" } });
  k = await newKey(noRef.store);
  r = await checkout(noRef.api, { key: k.api_key, body: { plan: "monthly" } });
  assert.equal(r._status, 503);
  assert.equal(r._body.reason, "account_ref_not_configured");
  assert.equal(noRef.stripe.calls.length, 0);

  const noPrice = setup({ prices: { account_monthly: PRICES.account_monthly } });
  k = await newKey(noPrice.store);
  r = await checkout(noPrice.api, { key: k.api_key, body: { plan: "yearly" } });
  assert.equal(r._status, 503);
  assert.equal(r._body.reason, "price_not_configured");
  assert.equal(noPrice.stripe.countOf("POST", "/v1/checkout/sessions"), 0);
});

test("CHECKOUT: a Stripe failure is 502 stripe_error and the secret key is never in the answer; the customer made before the failure is kept for the retry", async () => {
  const { api, stripe, store } = setup();
  const { account_id, api_key } = await newKey(store);
  stripe.fail = (path) => (path === "/v1/checkout/sessions" ? { status: 500, body: { error: { message: `boom ${SK}` } } } : null);
  const r = await checkout(api, { key: api_key, body: { plan: "monthly" } });
  assert.equal(r._status, 502);
  assert.equal(r._body.reason, "stripe_error");
  assert.ok(!JSON.stringify(r._body).includes(SK));
  const cus = store._account(account_id).stripe_customer_id;
  assert.match(cus, /^cus_/, "the customer is stored even though the session failed");
  stripe.fail = null;
  const ok = await checkout(api, { key: api_key, body: { plan: "monthly" } });
  assert.equal(ok._status, 201);
  assert.equal(ok._body.customer_id, cus);
  assert.equal(stripe.countOf("POST", "/v1/customers"), 1);
});

test("CHECKOUT REFUSED: an account whose customer already holds a plan (active, trialing, past_due) gets 409 for a plan, but can still buy a pack", async () => {
  const { api, stripe, store, clock } = setup();
  useStore(store, () => clock.t);
  const { account_id, api_key } = await newKey(store);
  const first = await checkout(api, { key: api_key, body: { plan: "monthly" } });
  const session = stripe.sessions.get(first._body.session_id);
  const sub = ev.nextId("sub_");
  await deliver(stripe.paidEvent(session, { sub, at: clock.t + 1000 }));
  const pe = billing.addMonthsUTC(clock.t, 1);
  await deliver(ev.invoiceEvent({ sub, cus: session.customer, ps: clock.t, pe, created: clock.t + 2000 }));
  assert.equal((await store.pinStatus({ account_id, now: clock.t + 3000 })).plan, "monthly");
  const again = await checkout(api, { key: api_key, body: { plan: "yearly" } });
  assert.equal(again._status, 409);
  assert.equal(again._body.reason, "plan_already_held");
  const pack = await checkout(api, { key: api_key, body: { pack: "pins_1000" } });
  assert.equal(pack._status, 201);
});

test("WIRING: ?op=account-checkout dispatches and vercel.json rewrites /api/account/checkout onto api/balance.js", async () => {
  const { api, store } = setup();
  const { api_key } = await newKey(store);
  const res = makeRes();
  const req = makeReq({ method: "POST", headers: { authorization: `Bearer ${api_key}`, "x-forwarded-for": "203.0.113.9" }, body: { plan: "monthly" }, query: { op: "account-checkout" } });
  assert.equal(await accountApi.dispatch(req, res, api), true);
  assert.equal(res._status, 201);
  const cfg = require("../vercel.json");
  const map = Object.fromEntries(cfg.rewrites.map((r) => [r.source, r.destination]));
  assert.equal(map["/api/account/checkout"], "/api/balance?op=account-checkout");
});

// ---------------------------------------------- round 2 (review fixes)

test("RELEASE GATE (round 2, item 5): checkout is refused 503 checkout_disabled unless ACCOUNT_CHECKOUT_ENABLED is exactly true; nothing reaches Stripe; open, it works", async () => {
  for (const v of [undefined, "", "false", "1", "TRUE ", "yes"]) {
    const env = { ACCOUNT_CHECKOUT_ENABLED: v };
    const closed = setup({ env });
    const k = await newKey(closed.store);
    const r = await checkout(closed.api, { key: k.api_key, body: { plan: "monthly" } });
    assert.equal(r._status, 503, `ACCOUNT_CHECKOUT_ENABLED=${JSON.stringify(v)}`);
    assert.equal(r._body.reason, "checkout_disabled");
    assert.equal(closed.stripe.calls.length, 0);
    const p = await checkout(closed.api, { key: k.api_key, body: { pack: "pins_200" } });
    assert.equal(p._status, 503);
  }
  const open = setup({ env: { ACCOUNT_CHECKOUT_ENABLED: "true" } });
  const k = await newKey(open.store);
  assert.equal((await checkout(open.api, { key: k.api_key, body: { plan: "monthly" } }))._status, 201);
});

test("ERROR BODIES (round 2, item 6): every checkout refusal is a reason code and a plain sentence with no env var or lookup-key name; the operator detail goes to console.error", async () => {
  const cases = [
    { name: "gate", s: setup({ env: { ACCOUNT_CHECKOUT_ENABLED: "" } }), body: { plan: "monthly" }, reason: "checkout_disabled", log: /ACCOUNT_CHECKOUT_ENABLED/ },
    { name: "no secret key", s: setup({ env: { WITNESS_STRIPE_SECRET_KEY: "" } }), body: { plan: "monthly" }, reason: "stripe_not_configured", log: /WITNESS_STRIPE_SECRET_KEY/ },
    { name: "no ref secret", s: setup({ env: { ACCOUNT_REF_SECRET: "" } }), body: { plan: "monthly" }, reason: "account_ref_not_configured", log: /ACCOUNT_REF_SECRET/ },
    { name: "no price", s: setup({ prices: { account_monthly: PRICES.account_monthly } }), body: { plan: "yearly" }, reason: "price_not_configured", log: /account_yearly/ },
    { name: "stripe down", s: setup(), body: { plan: "monthly" }, reason: "stripe_error", log: /\/v1\/checkout\/sessions/, fail: true },
  ];
  for (const c of cases) {
    const k = await newKey(c.s.store);
    if (c.fail) c.s.stripe.fail = (path) => (path === "/v1/checkout/sessions" ? { status: 500, body: {} } : null);
    const { out: r, lines } = await capturingErrors(() => checkout(c.s.api, { key: k.api_key, body: c.body }));
    assert.equal(r._body.reason, c.reason, c.name);
    assert.equal(typeof r._body.error, "string", c.name);
    assert.ok(r._body.error.length > 10, c.name);
    assert.ok(!OPERATOR_DETAIL.test(JSON.stringify(r._body)), `${c.name}: ${JSON.stringify(r._body)}`);
    assert.ok(lines.some((l) => c.log.test(l)), `${c.name}: operator line logged: ${lines.join(" | ")}`);
  }
  // No account store: the same rule.
  const api = accountApi.createAccountApi({ getStore: () => null, env: { ACCOUNT_CHECKOUT_ENABLED: "true" } });
  const { out: r, lines } = await capturingErrors(() => checkout(api, { key: "ak_" + "y".repeat(43), body: { plan: "monthly" } }));
  assert.equal(r._body.reason, "account_store_not_configured");
  assert.ok(!OPERATOR_DETAIL.test(JSON.stringify(r._body)), JSON.stringify(r._body));
  assert.ok(lines.some((l) => /SUPABASE_URL/.test(l)), lines.join(" | "));
});

test("DOUBLE SUBMIT (round 2, item 7): two plan checkouts for one account inside the same few minutes carry one Idempotency-Key and one body, so Stripe answers ONE session; another plan, or a later bucket, is a new session", async () => {
  const { api, stripe, store, clock } = setup();
  const { account_id, api_key } = await newKey(store);
  const [a, b] = await Promise.all([
    checkout(api, { key: api_key, body: { plan: "monthly" } }),
    checkout(api, { key: api_key, body: { plan: "monthly" } }),
  ]);
  assert.equal(a._status, 201, JSON.stringify(a._body));
  assert.equal(b._status, 201, JSON.stringify(b._body));
  clock.t += 60 * 1000; // a third click a minute later
  const c = await checkout(api, { key: api_key, body: { plan: "monthly" } });
  assert.equal(c._status, 201, JSON.stringify(c._body));
  assert.equal(a._body.session_id, b._body.session_id);
  assert.equal(c._body.session_id, a._body.session_id);
  assert.equal(stripe.sessions.size, 1, "one open plan session at Stripe");
  const posts = stripe.calls.filter((x) => x.method === "POST" && x.path === "/v1/checkout/sessions");
  assert.equal(posts.length, 3);
  const keys = new Set(posts.map((x) => x.idempotencyKey));
  assert.equal(keys.size, 1);
  const [key] = keys;
  assert.ok(key && key.includes(account_id) && key.includes("monthly"), key);
  // Another plan is another purchase.
  const y = await checkout(api, { key: api_key, body: { plan: "yearly" } });
  assert.notEqual(y._body.session_id, a._body.session_id);
  // A later bucket is a new session.
  clock.t += 30 * 60 * 1000;
  const later = await checkout(api, { key: api_key, body: { plan: "monthly" } });
  assert.equal(later._status, 201, JSON.stringify(later._body));
  assert.notEqual(later._body.session_id, a._body.session_id);
});

// ------------------------------------------- the lockout gap, end to end

test("LEAKED LINK (the lockout gap): a stranger pays the owner's fresh session inside the 2 hours and the plan goes active: the account stays on the OWNER's customer; the owner is never refused", async () => {
  const { api, stripe, store, clock } = setup();
  useStore(store, () => clock.t);
  const { account_id, api_key } = await newKey(store);
  const made = await checkout(api, { key: api_key, body: { plan: "monthly" } });
  assert.equal(made._status, 201);
  const ownersCus = store._account(account_id).stripe_customer_id;
  const session = stripe.sessions.get(made._body.session_id);
  assert.equal(session.customer, ownersCus, "the session Stripe holds is on the owner's customer");

  // The URL leaks. A stranger opens it an hour later and pays with their own
  // card. Stripe completes THE SESSION: its customer is still ours; the
  // stranger's card is just a payment method on it. No "stranger customer"
  // exists anywhere in what Stripe sends.
  clock.t = T0 + HOUR;
  const sub = ev.nextId("sub_");
  const completed = stripe.paidEvent(session, { sub, at: clock.t });
  assert.equal(completed.data.object.customer, ownersCus);
  const r1 = await deliver(completed);
  assert.equal(r1._status, 200);
  assert.equal(r1._body.outcome, "linked");
  const pe = billing.addMonthsUTC(T0 + HOUR, 1);
  const r2 = await deliver(ev.subEvent({ type: "customer.subscription.created", sub, cus: ownersCus, ps: T0 + HOUR, pe, created: clock.t + 1000 }));
  assert.equal(r2._body.outcome, "subscription_applied");
  const r3 = await deliver(ev.invoiceEvent({ sub, cus: ownersCus, ps: T0 + HOUR, pe, created: clock.t + 2000 }));
  assert.equal(r3._body.outcome, "subscription_applied");

  // The plan is active, on the owner's account and the owner's customer.
  const acct = store._account(account_id);
  assert.equal(acct.stripe_customer_id, ownersCus, "the stranger's payment did not move the link");
  assert.equal(acct.stripe_subscription_id, sub);
  const st = await store.pinStatus({ account_id, now: clock.t + 3000 });
  assert.equal(st.plan, "monthly");
  assert.equal(st.status, "active");
  assert.equal(st.monthly_allowance, 3000);
  // The owner is not locked out of anything: their next checkout (a pack) is
  // on the same customer, and no customer mismatch can arise.
  const pack = await checkout(api, { key: api_key, body: { pack: "pins_200" } });
  assert.equal(pack._status, 201);
  assert.equal(pack._body.customer_id, ownersCus);
  assert.equal(stripe.countOf("POST", "/v1/customers"), 1);
  assert.ok(store._stripeEvents().every((e) => e.outcome !== "ignored_customer_mismatch" && e.outcome !== "relinked"));
});

test("LEAKED REF ON A PAYMENT LINK: a valid ref pasted into a Payment Link URL and paid by a stranger's own customer links nothing, even with no plan held; the stranger's subscription is nobody's", async () => {
  const { api, stripe, store, clock } = setup();
  useStore(store, () => clock.t);
  const { account_id, api_key } = await newKey(store);
  const made = await checkout(api, { key: api_key, body: { plan: "monthly" } });
  const ownersCus = store._account(account_id).stripe_customer_id;
  const ref = stripe.sessions.get(made._body.session_id).client_reference_id;
  // A Payment Link checkout: Stripe makes a NEW customer for the payer, and
  // client_reference_id comes from the URL. The ref is still inside its 2 hours.
  const strangerCus = "cus_stranger1";
  const strangerSub = "sub_stranger1";
  const r = await deliver(ev.checkoutSubEvent({ account: account_id, cus: strangerCus, sub: strangerSub, created: T0 + 30 * 60 * 1000, ref }));
  assert.equal(r._status, 200);
  assert.equal(r._body.outcome, "ignored_customer_mismatch");
  assert.equal(store._account(account_id).stripe_customer_id, ownersCus, "the owner's customer stays; no relink exists");
  // The stranger's subscription events find no account (503: Stripe retries, then gives up).
  const pe = billing.addMonthsUTC(T0, 1);
  const s1 = await deliver(ev.subEvent({ type: "customer.subscription.created", sub: strangerSub, cus: strangerCus, ps: T0, pe, created: T0 + 31 * 60 * 1000, account: account_id }));
  assert.equal(s1._body.outcome, "ignored_customer_mismatch", "even with the owner's ref in its metadata");
  const s2 = await deliver(ev.invoiceEvent({ sub: strangerSub, cus: strangerCus, ps: T0, pe, created: T0 + 32 * 60 * 1000 }));
  assert.equal(s2._status, 503);
  assert.equal((await store.pinStatus({ account_id, now: T0 + HOUR })).plan, "free");
  // The owner's own session, paid by the owner, works as before.
  const sub = ev.nextId("sub_");
  await deliver(stripe.paidEvent(stripe.sessions.get(made._body.session_id), { sub, at: T0 + 40 * 60 * 1000 }));
  await deliver(ev.invoiceEvent({ sub, cus: ownersCus, ps: T0, pe, created: T0 + 41 * 60 * 1000 }));
  assert.equal((await store.pinStatus({ account_id, now: T0 + HOUR })).plan, "monthly");
});

test("NO CUSTOMER, NO LINK: a verified checkout for an account that has no stored customer is refused; the webhook never writes stripe_customer_id", async () => {
  const store = accountdb.memoryStore();
  useStore(store, () => T0);
  const a = await store._createAccount();
  const r = await deliver(ev.checkoutSubEvent({ account: a, cus: "cus_first1", sub: "sub_first1", created: T0 }));
  assert.equal(r._status, 200);
  assert.equal(r._body.outcome, "ignored_customer_mismatch");
  assert.equal(store._account(a).stripe_customer_id, null);
  const inv = await deliver(ev.invoiceEvent({ sub: "sub_first1", cus: "cus_first1", ps: T0, pe: billing.addMonthsUTC(T0, 1), created: T0 + 1000, account: a }));
  assert.equal(inv._body.outcome, "ignored_customer_mismatch");
  assert.equal(store._account(a).stripe_customer_id, null);
});

test("STORE: setStripeCustomer sets once (set-if-null), answers the stored one after, and refuses a customer another account holds", async () => {
  const s = accountdb.memoryStore();
  const a = await s._createAccount();
  const b = await s._createAccount();
  assert.deepEqual(await s.setStripeCustomer({ account_id: a, customer_id: "cus_a1" }), { ok: true, customer_id: "cus_a1", set: true });
  assert.deepEqual(await s.setStripeCustomer({ account_id: a, customer_id: "cus_a2" }), { ok: true, customer_id: "cus_a1", set: false });
  assert.deepEqual(await s.setStripeCustomer({ account_id: b, customer_id: "cus_a1" }), { ok: false, reason: "customer_taken" });
  assert.deepEqual(await s.setStripeCustomer({ account_id: "00000000-0000-4000-8000-00000000dead", customer_id: "cus_x" }), { ok: false, reason: "unknown_account" });
  const acct = await s.getAccount(a);
  assert.equal(acct.stripe_customer_id, "cus_a1");
  assert.equal(acct.plan, "free");
  assert.equal(await s.getAccount("00000000-0000-4000-8000-00000000dead"), null);
});

test("POSTGREST: getAccount is one GET of the billing columns; setStripeCustomer is one RPC; the key stays in headers", async () => {
  const calls = [];
  const KEY = "service-role-placeholder-not-real";
  const fetchImpl = async (url, opts) => {
    calls.push({ url: String(url), opts });
    if (String(url).includes("/rpc/account_set_stripe_customer")) {
      return new Response(JSON.stringify([{ outcome: "already_set", customer_id: "cus_z1" }]), { status: 200 });
    }
    return new Response(JSON.stringify([{ id: "00000000-0000-4000-8000-000000000001", stripe_customer_id: "cus_z1", stripe_subscription_id: null, plan: "free", status: "active" }]), { status: 200 });
  };
  const s = accountdb.postgrestStore({ url: "https://example.invalid", key: KEY, fetchImpl });
  const acct = await s.getAccount("00000000-0000-4000-8000-000000000001");
  assert.equal(acct.stripe_customer_id, "cus_z1");
  assert.match(calls[0].url, /\/accounts\?id=eq\.00000000-0000-4000-8000-000000000001&select=/);
  const r = await s.setStripeCustomer({ account_id: "00000000-0000-4000-8000-000000000001", customer_id: "cus_z9" });
  assert.deepEqual(r, { ok: true, customer_id: "cus_z1", set: false });
  assert.deepEqual(JSON.parse(calls[1].opts.body), { p_account_id: "00000000-0000-4000-8000-000000000001", p_customer: "cus_z9" });
  for (const c of calls) assert.ok(!c.url.includes(KEY));
});
