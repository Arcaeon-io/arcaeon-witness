// test/account_billing.test.js — the account, phase 2: the Stripe
// subscription lifecycle and the pin allowance (lib/_account_billing.js),
// run on the in-memory store, plus the webhook branch in
// api/stripe-webhook.js and GET /api/account/pins.
"use strict";

process.env.WITNESS_STRIPE_WEBHOOK_SECRET = process.env.WITNESS_STRIPE_WEBHOOK_SECRET || "whsec_test_secret_123";
delete process.env.WITNESS_STRIPE_LIVEMODE;

const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const billing = require("../lib/_account_billing.js");
const accountdb = require("../lib/_accountdb.js");
const accountApi = require("../lib/_account_api.js");
const webhook = require("../api/stripe-webhook.js");
const { makeReq, makeRawReq, makeRes } = require("./helpers/http_mocks.js");
const { stripeSigHeader } = require("./helpers/stripe_sign.js");
const ev = require("./helpers/account_events.js");
const { scenarios, T0 } = require("./helpers/account_billing_scenarios.js");

const SECRET = process.env.WITNESS_STRIPE_WEBHOOK_SECRET;
const { addMonthsUTC, monthsSince } = billing;

// ------------------------------------------------- the plan's cases (memory)
scenarios(test, async () => accountdb.memoryStore());

// --------------------------------------------------------------- the clock

test("CLOCK: add months in UTC clamps to the month's last day (Jan 31 -> Feb 28, leap Feb 29, back to Mar 31)", () => {
  const jan31 = Date.UTC(2027, 0, 31, 9);
  assert.equal(new Date(addMonthsUTC(jan31, 1)).toISOString(), "2027-02-28T09:00:00.000Z");
  assert.equal(new Date(addMonthsUTC(jan31, 2)).toISOString(), "2027-03-31T09:00:00.000Z");
  assert.equal(new Date(addMonthsUTC(Date.UTC(2028, 0, 31), 1)).toISOString(), "2028-02-29T00:00:00.000Z");
  assert.equal(new Date(addMonthsUTC(Date.UTC(2026, 10, 30), 3)).toISOString(), "2027-02-28T00:00:00.000Z");
  assert.equal(monthsSince(jan31, Date.UTC(2027, 1, 28, 8, 59)), 0);
  assert.equal(monthsSince(jan31, Date.UTC(2027, 1, 28, 9)), 1);
  assert.equal(monthsSince(jan31, Date.UTC(2027, 11, 31, 9)), 11);
});

test("RULES: the owner's numbers: 3,000 a month paid, 30 free; pins_200 = 200 for $5, pins_1000 = 1,000 for $20; lookup keys", () => {
  assert.equal(billing.PAID_MONTHLY_PINS, 3000);
  assert.equal(billing.FREE_MONTHLY_PINS, 30);
  assert.deepEqual({ ...billing.ACCOUNT_PACKS.pins_200 }, { price_usd: 5, pins: 200 });
  assert.deepEqual({ ...billing.ACCOUNT_PACKS.pins_1000 }, { price_usd: 20, pins: 1000 });
  assert.deepEqual({ ...billing.PLAN_BY_LOOKUP }, { account_monthly: "monthly", account_yearly: "yearly" });
  // Mirrored by id: where lib/_balance.js carries these ids (another branch),
  // the numbers must agree.
  const legacy = require("../lib/_balance.js").PACKS;
  for (const id of ["pins_200", "pins_1000"]) {
    if (legacy[id]) {
      assert.equal(legacy[id].pins, billing.ACCOUNT_PACKS[id].pins, id);
      assert.equal(legacy[id].price_usd, billing.ACCOUNT_PACKS[id].price_usd, id);
    }
  }
});

test("FACTS: a price that is not an account price, or a legacy checkout, is not an account event", () => {
  const sub = ev.subEvent({ sub: "sub_x1", cus: "cus_x1", lookup: "something_else", ps: T0, pe: T0 + ev.DAY, created: T0 });
  assert.equal(billing.factFromEvent(sub).kind, "ignore");
  const legacy = { id: "evt_l", type: "checkout.session.completed", data: { object: { mode: "payment", metadata: { pack: "mini" }, client_reference_id: "a".repeat(64) } } };
  assert.equal(billing.isAccountEvent(legacy), false);
  assert.equal(billing.isAccountEvent({ type: "invoice.paid" }), true);
  assert.equal(billing.isAccountEvent({ type: "payment_intent.succeeded" }), false);
});

test("FACTS: cancel_at inside the period moves the effective end earlier and counts as a scheduled cancel (F6)", () => {
  const pe = addMonthsUTC(T0, 1);
  const e = ev.subEvent({ sub: "sub_f6", cus: "cus_f6", ps: T0, pe, cancelAt: T0 + 10 * ev.DAY, created: T0 });
  const f = billing.factFromEvent(e);
  assert.equal(f.period_end, new Date(Math.floor((T0 + 10 * ev.DAY) / 1000) * 1000).toISOString());
  assert.equal(f.cancel_at_period_end, true);
});

// ------------------------------------------------ memory-only ledger checks

test("I3 LEDGER: a full refund of a pack with 200 left removes the 200 and records the 800 spent as a shortfall (counts only)", async () => {
  const s = accountdb.memoryStore();
  const a = await s._createAccount();
  const pi = ev.nextId("pi_");
  const fact = (e) => billing.factFromEvent(e);
  const ck = ev.checkoutPackEvent({ account: a, session: ev.nextId("cs_test_"), pi, created: T0 });
  await s.applyStripeEvent({ event_id: ck.id, type: ck.type, fact: fact(ck), now: T0 });
  await s.debitPins({ account_id: a, request_id: "spend", n: 830, now: T0 });
  const rf = ev.refundEvent({ pi, amount: 2000, refunded: 2000, created: T0 + 1000 });
  await s.applyStripeEvent({ event_id: rf.id, type: rf.type, fact: fact(rf), now: T0 + 1000 });
  const row = s._ledger(a).find((r) => r.entry === "pack_refund");
  assert.equal(row.pack_delta, -200);
  assert.equal(row.shortfall, 800);
  const debit = s._ledger(a).find((r) => r.entry === "debit");
  assert.equal(debit.monthly_delta, -30);
  assert.equal(debit.pack_delta, -800);
  // Counts only: no ledger row or event row carries anything but numbers and ids.
  for (const r of [...s._ledger(a), ...s._stripeEvents()]) {
    for (const k of Object.keys(r)) assert.ok(!["content", "text", "body", "note", "message", "payload", "data"].includes(k), k);
  }
});

test("RESET LEDGER: one monthly_reset row per window, however many times it is rolled", async () => {
  const s = accountdb.memoryStore();
  const a = await s._createAccount();
  for (let i = 0; i < 5; i++) await s.pinStatus({ account_id: a, now: T0 + i * 1000 });
  await s.debitPins({ account_id: a, request_id: "x", n: 1, now: T0 + 9000 });
  assert.equal(s._ledger(a).filter((r) => r.entry === "monthly_reset").length, 1);
});

// --------------------------------------------------------- the webhook

let restoreDeps = null;
afterEach(() => {
  if (restoreDeps) { restoreDeps(); restoreDeps = null; }
});
function useStore(store, now = () => T0) {
  const prev = { ...billing.deps };
  billing.deps.getStore = () => store;
  billing.deps.now = now;
  restoreDeps = () => Object.assign(billing.deps, prev);
}

async function post(event, { header, rawBody } = {}) {
  const raw = rawBody || Buffer.from(JSON.stringify(event), "utf8");
  const headers = { "stripe-signature": header === undefined ? stripeSigHeader(SECRET, raw) : header };
  if (header === null) delete headers["stripe-signature"];
  const req = makeRawReq({ headers, rawBody: raw });
  const res = makeRes();
  await webhook(req, res);
  return res;
}

test("WEBHOOK: a signed account event goes to the account branch; the repeat answers 200 duplicate", async () => {
  const s = accountdb.memoryStore();
  useStore(s);
  const a = await s._createAccount();
  const e = ev.checkoutPackEvent({ account: a, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0 });
  const r1 = await post(e);
  assert.equal(r1._status, 200);
  assert.equal(r1._body.outcome, "pack_credited");
  const r2 = await post(e);
  assert.equal(r2._status, 200);
  assert.equal(r2._body.duplicate, true);
  assert.equal((await s.pinStatus({ account_id: a, now: T0 })).pack_balance, 1000);
});

test("J8/J10/J9/J11: wrong secret, no header, a timestamp 301 s old, or a re-serialized body -> 400 and no change", async () => {
  const s = accountdb.memoryStore();
  useStore(s);
  const a = await s._createAccount();
  const e = ev.checkoutPackEvent({ account: a, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0 });
  const raw = Buffer.from(JSON.stringify(e), "utf8");
  assert.equal((await post(e, { header: stripeSigHeader("whsec_wrong", raw) }))._status, 400);
  assert.equal((await post(e, { header: null }))._status, 400);
  const old = Math.floor(Date.now() / 1000) - 301;
  assert.equal((await post(e, { header: stripeSigHeader(SECRET, raw, old) }))._status, 400);
  const pretty = Buffer.from(JSON.stringify(e, null, 2), "utf8");
  assert.equal((await post(e, { header: stripeSigHeader(SECRET, pretty), rawBody: raw }))._status, 400);
  assert.equal((await s.pinStatus({ account_id: a, now: T0 })).pack_balance, 0);
});

test("J12: during a secret roll the header carries two v1 signatures; the one made with our secret is enough", async () => {
  const s = accountdb.memoryStore();
  useStore(s);
  const a = await s._createAccount();
  const e = ev.checkoutPackEvent({ account: a, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0 });
  const raw = Buffer.from(JSON.stringify(e), "utf8");
  const t = Math.floor(Date.now() / 1000);
  const good = stripeSigHeader(SECRET, raw, t).split(",")[1];
  const other = stripeSigHeader("whsec_old_one", raw, t).split(",")[1];
  const r = await post(e, { header: `t=${t},${good},${other}` });
  assert.equal(r._status, 200);
  assert.equal(r._body.outcome, "pack_credited");
  const v = webhook.verifyStripeSignature(raw, `t=${t},${other},${good}`, SECRET);
  assert.equal(v.ok, true, "order of the two signatures does not matter");
});

test("WEBHOOK: an account event for an account not linked yet answers 503 so Stripe retries; a non-pack refund answers 200", async () => {
  const s = accountdb.memoryStore();
  useStore(s);
  const e = ev.invoiceEvent({ sub: "sub_nolink1", cus: "cus_nolink1", ps: T0, pe: addMonthsUTC(T0, 1), created: T0 });
  const r = await post(e);
  assert.equal(r._status, 503);
  assert.equal(r._body.reason, "account_not_linked_yet");
  const rf = await post(ev.refundEvent({ pi: ev.nextId("pi_"), amount: 900, refunded: 900, created: T0 }));
  assert.equal(rf._status, 200);
});

test("WEBHOOK: no account store configured -> 503 for subscription events (retry), 200 skip for refunds; legacy checkouts untouched", async () => {
  useStore(null);
  const sub = ev.subEvent({ sub: "sub_nostore", cus: "cus_nostore", ps: T0, pe: addMonthsUTC(T0, 1), created: T0 });
  const r = await post(sub);
  assert.equal(r._status, 503);
  assert.equal(r._body.reason, "account_store_not_configured");
  const rf = await post(ev.refundEvent({ pi: ev.nextId("pi_"), amount: 900, refunded: 900, created: T0 }));
  assert.equal(rf._status, 200);
  // A legacy pack checkout (no account id) still takes the old path: with
  // no GitHub store configured here it is skipped there, never routed here.
  const legacy = { id: "evt_legacy1", type: "checkout.session.completed", livemode: true,
    data: { object: { id: "cs_legacy", payment_status: "paid", client_reference_id: "zz", metadata: { pack: "mini" }, amount_total: 500, currency: "usd" } } };
  const lr = await post(legacy);
  assert.equal(lr._status, 200);
  assert.match(lr._body.skipped, /client_reference_id/);
});

test("WEBHOOK: a test-mode account event is skipped by the livemode gate", async () => {
  const s = accountdb.memoryStore();
  useStore(s);
  const a = await s._createAccount();
  const e = ev.checkoutPackEvent({ account: a, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0 });
  e.livemode = false;
  const r = await post(e);
  assert.equal(r._status, 200);
  assert.match(r._body.skipped, /livemode/);
  assert.equal((await s.pinStatus({ account_id: a, now: T0 })).pack_balance, 0);
});

// ------------------------------------------------------ GET /api/account/pins

test("ROUTE: GET /api/account/pins (balance.js ?op=account-pins) shows the allowance for the bearer's account", async () => {
  const s = accountdb.memoryStore();
  const a = await s._createAccount();
  const { api_key } = await s.issueApiKey({ account_id: a });
  const api = accountApi.createAccountApi({ getStore: () => s, now: () => T0 });
  const res = makeRes();
  const req = makeReq({ method: "GET", headers: { authorization: `Bearer ${api_key}` }, query: { op: "account-pins" } });
  assert.equal(await accountApi.dispatch(req, res, api), true);
  assert.equal(res._status, 200);
  assert.equal(res._body.plan, "free");
  assert.equal(res._body.monthly_allowance, 30);
  assert.equal(res._body.monthly_left, 30);
  assert.equal(res._body.pack_balance, 0);
  const none = makeRes();
  await accountApi.dispatch(makeReq({ method: "GET", query: { op: "account-pins" } }), none, api);
  assert.equal(none._status, 401);
  const cfg = require("../vercel.json");
  const map = Object.fromEntries(cfg.rewrites.map((r) => [r.source, r.destination]));
  assert.equal(map["/api/account/pins"], "/api/balance?op=account-pins");
});

test("POSTGREST: the billing calls are one RPC each, the key stays in headers, and failures name only the step", async () => {
  const calls = [];
  const KEY = "service-role-" + crypto.randomBytes(8).toString("hex");
  const fetchImpl = async (url, opts) => {
    calls.push({ url, opts });
    if (url.endsWith("/rpc/account_debit_pins")) {
      return new Response(JSON.stringify([{ ok: true, reason: null, replay: false, from_monthly: 1, from_packs: 0,
        monthly_used: 1, monthly_allowance: 3000, pack_balance: "0", window_end: "2026-12-03T12:00:00+00:00" }]), { status: 200 });
    }
    if (url.endsWith("/rpc/account_apply_stripe_event")) return new Response(JSON.stringify({ code: "XX000" }), { status: 500 });
    return new Response("[]", { status: 200 });
  };
  const s = accountdb.postgrestStore({ url: "https://example.invalid", key: KEY, fetchImpl });
  const r = await s.debitPins({ account_id: "00000000-0000-4000-8000-000000000001", request_id: "q1", n: 1, now: T0 });
  assert.equal(r.ok, true);
  assert.equal(r.pack_balance, 0);
  const body = JSON.parse(calls[0].opts.body);
  assert.deepEqual(Object.keys(body).sort(), ["p_account_id", "p_n", "p_now", "p_request_id"]);
  await assert.rejects(
    s.applyStripeEvent({ event_id: "evt_1", type: "invoice.paid", fact: { kind: "ignore" }, now: T0 }),
    (err) => err.storeError && !err.message.includes(KEY) && /applyStripeEvent/.test(err.message));
  for (const c of calls) assert.ok(!c.url.includes(KEY));
});
