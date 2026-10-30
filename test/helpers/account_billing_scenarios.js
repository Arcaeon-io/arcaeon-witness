// test/helpers/account_billing_scenarios.js — the account billing cases from
// the outside test plan (case ids in the names), written against the store
// INTERFACE only, so the same cases run against any store:
//   test/account_billing.test.js runs them on the in-memory store.
// A store needs: _createAccount(), setStripeCustomer, applyStripeEvent,
// debitPins, pinStatus, listPacks. Not a test file itself (no top-level
// test() calls).
//
// The customer. In the real flow the checkout endpoint makes the account's
// Stripe customer and stores it BEFORE any Checkout Session exists
// (lib/_account_checkout.js); every event then carries that customer.
// `linkedAccount` below does the store half of that. An event whose customer
// is not the stored one is ignored_customer_mismatch, always.

"use strict";

const assert = require("node:assert/strict");
const billing = require("../../lib/_account_billing.js");
const ev = require("./account_events.js");

const { addMonthsUTC } = billing;
const { DAY } = ev;
const T0 = Date.UTC(2026, 10, 3, 12, 0, 0); // Tue 2026-11-03 12:00 UTC
const HOUR = 60 * 60 * 1000;

function idsFor(tag) {
  const k = ev.nextId("").slice(-10);
  return { cus: `cus_${tag}${k}`, sub: `sub_${tag}${k}`, sub2: `sub_${tag}2${k}` };
}

function scenarios(test, makeStore) {
  // Through the webhook's own entry (billing.applyAccountEvent), so the
  // unverified-reference rule is exercised on every store.
  const apply = (s, event, now) =>
    billing.applyAccountEvent(s, { event_id: event.id, type: event.type, fact: billing.factFromEvent(event), now });
  const isoOf = (ms) => new Date(ms).toISOString();

  async function debitN(s, account_id, count, now, tag = "r") {
    let ok = 0;
    for (let i = 0; i < count; i++) {
      const r = await s.debitPins({ account_id, request_id: `${tag}-${i}-${ev.nextId("")}`, n: 1, now });
      if (r.ok) ok++;
    }
    return ok;
  }

  // An account whose Stripe customer the checkout endpoint has made and
  // stored (the step before any session exists).
  async function linkedAccount(s, tag = "ac") {
    const account = await s._createAccount();
    const ids = idsFor(tag);
    const r = await s.setStripeCustomer({ account_id: account, customer_id: ids.cus });
    assert.equal(r.ok, true);
    assert.equal(r.set, true);
    return { account, ...ids };
  }

  // An account on the monthly plan from `ps`, the way a real checkout does
  // it: the customer stored, then checkout.session.completed on that
  // customer, subscription.created, invoice.paid.
  async function subscribe(s, { ps = T0, lookup = "account_monthly", months = 1, tag = "m" } = {}) {
    const { account, cus, sub, sub2 } = await linkedAccount(s, tag);
    const pe = addMonthsUTC(ps, lookup === "account_yearly" ? 12 : months);
    await apply(s, ev.checkoutSubEvent({ account, cus, sub, created: ps }), ps);
    await apply(s, ev.subEvent({ type: "customer.subscription.created", sub, cus, lookup, ps, pe, created: ps }), ps);
    await apply(s, ev.invoiceEvent({ sub, cus, lookup, ps, pe, created: ps + 1000 }), ps + 1000);
    return { account, cus, sub, sub2, ps, pe, lookup };
  }

  // The account's stored customer, making one first if it has none (what the
  // checkout endpoint does before any session exists).
  async function customerOf(s, account) {
    const a = await s.getAccount(account);
    if (a && a.stripe_customer_id) return a.stripe_customer_id;
    const cus = idsFor("pk").cus;
    const r = await s.setStripeCustomer({ account_id: account, customer_id: cus });
    assert.equal(r.ok, true);
    return r.customer_id;
  }

  async function buyPack(s, account, { pack = "pins_1000", at = T0, pi } = {}) {
    const session = ev.nextId("cs_test_");
    const payment_intent = pi || ev.nextId("pi_");
    const cus = await customerOf(s, account);
    const r = await apply(s, ev.checkoutPackEvent({ account, session, pack, pi: payment_intent, created: at, cus }), at);
    return { session, pi: payment_intent, outcome: r.outcome };
  }

  // ------------------------------------------------------------ free tier

  test("FREE: no plan gets 10 a month on the UTC calendar month; the 11th pin is refused; next month resets", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    assert.equal(await debitN(s, a, 11, T0), 10);
    const st = await s.pinStatus({ account_id: a, now: T0 });
    assert.equal(st.plan, "free");
    assert.equal(st.monthly_allowance, 10);
    assert.equal(st.monthly_left, 0);
    assert.equal(st.window_end, "2026-12-01T00:00:00.000Z");
    const r = await s.debitPins({ account_id: a, request_id: "next-month", n: 1, now: Date.UTC(2026, 11, 1) });
    assert.equal(r.ok, true);
    assert.equal(r.monthly_used, 1);
  });

  // -------------------------------------------------------- subscribe (A1)

  test("A1: checkout + subscription.created + invoice.paid -> monthly plan, 0/3000, period from Stripe", async () => {
    const s = await makeStore();
    const { account, pe } = await subscribe(s);
    const st = await s.pinStatus({ account_id: account, now: T0 + HOUR });
    assert.equal(st.plan, "monthly");
    assert.equal(st.status, "active");
    assert.equal(st.monthly_used, 0);
    assert.equal(st.monthly_allowance, 3000);
    assert.equal(st.period_end, new Date(pe).toISOString());
    assert.equal(st.window_end, new Date(pe).toISOString());
  });

  test("A2 (incomplete): subscription.created incomplete gives no plan in force, only the free 10", async () => {
    const s = await makeStore();
    const { account, cus, sub } = await linkedAccount(s, "inc");
    await apply(s, ev.checkoutSubEvent({ account, cus, sub, created: T0 }), T0);
    await apply(s, ev.subEvent({ type: "customer.subscription.created", sub, cus, status: "incomplete", ps: T0,
      pe: addMonthsUTC(T0, 1), created: T0 }), T0);
    const st = await s.pinStatus({ account_id: account, now: T0 });
    assert.equal(st.status, "incomplete");
    assert.equal(st.monthly_allowance, 10);
  });

  // ------------------------------------------------------ duplicates (J1-J3)

  test("J1: the same event id delivered twice is applied once (the second answers duplicate, no second reset)", async () => {
    const s = await makeStore();
    const { account, cus, sub, pe } = await subscribe(s);
    const renewal = ev.invoiceEvent({ sub, cus, ps: pe, pe: addMonthsUTC(pe, 1), created: pe + 1000 });
    const r1 = await apply(s, renewal, pe + 1000);
    assert.equal(r1.outcome, "subscription_applied");
    assert.equal(await debitN(s, account, 5, pe + 2000), 5);
    const r2 = await apply(s, renewal, pe + 3000);
    assert.equal(r2.outcome, "duplicate");
    const st = await s.pinStatus({ account_id: account, now: pe + 4000 });
    assert.equal(st.monthly_used, 5, "a repeat of the renewal must not reset the month again");
  });

  test("J2/H2: two different event ids for one Checkout Session credit the pack once", async () => {
    const s = await makeStore();
    const account = await s._createAccount();
    const session = ev.nextId("cs_test_");
    const pi = ev.nextId("pi_");
    const cus = await customerOf(s, account);
    const e1 = ev.checkoutPackEvent({ account, session, pi, created: T0, cus });
    const e2 = ev.checkoutPackEvent({ account, session, pi, type: "checkout.session.async_payment_succeeded", created: T0 + 1000, cus });
    assert.equal((await apply(s, e1, T0)).outcome, "pack_credited");
    assert.equal((await apply(s, e2, T0)).outcome, "already_credited");
    const packs = await s.listPacks(account);
    assert.equal(packs.length, 1);
    assert.equal((await s.pinStatus({ account_id: account, now: T0 })).pack_balance, 1000);
  });

  test("J3: the same event delivered to two workers at once has one effect", async () => {
    const s = await makeStore();
    const account = await s._createAccount();
    const e = ev.checkoutPackEvent({ account, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0, cus: await customerOf(s, account) });
    const rs = await Promise.all([apply(s, e, T0), apply(s, e, T0)]);
    assert.deepEqual(rs.map((r) => r.outcome).sort(), ["duplicate", "pack_credited"]);
    assert.equal((await s.listPacks(account)).length, 1);
  });

  // --------------------------------------------------------- order (J4-J5)

  test("J4: invoice.paid for a customer no account holds is unresolved (not recorded), then lands on Stripe's retry once the customer is stored", async () => {
    const s = await makeStore();
    const account = await s._createAccount();
    const { cus, sub } = idsFor("j4");
    const pe = addMonthsUTC(T0, 1);
    const paid = ev.invoiceEvent({ sub, cus, ps: T0, pe, created: T0 + 1000 });
    assert.equal((await apply(s, paid, T0 + 1000)).outcome, "unresolved");
    await s.setStripeCustomer({ account_id: account, customer_id: cus });
    const retry = await apply(s, paid, T0 + 60000);
    assert.equal(retry.outcome, "subscription_applied", "the retry is applied, not answered duplicate");
    const st = await s.pinStatus({ account_id: account, now: T0 + 60000 });
    assert.equal(st.plan, "monthly");
    assert.equal(st.monthly_allowance, 3000);
  });

  test("J4b: an invoice that carries subscription metadata.account_ref resolves without the checkout event, when its customer is the account's own", async () => {
    const s = await makeStore();
    const { account, cus, sub } = await linkedAccount(s, "j4b");
    const r = await apply(s, ev.invoiceEvent({ sub, cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0, account }), T0);
    assert.equal(r.outcome, "subscription_applied");
    assert.equal((await s.pinStatus({ account_id: account, now: T0 })).plan, "monthly");
    // The same invoice shape for an account with no customer, or from another
    // customer, names the account and is still refused: the ref alone never links.
    const bare = await s._createAccount();
    const other = idsFor("j4c");
    assert.equal((await apply(s, ev.invoiceEvent({ sub: other.sub, cus: other.cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0, account: bare }), T0)).outcome,
      "ignored_customer_mismatch");
    assert.equal((await apply(s, ev.invoiceEvent({ sub: other.sub, cus: other.cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0 + 1, account }), T0)).outcome,
      "ignored_customer_mismatch");
    assert.equal((await s.pinStatus({ account_id: bare, now: T0 })).plan, "free");
  });

  test("J5: an old subscription.updated (active) arriving after .deleted changes nothing (canceled is terminal)", async () => {
    const s = await makeStore();
    const { account, cus, sub, ps, pe } = await subscribe(s);
    const del = ev.subEvent({ type: "customer.subscription.deleted", sub, cus, status: "canceled", ps, pe, created: T0 + 5 * DAY });
    assert.equal((await apply(s, del, T0 + 5 * DAY)).outcome, "subscription_applied");
    const stale = ev.subEvent({ sub, cus, status: "active", ps, pe, created: T0 + 2 * DAY });
    assert.equal((await apply(s, stale, T0 + 5 * DAY + 1000)).outcome, "ignored_terminal");
    const st = await s.pinStatus({ account_id: account, now: T0 + 6 * DAY });
    assert.equal(st.status, "canceled");
    assert.equal(st.plan, "free");
  });

  test("ORDER: an older past_due update arriving after a newer invoice.paid is ignored as stale", async () => {
    const s = await makeStore();
    const { account, cus, sub, ps, pe } = await subscribe(s);
    const paid = ev.invoiceEvent({ sub, cus, ps, pe, created: T0 + 3 * DAY });
    await apply(s, paid, T0 + 3 * DAY);
    const old = ev.subEvent({ sub, cus, status: "past_due", ps, pe, created: T0 + 2 * DAY });
    assert.equal((await apply(s, old, T0 + 3 * DAY + 1000)).outcome, "ignored_stale");
    assert.equal((await s.pinStatus({ account_id: account, now: T0 + 3 * DAY })).status, "active");
  });

  test("ORDER: a period never moves backward (an old invoice for the previous period does not undo the renewal)", async () => {
    const s = await makeStore();
    const { account, cus, sub, ps, pe } = await subscribe(s);
    const pe2 = addMonthsUTC(pe, 1);
    await apply(s, ev.invoiceEvent({ sub, cus, ps: pe, pe: pe2, created: pe + 1000 }), pe + 1000);
    await debitN(s, account, 7, pe + 2000);
    await apply(s, ev.invoiceEvent({ sub, cus, ps, pe, created: pe + 5000 }), pe + 5000);
    const st = await s.pinStatus({ account_id: account, now: pe + 6000 });
    assert.equal(st.period_end, new Date(pe2).toISOString());
    assert.equal(st.monthly_used, 7);
  });

  // ------------------------------------------------------- renewal (B1-B5)

  test("B1-B3: each monthly renewal resets to 0/3000 and unused pins do not carry over", async () => {
    const s = await makeStore();
    const { account, cus, sub, pe } = await subscribe(s);
    await debitN(s, account, 320, T0 + DAY);
    let ps = pe;
    for (let i = 0; i < 2; i++) {
      const next = addMonthsUTC(ps, 1);
      await apply(s, ev.invoiceEvent({ sub, cus, ps, pe: next, created: ps + 1000 }), ps + 1000);
      const st = await s.pinStatus({ account_id: account, now: ps + 2000 });
      assert.equal(st.monthly_used, 0);
      assert.equal(st.monthly_allowance, 3000, "no carry over: still 3000, never 3000 + unused");
      ps = next;
    }
  });

  test("B4/B5: our clock passes period_end with no webhook -> the month resets anyway; the late renewal does not reset again", async () => {
    const s = await makeStore();
    const { account, cus, sub, pe } = await subscribe(s);
    await debitN(s, account, 100, T0 + DAY);
    const late = pe + 2 * HOUR;
    const st = await s.pinStatus({ account_id: account, now: pe + 1 });
    assert.equal(st.monthly_used, 0, "provisional reset at the boundary");
    await debitN(s, account, 9, pe + HOUR);
    await apply(s, ev.invoiceEvent({ sub, cus, ps: pe, pe: addMonthsUTC(pe, 1), created: late }), late);
    const after = await s.pinStatus({ account_id: account, now: late + 1000 });
    assert.equal(after.monthly_used, 9, "the late invoice.paid confirms the same window; no second reset");
  });

  test("B7/H11: a reset never touches packs, and packs never expire (still whole 400 days later)", async () => {
    const s = await makeStore();
    const { account, cus, sub, pe } = await subscribe(s);
    await buyPack(s, account, { pack: "pins_200", at: T0 + DAY });
    await apply(s, ev.invoiceEvent({ sub, cus, ps: pe, pe: addMonthsUTC(pe, 1), created: pe + 1000 }), pe + 1000);
    assert.equal((await s.pinStatus({ account_id: account, now: pe + 2000 })).pack_balance, 200);
    const later = await s.pinStatus({ account_id: account, now: T0 + 400 * DAY });
    assert.equal(later.pack_balance, 200);
  });

  // ------------------------------------------------- yearly and plan change

  test("YEARLY: 3,000 each month on our own anniversary clock (Jan 31 anchor clamps to Feb 28), no pool, 12 resets", async () => {
    const s = await makeStore();
    const ps = Date.UTC(2027, 0, 31, 9, 0, 0);
    const { account } = await subscribe(s, { ps, lookup: "account_yearly", tag: "y" });
    const expectEnds = [];
    for (let k = 1; k <= 12; k++) expectEnds.push(new Date(addMonthsUTC(ps, k)).toISOString());
    assert.equal(expectEnds[0], "2027-02-28T09:00:00.000Z");
    assert.equal(expectEnds[1], "2027-03-31T09:00:00.000Z");
    for (let k = 0; k < 12; k++) {
      const inside = addMonthsUTC(ps, k) + DAY;
      const st = await s.pinStatus({ account_id: account, now: inside });
      assert.equal(st.plan, "yearly");
      assert.equal(st.monthly_used, 0, `month ${k} starts at 0`);
      assert.equal(st.monthly_allowance, 3000, `month ${k}: 3000, never pooled`);
      assert.equal(st.window_end, expectEnds[k], `month ${k} window end`);
      if (k === 0) assert.equal(await debitN(s, account, 3001, inside, "y0"), 3000, "the 3,001st pin of a month is refused");
      else await debitN(s, account, 10, inside, `y${k}`);
    }
  });

  test("YEARLY: the renewal invoice for year two after our provisional reset does not reset a second time", async () => {
    const s = await makeStore();
    const { account, cus, sub, pe } = await subscribe(s, { lookup: "account_yearly", tag: "y2" });
    await debitN(s, account, 4, pe + HOUR);
    const late = pe + 3 * HOUR;
    await apply(s, ev.invoiceEvent({ sub, cus, lookup: "account_yearly", ps: pe, pe: addMonthsUTC(pe, 12), created: late }), late);
    const st = await s.pinStatus({ account_id: account, now: late + 1000 });
    assert.equal(st.monthly_used, 4);
    assert.equal(st.window_end, new Date(addMonthsUTC(pe, 1)).toISOString());
  });

  test("MONTHLY -> YEARLY: the switch starts a fresh month (0/3000) on the new anchor; year end set; then monthly resets inside the year", async () => {
    const s = await makeStore();
    const { account, cus, sub } = await subscribe(s);
    await debitN(s, account, 1000, T0 + DAY);
    const sw = T0 + 10 * DAY;
    const ype = addMonthsUTC(sw, 12);
    await apply(s, ev.subEvent({ sub, cus, lookup: "account_yearly", ps: sw, pe: ype, created: sw }), sw);
    await apply(s, ev.invoiceEvent({ sub, cus, lookup: "account_yearly", ps: sw, pe: ype, created: sw + 1000 }), sw + 1000);
    let st = await s.pinStatus({ account_id: account, now: sw + 2000 });
    assert.equal(st.plan, "yearly");
    assert.equal(st.monthly_used, 0);
    assert.equal(st.monthly_allowance, 3000);
    assert.equal(st.period_end, new Date(ype).toISOString());
    assert.equal(st.window_end, new Date(addMonthsUTC(sw, 1)).toISOString());
    await debitN(s, account, 50, sw + DAY);
    st = await s.pinStatus({ account_id: account, now: addMonthsUTC(sw, 1) });
    assert.equal(st.monthly_used, 0, "first anniversary inside the year resets");
  });

  // -------------------------------------------- failed payment (E1-E7)

  test("E1-E3: renewal payment fails -> past_due gets no new month (the free 10); a second failure changes nothing; recovery starts the paid month once", async () => {
    const s = await makeStore();
    const { account, cus, sub, pe } = await subscribe(s);
    await debitN(s, account, 2999, T0 + DAY);
    const pe2 = addMonthsUTC(pe, 1);
    const f1 = ev.invoiceEvent({ type: "invoice.payment_failed", sub, cus, ps: pe, pe: pe2, created: pe + 1000 });
    assert.equal((await apply(s, f1, pe + 1000)).outcome, "subscription_applied");
    let st = await s.pinStatus({ account_id: account, now: pe + 2000 });
    assert.equal(st.status, "past_due");
    assert.equal(st.monthly_used, 0);
    assert.equal(st.monthly_allowance, 10, "past_due: no new monthly reset, the paid window ended, so the no-plan 10");
    assert.equal(await debitN(s, account, 40, pe + 3000), 10);
    const f2 = ev.invoiceEvent({ type: "invoice.payment_failed", sub, cus, ps: pe, pe: pe2, created: pe + 3 * DAY });
    await apply(s, f2, pe + 3 * DAY);
    st = await s.pinStatus({ account_id: account, now: pe + 3 * DAY });
    assert.equal(st.status, "past_due");
    assert.equal(st.monthly_used, 10);
    const ok = ev.invoiceEvent({ sub, cus, ps: pe, pe: pe2, created: pe + 4 * DAY });
    await apply(s, ok, pe + 4 * DAY);
    st = await s.pinStatus({ account_id: account, now: pe + 4 * DAY });
    assert.equal(st.status, "active");
    assert.equal(st.monthly_used, 0, "recovery: the paid month from period_start");
    assert.equal(st.monthly_allowance, 3000);
    assert.equal(st.window_end, new Date(pe2).toISOString());
    assert.equal(await debitN(s, account, 7, pe + 4 * DAY + 1), 7);
    await apply(s, ev.invoiceEvent({ sub, cus, ps: pe, pe: pe2, created: pe + 5 * DAY }), pe + 5 * DAY);
    st = await s.pinStatus({ account_id: account, now: pe + 5 * DAY });
    assert.equal(st.monthly_used, 7, "a second invoice.paid for the same period does not reset again");
  });

  // ------------------------------------- no plan in force and past_due (v2 rule)

  test("NO PLAN 10: never paid, and every lapsed status (canceled, unpaid, incomplete, incomplete_expired, paused) get 10 on the UTC month", async () => {
    const s = await makeStore();
    const fresh = await s._createAccount();
    assert.equal(await debitN(s, fresh, 11, T0, "np"), 10);
    let st = await s.pinStatus({ account_id: fresh, now: T0 });
    assert.equal(st.monthly_allowance, 10);
    assert.equal(st.window_start, "2026-11-01T00:00:00.000Z");
    for (const status of ["unpaid", "incomplete", "incomplete_expired", "paused", "canceled"]) {
      const { account, cus, sub, ps, pe } = await subscribe(s, { tag: "lp" });
      const type = status === "canceled" ? "customer.subscription.deleted" : "customer.subscription.updated";
      await apply(s, ev.subEvent({ type, sub, cus, status, ps, pe, created: T0 + 2 * DAY }), T0 + 2 * DAY);
      st = await s.pinStatus({ account_id: account, now: T0 + 2 * DAY });
      assert.equal(st.status, status);
      assert.equal(st.monthly_allowance, 10, status);
      st = await s.pinStatus({ account_id: account, now: Date.UTC(2026, 11, 2) });
      assert.equal(st.monthly_allowance, 10, `${status}: next calendar month`);
      assert.equal(st.monthly_used, 0, `${status}: next calendar month resets`);
      assert.equal(await debitN(s, account, 11, Date.UTC(2026, 11, 2), "lp"), 10, status);
    }
  });

  test("PAST_DUE KEEPS ITS WINDOW: the current window's 3000 and its use stay while past_due; at the window's end it drops to 10, no new month", async () => {
    const s = await makeStore();
    const { account, cus, sub, pe } = await subscribe(s, { tag: "pk" });
    await debitN(s, account, 100, T0 + DAY, "pk");
    // A billing change mid-window whose invoice fails: Stripe moves the period
    // to the change and marks the subscription past_due.
    const sw = T0 + 10 * DAY;
    await apply(s, ev.subEvent({ sub, cus, status: "past_due", ps: sw, pe: addMonthsUTC(sw, 1), created: sw }), sw);
    let st = await s.pinStatus({ account_id: account, now: sw + HOUR });
    assert.equal(st.status, "past_due");
    assert.equal(st.monthly_allowance, 3000, "keeps the window it is in");
    assert.equal(st.monthly_used, 100, "and what it used");
    assert.equal(st.window_end, new Date(pe).toISOString());
    assert.equal(await debitN(s, account, 5, sw + 2 * HOUR, "pk2"), 5);
    st = await s.pinStatus({ account_id: account, now: addMonthsUTC(sw, 1) + DAY });
    assert.equal(st.monthly_allowance, 10, "the window ended while past_due: the no-plan 10");
    assert.equal(st.monthly_used, 0);
    assert.equal(st.window_start, "2026-12-01T00:00:00.000Z");
    assert.equal(st.window_end, "2027-01-01T00:00:00.000Z");
    st = await s.pinStatus({ account_id: account, now: Date.UTC(2027, 0, 5) });
    assert.equal(st.monthly_allowance, 10, "still past_due a month later: still 10, never a new 3000");
  });

  test("PAST_DUE -> ACTIVE: recovery resumes 3000 on the anniversary clock from period_start", async () => {
    const s = await makeStore();
    const { account, cus, sub, pe } = await subscribe(s, { tag: "pa" });
    const pe2 = addMonthsUTC(pe, 1);
    await apply(s, ev.invoiceEvent({ type: "invoice.payment_failed", sub, cus, ps: pe, pe: pe2, created: pe + HOUR }), pe + HOUR);
    let st = await s.pinStatus({ account_id: account, now: pe + 2 * HOUR });
    assert.equal(st.monthly_allowance, 10);
    const back = pe + 6 * DAY;
    await apply(s, ev.subEvent({ sub, cus, status: "active", ps: pe, pe: pe2, created: back }), back);
    st = await s.pinStatus({ account_id: account, now: back + 1000 });
    assert.equal(st.status, "active");
    assert.equal(st.monthly_allowance, 3000);
    assert.equal(st.monthly_used, 0);
    assert.equal(st.window_start, new Date(pe).toISOString(), "the anniversary window from period_start, not the recovery day");
    assert.equal(st.window_end, new Date(pe2).toISOString());
  });

  test("PAST_DUE after our provisional reset: the window granted on our clock for the unpaid period is not kept", async () => {
    const s = await makeStore();
    const { account, cus, sub, pe } = await subscribe(s, { tag: "pr" });
    // A pin lands after period_end, before Stripe's renewal outcome: the clock rolls provisionally.
    await debitN(s, account, 4, pe + 10 * 60 * 1000, "pr");
    assert.equal((await s.pinStatus({ account_id: account, now: pe + 20 * 60 * 1000 })).monthly_allowance, 3000);
    const pe2 = addMonthsUTC(pe, 1);
    await apply(s, ev.invoiceEvent({ type: "invoice.payment_failed", sub, cus, ps: pe, pe: pe2, created: pe + HOUR }), pe + HOUR);
    const st = await s.pinStatus({ account_id: account, now: pe + 2 * HOUR });
    assert.equal(st.status, "past_due");
    assert.equal(st.monthly_allowance, 10, "the renewal failed: no 3000 for the unpaid period");
    assert.equal(st.monthly_left, 6);
    assert.equal(await debitN(s, account, 7, pe + 3 * HOUR, "pr2"), 6);
  });

  test("YEARLY RENEWAL FAILS: past_due gets no new year of resets (10 a calendar month), recovery resumes on the anniversary", async () => {
    const s = await makeStore();
    const ps = Date.UTC(2026, 10, 15, 8);
    const { account, cus, sub, pe } = await subscribe(s, { ps, lookup: "account_yearly", tag: "yf" });
    assert.equal((await s.pinStatus({ account_id: account, now: addMonthsUTC(ps, 11) + DAY })).monthly_allowance, 3000);
    const pe2 = addMonthsUTC(pe, 12);
    await debitN(s, account, 2, pe + 30 * 60 * 1000, "yf"); // the provisional roll, too
    await apply(s, ev.invoiceEvent({ type: "invoice.payment_failed", sub, cus, lookup: "account_yearly", ps: pe, pe: pe2, created: pe + HOUR }), pe + HOUR);
    for (let k = 0; k < 4; k++) {
      const at = addMonthsUTC(pe, k) + 2 * DAY;
      const st = await s.pinStatus({ account_id: account, now: at });
      assert.equal(st.status, "past_due");
      assert.equal(st.monthly_allowance, 10, `month ${k} of the unpaid year: 10`);
    }
    const back = addMonthsUTC(pe, 3) + 5 * DAY;
    await apply(s, ev.invoiceEvent({ sub, cus, lookup: "account_yearly", ps: pe, pe: pe2, created: back }), back);
    const st = await s.pinStatus({ account_id: account, now: back + 1000 });
    assert.equal(st.status, "active");
    assert.equal(st.monthly_allowance, 3000);
    assert.equal(st.window_start, new Date(addMonthsUTC(pe, 3)).toISOString());
    assert.equal(st.window_end, new Date(addMonthsUTC(pe, 4)).toISOString());
  });

  test("E4/E7: unpaid falls back to the free 10 (packs still spend); deletion leaves the account free with its packs", async () => {
    const s = await makeStore();
    const { account, cus, sub, ps, pe } = await subscribe(s);
    await buyPack(s, account, { pack: "pins_200", at: T0 + HOUR });
    await apply(s, ev.subEvent({ sub, cus, status: "unpaid", ps, pe, created: T0 + 20 * DAY }), T0 + 20 * DAY);
    let st = await s.pinStatus({ account_id: account, now: T0 + 20 * DAY });
    assert.equal(st.status, "unpaid");
    assert.equal(st.monthly_allowance, 10);
    assert.equal(st.pack_balance, 200);
    await apply(s, ev.subEvent({ type: "customer.subscription.deleted", sub, cus, status: "canceled", ps, pe, created: T0 + 50 * DAY }), T0 + 50 * DAY);
    st = await s.pinStatus({ account_id: account, now: T0 + 50 * DAY });
    assert.equal(st.plan, "free");
    assert.equal(st.pack_balance, 200, "packs are never revoked by a subscription change");
  });

  test("FIRST INVOICE FAILS: a payment_failed for an account with no plan never grants the 3000", async () => {
    const s = await makeStore();
    const { account, cus, sub } = await linkedAccount(s, "ff");
    await apply(s, ev.checkoutSubEvent({ account, cus, sub, created: T0 }), T0);
    const r = await apply(s, ev.invoiceEvent({ type: "invoice.payment_failed", sub, cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0 }), T0);
    assert.equal(r.outcome, "ignored_no_plan");
    const st = await s.pinStatus({ account_id: account, now: T0 });
    assert.equal(st.plan, "free");
    assert.equal(st.monthly_allowance, 10);
  });

  // ------------------------------------------------------- cancel (F1-F5)

  test("F1/F2: cancel at period end keeps the month to the end, grants no new month after it, then deletion -> free", async () => {
    const s = await makeStore();
    const { account, cus, sub, ps, pe } = await subscribe(s);
    await debitN(s, account, 200, T0 + DAY);
    await apply(s, ev.subEvent({ sub, cus, cape: true, ps, pe, created: T0 + 2 * DAY }), T0 + 2 * DAY);
    let st = await s.pinStatus({ account_id: account, now: T0 + 3 * DAY });
    assert.equal(st.cancel_at_period_end, true);
    assert.equal(st.monthly_used, 200);
    assert.equal(st.monthly_allowance, 3000);
    st = await s.pinStatus({ account_id: account, now: pe + 1 });
    assert.equal(st.monthly_allowance, 0, "no provisional reset when a cancel is scheduled");
    const r = await s.debitPins({ account_id: account, request_id: "after-end", n: 1, now: pe + 2 });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "no_pins_left");
    await apply(s, ev.subEvent({ type: "customer.subscription.deleted", sub, cus, status: "canceled", ps, pe, created: pe + 1000 }), pe + 1000);
    st = await s.pinStatus({ account_id: account, now: pe + 2000 });
    assert.equal(st.plan, "free");
    assert.equal(st.status, "canceled");
    assert.equal(st.monthly_allowance, 10);
  });

  test("F3: un-cancelling before the end clears the flag; the renewal then resets as normal", async () => {
    const s = await makeStore();
    const { account, cus, sub, ps, pe } = await subscribe(s);
    await apply(s, ev.subEvent({ sub, cus, cape: true, ps, pe, created: T0 + DAY }), T0 + DAY);
    await apply(s, ev.subEvent({ sub, cus, cape: false, ps, pe, created: T0 + 2 * DAY }), T0 + 2 * DAY);
    const st = await s.pinStatus({ account_id: account, now: pe + 1 });
    assert.equal(st.cancel_at_period_end, false);
    assert.equal(st.monthly_allowance, 3000);
  });

  test("F5: subscribing again (a new subscription id) after cancel starts a new plan; a stale event for the old one is ignored", async () => {
    const s = await makeStore();
    const { account, cus, sub, sub2, ps, pe } = await subscribe(s);
    await apply(s, ev.subEvent({ type: "customer.subscription.deleted", sub, cus, status: "canceled", ps, pe, created: T0 + DAY }), T0 + DAY);
    const t2 = T0 + 5 * DAY;
    const pe2 = addMonthsUTC(t2, 1);
    await apply(s, ev.subEvent({ type: "customer.subscription.created", sub: sub2, cus, ps: t2, pe: pe2, created: t2 }), t2);
    let st = await s.pinStatus({ account_id: account, now: t2 + 1000 });
    assert.equal(st.plan, "monthly");
    assert.equal(st.status, "active");
    assert.equal(st.monthly_used, 0);
    const r = await apply(s, ev.subEvent({ sub, cus, status: "canceled", ps, pe, created: T0 + 2 * DAY }), t2 + 2000);
    assert.equal(r.outcome, "ignored_other_subscription");
    st = await s.pinStatus({ account_id: account, now: t2 + 3000 });
    assert.equal(st.status, "active");
  });

  // ------------------------------------------------------ packs and debits

  test("H7: a pack bought while past_due is credited; the account stays past_due; the month is spent first, then the pack", async () => {
    const s = await makeStore();
    const { account, cus, sub, pe } = await subscribe(s);
    const pe2 = addMonthsUTC(pe, 1);
    await apply(s, ev.invoiceEvent({ type: "invoice.payment_failed", sub, cus, ps: pe, pe: pe2, created: pe + 1000 }), pe + 1000);
    const { outcome } = await buyPack(s, account, { pack: "pins_200", at: pe + 2000 });
    assert.equal(outcome, "pack_credited");
    const r = await s.debitPins({ account_id: account, request_id: "pd-1", n: 11, now: pe + 3000 });
    assert.equal(r.ok, true);
    assert.equal(r.from_monthly, 10, "past_due after the window ended: the no-plan 10 first");
    assert.equal(r.from_packs, 1);
    const st = await s.pinStatus({ account_id: account, now: pe + 4000 });
    assert.equal(st.status, "past_due");
    assert.equal(st.pack_balance, 199);
  });

  test("C4-C6: monthly first, then packs oldest first; an emptied pack is skipped", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const p1 = await buyPack(s, a, { pack: "pins_200", at: T0 });
    const p2 = await buyPack(s, a, { pack: "pins_1000", at: T0 + 1000 });
    const r = await s.debitPins({ account_id: a, request_id: "c4", n: 10 + 201, now: T0 + 2000 });
    assert.equal(r.ok, true);
    assert.equal(r.from_monthly, 10);
    assert.equal(r.from_packs, 201);
    const packs = await s.listPacks(a);
    assert.deepEqual(packs.map((p) => [p.purchase_ref, p.units_remaining]), [[p1.session, 0], [p2.session, 999]]);
  });

  test("RACE (C3): two debits for the last pin at the same instant -> exactly one wins", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    await debitN(s, a, 9, T0);
    const rs = await Promise.all([
      s.debitPins({ account_id: a, request_id: "race-a", n: 1, now: T0 }),
      s.debitPins({ account_id: a, request_id: "race-b", n: 1, now: T0 }),
    ]);
    assert.equal(rs.filter((r) => r.ok).length, 1);
    assert.equal(rs.find((r) => !r.ok).reason, "no_pins_left");
    const st = await s.pinStatus({ account_id: a, now: T0 });
    assert.equal(st.monthly_used, 10);
  });

  test("RACE: twenty parallel debits against 3 pins left (1 monthly + a pack with 2) -> exactly 3 succeed, nothing negative", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const p = await buyPack(s, a, { pack: "pins_200", at: T0 });
    await s.debitPins({ account_id: a, request_id: "pre", n: 9 + 198, now: T0 });
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) =>
      s.debitPins({ account_id: a, request_id: `par-${i}`, n: 1, now: T0 })));
    assert.equal(rs.filter((r) => r.ok).length, 3);
    const st = await s.pinStatus({ account_id: a, now: T0 });
    assert.equal(st.monthly_left, 0);
    assert.equal(st.pack_balance, 0);
    assert.equal((await s.listPacks(a)).find((x) => x.purchase_ref === p.session).units_remaining, 0);
  });

  test("C12: the same request id twice is charged once (replay); a different count under it is refused", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const r1 = await s.debitPins({ account_id: a, request_id: "same", n: 2, now: T0 });
    const r2 = await s.debitPins({ account_id: a, request_id: "same", n: 2, now: T0 });
    assert.equal(r1.ok && r2.ok, true);
    assert.equal(r2.replay, true);
    assert.equal(r2.monthly_used, 2);
    const r3 = await s.debitPins({ account_id: a, request_id: "same", n: 5, now: T0 });
    assert.equal(r3.ok, false);
    assert.equal(r3.reason, "idempotency_key_mismatch");
  });

  test("NEVER NEGATIVE: a debit larger than everything left is refused whole and takes nothing", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    await buyPack(s, a, { pack: "pins_200", at: T0 });
    const r = await s.debitPins({ account_id: a, request_id: "big", n: 231, now: T0 });
    assert.equal(r.ok, false);
    const st = await s.pinStatus({ account_id: a, now: T0 });
    assert.equal(st.monthly_used, 0);
    assert.equal(st.pack_balance, 200);
    const bad = await s.debitPins({ account_id: a, request_id: "zero", n: 0, now: T0 });
    assert.equal(bad.reason, "bad_count");
  });

  test("H3/H12/amount: unpaid, wrong amount or unknown pack sessions credit nothing; an unknown account is unresolved", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const mk = (o) => ev.checkoutPackEvent({ account: a, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0, ...o });
    assert.equal(billing.factFromEvent(mk({ paymentStatus: "unpaid" })).kind, "ignore");
    assert.equal(billing.factFromEvent(mk({ pack: "pins_1000", amount: 500 })).kind, "ignore", "a $5 payment is not a $20 pack");
    assert.equal(billing.factFromEvent(mk({ pack: "mini" })).kind, "ignore");
    assert.equal(billing.factFromEvent(mk({ currency: "eur" })).kind, "ignore");
    const ghost = ev.checkoutPackEvent({ account: "00000000-0000-4000-8000-000000000000", /* signed, but no such account */ session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0 });
    assert.equal((await apply(s, ghost, T0)).outcome, "unresolved");
    assert.equal((await s.pinStatus({ account_id: a, now: T0 })).pack_balance, 0);
  });

  // ----------------------------------------------- refunds and disputes (I)

  test("I2: refund of the unspent value of a partly spent pack takes the remaining units; spent ones stay spent", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const { pi } = await buyPack(s, a, { pack: "pins_1000", at: T0 });
    await s.debitPins({ account_id: a, request_id: "use", n: 10 + 400, now: T0 + 1000 });
    const r = await apply(s, ev.refundEvent({ pi, amount: 2000, refunded: 1200, created: T0 + 2000 }), T0 + 2000);
    assert.equal(r.outcome, "pack_refunded");
    const [p] = await s.listPacks(a);
    assert.equal(p.units_remaining, 0);
    assert.equal(p.state, "refunded");
    assert.equal((await s.pinStatus({ account_id: a, now: T0 + 3000 })).pack_balance, 0);
  });

  test("I-partial: a 30% refund of a partly spent pack removes 300 units and the pack stays live; repeating it changes nothing", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const { pi } = await buyPack(s, a, { pack: "pins_1000", at: T0 });
    await s.debitPins({ account_id: a, request_id: "use", n: 10 + 400, now: T0 + 1000 });
    const e = ev.refundEvent({ pi, amount: 2000, refunded: 600, created: T0 + 2000 });
    await apply(s, e, T0 + 2000);
    let [p] = await s.listPacks(a);
    assert.equal(p.units_remaining, 300);
    assert.equal(p.state, "live");
    const again = ev.refundEvent({ pi, amount: 2000, refunded: 600, created: T0 + 3000 });
    assert.equal((await apply(s, again, T0 + 3000)).outcome, "refund_no_change");
    await apply(s, ev.refundEvent({ pi, amount: 2000, refunded: 2000, created: T0 + 4000 }), T0 + 4000);
    [p] = await s.listPacks(a);
    assert.equal(p.units_remaining, 0);
    assert.equal(p.state, "refunded");
  });

  test("J6: a late checkout.session.completed after the pack was refunded does not credit it again", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const session = ev.nextId("cs_test_");
    const pi = ev.nextId("pi_");
    const cus = await customerOf(s, a);
    await apply(s, ev.checkoutPackEvent({ account: a, session, pi, created: T0, cus }), T0);
    await apply(s, ev.refundEvent({ pi, amount: 2000, refunded: 2000, created: T0 + 1000 }), T0 + 1000);
    const late = ev.checkoutPackEvent({ account: a, session, pi, created: T0, cus });
    assert.equal((await apply(s, late, T0 + 2000)).outcome, "already_credited");
    assert.equal((await s.pinStatus({ account_id: a, now: T0 + 3000 })).pack_balance, 0);
  });

  test("I5-I7/I12: an open dispute holds the pack (refusal names pack_held); won releases it; lost voids it", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const { pi } = await buyPack(s, a, { pack: "pins_200", at: T0 });
    await s.debitPins({ account_id: a, request_id: "m", n: 10, now: T0 });
    await apply(s, ev.disputeEvent({ pi, status: "needs_response", created: T0 + 1000 }), T0 + 1000);
    const r = await s.debitPins({ account_id: a, request_id: "held", n: 1, now: T0 + 2000 });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "pack_held");
    await apply(s, ev.disputeEvent({ type: "charge.dispute.closed", pi, status: "won", created: T0 + 3000 }), T0 + 3000);
    assert.equal((await s.pinStatus({ account_id: a, now: T0 + 3000 })).pack_balance, 200);

    const p2 = await buyPack(s, a, { pack: "pins_1000", at: T0 + 4000 });
    await apply(s, ev.disputeEvent({ pi: p2.pi, created: T0 + 5000 }), T0 + 5000);
    await apply(s, ev.disputeEvent({ type: "charge.dispute.closed", pi: p2.pi, status: "lost", created: T0 + 6000 }), T0 + 6000);
    const packs = await s.listPacks(a);
    assert.equal(packs.find((x) => x.purchase_ref === p2.session).state, "voided");
    assert.equal((await s.pinStatus({ account_id: a, now: T0 + 7000 })).pack_balance, 200, "the other pack is untouched");
  });

  test("I8/J7: closed(lost) before created voids once and the late created is ignored; a later won releases it", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const { pi, session } = await buyPack(s, a, { pack: "pins_200", at: T0 });
    await apply(s, ev.disputeEvent({ type: "charge.dispute.closed", pi, status: "lost", created: T0 + 5000 }), T0 + 5000);
    const r = await apply(s, ev.disputeEvent({ type: "charge.dispute.created", pi, status: "needs_response", created: T0 + 1000 }), T0 + 6000);
    assert.equal(r.outcome, "ignored_stale");
    assert.equal((await s.listPacks(a)).find((x) => x.purchase_ref === session).state, "voided");
    await apply(s, ev.disputeEvent({ type: "charge.dispute.updated", pi, status: "won", created: T0 + 9000 }), T0 + 9000);
    assert.equal((await s.listPacks(a)).find((x) => x.purchase_ref === session).state, "live");
    assert.equal((await s.pinStatus({ account_id: a, now: T0 + 9000 })).pack_balance, 200);
  });

  // ------------------------------------------- the signed checkout reference

  test("REF: a forged reference (bare account id, wrong mac, other secret) links nothing; the victim can still subscribe", async () => {
    const s = await makeStore();
    const mine = await linkedAccount(s, "vic");
    const victim = mine.account;
    const attacker = idsFor("atk");
    const otherSecret = billing.mintAccountRef(victim, T0, "some-other-secret-0123456789");
    const wrongMac = victim + "." + "0".repeat(64);
    for (const ref of [victim, wrongMac, otherSecret, "garbage"]) {
      const e = ev.checkoutSubEvent({ account: victim, cus: attacker.cus, sub: attacker.sub, created: T0, ref });
      e.data.object.metadata = { account_id: victim };
      const r = await apply(s, e, T0);
      assert.equal(r.outcome, "unverified_unresolved", `ref ${ref.slice(0, 12)}`);
      assert.equal(r.account_id, null);
      assert.equal((await apply(s, e, T0)).outcome, "unverified_unresolved", "not recorded: Stripe's retry is answered the same");
    }
    // The attacker's own subscription events find no account (not linked).
    const sub = ev.subEvent({ type: "customer.subscription.created", sub: attacker.sub, cus: attacker.cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0 });
    assert.equal((await apply(s, sub, T0)).outcome, "unresolved");
    assert.equal((await s.pinStatus({ account_id: victim, now: T0 })).plan, "free");
    // The victim's own checkout, signed by us, on the victim's own customer, subscribes.
    assert.equal((await apply(s, ev.checkoutSubEvent({ account: victim, cus: mine.cus, sub: mine.sub, created: T0 }), T0)).outcome, "linked");
    await apply(s, ev.invoiceEvent({ sub: mine.sub, cus: mine.cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0 + 1000 }), T0 + 1000);
    const st = await s.pinStatus({ account_id: victim, now: T0 + 2000 });
    assert.equal(st.plan, "monthly");
    assert.equal(st.monthly_allowance, 3000);
  });

  test("REF UNVERIFIED + MARK + OWN CUSTOMER (round 2, item 3): a paid pack whose ref does not verify (secret rotated) is credited on the server mark and the account's own customer; a repeat is a duplicate", async () => {
    const s = await makeStore();
    const { account: a, cus } = await linkedAccount(s, "uv");
    // Our signed shape with a wrong mac: what every ref looks like after the
    // secret is rotated. (A bare uuid on a payment checkout without our mark
    // is not ours at all: not an account event, see the FACTS test.)
    const bad = `${a}.${Math.floor(T0 / 1000) + 7200}.${"0".repeat(64)}`;
    const e = ev.checkoutPackEvent({ account: a, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0, ref: bad, cus, pack: "pins_200" });
    assert.equal((await apply(s, e, T0)).outcome, "pack_credited");
    assert.equal((await apply(s, e, T0)).outcome, "duplicate");
    assert.equal((await s.pinStatus({ account_id: a, now: T0 })).pack_balance, 200);
  });

  test("REF UNVERIFIED otherwise (round 2, item 3): another customer, no mark, or a mark naming no account is answered unverified_unresolved (retryable), never recorded, never credited", async () => {
    const s = await makeStore();
    const { account: a } = await linkedAccount(s, "uw");
    const bad = `${a}.${Math.floor(T0 / 1000) + 7200}.${"0".repeat(64)}`;
    const session = ev.nextId("cs_test_");
    const cases = [
      ev.checkoutPackEvent({ account: a, session, pi: ev.nextId("pi_"), created: T0, ref: bad, cus: idsFor("ux").cus }),
      ev.checkoutPackEvent({ account: a, session, pi: ev.nextId("pi_"), created: T0, ref: bad, cus: idsFor("uy").cus, mark: false }),
      ev.checkoutPackEvent({ account: "00000000-0000-4000-8000-00000000f00d", session, pi: ev.nextId("pi_"), created: T0, ref: bad, cus: idsFor("uz").cus }),
    ];
    for (const e of cases) {
      assert.equal((await apply(s, e, T0)).outcome, "unverified_unresolved");
      assert.equal((await apply(s, e, T0)).outcome, "unverified_unresolved", "a retry is not a duplicate: nothing was recorded");
    }
    assert.equal((await s.pinStatus({ account_id: a, now: T0 })).pack_balance, 0);
    assert.equal((await s.listPacks(a)).length, 0);
  });

  // ------------------- ref expiry, and the customer rule (rounds 2 and 3)

  test("REF EXPIRY: a signed ref replayed after its two hours is refused (ignored_unverified_reference, reason expired); nothing is linked", async () => {
    const s = await makeStore();
    const mine = await linkedAccount(s, "ry");
    const victim = mine.account;
    const atk = idsFor("rx");
    const ref = billing.mintAccountRef(victim, T0);
    const late = T0 + 2 * HOUR + 1000; // the session is made after the ref ran out
    const e = ev.checkoutSubEvent({ account: victim, cus: atk.cus, sub: atk.sub, created: late, ref });
    const f = billing.factFromEvent(e);
    assert.equal(f.kind, "unverified_reference");
    assert.match(f.reason, /expired/);
    const r = await apply(s, e, late);
    assert.equal(r.outcome, "unverified_unresolved");
    assert.equal(r.account_id, null);
    // A pack bought on an expired ref by another customer is not credited either.
    const p = ev.checkoutPackEvent({ account: victim, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: late, ref, cus: atk.cus });
    assert.equal((await apply(s, p, late)).outcome, "unverified_unresolved");
    assert.equal((await s.pinStatus({ account_id: victim, now: late })).pack_balance, 0);
    // The owner's fresh ref, on the owner's customer, still works.
    assert.equal((await apply(s, ev.checkoutSubEvent({ account: victim, cus: mine.cus, sub: mine.sub, created: late }), late)).outcome, "linked");
  });

  test("REF RETRY: a session created inside the window is honoured when Stripe delivers (or retries) it days later", async () => {
    const s = await makeStore();
    const { account: a, cus, sub } = await linkedAccount(s, "rr");
    const ref = billing.mintAccountRef(a, T0);
    const e = ev.checkoutSubEvent({ account: a, cus, sub, created: T0 + 3 * DAY, sessionCreated: T0 + 2 * HOUR, ref });
    assert.equal((await apply(s, e, T0 + 3 * DAY)).outcome, "linked");
    const p = ev.checkoutPackEvent({ account: a, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0 + 3 * DAY,
      sessionCreated: T0 + HOUR, ref, cus });
    assert.equal((await apply(s, p, T0 + 3 * DAY)).outcome, "pack_credited");
  });

  test("LEAKED LINK (the lockout gap): a stranger pays the owner's session inside the 2 hours: the session is on the owner's customer, so the plan lands on the owner; no mismatch, no relink, nothing to cancel", async () => {
    const s = await makeStore();
    const { account, cus, sub } = await linkedAccount(s, "lk");
    // The server made the session on the owner's customer `cus` with the
    // owner's signed ref. The URL leaks; a stranger pays it an hour later.
    // Stripe completes THAT session: customer `cus`, whoever held the card.
    const paid = ev.checkoutSubEvent({ account, cus, sub, created: T0 + HOUR, sessionCreated: T0 });
    assert.equal((await apply(s, paid, T0 + HOUR)).outcome, "linked");
    const pe = addMonthsUTC(T0 + HOUR, 1);
    await apply(s, ev.subEvent({ type: "customer.subscription.created", sub, cus, ps: T0 + HOUR, pe, created: T0 + HOUR + 1000 }), T0 + HOUR + 1000);
    await apply(s, ev.invoiceEvent({ sub, cus, ps: T0 + HOUR, pe, created: T0 + HOUR + 2000 }), T0 + HOUR + 2000);
    const st = await s.pinStatus({ account_id: account, now: T0 + 2 * HOUR });
    assert.equal(st.plan, "monthly");
    assert.equal(st.status, "active");
    assert.equal(st.monthly_allowance, 3000);
    // The owner's next checkout is on the same customer: it is simply theirs.
    const r = await apply(s, ev.checkoutPackEvent({ account, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0 + 2 * HOUR, cus }), T0 + 2 * HOUR);
    assert.equal(r.outcome, "pack_credited");
  });

  test("NO RELINK: a verified checkout on another customer is refused whether the account holds a plan or not; a leaked ref on a Payment Link links nothing", async () => {
    const s = await makeStore();
    // No plan at all: still refused (there is no 'relink' of an idle account).
    const idle = await linkedAccount(s, "nr");
    const atk = idsFor("na");
    const r0 = await apply(s, ev.checkoutSubEvent({ account: idle.account, cus: atk.cus, sub: atk.sub, created: T0 }), T0);
    assert.equal(r0.outcome, "ignored_customer_mismatch");
    assert.equal(r0.account_id, idle.account);
    // The stranger's subscription events, even naming the account with the
    // owner's ref, are a mismatch; without the ref they are nobody's.
    const named = ev.subEvent({ type: "customer.subscription.created", sub: atk.sub, cus: atk.cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0, account: idle.account });
    assert.equal((await apply(s, named, T0 + 1000)).outcome, "ignored_customer_mismatch");
    const bare = ev.invoiceEvent({ sub: atk.sub, cus: atk.cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0 + 1000 });
    assert.equal((await apply(s, bare, T0 + 2000)).outcome, "unresolved");
    assert.equal((await s.pinStatus({ account_id: idle.account, now: T0 + 2000 })).plan, "free");
    // The owner's own checkout still works afterwards.
    assert.equal((await apply(s, ev.checkoutSubEvent({ account: idle.account, cus: idle.cus, sub: idle.sub, created: T0 + 3000 }), T0 + 3000)).outcome, "linked");
    // A canceled plan does not open the account to another customer either.
    const { account, cus, sub, ps, pe } = await subscribe(s, { tag: "rc" });
    await apply(s, ev.subEvent({ type: "customer.subscription.deleted", sub, cus, status: "canceled", ps, pe, created: T0 + DAY }), T0 + DAY);
    const own = idsFor("rd");
    const elsewhere = await subscribe(s, { tag: "re" });
    const r1 = await apply(s, ev.checkoutSubEvent({ account, cus: elsewhere.cus, sub: own.sub2, created: T0 + 2 * DAY }), T0 + 2 * DAY);
    assert.equal(r1.outcome, "ignored_customer_mismatch");
    const r2 = await apply(s, ev.checkoutSubEvent({ account, cus: own.cus, sub: own.sub, created: T0 + 2 * DAY }), T0 + 2 * DAY);
    assert.equal(r2.outcome, "ignored_customer_mismatch");
    // And a new subscription on the account's own customer resumes it.
    const r3 = await apply(s, ev.checkoutSubEvent({ account, cus, sub: own.sub, created: T0 + 2 * DAY }), T0 + 2 * DAY);
    assert.equal(r3.outcome, "linked");
  });

  test("NO CUSTOMER, NO LINK: an account with no stored customer refuses every verified checkout and subscription event; the event path never writes stripe_customer_id", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const { cus, sub } = idsFor("nc");
    assert.equal((await apply(s, ev.checkoutSubEvent({ account: a, cus, sub, created: T0 }), T0)).outcome, "ignored_customer_mismatch");
    assert.equal((await apply(s, ev.subEvent({ type: "customer.subscription.created", sub, cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0, account: a }), T0)).outcome,
      "ignored_customer_mismatch");
    assert.equal((await apply(s, ev.invoiceEvent({ sub, cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0 + 1000 }), T0 + 1000)).outcome, "unresolved");
    const acct = await s.getAccount(a);
    assert.equal(acct.stripe_customer_id, null);
    assert.equal((await s.pinStatus({ account_id: a, now: T0 })).plan, "free");
    // The store's setter is set-if-null, and one customer belongs to one account.
    assert.equal((await s.setStripeCustomer({ account_id: a, customer_id: cus })).set, true);
    const again = await s.setStripeCustomer({ account_id: a, customer_id: idsFor("nc2").cus });
    assert.equal(again.ok, true);
    assert.equal(again.set, false);
    assert.equal(again.customer_id, cus);
    const b = await s._createAccount();
    assert.deepEqual(await s.setStripeCustomer({ account_id: b, customer_id: cus }), { ok: false, reason: "customer_taken" });
    assert.equal((await s.setStripeCustomer({ account_id: "00000000-0000-4000-8000-00000000dead", customer_id: cus })).reason, "unknown_account");
    assert.equal((await s.getAccount(a)).stripe_customer_id, cus);
  });

  test("MISMATCH: an account whose customer has a plan in force (active, trialing, past_due) refuses another customer's verified checkout", async () => {
    const s = await makeStore();
    for (const status of ["active", "trialing", "past_due"]) {
      const { account, cus, sub, ps, pe } = await subscribe(s, { tag: "mm" });
      if (status !== "active") {
        await apply(s, ev.subEvent({ sub, cus, status, ps, pe, created: T0 + 5000 }), T0 + 5000);
      }
      const other = idsFor("mo");
      const r = await apply(s, ev.checkoutSubEvent({ account, cus: other.cus, sub: other.sub, created: T0 + HOUR }), T0 + HOUR);
      assert.equal(r.outcome, "ignored_customer_mismatch", status);
      // The original customer still drives the account.
      const again = await apply(s, ev.invoiceEvent({ sub, cus, ps, pe, created: T0 + 2 * HOUR }), T0 + 2 * HOUR);
      assert.equal(again.outcome, "subscription_applied", status);
      const no = await apply(s, ev.invoiceEvent({ sub: other.sub, cus: other.cus, ps, pe, created: T0 + 3 * HOUR }), T0 + 3 * HOUR);
      assert.equal(no.outcome, "unresolved", status);
    }
  });

  test("NOT FOUND: pin status for an account that does not exist returns nothing (no pack data)", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    await buyPack(s, a, { at: T0 });
    assert.equal(await s.pinStatus({ account_id: "00000000-0000-4000-8000-00000000abcd", now: T0 }), null);
  });

  // --------------------------------------- JS vs SQL divergence probes

  test("PROBE 1: after cancel the plan is free, and a new subscription seen only through invoice.paid is accepted", async () => {
    const s = await makeStore();
    const { account, cus, sub, sub2, ps, pe } = await subscribe(s);
    await apply(s, ev.subEvent({ type: "customer.subscription.deleted", sub, cus, status: "canceled", ps, pe, created: T0 + DAY }), T0 + DAY);
    let st = await s.pinStatus({ account_id: account, now: T0 + DAY });
    assert.equal(st.plan, "free");
    assert.equal(st.status, "canceled");
    const t2 = T0 + 3 * DAY;
    const r = await apply(s, ev.invoiceEvent({ sub: sub2, cus, ps: t2, pe: addMonthsUTC(t2, 1), created: t2 }), t2);
    assert.equal(r.outcome, "subscription_applied");
    st = await s.pinStatus({ account_id: account, now: t2 + 1000 });
    assert.equal(st.plan, "monthly");
    assert.equal(st.status, "active");
    assert.equal(st.monthly_used, 0);
    assert.equal(st.monthly_allowance, 3000);
  });

  test("PROBE 2: cancel mid-month moves the allowance to the free 10 at once (no extra 10 on top of pins used), fresh 10 next month", async () => {
    const s = await makeStore();
    const { account, cus, sub, ps, pe } = await subscribe(s);
    await debitN(s, account, 200, T0 + HOUR);
    const at = T0 + 5 * DAY;
    await apply(s, ev.subEvent({ type: "customer.subscription.deleted", sub, cus, status: "canceled", ps, pe, created: at }), at);
    let st = await s.pinStatus({ account_id: account, now: at + 1000 });
    assert.equal(st.monthly_allowance, 10);
    assert.equal(st.monthly_left, 0);
    assert.equal(st.window_end, "2026-12-01T00:00:00.000Z");
    st = await s.pinStatus({ account_id: account, now: Date.UTC(2026, 11, 1) });
    assert.equal(st.monthly_used, 0);
    assert.equal(st.monthly_left, 10);
  });

  test("PROBE 3: yearly across the year boundary (anchor Nov 30) and monthly -> yearly in December keep the anniversary", async () => {
    const s = await makeStore();
    const ps = Date.UTC(2026, 10, 30, 6);
    const { account } = await subscribe(s, { ps, lookup: "account_yearly", tag: "yb" });
    const ends = [];
    for (let k = 0; k < 4; k++) ends.push((await s.pinStatus({ account_id: account, now: addMonthsUTC(ps, k) + HOUR })).window_end);
    assert.deepEqual(ends, ["2026-12-30T06:00:00.000Z", "2027-01-30T06:00:00.000Z", "2027-02-28T06:00:00.000Z", "2027-03-30T06:00:00.000Z"]);

    const m = await subscribe(s, { ps: Date.UTC(2026, 10, 15), tag: "my" });
    const sw = Date.UTC(2026, 11, 20, 18);
    const ype = addMonthsUTC(sw, 12);
    await apply(s, ev.subEvent({ sub: m.sub, cus: m.cus, lookup: "account_yearly", ps: sw, pe: ype, created: sw }), sw);
    const a = await s.pinStatus({ account_id: m.account, now: sw + HOUR });
    assert.equal(a.window_end, "2027-01-20T18:00:00.000Z");
    assert.equal(a.period_end, "2027-12-20T18:00:00.000Z");
    const b = await s.pinStatus({ account_id: m.account, now: Date.UTC(2027, 11, 1) });
    assert.equal(b.window_end, "2027-12-20T18:00:00.000Z", "the last month of the year ends at period_end");
  });

  // ------------------------------------------------ round 2 (review fixes)

  // Item 1. Stripe's monthly periods from a Jan 31 09:00 anchor: Jan 31 ->
  // Feb 28 -> Mar 31 -> Apr 30 -> May 31 -> Jun 30. Each period is exactly one
  // window: one reset at its start and none inside it.
  test("WINDOW 29-31 (round 2, item 1): Stripe-shaped monthly renewals from Jan 31 09:00 reset exactly once per period, never inside one (Mar 28 is not a new month)", async () => {
    const s = await makeStore();
    const anchor = Date.UTC(2027, 0, 31, 9, 0, 0);
    const starts = [0, 1, 2, 3, 4, 5].map((k) => addMonthsUTC(anchor, k));
    assert.deepEqual(starts.map(isoOf), ["2027-01-31T09:00:00.000Z", "2027-02-28T09:00:00.000Z", "2027-03-31T09:00:00.000Z",
      "2027-04-30T09:00:00.000Z", "2027-05-31T09:00:00.000Z", "2027-06-30T09:00:00.000Z"]);
    const { account, cus, sub } = await subscribe(s, { ps: anchor, tag: "w31" });
    for (let i = 0; i < 5; i++) {
      const ps = starts[i];
      const pe = starts[i + 1];
      if (i > 0) {
        const r = await apply(s, ev.invoiceEvent({ sub, cus, ps, pe, created: ps + 1000 }), ps + 1000);
        assert.equal(r.outcome, "subscription_applied");
      }
      assert.equal(await debitN(s, account, 1, ps + 2000, `w${i}`), 1);
      for (let t = ps + 2000; t < pe; t += DAY / 2) {
        const st = await s.pinStatus({ account_id: account, now: t });
        assert.equal(st.window_start, isoOf(ps), `period ${i} at ${isoOf(t)}: the window is the period`);
        assert.equal(st.window_end, isoOf(pe), `period ${i} at ${isoOf(t)}`);
        assert.equal(st.monthly_used, 1, `period ${i} at ${isoOf(t)}: no second reset inside the period`);
      }
      const last = await s.pinStatus({ account_id: account, now: pe - 1 });
      assert.equal(last.monthly_used, 1, `period ${i}: still the same month one ms before its end`);
    }
  });

  test("WINDOW provisional (round 2, item 1): the renewal is late after a Feb 28 period: the month our clock opens at period_end (Mar 31) is on the fixed anchor, not period_start + 1 (Mar 28); the late invoice does not reset again", async () => {
    const s = await makeStore();
    const anchor = Date.UTC(2027, 0, 31, 9, 0, 0);
    const { account, cus, sub } = await subscribe(s, { ps: anchor, tag: "wpr" });
    const feb = addMonthsUTC(anchor, 1);
    const mar = addMonthsUTC(anchor, 2);
    await apply(s, ev.invoiceEvent({ sub, cus, ps: feb, pe: mar, created: feb + 1000 }), feb + 1000);
    await debitN(s, account, 3, Date.UTC(2027, 2, 29, 12), "wpr");
    const apr2 = Date.UTC(2027, 3, 2, 12);
    const st = await s.pinStatus({ account_id: account, now: apr2 });
    assert.equal(st.window_start, isoOf(mar), "the provisional month starts at period_end, Mar 31 09:00");
    assert.equal(st.window_end, isoOf(addMonthsUTC(anchor, 3)), "and ends on the anchor clock, Apr 30 09:00");
    assert.equal(st.monthly_used, 0);
    await debitN(s, account, 2, apr2, "wpr2");
    await apply(s, ev.invoiceEvent({ sub, cus, ps: mar, pe: addMonthsUTC(anchor, 3), created: apr2 + 1000 }), apr2 + 1000);
    assert.equal((await s.pinStatus({ account_id: account, now: apr2 + 2000 })).monthly_used, 2, "the late renewal confirms the same window");
  });

  test("YEARLY ANCHOR Feb 29 (round 2, item 1): monthly windows inside year two stay on the Feb 29 anchor (Mar 29), not on year two's moving period_start (Feb 28 + 1 = Mar 28)", async () => {
    const s = await makeStore();
    const anchor = Date.UTC(2028, 1, 29, 9, 0, 0);
    const { account, cus, sub } = await linkedAccount(s, "yfeb");
    const pe1 = addMonthsUTC(anchor, 12);
    assert.equal(isoOf(pe1), "2029-02-28T09:00:00.000Z");
    await apply(s, ev.checkoutSubEvent({ account, cus, sub, created: anchor }), anchor);
    await apply(s, ev.subEvent({ type: "customer.subscription.created", sub, cus, lookup: "account_yearly", ps: anchor, pe: pe1, created: anchor, anchor }), anchor);
    await apply(s, ev.invoiceEvent({ sub, cus, lookup: "account_yearly", ps: anchor, pe: pe1, created: anchor + 1000 }), anchor + 1000);
    // Year one: Feb 29 -> Mar 29 -> Apr 29.
    assert.equal((await s.pinStatus({ account_id: account, now: Date.UTC(2028, 2, 29, 10) })).window_start, "2028-03-29T09:00:00.000Z");
    // Year two: Stripe's period runs Feb 28 2029 -> Feb 28 2030 on the same anchor.
    const pe2 = addMonthsUTC(anchor, 24);
    await apply(s, ev.subEvent({ sub, cus, lookup: "account_yearly", ps: pe1, pe: pe2, created: pe1 + 500, anchor }), pe1 + 500);
    await apply(s, ev.invoiceEvent({ sub, cus, lookup: "account_yearly", ps: pe1, pe: pe2, created: pe1 + 1000 }), pe1 + 1000);
    await debitN(s, account, 1, Date.UTC(2029, 2, 1, 12), "yfeb");
    const mar28 = await s.pinStatus({ account_id: account, now: Date.UTC(2029, 2, 28, 12) });
    assert.equal(mar28.window_start, "2029-02-28T09:00:00.000Z");
    assert.equal(mar28.window_end, "2029-03-29T09:00:00.000Z");
    assert.equal(mar28.monthly_used, 1, "no reset on Mar 28");
    const mar29 = await s.pinStatus({ account_id: account, now: Date.UTC(2029, 2, 29, 10) });
    assert.equal(mar29.window_start, "2029-03-29T09:00:00.000Z");
    assert.equal(mar29.monthly_used, 0, "the reset is on the anchor's day");
  });

  // Item 2. The positive server mark and the customer lock on packs.
  test("CUSTOMER LOCK on packs (round 2, item 2): a verified, marked pack session on another customer is ignored_customer_mismatch and credits nothing; on the account's own customer it credits", async () => {
    const s = await makeStore();
    const { account, cus } = await linkedAccount(s, "cl");
    const other = idsFor("clo").cus;
    const r1 = await apply(s, ev.checkoutPackEvent({ account, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0, cus: other }), T0);
    assert.equal(r1.outcome, "ignored_customer_mismatch");
    const r2 = await apply(s, ev.checkoutPackEvent({ account, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0 }), T0);
    assert.equal(r2.outcome, "ignored_customer_mismatch", "no customer at all is a mismatch too");
    assert.equal((await s.pinStatus({ account_id: account, now: T0 })).pack_balance, 0);
    const r3 = await apply(s, ev.checkoutPackEvent({ account, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0, cus }), T0);
    assert.equal(r3.outcome, "pack_credited");
    assert.equal((await s.pinStatus({ account_id: account, now: T0 })).pack_balance, 1000);
  });

  test("SERVER MARK (round 2, item 2): a verified ref without our metadata.account_id, or with one naming another account, credits no pack and links no plan, even on the account's own customer", async () => {
    const s = await makeStore();
    const { account, cus, sub } = await linkedAccount(s, "sm");
    const p1 = ev.checkoutPackEvent({ account, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0, cus, mark: false });
    assert.equal((await apply(s, p1, T0)).outcome, "ignored_no_server_mark");
    const p2 = ev.checkoutPackEvent({ account, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0, cus });
    p2.data.object.metadata.account_id = "00000000-0000-4000-8000-0000000000aa";
    assert.equal((await apply(s, p2, T0)).outcome, "ignored_no_server_mark");
    const l1 = ev.checkoutSubEvent({ account, cus, sub, created: T0, mark: false });
    assert.equal((await apply(s, l1, T0)).outcome, "ignored_no_server_mark");
    assert.equal((await apply(s, l1, T0)).outcome, "duplicate", "recorded: a final refusal");
    assert.equal((await s.pinStatus({ account_id: account, now: T0 })).pack_balance, 0);
    assert.equal((await s.listPacks(account)).length, 0);
  });

  // Item 4. Refunds and disputes on a plan invoice's charge.
  async function subscribePaid(s, tag) {
    const { account, cus, sub, sub2 } = await linkedAccount(s, tag);
    const ps = T0;
    const pe = addMonthsUTC(ps, 1);
    const inv = ev.nextId("in_");
    const pi = ev.nextId("pi_");
    const charge = ev.nextId("ch_");
    await apply(s, ev.checkoutSubEvent({ account, cus, sub, created: ps }), ps);
    await apply(s, ev.subEvent({ type: "customer.subscription.created", sub, cus, ps, pe, created: ps }), ps);
    await apply(s, ev.invoiceEvent({ sub, cus, ps, pe, created: ps + 1000, inv, pi, charge, amount: 900 }), ps + 1000);
    return { account, cus, sub, sub2, ps, pe, inv, pi, charge };
  }

  test("PLAN DISPUTE (round 2, item 4): an open dispute on the plan invoice's charge holds the plan (allowance 0, use kept); won releases it; lost holds it", async () => {
    const s = await makeStore();
    const { account, pi, charge } = await subscribePaid(s, "pd");
    assert.equal(await debitN(s, account, 5, T0 + HOUR, "pd"), 5);
    const open = await apply(s, ev.disputeEvent({ pi, charge, status: "needs_response", created: T0 + DAY }), T0 + DAY);
    assert.equal(open.outcome, "plan_hold");
    let st = await s.pinStatus({ account_id: account, now: T0 + DAY + 1000 });
    assert.equal(st.monthly_allowance, 0);
    assert.equal(st.monthly_used, 5);
    assert.equal((await s.debitPins({ account_id: account, request_id: "pd-held", n: 1, now: T0 + DAY + 2000 })).ok, false);
    const won = await apply(s, ev.disputeEvent({ type: "charge.dispute.closed", pi, charge, status: "won", created: T0 + 2 * DAY }), T0 + 2 * DAY);
    assert.equal(won.outcome, "plan_release");
    st = await s.pinStatus({ account_id: account, now: T0 + 2 * DAY + 1000 });
    assert.equal(st.monthly_allowance, 3000);
    assert.equal(st.monthly_used, 5, "release is not a reset");
    const s2 = await subscribePaid(s, "pl");
    await apply(s, ev.disputeEvent({ pi: s2.pi, charge: s2.charge, created: T0 + DAY }), T0 + DAY);
    const lost = await apply(s, ev.disputeEvent({ type: "charge.dispute.closed", pi: s2.pi, charge: s2.charge, status: "lost", created: T0 + 2 * DAY }), T0 + 2 * DAY);
    assert.equal(lost.outcome, "plan_hold");
    assert.equal((await s.pinStatus({ account_id: s2.account, now: T0 + 3 * DAY })).monthly_allowance, 0);
  });

  test("PLAN REFUND (round 2, item 4): a full refund of the current period's invoice ends that period's allowance; a partial one does not; the next paid period gets its 3000", async () => {
    const s = await makeStore();
    const { account, cus, sub, pe, inv, pi, charge } = await subscribePaid(s, "pr");
    await debitN(s, account, 7, T0 + HOUR, "pr");
    const part = await apply(s, ev.refundEvent({ pi, charge, inv, cus, amount: 900, refunded: 300, created: T0 + DAY }), T0 + DAY);
    assert.equal(part.outcome, "plan_refund_partial");
    assert.equal((await s.pinStatus({ account_id: account, now: T0 + DAY + 1000 })).monthly_allowance, 3000);
    const full = await apply(s, ev.refundEvent({ pi, charge, inv, cus, amount: 900, refunded: 900, created: T0 + 2 * DAY }), T0 + 2 * DAY);
    assert.equal(full.outcome, "plan_refund_voided");
    const st = await s.pinStatus({ account_id: account, now: T0 + 2 * DAY + 1000 });
    assert.equal(st.monthly_allowance, 0);
    assert.equal(st.monthly_left, 0);
    await apply(s, ev.invoiceEvent({ sub, cus, ps: pe, pe: addMonthsUTC(pe, 1), created: pe + 1000 }), pe + 1000);
    const next = await s.pinStatus({ account_id: account, now: pe + 2000 });
    assert.equal(next.monthly_allowance, 3000);
    assert.equal(next.monthly_used, 0);
  });

  test("PLAN REFUND by the charge's customer (round 2, item 4): a refund on an invoice charge whose payment intent was never seen resolves by the invoice and the charge's customer", async () => {
    const s = await makeStore();
    const { account, cus, inv } = await subscribePaid(s, "pc");
    const r = await apply(s, ev.refundEvent({ pi: ev.nextId("pi_"), inv, cus, amount: 900, refunded: 900, created: T0 + DAY }), T0 + DAY);
    assert.equal(r.outcome, "plan_refund_voided");
    assert.equal(r.account_id, account);
    assert.equal((await s.pinStatus({ account_id: account, now: T0 + DAY + 1000 })).monthly_allowance, 0);
    // An invoice charge on a customer no account holds is unresolved.
    const nobody = await apply(s, ev.refundEvent({ pi: ev.nextId("pi_"), inv: ev.nextId("in_"), cus: idsFor("pz").cus, amount: 900, refunded: 900, created: T0 + DAY }), T0 + DAY);
    assert.equal(nobody.outcome, "unresolved");
  });

  test("I13/LINK: a refund or dispute on a charge that is neither a pack nor a plan invoice changes nothing; one customer cannot serve two accounts", async () => {
    const s = await makeStore();
    const { account, cus } = await subscribe(s);
    const r = await apply(s, ev.refundEvent({ pi: ev.nextId("pi_"), amount: 900, refunded: 900, created: T0 }), T0);
    assert.equal(r.outcome, "unresolved");
    const d = await apply(s, ev.disputeEvent({ pi: ev.nextId("pi_"), created: T0 }), T0);
    assert.equal(d.outcome, "unresolved");
    assert.equal((await s.pinStatus({ account_id: account, now: T0 + 1000 })).monthly_allowance, 3000);
    const other = await s._createAccount();
    const r2 = await apply(s, ev.checkoutSubEvent({ account: other, cus, sub: ev.nextId("sub_"), created: T0 }), T0);
    assert.equal(r2.outcome, "ignored_customer_mismatch");
    assert.deepEqual(await s.setStripeCustomer({ account_id: other, customer_id: cus }), { ok: false, reason: "customer_taken" });
    assert.equal((await s.pinStatus({ account_id: account, now: T0 })).plan, "monthly");
    assert.equal((await s.pinStatus({ account_id: other, now: T0 })).plan, "free");
  });
}

module.exports = { scenarios, T0 };
