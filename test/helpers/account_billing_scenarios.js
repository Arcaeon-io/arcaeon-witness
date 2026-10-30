// test/helpers/account_billing_scenarios.js — the account billing cases from
// the outside test plan (case ids in the names), written against the store
// INTERFACE only, so the same cases run against any store:
//   test/account_billing.test.js runs them on the in-memory store.
// A store needs: _createAccount(), applyStripeEvent, debitPins, pinStatus,
// listPacks. Not a test file itself (no top-level test() calls).

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
  const apply = (s, event, now) =>
    s.applyStripeEvent({ event_id: event.id, type: event.type, fact: billing.factFromEvent(event), now });

  async function debitN(s, account_id, count, now, tag = "r") {
    let ok = 0;
    for (let i = 0; i < count; i++) {
      const r = await s.debitPins({ account_id, request_id: `${tag}-${i}-${ev.nextId("")}`, n: 1, now });
      if (r.ok) ok++;
    }
    return ok;
  }

  // An account on the monthly plan from `ps`, linked the way a real checkout
  // links it: checkout.session.completed, subscription.created, invoice.paid.
  async function subscribe(s, { ps = T0, lookup = "account_monthly", months = 1, tag = "m" } = {}) {
    const account = await s._createAccount();
    const { cus, sub, sub2 } = idsFor(tag);
    const pe = addMonthsUTC(ps, lookup === "account_yearly" ? 12 : months);
    await apply(s, ev.checkoutSubEvent({ account, cus, sub, created: ps }), ps);
    await apply(s, ev.subEvent({ type: "customer.subscription.created", sub, cus, lookup, ps, pe, created: ps }), ps);
    await apply(s, ev.invoiceEvent({ sub, cus, lookup, ps, pe, created: ps + 1000 }), ps + 1000);
    return { account, cus, sub, sub2, ps, pe, lookup };
  }

  async function buyPack(s, account, { pack = "pins_1000", at = T0, pi } = {}) {
    const session = ev.nextId("cs_test_");
    const payment_intent = pi || ev.nextId("pi_");
    const r = await apply(s, ev.checkoutPackEvent({ account, session, pack, pi: payment_intent, created: at }), at);
    return { session, pi: payment_intent, outcome: r.outcome };
  }

  // ------------------------------------------------------------ free tier

  test("FREE: no plan gets 30 a month on the UTC calendar month; the 31st pin is refused; next month resets", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    assert.equal(await debitN(s, a, 31, T0), 30);
    const st = await s.pinStatus({ account_id: a, now: T0 });
    assert.equal(st.plan, "free");
    assert.equal(st.monthly_allowance, 30);
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

  test("A2 (incomplete): subscription.created incomplete gives no plan in force, only the free 30", async () => {
    const s = await makeStore();
    const account = await s._createAccount();
    const { cus, sub } = idsFor("inc");
    await apply(s, ev.checkoutSubEvent({ account, cus, sub, created: T0 }), T0);
    await apply(s, ev.subEvent({ type: "customer.subscription.created", sub, cus, status: "incomplete", ps: T0,
      pe: addMonthsUTC(T0, 1), created: T0 }), T0);
    const st = await s.pinStatus({ account_id: account, now: T0 });
    assert.equal(st.status, "incomplete");
    assert.equal(st.monthly_allowance, 30);
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
    const e1 = ev.checkoutPackEvent({ account, session, pi, created: T0 });
    const e2 = ev.checkoutPackEvent({ account, session, pi, type: "checkout.session.async_payment_succeeded", created: T0 + 1000 });
    assert.equal((await apply(s, e1, T0)).outcome, "pack_credited");
    assert.equal((await apply(s, e2, T0)).outcome, "already_credited");
    const packs = await s.listPacks(account);
    assert.equal(packs.length, 1);
    assert.equal((await s.pinStatus({ account_id: account, now: T0 })).pack_balance, 1000);
  });

  test("J3: the same event delivered to two workers at once has one effect", async () => {
    const s = await makeStore();
    const account = await s._createAccount();
    const e = ev.checkoutPackEvent({ account, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0 });
    const rs = await Promise.all([apply(s, e, T0), apply(s, e, T0)]);
    assert.deepEqual(rs.map((r) => r.outcome).sort(), ["duplicate", "pack_credited"]);
    assert.equal((await s.listPacks(account)).length, 1);
  });

  // --------------------------------------------------------- order (J4-J5)

  test("J4: invoice.paid before the account is linked is unresolved (not recorded), then lands on Stripe's retry", async () => {
    const s = await makeStore();
    const account = await s._createAccount();
    const { cus, sub } = idsFor("j4");
    const pe = addMonthsUTC(T0, 1);
    const paid = ev.invoiceEvent({ sub, cus, ps: T0, pe, created: T0 + 1000 });
    assert.equal((await apply(s, paid, T0 + 1000)).outcome, "unresolved");
    await apply(s, ev.checkoutSubEvent({ account, cus, sub, created: T0 }), T0 + 2000);
    const retry = await apply(s, paid, T0 + 60000);
    assert.equal(retry.outcome, "subscription_applied", "the retry is applied, not answered duplicate");
    const st = await s.pinStatus({ account_id: account, now: T0 + 60000 });
    assert.equal(st.plan, "monthly");
    assert.equal(st.monthly_allowance, 3000);
  });

  test("J4b: an invoice that carries subscription metadata.account_id resolves without the checkout event", async () => {
    const s = await makeStore();
    const account = await s._createAccount();
    const { cus, sub } = idsFor("j4b");
    const r = await apply(s, ev.invoiceEvent({ sub, cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0, account }), T0);
    assert.equal(r.outcome, "subscription_applied");
    assert.equal((await s.pinStatus({ account_id: account, now: T0 })).plan, "monthly");
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

  test("E1-E3: renewal payment fails -> past_due keeps access with a fresh 3000; a second failure changes nothing; recovery does not reset again", async () => {
    const s = await makeStore();
    const { account, cus, sub, pe } = await subscribe(s);
    await debitN(s, account, 2999, T0 + DAY);
    const pe2 = addMonthsUTC(pe, 1);
    const f1 = ev.invoiceEvent({ type: "invoice.payment_failed", sub, cus, ps: pe, pe: pe2, created: pe + 1000 });
    assert.equal((await apply(s, f1, pe + 1000)).outcome, "subscription_applied");
    let st = await s.pinStatus({ account_id: account, now: pe + 2000 });
    assert.equal(st.status, "past_due");
    assert.equal(st.monthly_used, 0);
    assert.equal(st.monthly_allowance, 3000, "past_due keeps access (the decision: keep access)");
    assert.equal(await debitN(s, account, 40, pe + 3000), 40);
    const f2 = ev.invoiceEvent({ type: "invoice.payment_failed", sub, cus, ps: pe, pe: pe2, created: pe + 3 * DAY });
    await apply(s, f2, pe + 3 * DAY);
    st = await s.pinStatus({ account_id: account, now: pe + 3 * DAY });
    assert.equal(st.status, "past_due");
    assert.equal(st.monthly_used, 40);
    const ok = ev.invoiceEvent({ sub, cus, ps: pe, pe: pe2, created: pe + 4 * DAY });
    await apply(s, ok, pe + 4 * DAY);
    st = await s.pinStatus({ account_id: account, now: pe + 4 * DAY });
    assert.equal(st.status, "active");
    assert.equal(st.monthly_used, 40, "recovery is the same period: no second 3000");
  });

  test("E4/E7: unpaid falls back to the free 30 (packs still spend); deletion leaves the account free with its packs", async () => {
    const s = await makeStore();
    const { account, cus, sub, ps, pe } = await subscribe(s);
    await buyPack(s, account, { pack: "pins_200", at: T0 + HOUR });
    await apply(s, ev.subEvent({ sub, cus, status: "unpaid", ps, pe, created: T0 + 20 * DAY }), T0 + 20 * DAY);
    let st = await s.pinStatus({ account_id: account, now: T0 + 20 * DAY });
    assert.equal(st.status, "unpaid");
    assert.equal(st.monthly_allowance, 30);
    assert.equal(st.pack_balance, 200);
    await apply(s, ev.subEvent({ type: "customer.subscription.deleted", sub, cus, status: "canceled", ps, pe, created: T0 + 50 * DAY }), T0 + 50 * DAY);
    st = await s.pinStatus({ account_id: account, now: T0 + 50 * DAY });
    assert.equal(st.plan, "free");
    assert.equal(st.pack_balance, 200, "packs are never revoked by a subscription change");
  });

  test("FIRST INVOICE FAILS: a payment_failed for an account with no plan never grants the 3000", async () => {
    const s = await makeStore();
    const account = await s._createAccount();
    const { cus, sub } = idsFor("ff");
    await apply(s, ev.checkoutSubEvent({ account, cus, sub, created: T0 }), T0);
    const r = await apply(s, ev.invoiceEvent({ type: "invoice.payment_failed", sub, cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0 }), T0);
    assert.equal(r.outcome, "ignored_no_plan");
    const st = await s.pinStatus({ account_id: account, now: T0 });
    assert.equal(st.plan, "free");
    assert.equal(st.monthly_allowance, 30);
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
    assert.equal(st.monthly_allowance, 30);
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
    const r = await s.debitPins({ account_id: account, request_id: "pd-1", n: 3001, now: pe + 3000 });
    assert.equal(r.ok, true);
    assert.equal(r.from_monthly, 3000);
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
    const r = await s.debitPins({ account_id: a, request_id: "c4", n: 30 + 201, now: T0 + 2000 });
    assert.equal(r.ok, true);
    assert.equal(r.from_monthly, 30);
    assert.equal(r.from_packs, 201);
    const packs = await s.listPacks(a);
    assert.deepEqual(packs.map((p) => [p.purchase_ref, p.units_remaining]), [[p1.session, 0], [p2.session, 999]]);
  });

  test("RACE (C3): two debits for the last pin at the same instant -> exactly one wins", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    await debitN(s, a, 29, T0);
    const rs = await Promise.all([
      s.debitPins({ account_id: a, request_id: "race-a", n: 1, now: T0 }),
      s.debitPins({ account_id: a, request_id: "race-b", n: 1, now: T0 }),
    ]);
    assert.equal(rs.filter((r) => r.ok).length, 1);
    assert.equal(rs.find((r) => !r.ok).reason, "no_pins_left");
    const st = await s.pinStatus({ account_id: a, now: T0 });
    assert.equal(st.monthly_used, 30);
  });

  test("RACE: twenty parallel debits against 3 pins left (1 monthly + a pack with 2) -> exactly 3 succeed, nothing negative", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const p = await buyPack(s, a, { pack: "pins_200", at: T0 });
    await s.debitPins({ account_id: a, request_id: "pre", n: 29 + 198, now: T0 });
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
    await s.debitPins({ account_id: a, request_id: "use", n: 30 + 400, now: T0 + 1000 });
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
    await s.debitPins({ account_id: a, request_id: "use", n: 30 + 400, now: T0 + 1000 });
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
    await apply(s, ev.checkoutPackEvent({ account: a, session, pi, created: T0 }), T0);
    await apply(s, ev.refundEvent({ pi, amount: 2000, refunded: 2000, created: T0 + 1000 }), T0 + 1000);
    const late = ev.checkoutPackEvent({ account: a, session, pi, created: T0 });
    assert.equal((await apply(s, late, T0 + 2000)).outcome, "already_credited");
    assert.equal((await s.pinStatus({ account_id: a, now: T0 + 3000 })).pack_balance, 0);
  });

  test("I5-I7/I12: an open dispute holds the pack (refusal names pack_held); won releases it; lost voids it", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const { pi } = await buyPack(s, a, { pack: "pins_200", at: T0 });
    await s.debitPins({ account_id: a, request_id: "m", n: 30, now: T0 });
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
    const victim = await s._createAccount();
    const attacker = idsFor("atk");
    const otherSecret = billing.mintAccountRef(victim, T0, "some-other-secret-0123456789");
    const wrongMac = victim + "." + "0".repeat(64);
    for (const ref of [victim, wrongMac, otherSecret, "garbage"]) {
      const e = ev.checkoutSubEvent({ account: victim, cus: attacker.cus, sub: attacker.sub, created: T0, ref });
      e.data.object.metadata = { account_id: victim };
      const r = await apply(s, e, T0);
      assert.equal(r.outcome, "ignored_unverified_reference", `ref ${ref.slice(0, 12)}`);
      assert.equal(r.account_id, null);
    }
    // The attacker's own subscription events find no account (not linked).
    const sub = ev.subEvent({ type: "customer.subscription.created", sub: attacker.sub, cus: attacker.cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0 });
    assert.equal((await apply(s, sub, T0)).outcome, "unresolved");
    assert.equal((await s.pinStatus({ account_id: victim, now: T0 })).plan, "free");
    // The victim's own checkout, signed by us, links and subscribes.
    const mine = idsFor("vic");
    assert.equal((await apply(s, ev.checkoutSubEvent({ account: victim, cus: mine.cus, sub: mine.sub, created: T0 }), T0)).outcome, "linked");
    await apply(s, ev.invoiceEvent({ sub: mine.sub, cus: mine.cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0 + 1000 }), T0 + 1000);
    const st = await s.pinStatus({ account_id: victim, now: T0 + 2000 });
    assert.equal(st.plan, "monthly");
    assert.equal(st.monthly_allowance, 3000);
  });

  test("REF: a paid pack under a bad reference is recorded as ignored_unverified_reference and never credited (a repeat is a duplicate)", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    // Our signed shape with a wrong mac. (A bare uuid on a payment checkout is
    // no longer ours at all: not an account event, see the FACTS test.)
    const bad = `${a}.${Math.floor(T0 / 1000) + 7200}.${"0".repeat(64)}`;
    const e = ev.checkoutPackEvent({ account: a, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0, ref: bad });
    assert.equal((await apply(s, e, T0)).outcome, "ignored_unverified_reference");
    assert.equal((await apply(s, e, T0)).outcome, "duplicate");
    assert.equal((await s.pinStatus({ account_id: a, now: T0 })).pack_balance, 0);
    assert.equal((await s.listPacks(a)).length, 0);
  });

  // ------------------------- ref expiry and the mismatch relink (round 2)

  test("REF EXPIRY: a signed ref replayed after its two hours is refused (ignored_unverified_reference, reason expired); nothing is linked", async () => {
    const s = await makeStore();
    const victim = await s._createAccount();
    const atk = idsFor("rx");
    const ref = billing.mintAccountRef(victim, T0);
    const late = T0 + 2 * HOUR + 1000; // the session is made after the ref ran out
    const e = ev.checkoutSubEvent({ account: victim, cus: atk.cus, sub: atk.sub, created: late, ref });
    const f = billing.factFromEvent(e);
    assert.equal(f.kind, "unverified_reference");
    assert.match(f.reason, /expired/);
    const r = await apply(s, e, late);
    assert.equal(r.outcome, "ignored_unverified_reference");
    assert.equal(r.account_id, null);
    // A pack bought on an expired ref is not credited either.
    const p = ev.checkoutPackEvent({ account: victim, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: late, ref });
    assert.equal((await apply(s, p, late)).outcome, "ignored_unverified_reference");
    assert.equal((await s.pinStatus({ account_id: victim, now: late })).pack_balance, 0);
    // The owner's fresh ref still links.
    const mine = idsFor("ry");
    assert.equal((await apply(s, ev.checkoutSubEvent({ account: victim, cus: mine.cus, sub: mine.sub, created: late }), late)).outcome, "linked");
  });

  test("REF RETRY: a session created inside the window is honoured when Stripe delivers (or retries) it days later", async () => {
    const s = await makeStore();
    const a = await s._createAccount();
    const { cus, sub } = idsFor("rr");
    const ref = billing.mintAccountRef(a, T0);
    const e = ev.checkoutSubEvent({ account: a, cus, sub, created: T0 + 3 * DAY, sessionCreated: T0 + 2 * HOUR, ref });
    assert.equal((await apply(s, e, T0 + 3 * DAY)).outcome, "linked");
    const p = ev.checkoutPackEvent({ account: a, session: ev.nextId("cs_test_"), pi: ev.nextId("pi_"), created: T0 + 3 * DAY,
      sessionCreated: T0 + HOUR, ref });
    assert.equal((await apply(s, p, T0 + 3 * DAY)).outcome, "pack_credited");
  });

  test("RELINK: an account an attacker linked (no plan in force) is relinked by the owner's verified checkout; the attacker's later events are refused", async () => {
    const s = await makeStore();
    const victim = await s._createAccount();
    const atk = idsFor("ra");
    // The attacker pays first on a leaked, still-valid ref; their payment never completes.
    assert.equal((await apply(s, ev.checkoutSubEvent({ account: victim, cus: atk.cus, sub: atk.sub, created: T0 }), T0)).outcome, "linked");
    const own = idsFor("ro");
    const r = await apply(s, ev.checkoutSubEvent({ account: victim, cus: own.cus, sub: own.sub, created: T0 + HOUR }), T0 + HOUR);
    assert.equal(r.outcome, "relinked");
    assert.equal(r.account_id, victim);
    const inv = await apply(s, ev.invoiceEvent({ sub: own.sub, cus: own.cus, ps: T0 + HOUR, pe: addMonthsUTC(T0 + HOUR, 1), created: T0 + HOUR + 1000 }), T0 + HOUR + 1000);
    assert.equal(inv.outcome, "subscription_applied");
    const st = await s.pinStatus({ account_id: victim, now: T0 + 2 * HOUR });
    assert.equal(st.plan, "monthly");
    assert.equal(st.monthly_allowance, 3000);
    // The attacker's own subscription, signed with the same leaked ref, is a mismatch now.
    const late = ev.subEvent({ type: "customer.subscription.created", sub: atk.sub, cus: atk.cus, ps: T0, pe: addMonthsUTC(T0, 1), created: T0, account: victim });
    assert.equal((await apply(s, late, T0 + 3 * HOUR)).outcome, "ignored_customer_mismatch");
    assert.equal((await s.pinStatus({ account_id: victim, now: T0 + 3 * HOUR })).plan, "monthly");
  });

  test("RELINK: a canceled attacker subscription no longer holds the account; the owner's verified checkout relinks it", async () => {
    const s = await makeStore();
    const { account, cus, sub, ps, pe } = await subscribe(s, { tag: "rc" });
    await apply(s, ev.subEvent({ type: "customer.subscription.deleted", sub, cus, status: "canceled", ps, pe, created: T0 + DAY }), T0 + DAY);
    const own = idsFor("rd");
    // A customer already linked to another account is never taken by a relink.
    const elsewhere = await subscribe(s, { tag: "re" });
    const r0 = await apply(s, ev.checkoutSubEvent({ account, cus: elsewhere.cus, sub: own.sub2, created: T0 + 2 * DAY }), T0 + 2 * DAY);
    assert.equal(r0.outcome, "ignored_customer_linked_elsewhere");
    const r = await apply(s, ev.checkoutSubEvent({ account, cus: own.cus, sub: own.sub, created: T0 + 2 * DAY }), T0 + 2 * DAY);
    assert.equal(r.outcome, "relinked");
  });

  test("MISMATCH: an account whose customer has a plan in force (active, trialing, past_due) is NOT relinked by another verified checkout", async () => {
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

  test("PROBE 2: cancel mid-month moves the allowance to the free 30 at once (no extra 30 on top of pins used), fresh 30 next month", async () => {
    const s = await makeStore();
    const { account, cus, sub, ps, pe } = await subscribe(s);
    await debitN(s, account, 200, T0 + HOUR);
    const at = T0 + 5 * DAY;
    await apply(s, ev.subEvent({ type: "customer.subscription.deleted", sub, cus, status: "canceled", ps, pe, created: at }), at);
    let st = await s.pinStatus({ account_id: account, now: at + 1000 });
    assert.equal(st.monthly_allowance, 30);
    assert.equal(st.monthly_left, 0);
    assert.equal(st.window_end, "2026-12-01T00:00:00.000Z");
    st = await s.pinStatus({ account_id: account, now: Date.UTC(2026, 11, 1) });
    assert.equal(st.monthly_used, 0);
    assert.equal(st.monthly_left, 30);
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

  test("I13/LINK: a refund or dispute on a charge that is not a pack changes nothing; one customer cannot link two accounts", async () => {
    const s = await makeStore();
    const { account, cus } = await subscribe(s);
    const r = await apply(s, ev.refundEvent({ pi: ev.nextId("pi_"), amount: 900, refunded: 900, created: T0 }), T0);
    assert.equal(r.outcome, "unresolved");
    const other = await s._createAccount();
    const r2 = await apply(s, ev.checkoutSubEvent({ account: other, cus, sub: ev.nextId("sub_"), created: T0 }), T0);
    assert.equal(r2.outcome, "ignored_customer_linked_elsewhere");
    assert.equal((await s.pinStatus({ account_id: account, now: T0 })).plan, "monthly");
  });
}

module.exports = { scenarios, T0 };
