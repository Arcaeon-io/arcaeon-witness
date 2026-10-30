// _account_billing.js — the Arcaeon account, phase 2: the Stripe subscription
// lifecycle and the pin allowance. Underscore prefix = not routed as a
// serverless function.
//
// The rules (the owner's, exact):
//   - Account plan: $9/month (Stripe price lookup key account_monthly) or
//     $99/year (account_yearly), auto-renew.
//   - 3,000 pins a month that RESET monthly, use it or lose it. A monthly
//     plan's month IS Stripe's billing period [period_start, period_end).
//     The yearly plan resets to 3,000 each month on our own anniversary clock
//     inside the paid year, counted from the subscription's FIXED anchor
//     (Stripe's billing_cycle_anchor, else the subscription's first
//     period_start), never from the moving period_start: a Jan 31 or Feb 29
//     anchor keeps its day (round 2: period_start + k months reset twice in
//     a Feb 28 -> Mar 31 period, on Mar 28). No pool.
//   - Packs (pins_200 = 200 pins $5, pins_1000 = 1,000 pins $20) never expire
//     and are spent only after the month's 3,000 run out.
//   - No plan in force (never paid, or lapsed: canceled, unpaid, incomplete,
//     incomplete_expired, paused) gets 10 pins a month (UTC calendar month).
//     (Owner + council, 2026-10-30: was 30.) Not the witness per-key daily
//     free cap, which is a separate mechanism.
//   - A plan in force ("paid") = plan monthly or yearly AND status active or
//     trialing.
//   - past_due keeps the monthly window it is in (its 3,000 and what it used)
//     but gets no new monthly reset; when that window ends while still
//     past_due, it falls to the no-plan 10 on the calendar month. Back to
//     active, the anniversary windows resume from period_start.
//   - A plan invoice's charge refunded in full ends that period's 3,000; an
//     open or lost dispute on it holds the plan's allowance at 0 until it is
//     won or closed (round 2).
//   - Counts and paid accounts only, never content.
//
// Three layers, all in this file:
//   1. factFromEvent(event): a VERIFIED Stripe event -> one small "fact"
//      (plain JSON: link, subscription, pack_credit, pack_refund, pack_dispute,
//      or ignore). Pure; no store, no clock.
//   2. The state machine over one account's state, in JS: windowAt, rollState,
//      debitState, applyFactToState. The in-memory store (lib/_accountdb.js)
//      runs exactly these. The Postgres functions in
//      supabase/migrations/2026_10_31_account_v2.sql run the same rules in
//      plpgsql, one transaction each, under the account row lock.
//   3. handleAccountEvent(event, res): the webhook branch. api/stripe-webhook.js
//      verifies the signature (its own verifyStripeSignature, reused) and the
//      livemode, then hands account events here.
//
// Who the customer is. accounts.stripe_customer_id is written by ONE path:
// the authenticated checkout endpoint (lib/_account_checkout.js) makes the
// account's Stripe customer once, stores it (set-if-null), and puts it on
// every Checkout Session it creates. Events here only ever COMPARE against
// it (checkCustomer): an event whose customer is not the account's own is
// ignored_customer_mismatch, whatever reference it carries. So paying a
// leaked session URL pays for the account on its own customer, and a leaked
// ref on a Payment Link links nothing. There is no relink.
//
// Ordering and duplicates. Stripe sends events twice and out of order. The
// event id is recorded with the change in one transaction (stripe_events), so
// a repeat is a no-op. Across different events the guards are: a canceled
// subscription never comes back (Stripe's canceled is terminal); a period
// never moves backward; an older event (by event.created) for the same
// subscription does not overwrite a newer one; packs are keyed by the
// Checkout Session id; refunds by cumulative amount; disputes by final status.
// NOT built: re-fetching the object from Stripe on every event (the plan's
// "events are hints"). That needs a live Stripe call, which this build never
// makes; the guards above are what stand in for it.

"use strict";

const crypto = require("crypto");

const PAID_MONTHLY_PINS = 3000;
const FREE_MONTHLY_PINS = 10;
const PLAN_BY_LOOKUP = Object.freeze({ account_monthly: "monthly", account_yearly: "yearly" });
// Mirrors lib/_balance.js PACKS by id (pins_200, pins_1000), resolved by id
// only, never from the amount: $5 is also the legacy mini pack's price.
const ACCOUNT_PACKS = Object.freeze({
  pins_200: Object.freeze({ price_usd: 5, pins: 200 }),
  pins_1000: Object.freeze({ price_usd: 20, pins: 1000 }),
});
const STATUSES = Object.freeze(["active", "trialing", "past_due", "unpaid", "incomplete",
  "incomplete_expired", "paused", "canceled"]);
// A plan in force: these statuses on plan monthly or yearly.
const PAID_STATUSES = new Set(["active", "trialing"]);
// The subscription is still live at Stripe and may recover: these protect the
// account's subscription id from being replaced by another, and make the
// checkout endpoint refuse a second plan (planHeld).
const HOLD_STATUSES = new Set(["active", "trialing", "past_due"]);
const HOLD_DISPUTE = new Set(["needs_response", "under_review", "warning_needs_response", "warning_under_review"]);
const TERMINAL_DISPUTE = new Set(["won", "lost", "warning_closed"]);
const RELEASE_DISPUTE = new Set(["won", "warning_closed"]);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const REQUEST_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const MAX_DEBIT = 1000000;

// ------------------------------------------------------------------ clock

// Add k calendar months in UTC, clamping the day to the target month's last
// day (Jan 31 + 1 month = Feb 28/29), the same as Postgres timestamptz +
// make_interval(months => k) with the session time zone at UTC.
function addMonthsUTC(ms, k) {
  const d = new Date(ms);
  const m = d.getUTCMonth() + k;
  const ty = d.getUTCFullYear() + Math.floor(m / 12);
  const tm = ((m % 12) + 12) % 12;
  const dim = new Date(Date.UTC(ty, tm + 1, 0)).getUTCDate();
  return Date.UTC(ty, tm, Math.min(d.getUTCDate(), dim),
    d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds(), d.getUTCMilliseconds());
}

// The largest k >= 0 with addMonthsUTC(anchor, k) <= now.
function monthsSince(anchor, now) {
  const a = new Date(anchor);
  const n = new Date(now);
  let k = (n.getUTCFullYear() - a.getUTCFullYear()) * 12 + n.getUTCMonth() - a.getUTCMonth();
  if (addMonthsUTC(anchor, k) > now) k -= 1;
  return Math.max(0, k);
}

function utcMonthStart(ms) {
  const d = new Date(ms);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
}

const iso = (ms) => (ms === null || ms === undefined ? null : new Date(ms).toISOString());
const msOf = (s) => (s === null || s === undefined ? null : Date.parse(s));

// ------------------------------------------------------------ the window

function paidInForce(a) {
  return (a.plan === "monthly" || a.plan === "yearly") && PAID_STATUSES.has(a.status) &&
    a.period_start !== null && a.period_end !== null;
}

// past_due keeps the window it is in, while that window lasts. Only a window
// that began before the unpaid period (window_start < period_start) counts: a
// window our clock opened provisionally at period_end, before the renewal
// failed, belongs to the unpaid period and is not kept.
function pastDueKeeps(a, now) {
  return a.status === "past_due" && (a.plan === "monthly" || a.plan === "yearly") &&
    a.window_start !== null && a.window_end !== null && now < a.window_end &&
    (a.period_start === null || a.window_start < a.period_start);
}

// A plan held back by its own payments: an open or lost dispute on a plan
// invoice's charge (plan_hold), or a full refund of the current period's
// invoice (plan_void_until = that period's end).
function planHeldBack(a, now) {
  return a.plan_hold === true || (a.plan_void_until !== null && a.plan_void_until !== undefined && now < a.plan_void_until);
}

// The monthly window that `now` falls in, and its allowance.
//   Paid plan in force, inside the billing period: the monthly plan's window
//   is exactly [period_start, period_end); the yearly plan's are the fixed
//   anchor + k months, clipped to the period. If our clock passes
//   period_end before Stripe's renewal arrives, a provisional month opens at
//   period_end and runs to the next anchor month (a late webhook must not
//   leave someone on last month's count), UNLESS a cancel is scheduled: then
//   no new month is granted. The anchor is a.cycle_anchor (fixed per
//   subscription), else period_start.
//   past_due: the window it is in, unchanged, until that window ends (no new
//   month while past_due); then the no-plan 10.
//   A plan held back (planHeldBack) keeps its window with an allowance of 0.
//   Otherwise: the no-plan 10, on the UTC calendar month.
function windowAt(a, now) {
  if (pastDueKeeps(a, now)) {
    return { start: a.window_start, end: a.window_end, allowance: planHeldBack(a, now) ? 0 : a.monthly_allowance };
  }
  if (paidInForce(a)) {
    const ps = a.period_start;
    const pe = a.period_end;
    const anchor = a.cycle_anchor === null || a.cycle_anchor === undefined ? ps : a.cycle_anchor;
    const allowance = planHeldBack(a, now) ? 0 : PAID_MONTHLY_PINS;
    if (now >= pe && a.cancel_at_period_end) {
      return { start: a.window_start === null ? ps : a.window_start, end: pe, allowance: 0 };
    }
    if (now < pe) {
      if (a.plan === "monthly") return { start: ps, end: pe, allowance };
      const t = Math.max(now, ps);
      if (anchor > t) return { start: ps, end: Math.min(addMonthsUTC(ps, 1), pe), allowance };
      const k = monthsSince(anchor, t);
      return {
        start: Math.max(addMonthsUTC(anchor, k), ps),
        end: Math.min(addMonthsUTC(anchor, k + 1), pe),
        allowance,
      };
    }
    // Provisional: past period_end, no renewal seen yet.
    const k = monthsSince(anchor, now);
    return { start: Math.max(addMonthsUTC(anchor, k), pe), end: addMonthsUTC(anchor, k + 1), allowance };
  }
  const start = utcMonthStart(now);
  return { start, end: addMonthsUTC(start, 1), allowance: FREE_MONTHLY_PINS };
}

// state: { account, packs: [..], ledger: Map(key -> row) }. Mutates in place.
function ledgerPut(st, key, row) {
  if (st.ledger.has(key)) return false;
  st.ledger.set(key, { idempotency_key: key, monthly_delta: 0, pack_delta: 0, shortfall: 0, pack_parts: null, ...row });
  return true;
}

function rollState(st, now) {
  const a = st.account;
  const w = windowAt(a, now);
  if (a.window_start === null || w.start > a.window_start) {
    a.window_start = w.start;
    a.window_end = w.end;
    a.monthly_used = 0;
    a.monthly_allowance = w.allowance;
    ledgerPut(st, "reset:" + iso(w.start), { entry: "monthly_reset", monthly_delta: w.allowance, at: now });
  } else {
    a.window_end = w.end;
    a.monthly_allowance = w.allowance;
  }
}

function recomputePackBalance(st) {
  st.account.pack_balance = st.packs
    .filter((p) => p.state === "live")
    .reduce((s, p) => s + p.units_remaining, 0);
}

function statusView(st) {
  const a = st.account;
  return {
    plan: a.plan,
    status: a.status,
    monthly_used: a.monthly_used,
    monthly_allowance: a.monthly_allowance,
    monthly_left: Math.max(0, a.monthly_allowance - a.monthly_used),
    window_start: iso(a.window_start),
    window_end: iso(a.window_end),
    pack_balance: a.pack_balance,
    period_end: iso(a.period_end),
    cancel_at_period_end: a.cancel_at_period_end,
  };
}

// ----------------------------------------------------------------- debit

// Atomic: the monthly allowance first, then live packs oldest first; all or
// nothing (never negative); idempotent by request id. A refusal writes
// nothing, so the same request id can succeed later (after a pack is bought).
function debitState(st, { request_id, n, now }) {
  const a = st.account;
  const out = (ok, reason, extra) => ({
    ok, reason, replay: false, from_monthly: 0, from_packs: 0,
    monthly_used: a.monthly_used, monthly_allowance: a.monthly_allowance,
    pack_balance: a.pack_balance, window_end: iso(a.window_end), ...(extra || {}),
  });
  if (!Number.isInteger(n) || n < 1 || n > MAX_DEBIT) return out(false, "bad_count");
  if (typeof request_id !== "string" || !REQUEST_ID.test(request_id)) return out(false, "bad_request_id");
  const key = "debit:" + request_id;
  const prior = st.ledger.get(key);
  if (prior) {
    const fm = -prior.monthly_delta;
    const fp = -prior.pack_delta;
    if (fm + fp !== n) return out(false, "idempotency_key_mismatch");
    return out(true, null, { replay: true, from_monthly: fm, from_packs: fp });
  }
  rollState(st, now);
  const monthlyLeft = Math.max(0, a.monthly_allowance - a.monthly_used);
  const live = st.packs.filter((p) => p.state === "live" && p.units_remaining > 0).sort((x, y) => x.seq - y.seq);
  const packTotal = live.reduce((s, p) => s + p.units_remaining, 0);
  if (monthlyLeft + packTotal < n) {
    const held = st.packs.some((p) => p.state === "held" && p.units_remaining > 0);
    return out(false, held ? "pack_held" : "no_pins_left");
  }
  const fromMonthly = Math.min(n, monthlyLeft);
  let rest = n - fromMonthly;
  const parts = [];
  for (const p of live) {
    if (rest === 0) break;
    const take = Math.min(rest, p.units_remaining);
    p.units_remaining -= take;
    rest -= take;
    parts.push({ pack: p.purchase_ref, n: take });
  }
  a.monthly_used += fromMonthly;
  recomputePackBalance(st);
  ledgerPut(st, key, {
    entry: "debit", monthly_delta: -fromMonthly, pack_delta: -(n - fromMonthly),
    pack_parts: parts.length ? parts : null, at: now,
  });
  return out(true, null, { from_monthly: fromMonthly, from_packs: n - fromMonthly });
}

// ---------------------------------------------------------- apply a fact

// Applies one fact to one account's state (already resolved and locked).
// Returns the outcome name. The caller records the event id.
function applyFactToState(st, fact, now, ctx = {}) {
  const a = st.account;
  switch (fact.kind) {
    case "link": {
      // A checkout whose signed ref verified. It confirms a session on the
      // account's OWN customer (the one the server put there before the
      // session was made); it never sets or moves the customer. A session
      // on any other customer, a Payment Link paid with a leaked ref, or an
      // account with no customer yet: refused, nothing written.
      const r = checkCustomer(a, fact.customer_id);
      if (r) return r;
      if (fact.subscription_id && !a.stripe_subscription_id) a.stripe_subscription_id = fact.subscription_id;
      rollState(st, now);
      return "linked";
    }
    case "subscription":
      return applySubscription(st, fact, now, ctx);
    case "pack_credit": {
      // The customer lock (round 2): a pack counts only on the account's own
      // stored customer, the one our checkout put on the session.
      const mismatch = checkCustomer(a, fact.customer_id);
      if (mismatch) return mismatch;
      if (st.packs.some((p) => p.purchase_ref === fact.purchase_ref)) return "already_credited";
      const cat = Object.prototype.hasOwnProperty.call(ACCOUNT_PACKS, fact.pack_id) ? ACCOUNT_PACKS[fact.pack_id] : null;
      if (!cat) return "ignored_unknown_pack";
      const units = cat.pins; // from the catalogue, never from the fact
      const seq = (ctx.nextSeq ? ctx.nextSeq() : st.packs.length + 1);
      st.packs.push({
        purchase_ref: fact.purchase_ref, pack_id: fact.pack_id, units_total: units,
        units_remaining: units, units_refunded: 0, state: "live",
        payment_intent: fact.payment_intent || null, amount_paid_cents: fact.amount_paid_cents,
        dispute_status: null, dispute_event_at: null, created_at: now, seq,
      });
      recomputePackBalance(st);
      ledgerPut(st, "pack:" + fact.purchase_ref, { entry: "pack_credit", pack_delta: units, at: now });
      return "pack_credited";
    }
    case "pack_refund": {
      const p = fact.payment_intent ? st.packs.find((x) => x.payment_intent === fact.payment_intent) : null;
      if (!p) return applyPlanRefund(st, fact, now);
      if (!Number.isInteger(fact.amount) || fact.amount <= 0 || !Number.isInteger(fact.amount_refunded)) return "ignored_bad_amount";
      // Units the refund pays for, pro rata to the amount paid, rounded up;
      // integer math so JS and Postgres numeric agree exactly.
      const frac = Math.max(0, Math.min(fact.amount_refunded, fact.amount));
      const target = Math.floor((p.units_total * frac + fact.amount - 1) / fact.amount);
      const delta = target - p.units_refunded;
      if (delta <= 0) return "refund_no_change";
      const take = Math.min(delta, p.units_remaining);
      p.units_remaining -= take;
      p.units_refunded = target;
      if (p.units_remaining === 0 && p.state !== "voided") p.state = "refunded";
      recomputePackBalance(st);
      ledgerPut(st, `refund:${fact.payment_intent}:${fact.amount_refunded}`, {
        entry: "pack_refund", pack_delta: -take, shortfall: delta - take, pack_parts: [{ pack: p.purchase_ref, n: take }], at: now,
      });
      return "pack_refunded";
    }
    case "pack_dispute": {
      const p = fact.payment_intent ? st.packs.find((x) => x.payment_intent === fact.payment_intent) : null;
      if (!p) return applyPlanDispute(st, fact, now);
      const at = msOf(fact.at);
      const cur = p.dispute_status;
      const nw = fact.dispute_status;
      if (cur && TERMINAL_DISPUTE.has(cur) && !TERMINAL_DISPUTE.has(nw)) return "ignored_stale";
      if (cur && p.dispute_event_at !== null && at !== null && at < p.dispute_event_at) return "ignored_stale";
      p.dispute_status = nw;
      if (at !== null) p.dispute_event_at = at;
      let entry = null;
      if (HOLD_DISPUTE.has(nw) && p.state === "live") { p.state = "held"; entry = "pack_hold"; }
      else if (RELEASE_DISPUTE.has(nw) && (p.state === "held" || p.state === "voided")) {
        p.state = "live"; entry = "pack_release";
      } else if (nw === "lost" && (p.state === "held" || p.state === "live")) { p.state = "voided"; entry = "pack_void"; }
      recomputePackBalance(st);
      if (!entry) return "dispute_no_change";
      ledgerPut(st, `dispute:${fact.payment_intent}:${nw}:${fact.at}`, {
        entry, shortfall: entry === "pack_void" ? Math.max(0, p.units_total - p.units_remaining - p.units_refunded) : 0,
        pack_parts: [{ pack: p.purchase_ref, n: p.units_remaining }], at: now,
      });
      return entry;
    }
    default:
      return "ignored_kind";
  }
}

// ------------------------------------------- plan invoices: refund, dispute
//
// invoice.paid on the account's own customer records the plan payment
// (invoice id, payment intent, charge, the period it paid for). A refund or
// a dispute on that charge finds it by payment intent, charge or invoice.

function findPlanPayment(st, fact) {
  return (st.planPayments || []).find((x) =>
    (fact.payment_intent && x.payment_intent === fact.payment_intent) ||
    (fact.charge_id && x.charge_id === fact.charge_id) ||
    (fact.invoice_id && x.invoice_id === fact.invoice_id)) || null;
}

function recordPlanPayment(st, f) {
  const pay = f.payment;
  if (!pay || !pay.invoice_id) return;
  st.planPayments = st.planPayments || [];
  if (st.planPayments.some((x) => x.invoice_id === pay.invoice_id)) return;
  st.planPayments.push({
    invoice_id: pay.invoice_id, payment_intent: pay.payment_intent || null, charge_id: pay.charge_id || null,
    amount_paid_cents: Number.isInteger(pay.amount) ? pay.amount : 0, refunded_cents: 0,
    period_start: msOf(f.period_start), period_end: msOf(f.period_end), dispute_status: null, dispute_event_at: null,
  });
}

// A full refund of the CURRENT period's invoice ends that period's
// allowance (until its period_end); a partial one changes nothing but the
// cumulative amount; a refund of a period already over changes nothing.
function applyPlanRefund(st, fact, now) {
  const a = st.account;
  const pp = findPlanPayment(st, fact);
  if (!pp) return "ignored_no_payment";
  if (fact.customer_id && checkCustomer(a, fact.customer_id)) return "ignored_customer_mismatch";
  if (!Number.isInteger(fact.amount) || fact.amount <= 0 || !Number.isInteger(fact.amount_refunded)) return "ignored_bad_amount";
  if (fact.amount_refunded <= pp.refunded_cents) return "refund_no_change";
  pp.refunded_cents = fact.amount_refunded;
  if (fact.amount_refunded < fact.amount) return "plan_refund_partial";
  if (pp.period_end === null || now >= pp.period_end) return "plan_refund_past_period";
  if (a.plan_void_until === null || a.plan_void_until === undefined || pp.period_end > a.plan_void_until) {
    a.plan_void_until = pp.period_end;
  }
  rollState(st, now);
  return "plan_refund_voided";
}

// An open or lost dispute on a plan invoice's charge holds the plan's
// allowance at 0; won or warning_closed releases it. Same staleness rules as
// a pack's dispute.
function applyPlanDispute(st, fact, now) {
  const a = st.account;
  const pp = findPlanPayment(st, fact);
  if (!pp) return "ignored_no_payment";
  const at = msOf(fact.at);
  const cur = pp.dispute_status;
  const nw = fact.dispute_status;
  if (cur && TERMINAL_DISPUTE.has(cur) && !TERMINAL_DISPUTE.has(nw)) return "ignored_stale";
  if (cur && pp.dispute_event_at !== null && at !== null && at < pp.dispute_event_at) return "ignored_stale";
  pp.dispute_status = nw;
  if (at !== null) pp.dispute_event_at = at;
  a.plan_hold = st.planPayments.some((x) => x.dispute_status && (HOLD_DISPUTE.has(x.dispute_status) || x.dispute_status === "lost"));
  rollState(st, now);
  if (HOLD_DISPUTE.has(nw) || nw === "lost") return "plan_hold";
  if (RELEASE_DISPUTE.has(nw)) return "plan_release";
  return "plan_dispute_no_change";
}

// The account's customer holds a plan on it: a subscription on a paid plan
// that is in force (active, trialing) or past_due (live at Stripe, the owner
// may be fixing a card). The checkout endpoint refuses to start a second plan
// while one is held.
function planHeld(a) {
  return !!a.stripe_subscription_id && (a.plan === "monthly" || a.plan === "yearly") && HOLD_STATUSES.has(a.status);
}

// The ONE rule about customers on the webhook side: an event counts for an
// account only when its customer IS the account's stored customer. The
// stored customer is written by exactly one path, the authenticated checkout
// endpoint (store.setStripeCustomer, set once, never moved). No event ever
// sets, changes or "relinks" it. An account with no customer yet, or an
// event with no customer, is a mismatch too: fail closed.
// null when it matches; else the refusal.
function checkCustomer(a, customer) {
  if (!customer || !a.stripe_customer_id || a.stripe_customer_id !== customer) return "ignored_customer_mismatch";
  return null;
}

function applySubscription(st, f, now, _ctx) {
  const a = st.account;
  const at = msOf(f.at);
  const sub = f.subscription_id;
  const ps = msOf(f.period_start);
  const pe = msOf(f.period_end);
  let switching = false;

  const mismatch = checkCustomer(a, f.customer_id);
  if (mismatch) return mismatch;
  // A paid plan invoice is recorded whatever the guards below decide about
  // the period: the money is real, and a refund or dispute must find it.
  recordPlanPayment(st, f);

  if (a.stripe_subscription_id && sub !== a.stripe_subscription_id) {
    const terminal = a.status === "canceled" || a.status === "incomplete_expired" || a.plan === "free";
    const newer = a.sub_event_at === null || (at !== null && at >= a.sub_event_at);
    if (!terminal && !(HOLD_STATUSES.has(f.status) && newer)) return "ignored_other_subscription";
    if (f.requires_paid_plan) return "ignored_no_plan";
    switching = true;
  } else if (a.stripe_subscription_id) {
    if (a.status === "canceled") return "ignored_terminal";
    if (a.sub_event_at !== null && at !== null && at < a.sub_event_at) return "ignored_stale";
    if (f.only_from && !f.only_from.includes(a.status)) return "ignored_status";
    if (f.requires_paid_plan && a.plan === "free") return "ignored_no_plan";
  } else {
    if (f.requires_paid_plan) return "ignored_no_plan";
    if (f.only_from && !f.only_from.includes(a.status)) return "ignored_status";
  }

  // The fixed anchor of the monthly clock: Stripe's billing_cycle_anchor
  // when the event carries it; else, on a new subscription, a plan change or
  // when none is held yet, the period it starts with. Never the renewal's
  // moving period_start.
  const periodAccepted = ps !== null && pe !== null && (switching || a.period_start === null || ps >= a.period_start);
  if (f.anchor) {
    a.cycle_anchor = msOf(f.anchor);
  } else if (periodAccepted && (switching || !a.stripe_subscription_id || a.cycle_anchor === null ||
    a.cycle_anchor === undefined || (f.plan && f.plan !== a.plan))) {
    a.cycle_anchor = ps;
  }
  a.stripe_subscription_id = sub;
  if (periodAccepted) {
    a.period_start = ps;
    a.period_end = pe;
  }
  if (f.plan) a.plan = f.plan;
  if (f.status) a.status = f.status;
  if (typeof f.cancel_at_period_end === "boolean") a.cancel_at_period_end = f.cancel_at_period_end;
  if (a.status === "canceled") { a.plan = "free"; a.cancel_at_period_end = false; }
  if (at !== null && (a.sub_event_at === null || at > a.sub_event_at)) a.sub_event_at = at;
  rollState(st, now);
  return "subscription_applied";
}

// -------------------------------------------------- Stripe event -> fact

const uuidOr = (v) => (typeof v === "string" && UUID.test(v.trim()) ? v.trim().toLowerCase() : null);

// ------------------------------------------------- the signed account ref
//
// client_reference_id is NOT ours to trust: a Payment Link takes it from the
// URL, so anyone can put a victim's account id there. The reference is bound
// server-side, and it runs out. Since the checkout endpoint
// (lib/_account_checkout.js) it is only one of two locks: the event's
// customer must ALSO be the account's own stored customer (checkCustomer),
// so a leaked ref can at most pay for the account it names, never link a
// stranger's customer to it.
//   <account_id> "." <exp_unix> "." hex(HMAC-SHA256(ACCOUNT_REF_SECRET,
//       "arcaeon-checkout-v2\n" + account_id + "\n" + exp_unix))
// minted by mintAccountRef(account_id, now) when we build the checkout link,
// exp = now + 2 hours. It verifies (timing-safe) only when the Stripe
// object's own `created` (the checkout session's, not the clock when the
// webhook lands, so Stripe's retries days later still verify) is <= exp. A
// leaked checkout URL is good for two hours, not for ever. No secret set
// means nothing verifies: fail closed. v1 refs (no expiry) are gone.
const REF_DOMAIN = "arcaeon-checkout-v2\n";
const REF_TTL_S = 2 * 60 * 60;
const REF_SHAPE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.([1-9][0-9]{0,11})\.([0-9a-f]{64})$/;

function refSecret(secret) {
  const s = secret === undefined ? process.env.ACCOUNT_REF_SECRET : secret;
  return typeof s === "string" && s.length >= 16 ? s : null;
}

function refMac(account_id, exp, secret) {
  return crypto.createHmac("sha256", secret).update(REF_DOMAIN + account_id + "\n" + exp, "utf8").digest();
}

// now: ms since the epoch (default the clock).
function mintAccountRef(account_id, now = Date.now(), secret) {
  const id = uuidOr(account_id);
  const key = refSecret(secret);
  if (!id) throw new Error("mintAccountRef: account_id must be a uuid");
  if (!key) throw new Error("mintAccountRef: ACCOUNT_REF_SECRET is not set (16+ characters)");
  if (!Number.isFinite(now)) throw new Error("mintAccountRef: now must be a time in ms");
  const exp = String(Math.floor(now / 1000) + REF_TTL_S);
  return `${id}.${exp}.${refMac(id, exp, key).toString("hex")}`;
}

// {account_id, exp} when the MAC checks (expired or not), else null.
function readAccountRef(ref, secret) {
  const key = refSecret(secret);
  if (!key || typeof ref !== "string") return null;
  const m = REF_SHAPE.exec(ref.trim());
  if (!m) return null;
  const want = refMac(m[1], m[2], key);
  const got = Buffer.from(m[3], "hex");
  if (!(got.length === want.length && crypto.timingSafeEqual(got, want))) return null;
  return { account_id: m[1], exp: Number(m[2]) };
}

// The account id when `ref` is a valid signed reference and `created` (unix
// seconds: the Stripe object's own created) is not after its expiry; else null.
function verifyAccountRef(ref, created, secret) {
  const r = readAccountRef(ref, secret);
  if (!r || created === null || created === undefined || created === "") return null;
  const at = Number(created);
  if (!Number.isFinite(at)) return null;
  return at <= r.exp ? r.account_id : null;
}

// For a checkout session: {account} when a signed reference verifies against
// the session's `created`; {claimed:true, reason} when something of ours is
// there but does not verify ("expired" for a good MAC past its time, else
// "bad"); {} when nothing claims an account. A bare uuid is not our shape.
function checkoutAccount(obj, secret) {
  const meta = obj.metadata || {};
  const candidates = [obj.client_reference_id, meta.account_ref, meta.account_id].filter((v) => typeof v === "string" && v);
  let expired = false;
  for (const c of candidates) {
    if (!readAccountRef(c, secret)) continue;
    const id = verifyAccountRef(c, obj.created, secret);
    if (id) return { account: id };
    expired = true;
  }
  const claimed = expired || !!meta.account_ref || !!meta.account_id || obj.mode === "subscription" ||
    candidates.some((c) => REF_SHAPE.test(c.trim()));
  if (!claimed) return {};
  return { claimed: true, reason: expired ? "expired" : "bad" };
}

const unverified = (reason) => ({ kind: "unverified_reference", reason });
// Stripe id shapes, the same patterns the v2 migration checks.
const ID_SHAPES = Object.freeze({
  cus_: /^cus_[A-Za-z0-9]{1,64}$/,
  sub_: /^sub_[A-Za-z0-9]{1,255}$/,
  pi_: /^pi_[A-Za-z0-9_]{1,255}$/,
  cs_: /^cs_[A-Za-z0-9_]{1,255}$/,
  in_: /^in_[A-Za-z0-9_]{1,255}$/,
  ch_: /^(ch|py)_[A-Za-z0-9_]{1,255}$/,
});
const idOr = (v, prefix) => {
  const s = v && typeof v === "object" ? v.id : v;
  return typeof s === "string" && ID_SHAPES[prefix].test(s) ? s : null;
};
const secIso = (v) => (Number.isFinite(Number(v)) && v !== null && v !== "" ? new Date(Number(v) * 1000).toISOString() : null);
const ignore = (reason) => ({ kind: "ignore", reason });

const PAID_ONLY_FROM = Object.freeze(["active", "trialing", "past_due", "unpaid", "incomplete"]);
const ACCOUNT_TYPES = new Set([
  "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted",
  "customer.subscription.paused", "customer.subscription.resumed",
  "invoice.paid", "invoice.payment_failed", "charge.refunded",
  "charge.dispute.created", "charge.dispute.updated", "charge.dispute.closed",
  "charge.dispute.funds_withdrawn", "charge.dispute.funds_reinstated",
]);

// pins_200 and pins_1000 are the SAME Stripe prices on two paths: the
// per-key Payment Links (credited to a key by api/fulfill.js and the legacy
// webhook path) and the account's server-made Checkout Session (credited to
// the account here). A session made from a Payment Link carries Stripe's own
// payment_link id, which the buyer cannot set or clear; the server's sessions
// (lib/_account_checkout.js) never carry one. So a one-time (mode payment)
// Payment Link session is a bare-key purchase whatever its
// client_reference_id says: a signed account ref pasted into a Payment Link
// URL must not credit the account (the key is credited by /api/fulfill, which
// the link redirects to). Subscription-mode sessions keep the account branch
// (the customer rule refuses a Payment Link there and records it).
function paymentLinkOf(s) {
  const v = s && s.payment_link;
  const id = v && typeof v === "object" ? v.id : v;
  return typeof id === "string" && id !== "" ? id : null;
}

// True when a checkout session belongs to the account path: mode
// subscription, metadata.account_id / account_ref, or a signed-ref-shaped
// client_reference_id, and not a one-time Payment Link session. The webhook
// routes on it; api/fulfill.js refuses these (it must never mint a key or
// credit one for an account purchase).
function isAccountCheckoutSession(s) {
  if (!s || typeof s !== "object") return false;
  if (s.mode !== "subscription" && paymentLinkOf(s)) return false;
  const meta = s.metadata || {};
  const ref = typeof s.client_reference_id === "string" ? s.client_reference_id.trim() : "";
  // Only the signed shape counts; a bare uuid is someone else's.
  return s.mode === "subscription" || !!meta.account_id || !!meta.account_ref || REF_SHAPE.test(ref);
}

// Which events take the account branch of the webhook. Checkout sessions do
// only when they say so (isAccountCheckoutSession); every other checkout
// session stays on the legacy pack path untouched.
function isAccountEvent(event) {
  if (!event || typeof event.type !== "string") return false;
  if (ACCOUNT_TYPES.has(event.type)) return true;
  if (event.type === "checkout.session.completed" || event.type === "checkout.session.async_payment_succeeded") {
    return isAccountCheckoutSession((event.data && event.data.object) || {});
  }
  return false;
}

function factFromEvent(event, { secret } = {}) {
  const type = event && event.type;
  const obj = (event && event.data && event.data.object) || {};
  const at = secIso(event && event.created);
  const meta = obj.metadata || {};

  if (type === "checkout.session.completed" || type === "checkout.session.async_payment_succeeded") {
    if (obj.mode !== "subscription" && paymentLinkOf(obj)) return ignore("payment link session: a bare-key purchase, never an account's");
    const who = checkoutAccount(obj, secret);
    if (!who.account && !who.claimed) return ignore("not an account checkout");
    // The positive server mark (round 2): our checkout puts the account id in
    // metadata.account_id on every session it makes, beside the signed ref.
    const mark = uuidOr(meta.account_id);
    const customer_id = idOr(obj.customer, "cus_");
    const inner = (hint) => {
      if (obj.mode === "subscription") {
        return {
          kind: "link", account_hint: hint, customer_id,
          subscription_id: idOr(obj.subscription, "sub_"), at, retry_if_unresolved: true,
        };
      }
      const packId = String(meta.pack || "").trim().toLowerCase();
      const pack = Object.prototype.hasOwnProperty.call(ACCOUNT_PACKS, packId) ? ACCOUNT_PACKS[packId] : null;
      if (!pack) return ignore(`unknown account pack (${packId})`);
      if (obj.payment_status !== "paid") return ignore(`session not paid (payment_status=${obj.payment_status})`);
      const paid = Number(obj.amount_total);
      const currency = obj.currency ? String(obj.currency).toLowerCase() : null;
      if (!Number.isFinite(paid) || paid < pack.price_usd * 100 || currency !== "usd") {
        return ignore(`payment does not match pack ${packId}`);
      }
      const ref = idOr(obj.id, "cs_");
      if (!ref) return ignore("checkout session id missing");
      return {
        kind: "pack_credit", account_hint: hint, customer_id, purchase_ref: ref, pack_id: packId,
        units: pack.pins, payment_intent: idOr(obj.payment_intent, "pi_"), amount_paid_cents: paid,
        at, retry_if_unresolved: true,
      };
    };
    if (who.account) {
      // A ref that verifies but no mark naming the same account: not a
      // session our checkout made. Recorded as a final refusal.
      if (mark !== who.account) return { kind: "no_server_mark", reason: "verified reference without our metadata.account_id for it" };
      return inner(who.account);
    }
    // The ref did not verify (bad mac, expired, the secret rotated or unset).
    // applyAccountEvent credits it only when the mark names an account AND
    // the session's customer is that account's own; otherwise 503, never
    // recorded, logged (round 2).
    const f = inner(mark);
    if (f.kind === "ignore") return f;
    return {
      ...unverified(who.reason === "expired"
        ? "expired: the signed account reference ran out before this session was created"
        : "checkout reference is not a valid signed account reference"),
      account_hint: mark, customer_id, fact: f, retry_if_unresolved: true,
    };
  }

  if (typeof type === "string" && type.startsWith("customer.subscription.")) {
    if (!ACCOUNT_TYPES.has(type)) return ignore(`unhandled ${type}`);
    const item = obj.items && Array.isArray(obj.items.data) ? obj.items.data[0] : null;
    const plan = item && item.price ? PLAN_BY_LOOKUP[item.price.lookup_key] : undefined;
    if (!plan) return ignore("not an account price");
    const sub = idOr(obj.id, "sub_");
    if (!sub) return ignore("subscription id missing");
    const status = type === "customer.subscription.deleted" ? "canceled" : obj.status;
    if (!STATUSES.includes(status)) return ignore(`unknown status ${status}`);
    let ps = secIso(item.current_period_start !== undefined ? item.current_period_start : obj.current_period_start);
    let pe = secIso(item.current_period_end !== undefined ? item.current_period_end : obj.current_period_end);
    const cancelAt = secIso(obj.cancel_at);
    if (cancelAt && pe && Date.parse(cancelAt) < Date.parse(pe)) pe = cancelAt;
    if (!ps || !pe) { ps = null; pe = null; }
    const anchor = secIso(obj.billing_cycle_anchor);
    return {
      kind: "subscription", account_hint: verifyAccountRef(meta.account_ref, obj.created, secret), customer_id: idOr(obj.customer, "cus_"),
      subscription_id: sub, plan, status, period_start: ps, period_end: pe,
      cancel_at_period_end: !!obj.cancel_at_period_end || !!cancelAt, at, retry_if_unresolved: true,
      ...(anchor ? { anchor } : {}),
    };
  }

  if (type === "invoice.paid" || type === "invoice.payment_failed") {
    const details = (obj.parent && obj.parent.subscription_details) || obj.subscription_details || {};
    const sub = idOr(obj.subscription || details.subscription, "sub_");
    const lines = obj.lines && Array.isArray(obj.lines.data) ? obj.lines.data : [];
    const line = lines.find((l) => l && l.price && PLAN_BY_LOOKUP[l.price.lookup_key]);
    if (!sub || !line) return ignore("not an account subscription invoice");
    const ps = line.period ? secIso(line.period.start) : null;
    const pe = line.period ? secIso(line.period.end) : null;
    const base = {
      kind: "subscription", account_hint: verifyAccountRef((details.metadata || {}).account_ref, obj.created, secret),
      customer_id: idOr(obj.customer, "cus_"), subscription_id: sub,
      period_start: ps && pe ? ps : null, period_end: ps && pe ? pe : null, at, retry_if_unresolved: true,
    };
    if (type === "invoice.paid") {
      // The payment, so a refund or dispute on its charge can find the plan.
      // payment_intent / charge: the classic invoice fields; newer API
      // versions list them under invoice.payments.
      const payRow = obj.payments && Array.isArray(obj.payments.data) && obj.payments.data[0] && obj.payments.data[0].payment;
      const payment = {
        invoice_id: idOr(obj.id, "in_"),
        payment_intent: idOr(obj.payment_intent || (payRow && payRow.payment_intent), "pi_"),
        charge_id: idOr(obj.charge || (payRow && payRow.charge), "ch_"),
        amount: Number.isInteger(Number(obj.amount_paid)) ? Number(obj.amount_paid) : null,
      };
      return { ...base, plan: PLAN_BY_LOOKUP[line.price.lookup_key], status: "active", only_from: PAID_ONLY_FROM,
        ...(payment.invoice_id ? { payment } : {}) };
    }
    // A failed payment: past_due keeps the window it is in, no new month;
    // never starts a plan.
    return { ...base, plan: null, status: "past_due", only_from: ["active", "trialing"], requires_paid_plan: true };
  }

  // A refund or dispute names a pack's payment intent, or a plan invoice's
  // charge (invoice and customer on the charge; the store finds the plan
  // payment by payment intent, charge or invoice, or the account by the
  // charge's customer when the charge has an invoice).
  if (type === "charge.refunded") {
    const pi = idOr(obj.payment_intent, "pi_");
    const invoice_id = idOr(obj.invoice, "in_");
    if (!pi && !invoice_id) return ignore("refund without a payment intent or an invoice");
    const amount = Number(obj.amount);
    const refunded = Number(obj.amount_refunded);
    if (!Number.isInteger(amount) || amount <= 0 || !Number.isInteger(refunded) || refunded < 0) return ignore("refund amounts missing");
    return {
      kind: "pack_refund", payment_intent: pi, charge_id: idOr(obj.id, "ch_"), invoice_id, customer_id: idOr(obj.customer, "cus_"),
      amount, amount_refunded: refunded, at,
    };
  }

  if (typeof type === "string" && type.startsWith("charge.dispute.")) {
    const pi = idOr(obj.payment_intent, "pi_");
    const charge_id = idOr(obj.charge, "ch_");
    if (!pi && !charge_id) return ignore("dispute without a payment intent or a charge");
    if (!HOLD_DISPUTE.has(obj.status) && !TERMINAL_DISPUTE.has(obj.status)) return ignore(`dispute status ${obj.status}`);
    return { kind: "pack_dispute", payment_intent: pi, charge_id, dispute_status: obj.status, at };
  }

  return ignore(`unhandled ${type}`);
}

// ------------------------------------------------------------ the webhook

const deps = {
  getStore: () => require("./_accountdb.js").fromEnv(),
  now: () => Date.now(),
};

// The one entry from a fact to a store (the webhook's, and the tests').
// An unverified reference is decided here, before the store records
// anything: credited only when the server mark names an account and the
// session's customer is that account's own stored customer (the customer is
// written once and never moves, so this read cannot go stale); otherwise
// {outcome: "unverified_unresolved"}: nothing recorded, the webhook answers
// 503 so Stripe retries, and the operator gets a line (round 2, item 3).
async function applyAccountEvent(store, { event_id, type, fact, now }) {
  if (fact && fact.kind === "unverified_reference") {
    const acct = fact.account_hint ? await store.getAccount(fact.account_hint) : null;
    if (!acct || !fact.customer_id || acct.stripe_customer_id !== fact.customer_id) {
      console.error(`[account] ${type} ${event_id}: the checkout reference did not verify (${fact.reason}) and the session's ` +
        "customer is not the marked account's own; nothing credited or recorded, answered for retry");
      return { outcome: "unverified_unresolved", account_id: null };
    }
    console.error(`[account] ${type} ${event_id}: the checkout reference did not verify (${fact.reason}); ` +
      `credited on the server mark and the account's own customer (account ${fact.account_hint})`);
    return store.applyStripeEvent({ event_id, type, fact: fact.fact, now });
  }
  return store.applyStripeEvent({ event_id, type, fact, now });
}

// Called by api/stripe-webhook.js AFTER its signature and livemode checks.
// Answers: 200 for applied, duplicate and ignored (Stripe must not retry
// those); 503 when the store is not configured or an account event names an
// account not linked yet (Stripe retries, so a subscription event that beat
// its checkout.session.completed lands on the retry); 500 on a store error.
async function handleAccountEvent(event, res) {
  const fact = factFromEvent(event);
  // Refunds and disputes are logged whatever they turn out to be (round 2):
  // money moved back, a person should be able to find it.
  const isCharge = typeof event.type === "string" && event.type.startsWith("charge.");
  const reply = (status, body) => {
    if (isCharge) {
      console.error(`[account] ${event.type} ${event.id}: ${status} ${body.outcome || body.reason || body.skipped || ""}`);
    }
    return res.status(status).json({ event_id: event.id, ...body });
  };
  if (fact.kind === "ignore") return reply(200, { ok: true, skipped: fact.reason });
  if (typeof event.id !== "string" || !/^evt_[A-Za-z0-9]{1,255}$/.test(event.id)) {
    return reply(200, { ok: true, skipped: "event id is not a Stripe event id" });
  }
  const store = deps.getStore();
  if (!store) {
    if (fact.retry_if_unresolved) {
      return reply(503, { ok: false, reason: "account_store_not_configured" });
    }
    return reply(200, { ok: true, skipped: "account store not configured" });
  }
  let r;
  try {
    r = await applyAccountEvent(store, { event_id: event.id, type: event.type, fact, now: deps.now() });
  } catch (err) {
    return reply(500, { ok: false, reason: "account_store_error", error: err && err.storeError ? err.message : "account store failed" });
  }
  if (r.outcome === "unverified_unresolved") return reply(503, { ok: false, reason: "unverified_reference" });
  if (r.outcome === "unresolved") {
    if (fact.retry_if_unresolved) return reply(503, { ok: false, reason: "account_not_linked_yet" });
    return reply(200, { ok: true, skipped: "no account for this object" });
  }
  return reply(200, { ok: true, outcome: r.outcome, duplicate: r.outcome === "duplicate" });
}

module.exports = {
  PAID_MONTHLY_PINS,
  FREE_MONTHLY_PINS,
  PLAN_BY_LOOKUP,
  ACCOUNT_PACKS,
  STATUSES,
  addMonthsUTC,
  monthsSince,
  windowAt,
  rollState,
  debitState,
  applyFactToState,
  planHeld,
  checkCustomer,
  statusView,
  factFromEvent,
  isAccountEvent,
  isAccountCheckoutSession,
  mintAccountRef,
  readAccountRef,
  verifyAccountRef,
  REF_TTL_S,
  handleAccountEvent,
  applyAccountEvent,
  planHeldBack,
  deps,
  iso,
  REQUEST_ID,
};
