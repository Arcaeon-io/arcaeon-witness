// test/helpers/account_events.js — Stripe-shaped event fixtures for the
// account billing tests. Not a test file. Shapes follow Stripe's event
// objects closely enough for lib/_account_billing.js factFromEvent(); ids
// are made up (no Stripe account was called to make them).

"use strict";

// Tests sign checkout references with a fixed test secret (never a real one).
if (!process.env.ACCOUNT_REF_SECRET) process.env.ACCOUNT_REF_SECRET = "test-account-ref-secret-0123456789";
const { mintAccountRef } = require("../../lib/_account_billing.js");
const signed = (account) => (account ? mintAccountRef(account) : undefined);

const sec = (ms) => Math.floor(ms / 1000);
const DAY = 24 * 60 * 60 * 1000;

let n = 0;
const nextId = (p) => `${p}${Date.now().toString(36)}${(++n).toString(36)}`.replace(/[^A-Za-z0-9_]/g, "");

function subEvent({ id, type = "customer.subscription.updated", sub, cus, status = "active", lookup = "account_monthly",
  ps, pe, cape = false, cancelAt = null, created, account = null }) {
  return {
    id: id || nextId("evt_"),
    type,
    created: sec(created),
    livemode: true,
    data: {
      object: {
        id: sub, object: "subscription", customer: cus, status, cancel_at_period_end: cape,
        cancel_at: cancelAt === null ? null : sec(cancelAt),
        metadata: account ? { account_ref: signed(account) } : {},
        items: { data: [{ price: { lookup_key: lookup }, current_period_start: sec(ps), current_period_end: sec(pe) }] },
      },
    },
  };
}

function invoiceEvent({ id, type = "invoice.paid", sub, cus, lookup = "account_monthly", ps, pe, created, account = null }) {
  return {
    id: id || nextId("evt_"),
    type,
    created: sec(created),
    livemode: true,
    data: {
      object: {
        id: nextId("in_"), object: "invoice", customer: cus,
        parent: { subscription_details: { subscription: sub, metadata: account ? { account_ref: signed(account) } : {} } },
        lines: { data: [{ price: { lookup_key: lookup }, period: { start: sec(ps), end: sec(pe) } }] },
      },
    },
  };
}

function checkoutSubEvent({ id, account, cus, sub, created, ref }) {
  const r = ref === undefined ? signed(account) : ref;
  return {
    id: id || nextId("evt_"),
    type: "checkout.session.completed",
    created: sec(created),
    livemode: true,
    data: { object: { id: nextId("cs_test_"), mode: "subscription", customer: cus, subscription: sub,
      client_reference_id: r, metadata: {}, payment_status: "paid" } },
  };
}

const PACK_CENTS = { pins_200: 500, pins_1000: 2000 };
function checkoutPackEvent({ id, type = "checkout.session.completed", account, session, pack = "pins_1000", pi,
  amount, currency = "usd", paymentStatus = "paid", created, ref }) {
  const r = ref === undefined ? signed(account) : ref;
  return {
    id: id || nextId("evt_"),
    type,
    created: sec(created),
    livemode: true,
    data: { object: { id: session, mode: "payment", payment_status: paymentStatus, payment_intent: pi,
      amount_total: amount === undefined ? PACK_CENTS[pack] : amount, currency, client_reference_id: r, metadata: { pack } } },
  };
}

function refundEvent({ id, pi, amount, refunded, created }) {
  return {
    id: id || nextId("evt_"),
    type: "charge.refunded",
    created: sec(created),
    livemode: true,
    data: { object: { id: nextId("ch_"), object: "charge", payment_intent: pi, amount, amount_refunded: refunded } },
  };
}

function disputeEvent({ id, type = "charge.dispute.created", pi, status = "needs_response", created }) {
  return {
    id: id || nextId("evt_"),
    type,
    created: sec(created),
    livemode: true,
    data: { object: { id: nextId("dp_"), object: "dispute", charge: nextId("ch_"), payment_intent: pi, status } },
  };
}

module.exports = { sec, DAY, nextId, subEvent, invoiceEvent, checkoutSubEvent, checkoutPackEvent, refundEvent, disputeEvent, PACK_CENTS };
