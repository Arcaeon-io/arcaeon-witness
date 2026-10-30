// test/helpers/stripe_api_mock.js — a stand-in for the three Stripe API calls
// the account checkout makes (lib/_account_checkout.js): POST /v1/customers,
// GET /v1/prices?lookup_keys[]=..., POST /v1/checkout/sessions. Same idea as
// the MockStripe in test/fulfill.test.js (one fetch-shaped handler, a bearer
// check, recorded calls), never the network. Not a test file.
//
// Honours Idempotency-Key the way Stripe does: the same key on the same path
// returns the first result again, so two creates with one key are one
// customer. `paidEvent(session, ...)` builds the checkout.session.completed
// Stripe would send after SOMEONE paid that session: the session's customer
// is the one WE put on it, whoever held the card.

"use strict";

const ev = require("./account_events.js");

function fakeResponse(status, body) {
  const text = JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => text,
    json: async () => JSON.parse(text),
  };
}

class MockStripeApi {
  // prices: lookup_key -> price id (unset keys answer an empty list, as Stripe does).
  constructor({ secret, prices = {}, now = () => Date.now() } = {}) {
    this.secret = secret;
    this.prices = { ...prices };
    this.now = now;
    this.calls = [];
    this.customers = new Map();
    this.sessions = new Map();
    this.idem = new Map();
    this.fail = null; // (path, method) => {status, body} | null
    this.seq = 0;
  }

  // The fetch stand-in: pass as fetchImpl.
  handle = async (url, opts = {}) => {
    const u = new URL(String(url));
    const method = (opts.method || "GET").toUpperCase();
    const headers = Object.fromEntries(Object.entries(opts.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
    const form = new URLSearchParams(typeof opts.body === "string" ? opts.body : "");
    const call = { method, path: u.pathname, search: u.searchParams, form, headers, idempotencyKey: headers["idempotency-key"] || null };
    this.calls.push(call);
    if (u.hostname !== "api.stripe.com") return fakeResponse(404, { error: { message: "mock: not stripe" } });
    if (headers.authorization !== `Bearer ${this.secret}`) {
      return fakeResponse(401, { error: { type: "invalid_request_error", message: "Invalid API Key provided" } });
    }
    if (this.fail) {
      const f = this.fail(u.pathname, method);
      if (f) return fakeResponse(f.status, f.body);
    }
    const idemKey = call.idempotencyKey ? `${method} ${u.pathname} ${call.idempotencyKey}` : null;
    if (idemKey && this.idem.has(idemKey)) return fakeResponse(200, this.idem.get(idemKey));

    let out;
    if (method === "POST" && u.pathname === "/v1/customers") {
      const id = `cus_mock${++this.seq}`;
      out = { id, object: "customer", created: Math.floor(this.now() / 1000), metadata: metaOf(form) };
      this.customers.set(id, out);
    } else if (method === "GET" && u.pathname === "/v1/prices") {
      const keys = u.searchParams.getAll("lookup_keys[]");
      const data = keys.filter((k) => this.prices[k]).map((k) => ({ id: this.prices[k], object: "price", lookup_key: k, active: true }));
      out = { object: "list", data };
    } else if (method === "POST" && u.pathname === "/v1/checkout/sessions") {
      const customer = form.get("customer");
      if (!customer || !this.customers.has(customer)) {
        return fakeResponse(400, { error: { type: "invalid_request_error", param: "customer", message: "No such customer" } });
      }
      const price = form.get("line_items[0][price]");
      if (!price || !Object.values(this.prices).includes(price)) {
        return fakeResponse(400, { error: { type: "invalid_request_error", param: "line_items[0][price]", message: "No such price" } });
      }
      const created = Math.floor(this.now() / 1000);
      const id = `cs_test_mock${++this.seq}`;
      out = {
        id, object: "checkout.session", created, mode: form.get("mode"), customer,
        client_reference_id: form.get("client_reference_id"), metadata: metaOf(form),
        subscription_data: form.has("subscription_data[metadata][account_ref]")
          ? { metadata: { account_ref: form.get("subscription_data[metadata][account_ref]") } } : undefined,
        expires_at: Number(form.get("expires_at")) || created + 24 * 3600,
        url: `https://checkout.stripe.com/c/pay/${id}`, status: "open", payment_status: "unpaid", subscription: null,
        amount_total: null, currency: "usd", line_items: undefined, price,
      };
      this.sessions.set(id, out);
    } else {
      return fakeResponse(404, { error: { message: "mock: unknown stripe path" } });
    }
    if (idemKey) this.idem.set(idemKey, out);
    return fakeResponse(200, out);
  };

  countOf(method, path) {
    return this.calls.filter((c) => c.method === method && c.path === path).length;
  }

  // checkout.session.completed as Stripe would send it once this session was
  // paid. `sub` is the subscription Stripe made (subscription mode); the
  // customer is the session's, whoever paid. `at` is the event time (ms).
  paidEvent(session, { sub = null, at, pi = null, amount = null } = {}) {
    const created = ev.sec(at === undefined ? session.created * 1000 : at);
    return {
      id: ev.nextId("evt_"),
      type: "checkout.session.completed",
      created,
      livemode: true,
      data: {
        object: {
          ...session, status: "complete", payment_status: "paid", subscription: sub, payment_intent: pi,
          amount_total: amount, currency: "usd",
        },
      },
    };
  }
}

function metaOf(form) {
  const meta = {};
  for (const [k, v] of form) {
    const m = /^metadata\[([a-z_]+)\]$/.exec(k);
    if (m) meta[m[1]] = v;
  }
  return meta;
}

module.exports = { MockStripeApi, fakeResponse };
