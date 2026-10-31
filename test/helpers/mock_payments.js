// test/helpers/mock_payments.js — stand ins for the two outside parties of
// lib/_agent_pay.js: the stablecoin processor's verification API (x402
// adapter) and a self hosted Lightning node's REST interface (l402 adapter).
// No network, no keys. A fixture, not a test file.

"use strict";

const crypto = require("crypto");

const PROCESSOR_URL = "https://processor.test.invalid";
const NODE_URL = "https://node.test.invalid";

function res(status, body) {
  const text = body === undefined ? "" : JSON.stringify(body);
  return { status, ok: status >= 200 && status < 300, json: async () => body, text: async () => text, headers: { get: () => null } };
}

class MockProcessor {
  constructor() {
    this.payments = new Map(); // payment_id -> {settled, nonce, amount, asset, network, pay_to}
    this.calls = [];
    this.down = false;
  }
  // The agent pays a quote: the processor now knows a payment for its terms.
  pay(quote, over = {}) {
    const id = "pay_" + crypto.randomBytes(6).toString("hex");
    this.payments.set(id, { settled: true, nonce: quote.nonce, amount: quote.amount, asset: quote.asset,
      network: quote.network, pay_to: quote.pay_to, ...over });
    return id;
  }
  async handleFetch(url, opts = {}) {
    this.calls.push({ url: String(url), headers: opts.headers, body: opts.body });
    if (this.down) return res(503, { error: "down" });
    const u = new URL(String(url));
    if (u.pathname !== "/v1/verify" || opts.method !== "POST") return res(404, { error: "no route" });
    const b = JSON.parse(opts.body);
    const p = this.payments.get(b.payment_id);
    if (!p) return res(404, { error: "unknown payment" });
    return res(200, { payment_id: b.payment_id, ...p });
  }
}

class MockNode {
  constructor() {
    this.invoices = new Map(); // hash hex -> {preimage, value, state, amt_paid_sat}
    this.calls = [];
    this.down = false;
  }
  // The agent pays the invoice: it settles and the payer learns the preimage.
  pay(hashHex, sats) {
    const inv = this.invoices.get(hashHex);
    inv.state = "SETTLED";
    inv.amt_paid_sat = String(sats === undefined ? inv.value : sats);
    return inv.preimage;
  }
  async handleFetch(url, opts = {}) {
    this.calls.push({ url: String(url), headers: opts.headers, body: opts.body, method: opts.method || "GET" });
    if (this.down) return res(503, { error: "down" });
    const u = new URL(String(url));
    if (u.pathname === "/v1/invoices" && opts.method === "POST") {
      const b = JSON.parse(opts.body);
      const preimage = crypto.randomBytes(32);
      const hash = crypto.createHash("sha256").update(preimage).digest();
      this.invoices.set(hash.toString("hex"), { preimage: preimage.toString("hex"), value: Number(b.value), state: "OPEN", amt_paid_sat: "0" });
      return res(200, { r_hash: hash.toString("base64"), payment_request: "lnbc" + hash.toString("hex").slice(0, 20) });
    }
    const m = u.pathname.match(/^\/v1\/invoice\/([0-9a-f]{64})$/);
    if (m) {
      const inv = this.invoices.get(m[1]);
      if (!inv) return res(404, { error: "unknown invoice" });
      return res(200, { state: inv.state, value: String(inv.value), amt_paid_sat: inv.amt_paid_sat });
    }
    return res(404, { error: "no route" });
  }
}

function installAll(gh, processor, node) {
  const original = global.fetch;
  global.fetch = (url, opts) => {
    const s = String(url);
    if (s.startsWith(PROCESSOR_URL)) return processor.handleFetch(url, opts);
    if (s.startsWith(NODE_URL)) return node.handleFetch(url, opts);
    return gh.handleFetch(url, opts);
  };
  return () => { global.fetch = original; };
}

module.exports = { MockProcessor, MockNode, installAll, PROCESSOR_URL, NODE_URL };
