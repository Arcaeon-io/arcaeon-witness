// _pay_l402.js — the Lightning adapter for lib/_agent_pay.js, in the L402
// style: the 402 carries an invoice and a token; the agent pays the invoice,
// learns its preimage, and retries with token and preimage. The node is
// SELF HOSTED: this adapter talks to the operator's own node over its REST
// interface (the LND REST shape, which a self hosted BTCPay with LND also
// serves). No custodial processor, and the witness never holds a spending key:
// the macaroon it needs only makes and reads invoices.
// Underscore prefix = not routed.
//
// Settings, all required or the adapter is not offered:
//   WITNESS_PAY_L402           on
//   WITNESS_PAY_L402_NODE      the node's REST base URL
//   WITNESS_PAY_L402_MACAROON  an invoice only macaroon, hex
//   WITNESS_PAY_L402_SATS      price per pin in satoshis, a whole number
//
// Calls:
//   POST <node>/v1/invoices {value, memo, expiry} -> {r_hash (base64), payment_request}
//   GET  <node>/v1/invoice/<payment hash hex>     -> {state, amt_paid_sat, value}
//
// The preimage alone is proof of payment (only the payer learns it), and the
// witness also asks its node that the invoice is SETTLED for at least the price.

"use strict";

const crypto = require("crypto");

const NAME = "l402";

function cfg(env = process.env) {
  return {
    node: env.WITNESS_PAY_L402_NODE,
    macaroon: env.WITNESS_PAY_L402_MACAROON,
    sats: env.WITNESS_PAY_L402_SATS,
  };
}

function configured(env = process.env) {
  const v = String(env.WITNESS_PAY_L402 || "").toLowerCase();
  if (!(v === "on" || v === "1" || v === "true" || v === "yes")) return false;
  const c = cfg(env);
  // Secrets go only to an https address.
  if (!/^https:\/\//i.test(String(c.node || ""))) return false;
  return Boolean(c.node && c.macaroon && /^[0-9a-f]+$/i.test(c.macaroon) && /^[1-9][0-9]{0,9}$/.test(String(c.sats || "")));
}

function base() {
  return String(cfg().node).replace(/\/+$/, "");
}

function headers() {
  return { "grpc-metadata-macaroon": cfg().macaroon, "content-type": "application/json", accept: "application/json" };
}

async function quote({ binding, exp }) {
  const sats = Number(cfg().sats);
  const expiry = Math.max(60, exp - Math.floor(Date.now() / 1000));
  const r = await fetch(`${base()}/v1/invoices`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ value: String(sats), memo: `arcaeon witness pin ${binding.slice(0, 12)}`, expiry: String(expiry) }),
  });
  if (!r.ok) throw new Error(`node answered ${r.status}`);
  const j = await r.json();
  if (!j || typeof j.r_hash !== "string" || typeof j.payment_request !== "string") throw new Error("node answer unreadable");
  const hash = Buffer.from(j.r_hash, "base64").toString("hex");
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("node answer unreadable");
  return {
    signed: { payment_hash: hash, sats },
    public: { invoice: j.payment_request, payment_hash: hash, amount_sats: sats },
  };
}

async function verify(proof, q) {
  if (!/^[0-9a-f]{64}$/.test(String(q.payment_hash || ""))) return { ok: false, reason: "malformed_token" };
  const h = crypto.createHash("sha256").update(Buffer.from(proof.preimage, "hex")).digest("hex");
  if (h !== q.payment_hash) return { ok: false, reason: "preimage_mismatch" };
  const r = await fetch(`${base()}/v1/invoice/${q.payment_hash}`, { headers: headers() });
  if (r.status === 404) return { ok: false, reason: "payment_not_found" };
  if (!r.ok) throw new Error(`node answered ${r.status}`);
  const j = await r.json();
  if (!j || typeof j !== "object") throw new Error("node answer unreadable");
  if (j.state !== "SETTLED") return { ok: false, reason: "payment_not_settled" };
  const paid = Number(j.amt_paid_sat);
  if (!Number.isSafeInteger(paid) || paid < q.sats) return { ok: false, reason: "payment_too_small", detail: "amt_paid_sat" };
  return { ok: true, ref: q.payment_hash, amount: String(paid), unit: "sat" };
}

module.exports = { NAME, configured, quote, verify };
