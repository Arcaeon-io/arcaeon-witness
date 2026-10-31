// _pay_x402.js — the stablecoin adapter for lib/_agent_pay.js, in the x402
// style: the 402 names what to pay (scheme, network, asset, amount, payee and a
// nonce), the agent pays through the payment processor's agent payments, and
// the witness confirms it server side by asking the processor, never by
// trusting what the agent sends. Underscore prefix = not routed.
//
// Settings, all required or the adapter is not offered:
//   WITNESS_PAY_X402           on
//   WITNESS_PAY_X402_API       the processor's verification base URL
//   WITNESS_PAY_X402_KEY       the processor secret (a test key until the owner says otherwise)
//   WITNESS_PAY_X402_PAY_TO    the receiving account or address
//   WITNESS_PAY_X402_ASSET     for example USDC
//   WITNESS_PAY_X402_NETWORK   the chain the asset settles on
//   WITNESS_PAY_X402_AMOUNT    price per pin in the asset's smallest unit, a whole number
//
// The verification call is ONE request, and its shape is this file's
// assumption about the processor, to be confirmed against its documentation
// before any live key (AGENT_PAYMENTS.md, "Before live keys"):
//   POST <api>/v1/verify  {payment_id, nonce, amount, asset, network, pay_to}
//   -> 200 {settled, payment_id, nonce, amount, asset, network, pay_to}
//   -> 404 unknown payment
// Every field that comes back is checked against the quote, so a processor
// answering about some other payment cannot pass.

"use strict";

const crypto = require("crypto");

const NAME = "x402";

function cfg(env = process.env) {
  return {
    api: env.WITNESS_PAY_X402_API,
    key: env.WITNESS_PAY_X402_KEY,
    payTo: env.WITNESS_PAY_X402_PAY_TO,
    asset: env.WITNESS_PAY_X402_ASSET,
    network: env.WITNESS_PAY_X402_NETWORK,
    amount: env.WITNESS_PAY_X402_AMOUNT,
  };
}

function configured(env = process.env) {
  const v = String(env.WITNESS_PAY_X402 || "").toLowerCase();
  if (!(v === "on" || v === "1" || v === "true" || v === "yes")) return false;
  const c = cfg(env);
  // Secrets go only to an https address.
  if (!/^https:\/\//i.test(String(c.api || ""))) return false;
  return Boolean(c.api && c.key && c.payTo && c.asset && c.network && /^[1-9][0-9]{0,30}$/.test(String(c.amount || "")));
}

async function quote() {
  const c = cfg();
  const nonce = crypto.randomBytes(16).toString("hex");
  const terms = { nonce, amount: String(c.amount), asset: c.asset, network: c.network, pay_to: c.payTo };
  return {
    signed: terms,
    public: { scheme: "exact", resource: "/api/pin", ...terms },
  };
}

// -> {ok:true, ref, amount, unit} | {ok:false, reason, detail?}. Throws when
// the processor cannot be asked, so the caller answers 503, not 402.
async function verify(proof, q) {
  const c = cfg();
  const body = { payment_id: proof.payment_id, nonce: q.nonce, amount: q.amount, asset: q.asset, network: q.network, pay_to: q.pay_to };
  const r = await fetch(`${String(c.api).replace(/\/+$/, "")}/v1/verify`, {
    method: "POST",
    headers: { authorization: `Bearer ${c.key}`, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (r.status === 404) return { ok: false, reason: "payment_not_found" };
  if (!r.ok) throw new Error(`processor answered ${r.status}`);
  let v;
  try { v = await r.json(); } catch (_e) { throw new Error("processor answer unreadable"); }
  if (!v || typeof v !== "object") throw new Error("processor answer unreadable");
  if (v.settled !== true) return { ok: false, reason: "payment_not_settled" };
  for (const f of ["payment_id", "nonce", "asset", "network", "pay_to"]) {
    if (String(v[f]) !== String(body[f])) return { ok: false, reason: "payment_terms_mismatch", detail: f };
  }
  let paid;
  try { paid = BigInt(String(v.amount)); } catch (_e) { return { ok: false, reason: "payment_terms_mismatch", detail: "amount" }; }
  if (paid < BigInt(q.amount)) return { ok: false, reason: "payment_too_small", detail: "amount" };
  return { ok: true, ref: crypto.createHash("sha256").update(`x402:${v.payment_id}`).digest("hex"), amount: String(v.amount), unit: q.asset };
}

module.exports = { NAME, configured, quote, verify };
