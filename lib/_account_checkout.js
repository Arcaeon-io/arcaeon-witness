// _account_checkout.js — the server makes the Stripe Checkout Session for an
// authenticated account. Underscore prefix = not routed as a serverless
// function; the route is POST /api/account/checkout (lib/_account_api.js).
//
// Why the server, and why the account's own customer. A Payment Link takes
// client_reference_id from its URL and makes a NEW Stripe customer for
// whoever pays. Even with the signed reference (mintAccountRef), a checkout
// URL that leaked inside its two hours let a stranger pay and put THEIR
// customer on the owner's account; the owner was then refused until that
// subscription died (the "lockout gap"). Here:
//
//   1. The account's Stripe customer is made ONCE (POST /v1/customers with an
//      Idempotency-Key bound to the account id, metadata.account_id set) and
//      stored with store.setStripeCustomer, which sets only when null. Every
//      later checkout reuses it. This is the only path that ever writes
//      accounts.stripe_customer_id.
//   2. The Checkout Session is created with `customer` = that customer, the
//      price found by its lookup key, client_reference_id and
//      metadata.account_ref = the signed reference (minted here, 2 hours),
//      subscription_data.metadata.account_ref for renewals, and expires_at
//      = the same two hours, so the session dies with the ref.
//
// So whoever pays the session URL pays for THIS account on THIS customer:
// Stripe's checkout.session.completed carries our customer, the webhook's
// checkCustomer sees it match, and nobody's own customer is ever linked by
// paying. The payer's identity is not used for anything.
//
// Stripe is called with fetch and form encoding, as api/fulfill.js does; no
// SDK, no dependency. The secret key is WITNESS_STRIPE_SECRET_KEY only. No
// fallback to a bare STRIPE_SECRET_KEY: that one belongs to a different
// Arcaeon product, and a customer or session CREATED in the wrong Stripe
// account would take real money where our webhook never hears of it
// (api/fulfill.js can fall back because its call only READS).
// The key goes in the request header only; never in an answer or a log.
//
// Round 2:
//   - RELEASE GATE. Every call is refused 503 checkout_disabled unless
//     ACCOUNT_CHECKOUT_ENABLED is exactly "true": /api/pin does not debit
//     accounts yet, so a paid plan would buy nothing (docs/ACCOUNT_V1.md).
//   - Refusals are a reason code and a plain sentence. Env var names, Stripe
//     lookup keys and Stripe's step go to console.error, never to the caller.
//   - A plan checkout carries an Idempotency-Key bound to the account, the
//     plan and a ten-minute bucket, and its ref and expiry are minted at the
//     bucket's start, so a double submit sends Stripe the same key with the
//     same body and gets ONE session back. (Refusing while another open plan
//     session exists would need a Stripe list call or a stored session id;
//     not built.)

"use strict";

const billing = require("./_account_billing.js");

const STRIPE = "https://api.stripe.com";
const PLAN_BUCKET_MS = 10 * 60 * 1000;
const PLANS = Object.freeze({ monthly: "account_monthly", yearly: "account_yearly" });
const DEFAULT_BASE_URL = "https://arcaeon-witness.vercel.app";

class StripeError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "StripeError";
    this.status = status;
    this.stripeError = true;
  }
}

// Body -> {mode, plan|pack, lookup_key} or {error, reason}. Exactly one of
// plan or pack. Only our names; the price itself is looked up at Stripe.
function parseItem(body) {
  if (!body || typeof body !== "object") return { error: "body must be a JSON object", reason: "bad_body" };
  const hasPlan = body.plan !== undefined;
  const hasPack = body.pack !== undefined;
  if (hasPlan === hasPack) return { error: "send exactly one of plan (monthly|yearly) or pack (pins_200|pins_1000)", reason: "bad_item" };
  if (hasPlan) {
    const plan = typeof body.plan === "string" ? body.plan.trim().toLowerCase() : "";
    if (!Object.prototype.hasOwnProperty.call(PLANS, plan)) return { error: "plan must be monthly or yearly", reason: "bad_plan" };
    return { mode: "subscription", plan, lookup_key: PLANS[plan] };
  }
  const pack = typeof body.pack === "string" ? body.pack.trim().toLowerCase() : "";
  if (!Object.prototype.hasOwnProperty.call(billing.ACCOUNT_PACKS, pack)) return { error: "pack must be pins_200 or pins_1000", reason: "bad_pack" };
  return { mode: "payment", pack, lookup_key: pack };
}

function form(params) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null) p.append(k, String(v));
  return p.toString();
}

// One Stripe call. Throws StripeError naming the step and status only.
async function stripeCall(fetchImpl, secret, { method, path, body, idempotencyKey }) {
  const headers = { authorization: `Bearer ${secret}` };
  if (body !== undefined) headers["content-type"] = "application/x-www-form-urlencoded";
  if (idempotencyKey) headers["idempotency-key"] = idempotencyKey;
  let res;
  try {
    res = await fetchImpl(STRIPE + path, { method, headers, body });
  } catch (_e) {
    throw new StripeError(`stripe unreachable (${method} ${path.split("?")[0]})`, 0);
  }
  let json = null;
  try {
    const text = await res.text();
    json = text ? JSON.parse(text) : null;
  } catch (_e) {
    json = null;
  }
  if (!res.ok) {
    // Stripe's error type and param are safe to name; its message may quote
    // the request, so it stays out of what we return.
    const e = (json && json.error) || {};
    const what = [e.type, e.code, e.param].filter(Boolean).join(" ");
    throw new StripeError(`stripe ${method} ${path.split("?")[0]} failed: HTTP ${res.status}${what ? ` (${what})` : ""}`, res.status);
  }
  return json;
}

// createCheckout({store, account_id, body, now, env, fetchImpl})
//   -> {ok:true, status:201, session_id, url, expires_at, mode, plan|pack, customer_id}
//    | {ok:false, status, reason, error}
// The store is already resolved; the api key already checked.
// A refusal for the caller (reason + plain sentence); the operator's detail
// goes to the server log only.
function refused(status, reason, error, operatorDetail) {
  if (operatorDetail) console.error(`account checkout refused (${reason}): ${operatorDetail}`);
  return { ok: false, status, reason, error };
}
const NOT_AVAILABLE = "account checkout is not available on this deployment right now; try again later";

async function createCheckout({ store, account_id, body, now = Date.now(), env = process.env, fetchImpl = (u, o) => fetch(u, o) }) {
  if (env.ACCOUNT_CHECKOUT_ENABLED !== "true") {
    return refused(503, "checkout_disabled", "account checkout is not open yet",
      "ACCOUNT_CHECKOUT_ENABLED is not \"true\" (release gate: /api/pin does not debit accounts yet)");
  }
  const item = parseItem(body);
  if (item.error) return { ok: false, status: 400, reason: item.reason, error: item.error };

  const secret = typeof env.WITNESS_STRIPE_SECRET_KEY === "string" ? env.WITNESS_STRIPE_SECRET_KEY : "";
  if (!secret) {
    return refused(503, "stripe_not_configured", NOT_AVAILABLE, "WITNESS_STRIPE_SECRET_KEY is not set on this deployment");
  }
  const refSecret = typeof env.ACCOUNT_REF_SECRET === "string" && env.ACCOUNT_REF_SECRET.length >= 16 ? env.ACCOUNT_REF_SECRET : null;
  if (!refSecret) {
    return refused(503, "account_ref_not_configured", NOT_AVAILABLE, "ACCOUNT_REF_SECRET is not set (16+ characters)");
  }

  const acct = await store.getAccount(account_id);
  if (!acct) return { ok: false, status: 401, reason: "unknown_account", error: "the account behind this api key was not found" };
  if (item.mode === "subscription" && billing.planHeld(acct)) {
    return { ok: false, status: 409, reason: "plan_already_held",
      error: `this account already holds a ${acct.plan} plan (${acct.status}); change or cancel it before starting another` };
  }

  // 1. The account's own customer, made once.
  let customer = acct.stripe_customer_id || null;
  if (!customer) {
    const made = await stripeCall(fetchImpl, secret, {
      method: "POST", path: "/v1/customers",
      body: form({ "metadata[account_id]": account_id, description: `arcaeon account ${account_id}` }),
      idempotencyKey: `arcaeon-account-customer-${account_id}`,
    });
    const id = made && typeof made.id === "string" && /^cus_[A-Za-z0-9]{1,64}$/.test(made.id) ? made.id : null;
    if (!id) throw new StripeError("stripe POST /v1/customers returned no customer id", 502);
    const set = await store.setStripeCustomer({ account_id, customer_id: id });
    if (!set.ok) {
      const err = new Error(`account store setStripeCustomer refused: ${set.reason}`);
      err.storeError = true;
      throw err;
    }
    customer = set.customer_id; // the winner's, if two first calls raced
  }

  // 2. The price, by lookup key (never a typed-in id).
  const prices = await stripeCall(fetchImpl, secret, {
    method: "GET", path: `/v1/prices?${form({ "lookup_keys[]": item.lookup_key, active: "true", limit: 1 })}`,
  });
  const price = prices && Array.isArray(prices.data) && prices.data[0] && typeof prices.data[0].id === "string" ? prices.data[0].id : null;
  if (!price) {
    return refused(503, "price_not_configured", "this item cannot be bought right now; try again later",
      `no active Stripe price has lookup key ${item.lookup_key}`);
  }

  // 3. The session, on our customer, with our reference, dying with it. A
  // plan's ref and expiry are minted at the start of its ten-minute bucket,
  // so the same account and plan in the same bucket is the same request
  // (same Idempotency-Key, same body) and Stripe answers the same session.
  const bucket = Math.floor(now / PLAN_BUCKET_MS);
  const mintAt = item.mode === "subscription" ? bucket * PLAN_BUCKET_MS : now;
  const ref = billing.mintAccountRef(account_id, mintAt, refSecret);
  const expUnix = Math.floor(mintAt / 1000) + billing.REF_TTL_S;
  const base = String(env.WITNESS_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const params = {
    mode: item.mode,
    customer,
    client_reference_id: ref,
    "line_items[0][price]": price,
    "line_items[0][quantity]": 1,
    "metadata[account_id]": account_id,
    "metadata[account_ref]": ref,
    expires_at: expUnix,
    success_url: `${base}/status?account_checkout=complete`,
    cancel_url: `${base}/status?account_checkout=canceled`,
  };
  if (item.mode === "subscription") {
    params["subscription_data[metadata][account_ref]"] = ref;
    params["subscription_data[metadata][account_id]"] = account_id;
  } else {
    params["metadata[pack]"] = item.pack;
  }
  const idempotencyKey = item.mode === "subscription" ? `arcaeon-account-plan-${account_id}-${item.plan}-${bucket}` : undefined;
  const session = await stripeCall(fetchImpl, secret, { method: "POST", path: "/v1/checkout/sessions", body: form(params), idempotencyKey });
  if (!session || typeof session.id !== "string" || typeof session.url !== "string") {
    throw new StripeError("stripe POST /v1/checkout/sessions returned no session", 502);
  }
  return {
    ok: true, status: 201, session_id: session.id, url: session.url,
    expires_at: new Date((Number(session.expires_at) || expUnix) * 1000).toISOString(),
    mode: item.mode, ...(item.plan ? { plan: item.plan } : { pack: item.pack }), customer_id: customer,
  };
}

module.exports = { createCheckout, parseItem, stripeCall, StripeError, PLANS, PLAN_BUCKET_MS };
