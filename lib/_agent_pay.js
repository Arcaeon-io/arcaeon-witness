// _agent_pay.js — agents pay per pin: the HTTP 402 flow on POST /api/pin.
// Design: AGENT_PAYMENTS.md. Underscore prefix = not routed as a serverless
// function. Off unless WITNESS_AGENT_PAY is on AND at least one adapter is
// fully configured. No live keys anywhere in this repo; the tests mock both
// the payment processor and the Lightning node.
//
// THE FLOW
//
//   1. A keyed pin whose free tier and credits are spent would have been
//      refused (429 over_cap or 402 credit_exhausted). With this on, it gets
//      402 payment_required instead, carrying one quote per adapter. Every
//      quote is bound to this exact request: the key (by hash), namespace,
//      rows, chain and intent, and it expires.
//   2. The agent pays one quote and retries the SAME request with the proof:
//        X-Payment: <base64 JSON {token, payment_id}>     (stablecoin adapter)
//        X-L402:    <token>:<preimage hex>               (Lightning adapter)
//   3. The witness checks the token (its own signature, its expiry, and that
//      its binding is this request), asks the adapter to confirm the payment
//      settled for at least the quoted amount, then claims the payment in the
//      ledger with a create only write. Only then does the pin write run.
//
// ONE PIN PER PAYMENT, ONE CHARGE PER WRITTEN PIN
//
//   - The ledger record payments/<adapter>/<ref>.json is created once. A
//     payment presented again finds it claimed and is refused 409
//     payment_already_used, whatever the request.
//   - A pin that writes nothing (rejected, or the idempotent re-pin of the
//     current head) never reaches the charge step, so it never claims a
//     payment; the proof stays unused.
//   - A claimed payment whose write then fails is RELEASED (release below):
//     the record moves to state "released" and the same proof is accepted again
//     for the same request. That is this path's refund, the same promise the
//     credit path keeps (api/pin.js refundFailedWrite): a charge that buys no
//     write is given back. No money is sent back automatically; the agent's
//     retry spends what it already paid.
//
// THE KEY STILL DECIDES THE NAMESPACE. Payment replaces the meter, never the
// key check: an anonymous payer could otherwise buy a write into any
// namespace and, through the monotonic guard, lock its owner out.

"use strict";

const crypto = require("crypto");
const pending = require("./_pending.js");
const x402 = require("./_pay_x402.js");
const l402 = require("./_pay_l402.js");

const ADAPTERS = { x402, l402 };
const QUOTE_TTL_SECONDS = 15 * 60;
const MIN_SECRET_LENGTH = 32;

function on(v) {
  const s = String(v || "").toLowerCase();
  return s === "on" || s === "1" || s === "true" || s === "yes";
}

function secret(env = process.env) {
  const s = env.WITNESS_PAY_SECRET || "";
  return s.length >= MIN_SECRET_LENGTH ? s : null;
}

// Adapters that are switched on and fully configured. An adapter missing any
// setting is not offered; nothing is offered without the token secret.
function activeAdapters(env = process.env) {
  if (!on(env.WITNESS_AGENT_PAY) || !secret(env)) return [];
  return Object.values(ADAPTERS).filter((a) => a.configured(env));
}

function enabled(env = process.env) {
  return activeAdapters(env).length > 0;
}

function keyHash(key) {
  return crypto.createHash("sha256").update(String(key), "utf8").digest("hex");
}

// The request a quote pays for, in one stable string.
function bindingOf({ key, namespace, rows, chain, intent }) {
  return crypto.createHash("sha256").update(JSON.stringify([
    "agent-pay:v1", keyHash(key), namespace, rows, String(chain).toLowerCase(), intent || "pin",
  ])).digest("hex");
}

// ---- the reference a public record may carry ----
//
// The ledger's own ref exists outside the witness: for Lightning it is the
// invoice's payment hash (every routing node on the path sees it), for the
// stablecoin adapter an unkeyed sha256 of the processor's payment id (anyone
// holding that id can recompute it). Either, published, links a pin to a
// payment. So the public record never carries it. It carries an HMAC of it
// under WITNESS_PAYMENT_REF_KEY, a server secret: a value that exists nowhere
// outside the witness, differs per payment, and cannot be computed or
// confirmed without the key. The operator, holding the key, can still go from
// a ledger entry to its record. Without the key (unset, or shorter than
// MIN_SECRET_LENGTH) there is no ref at all: the record only says a payment
// was made, and by which method. A ref key equal to WITNESS_PAY_SECRET is
// refused the same way: one secret doing two jobs means a leak of either
// exposes both, so no ref is published until the operator sets a distinct key.
// The comparison is on trimmed values and also refuses when either is a prefix
// of the other, so a key that is the pay secret plus a suffix (or a cut of it)
// does not pass as distinct.
// Either case logs one line per process (warnOnce below), like the per IP
// secret warning in lib/_ratelimit.js.
const warned = new Set();
function warnOnce(code, msg) {
  if (warned.has(code)) return;
  warned.add(code);
  console.error(msg);
}

function paymentRefKey(env = process.env) {
  const s = env.WITNESS_PAYMENT_REF_KEY || "";
  if (s.trim().length < MIN_SECRET_LENGTH) {
    warnOnce("ref_key_unset", `[agent-pay] WITNESS_PAYMENT_REF_KEY unset or shorter than ${MIN_SECRET_LENGTH}; ` +
      "paid records carry no payment ref");
    return null;
  }
  const k = s.trim();
  const pay = String(env.WITNESS_PAY_SECRET || "").trim();
  if (pay && (k === pay || k.includes(pay) || pay.includes(k))) {
    warnOnce("ref_key_reused", "[agent-pay] WITNESS_PAYMENT_REF_KEY equals WITNESS_PAY_SECRET (trimmed, or one contains the other); refused, " +
      "paid records carry no payment ref until it is set to a distinct key");
    return null;
  }
  return s;
}

// -> hex string | null (no usable key: publish no ref)
function publicRef(adapterName, ref, env = process.env) {
  if (typeof ref !== "string" || !ref) return null;
  const k = paymentRefKey(env);
  if (!k) return null;
  return crypto.createHmac("sha256", k).update(`witness-payment-ref:v1:${adapterName}:${ref}`, "utf8").digest("hex");
}

// What a log line may say about a payment: the first 12 hex of its public
// ref, or "ref-hidden" when there is no ref key. Never the ledger's ref, which
// links a pin to a payment (see above). This is the one place that decides
// how a ref looks in a log; ledgerLogPath below and lib/_pending.js's store
// error lines both go through it.
//
// What this does and does not hide. Log lines (Vercel's function logs, which
// are kept and shown outside the usage repo) never carry the ledger ref. The
// ledger commit messages use it too, but that buys consistency, not secrecy:
// the ledger FILE is still named on the ledger ref (ledgerPath), and the file
// body holds it, so anyone who can read the private usage repo can read the
// ref whatever the message says. The file name stays on the ledger ref on
// purpose. The public ref needs WITNESS_PAYMENT_REF_KEY, which may be unset
// (then there is no name to use) and may be rotated (then the same payment
// gets a new name, and the one payment one pin check is gone). The ledger's
// guarantee must not depend on an optional, rotatable key.
function logRef(adapterName, ref, env = process.env) {
  const p = publicRef(adapterName, ref, env);
  return p ? `pub:${p.slice(0, 12)}` : "ref-hidden";
}

function _resetWarnings() { warned.clear(); }

// ---- the quote token: our own signature, so a quote needs no stored state ----

function sign(payload, env = process.env) {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const mac = crypto.createHmac("sha256", secret(env)).update(body).digest("base64url");
  return `${body}.${mac}`;
}

// -> {ok:true, payload} | {ok:false, reason}
function openToken(token, env = process.env) {
  if (typeof token !== "string" || token.length > 4096) return { ok: false, reason: "malformed_token" };
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, reason: "malformed_token" };
  const want = crypto.createHmac("sha256", secret(env)).update(parts[0]).digest();
  let got;
  try { got = Buffer.from(parts[1], "base64url"); } catch (_e) { return { ok: false, reason: "malformed_token" }; }
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) return { ok: false, reason: "bad_token_signature" };
  let payload;
  try { payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")); } catch (_e) { return { ok: false, reason: "malformed_token" }; }
  if (!payload || typeof payload !== "object") return { ok: false, reason: "malformed_token" };
  return { ok: true, payload };
}

// ---- reading the proof off a request ----

// -> null (no proof) | {adapter, token, proof} | {error, field}
function proofFrom(req) {
  const h = req.headers || {};
  const xp = h["x-payment"];
  const xl = h["x-l402"];
  if (xp !== undefined && xl !== undefined) {
    return { error: "send one payment proof, not two", field: "x-payment" };
  }
  if (xp !== undefined) {
    let p;
    try { p = JSON.parse(Buffer.from(String(xp), "base64").toString("utf8")); } catch (_e) { p = null; }
    if (!p || typeof p !== "object" || typeof p.token !== "string" || typeof p.payment_id !== "string") {
      return { error: "X-Payment must be base64 JSON {token, payment_id}", field: "x-payment" };
    }
    return { adapter: "x402", token: p.token, proof: { payment_id: p.payment_id } };
  }
  if (xl !== undefined) {
    const s = String(xl);
    const i = s.lastIndexOf(":");
    const preimage = i > 0 ? s.slice(i + 1) : "";
    if (i <= 0 || !/^[0-9a-f]{64}$/.test(preimage)) {
      return { error: "X-L402 must be <token>:<preimage as 64 hex>", field: "x-l402" };
    }
    return { adapter: "l402", token: s.slice(0, i), proof: { preimage } };
  }
  return null;
}

// What the handler builds once per request and passes to charge and release.
function contextFor(req, { key, namespace, rows, chain, intent }) {
  if (!enabled()) return { enabled: false };
  return {
    enabled: true,
    request: { key, namespace, rows, chain, intent: intent || "pin" },
    binding: bindingOf({ key, namespace, rows, chain, intent }),
    proof: proofFrom(req),
    claimed: null,
  };
}

function deny(status, reason, field, error, extra = {}) {
  return { deny: { status, body: { error, reason, field, ...extra } }, headers: {} };
}

// ---- the 402 ----

// Called with the meter's refusal. Over the free cap or out of credits is
// what a payment answers; any other refusal (no cap configured) stands.
function payable(meterDeny) {
  const r = meterDeny && meterDeny.body && meterDeny.body.reason;
  return r === "over_cap" || r === "credit_exhausted";
}

async function paymentRequired(ctx, meterCharge, { now = Date.now() } = {}) {
  const exp = Math.floor(now / 1000) + QUOTE_TTL_SECONDS;
  const accepts = [];
  const notes = [];
  for (const a of activeAdapters()) {
    try {
      const q = await a.quote({ binding: ctx.binding, exp, request: ctx.request });
      const token = sign({ v: 1, adapter: a.NAME, binding: ctx.binding, exp, ...q.signed });
      accepts.push({ adapter: a.NAME, token, expires_at: new Date(exp * 1000).toISOString(), ...q.public });
    } catch (err) {
      // One adapter down does not take the other with it; it is named.
      console.error(`[agent-pay] ${a.NAME} quote failed: ${err && err.message}`);
      notes.push({ adapter: a.NAME, reason: "quote_unavailable" });
    }
  }
  if (accepts.length === 0) {
    return deny(503, "payment_unavailable", "payment", "no payment method could quote right now; the pin was not attempted",
      { retry_safe: true, unavailable: notes });
  }
  const headers = { ...(meterCharge.headers || {}) };
  const l = accepts.find((x) => x.adapter === "l402");
  if (l) headers["WWW-Authenticate"] = `L402 token="${l.token}", invoice="${l.invoice}"`;
  return {
    deny: {
      status: 402,
      body: {
        error: "payment required: the free tier and credits for this key are spent",
        reason: "payment_required",
        field: "payment",
        meter_reason: meterCharge.deny.body.reason,
        binding: { namespace: ctx.request.namespace, rows: ctx.request.rows, chain: ctx.request.chain, intent: ctx.request.intent },
        accepts,
        unavailable: notes.length ? notes : undefined,
        how: "pay one quote, then send this same request again with X-Payment (x402) or X-L402 (l402)",
      },
    },
    headers,
  };
}

// ---- charging with a proof ----

function ledgerPath(adapter, ref) {
  return `payments/${adapter}/${ref}.json`;
}

// What a log line says instead of ledgerPath: same shape, ref through logRef.
// Passed to lib/_pending.js as {logAs} on every ledger read and write.
function ledgerLogPath(adapter, ref, env = process.env) {
  return `payments/${adapter}/${logRef(adapter, ref, env)}`;
}

async function chargeWithProof(ctx, { now = Date.now() } = {}) {
  const p = ctx.proof;
  if (p.error) return deny(400, "malformed_payment_proof", p.field, p.error);
  const adapter = activeAdapters().find((a) => a.NAME === p.adapter);
  if (!adapter) return deny(400, "payment_method_not_offered", p.adapter === "x402" ? "x-payment" : "x-l402",
    `payment method ${p.adapter} is not offered by this witness`);
  const field = p.adapter === "x402" ? "x-payment" : "x-l402";

  const t = openToken(p.token);
  if (!t.ok) return deny(401, t.reason, field, "the payment token is not one this witness issued");
  const q = t.payload;
  if (q.adapter !== p.adapter) return deny(401, "token_for_other_method", field, "the payment token was issued for another method");
  if (!Number.isInteger(q.exp)) return deny(401, "malformed_token", field, "the payment token is not one this witness issued");
  // Expiry is checked at the ledger step below, not here: a payment released
  // after a failed write must stay redeemable for its own request after its
  // quote's 15 minutes, or the agent's money would be stuck.
  const expired = q.exp * 1000 < now;
  if (q.binding !== ctx.binding) {
    return deny(409, "payment_for_other_request", field,
      "this payment was quoted for a different request (key, namespace, rows, chain or intent)");
  }

  let v;
  try {
    v = await adapter.verify(p.proof, q);
  } catch (err) {
    console.error(`[agent-pay] ${adapter.NAME} verify unreachable: ${err && err.message}`);
    return deny(503, "payment_check_unavailable", field, "the payment could not be checked right now; nothing was charged", { retry_safe: true });
  }
  if (!v.ok) return deny(402, v.reason || "payment_not_settled", field, "the payment did not check out", { detail: v.detail });

  const path = ledgerPath(adapter.NAME, v.ref);
  const logAs = { logAs: ledgerLogPath(adapter.NAME, v.ref) };
  const record = {
    adapter: adapter.NAME,
    ref: v.ref,
    amount: v.amount,
    unit: v.unit,
    binding: ctx.binding,
    key_hash: keyHash(ctx.request.key).slice(0, 16),
    namespace: ctx.request.namespace,
    state: "claimed",
    claimed_at: new Date(now).toISOString(),
  };
  try {
    const cur = await pending.readUsageDoc(path, logAs);
    if (cur === null) {
      if (expired) return deny(401, "quote_expired", field, "the quote this payment answers has expired; ask again");
      await pending.writeUsageDoc(path, record, undefined, `payment ${adapter.NAME} ${logRef(adapter.NAME, v.ref)} claimed`, logAs);
    } else if (cur.json && cur.json.state === "released" && cur.json.binding === ctx.binding) {
      await pending.writeUsageDoc(path, { ...cur.json, state: "claimed", claimed_at: record.claimed_at,
        reclaims: (cur.json.reclaims || 0) + 1 }, cur.sha, `payment ${adapter.NAME} ${logRef(adapter.NAME, v.ref)} claimed again after a failed write`, logAs);
    } else {
      return deny(409, "payment_already_used", field, "this payment has already bought a pin");
    }
  } catch (err) {
    if (err && err.conflict) return deny(409, "payment_already_used", field, "this payment has already bought a pin");
    console.error(`[agent-pay] ledger claim failed: ${err && err.message}`);
    return deny(503, "payment_ledger_unavailable", field, "the payment could not be recorded; nothing was charged", { retry_safe: true });
  }
  ctx.claimed = { path, adapter: adapter.NAME, ref: v.ref };
  return {
    ok: true,
    source: "payment",
    headers: { "X-Meter-Source": "payment", "X-Payment-Method": adapter.NAME, "X-Payment-Ref": v.ref },
  };
}

// The write failed after the payment was claimed: give it back for a retry.
// Never throws; a failed release is logged loudly, like a failed credit refund.
async function release(ctx, cause) {
  if (!ctx || !ctx.claimed) return;
  const { path, adapter, ref } = ctx.claimed;
  const shown = logRef(adapter, ref);
  const logAs = { logAs: ledgerLogPath(adapter, ref) };
  try {
    const cur = await pending.readUsageDoc(path, logAs);
    if (!cur || !cur.json || cur.json.state !== "claimed") return;
    await pending.writeUsageDoc(path, { ...cur.json, state: "released", released_at: new Date().toISOString(),
      release_cause: "pin write failed" }, cur.sha, `payment ${adapter} ${shown} released after a failed write`, logAs);
    console.error(`[agent-pay] released ${adapter} ${shown} after write failure: ${cause && cause.message}`);
  } catch (err) {
    console.error(`[agent-pay] RELEASE FAILED, payment stays claimed with no pin: ${adapter} ${shown} ` +
      `err=${err && err.message} cause=${cause && cause.message}`);
  }
}

module.exports = {
  enabled, activeAdapters, contextFor, proofFrom, bindingOf, payable,
  paymentRequired, chargeWithProof, release, sign, openToken, ledgerPath, ledgerLogPath, publicRef, logRef, _resetWarnings,
  QUOTE_TTL_SECONDS, ADAPTERS,
};
