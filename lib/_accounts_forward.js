// lib/_accounts_forward.js: after api/stripe-webhook.js has verified a paid
// checkout and applied its credit to the key, send the same checkout to the
// account service's POST /accounts/v1/checkout, so the buyer's account (found
// or made by the buyer's email) holds the same credits. Not routed: api/ is at
// its function cap, so this lives in lib/ and the webhook calls it.
//
// What the account service takes (witness/accounts.py read_checkout and
// verify_checkout in the account service's repository, docs/ACCOUNTS.md
// "Checkout"): a JSON object with exactly these seven fields and no others,
//
//   {"checkout": <checkout session id>, "completed_at": "YYYY-MM-DDTHH:MM:SSZ",
//    "customer": <customer id>, "email": <buyer's email>,
//    "grant": {"credits": N}, "kind": "checkout", "v": 1}
//
// sent with the header
//
//   Checkout-Signature: t=<unix seconds>,v1=<64 lower case hex>
//
// where the hex is HMAC-SHA256, under the secret shared with the account
// service, of the seconds as decimal digits, a dot, and the body bytes exactly
// as sent. The service refuses a signature more than 300 seconds from its own
// clock, and a secret shorter than 32 bytes. It is idempotent by the checkout
// id: the same checkout sent again attaches nothing twice and answers the same
// account, so a provider retry that forwards a checkout again is safe.
//
// Settings (environment):
//   WITNESS_ACCOUNTS_FORWARD          "off" (default, sends nothing),
//                                     "dry-run" (builds and signs, logs one
//                                     line, sends nothing), or "on". Any other
//                                     value counts as off and is logged.
//   WITNESS_ACCOUNTS_URL              the account service's base address,
//                                     https only; the path
//                                     /accounts/v1/checkout is added to it.
//   WITNESS_ACCOUNTS_CHECKOUT_SECRET  the shared secret, at least 32 bytes.
//                                     Set it as an encrypted value; it is
//                                     never logged.
//
// Every outcome is one log line, and no line ever holds the email, the
// secret, the signature or the body. Nothing here throws to the caller and
// nothing here changes the webhook's answer or the key's credit: the forward
// runs only after the credit, and its result is only logged.
//
// A forward that is missed (the service down, slow or refusing, or the mode
// off at the time) is caught up by a one time script run by the operator, not
// by a retry record: this module keeps no store. The script lists the paid
// checkouts from the payment provider and sends each through buildForward and
// sendForward below; the service's idempotency by checkout id makes sending
// one twice harmless. The log line of every missed forward names the checkout
// id, so the operator can also send just those.

"use strict";

const crypto = require("crypto");

const PATH = "/accounts/v1/checkout";
const MODES = new Set(["off", "dry-run", "on"]);
const MIN_SECRET_BYTES = 32;
const TIMEOUT_MS = 3000;
const MAX_TEXT = 255;
const PRINTABLE = /^[!-~]{1,255}$/;

function log(line) {
  console.error(`[accounts-forward] ${line}`);
}

// The mode, from WITNESS_ACCOUNTS_FORWARD. Unset or empty is off with no
// line; an unknown value is off and says so. No part of an unknown value is
// printed: an operator may have pasted the secret into the wrong setting.
function readMode(env = process.env) {
  const raw = env.WITNESS_ACCOUNTS_FORWARD;
  if (raw === undefined || raw === "") return { mode: "off", logged: false };
  if (MODES.has(raw)) return { mode: raw, logged: false };
  log("WITNESS_ACCOUNTS_FORWARD is not off, dry-run or on; counted as off, nothing sent");
  return { mode: "off", logged: true };
}

// The full address to POST to, or null with the reason.
function checkoutUrl(base) {
  if (typeof base !== "string" || !base) return { url: null, reason: "WITNESS_ACCOUNTS_URL is not set" };
  let u;
  try {
    u = new URL(base);
  } catch {
    return { url: null, reason: "WITNESS_ACCOUNTS_URL is not an address" };
  }
  if (u.protocol !== "https:") return { url: null, reason: "WITNESS_ACCOUNTS_URL must start with https://" };
  if (u.username || u.password) return { url: null, reason: "WITNESS_ACCOUNTS_URL must not hold a user name or password" };
  if (u.search || u.hash) return { url: null, reason: "WITNESS_ACCOUNTS_URL must not hold a query or a fragment" };
  // A base that already ends in the checkout path is taken as the base
  // without it, so the path is never added twice.
  let path = u.pathname.replace(/\/+$/, "");
  if (path.endsWith(PATH)) path = path.slice(0, -PATH.length);
  return { url: `${u.origin}${path}${PATH}`, reason: null };
}

// The contract's time form, whole seconds in UTC.
function formatTime(seconds) {
  return new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

// The buyer's email: the checkout session's customer details first, then the
// email the session was opened with (the same order api/fulfill.js reads).
function buyerEmail(session) {
  const d = session && session.customer_details;
  if (d && typeof d.email === "string" && d.email) return d.email;
  if (session && typeof session.customer_email === "string" && session.customer_email) return session.customer_email;
  return null;
}

// The account service's own email shape check (normal_email): 3 to 254
// printable characters with no white space, one at sign with something
// before it, and a domain that holds a dot and neither starts nor ends with
// one. An email it would refuse is not sent.
function usableEmail(email) {
  if (typeof email !== "string" || email.length < 3 || email.length > 254) return false;
  if (!/^[!-~]+$/.test(email)) return false;
  const at = email.indexOf("@");
  if (at < 1) return false;
  const domain = email.slice(at + 1);
  if (domain.includes("@") || domain.startsWith(".") || domain.endsWith(".")) return false;
  return domain.replace(/^\.+|\.+$/g, "").includes(".");
}

// The customer id, whether the session carries it as an id or as an object.
function customerId(session) {
  const c = session && session.customer;
  if (typeof c === "string" && c) return c;
  if (c && typeof c === "object" && typeof c.id === "string" && c.id) return c.id;
  return null;
}

// Build the body the account service takes, or say why there is none.
// completedSeconds is when the payment was known paid (the event's created
// time); it falls back to nowSeconds.
function buildForward({ session, pins, completedSeconds, nowSeconds }) {
  const checkout = session && session.id ? String(session.id) : null;
  if (!checkout || checkout.length > MAX_TEXT || !PRINTABLE.test(checkout)) {
    return { body: null, skip: "the checkout carries no usable checkout id" };
  }
  const email = buyerEmail(session);
  if (!email) return { body: null, skip: "the checkout carries no email" };
  if (!usableEmail(email)) return { body: null, skip: "the checkout carries no usable email" };
  const customer = customerId(session);
  if (!customer || customer.length > MAX_TEXT || !PRINTABLE.test(customer)) {
    return { body: null, skip: "the checkout carries no customer id, which the account service requires" };
  }
  if (!Number.isInteger(pins) || pins < 1 || pins > 10 ** 7) {
    return { body: null, skip: "the pins granted for this checkout are not known or not a whole number from 1 to 10000000" };
  }
  const at = Number.isInteger(completedSeconds) && completedSeconds > 0 ? completedSeconds : nowSeconds;
  // Keys written in sorted order, so the same checkout always makes the same
  // bytes. The account service checks the bytes as sent, not a re-encoding.
  const obj = {
    checkout,
    completed_at: formatTime(at),
    customer,
    email,
    grant: { credits: pins },
    kind: "checkout",
    v: 1,
  };
  return { body: Buffer.from(JSON.stringify(obj), "utf8"), skip: null };
}

// The Checkout-Signature header value: the account service's sign_checkout.
function signForward(secret, body, seconds) {
  const mac = crypto
    .createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(Buffer.concat([Buffer.from(`${seconds}.`, "utf8"), body]))
    .digest("hex");
  return `t=${seconds},v1=${mac}`;
}

// POST the signed body. Answers { status } or { error }; never throws.
async function sendForward(url, body, header, { timeoutMs = module.exports.TIMEOUT_MS } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "checkout-signature": header },
      body,
      // Never follow a redirect: it would resend the signed body, which holds
      // the buyer's email, to wherever the answer points. A 3xx is not 200,
      // so it is logged as refused.
      redirect: "manual",
      signal: ctl.signal,
    });
    let field = null;
    try {
      const text = await r.text();
      const j = JSON.parse(text);
      if (j && typeof j.field === "string") field = j.field.slice(0, 40).replace(/[^!-~]/g, "?");
    } catch {
      // the answer's body is only read for a refusal's field name
    }
    return { status: r.status, field };
  } catch (err) {
    return { error: ctl.signal.aborted ? `no answer within ${timeoutMs} ms` : "the request failed" };
  } finally {
    clearTimeout(timer);
  }
}

// The one entry point the webhook calls, after the credit. Always resolves,
// to a short outcome the tests read; the webhook ignores it.
async function forwardCheckout({ session, pack, pins, eventCreated }, env = process.env, opts = {}) {
  try {
    const { mode } = readMode(env);
    if (mode === "off") return { outcome: "off" };
    const sid = session && session.id ? String(session.id).slice(0, 80).replace(/[^!-~]/g, "?") : "(none)";
    const nowSeconds = Math.floor((opts.now ? opts.now() : Date.now()) / 1000);
    const built = buildForward({ session, pins, completedSeconds: eventCreated, nowSeconds });
    if (!built.body) {
      log(`${mode}: not forwarded, ${built.skip}: session=${sid}`);
      return { outcome: "skipped", reason: built.skip };
    }
    const target = checkoutUrl(env.WITNESS_ACCOUNTS_URL);
    if (!target.url) {
      log(`${mode}: not forwarded, ${target.reason}: session=${sid}`);
      return { outcome: "skipped", reason: target.reason };
    }
    const secret = env.WITNESS_ACCOUNTS_CHECKOUT_SECRET;
    if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < MIN_SECRET_BYTES) {
      const reason = `WITNESS_ACCOUNTS_CHECKOUT_SECRET is not set or shorter than ${MIN_SECRET_BYTES} bytes`;
      log(`${mode}: not forwarded, ${reason}: session=${sid}`);
      return { outcome: "skipped", reason };
    }
    const header = signForward(secret, built.body, nowSeconds);
    if (mode === "dry-run") {
      log(`dry-run: built and signed the checkout forward, not sent: session=${sid} pack=${pack} credits=${pins} bytes=${built.body.length}`);
      return { outcome: "dry-run", body: built.body, header, url: target.url };
    }
    const sent = await sendForward(target.url, built.body, header, opts);
    if (sent.error) {
      log(`on: forward failed, ${sent.error}; catch up with the one time script: session=${sid}`);
      return { outcome: "failed", reason: sent.error };
    }
    if (sent.status !== 200) {
      log(`on: forward refused, status ${sent.status} field=${sent.field || "-"}; catch up with the one time script: session=${sid}`);
      return { outcome: "refused", status: sent.status, field: sent.field };
    }
    log(`on: forwarded: session=${sid} pack=${pack} credits=${pins} status=200`);
    return { outcome: "sent", status: 200 };
  } catch (err) {
    // Belt and braces: nothing above should throw, and a throw here must not
    // reach the webhook. The message is not logged, since it is not ours.
    log("forward failed inside the witness, nothing sent; catch up with the one time script");
    return { outcome: "failed", reason: "internal" };
  }
}

module.exports = {
  PATH,
  TIMEOUT_MS,
  MIN_SECRET_BYTES,
  readMode,
  checkoutUrl,
  usableEmail,
  buildForward,
  signForward,
  sendForward,
  forwardCheckout,
};
