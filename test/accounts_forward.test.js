// test/accounts_forward.test.js: api/stripe-webhook.js forwarding each paid
// checkout to the account service's POST /accounts/v1/checkout
// (lib/_accounts_forward.js). The fake account service below checks the
// signature and the body by the account service's own rule, written here
// from its Python code (witness/accounts.py verify_checkout, read_checkout,
// normal_email; witness/account_service.py _checkout), and applies each
// checkout id once as its apply_checkout does: a recorded or a spendable
// grant, never both (409 naming checkout on a kind change), and a checkout
// with no customer id kept on the unmatched list (202 UNMATCHED).
"use strict";

process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_STRIPE_WEBHOOK_SECRET = "whsec_test_secret_123";
delete process.env.WITNESS_STRIPE_LIVEMODE;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeRawReq, makeRes } = require("./helpers/http_mocks.js");
const { stripeSigHeader } = require("./helpers/stripe_sign.js");
const balance = require("../lib/_balance.js");
const forward = require("../lib/_accounts_forward.js");
const webhook = require("../api/stripe-webhook.js");

const STRIPE_SECRET = process.env.WITNESS_STRIPE_WEBHOOK_SECRET;
const ACCOUNTS_BASE = "https://accounts.test.invalid";
const ACCOUNTS_SECRET = "accounts-checkout-secret-for-tests-0123456789";
const EMAIL = "Buyer.Person@Example.org";
const SETTINGS = ["WITNESS_ACCOUNTS_FORWARD", "WITNESS_ACCOUNTS_URL", "WITNESS_ACCOUNTS_CHECKOUT_SECRET"];

// ---------------------------------------------------------------------
// The account service's rule, from its Python code
// ---------------------------------------------------------------------

const SIGNATURE = /^t=([0-9]{1,12}),v1=([0-9a-f]{64})$/;
const FIELDS = ["checkout", "completed_at", "customer", "email", "grant", "kind", "v"];
const OPTIONAL = ["customer"];
const PACK = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

// Answers { field } for a refusal or { answer } for a checked checkout.
function accountServiceCheck(raw, header, secret, nowSeconds) {
  if (Buffer.byteLength(secret, "utf8") < 32) return { field: "secret" };
  if (typeof header !== "string" || !header) return { field: "signature" };
  const m = SIGNATURE.exec(header);
  if (!m) return { field: "signature" };
  const seconds = Number(m[1]);
  if (Math.abs(seconds - nowSeconds) > 300) return { field: "timestamp" };
  const want = crypto
    .createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(Buffer.concat([Buffer.from(`${seconds}.`, "utf8"), raw]))
    .digest("hex");
  if (!crypto.timingSafeEqual(Buffer.from(want), Buffer.from(m[2]))) return { field: "signature" };
  let obj;
  try {
    obj = JSON.parse(raw.toString("utf8"));
  } catch {
    return { field: "checkout" };
  }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return { field: "checkout" };
  for (const f of FIELDS) if (!(f in obj) && !OPTIONAL.includes(f)) return { field: f };
  for (const f of Object.keys(obj)) if (!FIELDS.includes(f)) return { field: "checkout" };
  if (obj.kind !== "checkout") return { field: "kind" };
  if (obj.v !== 1) return { field: "v" };
  if (obj.customer === undefined) obj.customer = null;
  for (const f of obj.customer === null ? ["checkout"] : ["checkout", "customer"]) {
    if (typeof obj[f] !== "string" || !/^[!-~]{1,255}$/.test(obj[f])) return { field: f };
  }
  const e = obj.email;
  if (typeof e !== "string" || e.length < 3 || e.length > 254 || !/^[!-~]+$/.test(e)) return { field: "email" };
  const at = e.indexOf("@");
  const local = e.slice(0, at);
  const domain = e.slice(at + 1);
  if (at < 0 || !local || domain.includes("@") || !domain.replace(/^\.+|\.+$/g, "").includes(".") ||
      domain.startsWith(".") || domain.endsWith(".")) return { field: "email" };
  if (typeof obj.completed_at !== "string" || !TIME.test(obj.completed_at)) return { field: "completed_at" };
  const g = obj.grant;
  if (!g || typeof g !== "object" || Array.isArray(g)) return { field: "grant" };
  const keys = Object.keys(g).sort().join(",");
  if ("recorded" in g) {
    if (keys !== "recorded") return { field: "grant" };
    const r = g.recorded;
    if (!r || typeof r !== "object" || Array.isArray(r) || Object.keys(r).sort().join(",") !== "credits,pack") {
      return { field: "grant.recorded" };
    }
    if (!Number.isInteger(r.credits) || r.credits < 1 || r.credits > 10 ** 7) return { field: "grant.recorded.credits" };
    if (typeof r.pack !== "string" || !PACK.test(r.pack)) return { field: "grant.recorded.pack" };
  } else if (keys === "credits") {
    if (!Number.isInteger(g.credits) || g.credits < 1 || g.credits > 10 ** 7) return { field: "grant.credits" };
  } else if (keys === "days,pins_per_day") {
    // a plan; the webhook never sends one
  } else {
    return { field: "grant" };
  }
  return { answer: { ...obj, email: e.toLowerCase() } };
}

function grantKind(grant) {
  return "recorded" in grant ? "recorded" : "spendable";
}

// A fake account service: checks by the rule above, applies each checkout id
// once in one kind, keeps a checkout with no customer id as unmatched, and
// answers like _checkout does.
function makeAccountService({ behaviour = "ok" } = {}) {
  const svc = { calls: [], byEmail: new Map(), checkouts: new Map(), kinds: new Map(), unmatched: new Map(),
    grants: [], recorded: [] };
  svc.handle = async (url, opts) => {
    const raw = Buffer.from(opts.body);
    const header = opts.headers["checkout-signature"];
    svc.calls.push({ url, method: opts.method, raw, header, headers: opts.headers, opts });
    if (behaviour === "throw") throw new Error("connect ECONNREFUSED");
    if (behaviour === "slow") {
      await new Promise((resolve, reject) => {
        const t = setTimeout(resolve, 5000);
        opts.signal.addEventListener("abort", () => {
          clearTimeout(t);
          const err = new Error("aborted");
          err.name = "AbortError";
          reject(err);
        });
      });
    }
    if (behaviour === "refuse") {
      return new Response(JSON.stringify({ status: "REFUSED", field: "customer", reason: "x" }), { status: 409 });
    }
    if (behaviour === "error") return new Response("upstream gone", { status: 502 });
    if (behaviour === "redirect") {
      // A real fetch follows a 307 unless redirect is "manual"; this fake
      // does the same, so a followed redirect shows up as a second call.
      if (!String(url).startsWith("https://elsewhere.test.invalid") && opts.redirect !== "manual") {
        return svc.handle("https://elsewhere.test.invalid/take", opts);
      }
      return new Response("", { status: 307, headers: { location: "https://elsewhere.test.invalid/take" } });
    }
    const checked = accountServiceCheck(raw, header, ACCOUNTS_SECRET, Math.floor(Date.now() / 1000));
    if (checked.field) {
      return new Response(JSON.stringify({ status: "REFUSED", field: checked.field, reason: "refused" }), { status: 401 });
    }
    const a = checked.answer;
    const kind = grantKind(a.grant);
    const done = svc.checkouts.get(a.checkout);
    const held = svc.unmatched.get(a.checkout);
    const was = done ? svc.kinds.get(a.checkout) : held ? grantKind(held.grant) : null;
    if (was !== null && was !== kind) {
      return new Response(JSON.stringify({ status: "REFUSED", field: "checkout", reason: "applied already as the other kind" }),
        { status: 409 });
    }
    let account = done;
    if (!account) {
      if (a.customer === null) {
        if (!held) svc.unmatched.set(a.checkout, { checkout: a.checkout, email: a.email, grant: a.grant });
        return new Response(JSON.stringify({ field: "customer", kept: "unmatched", reason: "no customer id",
          status: "UNMATCHED" }), { status: 202 });
      }
      account = svc.byEmail.get(a.email) || crypto.randomBytes(16).toString("hex");
      svc.byEmail.set(a.email, account);
      svc.checkouts.set(a.checkout, account);
      svc.kinds.set(a.checkout, kind);
      if (kind === "recorded") {
        svc.recorded.push({ account, checkout: a.checkout, credits: a.grant.recorded.credits, pack: a.grant.recorded.pack });
      } else {
        svc.grants.push({ account, checkout: a.checkout, credits: a.grant.credits });
      }
    }
    return new Response(JSON.stringify({ account, kept: kind, status: "OK" }), { status: 200 });
  };
  return svc;
}

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

let gh;
let restoreStore;
let svc;
let lines;
let saved;
let originalConsoleError;

function useService(s) {
  svc = s;
  const storeFetch = global.fetch;
  global.fetch = (url, opts) => (String(url).startsWith(ACCOUNTS_BASE) ? svc.handle(url, opts) : storeFetch(url, opts));
}

beforeEach(() => {
  gh = new MockGitHubStore();
  restoreStore = install(gh);
  useService(makeAccountService());
  saved = {};
  for (const k of SETTINGS) saved[k] = process.env[k];
  process.env.WITNESS_ACCOUNTS_URL = ACCOUNTS_BASE;
  process.env.WITNESS_ACCOUNTS_CHECKOUT_SECRET = ACCOUNTS_SECRET;
  delete process.env.WITNESS_ACCOUNTS_FORWARD;
  lines = [];
  originalConsoleError = console.error;
  console.error = (...args) => {
    const line = args.map(String).join(" ");
    if (line.startsWith("[accounts-forward]")) lines.push(line);
    else originalConsoleError(...args);
  };
});

afterEach(() => {
  console.error = originalConsoleError;
  forward.TIMEOUT_MS = 3000;
  for (const k of SETTINGS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  restoreStore();
});

function paidEvent({ id = "evt-fwd-1", sessionId = "cs_live_fwd_1", hash, pack = "pins_200", amount = 500,
  email = EMAIL, customer = "cus_Fwd001", created = Math.floor(Date.now() / 1000) - 5,
  type = "checkout.session.completed" } = {}) {
  const object = {
    id: sessionId,
    payment_status: "paid",
    client_reference_id: hash,
    metadata: { pack },
    amount_total: amount,
    currency: "usd",
    customer,
    customer_details: email === null ? { email: null, name: "No Email" } : { email, name: "Buyer Person" },
  };
  return { id, type, livemode: true, created, data: { object } };
}

async function post(event) {
  const rawBody = Buffer.from(JSON.stringify(event), "utf8");
  const req = makeRawReq({ headers: { "stripe-signature": stripeSigHeader(STRIPE_SECRET, rawBody) }, rawBody });
  const res = makeRes();
  await webhook(req, res);
  return res;
}

function expectedAnswer(event, { credited = true, balanceAfter = 200 } = {}) {
  return {
    ok: true,
    pack: "pins_200",
    pack_source: "metadata",
    credited,
    already_credited: !credited,
    balance_after: balanceAfter,
    event_id: event.id,
    session_id: event.data.object.id,
  };
}

function assertNoSecretsIn(line) {
  assert.ok(!line.toLowerCase().includes(EMAIL.toLowerCase()), `the email must not be logged: ${line}`);
  assert.ok(!line.includes("@"), `no email of any form in the log: ${line}`);
  assert.ok(!line.includes(ACCOUNTS_SECRET), `the secret must not be logged: ${line}`);
  assert.ok(!line.includes("v1="), `the signature must not be logged: ${line}`);
  assert.ok(!line.includes("{"), `no body in the log: ${line}`);
}

// ---------------------------------------------------------------------
// Off, dry-run, bad settings
// ---------------------------------------------------------------------

test("FORWARD off (unset): sends nothing, logs nothing, credit and answer as today", async () => {
  const hash = "a1".repeat(32);
  const event = paidEvent({ hash });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.deepEqual(res._body, expectedAnswer(event));
  assert.equal(svc.calls.length, 0);
  assert.equal(lines.length, 0);
  assert.equal((await balance.readBalance(hash)).balance, 200);
});

test("FORWARD off (explicit): sends nothing and logs nothing", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "off";
  const hash = "a2".repeat(32);
  const res = await post(paidEvent({ hash }));
  assert.equal(res._status, 200);
  assert.equal(svc.calls.length, 0);
  assert.equal(lines.length, 0);
});

test("FORWARD dry-run: builds and signs, sends nothing, logs one line with no email, secret, signature or body", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "dry-run";
  const hash = "a3".repeat(32);
  const event = paidEvent({ hash, sessionId: "cs_live_dry_1" });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.deepEqual(res._body, expectedAnswer(event));
  assert.equal(svc.calls.length, 0, "dry-run must send nothing");
  assert.equal(lines.length, 1);
  assert.match(lines[0], /dry-run: built and signed/);
  assert.match(lines[0], /session=cs_live_dry_1/);
  assertNoSecretsIn(lines[0]);
});

for (const bad of ["ON", "On", "yes", "true", "1", "dryrun", " on", "on "]) {
  test(`FORWARD bad setting ${JSON.stringify(bad)} counts as off: nothing sent, one line saying so`, async () => {
    process.env.WITNESS_ACCOUNTS_FORWARD = bad;
    const hash = crypto.createHash("sha256").update(`bad-${bad}`).digest("hex");
    const event = paidEvent({ hash });
    const res = await post(event);
    assert.equal(res._status, 200);
    assert.deepEqual(res._body, expectedAnswer(event));
    assert.equal(svc.calls.length, 0);
    assert.equal(lines.length, 1);
    assert.match(lines[0], /counted as off, nothing sent/);
    assert.ok(!lines[0].includes(`"${bad}"`), "no part of the value is printed");
    assertNoSecretsIn(lines[0]);
  });
}

test("FORWARD bad setting: the secret pasted into WITNESS_ACCOUNTS_FORWARD is never printed, not even a part", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = ACCOUNTS_SECRET;
  await post(paidEvent({ hash: "a4".repeat(32) }));
  assert.equal(svc.calls.length, 0);
  assert.equal(lines.length, 1);
  assert.equal(lines[0], "[accounts-forward] WITNESS_ACCOUNTS_FORWARD is not off, dry-run or on; counted as off, nothing sent");
  for (const part of ["checkout-secret", ACCOUNTS_SECRET.slice(-12), ACCOUNTS_SECRET.slice(9, 30)]) {
    assert.ok(!lines[0].includes(part));
  }
});

// ---------------------------------------------------------------------
// On
// ---------------------------------------------------------------------

test("FORWARD on: exactly one signed POST with the account service's body, accepted by its rule", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const hash = "b1".repeat(32);
  const created = Math.floor(Date.now() / 1000) - 30;
  const event = paidEvent({ hash, sessionId: "cs_live_on_1", customer: "cus_On001", created });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.deepEqual(res._body, expectedAnswer(event));
  assert.equal((await balance.readBalance(hash)).balance, 200, "the key's credit is applied as today");

  assert.equal(svc.calls.length, 1);
  const call = svc.calls[0];
  assert.equal(call.url, `${ACCOUNTS_BASE}/accounts/v1/checkout`);
  assert.equal(call.method, "POST");
  assert.equal(call.headers["content-type"], "application/json");
  assert.deepEqual(JSON.parse(call.raw.toString("utf8")), {
    checkout: "cs_live_on_1",
    completed_at: new Date(created * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
    customer: "cus_On001",
    email: EMAIL,
    grant: { recorded: { credits: 200, pack: "pins_200" } },
    kind: "checkout",
    v: 1,
  });
  const checked = accountServiceCheck(call.raw, call.header, ACCOUNTS_SECRET, Math.floor(Date.now() / 1000));
  assert.equal(checked.field, undefined, `the account service's rule must accept it (refused ${checked.field})`);
  assert.equal(checked.answer.email, EMAIL.toLowerCase(), "keyed by the buyer's email, lower case on the service");
  assert.equal(svc.recorded.length, 1, "kept as a recorded purchase");
  assert.equal(svc.recorded[0].credits, 200);
  assert.equal(svc.recorded[0].pack, "pins_200");
  assert.equal(svc.grants.length, 0, "never a spendable grant");

  // the same request under the wrong secret, or late, is refused by the rule
  assert.equal(accountServiceCheck(call.raw, call.header, "x".repeat(40), Math.floor(Date.now() / 1000)).field, "signature");
  assert.equal(accountServiceCheck(call.raw, call.header, ACCOUNTS_SECRET, Math.floor(Date.now() / 1000) + 301).field, "timestamp");
  assert.equal(accountServiceCheck(Buffer.concat([call.raw, Buffer.from(" ")]), call.header, ACCOUNTS_SECRET,
    Math.floor(Date.now() / 1000)).field, "signature", "one byte more and the signature fails");

  assert.equal(lines.length, 1);
  assert.match(lines[0], /on: forwarded: session=cs_live_on_1 pack=pins_200 credits=200 status=200/);
  assertNoSecretsIn(lines[0]);
});

test("FORWARD on: a pins_1000 pack forwards 1000 credits; an expanded customer object forwards its id", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const hash = "b2".repeat(32);
  const event = paidEvent({ hash, sessionId: "cs_live_on_2", pack: "pins_1000", amount: 2000 });
  event.data.object.customer = { id: "cus_Expanded02", object: "customer" };
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.equal(svc.calls.length, 1);
  const body = JSON.parse(svc.calls[0].raw.toString("utf8"));
  assert.deepEqual(body.grant, { recorded: { credits: 1000, pack: "pins_1000" } });
  assert.equal(body.customer, "cus_Expanded02");
});

test("FORWARD on: the email falls back to customer_email when customer_details has none", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const hash = "b3".repeat(32);
  const event = paidEvent({ hash, sessionId: "cs_live_on_3", email: null });
  event.data.object.customer_email = "opened.with@example.org";
  await post(event);
  assert.equal(svc.calls.length, 1);
  assert.equal(JSON.parse(svc.calls[0].raw.toString("utf8")).email, "opened.with@example.org");
});

// ---------------------------------------------------------------------
// The account service failing never changes the answer or the credit
// ---------------------------------------------------------------------

for (const behaviour of ["refuse", "error", "throw", "slow", "redirect"]) {
  test(`FORWARD on, account service ${behaviour}: the webhook's answer and the credit are unchanged, one line`, async () => {
    process.env.WITNESS_ACCOUNTS_FORWARD = "on";
    forward.TIMEOUT_MS = 50;
    useService(makeAccountService({ behaviour }));
    const hash = crypto.createHash("sha256").update(`fail-${behaviour}`).digest("hex");
    const event = paidEvent({ hash, sessionId: `cs_live_fail_${behaviour}` });
    const res = await post(event);
    assert.equal(res._status, 200);
    assert.deepEqual(res._body, expectedAnswer(event));
    assert.equal((await balance.readBalance(hash)).balance, 200);
    assert.equal(svc.calls.length, 1);
    assert.equal(lines.length, 1);
    assert.match(lines[0], ["refuse", "error", "redirect"].includes(behaviour) ? /forward refused, status/ : /forward failed/);
    assert.match(lines[0], new RegExp(`session=cs_live_fail_${behaviour}`));
    assert.match(lines[0], /one time script/);
    if (behaviour === "refuse") assert.match(lines[0], /status 409 field=customer/);
    if (behaviour === "slow") assert.match(lines[0], /no answer within 50 ms/);
    if (behaviour === "redirect") {
      assert.match(lines[0], /status 307/);
      assert.equal(svc.calls[0].opts.redirect, "manual", "redirects are never followed");
      assert.ok(svc.calls.every((c) => String(c.url).startsWith(ACCOUNTS_BASE)), "the signed body never goes to another origin");
    }
    assertNoSecretsIn(lines[0]);
  });
}

test("FORWARD on, a credit store error: the webhook answers 500 as today and forwards nothing", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const hash = "b4".repeat(32);
  const storeFetch = global.fetch;
  global.fetch = (url, opts) =>
    String(url).startsWith(ACCOUNTS_BASE) ? svc.handle(url, opts) : Promise.resolve(new Response("down", { status: 503 }));
  const res = await post(paidEvent({ hash, sessionId: "cs_live_store_down" }));
  global.fetch = storeFetch;
  assert.equal(res._status, 500);
  assert.equal(svc.calls.length, 0, "nothing is forwarded for a checkout whose credit was not applied");
});

// ---------------------------------------------------------------------
// What is never forwarded
// ---------------------------------------------------------------------

test("FORWARD on, a checkout with no email: nothing sent, one line naming no email", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const hash = "c1".repeat(32);
  const event = paidEvent({ hash, sessionId: "cs_live_noemail", email: null });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.deepEqual(res._body, expectedAnswer(event));
  assert.equal(svc.calls.length, 0);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /not forwarded, the checkout carries no email: session=cs_live_noemail/);
});

test("FORWARD dry-run, a checkout with no email: nothing built, one line", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "dry-run";
  const hash = "c2".repeat(32);
  await post(paidEvent({ hash, email: null }));
  assert.equal(svc.calls.length, 0);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^\[accounts-forward\] dry-run: not forwarded, the checkout carries no email/);
});

test("FORWARD on, a checkout with no customer id: sent without customer, the 202 UNMATCHED is logged as kept unmatched", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const hash = "c3".repeat(32);
  const event = paidEvent({ hash, sessionId: "cs_live_nocus", customer: null });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.deepEqual(res._body, expectedAnswer(event));
  assert.equal((await balance.readBalance(hash)).balance, 200, "the key's credit is applied as today");
  assert.equal(svc.calls.length, 1, "sent, not skipped");
  const body = JSON.parse(svc.calls[0].raw.toString("utf8"));
  assert.ok(!("customer" in body), "no customer field and no stand in id");
  assert.deepEqual(Object.keys(body), ["checkout", "completed_at", "email", "grant", "kind", "v"]);
  assert.deepEqual(body.grant, { recorded: { credits: 200, pack: "pins_200" } });
  assert.equal(svc.unmatched.size, 1, "kept on the account service's unmatched list");
  assert.equal(svc.checkouts.size, 0, "attached to no account");
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^\[accounts-forward\] on: kept unmatched for the owner, the checkout names no customer id: session=cs_live_nocus pack=pins_200 credits=200 status=202$/);
  assert.ok(!/refused|failed|one time script/.test(lines[0]), "not a refusal and not a miss");
  assertNoSecretsIn(lines[0]);

  // a provider retry: unmatched again, still one line, still kept once
  lines.length = 0;
  await post(event);
  assert.equal(svc.calls.length, 2);
  assert.equal(svc.unmatched.size, 1);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /kept unmatched for the owner/);
});

test("FORWARD on, the service says applied already as the other kind (409 checkout): one line to look into", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const hash = "c6".repeat(32);
  // the same checkout id applied earlier at the service as a spendable grant
  svc.checkouts.set("cs_live_kind_1", "a".repeat(32));
  svc.kinds.set("cs_live_kind_1", "spendable");
  const event = paidEvent({ hash, sessionId: "cs_live_kind_1" });
  const res = await post(event);
  assert.equal(res._status, 200);
  assert.deepEqual(res._body, expectedAnswer(event));
  assert.equal((await balance.readBalance(hash)).balance, 200);
  assert.equal(svc.calls.length, 1);
  assert.equal(svc.recorded.length, 0, "never both recorded and spendable");
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^\[accounts-forward\] on: applied already as the other kind \(recorded or spendable\), look into it: session=cs_live_kind_1 pack=pins_200 status 409 field=checkout$/);
  assert.ok(!/forwarded:|refused|one time script/.test(lines[0]));
  assertNoSecretsIn(lines[0]);
  const out = await forward.forwardCheckout({ session: event.data.object, pack: "pins_200", pins: 200 }, process.env);
  assert.deepEqual(out, { outcome: "other-kind", status: 409, field: "checkout" });
});

test("FORWARD on, a 409 naming customer is still a refusal, not the other kind", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  useService(makeAccountService({ behaviour: "refuse" }));
  await post(paidEvent({ hash: "c7".repeat(32), sessionId: "cs_live_kind_2" }));
  assert.equal(lines.length, 1);
  assert.match(lines[0], /forward refused, status 409 field=customer/);
});

for (const [name, pack] of [
  ["upper case", "Pins_200"],
  ["a space", "pins 200"],
  ["empty", ""],
  ["a leading hyphen", "-pins"],
  ["65 characters", "p".repeat(65)],
  ["not a string", 200],
  ["missing", undefined],
]) {
  test(`FORWARD on, a pack id with ${name}: nothing sent, one line`, async () => {
    process.env.WITNESS_ACCOUNTS_FORWARD = "on";
    const session = { id: "cs_live_pack_bad", customer: "cus_Pack01", customer_details: { email: EMAIL } };
    const out = await forward.forwardCheckout({ session, pack, pins: 200 }, process.env);
    assert.deepEqual(out, { outcome: "skipped", reason: "the pack is not a pack id the account service takes" });
    assert.equal(svc.calls.length, 0);
    assert.equal(lines.length, 1);
    assert.equal(lines[0], "[accounts-forward] on: not forwarded, the pack is not a pack id the account service takes: session=cs_live_pack_bad");
  });
}

test("FORWARD buildForward: the pack shape is the service's own, 1 to 64 of a-z 0-9 _ -, first a letter or digit", () => {
  const base = { session: { id: "cs_x", customer: "cus_x", customer_details: { email: "a@b.org" } }, pins: 5, nowSeconds: 1 };
  for (const ok of ["a", "0", "pins_200", "pins-1000", "p".repeat(64)]) {
    assert.ok(forward.buildForward({ ...base, pack: ok }).body, ok);
  }
  for (const bad of ["_a", "A", "a.b", "p".repeat(65), "a\n"]) {
    assert.equal(forward.buildForward({ ...base, pack: bad }).body, null, bad);
  }
});

test("FORWARD buildForward: the recorded body exactly, keys sorted, customer kept and left out", () => {
  const session = { id: "cs_live_exact_1", customer: "cus_Exact01", customer_details: { email: "a.b@example.org" } };
  const built = forward.buildForward({ session, pack: "pins_200", pins: 200, completedSeconds: 1793923200, nowSeconds: 0 });
  assert.equal(built.skip, null);
  assert.equal(
    built.body.toString("utf8"),
    '{"checkout":"cs_live_exact_1","completed_at":"2026-11-06T00:00:00Z","customer":"cus_Exact01",' +
      '"email":"a.b@example.org","grant":{"recorded":{"credits":200,"pack":"pins_200"}},"kind":"checkout","v":1}'
  );
  const none = forward.buildForward({ session: { ...session, customer: null }, pack: "pins_1000", pins: 1000,
    completedSeconds: 1793923200, nowSeconds: 0 });
  assert.equal(
    none.body.toString("utf8"),
    '{"checkout":"cs_live_exact_1","completed_at":"2026-11-06T00:00:00Z",' +
      '"email":"a.b@example.org","grant":{"recorded":{"credits":1000,"pack":"pins_1000"}},"kind":"checkout","v":1}'
  );
  const bad = forward.buildForward({ session: { ...session, customer: "cus with space" }, pack: "pins_200", pins: 200,
    nowSeconds: 1 });
  assert.equal(bad.body, null);
  assert.match(bad.skip, /customer id the account service would refuse/);
});

test("FORWARD on, an unpaid or unpriced checkout is never forwarded (no credit, no forward)", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const unpaid = paidEvent({ hash: "c4".repeat(32), sessionId: "cs_live_unpaid" });
  unpaid.data.object.payment_status = "unpaid";
  assert.equal((await post(unpaid))._status, 200);
  const cheap = paidEvent({ hash: "c5".repeat(32), sessionId: "cs_live_cheap", amount: 100 });
  assert.equal((await post(cheap))._status, 200);
  assert.equal(svc.calls.length, 0);
  assert.equal(lines.length, 0);
});

for (const [name, setting] of [
  ["no WITNESS_ACCOUNTS_URL", { WITNESS_ACCOUNTS_URL: undefined }],
  ["an http address", { WITNESS_ACCOUNTS_URL: "http://accounts.test.invalid" }],
  ["an address with a user name", { WITNESS_ACCOUNTS_URL: "https://u:p@accounts.test.invalid" }],
  ["no secret", { WITNESS_ACCOUNTS_CHECKOUT_SECRET: undefined }],
  ["a secret shorter than 32 bytes", { WITNESS_ACCOUNTS_CHECKOUT_SECRET: "short-secret" }],
]) {
  test(`FORWARD on with ${name}: nothing sent, one line, answer unchanged`, async () => {
    process.env.WITNESS_ACCOUNTS_FORWARD = "on";
    for (const [k, v] of Object.entries(setting)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    const hash = crypto.createHash("sha256").update(`setting-${name}`).digest("hex");
    const event = paidEvent({ hash });
    const res = await post(event);
    assert.deepEqual(res._body, expectedAnswer(event));
    assert.equal(svc.calls.length, 0);
    assert.equal(lines.length, 1);
    assert.match(lines[0], /not forwarded, WITNESS_ACCOUNTS_/);
    assert.ok(!lines[0].includes("short-secret"));
    assertNoSecretsIn(lines[0]);
  });
}

// ---------------------------------------------------------------------
// Idempotency: a provider retry forwards the same checkout id again
// ---------------------------------------------------------------------

test("FORWARD on, a provider retry: the same checkout id is forwarded again, the service attaches it once", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const hash = "d1".repeat(32);
  const event = paidEvent({ hash, id: "evt-retry-1", sessionId: "cs_live_retry_1" });
  const first = await post(event);
  const second = await post(event);
  assert.deepEqual(first._body, expectedAnswer(event));
  assert.deepEqual(second._body, expectedAnswer(event, { credited: false }));
  assert.equal((await balance.readBalance(hash)).balance, 200, "credited once");
  assert.equal(svc.calls.length, 2, "forwarded on both deliveries");
  const ids = svc.calls.map((c) => JSON.parse(c.raw.toString("utf8")).checkout);
  assert.deepEqual(ids, ["cs_live_retry_1", "cs_live_retry_1"]);
  assert.equal(svc.recorded.length, 1, "the account service attaches the checkout once");

  // the async success event for the same session: a third forward, same id
  const asyncEvent = paidEvent({ hash, id: "evt-retry-2", sessionId: "cs_live_retry_1",
    type: "checkout.session.async_payment_succeeded" });
  await post(asyncEvent);
  assert.equal(svc.calls.length, 3);
  assert.equal(JSON.parse(svc.calls[2].raw.toString("utf8")).checkout, "cs_live_retry_1");
  assert.equal(svc.recorded.length, 1);
});

// ---------------------------------------------------------------------
// Review follow ups: what a retry forwards, a bad provider signature, the
// email shape, the base address
// ---------------------------------------------------------------------

test("FORWARD on, a retry after another path credited the session: the pins actually granted are forwarded", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const hash = "e1".repeat(32);
  // the session was credited first under a legacy pack of 1000 pins (as an
  // old link or the fulfill page could), then the webhook arrives naming pins_200
  await balance.creditPack(hash, "mini", "cs_live_granted_1", "fulfill");
  const event = paidEvent({ hash, sessionId: "cs_live_granted_1" });
  const res = await post(event);
  assert.equal(res._body.already_credited, true);
  assert.equal(svc.calls.length, 1);
  assert.deepEqual(JSON.parse(svc.calls[0].raw.toString("utf8")).grant, { recorded: { credits: 1000, pack: "mini" } },
    "the grant on record, pack and pins both, not the pack the retry names");
  assert.match(lines[0], /on: forwarded: session=cs_live_granted_1 pack=mini credits=1000 status=200/);
});

test("FORWARD on, a retry whose grant record holds no pack: nothing forwarded, the pack line", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const hash = "e4".repeat(32);
  const event = paidEvent({ hash, sessionId: "cs_live_granted_3" });
  await post(event);
  assert.equal(svc.calls.length, 1);
  const repo = gh._repoMap(process.env.GITHUB_USAGE_REPO);
  const path = `ledger/${hash}/grant-cs_live_granted_3.json`;
  const entry = repo.get(path);
  const rec = JSON.parse(entry.content);
  delete rec.pack;
  repo.set(path, { ...entry, content: JSON.stringify(rec) });
  lines.length = 0;
  const again = await post(event);
  assert.deepEqual(again._body, expectedAnswer(event, { credited: false }));
  assert.equal(svc.calls.length, 1, "an unknown pack is never guessed from the retry");
  assert.equal(lines.length, 1);
  assert.equal(lines[0], "[accounts-forward] on: not forwarded, the pack is not a pack id the account service takes: session=cs_live_granted_3");
});

test("FORWARD on, a retry whose grant record cannot be read: nothing forwarded, one line", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const hash = "e2".repeat(32);
  const event = paidEvent({ hash, sessionId: "cs_live_granted_2" });
  await post(event);
  assert.equal(svc.calls.length, 1);
  gh._repoMap(process.env.GITHUB_USAGE_REPO).delete(`ledger/${hash}/grant-cs_live_granted_2.json`);
  lines.length = 0;
  const again = await post(event);
  assert.deepEqual(again._body, expectedAnswer(event, { credited: false }));
  assert.equal(svc.calls.length, 1, "an unknown grant size is never guessed");
  assert.equal(lines.length, 1);
  assert.match(lines[0], /not forwarded, the pins granted for this checkout are not known/);
});

test("FORWARD on, a bad provider signature: 400 as today and nothing forwarded", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  const event = paidEvent({ hash: "e3".repeat(32), sessionId: "cs_live_badsig" });
  const rawBody = Buffer.from(JSON.stringify(event), "utf8");
  const req = makeRawReq({ headers: { "stripe-signature": stripeSigHeader("whsec_wrong", rawBody) }, rawBody });
  const res = makeRes();
  await webhook(req, res);
  assert.equal(res._status, 400);
  assert.equal(svc.calls.length, 0);
  assert.equal(lines.length, 0);
});

for (const [name, email] of [
  ["white space", "buyer person@example.org"],
  ["a trailing space", "buyer@example.org "],
  ["no at sign", "buyer.example.org"],
  ["two at signs", "a@b@example.org"],
  ["no dot in the domain", "buyer@localhost"],
  ["a domain ending in a dot", "buyer@example.org."],
  ["a letter outside plain ASCII", "b\u00fcyer@example.org"],
  ["more than 254 characters", `${"b".repeat(250)}@example.org`],
]) {
  test(`FORWARD on, an email with ${name}: nothing sent, one line, the email not logged`, async () => {
    process.env.WITNESS_ACCOUNTS_FORWARD = "on";
    const hash = crypto.createHash("sha256").update(`email-${name}`).digest("hex");
    const event = paidEvent({ hash, email });
    const res = await post(event);
    assert.deepEqual(res._body, expectedAnswer(event));
    assert.equal(svc.calls.length, 0);
    assert.equal(lines.length, 1);
    assert.match(lines[0], /not forwarded, the checkout carries no usable email/);
    assertNoSecretsIn(lines[0]);
  });
}

// ---------------------------------------------------------------------
// The shared test vector (the Python side checks the same bytes)
// ---------------------------------------------------------------------

const VECTOR_SECRET = "arcaeon-shared-test-vector-secret-0001";

test("FORWARD shared vector 0001: a recorded grant with a customer, body and Checkout-Signature byte for byte", () => {
  const built = forward.buildForward({
    session: { id: "cs_test_vector_0001", customer: "cus_test_vector_0001", customer_details: { email: "buyer@example.org" } },
    pack: "pins_200",
    pins: 200,
    completedSeconds: 1793923200,
    nowSeconds: 0,
  });
  assert.equal(
    built.body.toString("utf8"),
    '{"checkout":"cs_test_vector_0001","completed_at":"2026-11-06T00:00:00Z","customer":"cus_test_vector_0001",' +
      '"email":"buyer@example.org","grant":{"recorded":{"credits":200,"pack":"pins_200"}},"kind":"checkout","v":1}'
  );
  const header = forward.signForward(VECTOR_SECRET, built.body, 1793923200);
  assert.equal(header, "t=1793923200,v1=d0598b9ae9994ccd14380099c332479422b3ef8ba8922c077942773879ce5307");
  const checked = accountServiceCheck(built.body, header, VECTOR_SECRET, 1793923200);
  assert.equal(checked.field, undefined);
});

test("FORWARD shared vector 0002: a recorded grant with no customer, body and Checkout-Signature byte for byte", () => {
  const built = forward.buildForward({
    session: { id: "cs_test_vector_0002", customer: null, customer_details: { email: "buyer@example.org" } },
    pack: "pins_1000",
    pins: 1000,
    completedSeconds: 1793923200,
    nowSeconds: 0,
  });
  assert.equal(
    built.body.toString("utf8"),
    '{"checkout":"cs_test_vector_0002","completed_at":"2026-11-06T00:00:00Z",' +
      '"email":"buyer@example.org","grant":{"recorded":{"credits":1000,"pack":"pins_1000"}},"kind":"checkout","v":1}'
  );
  const header = forward.signForward(VECTOR_SECRET, built.body, 1793923200);
  assert.equal(header, "t=1793923200,v1=bc6698afe26c6aa0e665cd9823f139e434a50fe7039d168a51500f667dd9df4e");
  const checked = accountServiceCheck(built.body, header, VECTOR_SECRET, 1793923200);
  assert.equal(checked.field, undefined);
  assert.equal(checked.answer.customer, null);
});

test("FORWARD readMode: only off, dry-run and on are read; unset is off with no line", () => {
  assert.deepEqual(forward.readMode({}), { mode: "off", logged: false });
  assert.deepEqual(forward.readMode({ WITNESS_ACCOUNTS_FORWARD: "on" }), { mode: "on", logged: false });
  assert.deepEqual(forward.readMode({ WITNESS_ACCOUNTS_FORWARD: "dry-run" }), { mode: "dry-run", logged: false });
  assert.deepEqual(forward.readMode({ WITNESS_ACCOUNTS_FORWARD: "maybe" }), { mode: "off", logged: true });
  assert.equal(lines.length, 1);
});

test("FORWARD checkoutUrl: the path is added once, a trailing slash or a base path is kept tidy", () => {
  assert.equal(forward.checkoutUrl("https://a.example/").url, "https://a.example/accounts/v1/checkout");
  assert.equal(forward.checkoutUrl("https://a.example/base/").url, "https://a.example/base/accounts/v1/checkout");
  assert.equal(forward.checkoutUrl("https://a.example/accounts/v1/checkout").url, "https://a.example/accounts/v1/checkout");
  assert.equal(forward.checkoutUrl("https://a.example/accounts/v1/checkout/").url, "https://a.example/accounts/v1/checkout");
  assert.equal(forward.checkoutUrl("https://a.example/base/accounts/v1/checkout").url, "https://a.example/base/accounts/v1/checkout");
  assert.equal(forward.checkoutUrl("https://a.example?x=1").url, null);
  assert.equal(forward.checkoutUrl("not an address").url, null);
});
