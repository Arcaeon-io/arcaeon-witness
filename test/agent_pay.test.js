// test/agent_pay.test.js — agents pay per pin (AGENT_PAYMENTS.md): the 402,
// both adapters against mocks, one pin per payment, release on a failed write.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_KEYS = "agentkeyA:agent-a-,agentkeyB:agent-b-";
delete process.env.WITNESS_CADENCE;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

const { MockGitHubStore } = require("./helpers/mock_store.js");
const { MockProcessor, MockNode, installAll, PROCESSOR_URL, NODE_URL } = require("./helpers/mock_payments.js");
const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const meter = require("../lib/_meter.js");
const agentPay = require("../lib/_agent_pay.js");
// Reloaded per test: its per instance rate limit (60 per key per hour) would
// otherwise be spent by the earlier tests in this file.
let pinHandler;

const PIN_REPO = process.env.GITHUB_PIN_REPO;
const USAGE_REPO = process.env.GITHUB_USAGE_REPO;
const SECRETS = {
  WITNESS_PAY_SECRET: "test-pay-secret-0123456789abcdef0123456789",
  WITNESS_PAY_X402_KEY: "sk_test_processor_never_print",
  WITNESS_PAY_L402_MACAROON: "0201036c6e64deadbeef",
};
const ENV = {
  WITNESS_AGENT_PAY: "on",
  WITNESS_PAY_SECRET: SECRETS.WITNESS_PAY_SECRET,
  WITNESS_PAY_X402: "on",
  WITNESS_PAY_X402_API: PROCESSOR_URL,
  WITNESS_PAY_X402_KEY: SECRETS.WITNESS_PAY_X402_KEY,
  WITNESS_PAY_X402_PAY_TO: "acct_witness",
  WITNESS_PAY_X402_ASSET: "USDC",
  WITNESS_PAY_X402_NETWORK: "base",
  WITNESS_PAY_X402_AMOUNT: "10000",
  WITNESS_PAY_L402: "on",
  WITNESS_PAY_L402_NODE: NODE_URL,
  WITNESS_PAY_L402_MACAROON: SECRETS.WITNESS_PAY_L402_MACAROON,
  WITNESS_PAY_L402_SATS: "31",
};

let gh, processor, node, restore, saved;
const realPutSleep = store._putRetry.sleep;

beforeEach(() => {
  saved = { ...process.env };
  Object.assign(process.env, ENV);
  // Both keys have spent their free tier: cap 0, no credits.
  process.env.WITNESS_PLANS = JSON.stringify({
    [meter.keyHash("agentkeyA")]: { plan: "free", monthly_cap: 0 },
    [meter.keyHash("agentkeyB")]: { plan: "free", monthly_cap: 0 },
  });
  gh = new MockGitHubStore();
  processor = new MockProcessor();
  node = new MockNode();
  restore = installAll(gh, processor, node);
  delete require.cache[require.resolve("../api/pin.js")];
  pinHandler = require("../api/pin.js");
  store._putRetry.sleep = async () => {};
});
afterEach(() => {
  store._putRetry.sleep = realPutSleep;
  restore();
  for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
  Object.assign(process.env, saved);
});

function body(over = {}) {
  return { namespace: "agent-a-mem", rows: 5, chain: "aaaaaaaa", ...over };
}
async function pin(b, { key = "agentkeyA", headers = {} } = {}) {
  const res = makeRes();
  await pinHandler(makeReq({ method: "POST", headers: { authorization: `Bearer ${key}`, ...headers }, body: b }), res);
  return res;
}
function x402Header(token, payment_id) {
  return { "x-payment": Buffer.from(JSON.stringify({ token, payment_id })).toString("base64") };
}
const pubWrites = () => gh.putLog.filter((p) => p.repo === PIN_REPO).length;
const accept = (res, a) => res._body.accepts.find((x) => x.adapter === a);

async function payX402(b = body(), opts = {}) {
  const q = await pin(b, opts);
  assert.equal(q._status, 402, JSON.stringify(q._body));
  const a = accept(q, "x402");
  const id = processor.pay(a);
  return { quote: a, id, res: await pin(b, { ...opts, headers: x402Header(a.token, id) }) };
}

// ---------------------------------------------------------------------------

test("FLAG OFF: a spent key gets the meter's 429 as before, no quotes, no node call", async () => {
  process.env.WITNESS_AGENT_PAY = "off";
  const res = await pin(body());
  assert.equal(res._status, 429);
  assert.equal(res._body.reason, "over_cap");
  assert.equal(node.calls.length, 0);
});

test("NO SECRET: without WITNESS_PAY_SECRET nothing is offered", async () => {
  delete process.env.WITNESS_PAY_SECRET;
  assert.equal(agentPay.enabled(), false);
  assert.equal((await pin(body()))._status, 429);
});

test("402: a spent key gets payment_required with one quote per adapter, bound to the request, and nothing is written", async () => {
  const res = await pin(body());
  assert.equal(res._status, 402);
  assert.equal(res._body.reason, "payment_required");
  assert.equal(res._body.field, "payment");
  assert.equal(res._body.meter_reason, "over_cap");
  assert.deepEqual(res._body.binding, { namespace: "agent-a-mem", rows: 5, chain: "aaaaaaaa", intent: "pin" });
  assert.deepEqual(res._body.accepts.map((a) => a.adapter).sort(), ["l402", "x402"]);
  const x = accept(res, "x402");
  assert.equal(x.amount, "10000");
  assert.equal(x.asset, "USDC");
  const l = accept(res, "l402");
  assert.equal(l.amount_sats, 31);
  assert.match(res._headers["www-authenticate"], /^L402 token="/);
  assert.equal(pubWrites(), 0);
});

test("X402: a paid retry pins once, charged by the payment, not the meter", async () => {
  const { res, id } = await payX402();
  assert.equal(res._status, 201, JSON.stringify(res._body));
  assert.equal(res._headers["x-meter-source"], "payment");
  assert.equal(res._headers["x-payment-method"], "x402");
  assert.equal(gh.read(PIN_REPO, "pins/agent-a-mem/latest.json").rows, 5);
  const ref = res._headers["x-payment-ref"];
  const rec = gh.read(USAGE_REPO, agentPay.ledgerPath("x402", ref));
  assert.equal(rec.state, "claimed");
  assert.equal(rec.amount, "10000");
  assert.ok(!JSON.stringify(rec).includes("agentkeyA"), "the ledger holds a key hash, never the key");
  const verifyCall = processor.calls.find((c) => c.url.endsWith("/v1/verify"));
  assert.equal(JSON.parse(verifyCall.body).payment_id, id);
});

test("L402: pay the invoice, retry with token and preimage, pin once", async () => {
  const q = await pin(body());
  const l = accept(q, "l402");
  const preimage = node.pay(l.payment_hash);
  const res = await pin(body(), { headers: { "x-l402": `${l.token}:${preimage}` } });
  assert.equal(res._status, 201, JSON.stringify(res._body));
  assert.equal(res._headers["x-payment-method"], "l402");
  assert.equal(res._headers["x-payment-ref"], l.payment_hash);
});

test("ONE PIN PER PAYMENT: a used payment cannot buy a second write", async () => {
  // A renewal writes every time, so it is the case where reuse would cost.
  const first = await payX402();
  assert.equal(first.res._status, 201);
  const renew = body({ intent: "renew" });
  const { quote, id, res } = await payX402(renew);
  assert.ok(res._status === 200 || res._status === 201, JSON.stringify(res._body));
  const writes = pubWrites();
  const again = await pin(renew, { headers: x402Header(quote.token, id) });
  assert.equal(again._status, 409);
  assert.equal(again._body.reason, "payment_already_used");
  assert.equal(pubWrites(), writes);
});

test("IDEMPOTENT: the same paid request sent again writes nothing and claims nothing", async () => {
  const { quote, id } = await payX402();
  const writes = pubWrites();
  const again = await pin(body(), { headers: x402Header(quote.token, id) });
  assert.ok(again._status === 200 || again._status === 201, JSON.stringify(again._body));
  assert.equal(pubWrites(), writes, "the re-pin of the current head writes nothing");
});

test("BINDING: a payment for one request cannot pay for another", async () => {
  const q = await pin(body());
  const a = accept(q, "x402");
  const id = processor.pay(a);
  // (A renewal on a namespace with no pin is refused 404 before any charge,
  // so intent is covered in RELEASE below, where a pin exists.)
  for (const other of [body({ rows: 6 }), body({ chain: "bbbbbbbb" }), body({ namespace: "agent-a-other" })]) {
    const res = await pin(other, { headers: x402Header(a.token, id) });
    assert.equal(res._status, 409, JSON.stringify(other));
    assert.equal(res._body.reason, "payment_for_other_request");
  }
  // Another key, same body: the binding carries the key too.
  process.env.WITNESS_KEYS = "agentkeyA:agent-a-,agentkeyB:agent-";
  const res = await pin(body(), { key: "agentkeyB", headers: x402Header(a.token, id) });
  assert.equal(res._body.reason, "payment_for_other_request");
  assert.equal(pubWrites(), 0);
});

test("NAMESPACE: payment never replaces the key check", async () => {
  const q = await pin(body());
  const a = accept(q, "x402");
  const id = processor.pay(a);
  const stranger = await pin(body(), { key: "agentkeyB", headers: x402Header(a.token, id) });
  assert.equal(stranger._status, 403);
  const nokey = makeRes();
  await pinHandler(makeReq({ method: "POST", headers: x402Header(a.token, id), body: body() }), nokey);
  assert.equal(nokey._status, 401);
  assert.equal(pubWrites(), 0);
});

test("TOKEN: a forged, tampered or expired token is refused 401 and nothing is charged", async () => {
  const q = await pin(body());
  const a = accept(q, "x402");
  const id = processor.pay(a);
  const [b64, mac] = a.token.split(".");
  const payload = JSON.parse(Buffer.from(b64, "base64url").toString());
  const tampered = Buffer.from(JSON.stringify({ ...payload, amount: "1" })).toString("base64url") + "." + mac;
  const r1 = await pin(body(), { headers: x402Header(tampered, id) });
  assert.equal(r1._body.reason, "bad_token_signature");
  const r2 = await pin(body(), { headers: x402Header("not-a-token", id) });
  assert.equal(r2._body.reason, "malformed_token");
  const expired = agentPay.sign({ ...payload, exp: Math.floor(Date.now() / 1000) - 1 });
  const r3 = await pin(body(), { headers: x402Header(expired, id) });
  assert.equal(r3._body.reason, "quote_expired");
  for (const r of [r1, r2, r3]) { assert.equal(r._status, 401); assert.equal(r._body.field, "x-payment"); }
  assert.equal(pubWrites(), 0);
});

test("X402 CHECKS: unknown, unsettled, too small or other terms are refused 402 naming the reason", async () => {
  const q = await pin(body());
  const a = accept(q, "x402");
  const cases = [
    ["pay_nope", "payment_not_found"],
    [processor.pay(a, { settled: false }), "payment_not_settled"],
    [processor.pay(a, { amount: "9999" }), "payment_too_small"],
    [processor.pay(a, { nonce: "0".repeat(32) }), "payment_terms_mismatch"],
    [processor.pay(a, { pay_to: "acct_someone_else" }), "payment_terms_mismatch"],
  ];
  for (const [id, reason] of cases) {
    const r = await pin(body(), { headers: x402Header(a.token, id) });
    assert.equal(r._status, 402, reason);
    assert.equal(r._body.reason, reason);
  }
  assert.equal(pubWrites(), 0);
});

test("L402 CHECKS: a wrong preimage, an unpaid invoice or an underpaid one is refused", async () => {
  const q = await pin(body());
  const l = accept(q, "l402");
  const wrong = await pin(body(), { headers: { "x-l402": `${l.token}:${"ab".repeat(32)}` } });
  assert.equal(wrong._body.reason, "preimage_mismatch");
  const inv = node.invoices.get(l.payment_hash);
  const unpaid = await pin(body(), { headers: { "x-l402": `${l.token}:${inv.preimage}` } });
  assert.equal(unpaid._body.reason, "payment_not_settled");
  node.pay(l.payment_hash, 30);
  const under = await pin(body(), { headers: { "x-l402": `${l.token}:${inv.preimage}` } });
  assert.equal(under._body.reason, "payment_too_small");
  const bad = await pin(body(), { headers: { "x-l402": `${l.token}:nothex` } });
  assert.equal(bad._status, 400);
  assert.equal(bad._body.field, "x-l402");
  assert.equal(pubWrites(), 0);
});

test("CHECKER DOWN: processor or node unreachable is a 503, nothing charged, nothing written", async () => {
  const q = await pin(body());
  const a = accept(q, "x402");
  const id = processor.pay(a);
  processor.down = true;
  const r = await pin(body(), { headers: x402Header(a.token, id) });
  assert.equal(r._status, 503);
  assert.equal(r._body.reason, "payment_check_unavailable");
  processor.down = false;
  const ok = await pin(body(), { headers: x402Header(a.token, id) });
  assert.equal(ok._status, 201, "the same payment works once the processor is back");
});

test("QUOTES: one adapter down still offers the other; both down is a 503 naming it", async () => {
  node.down = true;
  const one = await pin(body());
  assert.equal(one._status, 402);
  assert.deepEqual(one._body.accepts.map((a) => a.adapter), ["x402"]);
  assert.deepEqual(one._body.unavailable, [{ adapter: "l402", reason: "quote_unavailable" }]);
  delete process.env.WITNESS_PAY_X402;
  const none = await pin(body());
  assert.equal(none._status, 503);
  assert.equal(none._body.reason, "payment_unavailable");
});

test("ADAPTER NOT OFFERED: a proof for a switched off method is refused by name", async () => {
  const q = await pin(body());
  const l = accept(q, "l402");
  const pre = node.pay(l.payment_hash);
  delete process.env.WITNESS_PAY_L402;
  const r = await pin(body(), { headers: { "x-l402": `${l.token}:${pre}` } });
  assert.equal(r._status, 400);
  assert.equal(r._body.reason, "payment_method_not_offered");
});

test("TWO PROOFS: sending both headers is refused, not guessed, even when both are real", async () => {
  const q = await pin(body());
  const a = accept(q, "x402");
  const l = accept(q, "l402");
  const id = processor.pay(a);
  const pre = node.pay(l.payment_hash);
  const r = await pin(body(), { headers: { ...x402Header(a.token, id), "x-l402": `${l.token}:${pre}` } });
  assert.equal(r._status, 400);
  assert.equal(r._body.reason, "malformed_payment_proof");
  assert.equal(pubWrites(), 0);
});

test("WRONG HEADER: a Lightning token sent as a stablecoin proof is refused by name", async () => {
  const q = await pin(body());
  const l = accept(q, "l402");
  const r = await pin(body(), { headers: x402Header(l.token, "pay_whatever") });
  assert.equal(r._status, 401);
  assert.equal(r._body.reason, "token_for_other_method");
  assert.equal(processor.calls.length, 0, "the processor is not even asked");
});

test("NOT PAYABLE: a key with no cap configured keeps its 401; a payment does not answer a config fault", async () => {
  process.env.WITNESS_PLANS = JSON.stringify({ [meter.keyHash("agentkeyA")]: { plan: "no-such-plan" } });
  const r = await pin(body());
  assert.equal(r._status, 401);
  assert.equal(r._body.reason, "no_cap_configured");
  assert.equal(node.calls.length, 0);
});

test("RELEASE: a write that fails after the claim gives the payment back; the retry pins once", async () => {
  const q = await pin(body());
  const a = accept(q, "x402");
  const id = processor.pay(a);
  gh.forceFailure(PIN_REPO, "pins/agent-a-mem/00000001.json", 50, 500);
  const failed = await pin(body(), { headers: x402Header(a.token, id) });
  assert.equal(failed._status, 502, JSON.stringify(failed._body));
  const [ledger] = [...gh.repos.get(USAGE_REPO).keys()].filter((p) => p.startsWith("payments/x402/"));
  assert.equal(gh.read(USAGE_REPO, ledger).state, "released");
  gh.forceFailure(PIN_REPO, "pins/agent-a-mem/00000001.json", 0, 500);
  const retry = await pin(body(), { headers: x402Header(a.token, id) });
  assert.equal(retry._status, 201, JSON.stringify(retry._body));
  const rec = gh.read(USAGE_REPO, ledger);
  assert.equal(rec.state, "claimed");
  assert.equal(rec.reclaims, 1);
  const third = await pin(body({ intent: "renew" }), { headers: x402Header(a.token, id) });
  assert.equal(third._body.reason, "payment_for_other_request");
});

test("LEDGER DOWN: the claim cannot be recorded, so nothing is written", async () => {
  const q = await pin(body());
  const a = accept(q, "x402");
  const id = processor.pay(a);
  gh.commitsStatus = 200;
  const orig = gh.handleFetch.bind(gh);
  gh.handleFetch = async (url, opts) =>
    String(url).includes("/contents/payments/") ? { status: 500, ok: false, json: async () => ({}), text: async () => "" } : orig(url, opts);
  const r = await pin(body(), { headers: x402Header(a.token, id) });
  assert.equal(r._status, 503);
  assert.equal(r._body.reason, "payment_ledger_unavailable");
  assert.equal(pubWrites(), 0);
});

test("UNDER THE FREE CAP: no proof, no 402, the meter charges as before", async () => {
  process.env.WITNESS_PLANS = "{}";
  const res = await pin(body());
  assert.equal(res._status, 201);
  assert.equal(node.calls.length, 0, "no invoice is made for a pin the meter covers");
});

test("SECRETS: the processor key, the macaroon and the token secret never reach a response", async () => {
  const outs = [];
  const q = await pin(body());
  outs.push(q);
  const a = accept(q, "x402");
  const id = processor.pay(a);
  outs.push(await pin(body(), { headers: x402Header(a.token, id) }));
  outs.push(await pin(body({ rows: 9 }), { headers: x402Header(a.token, id) }));
  processor.down = true;
  outs.push(await pin(body({ rows: 9 })));
  for (const r of outs) {
    const text = JSON.stringify(r._body) + JSON.stringify(r._headers);
    for (const s of Object.values(SECRETS)) assert.ok(!text.includes(s), `leaked ${s}`);
  }
  assert.equal(processor.calls[0].headers.authorization, `Bearer ${SECRETS.WITNESS_PAY_X402_KEY}`);
  assert.equal(node.calls[0].headers["grpc-metadata-macaroon"], SECRETS.WITNESS_PAY_L402_MACAROON);
});

// --- the review's blocker and its three follow ups ---

test("RELEASE ON EVERY EARLY RETURN: charged, then a heal adopts another writer's higher head and the pass ends 409; the payment is given back", async () => {
  const first = await payX402(); // rows 5, seq 1
  assert.equal(first.res._status, 201);
  const slot = "pins/agent-a-mem/00000002.json";
  const orig = gh.handleFetch.bind(gh);
  let raced = false;
  gh.handleFetch = async (url, opts) => {
    if (!raced && opts && opts.method === "PUT" && String(url).endsWith(`/contents/${slot}`)) {
      raced = true;
      // Another writer lands a higher head in our slot a moment before us.
      const ours = JSON.parse(Buffer.from(JSON.parse(opts.body).content, "base64").toString());
      gh.seed(PIN_REPO, slot, { ...ours, rows: 10, chain: "cccccccc" });
    }
    return orig(url, opts);
  };
  const { quote, id, res } = await payX402(body({ rows: 6, chain: "bbbbbbbb" }));
  assert.equal(raced, true);
  assert.equal(res._status, 409, JSON.stringify(res._body));
  const ref = Object.keys(Object.fromEntries(gh.repos.get(USAGE_REPO))).filter((p) => p.startsWith("payments/x402/"))
    .map((p) => gh.read(USAGE_REPO, p)).find((r) => r.binding === agentPay.bindingOf({ key: "agentkeyA", ...body({ rows: 6, chain: "bbbbbbbb" }) }));
  assert.equal(ref.state, "released", "money taken for no write must be given back");
  assert.ok(quote && id);
});

test("PARTIAL WRITE: a heartbeat whose record landed keeps its payment; the retry cannot buy a second heartbeat", async () => {
  await payX402(); // rows 5, seq 1
  const renew = body({ intent: "renew" });
  const q = await pin(renew);
  const a = accept(q, "x402");
  const id = processor.pay(a);
  gh.forceFailure(PIN_REPO, "pins/agent-a-mem/latest.json", 50, 500);
  const failed = await pin(renew, { headers: x402Header(a.token, id) });
  assert.equal(failed._status, 502);
  assert.ok(gh.has(PIN_REPO, "pins/agent-a-mem/00000002.json"), "the heartbeat record landed");
  gh.forceFailure(PIN_REPO, "pins/agent-a-mem/latest.json", 0, 500);
  const retry = await pin(renew, { headers: x402Header(a.token, id) });
  assert.equal(retry._status, 409, JSON.stringify(retry._body));
  assert.equal(retry._body.reason, "payment_already_used");
  assert.equal(gh.has(PIN_REPO, "pins/agent-a-mem/00000003.json"), false, "no second heartbeat");
});

test("MISCONFIGURED KEY WITH A PROOF: still 401 no_cap_configured; the processor is not asked", async () => {
  const q = await pin(body());
  const a = accept(q, "x402");
  const id = processor.pay(a);
  process.env.WITNESS_PLANS = JSON.stringify({ [meter.keyHash("agentkeyA")]: { plan: "no-such-plan" } });
  const r = await pin(body(), { headers: x402Header(a.token, id) });
  assert.equal(r._status, 401);
  assert.equal(r._body.reason, "no_cap_configured");
  assert.equal(processor.calls.length, 0);
  assert.equal(pubWrites(), 0);
});

test("RELEASED OUTLIVES ITS QUOTE: a payment released after a failed write is redeemable after the quote expires", async () => {
  const q = await pin(body());
  const a = accept(q, "x402");
  const id = processor.pay(a);
  gh.forceFailure(PIN_REPO, "pins/agent-a-mem/00000001.json", 50, 500);
  assert.equal((await pin(body(), { headers: x402Header(a.token, id) }))._status, 502);
  gh.forceFailure(PIN_REPO, "pins/agent-a-mem/00000001.json", 0, 500);
  const realNow = Date.now;
  Date.now = () => realNow() + 20 * 60 * 1000;
  try {
    const late = await pin(body(), { headers: x402Header(a.token, id) });
    assert.equal(late._status, 201, JSON.stringify(late._body));
    // An unspent expired quote is still refused.
    const q2 = accept(await pin(body({ rows: 6 })), "x402");
    Date.now = () => realNow() + 40 * 60 * 1000;
    const r = await pin(body({ rows: 6 }), { headers: x402Header(q2.token, processor.pay(q2)) });
    assert.equal(r._body.reason, "quote_expired");
  } finally {
    Date.now = realNow;
  }
});

test("HTTPS ONLY: an adapter whose address is not https is not offered", async () => {
  process.env.WITNESS_PAY_L402_NODE = "http://node.test.invalid";
  process.env.WITNESS_PAY_X402_API = "http://processor.test.invalid";
  assert.equal(agentPay.enabled(), false);
});

// --- job 14: a paid pin gets the same signed receipt, and its record the payment reference ---

const receiptsMod = require("../lib/_receipt.js");
const RSEED = "22".repeat(32);
function receiptsOn() {
  process.env.WITNESS_RECEIPTS = "on";
  process.env.WITNESS_RECEIPT_KEY = RSEED;
}
const CH64 = "ab".repeat(32);

test("PAID: a paid pin is answered with the same signed receipt as any pin", async () => {
  receiptsOn();
  const { res } = await payX402(body({ chain: CH64 }));
  assert.equal(res._status, 201, JSON.stringify(res._body));
  const pub = receiptsMod.keyFromEnv().publicRaw;
  assert.deepEqual(receiptsMod.verify(res._body.receipt, pub), { ok: true });
  assert.deepEqual(res._body.receipt.head, { chain: CH64, kind: "head", n: 5, v: 1 });
  assert.deepEqual(res._body.receipt, receiptsMod.forRecord(res._body.pin).receipt, "the receipt is the record's, nothing more");
});

test("PAID: the public record carries the payment reference and nothing about the payer", async () => {
  const { res, id } = await payX402();
  const record = gh.read(PIN_REPO, "pins/agent-a-mem/latest.json");
  assert.deepEqual(record.payment, { method: "x402", ref: res._headers["x-payment-ref"] });
  const text = JSON.stringify(record);
  assert.ok(!text.includes(id), "not the processor's payment id");
  assert.ok(!text.includes("acct_witness") && !text.includes("agentkeyA"), "no account, no key");
  // Lightning: the invoice's payment hash.
  const q = await pin(body({ namespace: "agent-a-ln", rows: 2 }));
  const l = accept(q, "l402");
  const pre = node.pay(l.payment_hash);
  await pin(body({ namespace: "agent-a-ln", rows: 2 }), { headers: { "x-l402": `${l.token}:${pre}` } });
  assert.deepEqual(gh.read(PIN_REPO, "pins/agent-a-ln/latest.json").payment, { method: "l402", ref: l.payment_hash });
  assert.ok(!JSON.stringify(gh.read(PIN_REPO, "pins/agent-a-ln/latest.json")).includes(pre), "never the preimage");
});

test("PAID: a paid renewal's record carries its own payment; an unpaid pin carries none", async () => {
  await payX402();
  const { res } = await payX402(body({ intent: "renew" }));
  assert.equal(gh.read(PIN_REPO, "pins/agent-a-mem/latest.json").payment.ref, res._headers["x-payment-ref"]);
  process.env.WITNESS_PLANS = "{}";
  const free = await pin(body({ namespace: "agent-a-free" }));
  assert.equal(free._status, 201);
  assert.equal("payment" in gh.read(PIN_REPO, "pins/agent-a-free/latest.json"), false);
});
