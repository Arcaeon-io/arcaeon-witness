// test/move.test.js: POST /api/v1/move (lib/_move.js) and the freeze it
// puts on a moved key in lib/_balance.js.
//
// Env vars are set BEFORE requiring the modules under test: the usage and
// pin repositories are read into top level consts at require time.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_USAGE_BRANCH = "main";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.STAMP_REPO = "test-owner/test-stamps";
process.env.STAMP_BRANCH = "main";
process.env.STAMP_TOKEN = "test-stamp-token";
process.env.STAMP_DAILY_CAP = "500";
process.env.WITNESS_KEYS = "movekeyA:mv-,movekeyB:mv-";
process.env.WITNESS_STRIPE_WEBHOOK_SECRET = "whsec_move_test_only"; // test-only literal
process.env.WITNESS_STRIPE_LIVEMODE = "false";
process.env.WITNESS_STRIPE_SECRET_KEY = "sk_test_move_mock_only"; // test-only literal
delete process.env.WITNESS_PLANS;
delete process.env.WITNESS_ACCOUNTS_FORWARD;
delete process.env.WITNESS_MOVE_ANSWER_KEY;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("child_process");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRawReq, makeRes } = require("./helpers/http_mocks.js");
const { stripeSigHeader } = require("./helpers/stripe_sign.js");
const store = require("../lib/_store.js");
const balance = require("../lib/_balance.js");
const meter = require("../lib/_meter.js");
const move = require("../lib/_move.js");
const stamp = require("../lib/_stamp.js");
const pinHandler = require("../api/pin.js");
const distill = require("../api/distill.js");
const credit = require("../api/credit.js");
const webhook = require("../api/stripe-webhook.js");
const fulfill = require("../api/fulfill.js");

const USAGE = process.env.GITHUB_USAGE_REPO;
const PINS = process.env.GITHUB_PIN_REPO;
const ORIGIN = "arcaeon.io/witness/v1";
const MOVED_WORDS = "this pack moved to https://arcaeon.io/witness/v1; update the package";

// Throwaway keys, made fresh for this run. Neither is a real key.
const ASKER_KEYS = move.generateKeyHex();
const SELLER_KEYS = move.generateKeyHex();
const ASKER = { origin: ORIGIN, public_key: ASKER_KEYS.public_key, key_id: ASKER_KEYS.key_id };
const ENV = { WITNESS_MOVE_ANSWER_KEY: SELLER_KEYS.seed };
const NOW = Date.UTC(2030, 0, 15, 12, 0, 0);
const NOW_TEXT = "2030-01-15T12:00:00Z";

let gh;
let restore;
let realPutSleep;
beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
  realPutSleep = store._putRetry.sleep;
  store._putRetry.sleep = async () => {};
  stamp._resetLimiterForTests();
});
afterEach(() => {
  store._putRetry.sleep = realPutSleep;
  restore();
});

// ---- helpers ----
let nonceCounter = 0;
function nonce() {
  nonceCounter += 1;
  return nonceCounter.toString(16).padStart(32, "0");
}

function signedAsk(over = {}, seed = ASKER_KEYS.seed) {
  const ask = {
    asked_at: NOW_TEXT,
    key_hash: over.key_hash,
    key_id: ASKER.key_id,
    kind: "move_ask",
    nonce: nonce(),
    to: ORIGIN,
    v: 1,
    ...over,
  };
  delete ask.sig;
  ask.sig = move.signObject(ask, move.privateKeyFromSeedHex(seed));
  return ask;
}

async function ask(body, { env = ENV, asker = ASKER, now = NOW } = {}) {
  const res = makeRes();
  await move.handle(makeReq({ method: "POST", body }), res, { env, asker, now: () => now });
  return res;
}

// Read a 200 answer: its bytes must be canonical and its signature must
// verify under the seller's key.
function readAnswer(res) {
  assert.equal(res._status, 200, JSON.stringify(res._body));
  assert.equal(res._headers["content-type"], "application/json");
  assert.ok(Buffer.isBuffer(res._body));
  assert.ok(res._body.length <= move.MAX_ANSWER_BYTES);
  const obj = JSON.parse(res._body.toString("utf8"));
  assert.deepEqual(move.canonicalBytes(obj), res._body, "the answer bytes are canonical");
  assert.equal(obj.key_id, SELLER_KEYS.key_id);
  assert.ok(move.verifyObject(obj, move.publicKeyFromHex(SELLER_KEYS.public_key)), "the answer's signature verifies");
  return obj;
}

const balPath = (hash) => `balance/${hash}.json`;

async function sell(key, checkout, pack = "pins_200", source = "stripe-webhook") {
  const hash = balance.keyHash(key);
  const r = await balance.creditPack(hash, pack, checkout, source);
  assert.equal(r.ok, true);
  return hash;
}

function writesTo(path) {
  return gh.putLog.filter((w) => w.repo === USAGE && w.path === path).length;
}

// The Python line from the specification, run on the given values.
function pythonCanonical(values) {
  const code =
    "import json,sys\n" +
    "for line in sys.stdin.buffer.read().decode(\"utf-8\").split(\"\\n\"):\n" +
    "    if not line: continue\n" +
    "    o=json.loads(line)\n" +
    "    print(json.dumps(o, sort_keys=True, separators=(\",\", \":\"), ensure_ascii=False).encode(\"utf-8\").hex())\n";
  const input = values.map((v) => JSON.stringify(v)).join("\n") + "\n";
  const r = spawnSync("python3", ["-I", "-c", code], { input, encoding: "utf8" });
  if (r.error || r.status !== 0) return null;
  return r.stdout.trim().split("\n");
}

// ---------------------------------------------------------------------
// CANONICAL JSON: the same bytes as the asking side's Python
// ---------------------------------------------------------------------

// Each case with the hex of the bytes Python's
//   json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
// gives for it, worked out once and written here.
const CANON_CASES = [
  // sorted keys at every depth, no white space
  [{ b: 1, a: { d: [3, { z: 1, y: 2 }], c: "x" } },
    "7b2261223a7b2263223a2278222c2264223a5b332c7b2279223a322c227a223a317d5d7d2c2262223a317d"],
  // text outside ASCII kept as UTF-8; control characters escaped as Python does
  [{ "é": "naïve ☃ \u{1F600}", e: " ", ctl: "\u0001\t\"\\\n", z: "\u007f/" },
    "7b2263746c223a225c75303030315c745c225c5c5c6e222c2265223a22e280a8222c227a223a227f2f222c22c3a9223a226e61c3af766520e2988320f09f9880227d"],
  // keys sorted by code point, not by UTF-16 unit: U+FFFF before U+1F600
  [{ "￿": 1, "\u{1F600}": 2, "": 3, a: 4, B: 5 },
    "7b2242223a352c2261223a342c22ee8080223a332c22efbfbf223a312c22f09f9880223a327d"],
  // whole numbers
  [{ max: 9007199254740991, neg: -5, zero: 0 },
    "7b226d6178223a393030373139393235343734303939312c226e6567223a2d352c227a65726f223a307d"],
  [{ a: [], b: {}, c: true, d: false },
    "7b2261223a5b5d2c2262223a7b7d2c2263223a747275652c2264223a66616c73657d"],
];

test("CANONICAL: fixed examples give exactly the bytes the Python line gives", () => {
  for (const [value, hex] of CANON_CASES) {
    assert.equal(move.canonicalBytes(value).toString("hex"), hex, JSON.stringify(value));
  }
});

test("CANONICAL: the same examples run through python3 here give the same bytes", (t) => {
  const got = pythonCanonical(CANON_CASES.map((c) => c[0]));
  if (got === null) return t.skip("python3 is not available");
  assert.deepEqual(got, CANON_CASES.map((c) => c[1]));
});

test("CANONICAL: null, fractions, unsafe integers and lone surrogates are refused, never encoded some other way", () => {
  for (const bad of [{ a: null }, { a: 1.5 }, { a: 2 ** 53 }, { a: NaN }, { a: "\ud800" }, { a: undefined }, { "\udc00": 1 }]) {
    assert.throws(() => move.canonicalBytes(bad), TypeError, JSON.stringify(bad));
  }
});

// ---------------------------------------------------------------------
// THE ROUTE: a true ask, a repeat, and two at once
// ---------------------------------------------------------------------

test("MOVE: a true signed ask marks the key and answers moved with the frozen balance and every sale", async () => {
  const key = "buyer-one";
  const hash = await sell(key, "cs_test_first0001", "pins_200", "stripe-fulfill");
  await sell(key, "cs_test_second002", "pins_1000", "stripe-webhook");
  await balance.debitCredits(key, 5, "spend before the move");

  const a = signedAsk({ key_hash: hash });
  const answer = readAnswer(await ask(a));
  assert.deepEqual(Object.keys(answer).sort(),
    ["credits", "key_hash", "key_id", "kind", "moved_at", "nonce", "sales", "sig", "status", "to", "v"]);
  assert.equal(answer.status, "moved");
  assert.equal(answer.kind, "move_answer");
  assert.equal(answer.v, 1);
  assert.equal(answer.key_hash, hash);
  assert.equal(answer.nonce, a.nonce);
  assert.equal(answer.to, ORIGIN);
  assert.equal(answer.credits, 1195);
  assert.equal(answer.moved_at, NOW_TEXT);
  assert.deepEqual(answer.sales, [
    { checkout: "cs_test_first0001", credits: 200, pack: "pins_200" },
    { checkout: "cs_test_second002", credits: 1000, pack: "pins_1000" },
  ]);

  const stored = gh.read(USAGE, balPath(hash));
  assert.equal(stored.moved.to, ORIGIN);
  assert.equal(stored.moved.credits, 1195);
  assert.equal(stored.balance, 1195, "the balance itself is left as it was");
  assert.equal(stored.applied_events.length, 2, "the idempotency set survives the mark");
});

test("MOVE: the same key asked again answers the same credits, sales and moved_at, with the new nonce, and writes nothing", async () => {
  const key = "buyer-two";
  const hash = await sell(key, "cs_test_again0001");
  const first = readAnswer(await ask(signedAsk({ key_hash: hash })));
  const writes = gh.putLog.length;

  const later = NOW + 120_000;
  const a2 = signedAsk({ key_hash: hash, asked_at: move.formatTime(later) });
  const second = readAnswer(await ask(a2, { now: later }));
  assert.equal(second.status, "moved");
  assert.equal(second.nonce, a2.nonce);
  assert.notEqual(second.nonce, first.nonce);
  assert.equal(second.credits, first.credits);
  assert.deepEqual(second.sales, first.sales);
  assert.equal(second.moved_at, first.moved_at, "moved_at is the time of the first mark");
  assert.equal(gh.putLog.length, writes, "a repeat writes nothing");
});

test("MOVE: a balance frozen at 0 is answered moved with credits 0", async () => {
  const key = "buyer-spent";
  const hash = await sell(key, "cs_test_spent0001");
  await balance.debitCredits(key, 200, "all of it");
  const answer = readAnswer(await ask(signedAsk({ key_hash: hash })));
  assert.equal(answer.status, "moved");
  assert.equal(answer.credits, 0);
});

test("MOVE: a fraction of a pin left by stamps is not moved; credits is the whole pins", async () => {
  const key = "buyer-stamps";
  const hash = await sell(key, "cs_test_stamps001");
  await balance.debitCredits(key, 0.1, "a stamp");
  const answer = readAnswer(await ask(signedAsk({ key_hash: hash })));
  assert.equal(answer.credits, 199);
  assert.equal(gh.read(USAGE, balPath(hash)).moved.balance_at_mark, 199.9);
});

test("MOVE: two asks at once for one key give one mark and the same answer", async () => {
  const key = "buyer-race";
  const hash = await sell(key, "cs_test_race00001");
  const before = writesTo(balPath(hash));
  const [r1, r2] = await Promise.all([ask(signedAsk({ key_hash: hash })), ask(signedAsk({ key_hash: hash }))]);
  const a1 = readAnswer(r1);
  const a2 = readAnswer(r2);
  assert.equal(a1.status, "moved");
  assert.equal(a2.status, "moved");
  assert.equal(a1.credits, a2.credits);
  assert.deepEqual(a1.sales, a2.sales);
  assert.equal(a1.moved_at, a2.moved_at);
  assert.equal(writesTo(balPath(hash)) - before, 1, "exactly one write marked the key");
});

test("MOVE: a spend racing the ask is either before the freeze or refused; the answer always equals the stored balance", async () => {
  const key = "buyer-spend-race";
  const hash = await sell(key, "cs_test_spendrace");
  const [res, spend] = await Promise.all([ask(signedAsk({ key_hash: hash })), balance.debitCredits(key, 1, "racing spend")]);
  const answer = readAnswer(res);
  const stored = gh.read(USAGE, balPath(hash));
  assert.equal(answer.credits, stored.balance);
  assert.equal(stored.balance, spend.ok ? 199 : 200);
  const after = await balance.debitCredits(key, 1, "after the mark");
  assert.equal(after.ok, false);
  assert.equal(after.reason, "pack_moved");
});

// ---------------------------------------------------------------------
// THE ROUTE: refusals mark nothing
// ---------------------------------------------------------------------

async function assertRefusedUnmarked(res, hash, status) {
  assert.notEqual(res._status, 200);
  if (status) assert.equal(res._status, status);
  assert.equal(typeof res._body.error, "string");
  assert.equal(typeof res._body.field, "string");
  const stored = gh.read(USAGE, balPath(hash));
  if (stored) assert.equal(stored.moved, undefined, "the key was not marked");
}

test("MOVE: a bad signature marks nothing and answers non 200", async () => {
  const hash = await sell("buyer-badsig", "cs_test_badsig001");
  const a = signedAsk({ key_hash: hash });
  a.sig = (a.sig[0] === "0" ? "1" : "0") + a.sig.slice(1);
  const res = await ask(a);
  await assertRefusedUnmarked(res, hash, 401);
  assert.equal(res._body.field, "sig");

  // Signed by some other key that claims the trusted key_id.
  const other = move.generateKeyHex();
  const forged = await ask(signedAsk({ key_hash: hash }, other.seed));
  await assertRefusedUnmarked(forged, hash, 401);
  assert.equal(forged._body.field, "sig");

  // A field changed after signing.
  const tampered = signedAsk({ key_hash: hash });
  tampered.nonce = "f".repeat(32);
  await assertRefusedUnmarked(await ask(tampered), hash, 401);
});

test("MOVE: a wrong origin marks nothing and answers non 200, even when correctly signed", async () => {
  const hash = await sell("buyer-origin", "cs_test_origin001");
  const res = await ask(signedAsk({ key_hash: hash, to: "example.org/witness/v1" }));
  await assertRefusedUnmarked(res, hash, 403);
  assert.equal(res._body.field, "to");
});

test("MOVE: a stale or future time marks nothing and answers non 200", async () => {
  const hash = await sell("buyer-stale", "cs_test_stale0001");
  for (const off of [-301_000, 301_000, -86_400_000]) {
    const res = await ask(signedAsk({ key_hash: hash, asked_at: move.formatTime(NOW + off) }));
    await assertRefusedUnmarked(res, hash, 401);
    assert.equal(res._body.field, "asked_at");
  }
  // 300 seconds is still inside.
  readAnswer(await ask(signedAsk({ key_hash: hash, asked_at: move.formatTime(NOW - 300_000) })));
});

test("MOVE: an unknown asking key marks nothing and answers non 200; the key is never adopted from the ask", async () => {
  const hash = await sell("buyer-unknown-asker", "cs_test_unknown01");
  const stranger = move.generateKeyHex();
  const res = await ask(signedAsk({ key_hash: hash, key_id: stranger.key_id }, stranger.seed));
  await assertRefusedUnmarked(res, hash, 401);
  assert.equal(res._body.field, "key_id");
});

test("MOVE: a malformed ask (extra field, wrong kind, wrong v, bad nonce) marks nothing", async () => {
  const hash = await sell("buyer-shape", "cs_test_shape0001");
  for (const over of [{ extra: "x" }, { kind: "move_answer" }, { v: 2 }, { nonce: "abc" }, { key_hash: hash.toUpperCase() }]) {
    const res = await ask(signedAsk({ key_hash: hash, ...over }));
    assert.equal(res._status, 400, JSON.stringify(over));
  }
  const missing = signedAsk({ key_hash: hash });
  delete missing.nonce;
  assert.equal((await ask(missing))._status, 400);
  assert.equal((await ask("not json"))._status, 400);
  assert.equal(gh.read(USAGE, balPath(hash)).moved, undefined);
});

test("MOVE: with the answer key setting missing or malformed, the route answers 503 and marks nothing", async () => {
  const hash = await sell("buyer-nokey", "cs_test_nokey0001");
  for (const env of [{}, { WITNESS_MOVE_ANSWER_KEY: "" }, { WITNESS_MOVE_ANSWER_KEY: "xyz" }, { WITNESS_MOVE_ANSWER_KEY: SELLER_KEYS.seed.toUpperCase() }]) {
    const res = await ask(signedAsk({ key_hash: hash }), { env });
    await assertRefusedUnmarked(res, hash, 503);
    assert.equal(res._body.field, "answer_key");
    assert.ok(!JSON.stringify(res._body).includes(SELLER_KEYS.seed));
  }
});

test("MOVE: through /api/credit?op=move, the pinned signing witness key decides; unpinned it answers 503 and marks nothing", async () => {
  const hash = await sell("buyer-route", "cs_test_route0001");
  process.env.WITNESS_MOVE_ANSWER_KEY = SELLER_KEYS.seed;
  try {
    const res = makeRes();
    await credit(makeReq({ method: "POST", query: { op: "move" }, body: signedAsk({ key_hash: hash, asked_at: move.formatTime(Date.now()) }) }), res);
    if (move.askerReady(move.ASKER)) {
      // Once the published key is pinned, a throwaway signature is refused.
      assert.equal(res._status, 401);
    } else {
      assert.equal(res._status, 503);
      assert.equal(res._body.field, "key_id");
    }
    assert.equal(gh.read(USAGE, balPath(hash)).moved, undefined);
    const get = makeRes();
    await credit(makeReq({ method: "GET", query: { op: "move" } }), get);
    assert.equal(get._status, 405);
  } finally {
    delete process.env.WITNESS_MOVE_ANSWER_KEY;
  }
  assert.equal(move.ASKER.origin, ORIGIN);
});

test("MOVE: vercel.json rewrites /api/v1/move onto the credit function", () => {
  const cfg = JSON.parse(require("fs").readFileSync(require("path").join(__dirname, "..", "vercel.json"), "utf8"));
  const rule = (cfg.rewrites || []).find((r) => r.source === "/api/v1/move");
  assert.ok(rule);
  assert.equal(rule.destination, "/api/credit?op=move");
});

// ---------------------------------------------------------------------
// THE ROUTE: not_sold and elsewhere
// ---------------------------------------------------------------------

const SHORT_FIELDS = ["key_hash", "key_id", "kind", "nonce", "sig", "status", "to", "v"];

test("MOVE: an unknown key answers not_sold with exactly the short fields, and marks nothing", async () => {
  const hash = balance.keyHash("never-seen-key");
  const a = signedAsk({ key_hash: hash });
  const answer = readAnswer(await ask(a));
  assert.deepEqual(Object.keys(answer).sort(), SHORT_FIELDS);
  assert.equal(answer.status, "not_sold");
  assert.equal(answer.nonce, a.nonce);
  assert.equal(answer.to, ORIGIN);
  assert.equal(gh.has(USAGE, balPath(hash)), false);
  assert.equal(gh.putLog.length, 0);
});

test("MOVE: a key with only free pins, or only an operator grant, answers not_sold and marks nothing", async () => {
  const free = "free-only-key";
  await meter.check(free);
  assert.equal(readAnswer(await ask(signedAsk({ key_hash: balance.keyHash(free) }))).status, "not_sold");

  const adminHash = balance.keyHash("admin-only-key");
  await balance.creditPack(adminHash, "pins_200", "ops-grant-1", "internal-admin");
  assert.equal(readAnswer(await ask(signedAsk({ key_hash: adminHash }))).status, "not_sold");
  assert.equal(gh.read(USAGE, balPath(adminHash)).moved, undefined);
});

test("MOVE: a key already marked moved to another origin answers elsewhere", async () => {
  const key = "buyer-elsewhere";
  const hash = await sell(key, "cs_test_elsewhere");
  const cur = gh.read(USAGE, balPath(hash));
  gh.seed(USAGE, balPath(hash), {
    ...cur,
    moved: { to: "example.org/witness/v1", moved_at: "2030-01-01T00:00:00Z", credits: 200, sales: [{ checkout: "cs_test_elsewhere", credits: 200, pack: "pins_200" }] },
  });
  const answer = readAnswer(await ask(signedAsk({ key_hash: hash })));
  assert.deepEqual(Object.keys(answer).sort(), SHORT_FIELDS);
  assert.equal(answer.status, "elsewhere");
  assert.equal(answer.to, ORIGIN, "to is the ask's");
  assert.equal(gh.read(USAGE, balPath(hash)).moved.to, "example.org/witness/v1", "the first mark stands");
});

test("MOVE: a key the answer cannot describe truthfully is refused and not marked (retired pack, balance over the sales, missing record, over 20 sales)", async () => {
  const legacy = await sell("buyer-legacy", "cs_test_legacy001", "mini");
  assert.equal((await ask(signedAsk({ key_hash: legacy })))._status, 409);
  assert.equal(gh.read(USAGE, balPath(legacy)).moved, undefined);

  const mixed = await sell("buyer-mixed", "cs_test_mixed0001");
  await balance.creditPack(mixed, "pins_200", "ops-grant-2", "internal-admin");
  assert.equal((await ask(signedAsk({ key_hash: mixed })))._status, 409);
  assert.equal(gh.read(USAGE, balPath(mixed)).moved, undefined);

  const lost = await sell("buyer-lost", "cs_test_lost00001");
  gh._repoMap(USAGE).delete(balance.ledgerGrantPath(lost, "cs_test_lost00001"));
  assert.equal((await ask(signedAsk({ key_hash: lost })))._status, 409);
  assert.equal(gh.read(USAGE, balPath(lost)).moved, undefined);

  const many = balance.keyHash("buyer-many");
  for (let i = 0; i < 21; i++) await balance.creditPack(many, "pins_200", `cs_test_many${String(i).padStart(5, "0")}`, "stripe-webhook");
  assert.equal((await ask(signedAsk({ key_hash: many })))._status, 409);
  assert.equal(gh.read(USAGE, balPath(many)).moved, undefined);
});

// ---------------------------------------------------------------------
// THE FREEZE: every route that spends bought pins refuses a moved key
// ---------------------------------------------------------------------

async function moveKey(key, checkout) {
  const hash = await sell(key, checkout);
  const answer = readAnswer(await ask(signedAsk({ key_hash: hash })));
  assert.equal(answer.status, "moved");
  return hash;
}

function zeroCap(hash) {
  return JSON.stringify({ [hash]: { plan: "free", monthly_cap: 0 } });
}

test("FREEZE: the plain pin route refuses a moved key past its free pins, naming key, and spends nothing", async () => {
  const hash = await moveKey("movekeyA", "cs_test_pinfreeze");
  process.env.WITNESS_PLANS = zeroCap(hash);
  try {
    const before = gh.putLog.length;
    const res = makeRes();
    await pinHandler(makeReq({ method: "POST", headers: { authorization: "Bearer movekeyA" }, body: { namespace: "mv-main", rows: 1, chain: "aa11bb22" } }), res);
    assert.equal(res._status, 403);
    assert.equal(res._body.reason, "pack_moved");
    assert.equal(res._body.field, "key");
    assert.equal(res._body.error, MOVED_WORDS);
    assert.equal(res._body.buy, undefined, "no buy links for a moved key");
    assert.equal(gh.read(USAGE, balPath(hash)).balance, 200, "nothing spent");
    assert.equal(gh.putLog.length, before, "nothing written anywhere");
    assert.equal(gh.has(PINS, "pins/mv-main/00000001.json"), false);
  } finally {
    delete process.env.WITNESS_PLANS;
  }
});

test("FREEZE: the free pins on a moved key are not moved and keep working on the plain pin route", async () => {
  const hash = await moveKey("movekeyB", "cs_test_freepins1");
  const res = makeRes();
  await pinHandler(makeReq({ method: "POST", headers: { authorization: "Bearer movekeyB" }, body: { namespace: "mv-free", rows: 1, chain: "aa11bb22" } }), res);
  assert.equal(res._status, 201, JSON.stringify(res._body));
  assert.equal(gh.read(USAGE, balPath(hash)).balance, 200, "the frozen balance is untouched");
  const used = gh.read(USAGE, `usage/${hash}/${meter.utcMonth()}.json`);
  assert.equal(used.used, 1, "the free pin was counted on the monthly meter");
});

test("FREEZE: distill refuses a moved key past its free pins, naming key, and spends nothing", async () => {
  const key = "distill-moved-key";
  const hash = await moveKey(key, "cs_test_distill01");
  for (let i = 0; i < meter.PLAN_CAPS.free; i++) assert.equal((await distill.meterAndCharge(key)).ok, true, "free pins still work");
  const r = await distill.meterAndCharge(key);
  assert.equal(r.deny.status, 403);
  assert.equal(r.deny.body.reason, "pack_moved");
  assert.equal(r.deny.body.field, "key");
  assert.equal(r.deny.body.error, MOVED_WORDS);
  assert.equal(gh.read(USAGE, balPath(hash)).balance, 200);
});

test("FREEZE: a paid stamp is refused for a moved key before anything is written, and spends nothing", async () => {
  process.env.WITNESS_KEYS = "movekeyA:mv-,movekeyB:mv-,stampkey:st-";
  process.env.STAMP_FREE_PER_DAY = "0";
  try {
    const hash = await moveKey("stampkey", "cs_test_stamp0001");
    const before = gh.putLog.length;
    const res = makeRes();
    await stamp.handleStamp(makeReq({ method: "POST", body: { sha256: "ab".repeat(32) }, headers: { authorization: "Bearer stampkey", "x-forwarded-for": "203.0.113.9" } }), res);
    assert.equal(res._status, 403, JSON.stringify(res._body));
    assert.equal(res._body.reason, "pack_moved");
    assert.equal(res._body.field, "key");
    assert.equal(res._body.error, MOVED_WORDS);
    assert.equal(gh.read(USAGE, balPath(hash)).balance, 200);
    assert.equal(gh.putLog.length, before, "no stamp and no budget unit were written");
  } finally {
    process.env.WITNESS_KEYS = "movekeyA:mv-,movekeyB:mv-";
    delete process.env.STAMP_FREE_PER_DAY;
  }
});

test("FREEZE: the spend primitive itself refuses every amount on a moved key", async () => {
  const key = "primitive-moved";
  const hash = await moveKey(key, "cs_test_primitive");
  for (const amt of [1, 0.1, 200]) {
    const d = await balance.debitCredits(key, amt, "x");
    assert.equal(d.ok, false);
    assert.equal(d.reason, "pack_moved");
    assert.equal(d.moved_to, ORIGIN);
  }
  assert.equal(gh.read(USAGE, balPath(hash)).balance, 200);
  const rb = await balance.readBalance(hash);
  assert.equal(rb.moved_to, ORIGIN);
});

// ---------------------------------------------------------------------
// A PURCHASE AFTER THE MOVE: nothing credited, recorded for a refund
// ---------------------------------------------------------------------

test("AFTER MOVE: a grant to a moved key adds nothing and leaves a refund record; a replay of an earlier sale is still already_credited", async () => {
  const hash = await moveKey("buyer-after", "cs_test_after0001");
  const g = await balance.creditPack(hash, "pins_1000", "cs_test_after0002", "stripe-fulfill-topup");
  assert.equal(g.ok, false);
  assert.equal(g.reason, "pack_moved");
  assert.equal(g.credited, false);
  const stored = gh.read(USAGE, balPath(hash));
  assert.equal(stored.balance, 200);
  assert.equal(stored.applied_events.includes("cs_test_after0002"), false);
  const rec = gh.read(USAGE, balance.ledgerAfterMovePath(hash, "cs_test_after0002"));
  assert.equal(rec.refund_due, true);
  assert.equal(rec.pins, 1000);
  assert.equal(rec.moved_to, ORIGIN);

  const replay = await balance.creditPack(hash, "pins_200", "cs_test_after0001", "stripe-webhook");
  assert.equal(replay.ok, true);
  assert.equal(replay.already_credited, true);
});

test("AFTER MOVE: the webhook credits nothing for a moved key, answers 200 so the provider stops retrying, and keeps the refund record", async () => {
  const hash = await moveKey("buyer-webhook-after", "cs_test_whafter01");
  const event = {
    id: "evt_test_after_move",
    type: "checkout.session.completed",
    livemode: false,
    created: Math.floor(Date.now() / 1000),
    data: { object: { id: "cs_test_whafter02", payment_status: "paid", client_reference_id: hash, metadata: { pack: "pins_200" }, amount_total: 500, currency: "usd" } },
  };
  const raw = Buffer.from(JSON.stringify(event));
  const res = makeRes();
  await webhook(makeRawReq({ headers: { "stripe-signature": stripeSigHeader(process.env.WITNESS_STRIPE_WEBHOOK_SECRET, raw) }, rawBody: raw }), res);
  assert.equal(res._status, 200);
  assert.equal(res._body.reason, "pack_moved");
  assert.equal(res._body.credited, false);
  assert.equal(gh.read(USAGE, balPath(hash)).balance, 200);
  assert.ok(gh.has(USAGE, balance.ledgerAfterMovePath(hash, "cs_test_whafter02")));
});

test("AFTER MOVE: the fulfilment page tops up nothing on a moved key, says so with 409, forwards nothing, and keeps the refund record", async () => {
  const hash = await moveKey("buyer-fulfill-after", "cs_test_ffafter01");
  const sid = "cs_test_ffafter02aaaaaaaaaaaaaaaaaaaa";
  const session = {
    id: sid, object: "checkout.session", livemode: false, status: "complete", payment_status: "paid",
    amount_total: 500, currency: "usd", client_reference_id: hash, customer_details: { email: "buyer@example.com" },
    metadata: { pack: "pins_200" },
  };
  const stripeCalls = [];
  const inner = global.fetch;
  global.fetch = async (url, opts) => {
    if (String(url).startsWith("https://api.stripe.com/")) {
      stripeCalls.push(String(url));
      return { status: 200, ok: true, json: async () => session, text: async () => JSON.stringify(session) };
    }
    return inner(url, opts);
  };
  require("../lib/_ratelimit.js")._resetForTests();
  process.env.WITNESS_ACCOUNTS_FORWARD = "dry-run";
  const lines = [];
  const savedErr = console.error;
  console.error = (...a) => lines.push(a.join(" "));
  try {
    const res = makeRes();
    await fulfill(makeReq({ method: "GET", headers: { accept: "application/json" }, query: { session_id: sid } }), res);
    assert.equal(res._status, 409, JSON.stringify(res._body));
    assert.equal(res._body.reason, "pack_moved");
    assert.equal(res._body.field, "key");
    assert.equal(res._body.error, MOVED_WORDS);
    assert.equal(res._body.credited, false);
    assert.equal(stripeCalls.length, 1);
  } finally {
    console.error = savedErr;
    delete process.env.WITNESS_ACCOUNTS_FORWARD;
    global.fetch = inner;
  }
  assert.equal(gh.read(USAGE, balPath(hash)).balance, 200);
  assert.ok(gh.has(USAGE, balance.ledgerAfterMovePath(hash, sid)));
  assert.equal(lines.filter((l) => l.includes("[accounts-forward]")).length, 0, "nothing forwarded");
});

test("AFTER MOVE: the admin credit path refuses a moved key with 409 and credits nothing", async () => {
  const hash = await moveKey("buyer-admin-after", "cs_test_admafter1");
  process.env.WITNESS_ADMIN_KEY = "admin-test-only";
  try {
    const res = makeRes();
    await credit(makeReq({ method: "POST", headers: { authorization: "Bearer admin-test-only" }, body: { key_hash: hash, pack: "pins_200", event_id: "ops-after-1" } }), res);
    assert.equal(res._status, 409);
    assert.equal(res._body.reason, "pack_moved");
    assert.equal(gh.read(USAGE, balPath(hash)).balance, 200);
  } finally {
    delete process.env.WITNESS_ADMIN_KEY;
  }
});

// ---------------------------------------------------------------------
// WORKED EXAMPLES (printed for docs/pack-move-route.md)
// ---------------------------------------------------------------------

test("EXAMPLES: one ask and one moved answer, canonical bytes printed, signed with throwaway keys made in this test", async (t) => {
  const key = "worked-example-key";
  const hash = await sell(key, "cs_test_example01", "pins_200", "stripe-fulfill");
  const a = signedAsk({ key_hash: hash, nonce: "0123456789abcdef0123456789abcdef" });
  const askBytes = move.canonicalBytes(a);
  const res = await ask(a);
  const answer = readAnswer(res);
  assert.equal(answer.credits, 200);

  const py = pythonCanonical([a, answer]);
  if (py !== null) {
    assert.equal(py[0], askBytes.toString("hex"), "the ask's bytes match the Python line");
    assert.equal(py[1], res._body.toString("hex"), "the answer's bytes match the Python line");
  } else {
    t.diagnostic("python3 is not available; the byte comparison with Python was skipped");
  }
  t.diagnostic(`throwaway asker public_key ${ASKER_KEYS.public_key}`);
  t.diagnostic(`throwaway asker key_id ${ASKER_KEYS.key_id}`);
  t.diagnostic(`throwaway seller public_key ${SELLER_KEYS.public_key}`);
  t.diagnostic(`throwaway seller key_id ${SELLER_KEYS.key_id}`);
  t.diagnostic(`ask ${askBytes.toString("utf8")}`);
  t.diagnostic(`answer ${res._body.toString("utf8")}`);
});
