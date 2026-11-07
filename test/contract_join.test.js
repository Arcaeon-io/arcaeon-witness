// test/contract_join.test.js: the join (W-J1), first slice. A desktop's
// contract pin, sent to POST /witness/v1/pins with the pack's bearer key,
// spends from the same pack as a plain pin (the pip client and the MCP
// server send those to /api/pin): one balance, one free allowance, spent
// once wherever the pin comes from. The answer is exactly a contract
// receipt signed by the witness's contract key.
//
// Settings are set BEFORE anything is required: the store modules read
// their repository names when they load.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_KEYS = "joinkeyA:team-,joinkeyB:team-,joinkeyC:other-";
delete process.env.WITNESS_PLANS;
delete process.env.WITNESS_CADENCE;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRawReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const balance = require("../lib/_balance.js");
const meter = require("../lib/_meter.js");
const c = require("../lib/_contract.js");
const pinHandler = require("../api/pin.js");

const VECTORS = JSON.parse(fs.readFileSync(path.join(__dirname, "vectors", "contract_vectors.json"), "utf8"));
const KEYS = VECTORS.test_keys;
const STATEMENT = VECTORS.objects.find((o) => o.name === "witness statement").canonical;
const PIN_REPO = process.env.GITHUB_PIN_REPO;
const USAGE_REPO = process.env.GITHUB_USAGE_REPO;

const OWNER = c.privateFromSeed(KEYS.owner.seed);
const OWNER_PUBLIC = KEYS.owner.public_key;
// A second pinner, made here from a fixed seed: a stranger's key.
const STRANGER = c.privateFromSeed(crypto.createHash("sha256").update("join test stranger").digest("hex"));
const STRANGER_PUBLIC = c.publicRaw(STRANGER).toString("hex");
const WITNESS_PUBLIC = Buffer.from(KEYS.witness.public_key, "hex");

function setKey() {
  process.env.WITNESS_CONTRACT_SEED = KEYS.witness.seed;
  process.env.WITNESS_CONTRACT_KEY_ID = KEYS.witness.key_id;
  process.env.WITNESS_CONTRACT_STATEMENT = STATEMENT;
}

let gh;
let restore;
const realPutSleep = store._putRetry.sleep;
let savedPlans;

beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
  store._putRetry.sleep = async () => {};
  savedPlans = process.env.WITNESS_PLANS;
  setKey();
});

afterEach(() => {
  store._putRetry.sleep = realPutSleep;
  restore();
  if (savedPlans === undefined) delete process.env.WITNESS_PLANS;
  else process.env.WITNESS_PLANS = savedPlans;
});

function head(n, fill) {
  const chain = n === 0 ? "0".repeat(64) : crypto.createHash("sha256").update(`${fill}:${n}`).digest("hex");
  return { chain, kind: "head", n, v: 1 };
}

function makePin({ ns = "team-notes", n = 3, fill = "a", key = OWNER, issuedAt = "2026-11-07T10:00:00Z", root } = {}) {
  const pin = { head: head(n, fill), issued_at: issuedAt, kind: "pin", namespace: ns, v: 1 };
  if (root) {
    pin.root = root;
    pin.root_n = n;
  }
  return c.canonical(c.sign(key, pin));
}

function contractReq(raw, { bearer = "joinkeyA", publicKey = OWNER_PUBLIC, headers = {}, query } = {}) {
  const h = { "content-type": "application/json", "content-length": String(raw.length), ...headers };
  if (bearer !== null) h.authorization = `Bearer ${bearer}`;
  if (publicKey !== null) h["public-key"] = publicKey;
  const req = makeRawReq({ method: "POST", headers: h, rawBody: raw });
  req.query = query || { op: "contract" };
  return req;
}

async function send(raw, opts) {
  const res = makeRes();
  await pinHandler(contractReq(raw, opts), res);
  return res;
}

function bodyOf(res) {
  return JSON.parse(Buffer.from(res._body).toString("utf8"));
}

function assertRefusal(res, status, field) {
  assert.equal(res._status, status, Buffer.from(res._body || "").toString());
  const body = bodyOf(res);
  assert.deepEqual(Object.keys(body).sort(), ["field", "reason", "status"]);
  assert.equal(body.status, "REFUSED");
  assert.equal(body.field, field);
  assert.equal(typeof body.reason, "string");
  assert.ok(body.reason.length > 0);
}

function noCap(key) {
  return JSON.stringify({ [balance.keyHash(key)]: { plan: "free", monthly_cap: 0 } });
}

function plainReq(namespace, rows, chain, key = "joinkeyA") {
  return makeReq({ method: "POST", headers: { authorization: `Bearer ${key}` }, body: { namespace, rows, chain } });
}

async function credits(key) {
  return (await balance.readBalance(balance.keyHash(key))).balance;
}

function freeUsed(key) {
  const rec = gh.read(USAGE_REPO, `usage/${meter.keyHash(key)}/${meter.utcMonth()}.json`);
  return rec ? rec.used : 0;
}

function rowPath(ns, seq) {
  return `contract/${ns}/rows/${String(seq).padStart(12, "0")}.json`;
}

// ---------------------------------------------------------------------
// The receipt
// ---------------------------------------------------------------------

test("a desktop pin with the pack's bearer key is answered 201 with exactly a contract receipt", async () => {
  const raw = makePin();
  const res = await send(raw);
  assert.equal(res._status, 201, Buffer.from(res._body).toString());
  assert.equal(res._headers["content-type"], "application/json");
  assert.equal(res._headers["cache-control"], "no-store");
  const bytes = Buffer.from(res._body);
  const receipt = JSON.parse(bytes.toString("utf8"));
  assert.deepEqual(Object.keys(receipt).sort(), ["head", "key_id", "kind", "namespace", "received_at", "sig", "v", "witness_seq"]);
  assert.equal(c.canonical(receipt).equals(bytes), true, "the body is the receipt's canonical bytes");
  assert.equal(receipt.kind, "receipt");
  assert.equal(receipt.witness_seq, 1);
  assert.equal(receipt.key_id, KEYS.witness.key_id);
  assert.deepEqual(receipt.head, JSON.parse(raw.toString()).head);
  assert.equal(c.verify(receipt, WITNESS_PUBLIC), true);
  assert.match(receipt.received_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  // The row is stored, and its pin is the bytes received.
  const row = gh.read(PIN_REPO, rowPath("team-notes", 1));
  assert.ok(row);
  assert.equal(c.canonical(row.pin).equals(raw), true);
  assert.equal(row.public_key, OWNER_PUBLIC);
  assert.equal(row.chain, c.rowChain(row));
  // No billing fact travels in the answer (an open question for the owner).
  for (const h of Object.keys(res._headers)) assert.equal(/^x-(meter|credit)/.test(h), false, h);
});

test("the next pin of the namespace gets witness_seq 2, its row chained to the first", async () => {
  assert.equal((await send(makePin({ n: 3 })))._status, 201);
  const res = await send(makePin({ n: 5 }));
  assert.equal(res._status, 201);
  assert.equal(bodyOf(res).witness_seq, 2);
  const r1 = gh.read(PIN_REPO, rowPath("team-notes", 1));
  const r2 = gh.read(PIN_REPO, rowPath("team-notes", 2));
  assert.equal(r2.prev, r1.chain);
});

// ---------------------------------------------------------------------
// One balance
// ---------------------------------------------------------------------

test("one balance: a plain pin and a desktop pin spend the same pack, once each, then both are refused", async () => {
  process.env.WITNESS_PLANS = noCap("joinkeyA");
  await balance.grantCredits(balance.keyHash("joinkeyA"), 2, "pack_200", "evt-join-one-balance", "test");

  const plain = makeRes();
  await pinHandler(plainReq("team-cli", 10, "aaaaaaaa"), plain);
  assert.equal(plain._status, 201);
  assert.equal(await credits("joinkeyA"), 1);

  const desk = await send(makePin());
  assert.equal(desk._status, 201);
  assert.equal(await credits("joinkeyA"), 0, "the desktop pin took the pack's last pin");

  assertRefusal(await send(makePin({ n: 9 })), 402, "plan");
  const plainAgain = makeRes();
  await pinHandler(plainReq("team-cli", 11, "bbbbbbbb"), plainAgain);
  assert.equal(plainAgain._status, 402, "the plain path sees the same empty pack");
  assert.equal(await credits("joinkeyA"), 0);
});

test("one balance: the desktop pin uses the key's free allowance first, the same counter the plain pin uses", async () => {
  process.env.WITNESS_PLANS = JSON.stringify({ [balance.keyHash("joinkeyA")]: { plan: "free", monthly_cap: 1 } });
  await balance.grantCredits(balance.keyHash("joinkeyA"), 1, "pack_200", "evt-join-free-first", "test");

  assert.equal((await send(makePin()))._status, 201);
  assert.equal(freeUsed("joinkeyA"), 1, "the free pin was counted on the key's own meter");
  assert.equal(await credits("joinkeyA"), 1, "no credit was taken while the free allowance had room");

  const plain = makeRes();
  await pinHandler(plainReq("team-cli", 10, "aaaaaaaa"), plain);
  assert.equal(plain._status, 201);
  assert.equal(await credits("joinkeyA"), 0, "the plain pin found the free allowance used by the desktop pin");
});

test("the same pin sent again is answered 200 with the same receipt and spends nothing", async () => {
  process.env.WITNESS_PLANS = noCap("joinkeyA");
  await balance.grantCredits(balance.keyHash("joinkeyA"), 5, "pack_200", "evt-join-replay", "test");
  const raw = makePin();
  const first = await send(raw);
  assert.equal(first._status, 201);
  assert.equal(await credits("joinkeyA"), 4);
  const again = await send(makePin({ issuedAt: "2026-11-07T11:00:00Z" }));
  assert.equal(again._status, 200);
  assert.equal(Buffer.from(again._body).equals(Buffer.from(first._body)), true, "the same receipt, byte for byte");
  assert.equal(await credits("joinkeyA"), 4, "a replay holds and spends nothing");
});

test("a replay is answered even when the pack is empty, since it adds no row", async () => {
  process.env.WITNESS_PLANS = noCap("joinkeyA");
  await balance.grantCredits(balance.keyHash("joinkeyA"), 1, "pack_200", "evt-join-replay-empty", "test");
  assert.equal((await send(makePin()))._status, 201);
  assert.equal(await credits("joinkeyA"), 0);
  assert.equal((await send(makePin()))._status, 200);
});

test("two copies of one pin sent at once add one row and spend one pin", async () => {
  process.env.WITNESS_PLANS = noCap("joinkeyA");
  await balance.grantCredits(balance.keyHash("joinkeyA"), 5, "pack_200", "evt-join-race", "test");
  const raw = makePin();
  const [a, b] = await Promise.all([send(raw), send(raw)]);
  const codes = [a._status, b._status].sort();
  assert.deepEqual(codes, [200, 201]);
  assert.equal(Buffer.from(a._body).equals(Buffer.from(b._body)), true);
  assert.equal(await credits("joinkeyA"), 4, "no purchase is spent twice");
  assert.equal(gh.has(PIN_REPO, rowPath("team-notes", 2)), false);
});

test("a row write that fails gives the credit back and signs nothing", async () => {
  process.env.WITNESS_PLANS = noCap("joinkeyA");
  await balance.grantCredits(balance.keyHash("joinkeyA"), 3, "pack_200", "evt-join-fail", "test");
  gh.forceFailure(PIN_REPO, rowPath("team-notes", 1), 1, 500);
  assertRefusal(await send(makePin()), 503, "storage");
  assert.equal(gh.has(PIN_REPO, rowPath("team-notes", 1)), false);
  assert.equal(await credits("joinkeyA"), 3);
});

test("an empty pack refuses with 402 naming plan, and no row is written", async () => {
  process.env.WITNESS_PLANS = noCap("joinkeyA");
  assertRefusal(await send(makePin()), 402, "plan");
  assert.equal(gh.has(PIN_REPO, rowPath("team-notes", 1)), false);
});

test("a key with no cap configured is refused naming bearer, never treated as unlimited", async () => {
  process.env.WITNESS_PLANS = JSON.stringify({ [balance.keyHash("joinkeyA")]: { plan: "no-such-plan" } });
  assertRefusal(await send(makePin()), 403, "bearer");
  assert.equal(gh.has(PIN_REPO, rowPath("team-notes", 1)), false);
});

test("a usage store that cannot be read refuses with 503 naming plan, nothing written", async () => {
  const realGet = gh.handleFetch.bind(gh);
  gh.handleFetch = async (url, opts) => {
    if (String(url).includes("/test-usage/contents/usage/")) {
      return { status: 500, ok: false, json: async () => ({}), text: async () => "down" };
    }
    return realGet(url, opts);
  };
  assertRefusal(await send(makePin()), 503, "plan");
  assert.equal(gh.has(PIN_REPO, rowPath("team-notes", 1)), false);
});

// ---------------------------------------------------------------------
// The account's record only grants are never spent (PR 74)
// ---------------------------------------------------------------------

test("a desktop pin spends only the live pack: it never calls the account service", async () => {
  process.env.WITNESS_ACCOUNTS_FORWARD = "on";
  process.env.WITNESS_ACCOUNTS_URL = "https://accounts.example.test/accounts/v1";
  const seen = [];
  const inner = global.fetch;
  global.fetch = (url, opts) => {
    seen.push(new URL(String(url)).host);
    return inner(url, opts);
  };
  try {
    process.env.WITNESS_PLANS = noCap("joinkeyA");
    await balance.grantCredits(balance.keyHash("joinkeyA"), 1, "pack_200", "evt-join-record-only", "test");
    assert.equal((await send(makePin()))._status, 201);
    assertRefusal(await send(makePin({ n: 4 })), 402, "plan");
  } finally {
    global.fetch = inner;
    delete process.env.WITNESS_ACCOUNTS_FORWARD;
    delete process.env.WITNESS_ACCOUNTS_URL;
  }
  assert.ok(seen.length > 0);
  for (const host of seen) assert.equal(host, "api.github.com");
});

// ---------------------------------------------------------------------
// Refusals before the charge cost nothing, and each names its field
// ---------------------------------------------------------------------

async function assertFree(fn) {
  process.env.WITNESS_PLANS = noCap("joinkeyA");
  await balance.grantCredits(balance.keyHash("joinkeyA"), 2, "pack_200", `evt-free-${crypto.randomUUID()}`, "test");
  const before = await credits("joinkeyA");
  const freeBefore = freeUsed("joinkeyA");
  await fn();
  assert.equal(await credits("joinkeyA"), before, "a refused pin spends nothing");
  assert.equal(freeUsed("joinkeyA"), freeBefore, "a refused pin counts nothing");
}

test("no bearer key, or an unknown one, is refused naming bearer", async () => {
  assertRefusal(await send(makePin(), { bearer: null }), 401, "bearer");
  assertRefusal(await send(makePin(), { bearer: "not-a-key" }), 401, "bearer");
  assertRefusal(await send(makePin(), { headers: { authorization: "Basic abc" }, bearer: null }), 401, "bearer");
  assert.equal(gh.has(PIN_REPO, rowPath("team-notes", 1)), false);
});

test("a namespace outside the bearer key's prefix is refused naming namespace, before any charge", async () => {
  await assertFree(async () => {
    assertRefusal(await send(makePin({ ns: "elsewhere" })), 403, "namespace");
  });
});

test("a namespace held by another pinner's key is refused naming key_id, before any charge", async () => {
  assert.equal((await send(makePin()))._status, 201);
  await assertFree(async () => {
    const res = await send(makePin({ key: STRANGER, n: 9 }), { publicKey: STRANGER_PUBLIC, bearer: "joinkeyA" });
    assertRefusal(res, 422, "key_id");
  });
});

test("the witness never goes backward: an older n, or another chain at the same n, is refused", async () => {
  assert.equal((await send(makePin({ n: 5 })))._status, 201);
  await assertFree(async () => {
    assertRefusal(await send(makePin({ n: 4 })), 422, "head.n");
    assertRefusal(await send(makePin({ n: 5, fill: "other" })), 422, "head.chain");
  });
});

test("the same head with another root, or a root added, is refused naming root", async () => {
  assert.equal((await send(makePin({ n: 5, root: "1".repeat(64) })))._status, 201);
  await assertFree(async () => {
    assertRefusal(await send(makePin({ n: 5, root: "2".repeat(64) })), 422, "root");
    assertRefusal(await send(makePin({ n: 5 })), 422, "root");
  });
});

test("a body that is not the pin's canonical bytes is refused naming pin", async () => {
  await assertFree(async () => {
    const raw = makePin();
    const spaced = Buffer.from(JSON.stringify(JSON.parse(raw.toString()), null, 1));
    assertRefusal(await send(spaced), 422, "pin");
    assertRefusal(await send(Buffer.concat([raw, Buffer.from("\n")])), 422, "pin");
  });
});

test("the Public-Key header is judged as sent", async () => {
  await assertFree(async () => {
    assertRefusal(await send(makePin(), { publicKey: null }), 422, "public_key");
    assertRefusal(await send(makePin(), { publicKey: OWNER_PUBLIC.toUpperCase() }), 422, "public_key");
    assertRefusal(await send(makePin(), { publicKey: `${OWNER_PUBLIC}, ${OWNER_PUBLIC}` }), 400, "public_key");
    assertRefusal(await send(makePin(), { publicKey: STRANGER_PUBLIC }), 422, "key_id");
  });
});

test("a pin whose signature does not verify is refused naming sig", async () => {
  await assertFree(async () => {
    const p = JSON.parse(makePin().toString());
    p.sig = (p.sig[0] === "0" ? "1" : "0") + p.sig.slice(1);
    assertRefusal(await send(c.canonical(p)), 422, "sig");
  });
});

test("a malformed field is named, in the reference witness's order", async () => {
  await assertFree(async () => {
    const p = JSON.parse(makePin().toString());
    p.extra = 1;
    assertRefusal(await send(c.canonical(p)), 422, "extra");
    assertRefusal(await send(Buffer.from("{nope")), 422, "pin");
  });
});

test("the body's length is judged first", async () => {
  const raw = makePin();
  const noLen = makeRawReq({ method: "POST", headers: { authorization: "Bearer joinkeyA", "public-key": OWNER_PUBLIC }, rawBody: raw });
  noLen.query = { op: "contract" };
  let res = makeRes();
  await pinHandler(noLen, res);
  assertRefusal(res, 411, "content-length");
  assertRefusal(await send(raw, { headers: { "content-length": "12x" } }), 400, "content-length");
  assertRefusal(await send(raw, { headers: { "content-length": "9000" } }), 413, "content-length");
  assertRefusal(await send(raw, { headers: { "content-length": String(raw.length + 5) } }), 400, "body");
  assertRefusal(await send(raw, { headers: { "transfer-encoding": "chunked" } }), 400, "transfer-encoding");
});

test("only POST, and no query of the client's own", async () => {
  const req = makeRawReq({ method: "GET", headers: {}, rawBody: Buffer.alloc(0) });
  req.query = { op: "contract" };
  const res = makeRes();
  await pinHandler(req, res);
  assertRefusal(res, 405, "method");
  assertRefusal(await send(makePin(), { query: { op: "contract", wait: "full" } }), 400, "query");
});

test("without the witness key set, every contract pin is refused naming key, and nothing is spent", async () => {
  await assertFree(async () => {
    delete process.env.WITNESS_CONTRACT_SEED;
    assertRefusal(await send(makePin()), 503, "key");
    setKey();
    process.env.WITNESS_CONTRACT_KEY_ID = KEYS.owner.key_id;
    assertRefusal(await send(makePin()), 503, "key");
    setKey();
    process.env.WITNESS_CONTRACT_STATEMENT = "{}";
    assertRefusal(await send(makePin()), 503, "statement");
  });
});

test("no secret is ever logged: not the bearer key, not the witness seed, not the pinner's key", async () => {
  const lines = [];
  const saved = { log: console.log, error: console.error, warn: console.warn, info: console.info };
  for (const k of Object.keys(saved)) console[k] = (...a) => lines.push(a.map(String).join(" "));
  try {
    process.env.WITNESS_PLANS = noCap("joinkeyA");
    await balance.grantCredits(balance.keyHash("joinkeyA"), 1, "pack_200", "evt-join-nolog", "test");
    await send(makePin());
    await send(makePin({ n: 6 }));
    gh.forceFailure(PIN_REPO, rowPath("team-notes", 2), 1, 500);
    await send(makePin({ n: 7 }));
    delete process.env.WITNESS_CONTRACT_SEED;
    await send(makePin({ n: 8 }));
  } finally {
    Object.assign(console, saved);
    setKey();
  }
  const all = lines.join("\n");
  for (const secret of ["joinkeyA", KEYS.witness.seed, balance.keyHash("joinkeyA"), OWNER_PUBLIC]) {
    assert.equal(all.includes(secret), false, "a log line holds a secret or the key's hash");
  }
});

test("the plain pin path is unchanged: a request without op=contract is a plain pin", async () => {
  const res = makeRes();
  await pinHandler(plainReq("team-plain", 3, "cccccccc"), res);
  assert.equal(res._status, 201);
  assert.equal(res._body.record_kind, "content_head_advance");
});
