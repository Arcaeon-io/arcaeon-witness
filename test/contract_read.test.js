// test/contract_read.test.js: the join's reads (W-J1, first slice), reached
// by rewrites onto /api/latest?op=contract-*: the witness key, its signed
// statement, the receipt of a namespace's newest row, and the signed rows
// answer the desktop reads back after a pin. Also the routes themselves.
"use strict";

process.env.GITHUB_PIN_REPO = "test-owner/test-pins";
process.env.GITHUB_PIN_BRANCH = "main";
process.env.GITHUB_USAGE_REPO = "test-owner/test-usage";
process.env.GITHUB_PIN_TOKEN = "test-token";
process.env.WITNESS_KEYS = "readkeyA:team-";
delete process.env.WITNESS_PLANS;

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { MockGitHubStore, install } = require("./helpers/mock_store.js");
const { makeReq, makeRawReq, makeRes } = require("./helpers/http_mocks.js");
const store = require("../lib/_store.js");
const c = require("../lib/_contract.js");
const pinHandler = require("../api/pin.js");
const latestHandler = require("../api/latest.js");

const VECTORS = JSON.parse(fs.readFileSync(path.join(__dirname, "vectors", "contract_vectors.json"), "utf8"));
const KEYS = VECTORS.test_keys;
const STATEMENT = VECTORS.objects.find((o) => o.name === "witness statement").canonical;
const OWNER = c.privateFromSeed(KEYS.owner.seed);
const WITNESS = c.privateFromSeed(KEYS.witness.seed);
const WITNESS_PUBLIC = Buffer.from(KEYS.witness.public_key, "hex");
const PIN_REPO = process.env.GITHUB_PIN_REPO;

let gh;
let restore;
const realPutSleep = store._putRetry.sleep;

beforeEach(() => {
  gh = new MockGitHubStore();
  restore = install(gh);
  store._putRetry.sleep = async () => {};
  process.env.WITNESS_CONTRACT_SEED = KEYS.witness.seed;
  process.env.WITNESS_CONTRACT_KEY_ID = KEYS.witness.key_id;
  process.env.WITNESS_CONTRACT_STATEMENT = STATEMENT;
});

afterEach(() => {
  store._putRetry.sleep = realPutSleep;
  restore();
});

let ipCounter = 0;
function readReq(query) {
  ipCounter += 1;
  // A fresh address each time, so the per address read limit never bites.
  return makeReq({ method: "GET", headers: { "x-forwarded-for": `10.9.${ipCounter >> 8}.${ipCounter & 255}` }, query });
}

async function read(query) {
  const res = makeRes();
  await latestHandler(readReq(query), res);
  return res;
}

function bodyOf(res) {
  return JSON.parse(Buffer.from(res._body).toString("utf8"));
}

function assertRefusal(res, status, field) {
  assert.equal(res._status, status, Buffer.from(res._body || "").toString());
  const body = bodyOf(res);
  assert.deepEqual(Object.keys(body).sort(), ["field", "reason", "status"]);
  assert.equal(body.field, field);
}

async function pin(n) {
  const chain = crypto.createHash("sha256").update(`read:${n}`).digest("hex");
  const raw = c.canonical(c.sign(OWNER, {
    head: { chain, kind: "head", n, v: 1 }, issued_at: "2026-11-07T10:00:00Z", kind: "pin", namespace: "team-notes", v: 1,
  }));
  const req = makeRawReq({
    method: "POST",
    headers: { authorization: "Bearer readkeyA", "public-key": KEYS.owner.public_key, "content-length": String(raw.length) },
    rawBody: raw,
  });
  req.query = { op: "contract" };
  const res = makeRes();
  await pinHandler(req, res);
  assert.equal(res._status, 201);
  return Buffer.from(res._body);
}

test("the key read serves the contract key id and public key, and nothing else", async () => {
  const res = await read({ op: "contract-key" });
  assert.equal(res._status, 200);
  assert.deepEqual(bodyOf(res), { key_id: KEYS.witness.key_id, public_key: KEYS.witness.public_key });
});

test("the statement read serves the statement's bytes exactly", async () => {
  const res = await read({ op: "contract-statement" });
  assert.equal(res._status, 200);
  assert.equal(Buffer.from(res._body).toString("utf8"), STATEMENT);
});

test("without the key set, the reads refuse naming key", async () => {
  delete process.env.WITNESS_CONTRACT_SEED;
  assertRefusal(await read({ op: "contract-key" }), 503, "key");
  assertRefusal(await read({ op: "contract-rows", ns: "team-notes" }), 503, "key");
});

test("the receipt read gives the newest row's receipt, the same bytes the pin was answered with", async () => {
  await pin(3);
  const second = await pin(5);
  const res = await read({ op: "contract-receipt", ns: "team-notes" });
  assert.equal(res._status, 200);
  assert.equal(Buffer.from(res._body).equals(second), true);
});

test("the rows answer is signed, newest first, and is what the reference witness would sign", async () => {
  await pin(3);
  await pin(5);
  const res = await read({ op: "contract-rows", ns: "team-notes" });
  assert.equal(res._status, 200);
  const answer = bodyOf(res);
  assert.equal(answer.rows.length, 2);
  assert.deepEqual(answer.rows.map((r) => r.seq), [2, 1]);
  assert.equal(c.verify(answer.envelope, WITNESS_PUBLIC), true);
  for (const s of answer.sigs) assert.equal(c.verify(s, WITNESS_PUBLIC), true);
  const again = c.makeAnswer(WITNESS, "team-notes", answer.rows, answer.envelope.served_at);
  assert.equal(c.canonical(again).equals(Buffer.from(res._body)), true);
  assert.equal(answer.rows[0].prev, answer.rows[1].chain);
});

test("the rows answer takes a limit, and refuses a bad one naming limit", async () => {
  await pin(3);
  await pin(5);
  const res = await read({ op: "contract-rows", ns: "team-notes", limit: "1" });
  assert.equal(res._status, 200);
  const answer = bodyOf(res);
  assert.equal(answer.rows.length, 1);
  assert.equal(answer.envelope.rows, 1);
  assert.equal(answer.rows[0].seq, 2);
  for (const bad of ["0", "1001", "x", "1.5"]) {
    assertRefusal(await read({ op: "contract-rows", ns: "team-notes", limit: bad }), 400, "limit");
  }
});

test("an unknown or malformed namespace is 404 naming namespace", async () => {
  assertRefusal(await read({ op: "contract-rows", ns: "nothing-here" }), 404, "namespace");
  assertRefusal(await read({ op: "contract-receipt", ns: "nothing-here" }), 404, "namespace");
  assertRefusal(await read({ op: "contract-rows", ns: "../pins" }), 404, "namespace");
});

test("a stored row that was edited is caught: nothing is signed for it", async () => {
  await pin(3);
  await pin(5);
  const p = "contract/team-notes/rows/000000000001.json";
  const row = gh.read(PIN_REPO, p);
  row.received_at = "2020-01-01T00:00:00Z";
  gh.seed(PIN_REPO, p, row);
  assertRefusal(await read({ op: "contract-rows", ns: "team-notes" }), 409, "namespace");
});

test("a read takes no query of its own", async () => {
  assertRefusal(await read({ op: "contract-key", extra: "1" }), 400, "query");
});

test("the plain latest read is unchanged", async () => {
  const res = await read({ ns: "nothing-yet" });
  assert.notEqual(res._status, 500);
  assert.equal(typeof res._body, "object");
});

test("the join's routes are rewrites onto existing functions, and api/ stays at twelve", () => {
  const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "vercel.json"), "utf8"));
  const want = {
    "/witness/v1/pins": "/api/pin?op=contract",
    "/witness/v1/key": "/api/latest?op=contract-key",
    "/witness/v1/statement": "/api/latest?op=contract-statement",
    "/witness/v1/pins/:ns/receipt": "/api/latest?op=contract-receipt&ns=:ns",
    "/witness/v1/pins/:ns": "/api/latest?op=contract-rows&ns=:ns",
  };
  const order = cfg.rewrites.map((r) => r.source);
  for (const [source, destination] of Object.entries(want)) {
    const r = cfg.rewrites.find((x) => x.source === source);
    assert.ok(r, source);
    assert.equal(r.destination, destination);
  }
  assert.ok(order.indexOf("/witness/v1/pins/:ns/receipt") < order.indexOf("/witness/v1/pins/:ns"));
  const fns = fs.readdirSync(path.join(__dirname, "..", "api")).filter((f) => f.endsWith(".js"));
  assert.equal(fns.length, 12);
});
