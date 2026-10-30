// test/account.test.js — the Arcaeon account, phase 1: agent sign-up by
// Ed25519 challenge-response with proof of work, and the device registry.
// Runs against the in-memory store (lib/_accountdb.js memoryStore). The
// PostgREST store has its own file (accountdb_postgrest.test.js), the SQL its
// own (account_schema.test.js).
"use strict";

// Cheap proof of work for the suite; the default (20) is asserted separately.
process.env.ACCOUNT_POW_BITS = "8";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const { makeReq, makeRes } = require("./helpers/http_mocks.js");
const ratelimit = require("../lib/_ratelimit.js");
const accountdb = require("../lib/_accountdb.js");
const account = require("../lib/_account_api.js");
const balanceHandler = require("../api/balance.js");

let ipCounter = 0;
function freshIp() {
  ipCounter += 1;
  return `198.51.${Math.floor(ipCounter / 250)}.${(ipCounter % 250) + 1}`;
}

function newAgent() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(12);
  return { privateKey, public_key: raw.toString("base64url") };
}

function sign(agent, message) {
  return crypto.sign(null, Buffer.from(message, "utf8"), agent.privateKey).toString("base64url");
}

function setup({ nowMs } = {}) {
  const store = accountdb.memoryStore();
  const clock = { t: nowMs || Date.now() };
  const api = account.createAccountApi({ getStore: () => store, now: () => clock.t });
  return { store, api, clock };
}

async function call(fn, { method = "POST", body, headers = {}, ip } = {}) {
  const res = makeRes();
  await fn(makeReq({ method, body, headers: { "x-forwarded-for": ip || freshIp(), ...headers } }), res);
  return res;
}

async function getChallenge(api, agent) {
  const res = await call(api.challenge, { body: { public_key: agent.public_key } });
  assert.equal(res._status, 201, JSON.stringify(res._body));
  return res._body;
}

function verifyBody(agent, ch, overrides = {}) {
  return {
    public_key: agent.public_key,
    nonce: ch.nonce,
    signature: sign(agent, account.DOMAIN + ch.nonce),
    pow_solution: account.solvePow(ch.nonce, ch.pow.difficulty),
    ...overrides,
  };
}

async function signUp(api, agent) {
  const ch = await getChallenge(api, agent);
  const res = await call(api.verify, { body: verifyBody(agent, ch) });
  return { ch, res };
}

// ---------------------------------------------------------------- happy path

test("HAPPY PATH: challenge -> sign -> pow -> verify creates agent + account and returns the api key once", async () => {
  const { api, store } = setup();
  const agent = newAgent();
  const ch = await getChallenge(api, agent);
  assert.match(ch.nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(ch.pow.difficulty, 8);
  assert.equal(typeof ch.pow.alg, "string");
  const ttl = Date.parse(ch.expires_at) - Date.now();
  assert.ok(ttl > 4 * 60 * 1000 && ttl <= 5 * 60 * 1000 + 1000, "5-minute expiry");

  const res = await call(api.verify, { body: verifyBody(agent, ch) });
  assert.equal(res._status, 201, JSON.stringify(res._body));
  assert.equal(res._body.agent_id, agent.public_key, "the public key is the agent id");
  assert.match(res._body.account_id, /^[0-9a-f-]{36}$/);
  assert.match(res._body.api_key, /^ak_[A-Za-z0-9_-]{43}$/);
  assert.equal(res._body.created, true);

  const found = await store.findAgent(agent.public_key);
  assert.equal(found.account_id, res._body.account_id);
  assert.equal(store._dump().challenges.length, 0, "the challenge is gone after use");
});

test("HAPPY PATH: the same key signing a fresh challenge gets its existing account back and a new key (created:false, 200)", async () => {
  const { api } = setup();
  const agent = newAgent();
  const first = (await signUp(api, agent)).res;
  const second = (await signUp(api, agent)).res;
  assert.equal(second._status, 200);
  assert.equal(second._body.created, false);
  assert.equal(second._body.account_id, first._body.account_id);
  assert.notEqual(second._body.api_key, first._body.api_key);
});

test("DEFAULT: ACCOUNT_POW_BITS unset (or 0, or junk) means 20 bits; proof of work cannot be configured off", () => {
  assert.equal(account.powBits({}), 20);
  assert.equal(account.powBits({ ACCOUNT_POW_BITS: "0" }), 20);
  assert.equal(account.powBits({ ACCOUNT_POW_BITS: "abc" }), 20);
  assert.equal(account.powBits({ ACCOUNT_POW_BITS: "33" }), 20);
  assert.equal(account.powBits({ ACCOUNT_POW_BITS: "12" }), 12);
});

// ---------------------------------------------------------------- refusals

test("REFUSED: a bad signature (signed by another key) is 401 signature_invalid and does NOT consume the challenge", async () => {
  const { api, store } = setup();
  const agent = newAgent();
  const other = newAgent();
  const ch = await getChallenge(api, agent);
  const res = await call(api.verify, {
    body: verifyBody(agent, ch, { signature: sign(other, account.DOMAIN + ch.nonce) }),
  });
  assert.equal(res._status, 401);
  assert.equal(res._body.reason, "signature_invalid");
  assert.equal(store._dump().challenges.length, 1, "a sniffed nonce cannot be burned without the private key");
  const ok = await call(api.verify, { body: verifyBody(agent, ch) });
  assert.equal(ok._status, 201, "the real owner can still use it");
});

test("REFUSED: a signature over the nonce with the wrong domain string is 401", async () => {
  const { api } = setup();
  const agent = newAgent();
  const ch = await getChallenge(api, agent);
  for (const msg of [ch.nonce, "arcaeon-account-v2\n" + ch.nonce, "arcaeon-account-v1" + ch.nonce, "arcaeon-account-v1\r\n" + ch.nonce]) {
    const res = await call(api.verify, { body: verifyBody(agent, ch, { signature: sign(agent, msg) }) });
    assert.equal(res._status, 401, `message ${JSON.stringify(msg.slice(0, 22))} must not verify`);
    assert.equal(res._body.reason, "signature_invalid");
  }
});

test("REFUSED: an expired nonce is 410 challenge_expired (and is used up)", async () => {
  const { api, clock } = setup();
  const agent = newAgent();
  const ch = await getChallenge(api, agent);
  clock.t += account.CHALLENGE_TTL_MS + 1;
  const res = await call(api.verify, { body: verifyBody(agent, ch) });
  assert.equal(res._status, 410);
  assert.equal(res._body.reason, "challenge_expired");
  const again = await call(api.verify, { body: verifyBody(agent, ch) });
  assert.equal(again._status, 409);
});

test("REFUSED: a replayed nonce — the second verify of the same body is 409 and issues no second key", async () => {
  const { api, store } = setup();
  const agent = newAgent();
  const ch = await getChallenge(api, agent);
  const body = verifyBody(agent, ch);
  const first = await call(api.verify, { body });
  assert.equal(first._status, 201);
  const replay = await call(api.verify, { body });
  assert.equal(replay._status, 409);
  assert.equal(replay._body.reason, "challenge_not_found_or_used");
  assert.equal(replay._body.api_key, undefined);
  assert.equal(store._dump().api_keys.length, 1);
});

test("RACE: two concurrent verifies of one nonce — exactly one succeeds", async () => {
  const { api, store } = setup();
  const agent = newAgent();
  const ch = await getChallenge(api, agent);
  const body = verifyBody(agent, ch);
  const results = await Promise.all([1, 2, 3].map(() => call(api.verify, { body })));
  const statuses = results.map((r) => r._status).sort();
  assert.deepEqual(statuses, [201, 409, 409], JSON.stringify(statuses));
  assert.equal(store._dump().api_keys.length, 1);
  assert.equal(store._dump().accounts.length, 1);
});

test("REFUSED: a nonce issued to one key cannot be used by another key (409, not consumed)", async () => {
  const { api, store } = setup();
  const a = newAgent();
  const b = newAgent();
  const ch = await getChallenge(api, a);
  const res = await call(api.verify, { body: verifyBody(b, ch) });
  assert.equal(res._status, 409);
  assert.equal(store._dump().challenges.length, 1);
});

test("REFUSED: bad or short proof of work is 400 pow_insufficient; a malformed solution is 400 bad_pow_solution", async () => {
  const { api } = setup();
  const agent = newAgent();
  const ch = await getChallenge(api, agent);
  // A solution that hashes to FEWER than `difficulty` leading zero bits.
  let bad;
  for (let i = 0; ; i++) {
    const s = "x" + i;
    if (!account.powOk(ch.nonce, s, ch.pow.difficulty)) { bad = s; break; }
  }
  const res = await call(api.verify, { body: verifyBody(agent, ch, { pow_solution: bad }) });
  assert.equal(res._status, 400);
  assert.equal(res._body.reason, "pow_insufficient");

  const ch2 = await getChallenge(api, agent);
  for (const pow_solution of ["", 42, null, "a".repeat(65)]) {
    const r = await call(api.verify, { body: verifyBody(agent, ch2, { pow_solution }) });
    assert.equal(r._status, 400);
    assert.equal(r._body.reason, "bad_pow_solution");
  }
});

test("POW: leading zero bit counting is exact at byte boundaries", () => {
  assert.equal(account.leadingZeroBits(Buffer.from([0x80])), 0);
  assert.equal(account.leadingZeroBits(Buffer.from([0x01])), 7);
  assert.equal(account.leadingZeroBits(Buffer.from([0x00, 0x00, 0x10])), 19);
  assert.equal(account.leadingZeroBits(Buffer.from([0x00, 0x00, 0x0f])), 20);
  assert.equal(account.leadingZeroBits(Buffer.alloc(4)), 32);
});

test("REFUSED: malformed key lengths and encodings are 400 bad_public_key on challenge and verify", async () => {
  const { api } = setup();
  const good = newAgent();
  const raw = Buffer.from(good.public_key, "base64url");
  const bads = [
    undefined, "", 123,
    raw.subarray(0, 31).toString("base64url"), // 31 bytes
    Buffer.concat([raw, Buffer.from([0])]).toString("base64url"), // 33 bytes
    raw.toString("base64"), // standard base64 with padding
    good.public_key + "=",
    "!".repeat(43),
    raw.toString("hex"), // 64 hex chars
  ];
  for (const public_key of bads) {
    const c = await call(api.challenge, { body: { public_key } });
    assert.equal(c._status, 400, `challenge: ${String(public_key)}`);
    assert.equal(c._body.reason, "bad_public_key");
  }
  const ch = await getChallenge(api, good);
  for (const public_key of bads) {
    const v = await call(api.verify, { body: verifyBody(good, ch, { public_key }) });
    assert.equal(v._status, 400, `verify: ${String(public_key)}`);
    assert.equal(v._body.reason, "bad_public_key");
  }
  const shortSig = await call(api.verify, { body: verifyBody(good, ch, { signature: "AAAA" }) });
  assert.equal(shortSig._body.reason, "bad_signature_encoding");
  const badNonce = await call(api.verify, { body: verifyBody(good, ch, { nonce: "short" }) });
  assert.equal(badNonce._body.reason, "bad_nonce");
});

test("RATE LIMIT: /challenge uses the shared free-endpoint per-IP limiter; the (LIMIT+1)th call from one IP is 429", async () => {
  const { api } = setup();
  const agent = newAgent();
  const ip = "192.0.2.77";
  for (let i = 0; i < ratelimit.LIMIT; i++) {
    const r = await call(api.challenge, { body: { public_key: agent.public_key }, ip });
    assert.equal(r._status, 201, `call ${i + 1}`);
  }
  const blocked = await call(api.challenge, { body: { public_key: agent.public_key }, ip });
  assert.equal(blocked._status, 429);
  assert.equal(blocked._body.reason, "rate_limited");
  assert.ok(Number(blocked._headers["retry-after"]) > 0);
  const other = await call(api.challenge, { body: { public_key: agent.public_key }, ip: "192.0.2.78" });
  assert.equal(other._status, 201);
});

test("HASH ONLY: the api key is stored as sha256 only; the raw key appears nowhere in the store", async () => {
  const { api, store } = setup();
  const agent = newAgent();
  const { res } = await signUp(api, agent);
  const rawKey = res._body.api_key;
  const dump = JSON.stringify(store._dump());
  assert.ok(!dump.includes(rawKey), "raw key must not be stored");
  assert.ok(!dump.includes(rawKey.slice(3)), "nor its body without the prefix");
  const rows = store._dump().api_keys;
  assert.equal(rows.length, 1);
  assert.equal(rows[0].key_hash, crypto.createHash("sha256").update(rawKey).digest("hex"));
  assert.deepEqual(Object.keys(rows[0]).sort(), ["account_id", "agent_public_key", "created_at", "key_hash", "revoked_at"]);
});

// ---------------------------------------------------------------- devices

test("DEVICES: auth required — no bearer 401 missing_api_key, wrong key 401 unknown_api_key, revoked key 401", async () => {
  const { api, store } = setup();
  const agent = newAgent();
  const { res } = await signUp(api, agent);
  const none = await call(api.devices, { method: "GET" });
  assert.equal(none._status, 401);
  assert.equal(none._body.reason, "missing_api_key");
  const wrong = await call(api.devices, { method: "GET", headers: { authorization: "Bearer ak_nope" } });
  assert.equal(wrong._status, 401);
  assert.equal(wrong._body.reason, "unknown_api_key");
  const post = await call(api.devices, { method: "POST", body: { name: "x", public_key: newAgent().public_key } });
  assert.equal(post._status, 401);
  await store._revoke(res._body.api_key);
  const revoked = await call(api.devices, { method: "GET", headers: { authorization: `Bearer ${res._body.api_key}` } });
  assert.equal(revoked._status, 401);
});

test("DEVICES: register then list, scoped to the key's account; duplicates 409; bad input 400", async () => {
  const { api } = setup();
  const a = (await signUp(api, newAgent())).res._body;
  const b = (await signUp(api, newAgent())).res._body;
  const auth = (k) => ({ authorization: `Bearer ${k}` });
  const dev = newAgent();

  const reg = await call(api.devices, { method: "POST", headers: auth(a.api_key), body: { name: "laptop", public_key: dev.public_key } });
  assert.equal(reg._status, 201, JSON.stringify(reg._body));
  assert.equal(reg._body.device.name, "laptop");
  assert.equal(reg._body.device.public_key, dev.public_key);

  const dup = await call(api.devices, { method: "POST", headers: auth(a.api_key), body: { name: "again", public_key: dev.public_key } });
  assert.equal(dup._status, 409);
  assert.equal(dup._body.reason, "device_exists");

  for (const body of [{ name: "", public_key: dev.public_key }, { name: "a".repeat(65), public_key: dev.public_key }, { name: "bad\nname", public_key: dev.public_key }]) {
    const r = await call(api.devices, { method: "POST", headers: auth(a.api_key), body });
    assert.equal(r._body.reason, "bad_name");
  }
  const badKey = await call(api.devices, { method: "POST", headers: auth(a.api_key), body: { name: "x", public_key: "abc" } });
  assert.equal(badKey._body.reason, "bad_public_key");

  const listA = await call(api.devices, { method: "GET", headers: auth(a.api_key) });
  assert.equal(listA._status, 200);
  assert.equal(listA._body.devices.length, 1);
  const listB = await call(api.devices, { method: "GET", headers: auth(b.api_key) });
  assert.equal(listB._body.devices.length, 0, "another account sees none of them");

  const del = await call(api.devices, { method: "DELETE", headers: auth(a.api_key) });
  assert.equal(del._status, 405);
});

test("DEVICES: an account holds at most MAX_DEVICES devices (409 device_limit)", async () => {
  const { api } = setup();
  const a = (await signUp(api, newAgent())).res._body;
  const headers = { authorization: `Bearer ${a.api_key}` };
  for (let i = 0; i < account.MAX_DEVICES; i++) {
    const r = await call(api.devices, { method: "POST", headers, body: { name: `d${i}`, public_key: newAgent().public_key } });
    assert.equal(r._status, 201);
  }
  const over = await call(api.devices, { method: "POST", headers, body: { name: "one more", public_key: newAgent().public_key } });
  assert.equal(over._status, 409);
  assert.equal(over._body.reason, "device_limit");
});

// ---------------------------------------------------------------- wiring

test("WIRING: no store configured means 503 account_store_not_configured, never an in-memory fallback", async () => {
  const api = account.createAccountApi({ getStore: () => null });
  const res = await call(api.challenge, { body: { public_key: newAgent().public_key } });
  assert.equal(res._status, 503);
  assert.equal(res._body.reason, "account_store_not_configured");
});

test("WIRING: api/balance.js dispatches ?op=account-* and vercel.json rewrites the public /api/account/* paths onto it", async () => {
  const saved = { u: process.env.SUPABASE_URL, k: process.env.SUPABASE_SERVICE_ROLE_KEY };
  delete process.env.SUPABASE_URL;
  delete process.env.SUPABASE_SERVICE_ROLE_KEY;
  try {
    const res = makeRes();
    await balanceHandler(makeReq({
      method: "POST", query: { op: "account-challenge" },
      headers: { "x-forwarded-for": "192.0.2.200" }, body: { public_key: newAgent().public_key },
    }), res);
    assert.equal(res._status, 503);
    assert.equal(res._body.reason, "account_store_not_configured");
  } finally {
    if (saved.u !== undefined) process.env.SUPABASE_URL = saved.u;
    if (saved.k !== undefined) process.env.SUPABASE_SERVICE_ROLE_KEY = saved.k;
  }
  const cfg = require("../vercel.json");
  const map = Object.fromEntries(cfg.rewrites.map((r) => [r.source, r.destination]));
  assert.equal(map["/api/account/challenge"], "/api/balance?op=account-challenge");
  assert.equal(map["/api/account/verify"], "/api/balance?op=account-verify");
  assert.equal(map["/api/account/devices"], "/api/balance?op=account-devices");
});

test("WIRING: api/ stays at or under the 12-function cap (the reason the account routes are co-hosted)", () => {
  const fs = require("fs");
  const path = require("path");
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith(".js") && !e.name.startsWith("_") ? [e.name] : []);
  const fns = walk(path.join(__dirname, "..", "api"));
  assert.ok(fns.length <= 12, `api/ has ${fns.length} functions: ${fns.join(", ")}`);
});

