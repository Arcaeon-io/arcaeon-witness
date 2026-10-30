// test/accountdb_postgrest.test.js — the PostgREST store in lib/_accountdb.js,
// against a recording fake fetch. Checks the request shapes the atomicity
// argument rests on (the challenge take is one conditional DELETE returning
// the row), and that the service role key goes in headers only, never into an
// error message.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const accountdb = require("../lib/_accountdb.js");

const URL_ = "https://example-project.invalid";
const KEY = "test-service-role-placeholder-not-a-real-key";

function fakeFetch(responder) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url: String(url), ...opts });
    const { status = 200, body = null } = responder(String(url), opts) || {};
    const text = body === null ? "" : JSON.stringify(body);
    return { ok: status >= 200 && status < 300, status, text: async () => text };
  };
  fn.calls = calls;
  return fn;
}

test("POSTGREST: takeChallenge is ONE conditional DELETE (nonce AND public_key) with return=representation", async () => {
  const exp = new Date(Date.now() + 60000).toISOString();
  const f = fakeFetch(() => ({ body: [{ nonce: "n", public_key: "p", pow_bits: 8, expires_at: exp }] }));
  const s = accountdb.postgrestStore({ url: URL_, key: KEY, fetchImpl: f });
  const r = await s.takeChallenge("n", "p", Date.now());
  assert.equal(r.ok, true);
  assert.equal(f.calls.length, 1);
  const c = f.calls[0];
  assert.equal(c.method, "DELETE");
  assert.equal(c.url, `${URL_}/rest/v1/auth_challenges?nonce=eq.n&public_key=eq.p`);
  assert.equal(c.headers.prefer, "return=representation");
  assert.equal(c.headers.apikey, KEY);
  assert.equal(c.headers.authorization, `Bearer ${KEY}`);
});

test("POSTGREST: an empty DELETE result is not_found (the loser of a race); an expired row is expired", async () => {
  const s1 = accountdb.postgrestStore({ url: URL_, key: KEY, fetchImpl: fakeFetch(() => ({ body: [] })) });
  assert.deepEqual(await s1.takeChallenge("n", "p", Date.now()), { ok: false, reason: "not_found" });
  const past = new Date(Date.now() - 1000).toISOString();
  const s2 = accountdb.postgrestStore({ url: URL_, key: KEY, fetchImpl: fakeFetch(() => ({ body: [{ expires_at: past, pow_bits: 8 }] })) });
  assert.deepEqual(await s2.takeChallenge("n", "p", Date.now()), { ok: false, reason: "expired" });
});

test("POSTGREST: agent+account and device registration go through the migration's RPC functions", async () => {
  const f = fakeFetch((url) => {
    if (url.endsWith("/rpc/account_create_agent")) return { body: [{ account_id: "a1", agent_id: "pk", created: true }] };
    if (url.endsWith("/rpc/account_register_device")) return { body: [{ id: null, refused: "device_limit" }] };
    return { status: 201 };
  });
  const s = accountdb.postgrestStore({ url: URL_, key: KEY, fetchImpl: f });
  assert.deepEqual(await s.createAgentWithAccount("pk"), { account_id: "a1", agent_id: "pk", created: true });
  assert.deepEqual(JSON.parse(f.calls[0].body), { p_public_key: "pk" });
  assert.deepEqual(await s.registerDevice({ account_id: "a1", name: "n", public_key: "pk", max: 50 }), { ok: false, reason: "device_limit" });
});

test("POSTGREST: issueApiKey sends only the sha256 of the key it returns", async () => {
  const f = fakeFetch(() => ({ status: 201 }));
  const s = accountdb.postgrestStore({ url: URL_, key: KEY, fetchImpl: f });
  const { api_key, key_hash } = await s.issueApiKey({ account_id: "a1", agent_public_key: "pk" });
  const sent = f.calls[0].body;
  assert.ok(!sent.includes(api_key));
  assert.deepEqual(JSON.parse(sent), { key_hash: accountdb.sha256Hex(api_key), account_id: "a1", agent_public_key: "pk" });
  assert.equal(key_hash, accountdb.sha256Hex(api_key));
});

test("POSTGREST: a failed call throws a StoreError naming the step and status, never the key", async () => {
  const s = accountdb.postgrestStore({ url: URL_, key: KEY, fetchImpl: fakeFetch(() => ({ status: 500, body: { code: "XX000", message: "boom" } })) });
  await assert.rejects(s.findAgent("pk"), (err) => {
    assert.equal(err.storeError, true);
    assert.match(err.message, /findAgent failed: HTTP 500/);
    assert.ok(!err.message.includes(KEY));
    assert.ok(!JSON.stringify(err).includes(KEY));
    return true;
  });
  const down = accountdb.postgrestStore({ url: URL_, key: KEY, fetchImpl: async () => { throw new Error(`connect failed ${KEY}`); } });
  await assert.rejects(down.listDevices("a1"), (err) => !err.message.includes(KEY));
});

test("POSTGREST: fromEnv needs both SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY, else null", () => {
  assert.equal(accountdb.fromEnv({}), null);
  assert.equal(accountdb.fromEnv({ SUPABASE_URL: URL_ }), null);
  assert.equal(accountdb.fromEnv({ SUPABASE_URL: URL_, SUPABASE_SERVICE_ROLE_KEY: KEY }).kind, "postgrest");
});
