// _accountdb.js — the account store (phase 1: agent identity + device
// registry). Underscore prefix = not routed as a serverless function.
//
// One interface, two implementations:
//
//   memoryStore()            in-process Maps, for tests. Every mutating step
//                            runs synchronously before its first await, so
//                            two concurrent calls on one event loop cannot
//                            interleave inside a step.
//   postgrestStore({url,key}) Supabase Postgres over fetch to PostgREST, using
//                            the service role key. The key goes in request
//                            headers only; it never appears in a thrown error,
//                            a return value or a log line.
//
// Interface (every method async):
//
//   createChallenge({nonce, public_key, pow_bits, expires_at})  -> {nonce, expires_at}
//   takeChallenge(nonce, public_key, nowMs)
//       -> {ok:true, challenge} | {ok:false, reason:"not_found"|"expired"}
//       Single use: the row is removed by the same step that reads it, so a
//       second take of the same nonce returns not_found. An expired row is
//       still removed (it can never be used) and answers "expired".
//   createAgentWithAccount(public_key) -> {account_id, agent_id, created}
//       The agent's id is its public key. A key that already has an agent
//       gets its existing account back with created:false.
//   issueApiKey({account_id, agent_public_key}) -> {api_key, key_hash}
//       The raw key is returned this once. Only sha256(raw) is stored.
//   resolveApiKey(raw) -> {account_id, agent_public_key} | null   (revoked -> null)
//   findAgent(public_key) -> {public_key, account_id, created_at, last_seen} | null
//   registerDevice({account_id, name, public_key, max})
//       -> {ok:true, device} | {ok:false, reason:"device_exists"|"device_limit"|"unknown_account"}
//   listDevices(account_id) -> [{id, name, public_key, created_at, last_seen}]
//
// Phase 2 (billing and the pin allowance; rules in lib/_account_billing.js):
//
//   applyStripeEvent({event_id, type, fact, now})
//       -> {outcome, account_id}. outcome "duplicate" for a recorded event
//       id, "unresolved" when no account matches (nothing recorded), else
//       what the fact did (subscription_applied, pack_credited, ignored_*...).
//   debitPins({account_id, request_id, n, now})
//       -> {ok, reason, replay, from_monthly, from_packs, monthly_used,
//           monthly_allowance, pack_balance, window_end}
//       reason on a refusal: no_pins_left | pack_held | bad_count |
//       bad_request_id | idempotency_key_mismatch | unknown_account.
//   pinStatus({account_id, now}) -> {plan, status, monthly_used,
//       monthly_allowance, monthly_left, window_start, window_end,
//       pack_balance, period_end, cancel_at_period_end} | null
//   listPacks(account_id) -> [{purchase_ref, pack_id, units_total, units_remaining, state}]
//   getAccount(account_id) -> {id, stripe_customer_id, stripe_subscription_id, plan, status} | null
//   setStripeCustomer({account_id, customer_id})
//       -> {ok:true, customer_id, set} | {ok:false, reason:"unknown_account"|"customer_taken"}
//       The ONLY writer of accounts.stripe_customer_id (the checkout endpoint,
//       lib/_account_checkout.js). Set-if-null: when one is already there it
//       is returned with set:false and nothing changes. The webhook never
//       writes this column.
//
//   In Postgres each is one function in
//   supabase/migrations/2026_10_31_account_v2.sql (one transaction, the
//   account row locked first).
//
// Atomicity in Postgres (see the migration's header for the same text):
//   - takeChallenge is ONE conditional DELETE with return=representation.
//     Postgres row locking means two concurrent deletes of the same row
//     cannot both return it, so only one verify can get the challenge.
//   - createAgentWithAccount and registerDevice need several statements in
//     one transaction, which plain PostgREST table calls cannot give, so they
//     call the RPC functions account_create_agent / account_register_device
//     defined in supabase/migrations/2026_10_30_account_v1.sql.
//   - issueApiKey is a single INSERT and does not need one. It is not in the
//     same transaction as createAgentWithAccount: if the key insert fails
//     after the agent was created, the agent exists with no key, and signing
//     a fresh challenge with the same key issues one (created:false).

"use strict";

const crypto = require("crypto");
const billing = require("./_account_billing.js");

const API_KEY_PREFIX = "ak_";

function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s), "utf8").digest("hex");
}

function mintApiKey() {
  return API_KEY_PREFIX + crypto.randomBytes(32).toString("base64url");
}

// --------------------------------------------------------------- in memory

function memoryStore() {
  const challenges = new Map(); // nonce -> row
  const accounts = new Map(); // id -> row
  const agents = new Map(); // public_key -> row
  const apiKeys = new Map(); // key_hash -> row
  const devices = new Map(); // id -> row
  const stripeEvents = new Map(); // event_id -> row
  const billingStates = new Map(); // account_id -> {account, packs, ledger}
  let packSeq = 0;

  const iso = () => new Date().toISOString();

  return {
    kind: "memory",
    // Read-only view for tests (what is actually held, not what a method says).
    _dump() {
      return {
        challenges: [...challenges.values()],
        accounts: [...accounts.values()],
        agents: [...agents.values()],
        api_keys: [...apiKeys.values()],
        devices: [...devices.values()],
      };
    },

    async createChallenge({ nonce, public_key, pow_bits, expires_at }) {
      const now = Date.now();
      for (const [n, c] of challenges) if (Date.parse(c.expires_at) <= now) challenges.delete(n);
      if (challenges.has(nonce)) throw new Error("nonce collision");
      challenges.set(nonce, { nonce, public_key, pow_bits, created_at: iso(), expires_at });
      return { nonce, expires_at };
    },

    async takeChallenge(nonce, public_key, nowMs) {
      const c = challenges.get(nonce);
      if (!c || c.public_key !== public_key) return { ok: false, reason: "not_found" };
      challenges.delete(nonce); // the take: synchronous, before any await
      await new Promise((r) => setImmediate(r)); // let a racing caller run here
      if (Date.parse(c.expires_at) <= nowMs) return { ok: false, reason: "expired" };
      return { ok: true, challenge: { ...c } };
    },

    async createAgentWithAccount(public_key) {
      const existing = agents.get(public_key);
      if (existing) {
        existing.last_seen = iso();
        return { account_id: existing.account_id, agent_id: public_key, created: false };
      }
      const id = crypto.randomUUID();
      const t = iso();
      accounts.set(id, newAccountRow(id, t));
      agents.set(public_key, { public_key, account_id: id, created_at: t, last_seen: t });
      return { account_id: id, agent_id: public_key, created: true };
    },

    async issueApiKey({ account_id, agent_public_key = null }) {
      const api_key = mintApiKey();
      const key_hash = sha256Hex(api_key);
      apiKeys.set(key_hash, { key_hash, account_id, agent_public_key, created_at: iso(), revoked_at: null });
      return { api_key, key_hash };
    },

    async resolveApiKey(raw) {
      const row = apiKeys.get(sha256Hex(raw));
      if (!row || row.revoked_at) return null;
      return { account_id: row.account_id, agent_public_key: row.agent_public_key };
    },

    // Test helper: revoke by raw key.
    async _revoke(raw) {
      const row = apiKeys.get(sha256Hex(raw));
      if (row) row.revoked_at = iso();
    },

    async findAgent(public_key) {
      const a = agents.get(public_key);
      return a ? { ...a } : null;
    },

    async registerDevice({ account_id, name, public_key, max }) {
      if (!accounts.has(account_id)) return { ok: false, reason: "unknown_account" };
      const mine = [...devices.values()].filter((d) => d.account_id === account_id);
      if (mine.some((d) => d.public_key === public_key)) return { ok: false, reason: "device_exists" };
      if (mine.length >= max) return { ok: false, reason: "device_limit" };
      const d = { id: crypto.randomUUID(), account_id, name, public_key, created_at: iso(), last_seen: null };
      devices.set(d.id, d);
      const { account_id: _a, ...device } = d;
      return { ok: true, device };
    },

    async listDevices(account_id) {
      return [...devices.values()]
        .filter((d) => d.account_id === account_id)
        .map(({ account_id: _a, ...d }) => d);
    },

    // The billing columns the checkout endpoint needs; null for no such account.
    async getAccount(account_id) {
      const a = accounts.get(account_id);
      if (!a) return null;
      const { id, stripe_customer_id, stripe_subscription_id, plan, status } = a;
      return { id, stripe_customer_id, stripe_subscription_id, plan, status };
    },

    // The only writer of stripe_customer_id. Set-if-null: an account that
    // already has one keeps it and the caller is told which (set:false).
    // A customer another account holds is refused (one customer, one account).
    async setStripeCustomer({ account_id, customer_id }) {
      const a = accounts.get(account_id);
      if (!a) return { ok: false, reason: "unknown_account" };
      if (a.stripe_customer_id) return { ok: true, customer_id: a.stripe_customer_id, set: false };
      if ([...accounts.values()].some((o) => o.id !== account_id && o.stripe_customer_id === customer_id)) {
        return { ok: false, reason: "customer_taken" };
      }
      a.stripe_customer_id = customer_id;
      a.updated_at = iso();
      return { ok: true, customer_id, set: true };
    },

    // ---- phase 2: billing and the pin allowance. Each method below runs
    // to completion synchronously before it returns its promise, so two
    // concurrent calls cannot interleave: the in-memory stand-in for the
    // account row lock the Postgres functions take.

    // Test helper: an account with no agent (people-only accounts later).
    async _createAccount() {
      const id = crypto.randomUUID();
      accounts.set(id, newAccountRow(id, iso()));
      return id;
    },

    async applyStripeEvent({ event_id, type, fact, now }) {
      if (stripeEvents.has(event_id)) {
        return { outcome: "duplicate", account_id: stripeEvents.get(event_id).account_id };
      }
      if (fact.kind === "unverified_reference") {
        const outcome = "ignored_unverified_reference";
        stripeEvents.set(event_id, { event_id, type, account_id: null, outcome, received_at: iso() });
        return { outcome, account_id: null };
      }
      const account_id = resolveAccount(fact);
      if (!account_id) return { outcome: "unresolved", account_id: null };
      const st = billingState(account_id);
      const outcome = billing.applyFactToState(st, fact, now, { nextSeq: () => ++packSeq });
      stripeEvents.set(event_id, { event_id, type, account_id, outcome, received_at: iso() });
      return { outcome, account_id };
    },

    async debitPins({ account_id, request_id, n, now }) {
      if (!accounts.has(account_id)) return { ok: false, reason: "unknown_account" };
      return billing.debitState(billingState(account_id), { request_id, n, now });
    },

    async pinStatus({ account_id, now }) {
      if (!accounts.has(account_id)) return null;
      const st = billingState(account_id);
      billing.rollState(st, now);
      return billing.statusView(st);
    },

    async listPacks(account_id) {
      return billingState(account_id).packs
        .slice().sort((x, y) => x.seq - y.seq)
        .map(({ purchase_ref, pack_id, units_total, units_remaining, state }) =>
          ({ purchase_ref, pack_id, units_total, units_remaining, state }));
    },

    // Test helpers: what is actually held.
    _ledger(account_id) { return [...billingState(account_id).ledger.values()]; },
    _stripeEvents() { return [...stripeEvents.values()]; },
    _account(account_id) { return accounts.get(account_id) ? { ...accounts.get(account_id) } : null; },
  };

  function billingState(account_id) {
    let st = billingStates.get(account_id);
    if (!st) {
      st = { account: accounts.get(account_id), packs: [], ledger: new Map() };
      billingStates.set(account_id, st);
    }
    return st;
  }

  function resolveAccount(fact) {
    if (fact.kind === "pack_refund" || fact.kind === "pack_dispute") {
      for (const [id, st] of billingStates) {
        if (st.packs.some((p) => p.payment_intent === fact.payment_intent)) return id;
      }
      return null;
    }
    if (fact.account_hint && accounts.has(fact.account_hint)) return fact.account_hint;
    if (fact.kind !== "pack_credit" && fact.customer_id) {
      for (const a of accounts.values()) if (a.stripe_customer_id === fact.customer_id) return a.id;
    }
    return null;
  }
}

// One account row. Times the billing code compares (period_*, window_*,
// sub_event_at) are epoch ms in memory and timestamptz in Postgres.
function newAccountRow(id, t) {
  return {
    id, stripe_customer_id: null, stripe_subscription_id: null, plan: "free", status: "active",
    period_start: null, period_end: null, cancel_at_period_end: false, sub_event_at: null,
    window_start: null, window_end: null,
    monthly_used: 0, monthly_allowance: billing.FREE_MONTHLY_PINS, pack_balance: 0, created_at: t, updated_at: t,
  };
}

// --------------------------------------------------------------- PostgREST

class StoreError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "StoreError";
    this.status = status;
    this.storeError = true;
  }
}

function postgrestStore({ url, key, fetchImpl } = {}) {
  if (!url || !key) throw new Error("postgrestStore needs url and key");
  const base = String(url).replace(/\/+$/, "") + "/rest/v1";
  const doFetch = fetchImpl || ((u, o) => fetch(u, o));

  // `what` names the step in an error; the key and headers never do.
  async function call(what, method, path, { body, prefer } = {}) {
    const headers = {
      apikey: key,
      authorization: `Bearer ${key}`,
      "content-type": "application/json",
      accept: "application/json",
    };
    if (prefer) headers.prefer = prefer;
    let res;
    try {
      res = await doFetch(base + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (_e) {
      throw new StoreError(`account store unreachable (${what})`, 0);
    }
    const text = await res.text();
    let json = null;
    if (text) {
      try { json = JSON.parse(text); } catch (_e) { json = null; }
    }
    if (!res.ok) {
      const code = json && typeof json.code === "string" ? ` ${json.code}` : "";
      const err = new StoreError(`account store ${what} failed: HTTP ${res.status}${code}`, res.status);
      err.pgCode = json && json.code;
      throw err;
    }
    return json;
  }

  const eq = (v) => "eq." + encodeURIComponent(String(v));

  return {
    kind: "postgrest",

    async createChallenge({ nonce, public_key, pow_bits, expires_at }) {
      // Best-effort sweep of expired rows; a failure here never blocks issuing.
      try {
        await call("sweep", "DELETE",
          `/auth_challenges?expires_at=lt.${encodeURIComponent(new Date().toISOString())}`,
          { prefer: "return=minimal" });
      } catch (_e) { /* swept next time */ }
      await call("createChallenge", "POST", "/auth_challenges", {
        body: { nonce, public_key, pow_bits, expires_at },
        prefer: "return=minimal",
      });
      return { nonce, expires_at };
    },

    async takeChallenge(nonce, public_key, nowMs) {
      const rows = await call("takeChallenge", "DELETE",
        `/auth_challenges?nonce=${eq(nonce)}&public_key=${eq(public_key)}`,
        { prefer: "return=representation" });
      if (!Array.isArray(rows) || rows.length === 0) return { ok: false, reason: "not_found" };
      const c = rows[0];
      if (Date.parse(c.expires_at) <= nowMs) return { ok: false, reason: "expired" };
      return { ok: true, challenge: c };
    },

    async createAgentWithAccount(public_key) {
      const rows = await call("createAgentWithAccount", "POST", "/rpc/account_create_agent", {
        body: { p_public_key: public_key },
      });
      const r = Array.isArray(rows) ? rows[0] : rows;
      if (!r || !r.account_id) throw new StoreError("account store createAgentWithAccount returned no row", 502);
      return { account_id: r.account_id, agent_id: r.agent_id, created: r.created === true };
    },

    async issueApiKey({ account_id, agent_public_key = null }) {
      const api_key = mintApiKey();
      const key_hash = sha256Hex(api_key);
      await call("issueApiKey", "POST", "/api_keys", {
        body: { key_hash, account_id, agent_public_key },
        prefer: "return=minimal",
      });
      return { api_key, key_hash };
    },

    async resolveApiKey(raw) {
      const rows = await call("resolveApiKey", "GET",
        `/api_keys?key_hash=${eq(sha256Hex(raw))}&revoked_at=is.null&select=account_id,agent_public_key`);
      return Array.isArray(rows) && rows[0] ? rows[0] : null;
    },

    async findAgent(public_key) {
      const rows = await call("findAgent", "GET",
        `/agents?public_key=${eq(public_key)}&select=public_key,account_id,created_at,last_seen`);
      return Array.isArray(rows) && rows[0] ? rows[0] : null;
    },

    async registerDevice({ account_id, name, public_key, max }) {
      const rows = await call("registerDevice", "POST", "/rpc/account_register_device", {
        body: { p_account_id: account_id, p_name: name, p_public_key: public_key, p_max: max },
      });
      const r = Array.isArray(rows) ? rows[0] : rows;
      if (!r) throw new StoreError("account store registerDevice returned no row", 502);
      if (r.refused) return { ok: false, reason: r.refused };
      const { refused: _r, ...device } = r;
      return { ok: true, device };
    },

    async listDevices(account_id) {
      const rows = await call("listDevices", "GET",
        `/devices?account_id=${eq(account_id)}&select=id,name,public_key,created_at,last_seen&order=created_at.asc`);
      return Array.isArray(rows) ? rows : [];
    },

    async getAccount(account_id) {
      const rows = await call("getAccount", "GET",
        `/accounts?id=${eq(account_id)}&select=id,stripe_customer_id,stripe_subscription_id,plan,status`);
      return Array.isArray(rows) && rows[0] ? rows[0] : null;
    },

    // One RPC (account_set_stripe_customer): row lock, set only when null.
    async setStripeCustomer({ account_id, customer_id }) {
      const rows = await call("setStripeCustomer", "POST", "/rpc/account_set_stripe_customer", {
        body: { p_account_id: account_id, p_customer: customer_id },
      });
      const r = Array.isArray(rows) ? rows[0] : rows;
      if (!r || !r.outcome) throw new StoreError("account store setStripeCustomer returned no row", 502);
      if (r.outcome === "set") return { ok: true, customer_id: r.customer_id, set: true };
      if (r.outcome === "already_set") return { ok: true, customer_id: r.customer_id, set: false };
      return { ok: false, reason: r.outcome };
    },

    // ---- phase 2. Each is ONE database function, one transaction, under
    // the account row lock (supabase/migrations/2026_10_31_account_v2.sql).

    async applyStripeEvent({ event_id, type, fact, now }) {
      const rows = await call("applyStripeEvent", "POST", "/rpc/account_apply_stripe_event", {
        body: { p_event_id: event_id, p_type: type, p_fact: fact, p_now: new Date(now).toISOString() },
      });
      const r = Array.isArray(rows) ? rows[0] : rows;
      if (!r || !r.outcome) throw new StoreError("account store applyStripeEvent returned no row", 502);
      return { outcome: r.outcome, account_id: r.account_id || null };
    },

    async debitPins({ account_id, request_id, n, now }) {
      const rows = await call("debitPins", "POST", "/rpc/account_debit_pins", {
        body: { p_account_id: account_id, p_request_id: request_id, p_n: n, p_now: new Date(now).toISOString() },
      });
      const r = Array.isArray(rows) ? rows[0] : rows;
      if (!r) throw new StoreError("account store debitPins returned no row", 502);
      return {
        ok: r.ok === true, reason: r.reason || null, replay: r.replay === true,
        from_monthly: Number(r.from_monthly) || 0, from_packs: Number(r.from_packs) || 0,
        monthly_used: r.monthly_used, monthly_allowance: r.monthly_allowance,
        pack_balance: Number(r.pack_balance), window_end: r.window_end,
      };
    },

    async pinStatus({ account_id, now }) {
      const rows = await call("pinStatus", "POST", "/rpc/account_pin_status", {
        body: { p_account_id: account_id, p_now: new Date(now).toISOString() },
      });
      const r = Array.isArray(rows) ? rows[0] : rows;
      if (!r || r.outcome !== "ok" || !r.plan) return null;
      const { outcome: _o, ...view } = r;
      return { ...view, pack_balance: Number(view.pack_balance) };
    },

    async listPacks(account_id) {
      const rows = await call("listPacks", "GET",
        `/account_packs?account_id=${eq(account_id)}&select=purchase_ref,pack_id,units_total,units_remaining,state&order=seq.asc`);
      return Array.isArray(rows) ? rows.map((p) => ({ ...p, units_total: Number(p.units_total), units_remaining: Number(p.units_remaining) })) : [];
    },
  };
}

// The store the endpoints use: PostgREST when both env vars are set, else
// null (the endpoints then refuse with 503 account_store_not_configured,
// never a silent in-memory fallback in production).
function fromEnv(env = process.env) {
  const url = env.SUPABASE_URL;
  const key = env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return null;
  return postgrestStore({ url, key });
}

module.exports = { memoryStore, postgrestStore, fromEnv, sha256Hex, mintApiKey, API_KEY_PREFIX, StoreError };
