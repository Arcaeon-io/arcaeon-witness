// test/account_v2_schema.test.js — reads supabase/migrations/2026_10_31_account_v2.sql
// as text (no Postgres in this harness) and holds it to its promises: counts
// only, RLS on the new tables with no policy, every function locked to
// service_role, the row lock and the idempotency keys present, and the
// owner's numbers the same as lib/_account_billing.js.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const billing = require("../lib/_account_billing.js");

const SQL = fs.readFileSync(path.join(__dirname, "..", "supabase", "migrations", "2026_10_31_account_v2.sql"), "utf8");
const CODE = SQL.replace(/--[^\n]*/g, "");
const NEW_TABLES = ["account_packs", "pin_ledger"];
const FORBIDDEN = new Set(["content", "text", "body", "note", "notes", "message", "messages", "payload", "data", "record", "records"]);
const FUNCTIONS = ["account_roll", "account_recompute_packs", "account_debit_pins", "account_pin_status",
  "account_check_customer", "account_set_stripe_customer", "account_apply_subscription", "account_apply_pack_credit",
  "account_apply_pack_refund", "account_apply_pack_dispute", "account_apply_stripe_event"];

function columns(table) {
  const m = CODE.match(new RegExp(`create table if not exists public\\.${table}\\s*\\(([\\s\\S]*?)\\n\\);`));
  assert.ok(m, `table ${table} not found`);
  return m[1].split("\n").map((l) => l.trim())
    .filter((l) => /^[a-z_]+\s/.test(l) && !/^(check|unique|primary|foreign|constraint)\b/.test(l))
    .map((l) => l.split(/\s+/)[0]);
}

test("V2 NO CONTENT: no new or added column is content-shaped", () => {
  for (const t of NEW_TABLES) for (const c of columns(t)) assert.ok(!FORBIDDEN.has(c), `${t}.${c}`);
  const added = [...CODE.matchAll(/add\s+column\s+(?:if\s+not\s+exists\s+)?([a-z_]+)/gi)].map((m) => m[1].toLowerCase());
  assert.ok(added.length >= 6);
  for (const c of added) assert.ok(!FORBIDDEN.has(c), c);
});

test("V2 RLS: on for the new tables, revoked from anon and authenticated, no policy, no security definer", () => {
  for (const t of NEW_TABLES) assert.match(CODE, new RegExp(`alter table public\\.${t}\\s+enable row level security`), t);
  assert.match(CODE, /revoke all on public\.account_packs, public\.pin_ledger from anon, authenticated;/);
  assert.doesNotMatch(CODE, /create\s+policy/i);
  assert.doesNotMatch(CODE, /security\s+definer/i);
});

test("V2 RPC: every function is revoked from public/anon/authenticated and granted to service_role only", () => {
  for (const fn of FUNCTIONS) {
    assert.match(CODE, new RegExp(`create or replace function public\\.${fn}\\(`), fn);
    assert.match(CODE, new RegExp(`revoke all on function public\\.${fn}\\([^)]*\\) from public, anon, authenticated;`), fn);
    assert.match(CODE, new RegExp(`grant execute on function public\\.${fn}\\([^)]*\\) to service_role;`), fn);
  }
  assert.doesNotMatch(CODE, /grant[^;]*to (anon|authenticated)/i);
});

test("V2 ATOMIC: the debit takes the account row lock and the packs in order; events and debits have unique keys", () => {
  const debit = CODE.slice(CODE.indexOf("function public.account_debit_pins("), CODE.indexOf("function public.account_pin_status("));
  assert.match(debit, /from public\.accounts ac where ac\.id = p_account_id for update;/);
  assert.match(debit, /order by ap\.seq for update/);
  assert.match(debit, /'debit:' \|\|/);
  assert.match(CODE, /unique \(account_id, idempotency_key\)/);
  const apply = CODE.slice(CODE.indexOf("function public.account_apply_stripe_event("));
  assert.match(apply, /on conflict \(event_id\) do nothing;/);
  assert.match(apply, /perform 1 from public\.accounts ac where ac\.id = v_acc for update;/);
  assert.match(CODE, /on conflict \(purchase_ref\) do nothing;/);
});

test("V2 ONE WRITER: only account_set_stripe_customer writes stripe_customer_id; the event path only compares; no relink remains", () => {
  const writes = [...CODE.matchAll(/set\s+stripe_customer_id\s*=/gi)];
  assert.equal(writes.length, 1, "exactly one UPDATE sets stripe_customer_id");
  const setter = CODE.slice(CODE.indexOf("function public.account_set_stripe_customer("), CODE.indexOf("function public.account_apply_subscription("));
  assert.match(setter, /set\s+stripe_customer_id\s*=/i);
  assert.match(setter, /for update/);
  assert.doesNotMatch(CODE, /relink/i);
  assert.doesNotMatch(CODE, /linked_elsewhere/);
  const check = CODE.slice(CODE.indexOf("function public.account_check_customer("), CODE.indexOf("function public.account_set_stripe_customer("));
  assert.doesNotMatch(check, /update\s/i, "the check never writes");
  assert.match(check, /ignored_customer_mismatch/);
});

test("V2 NUMBERS: 3000 paid, 10 free, pack units by id, statuses: the SQL and the JS say the same", () => {
  const roll = CODE.slice(CODE.indexOf("function public.account_roll("), CODE.indexOf("function public.account_recompute_packs("));
  assert.match(roll, new RegExp(`v_allow := ${billing.PAID_MONTHLY_PINS};`));
  assert.match(roll, new RegExp(`v_allow := ${billing.FREE_MONTHLY_PINS};`));
  assert.match(roll, /set timezone = 'UTC'/);
  assert.match(roll, /make_interval\(months => v_k\)/);
  for (const [id, p] of Object.entries(billing.ACCOUNT_PACKS)) {
    assert.match(CODE, new RegExp(`when '${id}' then ${p.pins}`), id);
  }
  for (const s of billing.STATUSES) assert.match(CODE, new RegExp(`'${s}'`), s);
  assert.match(CODE, /alter column monthly_allowance set default 10;/);
  assert.match(CODE, /update public\.accounts set monthly_allowance = 10 where plan = 'free' and monthly_allowance in \(100, 30\);/);
  // Paid (a plan in force) is active or trialing; past_due keeps its current window only.
  assert.match(roll, /a\.status in \('active', 'trialing'\)/);
  assert.doesNotMatch(roll, /'trialing', 'past_due'/);
  assert.match(roll, /a\.status = 'past_due'/);
});
