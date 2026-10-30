// test/account_schema.test.js — reads supabase/migrations/2026_10_30_account_v1.sql
// as text. There is no Postgres in this harness, so this checks the promises
// the file makes in words: counts and paid accounts, never content; RLS on
// every table with no public policy; the RPC functions locked to service_role.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const SQL = fs.readFileSync(path.join(__dirname, "..", "supabase", "migrations", "2026_10_30_account_v1.sql"), "utf8");
const CODE = SQL.replace(/--[^\n]*/g, ""); // comments out
const TABLES = ["accounts", "agents", "people", "api_keys", "auth_challenges", "stripe_events", "devices"];
const FORBIDDEN = new Set(["content", "text", "body", "note", "notes", "message", "messages", "payload", "data", "record", "records"]);

// Column names of `create table public.<t> ( ... );`, one per line that
// starts with an identifier and is not a table constraint.
function columns(table) {
  const m = CODE.match(new RegExp(`create table if not exists public\\.${table}\\s*\\(([\\s\\S]*?)\\n\\);`));
  assert.ok(m, `table ${table} not found`);
  return m[1].split("\n")
    .map((l) => l.trim())
    .filter((l) => /^[a-z_]+\s/.test(l) && !/^(check|unique|primary|foreign|constraint)\b/.test(l))
    .map((l) => l.split(/\s+/)[0]);
}

test("SCHEMA: all seven tables from the decision exist", () => {
  for (const t of TABLES) assert.ok(columns(t).length > 0, t);
});

test("NO CONTENT: no table has a column named content/text/body/note (or any close cousin)", () => {
  for (const t of TABLES) {
    for (const c of columns(t)) assert.ok(!FORBIDDEN.has(c), `${t}.${c} is a content-shaped column`);
  }
  // And nothing slips in through ALTER TABLE ... ADD COLUMN either.
  const added = [...CODE.matchAll(/add\s+column\s+(?:if\s+not\s+exists\s+)?([a-z_]+)/gi)].map((m) => m[1].toLowerCase());
  for (const c of added) assert.ok(!FORBIDDEN.has(c), `added column ${c}`);
});

test("SCHEMA: the columns the decision names are present", () => {
  const want = {
    accounts: ["id", "stripe_customer_id", "plan", "status", "period_end", "monthly_used", "monthly_allowance", "pack_balance", "created_at"],
    agents: ["public_key", "account_id", "created_at", "last_seen"],
    people: ["auth_user_id", "account_id"],
    api_keys: ["key_hash", "account_id", "agent_public_key", "created_at", "revoked_at"],
    auth_challenges: ["nonce", "public_key", "expires_at"],
    stripe_events: ["event_id"],
    devices: ["id", "account_id", "name", "public_key", "last_seen"],
  };
  for (const [t, cols] of Object.entries(want)) {
    const have = columns(t);
    for (const c of cols) assert.ok(have.includes(c), `${t}.${c}`);
  }
});

test("RLS: enabled on every table, and no policy anywhere (service role only)", () => {
  for (const t of TABLES) {
    assert.match(CODE, new RegExp(`alter table public\\.${t}\\s+enable row level security`), t);
  }
  assert.doesNotMatch(CODE, /create\s+policy/i);
  assert.match(CODE, /revoke all on public\.accounts[\s\S]*?from anon, authenticated;/);
});

test("RPC: the functions are executable by service_role only", () => {
  for (const fn of ["account_create_agent", "account_register_device"]) {
    assert.match(CODE, new RegExp(`revoke all on function public\\.${fn}\\([^)]*\\)\\s+from public, anon, authenticated`), fn);
    assert.match(CODE, new RegExp(`grant execute on function public\\.${fn}\\([^)]*\\)\\s+to service_role`), fn);
  }
  assert.doesNotMatch(CODE, /security\s+definer/i, "no definer functions: the caller is already service_role");
});

test("SCHEMA: api keys are stored as a 64-hex sha256 only; agent ids are 43-char base64url keys", () => {
  assert.match(CODE, /key_hash\s+text\s+primary key check \(key_hash ~ '\^\[0-9a-f\]\{64\}\$'\)/);
  assert.match(CODE, /public_key\s+text\s+primary key check \(public_key ~ '\^\[A-Za-z0-9_-\]\{43\}\$'\)/);
  assert.doesNotMatch(CODE, /\bapi_key\s+text/, "no raw api_key column");
});
