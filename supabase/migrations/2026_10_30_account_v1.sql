-- 2026_10_30_account_v1.sql: the Arcaeon account, phase 1 (schema + agent identity).
--
-- Counts and paid accounts, never content. No table here has a column that
-- holds what an agent logs, says, or sends. test/account_schema.test.js reads
-- this file and refuses a column named content, text, body, note, notes,
-- message, payload or data.
--
-- Access: row level security is ENABLED on every table and NO policy is
-- defined, so the anon and authenticated roles see nothing. Only the service
-- role (which bypasses RLS) reads or writes, and only from the serverless
-- functions. The two RPC functions below are executable by service_role only.
--
-- Atomicity: taking a challenge is a single conditional DELETE through
-- PostgREST (delete ... where nonce = ? and public_key = ? returning *). Two
-- concurrent deletes of one row cannot both return it, so two verifies of one
-- nonce cannot both succeed. Creating an agent together with its account, and
-- registering a device under a per-account cap, each need more than one
-- statement in one transaction, which PostgREST cannot do over plain table
-- calls, so they are the RPC functions account_create_agent and
-- account_register_device.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------- accounts
create table if not exists public.accounts (
  id                 uuid        primary key default gen_random_uuid(),
  stripe_customer_id text        unique,
  plan               text        not null default 'free'
                                 check (plan in ('free', 'monthly', 'yearly')),
  status             text        not null default 'active'
                                 check (status in ('active', 'past_due', 'canceled')),
  period_end         timestamptz,
  monthly_used       integer     not null default 0   check (monthly_used >= 0),
  monthly_allowance  integer     not null default 100 check (monthly_allowance >= 0),
  pack_balance       bigint      not null default 0   check (pack_balance >= 0),
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  check (stripe_customer_id is null or stripe_customer_id ~ '^cus_[A-Za-z0-9]{1,64}$')
);

-- ------------------------------------------------------------------ agents
-- The agent's id IS its public key: base64url of the raw 32-byte Ed25519 key
-- (43 characters, no padding).
create table if not exists public.agents (
  public_key  text        primary key check (public_key ~ '^[A-Za-z0-9_-]{43}$'),
  account_id  uuid        not null references public.accounts (id) on delete restrict,
  created_at  timestamptz not null default now(),
  last_seen   timestamptz not null default now()
);
create index if not exists agents_account_id_idx on public.agents (account_id);

-- ------------------------------------------------------------------ people
-- A signed-in person (Supabase Auth, magic link). Not used by phase 1 code;
-- the table exists so the account has its second kind of member from day one.
create table if not exists public.people (
  auth_user_id uuid        primary key references auth.users (id) on delete cascade,
  account_id   uuid        not null references public.accounts (id) on delete restrict,
  created_at   timestamptz not null default now()
);
create index if not exists people_account_id_idx on public.people (account_id);

-- ---------------------------------------------------------------- api_keys
-- Only sha256(raw key), hex. The raw key is returned once and never stored.
create table if not exists public.api_keys (
  key_hash         text        primary key check (key_hash ~ '^[0-9a-f]{64}$'),
  account_id       uuid        not null references public.accounts (id) on delete cascade,
  agent_public_key text        references public.agents (public_key) on delete cascade,
  created_at       timestamptz not null default now(),
  revoked_at       timestamptz,
  check (revoked_at is null or revoked_at >= created_at)
);
create index if not exists api_keys_account_id_idx on public.api_keys (account_id);
create index if not exists api_keys_agent_idx on public.api_keys (agent_public_key);

-- --------------------------------------------------------- auth_challenges
-- Single use: taken by a conditional DELETE. pow_bits is the difficulty told
-- to the caller when the challenge was issued, so a later env change cannot
-- move the bar under an in-flight sign-up.
create table if not exists public.auth_challenges (
  nonce       text        primary key check (nonce ~ '^[A-Za-z0-9_-]{43}$'),
  public_key  text        not null check (public_key ~ '^[A-Za-z0-9_-]{43}$'),
  pow_bits    integer     not null check (pow_bits between 1 and 32),
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null,
  check (expires_at > created_at)
);
create index if not exists auth_challenges_expires_at_idx on public.auth_challenges (expires_at);

-- ----------------------------------------------------------- stripe_events
-- Idempotency for the webhook (phase 2). Keyed by the event id.
create table if not exists public.stripe_events (
  event_id     text        primary key check (event_id ~ '^evt_[A-Za-z0-9]{1,255}$'),
  type         text        not null check (char_length(type) between 1 and 128),
  received_at  timestamptz not null default now(),
  processed_at timestamptz
);

-- ----------------------------------------------------------------- devices
-- A registry only: a name, a public key, when it was last seen. No relay, no
-- transfer, nothing a device sends is kept here.
create table if not exists public.devices (
  id          uuid        primary key default gen_random_uuid(),
  account_id  uuid        not null references public.accounts (id) on delete cascade,
  name        text        not null check (char_length(name) between 1 and 64),
  public_key  text        not null check (public_key ~ '^[A-Za-z0-9_-]{43}$'),
  created_at  timestamptz not null default now(),
  last_seen   timestamptz,
  unique (account_id, public_key)
);
create index if not exists devices_account_id_idx on public.devices (account_id);

-- ------------------------------------------------------ row level security
alter table public.accounts        enable row level security;
alter table public.agents          enable row level security;
alter table public.people          enable row level security;
alter table public.api_keys        enable row level security;
alter table public.auth_challenges enable row level security;
alter table public.stripe_events   enable row level security;
alter table public.devices         enable row level security;

revoke all on public.accounts, public.agents, public.people, public.api_keys,
  public.auth_challenges, public.stripe_events, public.devices
  from anon, authenticated;

-- ------------------------------------------------------------ rpc functions
-- account_create_agent: the agent row plus an account if the agent has none,
-- in one transaction. A key that already has an agent gets its existing
-- account back (created = false) and last_seen moves.
create or replace function public.account_create_agent(p_public_key text)
returns table (account_id uuid, agent_id text, created boolean)
language plpgsql
set search_path = public
as $$
#variable_conflict use_column
declare
  v_account uuid;
begin
  select a.account_id into v_account
    from public.agents a where a.public_key = p_public_key for update;
  if found then
    update public.agents set last_seen = now() where public_key = p_public_key;
    return query select v_account, p_public_key, false;
    return;
  end if;

  insert into public.accounts default values returning id into v_account;
  begin
    insert into public.agents (public_key, account_id) values (p_public_key, v_account);
  exception when unique_violation then
    -- A concurrent call created this agent first: drop our account (this
    -- whole function is one transaction, so nothing else saw it) and return
    -- the winner's.
    delete from public.accounts where id = v_account;
    select a.account_id into v_account from public.agents a where a.public_key = p_public_key;
    return query select v_account, p_public_key, false;
    return;
  end;
  return query select v_account, p_public_key, true;
end;
$$;

-- account_register_device: insert a device under a per-account cap, with the
-- account row locked so two concurrent registrations cannot both pass the
-- count. Always returns one row; on a refusal every column is null except
-- `refused`, which names it, so the caller can say why instead of a raise.
create or replace function public.account_register_device(
  p_account_id uuid, p_name text, p_public_key text, p_max integer
)
returns table (id uuid, name text, public_key text, created_at timestamptz,
               last_seen timestamptz, refused text)
language plpgsql
set search_path = public
as $$
#variable_conflict use_column
declare
  v_count   integer;
  v_id      uuid;
  v_created timestamptz;
  v_seen    timestamptz;
begin
  perform 1 from public.accounts where accounts.id = p_account_id for update;
  if not found then
    return query select null::uuid, null::text, null::text, null::timestamptz,
                        null::timestamptz, 'unknown_account'::text;
    return;
  end if;
  if exists (select 1 from public.devices d
              where d.account_id = p_account_id and d.public_key = p_public_key) then
    return query select null::uuid, null::text, null::text, null::timestamptz,
                        null::timestamptz, 'device_exists'::text;
    return;
  end if;
  select count(*) into v_count from public.devices d where d.account_id = p_account_id;
  if v_count >= p_max then
    return query select null::uuid, null::text, null::text, null::timestamptz,
                        null::timestamptz, 'device_limit'::text;
    return;
  end if;
  insert into public.devices as d (account_id, name, public_key)
    values (p_account_id, p_name, p_public_key)
    returning d.id, d.created_at, d.last_seen into v_id, v_created, v_seen;
  return query select v_id, p_name, p_public_key, v_created, v_seen, null::text;
end;
$$;

revoke all on function public.account_create_agent(text) from public, anon, authenticated;
revoke all on function public.account_register_device(uuid, text, text, integer)
  from public, anon, authenticated;
grant execute on function public.account_create_agent(text) to service_role;
grant execute on function public.account_register_device(uuid, text, text, integer)
  to service_role;
