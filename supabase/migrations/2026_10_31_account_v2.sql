-- 2026_10_31_account_v2.sql: the Arcaeon account, phase 2 (the Stripe
-- subscription lifecycle and the pin allowance). Runs after
-- 2026_10_30_account_v1.sql.
--
-- Counts and paid accounts, never content. Like v1, no column here holds
-- what an agent logs, says or sends; test/account_v2_schema.test.js reads
-- this file and refuses a content-shaped column name.
--
-- The rules (the owner's): $9/month (lookup key account_monthly) or $99/year
-- (account_yearly). 3,000 pins a month, reset monthly, use it or lose it; the
-- yearly plan resets to 3,000 on our own monthly anniversary clock inside the
-- paid year (period_start + k months), no pool. Packs (pins_200 = 200,
-- pins_1000 = 1,000) never expire and are spent only after the month's 3,000.
-- No plan in force: the free 30 a month, on the UTC calendar month.
--
-- Atomicity. Every write goes through one of three functions, each one
-- transaction, each taking the account row lock (select ... for update)
-- before touching the account or its packs:
--   account_debit_pins       monthly first, then live packs oldest first; all
--                            or nothing, never negative; idempotent by
--                            request id (pin_ledger unique key).
--   account_apply_stripe_event  records the Stripe event id and applies its
--                            fact in the same transaction; a repeat event id
--                            is a no-op (stripe_events primary key, insert
--                            ... on conflict do nothing).
--   account_pin_status       rolls the monthly window if it has passed, then
--                            reads.
-- lib/_account_billing.js holds the same rules in JS (the in-memory store the
-- tests run); the two are kept line for line in step.
--
-- Access: as v1. RLS on, no policy, revoked from anon and authenticated;
-- functions executable by service_role only; no security definer.

-- ------------------------------------------------------- accounts: columns
alter table public.accounts drop constraint if exists accounts_status_check;
alter table public.accounts add constraint accounts_status_check
  check (status in ('active', 'trialing', 'past_due', 'unpaid', 'incomplete',
                    'incomplete_expired', 'paused', 'canceled'));
alter table public.accounts alter column monthly_allowance set default 30;

alter table public.accounts add column if not exists stripe_subscription_id text
  check (stripe_subscription_id is null or stripe_subscription_id ~ '^sub_[A-Za-z0-9]{1,255}$');
alter table public.accounts add column if not exists period_start timestamptz;
alter table public.accounts add column if not exists cancel_at_period_end boolean not null default false;
alter table public.accounts add column if not exists sub_event_at timestamptz;
alter table public.accounts add column if not exists window_start timestamptz;
alter table public.accounts add column if not exists window_end timestamptz;

-- Free accounts made under v1 had 100; the owner's free number is 30.
update public.accounts set monthly_allowance = 30 where plan = 'free' and monthly_allowance = 100;

-- ----------------------------------------------------------- account_packs
-- One row per pack bought. Keyed by the Checkout Session id, so the same
-- purchase delivered twice (two events, a retry, the return page) is one row.
create table if not exists public.account_packs (
  purchase_ref      text        primary key check (purchase_ref ~ '^cs_[A-Za-z0-9_]{1,255}$'),
  account_id        uuid        not null references public.accounts (id) on delete restrict,
  pack_id           text        not null check (pack_id in ('pins_200', 'pins_1000')),
  units_total       bigint      not null check (units_total > 0),
  units_remaining   bigint      not null check (units_remaining >= 0 and units_remaining <= units_total),
  units_refunded    bigint      not null default 0 check (units_refunded >= 0 and units_refunded <= units_total),
  state             text        not null default 'live' check (state in ('live', 'held', 'voided', 'refunded')),
  payment_intent    text        check (payment_intent is null or payment_intent ~ '^pi_[A-Za-z0-9_]{1,255}$'),
  amount_paid_cents integer     not null check (amount_paid_cents >= 0),
  dispute_status    text        check (dispute_status is null or dispute_status in
                                  ('needs_response', 'under_review', 'warning_needs_response',
                                   'warning_under_review', 'won', 'lost', 'warning_closed')),
  dispute_event_at  timestamptz,
  created_at        timestamptz not null default now(),
  seq               bigserial   not null
);
create index if not exists account_packs_account_seq_idx on public.account_packs (account_id, seq);
create unique index if not exists account_packs_payment_intent_idx
  on public.account_packs (payment_intent) where payment_intent is not null;

-- -------------------------------------------------------------- pin_ledger
-- Every debit and credit, as counts. idempotency_key is unique per account:
--   debit:<request id>, pack:<session id>, reset:<window start>,
--   refund:<payment intent>:<cumulative cents>, dispute:<pi>:<status>:<at>.
-- monthly_delta / pack_delta are signed (a debit is negative). pack_parts
-- lists which packs a debit or refund touched: [{"pack": "cs_...", "n": 3}].
create table if not exists public.pin_ledger (
  id              bigserial   primary key,
  account_id      uuid        not null references public.accounts (id) on delete restrict,
  idempotency_key text        not null check (char_length(idempotency_key) between 1 and 300),
  entry           text        not null check (entry in ('debit', 'monthly_reset', 'pack_credit', 'pack_refund',
                                                        'pack_hold', 'pack_release', 'pack_void')),
  monthly_delta   integer     not null default 0,
  pack_delta      bigint      not null default 0,
  shortfall       bigint      not null default 0 check (shortfall >= 0),
  pack_parts      jsonb,
  created_at      timestamptz not null default now(),
  unique (account_id, idempotency_key)
);

-- ----------------------------------------------------- stripe_events: more
alter table public.stripe_events add column if not exists account_id uuid
  references public.accounts (id) on delete set null;
alter table public.stripe_events add column if not exists outcome text
  check (outcome is null or char_length(outcome) between 1 and 64);

-- ------------------------------------------------------ row level security
alter table public.account_packs enable row level security;
alter table public.pin_ledger    enable row level security;
revoke all on public.account_packs, public.pin_ledger from anon, authenticated;

-- --------------------------------------------------------- account_roll
-- Moves the account into the monthly window `p_now` falls in. Resets
-- monthly_used to 0 only when the window START moves forward, so a late or
-- repeated renewal never resets twice. The caller holds the row lock.
create or replace function public.account_roll(p_account_id uuid, p_now timestamptz)
returns void
language plpgsql
set search_path = public
set timezone = 'UTC'
as $$
declare
  a       public.accounts%rowtype;
  v_paid  boolean;
  v_s     timestamptz;
  v_e     timestamptz;
  v_allow integer;
  v_k     integer;
begin
  select * into a from public.accounts ac where ac.id = p_account_id for update;
  if not found then return; end if;
  v_paid := a.plan in ('monthly', 'yearly') and a.status in ('active', 'trialing', 'past_due')
            and a.period_start is not null and a.period_end is not null;
  if v_paid then
    if p_now >= a.period_end and a.cancel_at_period_end then
      -- A cancel is scheduled and the period is over: no new month.
      v_s := coalesce(a.window_start, a.period_start);
      v_e := a.period_end;
      v_allow := 0;
    else
      if p_now < a.period_start then
        v_k := 0;
      else
        v_k := ((extract(year from p_now) - extract(year from a.period_start)) * 12
                + extract(month from p_now) - extract(month from a.period_start))::integer;
        if a.period_start + make_interval(months => v_k) > p_now then v_k := v_k - 1; end if;
        if v_k < 0 then v_k := 0; end if;
      end if;
      v_s := a.period_start + make_interval(months => v_k);
      v_e := a.period_start + make_interval(months => v_k + 1);
      if p_now < a.period_end and v_e > a.period_end then v_e := a.period_end; end if;
      v_allow := 3000;
    end if;
  else
    v_s := date_trunc('month', p_now);
    v_e := v_s + interval '1 month';
    v_allow := 30;
  end if;

  if a.window_start is null or v_s > a.window_start then
    update public.accounts ac
       set window_start = v_s, window_end = v_e, monthly_used = 0,
           monthly_allowance = v_allow, updated_at = now()
     where ac.id = p_account_id;
    insert into public.pin_ledger (account_id, idempotency_key, entry, monthly_delta)
    values (p_account_id, 'reset:' || to_char(v_s, 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'monthly_reset', v_allow)
    on conflict (account_id, idempotency_key) do nothing;
  elsif a.window_end is distinct from v_e or a.monthly_allowance <> v_allow then
    update public.accounts ac
       set window_end = v_e, monthly_allowance = v_allow, updated_at = now()
     where ac.id = p_account_id;
  end if;
end;
$$;

create or replace function public.account_recompute_packs(p_account_id uuid)
returns void
language sql
set search_path = public
as $$
  update public.accounts ac
     set pack_balance = coalesce((select sum(ap.units_remaining) from public.account_packs ap
                                   where ap.account_id = p_account_id and ap.state = 'live'), 0),
         updated_at = now()
   where ac.id = p_account_id;
$$;

-- ------------------------------------------------------ account_debit_pins
create or replace function public.account_debit_pins(
  p_account_id uuid, p_request_id text, p_n integer, p_now timestamptz default now()
)
returns table (ok boolean, reason text, replay boolean, from_monthly integer, from_packs bigint,
               monthly_used integer, monthly_allowance integer, pack_balance bigint,
               window_end timestamptz)
language plpgsql
set search_path = public
set timezone = 'UTC'
as $$
#variable_conflict use_column
declare
  a        public.accounts%rowtype;
  l        public.pin_ledger%rowtype;
  p        public.account_packs%rowtype;
  v_key    text := 'debit:' || coalesce(p_request_id, '');
  v_left   integer;
  v_ptotal bigint;
  v_fm     integer;
  v_rest   bigint;
  v_take   bigint;
  v_parts  jsonb := '[]'::jsonb;
begin
  if p_n is null or p_n < 1 or p_n > 1000000 then
    return query select false, 'bad_count'::text, false, 0, 0::bigint, null::integer, null::integer,
                        null::bigint, null::timestamptz;
    return;
  end if;
  if p_request_id is null or p_request_id !~ '^[A-Za-z0-9_.:-]{1,128}$' then
    return query select false, 'bad_request_id'::text, false, 0, 0::bigint, null::integer, null::integer,
                        null::bigint, null::timestamptz;
    return;
  end if;

  select * into a from public.accounts ac where ac.id = p_account_id for update;
  if not found then
    return query select false, 'unknown_account'::text, false, 0, 0::bigint, null::integer, null::integer,
                        null::bigint, null::timestamptz;
    return;
  end if;

  select * into l from public.pin_ledger pl where pl.account_id = p_account_id and pl.idempotency_key = v_key;
  if found then
    if -(l.monthly_delta + l.pack_delta) <> p_n then
      return query select false, 'idempotency_key_mismatch'::text, false, 0, 0::bigint,
                          a.monthly_used, a.monthly_allowance, a.pack_balance, a.window_end;
    else
      return query select true, null::text, true, -l.monthly_delta, -l.pack_delta,
                          a.monthly_used, a.monthly_allowance, a.pack_balance, a.window_end;
    end if;
    return;
  end if;

  perform public.account_roll(p_account_id, p_now);
  select * into a from public.accounts ac where ac.id = p_account_id;

  v_left := greatest(0, a.monthly_allowance - a.monthly_used);
  select coalesce(sum(ap.units_remaining), 0) into v_ptotal from public.account_packs ap
   where ap.account_id = p_account_id and ap.state = 'live';
  if v_left + v_ptotal < p_n then
    return query select false,
      (case when exists (select 1 from public.account_packs ap where ap.account_id = p_account_id
                          and ap.state = 'held' and ap.units_remaining > 0)
            then 'pack_held' else 'no_pins_left' end)::text,
      false, 0, 0::bigint, a.monthly_used, a.monthly_allowance, a.pack_balance, a.window_end;
    return;
  end if;

  v_fm := least(p_n, v_left);
  v_rest := p_n - v_fm;
  for p in select * from public.account_packs ap
            where ap.account_id = p_account_id and ap.state = 'live' and ap.units_remaining > 0
            order by ap.seq for update
  loop
    exit when v_rest = 0;
    v_take := least(v_rest, p.units_remaining);
    update public.account_packs ap set units_remaining = ap.units_remaining - v_take
     where ap.purchase_ref = p.purchase_ref;
    v_parts := v_parts || jsonb_build_array(jsonb_build_object('pack', p.purchase_ref, 'n', v_take));
    v_rest := v_rest - v_take;
  end loop;

  update public.accounts ac set monthly_used = ac.monthly_used + v_fm, updated_at = now()
   where ac.id = p_account_id;
  perform public.account_recompute_packs(p_account_id);
  insert into public.pin_ledger (account_id, idempotency_key, entry, monthly_delta, pack_delta, pack_parts)
  values (p_account_id, v_key, 'debit', -v_fm, -(p_n - v_fm),
          case when jsonb_array_length(v_parts) > 0 then v_parts else null end);

  select * into a from public.accounts ac where ac.id = p_account_id;
  return query select true, null::text, false, v_fm, (p_n - v_fm)::bigint,
                      a.monthly_used, a.monthly_allowance, a.pack_balance, a.window_end;
end;
$$;

-- ------------------------------------------------------ account_pin_status
create or replace function public.account_pin_status(p_account_id uuid, p_now timestamptz default now())
returns table (plan text, status text, monthly_used integer, monthly_allowance integer, monthly_left integer,
               window_start timestamptz, window_end timestamptz, pack_balance bigint,
               period_end timestamptz, cancel_at_period_end boolean)
language plpgsql
set search_path = public
set timezone = 'UTC'
as $$
#variable_conflict use_column
begin
  perform public.account_roll(p_account_id, p_now);
  return query
    select ac.plan, ac.status, ac.monthly_used, ac.monthly_allowance,
           greatest(0, ac.monthly_allowance - ac.monthly_used), ac.window_start, ac.window_end,
           ac.pack_balance, ac.period_end, ac.cancel_at_period_end
      from public.accounts ac where ac.id = p_account_id;
end;
$$;

-- ------------------------------------------------- the event fact helpers
-- Each runs inside account_apply_stripe_event, which already holds the row
-- lock. Each returns the outcome name.

-- null when linked (or already linked to this customer); else the refusal.
create or replace function public.account_link_customer(p_account_id uuid, p_customer text)
returns text
language plpgsql
set search_path = public
as $$
declare
  v_cur text;
begin
  if p_customer is null then return null; end if;
  select ac.stripe_customer_id into v_cur from public.accounts ac where ac.id = p_account_id;
  if v_cur = p_customer then return null; end if;
  if v_cur is not null then return 'ignored_customer_mismatch'; end if;
  if exists (select 1 from public.accounts ac where ac.stripe_customer_id = p_customer and ac.id <> p_account_id) then
    return 'ignored_customer_linked_elsewhere';
  end if;
  update public.accounts ac set stripe_customer_id = p_customer, updated_at = now() where ac.id = p_account_id;
  return null;
end;
$$;

-- The subscription guards, in order: another subscription id only replaces
-- a terminal one (or a newer granting event); canceled is terminal; an older
-- event never overwrites a newer one; a period never moves backward.
create or replace function public.account_apply_subscription(p_account_id uuid, f jsonb)
returns text
language plpgsql
set search_path = public
set timezone = 'UTC'
as $$
declare
  a          public.accounts%rowtype;
  v_at       timestamptz := (f->>'at')::timestamptz;
  v_sub      text := f->>'subscription_id';
  v_ps       timestamptz := (f->>'period_start')::timestamptz;
  v_pe       timestamptz := (f->>'period_end')::timestamptz;
  v_status   text := f->>'status';
  v_plan     text := f->>'plan';
  v_req      boolean := coalesce((f->>'requires_paid_plan')::boolean, false);
  v_only     text[];
  v_switch   boolean := false;
  v_terminal boolean;
  v_newer    boolean;
  v_r        text;
begin
  select * into a from public.accounts ac where ac.id = p_account_id for update;
  if jsonb_typeof(f->'only_from') = 'array' then
    select array_agg(x) into v_only from jsonb_array_elements_text(f->'only_from') as t(x);
  end if;

  if a.stripe_customer_id is not null and f->>'customer_id' is not null
     and a.stripe_customer_id <> f->>'customer_id' then
    return 'ignored_customer_mismatch';
  end if;

  if a.stripe_subscription_id is not null and v_sub is distinct from a.stripe_subscription_id then
    v_terminal := a.status in ('canceled', 'incomplete_expired') or a.plan = 'free';
    v_newer := a.sub_event_at is null or (v_at is not null and v_at >= a.sub_event_at);
    if not v_terminal and not (v_status in ('active', 'trialing', 'past_due') and v_newer) then
      return 'ignored_other_subscription';
    end if;
    if v_req then return 'ignored_no_plan'; end if;
    v_switch := true;
  elsif a.stripe_subscription_id is not null then
    if a.status = 'canceled' then return 'ignored_terminal'; end if;
    if a.sub_event_at is not null and v_at is not null and v_at < a.sub_event_at then return 'ignored_stale'; end if;
    if v_only is not null and not (a.status = any (v_only)) then return 'ignored_status'; end if;
    if v_req and a.plan = 'free' then return 'ignored_no_plan'; end if;
  else
    if v_req then return 'ignored_no_plan'; end if;
    if v_only is not null and not (a.status = any (v_only)) then return 'ignored_status'; end if;
  end if;

  v_r := public.account_link_customer(p_account_id, f->>'customer_id');
  if v_r is not null then return v_r; end if;

  update public.accounts ac set
    stripe_subscription_id = v_sub,
    period_start = case when v_ps is not null and v_pe is not null
                         and (v_switch or ac.period_start is null or v_ps >= ac.period_start)
                        then v_ps else ac.period_start end,
    period_end   = case when v_ps is not null and v_pe is not null
                         and (v_switch or ac.period_start is null or v_ps >= ac.period_start)
                        then v_pe else ac.period_end end,
    plan = coalesce(v_plan, ac.plan),
    status = coalesce(v_status, ac.status),
    cancel_at_period_end = case when jsonb_typeof(f->'cancel_at_period_end') = 'boolean'
                                then (f->>'cancel_at_period_end')::boolean else ac.cancel_at_period_end end,
    sub_event_at = case when v_at is not null and (ac.sub_event_at is null or v_at > ac.sub_event_at)
                        then v_at else ac.sub_event_at end,
    updated_at = now()
  where ac.id = p_account_id;
  update public.accounts ac set plan = 'free', cancel_at_period_end = false
   where ac.id = p_account_id and ac.status = 'canceled';
  return 'subscription_applied';
end;
$$;

create or replace function public.account_apply_pack_credit(p_account_id uuid, f jsonb)
returns text
language plpgsql
set search_path = public
as $$
declare
  v_units bigint;
  v_n     integer;
begin
  -- Units from the catalogue by pack id, never from the event.
  v_units := case f->>'pack_id' when 'pins_200' then 200 when 'pins_1000' then 1000 else null end;
  if v_units is null then return 'ignored_unknown_pack'; end if;
  insert into public.account_packs (purchase_ref, account_id, pack_id, units_total, units_remaining,
                                    payment_intent, amount_paid_cents)
  values (f->>'purchase_ref', p_account_id, f->>'pack_id', v_units, v_units,
          f->>'payment_intent', (f->>'amount_paid_cents')::integer)
  on conflict (purchase_ref) do nothing;
  get diagnostics v_n = row_count;
  if v_n = 0 then return 'already_credited'; end if;
  perform public.account_recompute_packs(p_account_id);
  insert into public.pin_ledger (account_id, idempotency_key, entry, pack_delta)
  values (p_account_id, 'pack:' || (f->>'purchase_ref'), 'pack_credit', v_units)
  on conflict (account_id, idempotency_key) do nothing;
  return 'pack_credited';
end;
$$;

-- Refund: the units the refund pays for (pro rata to the amount paid,
-- rounded up, on the CUMULATIVE amount refunded) come off what is left.
-- Spent units cannot come back; the part already spent is the shortfall.
create or replace function public.account_apply_pack_refund(p_account_id uuid, f jsonb)
returns text
language plpgsql
set search_path = public
as $$
declare
  p        public.account_packs%rowtype;
  v_amount bigint := (f->>'amount')::bigint;
  v_ref    bigint := (f->>'amount_refunded')::bigint;
  v_target bigint;
  v_delta  bigint;
  v_take   bigint;
begin
  select * into p from public.account_packs ap where ap.payment_intent = f->>'payment_intent' for update;
  if not found then return 'ignored_no_pack'; end if;
  if v_amount is null or v_amount <= 0 or v_ref is null then return 'ignored_bad_amount'; end if;
  v_target := (p.units_total * greatest(0, least(v_ref, v_amount)) + v_amount - 1) / v_amount;
  v_delta := v_target - p.units_refunded;
  if v_delta <= 0 then return 'refund_no_change'; end if;
  v_take := least(v_delta, p.units_remaining);
  update public.account_packs ap
     set units_remaining = ap.units_remaining - v_take,
         units_refunded = v_target,
         state = case when ap.units_remaining - v_take = 0 and ap.state <> 'voided' then 'refunded' else ap.state end
   where ap.purchase_ref = p.purchase_ref;
  perform public.account_recompute_packs(p_account_id);
  insert into public.pin_ledger (account_id, idempotency_key, entry, pack_delta, shortfall, pack_parts)
  values (p_account_id, 'refund:' || (f->>'payment_intent') || ':' || v_ref, 'pack_refund', -v_take,
          v_delta - v_take, jsonb_build_array(jsonb_build_object('pack', p.purchase_ref, 'n', v_take)))
  on conflict (account_id, idempotency_key) do nothing;
  return 'pack_refunded';
end;
$$;

-- Dispute: open -> held (not spendable); won or warning_closed -> live
-- again; lost -> voided (a later won releases it). A final status is never
-- undone by an older or an open one.
create or replace function public.account_apply_pack_dispute(p_account_id uuid, f jsonb)
returns text
language plpgsql
set search_path = public
as $$
declare
  p       public.account_packs%rowtype;
  v_new   text := f->>'dispute_status';
  v_at    timestamptz := (f->>'at')::timestamptz;
  v_entry text;
  v_state text;
begin
  select * into p from public.account_packs ap where ap.payment_intent = f->>'payment_intent' for update;
  if not found then return 'ignored_no_pack'; end if;
  if p.dispute_status in ('won', 'lost', 'warning_closed') and v_new not in ('won', 'lost', 'warning_closed') then
    return 'ignored_stale';
  end if;
  if p.dispute_status is not null and p.dispute_event_at is not null and v_at is not null
     and v_at < p.dispute_event_at then
    return 'ignored_stale';
  end if;
  v_state := p.state;
  if v_new in ('needs_response', 'under_review', 'warning_needs_response', 'warning_under_review')
     and p.state = 'live' then
    v_state := 'held'; v_entry := 'pack_hold';
  elsif v_new in ('won', 'warning_closed') and p.state in ('held', 'voided') then
    v_state := 'live'; v_entry := 'pack_release';
  elsif v_new = 'lost' and p.state in ('held', 'live') then
    v_state := 'voided'; v_entry := 'pack_void';
  end if;
  update public.account_packs ap
     set dispute_status = v_new, dispute_event_at = coalesce(v_at, ap.dispute_event_at), state = v_state
   where ap.purchase_ref = p.purchase_ref;
  perform public.account_recompute_packs(p_account_id);
  if v_entry is null then return 'dispute_no_change'; end if;
  insert into public.pin_ledger (account_id, idempotency_key, entry, shortfall, pack_parts)
  values (p_account_id, 'dispute:' || (f->>'payment_intent') || ':' || v_new || ':' || coalesce(f->>'at', 'null'),
          v_entry,
          case when v_entry = 'pack_void' then greatest(0, p.units_total - p.units_remaining - p.units_refunded) else 0 end,
          jsonb_build_array(jsonb_build_object('pack', p.purchase_ref, 'n', p.units_remaining)))
  on conflict (account_id, idempotency_key) do nothing;
  return v_entry;
end;
$$;

-- ---------------------------------------------- account_apply_stripe_event
-- p_fact is the JSON lib/_account_billing.js factFromEvent() made from a
-- verified event. Returns (outcome, account_id); outcome 'duplicate' for an
-- event id already recorded, 'unresolved' when no account matches (nothing
-- is recorded then, so Stripe's retry can land after the account is linked).
create or replace function public.account_apply_stripe_event(
  p_event_id text, p_type text, p_fact jsonb, p_now timestamptz default now()
)
returns table (outcome text, account_id uuid)
language plpgsql
set search_path = public
set timezone = 'UTC'
as $$
#variable_conflict use_column
declare
  v_kind text := p_fact->>'kind';
  v_acc  uuid;
  v_hint uuid;
  v_out  text;
  v_n    integer;
begin
  select se.account_id into v_acc from public.stripe_events se where se.event_id = p_event_id;
  if found then
    return query select 'duplicate'::text, v_acc;
    return;
  end if;

  v_acc := null;
  if v_kind in ('pack_refund', 'pack_dispute') then
    select ap.account_id into v_acc from public.account_packs ap where ap.payment_intent = p_fact->>'payment_intent';
  else
    if coalesce(p_fact->>'account_hint', '') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
      v_hint := (p_fact->>'account_hint')::uuid;
      select ac.id into v_acc from public.accounts ac where ac.id = v_hint;
    end if;
    if v_acc is null and v_kind <> 'pack_credit' and p_fact->>'customer_id' is not null then
      select ac.id into v_acc from public.accounts ac where ac.stripe_customer_id = p_fact->>'customer_id';
    end if;
  end if;
  if v_acc is null then
    return query select 'unresolved'::text, null::uuid;
    return;
  end if;

  -- The event id and the change commit together, or neither does. A
  -- concurrent delivery of the same id waits here on the primary key and
  -- then inserts nothing.
  insert into public.stripe_events (event_id, type, account_id) values (p_event_id, p_type, v_acc)
  on conflict (event_id) do nothing;
  get diagnostics v_n = row_count;
  if v_n = 0 then
    return query select 'duplicate'::text, v_acc;
    return;
  end if;

  perform 1 from public.accounts ac where ac.id = v_acc for update;

  if v_kind = 'link' then
    v_out := public.account_link_customer(v_acc, p_fact->>'customer_id');
    if v_out is null then
      update public.accounts ac
         set stripe_subscription_id = coalesce(ac.stripe_subscription_id, p_fact->>'subscription_id'), updated_at = now()
       where ac.id = v_acc;
      v_out := 'linked';
    end if;
  elsif v_kind = 'subscription' then
    v_out := public.account_apply_subscription(v_acc, p_fact);
  elsif v_kind = 'pack_credit' then
    v_out := public.account_apply_pack_credit(v_acc, p_fact);
  elsif v_kind = 'pack_refund' then
    v_out := public.account_apply_pack_refund(v_acc, p_fact);
  elsif v_kind = 'pack_dispute' then
    v_out := public.account_apply_pack_dispute(v_acc, p_fact);
  else
    v_out := 'ignored_kind';
  end if;
  if v_out in ('linked', 'subscription_applied') then
    perform public.account_roll(v_acc, p_now);
  end if;

  update public.stripe_events se set processed_at = now(), outcome = v_out where se.event_id = p_event_id;
  return query select v_out, v_acc;
end;
$$;

-- ------------------------------------------------------------- privileges
revoke all on function public.account_roll(uuid, timestamptz) from public, anon, authenticated;
revoke all on function public.account_recompute_packs(uuid) from public, anon, authenticated;
revoke all on function public.account_debit_pins(uuid, text, integer, timestamptz) from public, anon, authenticated;
revoke all on function public.account_pin_status(uuid, timestamptz) from public, anon, authenticated;
revoke all on function public.account_link_customer(uuid, text) from public, anon, authenticated;
revoke all on function public.account_apply_subscription(uuid, jsonb) from public, anon, authenticated;
revoke all on function public.account_apply_pack_credit(uuid, jsonb) from public, anon, authenticated;
revoke all on function public.account_apply_pack_refund(uuid, jsonb) from public, anon, authenticated;
revoke all on function public.account_apply_pack_dispute(uuid, jsonb) from public, anon, authenticated;
revoke all on function public.account_apply_stripe_event(text, text, jsonb, timestamptz) from public, anon, authenticated;

-- The helpers run as the caller (no security definer), so service_role
-- needs execute on them too.
grant execute on function public.account_roll(uuid, timestamptz) to service_role;
grant execute on function public.account_recompute_packs(uuid) to service_role;
grant execute on function public.account_debit_pins(uuid, text, integer, timestamptz) to service_role;
grant execute on function public.account_pin_status(uuid, timestamptz) to service_role;
grant execute on function public.account_link_customer(uuid, text) to service_role;
grant execute on function public.account_apply_subscription(uuid, jsonb) to service_role;
grant execute on function public.account_apply_pack_credit(uuid, jsonb) to service_role;
grant execute on function public.account_apply_pack_refund(uuid, jsonb) to service_role;
grant execute on function public.account_apply_pack_dispute(uuid, jsonb) to service_role;
grant execute on function public.account_apply_stripe_event(text, text, jsonb, timestamptz) to service_role;
