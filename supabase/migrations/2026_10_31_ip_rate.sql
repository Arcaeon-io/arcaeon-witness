-- ip_rate_windows: the per IP limit on the public read endpoints, one count
-- per IP per 10 minute slot, shared by every instance (lib/_ratelimit.js
-- checkShared). Used only when WITNESS_USAGE_STORE=postgres AND
-- WITNESS_IP_RATE_SECRET are set; otherwise nothing is written here.
--
-- What is stored, per row: ip_hash = HMAC-SHA256 of the IP under the server
-- secret WITNESS_IP_RATE_SECRET (the IP itself is never sent, and without the
-- secret the value cannot be recomputed from a guessed IP), the slot's start
-- time, and the hit count. Nothing else.
--
-- How long: ip_rate_sweep() deletes every row whose slot started more than one
-- hour ago. It is scheduled every 10 minutes below (pg_cron), so a row lives
-- at most about 80 minutes. ip_rate_hit itself never deletes: the per request
-- path is one upsert and nothing more, so a read flood cannot pile extra work
-- onto the database the per key pin limit fails closed on.

create table if not exists public.ip_rate_windows (
  ip_hash       text not null check (ip_hash ~ '^[0-9a-f]{64}$'),
  window_start  timestamptz not null,
  hits          integer not null check (hits >= 1),
  primary key (ip_hash, window_start)
);

create index if not exists ip_rate_windows_window_start on public.ip_rate_windows (window_start);

alter table public.ip_rate_windows enable row level security;
revoke all on public.ip_rate_windows from anon, authenticated;

-- One atomic increment by p_cost (bulk verify weighs a call by its items).
create or replace function public.ip_rate_hit(p_ip_hash text, p_window_start timestamptz, p_cost integer)
returns integer
language plpgsql
as $$
declare
  n integer;
begin
  if p_cost is null or p_cost < 1 then
    raise exception 'p_cost must be at least 1';
  end if;
  insert into public.ip_rate_windows as w (ip_hash, window_start, hits)
  values (p_ip_hash, p_window_start, p_cost)
  on conflict (ip_hash, window_start) do update set hits = w.hits + p_cost
  returning w.hits into n;
  return n;
end;
$$;

revoke all on function public.ip_rate_hit(text, timestamptz, integer) from public, anon, authenticated;

-- The scheduled cleanup. Returns the number of rows removed.
create or replace function public.ip_rate_sweep()
returns integer
language plpgsql
as $$
declare
  n integer;
begin
  delete from public.ip_rate_windows where window_start < now() - interval '1 hour';
  get diagnostics n = row_count;
  return n;
end;
$$;

revoke all on function public.ip_rate_sweep() from public, anon, authenticated;

-- Schedule it every 10 minutes when pg_cron is installed. Without pg_cron this
-- does nothing and the operator must run `select public.ip_rate_sweep();` on a
-- schedule some other way, by hand or from an outside scheduler (README,
-- "Stage-0 limits"). Nothing else deletes these rows.
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('ip_rate_sweep', '*/10 * * * *', 'select public.ip_rate_sweep()');
  end if;
end;
$$;
