-- ip_rate_windows: the per IP limit on the public read endpoints, one count
-- per IP per 10 minute slot, shared by every instance (lib/_ratelimit.js
-- checkShared). Used only when WITNESS_USAGE_STORE=postgres.
--
-- ip_hash is the sha256 of "ip-rate:v1\n" and the IP; the IP itself is never
-- sent. Rows older than a day are cleared by the same call.

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
  delete from public.ip_rate_windows where window_start < p_window_start - interval '1 day';
  return n;
end;
$$;

revoke all on function public.ip_rate_hit(text, timestamptz, integer) from public, anon, authenticated;
