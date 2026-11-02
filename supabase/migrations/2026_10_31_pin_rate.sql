-- pin_rate_windows: the per key pin limit, one count per key per clock hour,
-- shared by every instance (lib/_pin_ratelimit.js). Used only when
-- WITNESS_USAGE_STORE=postgres.
--
-- key_hash is the sha256 of the caller's key; the key itself is never sent.

create table if not exists public.pin_rate_windows (
  key_hash      text not null check (key_hash ~ '^[0-9a-f]{64}$'),
  window_start  timestamptz not null,
  hits          integer not null check (hits >= 1),
  primary key (key_hash, window_start)
);

create index if not exists pin_rate_windows_window_start
  on public.pin_rate_windows (window_start);

alter table public.pin_rate_windows enable row level security;
revoke all on public.pin_rate_windows from anon, authenticated;

-- One atomic increment. INSERT ... ON CONFLICT DO UPDATE locks the row, so two
-- concurrent calls for one key and window get two different counts. Windows
-- older than a day are cleared on the way: these are counters, not records.
create or replace function public.pin_rate_hit(p_key_hash text, p_window_start timestamptz)
returns integer
language plpgsql
as $$
declare
  n integer;
begin
  insert into public.pin_rate_windows as w (key_hash, window_start, hits)
  values (p_key_hash, p_window_start, 1)
  on conflict (key_hash, window_start) do update set hits = w.hits + 1
  returning w.hits into n;
  delete from public.pin_rate_windows where window_start < p_window_start - interval '1 day';
  return n;
end;
$$;

revoke all on function public.pin_rate_hit(text, timestamptz) from public, anon, authenticated;
