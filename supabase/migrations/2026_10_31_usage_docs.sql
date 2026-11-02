-- usage_docs: the witness's private, per-pin bookkeeping, moved off the
-- private GitHub usage repo (WITNESS_METER_OFF_GITHUB.md). Read and written by
-- lib/_usage_store.js only when WITNESS_USAGE_STORE=postgres.
--
-- One row per document, keyed by the path it had in the usage repo:
--   usage/<sha256 of key>/<YYYY-MM>.json   the meter's monthly count
--   pending/open_batch.json                the open Merkle batch
--   pending/seal_claim.json                the single sealer claim
--
-- `version` is the compare and swap counter. The code creates a row with
-- version 1 (a duplicate path is the lost create race) and updates only with
-- WHERE path = $1 AND version = $2, setting version = $2 + 1, so of two
-- writers holding the same version exactly one matches.
--
-- What is stored: counts, timestamps, key hashes, and leaf fingerprints, the
-- same class of data the public pin repo already publishes. Never log content,
-- never a raw key.
--
-- Standalone: this table references nothing in the account schema and the
-- account schema references nothing here. It only shares the database.

create table if not exists public.usage_docs (
  path        text primary key check (length(path) between 1 and 512),
  doc         jsonb not null,
  version     bigint not null check (version >= 1),
  note        text not null default '',
  updated_at  timestamptz not null default now()
);

-- Only the service role reaches this table (it bypasses row level security).
-- With security on and no policies, the public and signed in roles see nothing.
alter table public.usage_docs enable row level security;
revoke all on public.usage_docs from anon, authenticated;
