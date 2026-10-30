# The Arcaeon account, phase 1: schema and agent identity

This is the first piece of the Arcaeon account. An agent can make itself an account by proving it holds an Ed25519 private key, and it gets an API key back. An account can keep a small list of its devices. That is all phase 1 does.

The account holds counts and paid status, never content. No table has a column for what an agent logs, says, or sends, and a test reads the migration and fails if one appears.

## What exists

| piece | file |
|---|---|
| Postgres schema | `supabase/migrations/2026_10_30_account_v1.sql` |
| store (in memory for tests, Supabase PostgREST for real) | `lib/_accountdb.js` |
| the three endpoints | `lib/_account_api.js` |
| tests | `test/account.test.js`, `test/account_schema.test.js`, `test/accountdb_postgrest.test.js` |

Tables: `accounts`, `agents`, `people`, `api_keys`, `auth_challenges`, `stripe_events`, `devices`. Row level security is on for every table and there are no policies, so only the service role can read or write them. The two database functions (`account_create_agent`, `account_register_device`) can only be run by the service role.

The endpoints live at `/api/account/challenge`, `/api/account/verify` and `/api/account/devices`. Under the hood `vercel.json` rewrites them onto `api/balance.js` with `?op=account-challenge`, `?op=account-verify` and `?op=account-devices`, because `api/` is already at the hosting plan's 12 function cap. This is the same trick `/api/stamp` and `/api/prefix-available` use.

## Signing up an agent

1. **Ask for a challenge.** `POST /api/account/challenge` with `{"public_key": "<base64url of the raw 32 byte Ed25519 public key, no padding>"}`. You get back `{nonce, expires_at, pow: {difficulty, alg}}`. The nonce is good for 5 minutes and only for this public key. This endpoint shares the per IP rate limit the other free endpoints use (`lib/_ratelimit.js`), so one address gets about 30 calls per 10 minutes per warm instance.
2. **Sign it.** Sign the UTF-8 bytes of `arcaeon-account-v1\n` followed by the nonce with your private key. The prefix is there so a signature made for this can never be replayed as a signature for anything else.
3. **Do the proof of work.** Find any string `pow_solution` (1 to 64 characters) where `sha256(nonce + pow_solution)` starts with `difficulty` zero bits. The default is 20 bits, about a million hashes, a few seconds in plain Node on an ordinary machine.
4. **Verify.** `POST /api/account/verify` with `{public_key, nonce, signature, pow_solution}`. The signature is base64url of the 64 byte signature. On success you get `{account_id, agent_id, api_key, created}`. The `agent_id` is your public key. **The API key is shown this once.** Only its sha256 is stored, so nobody can show it to you again.

If the same public key signs up again it keeps its account and gets a new API key, with `created: false` and status 200 instead of 201. Old keys keep working (revoking them is not built yet).

### How verify refuses

| status | reason | what it means |
|---|---|---|
| 400 | `bad_public_key`, `bad_nonce`, `bad_signature_encoding`, `bad_pow_solution`, `bad_body` | something is the wrong shape or length |
| 401 | `signature_invalid` | the signature does not check out for this key and nonce |
| 409 | `challenge_not_found_or_used` | no open challenge for this nonce and key: never issued, issued to a different key, or already used |
| 410 | `challenge_expired` | older than 5 minutes |
| 400 | `pow_insufficient` | the proof of work does not have enough zero bits |
| 503 | `account_store_not_configured` | the database env vars are not set on this deployment |
| 502 | `account_store_error` | the database call failed |

The signature is checked before the challenge is used up, so someone who only saw your nonce cannot burn it. After the signature passes, the nonce is gone whatever happens next: an expired nonce or a short proof of work costs you that challenge, and you ask for a new one.

### Single use, and why two verifies cannot both win

Taking a challenge is one SQL `DELETE ... WHERE nonce = ? AND public_key = ? RETURNING *`, sent through PostgREST with `Prefer: return=representation`. Postgres locks the row, so when two of these race only one gets the row back; the other gets nothing and answers 409. No database function was needed for this step.

Two steps did need one, because they are several statements that must happen together and plain PostgREST table calls cannot do that:

* `account_create_agent` makes the account and the agent in one transaction, or returns the existing account if the key already has an agent.
* `account_register_device` locks the account row, checks the device count and the duplicate key, and inserts.

Issuing the API key is a separate insert after the agent is made. If that one insert fails, the agent exists without a key, and signing a fresh challenge with the same key issues one.

## Devices

`GET /api/account/devices` lists the account's devices. `POST /api/account/devices` with `{name, public_key}` adds one. Both need `Authorization: Bearer <api key>`. A name is 1 to 64 printable characters, a public key is the same 32 byte Ed25519 format as above, a key can be on an account once, and an account holds at most 50 devices. This is only a list: name, key, when added, when last seen. Nothing is relayed or stored for a device.

## Environment

| variable | what it does |
|---|---|
| `SUPABASE_URL` | the project URL. Without it the account endpoints answer 503 |
| `SUPABASE_SERVICE_ROLE_KEY` | the service role key, sent only as request headers to PostgREST, never logged and never in an error message. Without it the endpoints answer 503 |
| `ACCOUNT_POW_BITS` | proof of work difficulty, a whole number from 1 to 32. Unset or anything else means 20. It can be made easier but never turned off |

The migration has not been applied to any database by this change.

## What is NOT built yet

* **Stripe subscription lifecycle.** The `stripe_events` table and the plan, status, allowance and period columns exist, but nothing writes them. Checkout, invoice paid, payment failed, and subscription updated or deleted all come later.
* **People sign in.** The `people` table exists. Magic link sign in, and a person attaching an agent by having it sign a link nonce, are not built.
* **Witness pin debit against Postgres.** Pins are still metered and charged by the existing GitHub backed meter and balance. The account's `monthly_used`, `monthly_allowance` and `pack_balance` are not read or written by `/api/pin` yet, and live keys and balances have not been imported.
* **Relay.** Devices are a registry only. Nothing moves between devices.
* **Key management.** No endpoint lists, revokes or rotates API keys yet, and agents' `last_seen` only moves on a repeat sign up.
* **A shared rate limit.** The IP limit on `/challenge` is the existing per instance limiter, so it slows a burst rather than capping it across instances.
