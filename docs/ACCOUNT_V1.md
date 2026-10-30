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

The endpoints live at `/api/account/challenge`, `/api/account/verify` and `/api/account/devices` (phase 2 adds `/api/account/pins`, phase 3 `/api/account/checkout`). Under the hood `vercel.json` rewrites them onto `api/balance.js` with `?op=account-challenge`, `?op=account-verify`, `?op=account-devices`, `?op=account-pins` and `?op=account-checkout`, because `api/` is already at the hosting plan's 12 function cap. This is the same trick `/api/stamp` and `/api/prefix-available` use.

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
| `ACCOUNT_REF_SECRET` | signs and checks the checkout account reference (16+ characters). Unset means no checkout session can be made and no checkout links or credits an account |
| `ACCOUNT_POW_BITS` | proof of work difficulty, a whole number from 1 to 32. Unset or anything else means 20. It can be made easier but never turned off |
| `WITNESS_STRIPE_SECRET_KEY` | the witness product's Stripe secret key, used by `/api/account/checkout` to make the account's customer and its Checkout Sessions. Sent only as a request header to Stripe. Unset means checkout answers 503. There is no fallback to a bare `STRIPE_SECRET_KEY` (that one is another product's; an object *created* in the wrong Stripe account would take money our webhook never hears of) |
| `WITNESS_BASE_URL` | where Stripe sends the payer after checkout (`/status?account_checkout=complete` or `=canceled`). Default `https://arcaeon-witness.vercel.app` |

The migration has not been applied to any database by this change.

## Phase 2: the subscription and the pin allowance

| piece | file |
|---|---|
| Postgres schema and functions | `supabase/migrations/2026_10_31_account_v2.sql` |
| the rules, the Stripe event mapping, the webhook branch | `lib/_account_billing.js` |
| store methods (memory and PostgREST) | `lib/_accountdb.js` |
| tests | `test/account_billing.test.js`, `test/account_v2_schema.test.js`, cases in `test/helpers/account_billing_scenarios.js` |

### The rules

* The plan is $9 a month (Stripe price lookup key `account_monthly`) or $99 a year (`account_yearly`), renewing on its own.
* A paid plan gets 3,000 pins a month. They reset each month and unused pins are lost. The yearly plan resets too: our own clock counts months from the start of the paid year (the start plus 1, 2, ... 11 months; the 31st becomes the last day of a shorter month). There is no yearly pool.
* Packs never expire. `pins_200` is 200 pins for $5 and `pins_1000` is 1,000 pins for $20, matched by id, never by amount. A pack is spent only after the month's 3,000 are gone, oldest pack first.
* A plan in force means plan monthly or yearly with status active or trialing.
* With no plan in force (never paid, or lapsed: canceled, unpaid, incomplete, incomplete_expired, paused) an account gets 10 pins a month, on the UTC calendar month. New accounts start at 10, and v1-era free rows (100, or 30) move to 10. Packs can be spent in every status. (Owner and council, 2026-10-30: this was 30. The witness per-key free cap is a separate mechanism and is not changed by this.)
* past_due keeps the monthly window it is in, with its 3,000 and what it used, but gets no new monthly reset. When that window ends while the account is still past_due, it falls to the no-plan 10 for the calendar month. A window our clock opened at period_end before the renewal failed belongs to the unpaid period and is not kept. When Stripe moves the subscription back to active, the anniversary windows resume from period_start. A yearly plan whose renewal fails gets no new year of resets.
* A debit never goes below zero. It takes everything it asks for or nothing. It is safe to retry under the same request id: the second call answers `replay: true` and charges nothing more.

### Stripe events

Account events come in on the existing `/api/stripe-webhook`. They use the same signing secret (`WITNESS_STRIPE_WEBHOOK_SECRET`) and the same `verifyStripeSignature`, which now accepts either of the two `v1` signatures Stripe sends while a secret is being rolled. Account events are subscription, invoice, refund and dispute events, plus any Checkout Session with `mode: subscription` or a `metadata.account_id`. Every other event goes down the old pack path, unchanged.

| event | what it does |
|---|---|
| `checkout.session.completed`, subscription mode | confirms a checkout on the account's own customer (see phase 3): notes the subscription id, opens the window. Never sets or moves the customer |
| `checkout.session.completed` / `.async_payment_succeeded`, payment mode, `metadata.account_id` + `metadata.pack` | credits the pack once per Checkout Session, and only if it is paid, in USD, and at least the pack's price |
| `customer.subscription.created` / `.updated` / `.paused` / `.resumed` | status, plan from the price lookup key, period, cancel at period end (a `cancel_at` inside the period moves the end earlier) |
| `customer.subscription.deleted` | status canceled, plan free. Packs are kept |
| `invoice.paid` | status active, plan from the line's lookup key, and the period from the line. A newer period start opens a fresh month |
| `invoice.payment_failed` | past_due: the current window is kept until it ends, no new month, then the no-plan 10. Never starts a plan on an account that has none |
| `charge.refunded` | takes off the units the refund pays for (pro rata to the amount paid, rounded up, counted on the running total refunded). Spent pins stay spent, and the spent part is written down as a shortfall |
| `charge.dispute.*` | open: the pack is held, not spendable. Won or warning_closed: live again. Lost: voided. A later won releases it again |

The checkout reference is signed. `client_reference_id` can be set by anyone (a Payment Link takes it from the URL), so a bare account id is never trusted. A link or pack checkout must carry `<account_id>.<exp_unix>.<hex HMAC-SHA256(ACCOUNT_REF_SECRET, "arcaeon-checkout-v2\n" + account_id + "\n" + exp_unix)>`, made by `mintAccountRef(account_id, now)` (exp = now + 2 hours), in `client_reference_id` or `metadata.account_ref`. It is checked with a timing-safe compare before anything is credited or confirmed, and it only counts when the checkout session's own `created` is at or before `exp`. That is the session time, not the time the webhook lands, so Stripe's retries days later still verify. An expired ref with a good MAC is refused like a bad one (reason "expired"). The v1 ref (no expiry) is gone. A bare account id in `client_reference_id` on a payment checkout is not ours at all: it stays on the legacy path and leaves no `stripe_events` row. A missing or bad reference is recorded in `stripe_events` as `ignored_unverified_reference`, with no account. Nothing is credited: a paid pack in that state waits for a person to look at it. Subscription and invoice events only use a signed `metadata.account_ref`. Otherwise they find the account by its customer. If `ACCOUNT_REF_SECRET` is unset (or shorter than 16 characters), nothing verifies.

The customer rule. The reference says *which account*; it never says *whose money*. `accounts.stripe_customer_id` is written by exactly one path, the checkout endpoint in phase 3 (`account_set_stripe_customer`, set once, never moved), and every Stripe event is held to it: an event whose customer is not the account's own stored customer is `ignored_customer_mismatch`, whatever reference it carries, whether the account holds a plan or not, and an account with no customer yet refuses every event. No event ever sets, changes or relinks the customer; there is no relink. So a leaked reference pasted into a Payment Link and paid by a stranger (a new Stripe customer) links nothing, and a leaked checkout session URL (phase 3) can only be paid *for* the account, on the account's own customer. The stranger's own subscription then belongs to no account (503, Stripe retries, then gives up).

## Phase 3: the server makes the checkout

| piece | file |
|---|---|
| the Stripe calls and the rules | `lib/_account_checkout.js` |
| the route | `lib/_account_api.js` (`checkout`), rewritten from `/api/account/checkout` onto `/api/balance?op=account-checkout` |
| the store half | `setStripeCustomer`, `getAccount` in `lib/_accountdb.js`; `account_set_stripe_customer` in the v2 migration |
| tests | `test/account_checkout.test.js`, the LEAKED LINK / NO RELINK / NO CUSTOMER cases in `test/helpers/account_billing_scenarios.js`; Stripe's API is the double in `test/helpers/stripe_api_mock.js` |

Why. With Payment Links, Stripe makes a new customer for whoever pays, and the account had to learn its customer from the first paid checkout. The signed reference stopped a stranger choosing *which* account, but a fresh checkout URL that leaked inside its two hours still let a stranger pay first and put *their* customer on the owner's account; the owner was then refused until that subscription died. Now the server makes the Checkout Session, and the payer's identity is not used for anything.

`POST /api/account/checkout` with `Authorization: Bearer <api key>` and a body of `{"plan": "monthly"}`, `{"plan": "yearly"}`, `{"pack": "pins_200"}` or `{"pack": "pins_1000"}` (exactly one of plan or pack). The server:

1. Makes the account's Stripe customer if it has none: `POST /v1/customers` with `metadata.account_id` and an `Idempotency-Key` bound to the account id, then stores it with `setStripeCustomer`, which sets only when the column is still null. Two first calls at once make one customer (Stripe's idempotency key on its side, set-if-null on ours). Every later checkout reuses it. If the session step fails after this, the customer is kept and the retry reuses it.
2. Finds the price by its lookup key (`account_monthly`, `account_yearly`, `pins_200`, `pins_1000`), never a typed-in price id. No active price with that key is 503 `price_not_configured`, naming the key.
3. Creates the Checkout Session with `customer` = the account's customer, `client_reference_id` and `metadata.account_ref` = a fresh signed reference, `metadata.account_id`, `subscription_data.metadata.account_ref` and `.account_id` (so renewal events can name the account), `metadata.pack` for a pack, and `expires_at` two hours out: the session dies with the reference.

Answer: 201 `{ok, session_id, url, expires_at, mode, plan|pack, customer_id, account_id}`. Send the payer to `url`. Whoever pays it pays for this account on this customer. A plan checkout while the account's customer already holds a plan (active, trialing or past_due) is 409 `plan_already_held`; a pack is always allowed. Other refusals: 401 `missing_api_key` / `unknown_api_key`, 400 `bad_body` / `bad_item` / `bad_plan` / `bad_pack`, 405, 429 (the shared per-IP limiter: every call makes a Stripe object), 503 `stripe_not_configured` / `account_ref_not_configured` / `account_store_not_configured`, 502 `stripe_error` (names the Stripe step and HTTP status only, never the key or Stripe's text) / `account_store_error`.

Payment Links. Account plans and account packs are bought through this endpoint only. The per-key witness packs (`mini`, `starter`, ... in `lib/_balance.js`, fulfilled by `/api/fulfill` and the legacy webhook path) keep their Payment Links untouched: they have no account. A Payment Link for an account price, if one exists in Stripe, should be deactivated: a checkout from it carries a stranger's customer and is refused as `ignored_customer_mismatch`, so it can only take someone's money for nothing.

Stripe setup this needs (a person, in the dashboard): four active prices with lookup keys `account_monthly` ($9/month), `account_yearly` ($99/year), `pins_200` ($5 one-time) and `pins_1000` ($20 one-time); `WITNESS_STRIPE_SECRET_KEY` set in the Vercel project; the webhook endpoint from phase 2 subscribed to the checkout, subscription, invoice, refund and dispute events. No live Stripe call was made by this change.

Duplicates and order. The event id is written in the same transaction as the change, so a repeated id does nothing. A canceled subscription never comes back. An older event never overwrites a newer one for the same subscription. A period never moves backward. A new month opens only when the window start moves forward, so a late or repeated renewal never resets the month twice. If an event names an account that is not linked yet, the webhook answers 503 and Stripe retries it later.

Read your allowance with `GET /api/account/pins` and `Authorization: Bearer <api key>` (rewritten to `/api/balance?op=account-pins`).

The migration has not been applied to any database by this change. No live Stripe call is made anywhere.

## What is NOT built yet

* **Re-fetching from Stripe.** The outside test plan treats every event as a hint and fetches the object again before acting on it. That needs a live Stripe call on the webhook path, and this build makes none there (the checkout endpoint is the only code that calls Stripe, and only to create). The guards above stand in for it.
* **A customer portal / changing plan.** `plan_already_held` refuses a second plan; moving monthly to yearly or canceling still happens in Stripe's dashboard (or a portal session, not built).
* **Plan-change top ups, trials, pending updates, the 30-day unpaid cancel job, account deletion refunds.** See the plan's groups D, G, L and M.
* **People sign in.** The `people` table exists. Magic link sign in, and a person attaching an agent by having it sign a link nonce, are not built.
* **Witness pin debit against Postgres.** Pins are still metered and charged by the existing GitHub backed meter and balance. `account_debit_pins` exists and is tested, but `/api/pin` does not call it yet, and live keys and balances have not been imported.
* **Relay.** Devices are a registry only. Nothing moves between devices.
* **Key management.** No endpoint lists, revokes or rotates API keys yet, and agents' `last_seen` only moves on a repeat sign up.
* **A shared rate limit.** The IP limit on `/challenge` is the existing per instance limiter, so it slows a burst rather than capping it across instances.
