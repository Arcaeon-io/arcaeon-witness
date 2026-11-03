# Deploying the free 10 pins a month (Tuesday)

Readiness check for the owner's Fri 2026-10-30 call: the free tier drops to
10 pins a month per key. Written Sat 2026-10-31 night. Nothing here was
deployed, merged or changed in the payment setup.

## Is the change merged and passing?

**Not merged.** The change is PR 2,
https://github.com/Arcaeon-io/arcaeon-witness/pull/2, branch
`pins-200-1000-free-30` at `abe8fb2` (Fri 2026-10-30 11:22 AM PT), open,
with no review comments. `main` (`8242bfa`) still says `free: 100`.

**Passing.** On that branch, `npm test`: 647 tests, 647 pass, 0 fail
(Node 22.23.4, run Sat night). After the review fixes (Sun 2026-11-01,
local commits on top of `abe8fb2`, not pushed): 677 tests, 677 pass,
0 fail. The repo has no CI workflow, so the PR shows
no checks; this local run is the only test result. The branch merges into
`main` with no conflict (checked with a trial merge, nothing written).

What PR 2 changes, in full (7 files, 52 lines added, 11 removed):

- `lib/_meter.js`: `PLAN_CAPS.free` from 100 to 10. This is the change.
- `api/fulfill.js`, `lib/_welcome_email.js`: the success page and welcome
  email read the cap from `PLAN_CAPS.free` instead of saying 100.
- `lib/_balance.js`: two new packs, `pins_200` (200 pins, $5) and
  `pins_1000` (1,000 pins, $20).
- `README.md` and two test files.

The review fixes on top (Sun 2026-11-01) change the pack logic:

- The packs on sale are only `pins_200` and `pins_1000`. The old packs
  (`mini`, `starter`, `standard`, `bulk`) are retired, but a purchase from
  an old link that names one of them still gets what it paid for.
- A pack, new or old, is credited only when it is named: by
  `metadata.pack` on the link, or by a price map entry for its price. The
  amount paid never picks a pack. A purchase that names no pack, or whose
  price map entry and `metadata.pack` disagree, is not credited and goes
  to the manual step (the buyer is told to email support).
- The webhook uses the same function as `/api/fulfill`, by `metadata.pack`
  only, and still checks the amount and the currency. With no
  `metadata.pack` it credits nothing and `/api/fulfill` handles the
  purchase.
- A top up page shows the pins actually granted for that purchase, even
  when the webhook granted them first.
- The out of pins answers (402 and 429) list only the new packs, and the
  429 says plainly that the free allowance is now 10 pins a month and that
  a pack gets more. Both carry a ready top up link per pack for that key
  (see `WITNESS_PACK_LINKS` below).

Not part of this: the branch `account-on-pr2` also sets free 10, for
accounts as well as bare keys, but has no pull request and is not needed
for Tuesday. The other open PRs (3 to 18) are not needed either.

## What must happen to deploy it

### Migrations

None. The monthly count lives where it lives today (the usage repo named by
`GITHUB_USAGE_REPO`); only the cap it is compared with changes. If PR 3
(the meter off the usage repo) is deployed the same day, its own three
migrations and flag come with it, and that is a separate deploy.

### Environment

Nothing new is required for the free 10 itself. Every change to a setting
reaches only a deployment made after it, so make all of these before step 5
below. There are two groups: the free 10, and the new packs.

For the free 10, look at two settings:

1. `WITNESS_PLANS`, keyed by the SHA-256 of each key, not the key. A key
   listed there with its own `monthly_cap`, or with plan `internal`, keeps
   what it has; every other key drops to 10. Decide
   whether any key that relies on the old 100 should be listed with
   `"monthly_cap": 100` first.
2. `WITNESS_KEYS`, for the smoke only: add one entry
   `<new random key>:veltest-smoke-20261103-` so the smoke has a key that
   is new this month and can pin only under a test prefix. The owner makes this
   key by hand and adds it; it is a secret like every key in that setting,
   and no file in this repo holds it.

### The new packs (on sale Tuesday)

The new packs, 200 pins for $5 and 1,000 pins for $20, go on sale Tuesday
with this release. They never expire and are used after the free 10 a
month. Making the prices and the links is the owner's job in the payment
dashboard; no code change is needed for it.

Every new link must:

- Carry `metadata.pack` set to `pins_200` or `pins_1000`. This is
  required: a purchase is credited only when its pack is named, and the
  webhook reads only `metadata.pack`. A price map entry (below) also names
  the pack for `/api/fulfill`, but not for the webhook.
- Have the quantity fixed at 1, no promotion codes, and no tax added on
  top. The code checks that the amount paid is at least the pack's price
  in USD: tax added on top raises the amount and would still credit, but a
  promotion code lowers it and sends the buyer to the manual step, and a
  quantity of 2 would be paid twice and credited once. Keeping all three
  off keeps the amount equal to the price.
- Send the buyer, after paying, to
  `https://arcaeon-witness.vercel.app/api/fulfill?session_id={CHECKOUT_SESSION_ID}`
  (written exactly like that; the payment service fills in the id). That
  page is the only place a new buyer gets a key. The webhook cannot create
  a key: it only adds pins to a key that already exists, named by
  `client_reference_id`.
- For someone who already has a key and wants more pins on it, the link
  must also carry `client_reference_id` set to the SHA-256 of that key.
  On a payment link this is a URL parameter added per buyer:
  `?client_reference_id=<sha256 of the key>`. Without it, the purchase
  makes a new key with a new prefix instead.

The settings the payment side reads (names from the code):

1. `WITNESS_STRIPE_SECRET_KEY` (the code falls back to `STRIPE_SECRET_KEY`
   only if it is not set): the live secret key, used by `/api/fulfill` to
   check each purchase.
2. `WITNESS_STRIPE_WEBHOOK_SECRET`: the signing secret of the webhook
   endpoint. Without it the webhook refuses every call with 501.
3. `WITNESS_STRIPE_LIVEMODE`: leave it unset or `true` in production. Set to
   `false`, production would refuse every real purchase.
4. `WITNESS_STRIPE_PRICE_MAP`: optional. A JSON map from price id to pack,
   for example `{"price_...":"pins_200","price_...":"pins_1000"}`. Only
   `/api/fulfill` uses it; a webhook delivery does not carry the price ids,
   so the webhook goes by `metadata.pack` only. If a price map entry and
   `metadata.pack` disagree, nothing is credited.
5. `WITNESS_PACK_LINKS`: the two new payment link URLs, as JSON:
   `{"pins_200":"<link url>","pins_1000":"<link url>"}`. These are public
   links, not secrets. When a key runs out of pins, the 402 and 429
   answers carry one top up link per pack, made from these with
   `?client_reference_id=<SHA-256 of that key>` added, so buying from it
   adds the pack to that same key. Only the hash goes in the link, never
   the key. If this is not set, the answers point at
   `https://arcaeon.io/pricing` instead and say plainly that buying there
   makes a new key, and how to add pins to the old key.

The webhook endpoint, at
`https://arcaeon-witness.vercel.app/api/stripe-webhook`, must be subscribed
to `checkout.session.completed` and `checkout.session.async_payment_succeeded`
(and may also send `checkout.session.async_payment_failed`, which is logged
and never credited).

Unchanged and must stay as they are: `GITHUB_PIN_TOKEN`,
`GITHUB_USAGE_REPO`, `GITHUB_USAGE_BRANCH`, `WITNESS_BASE_URL`.

### The old payment links (deactivate at deploy)

Read from the payment account on Sun 2026-11-01. Five live links still
sell the old offers:

| Link id | Sells | Carries |
|---|---|---|
| `plink_1U550D` | mini, $5 / 1,000 pins | `metadata.pack` = mini |
| `plink_1U54Nr` | starter, $15 / 3,000 pins | `metadata.pack` = starter |
| `plink_1U54Pf` | standard, $50 / 12,000 pins | `metadata.pack` = standard |
| `plink_1U54R0` | bulk, $150 / 40,000 pins | `metadata.pack` = bulk |
| `plink_1U4Ow5` | the $9 a month "witnessed" subscription | `metadata.plan` = witnessed, no pack |

All four pack links name their pack and send the buyer to
`/api/fulfill?session_id={CHECKOUT_SESSION_ID}`, so anyone who buys from
one of them, before or after the deploy, still gets exactly that pack.
All five have promotion codes allowed and tax added automatically. A
promotion code lowers the amount below the pack's price, so such a
purchase goes to the manual step; added tax raises it and still credits.

The step: at deploy (step 5 below), with the owner's yes, deactivate all
five links in the payment dashboard. Every live link must name its pack
or be deactivated before PR 2 is in production; these four name theirs,
and the subscription link names no pack, so a purchase from it would go
to the manual step.

### What people will see

The cap is read per calendar month and the count is not reset by the
deploy. A free key that has already pinned 10 or more times in November is
over the cap from the moment it ships: the next pin uses a bought credit if
the key has any, and otherwise is refused with status 429, reason
`over_cap`, `cap: 10`, until December 1. That answer says in plain words
that the free allowance is now 10 pins a month and that a pack (200 for $5
or 1,000 for $20) gets more; nothing else is asked of the key holder. A key that bought credits once and
has none left gets 402, `credit_exhausted`. Decide before Tuesday whether to
tell free users, or to list heavy ones in `WITNESS_PLANS` for the rest of
November.

### The steps, in order

1. The owner reviews and merges PR 2 into `main`.
2. On the merged `main`: `npm test`, which must end with 0 fail.
3. Check the settings above (the two for the free 10, and the five payment
   settings and the webhook endpoint) in the production environment, and
   that each new link carries `metadata.pack`, quantity 1, no promotion
   codes and no added tax.
4. Note the id of the deployment now in production, for rollback.
5. With the owner's yes, deactivate the five old links listed above.
   Then deploy to a preview and run the smoke below against the preview's
   address.
6. Promote to production and run the smoke again against it.
7. If anything in the smoke fails: promote the deployment noted in step 4
   back. The cap is a constant in the code, so rolling back the code rolls
   back the cap; no data needs undoing.

### Smoke

Use the smoke key from setting 2 (`WITNESS_KEYS`): a key with no pins this month, whose
prefix is under `veltest-`, the reserved test prefix. It is the namespace
that must start with `veltest-`, so pin under
`veltest-smoke-20261103-a`. Every smoke pin and the test namespace stay in
the public record for good, recognised as test data; nothing is deleted.

1. `GET /api/status` answers 200.
2. The balance page (`/balance`, paste the smoke key) says `0 of 10 used`.
   This holds only for a key with no pins this month, which is why the key
   is new.
3. Pin 10 times under `veltest-smoke-20261103-a` with the smoke key, with
   `rows` 1, 2, 3 and so on to 10 and a new 64 character hex `chain` each
   time. A pin that repeats the last rows and chain is a no op that is not
   counted, and the same rows with another chain is refused as a conflict,
   so the rows must rise. Each answers success with `X-Meter-Cap: 10` and
   `X-Meter-Used` rising by one each time.
4. The 11th pin, rows 11, answers 429 with reason `over_cap` and `cap: 10`.
5. The balance page now says `10 of 10 used`, `0 remaining`.
6. A key listed in `WITNESS_PLANS` (by its SHA-256) as `internal` still
   pins: one pin under its own prefix, with rows above its last.
7. On production only, after step 6: one real $5 purchase of `pins_200`
   from the new link, with no `client_reference_id`, so it makes a new
   throwaway key (not a customer's key, not the smoke key). On the page it
   lands on, `/api/fulfill`, pick the prefix `veltest-buy-20261103-` (it
   does not overlap the smoke key's `veltest-smoke-20261103-`). The page must
   show the key and 200 prepaid pins and say the free tier is 10 pins a
   month. Then refund that purchase in the payment dashboard. A refund does
   not take the pins back, so leave the throwaway key unused. Do not try a
   test mode purchase against production: production expects live mode
   and refuses a test mode purchase, so it proves nothing.

## Not checked here

- The deploy itself, the production settings, and the payment dashboard:
  this session has no access to them and was told not to deploy.
- The welcome email as sent; its text is covered by the unit tests only.
