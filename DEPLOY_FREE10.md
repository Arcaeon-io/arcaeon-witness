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
(Node 22.23.4, run Sat night). The repo has no CI workflow, so the PR shows
no checks; this local run is the only test result. The branch merges into
`main` with no conflict (checked with a trial merge, nothing written).

What PR 2 changes, in full (7 files, 52 lines added, 11 removed):

- `lib/_meter.js`: `PLAN_CAPS.free` from 100 to 10. This is the change.
- `api/fulfill.js`, `lib/_welcome_email.js`: the success page and welcome
  email read the cap from `PLAN_CAPS.free` instead of saying 100.
- `lib/_balance.js`: two new packs, `pins_200` (200 pins, $5) and
  `pins_1000` (1,000 pins, $20), marked `by_id_only`, so a payment is never
  matched to them by its amount (the $5 mini pack has the same price).
- `README.md` and two test files.

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

Nothing new is required for the free 10. Look at two settings before the
deploy:

1. `WITNESS_PLANS`. A key listed there with its own `monthly_cap`, or with
   plan `internal`, keeps what it has; every other key drops to 10. Decide
   whether any key that relies on the old 100 should be listed with
   `"monthly_cap": 100` first.
2. `WITNESS_STRIPE_PRICE_MAP`, only if the two new packs are put on sale
   Tuesday. Each new price id must map to `pins_200` or `pins_1000`, or the
   checkout must carry `metadata.pack`. Without one of those, a buyer of a
   new pack is not credited and lands on the support path, by design, since
   the amount alone is never trusted for these two. Making the prices is the
   owner's job in the payment dashboard; no code change is needed for it.

Unchanged and must stay as they are: `GITHUB_PIN_TOKEN`,
`GITHUB_USAGE_REPO`, `GITHUB_USAGE_BRANCH`, the payment keys,
`WITNESS_BASE_URL`.

### What people will see

The cap is read per calendar month and the count is not reset by the
deploy. A free key that has already pinned 10 or more times in November is
over the cap from the moment it ships: the next pin uses a bought credit if
the key has any, and otherwise is refused with status 429, reason
`over_cap`, `cap: 10`, until December 1. A key that bought credits once and
has none left gets 402, `credit_exhausted`. Decide before Tuesday whether to
tell free users, or to list heavy ones in `WITNESS_PLANS` for the rest of
November.

### The steps, in order

1. The owner reviews and merges PR 2 into `main`.
2. On the merged `main`: `npm test`, which must end with 0 fail.
3. Check the two settings above in the production environment.
4. Note the id of the deployment now in production, for rollback.
5. Deploy to a preview and run the smoke below against the preview's
   address.
6. Promote to production and run the smoke again against it.
7. If anything in the smoke fails: promote the deployment noted in step 4
   back. The cap is a constant in the code, so rolling back the code rolls
   back the cap; no data needs undoing.

### Smoke

Use a fresh test key whose prefix starts with `veltest-`, the reserved test
prefix, so its pins are recognised as test data (they stay in the public
record for good; nothing is deleted).

1. `GET /api/status` answers 200.
2. The balance page (`/balance`, paste the test key) says
   `0 of 10 used`.
3. Pin 10 times under the test key: each answers success with
   `X-Meter-Cap: 10` and `X-Meter-Used` rising by one each time.
4. The 11th pin answers 429 with reason `over_cap` and `cap: 10`.
5. The balance page now says `10 of 10 used`, `0 remaining`.
6. A key listed in `WITNESS_PLANS` as `internal` still pins (one pin).
7. Only if the new packs are on sale: one test mode purchase of `pins_200`
   credits 200 pins, and the success page says the free tier is 10 pins a
   month.

## Not checked here

- The deploy itself, the production settings, and the payment dashboard:
  this session has no access to them and was told not to deploy.
- The welcome email as sent; its text is covered by the unit tests only.
