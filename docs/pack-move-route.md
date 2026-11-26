# Pack move route

`POST /api/v1/move`. The seller's half of moving a bought pin pack to the signing witness at `arcaeon.io/witness/v1`.

## Read first

1. **A deployment setting changed, because the route cannot exist without it.** `vercel.json` gains one rewrite: `/api/v1/move` to `/api/credit?op=move`. `api/` already holds 12 functions, the host's limit, and `test/cross_feature_rc.test.js` refuses a 13th. So the route lives in `lib/_move.js` and `api/credit.js` hands `?op=move` to it before anything else. Nothing else in `vercel.json` changed. The operator writes `https://<this host>/api/v1/move` as `url` in `seller.json`. A rewrite is not a redirect.
2. **The signing witness's public key is not pinned yet. Until it is, every ask is refused with 503 and nothing is marked.** The specification names the place it is published (`https://arcaeon.io/.well-known/arcaeon-witness.json`, fields `key_id` and `public_key`) but not the values. This build could not read that file: the network here refused the host. `ASKER` in `lib/_move.js` holds the origin `arcaeon.io/witness/v1` and two empty strings. The smallest change that makes the route work: copy the two published values into `ASKER.public_key` and `ASKER.key_id`. The route checks that `key_id` is the SHA-256 of `public_key` and refuses every ask if not.
3. **Owner's decision: a purchase that arrives for a key already marked moved.** Before this change, fulfilment would add the pins to the key's balance. With the freeze those pins could be spent neither here nor at the signing witness, because the move answer never changes after the first time. That would strand the money. What is built now: nothing is credited, nothing is forwarded to the account service, the checkout is kept in a create only record for a refund by hand, and the buyer and the payment event both say so. The payment itself is already taken by the provider and must be refunded by hand. Carrying the pins to the signing witness instead needs a change on the asking side (some way to carry a sale made after the mark), so that is the owner's decision.
4. **"One append only step" is built as one compare and swap.** The usage store is the GitHub contents API, which only swaps one file at a time. The mark is written into the key's own balance file, `balance/<key_hash>.json`, as a new field `moved`, in one compare and swap against the same file every spend and every grant swaps. So no spend can land between reading the balance and freezing it. The mark is written once and never changed. The usage repository's commit history keeps the write. A separate create only mark file could not freeze the balance against a racing spend. No field name of the specification changed.
5. **Keys this route will not move automatically.** It answers 409 and marks nothing when the answer could not be true and accepted: a sale of a retired pack (its size is not one on sale today), a balance larger than the key's sales (an operator grant added pins), a grant with no readable ledger record, or more than 20 sales. Marking such a key and then having the answer refused would freeze the money here with nowhere to go. These keys stay usable here. An operator moves them by hand.

## What the route does

1. Only `POST`. Other methods get 405.
2. The answer key must be set (see Setting). Missing or malformed: 503, field `answer_key`, nothing marked.
3. The pinned signing witness key must be set and consistent. If not: 503, field `key_id`, nothing marked.
4. The ask must hold exactly the eight fields of the specification. Then, in this order: `kind` is `move_ask`, `v` is `1`, `key_hash` is 64 lower case hex, `nonce` is 32 lower case hex (400 on any of these); `key_id` is the pinned one (401); `sig` verifies under the pinned public key (401); `to` is `arcaeon.io/witness/v1` (403); `asked_at` has the right form (400) and is within 300 seconds of this host's clock (401). Every refusal is a JSON body `{error, field}`, unsigned, and marks nothing.
5. Then by `key_hash`, which is the name of the key's balance file:
   * No balance file: `not_sold`.
   * A mark to another `to`: `elsewhere`.
   * A mark to this `to`: `moved`, with the stored `credits`, `sales` and `moved_at`, and the new `nonce`. Nothing is written.
   * No mark: the sales are read (below). No sales: `not_sold`, nothing marked. Otherwise the mark is written and the answer is `moved`.
6. Sales are read from the balance file's `applied_events` (the checkout ids each grant records, oldest first) and each grant's ledger record `ledger/<key_hash>/grant-<checkout>.json`. A grant counts as a sale when its source is `stripe-webhook`, `stripe-fulfill` or `stripe-fulfill-topup`. Operator grants (`internal-admin`) and pin refunds are not sales. `checkout` is the checkout session id, the same id the account service forward sends. `pack` and `credits` come from the ledger record, and must be a pack and size in `PACKS` today.
7. `credits` is the whole pins of the balance at the mark. A stamp costs a fraction of a pin, so a balance can hold a part of one. That part is not moved. It stays in the mark as `balance_at_mark`.
8. The mark stored in the balance file is `{to, moved_at, credits, sales, balance_at_mark, asked_by}`. The answer is built and its size checked (at most 16384 bytes) before the mark is written.
9. A 200 answer is canonical JSON with `Content-Type: application/json`, signed with the answer key. `key_id` in it is the SHA-256 of the answer key's public half.
10. Two asks at once: one compare and swap wins. The other re-reads, finds the mark, and answers the same `credits`, `sales` and `moved_at`.
11. The nonce is not stored. A replay of a signed ask within 300 seconds gets the same answer and writes nothing.

## After the mark

| route | what spends bought pins | on a moved key |
|---|---|---|
| `POST /api/pin` and `POST /api/renew` | `api/pin.js:155` `decrementCredit`, after the month's free pins are used | 403, `reason: "pack_moved"`, `field: "key"`, `error: "this pack moved to https://arcaeon.io/witness/v1; update the package"`. Nothing spent, nothing written, no buy links. |
| `GET /api/distill` | `api/distill.js:90` `decrementCredit`, after the free pins | the same 403 |
| `POST /api/stamp` (rewrite to `api/verify.js?op=stamp`) | `lib/_stamp.js:566` reads the balance, `lib/_stamp.js:641` `debitCredits` after the write | 403 with the same words, before anything is written |
| every spend | `lib/_balance.js:476` `debitCredits` | refused with `reason: "pack_moved"` at `lib/_balance.js:493`, for any amount |

The free pins are not moved. `lib/_meter.js` counts them per key per month (10 a month, `lib/_meter.js:50`) and is not touched by the mark. A moved key keeps pinning on its free pins. Only past them does it meet the refusal.

`/api/balance` still shows the frozen balance and does not say it moved. `readBalance` now carries `moved_to`, but the balance page does not show it yet.

## Map: how pins get on a key, where they live, what spends them

Where things live, all in the private usage repository:

* Bought balance: `balance/<key_hash>.json`, written by `grantCredits` (`lib/_balance.js:559`), read by `readBalance` (`lib/_balance.js:387`). It holds `balance`, `seq`, and `applied_events`, the checkout ids already applied. Since this change it can also hold `moved`.
* Grant records: `ledger/<key_hash>/grant-<event>.json`, one per grant, with `pack`, `pins` and `source`.
* Spend records: `ledger/<key_hash>/<seq>-decrement.json`.
* Free allowance: `usage/<key_hash>/<YYYY-MM>.json`, counted by `check` (`lib/_meter.js:180`), cap 10 (`lib/_meter.js:50`).
* Refused after move: `ledger/<key_hash>/after-move-<event>.json`, new, create only (`lib/_balance.js:692`).

How a purchase puts pins on a key (fulfilment):

* `GET/POST /api/fulfill` verifies the checkout session with the provider. For a top up (`client_reference_id` is the key's SHA-256) it calls `creditPack` at `api/fulfill.js:557`. For a new key it mints the key, writes the issued key record (`api/fulfill.js:716`), and calls `creditPack` at `api/fulfill.js:738`. Both use the checkout session id as the idempotency key.
* `POST /api/stripe-webhook` calls `creditPack` at `api/stripe-webhook.js:325`, keyed on the same session id.
* `POST /api/credit` (operator, admin key) calls `creditPack` at `api/credit.js:80`, keyed on an event id the operator gives.
* `creditPack` (`lib/_balance.js:760`) looks up the pack and calls `grantCredits`.
* A pin whose write fails after a charge gets one pin back through `grantCredits` (`api/pin.js:274`).

Every route that spends bought pins: the table under After the mark.

## A purchase after the move

`grantCredits` checks, in one read of the balance file: a checkout already applied is answered `already_credited` as before, so a receipt revisit still shows the key. Otherwise, a moved key gets `{ok: false, reason: "pack_moved"}`, the balance is not touched, and `ledger/<key_hash>/after-move-<checkout>.json` records the pack, the pins, the source and `refund_due: true`.

* `/api/fulfill` answers 409 with the moved words, `credited: false`, and a line asking the buyer to email support for a refund. Nothing is forwarded to the account service.
* `/api/stripe-webhook` answers 200 with `reason: "pack_moved"` and `credited: false`, so the provider does not retry a delivery whose answer cannot change, and logs one line naming the session.
* `/api/credit` answers 409.
* A pin refund refused this way is logged as `REFUND REFUSED`. It needs a pin charged before the mark and a failed write after it.

## Setting

`WITNESS_MOVE_ANSWER_KEY`: this host's Ed25519 answer key, the 32 byte private seed as 64 lower case hex. Set it as an encrypted value on the host. It is never written to the repository and never logged. To make one, on a trusted machine, from a checkout of this repository:

```bash
node -e 'console.log(require("./lib/_move.js").generateKeyHex())'
```

That prints `seed` (the setting's value), `public_key` (64 hex, for `seller.json`) and `key_id`.

The signing witness's origin, public key and key_id are in `ASKER` in `lib/_move.js`, the one place in code. They are never read from an ask.

## Canonical JSON

`canonicalBytes` in `lib/_move.js` is written once. Keys are sorted by code point at every depth, which is how Python sorts text and not how JavaScript sorts by default. Text is written as `JSON.stringify` writes it, which escapes exactly what Python escapes with `ensure_ascii=False`. Null, fractions, integers past 2^53 and lone surrogates are refused. `test/move.test.js` checks five fixed examples against the bytes the Python line gives, and runs the Python line here on the same examples and on both worked examples below.

## Worked examples

Made by the last test in `test/move.test.js`, with throwaway keys made fresh by that test. Neither is a real key.

Throwaway asker (stands in for the signing witness):

```
public_key f056a3b22440ee3920a857ccec1b442af45cf4c6d92a12def76c691ed40861da
key_id     f90f27de82eae933e5a78ba2aab2e0a2be38c6d228ca9999471538253de44e40
```

Throwaway seller answer key:

```
public_key 51211e9575e22179c7f7baf434095a986170e13a980a28fdd2ef8e03539395cb
key_id     bdf1ee9f0eec071097e23bbf10c1a8fbea4c859ba2533319df075ba30162d784
```

The ask, exact canonical bytes:

```
{"asked_at":"2030-01-15T12:00:00Z","key_hash":"b33b27ec32f5a7516156decaca8fe1488b42644003736ffd7a4ef03605ce7f63","key_id":"f90f27de82eae933e5a78ba2aab2e0a2be38c6d228ca9999471538253de44e40","kind":"move_ask","nonce":"0123456789abcdef0123456789abcdef","sig":"994975199548aa651137c9228636bb3f225a338e87e5975dea8540ea183df779a410255ee4f79d242db941213d38eb0ce46c4d3f7ca9fe116afef064d774da0c","to":"arcaeon.io/witness/v1","v":1}
```

The moved answer, exact canonical bytes:

```
{"credits":200,"key_hash":"b33b27ec32f5a7516156decaca8fe1488b42644003736ffd7a4ef03605ce7f63","key_id":"bdf1ee9f0eec071097e23bbf10c1a8fbea4c859ba2533319df075ba30162d784","kind":"move_answer","moved_at":"2030-01-15T12:00:00Z","nonce":"0123456789abcdef0123456789abcdef","sales":[{"checkout":"cs_test_example01","credits":200,"pack":"pins_200"}],"sig":"e86fc25b0f20e3a095a34e610061272bd0da2ff13711d8d7401b137bd076c0310194f623b7207098b62aa23407722f3afcffe3c518f7c1247bafae0abf3ca101","status":"moved","to":"arcaeon.io/witness/v1","v":1}
```

Each signature is over these bytes with the `sig` field taken out. The time is the test's fixed clock.

## Tests

```bash
node --test test/move.test.js
```

Last result lines: `# tests 31`, `# pass 31`, `# fail 0`, `# skipped 0`.

```bash
npm test
```

Last result lines: `# tests 881`, `# pass 881`, `# fail 0`, `# skipped 0`.

Each guard was also taken out in turn and the move tests run: with the spend refusal gone, four tests fail; with the grant refusal gone, three fail.

## Not done, and why

* The signing witness's public key and key_id are not pinned. The file that publishes them could not be read here. See Read first, item 2.
* A purchase after the move is refused and recorded, not carried over. Carrying it needs a change on the asking side. See Read first, item 3.
* The answer time is not measured against the real store. A first ask is one read of the balance file, one read per grant record (in parallel), and one write. A repeat ask is one read. If a first answer is later than 3 seconds, the signing witness refuses that pin, and its next ask gets the same mark back at once.
* `share` is left out of every answer, as the specification says for now.
* The balance page does not say a key moved.
* Keys with a retired pack sale, an operator grant, a missing grant record, or more than 20 sales are refused with 409 and stay here. See Read first, item 5.
