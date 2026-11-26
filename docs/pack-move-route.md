# Pack move route

`POST /api/v1/move`. The seller's half of moving a bought pin pack to the signing witness at `arcaeon.io/witness/v1`.

## Read first

1. **A deployment setting changed, because the route cannot exist without it.** `vercel.json` gains one rewrite: `/api/v1/move` to `/api/credit?op=move`. `api/` already holds 12 functions, the host's limit, and `test/cross_feature_rc.test.js` refuses a 13th. So the route lives in `lib/_move.js` and `api/credit.js` hands `?op=move` to it before anything else. Nothing else in `vercel.json` changed. The operator writes `https://<this host>/api/v1/move` as `url` in `seller.json`. A rewrite is not a redirect.
2. **The signing witness's public key is not pinned yet. Until it is, every ask is refused with 503 and nothing is marked.** The specification names the place it is published (`https://arcaeon.io/.well-known/arcaeon-witness.json`, fields `key_id` and `public_key`) but not the values. This build could not read that file: the network here refused the host. `ASKER` in `lib/_move.js` holds the origin `arcaeon.io/witness/v1` and two empty strings. The smallest change that makes the route work: copy the two published values into `ASKER.public_key` and `ASKER.key_id`. The route checks that `key_id` is the SHA-256 of `public_key` and refuses every ask if not.
3. **Two settings must be set on the host** before the route answers anything but 503: `WITNESS_MOVE_ANSWER_KEY` and `WITNESS_MOVE_PACK_SIZES` (see Settings).
4. **"One append only step" is built as one compare and swap.** The usage store is the GitHub contents API, which only swaps one file at a time. The mark is written into the key's own balance file, `balance/<key_hash>.json`, as a new field `moved`, in one compare and swap against the same file every spend and every grant swaps. So no spend and no grant can land between reading the balance and freezing it. The mark is written once and never changed. The usage repository's commit history keeps the write. No field name of the specification changed.
5. **Owner's decision: a refund after the move.** See item 9 under What the signing witness expects.

## What the route does

1. Only `POST`. Other methods get 405.
2. `WITNESS_MOVE_ANSWER_KEY` must be usable, or 503 with field `answer_key`. `WITNESS_MOVE_PACK_SIZES` must be usable, or 503 with field `pack_sizes`. The pinned signing witness key must be set and consistent, or 503 with field `key_id`. Nothing is marked on any of these.
3. The ask must hold exactly the eight fields of the specification. Then, in this order: `kind` is `move_ask`, `v` is `1`, `key_hash` is 64 lower case hex, `nonce` is 32 lower case hex (400 on any of these); `key_id` is the pinned one (401); `sig` verifies under the pinned public key (401); `to` is `arcaeon.io/witness/v1` (403); `asked_at` has the right form (400) and is within 300 seconds of this host's clock (401, naming the clock). Every refusal is a JSON body `{error, field}`, unsigned, and marks nothing.
4. Then by `key_hash`, which is the name of the key's balance file:
   * No balance file: `not_sold`.
   * A mark to another `to`: `elsewhere`.
   * A mark to this `to`: `moved`, with the stored `credits`, `sales` and `moved_at`, and the new `nonce`. Nothing is written.
   * No mark: every check below runs on the balance as read. Any failure is 409 and nothing is marked. No sales: `not_sold`, nothing marked. Otherwise the mark is written and the answer is `moved`.
5. The checks, all before the mark: every grant on the key has a readable ledger record; no grant was put on by hand (any source other than the two checkout paths and pin refunds); every checkout id has the form the answer allows; every sale's pack and pins are on `WITNESS_MOVE_PACK_SIZES`; there are at most 20 sales; the whole pins of the balance are not more than the sales' pins; the signed answer fits in 16384 bytes.
6. Sales are read from the balance file's `applied_events` (the checkout ids each grant records, oldest first) and each grant's ledger record `ledger/<key_hash>/grant-<checkout>.json`. A grant counts as a sale when its source is `stripe-webhook`, `stripe-fulfill` or `stripe-fulfill-topup`. `checkout` is the checkout session id, the same id the account service forward sends.
7. `credits` is the whole pins of the balance at the mark. A stamp costs a fraction of a pin, so a balance can hold a part of one. That part is not moved. It stays in the mark as `balance_at_mark`.
8. The mark stored in the balance file is `{to, moved_at, credits, sales, balance_at_mark, asked_by}`.
9. A 200 answer is canonical JSON with `Content-Type: application/json`, signed with the answer key. `key_id` in it is the SHA-256 of the answer key's public half.
10. Two asks at once: one compare and swap wins. The other re-reads, finds the mark, and answers the same `credits`, `sales` and `moved_at`.
11. The nonce is not stored. A replay of a signed ask within 300 seconds gets the same answer and writes nothing.

## What the signing witness expects

1. **A purchase onto a moved key.** Today the site sells two ways. A plain payment link makes a new key (`/api/fulfill` mints one). A top up link carries `client_reference_id`, the SHA-256 of an existing key, and adds the pack to that key. Now a top up that names a moved key is never put on it. `grantCredits` refuses any grant to a moved key (`lib/_balance.js:598`) and writes nothing. `/api/fulfill` then gives the checkout a NEW key with the pack on it, through the same mint path as a first purchase (`api/fulfill.js:572`). The picker page and the JSON answer say why (`new_key_because_moved`), and the fulfillment record keeps `topup_of_moved_key` for support. The webhook puts nothing on the moved key and leaves the checkout to `/api/fulfill`, which the buyer reaches from the checkout and from the receipt (`api/stripe-webhook.js:326`). The operator path `/api/credit` answers 409. A moved key is never offered buy links: its refusals carry none. So every purchase on a moved key happened before its mark and is in its `sales`, and the route and the checkout agree.
2. **A balance the answer cannot describe.** Pins put on by hand, a size not listed, a grant without a record, more than 20 sales, a balance over the sales: each is 409 and nothing is marked. All of it is checked in the decide step, which runs on the balance as read and before the compare and swap that writes the mark (`lib/_move.js:301`, `lib/_balance.js:724`).
3. **A pin in flight at the mark.** A pin is charged at `api/pin.js:155` through `debitCredits`, which swaps the same balance file as the mark. Either the charge swaps first, is in the balance the mark freezes, and the pin is recorded here; or the mark swaps first and the charge is refused with `pack_moved`. If a charge landed before the mark and the pin's write then fails, the refund is not put back on the frozen balance; it is recorded as one pin owed (`api/pin.js:279`). A paid stamp checks the balance before its write and is charged after it (`lib/_stamp.js:566`, `lib/_stamp.js:641`); a mark between the two leaves that stamp uncharged here, which this host eats. A pin is never spent on both hosts.
4. **The clocks.** An ask more than 300 seconds from this host's clock is refused 401 with `reason: "clock"`, `field: "asked_at"`, `seller_clock`, the ask's `asked_at`, `skew_seconds`, and an error that starts `clock:` and says how far ahead or behind. One log line names both times.
5. **The headers.** The route reads no header. It does not look at the agent, the accepted encodings, or the connection header. It takes a parsed or an unparsed JSON body. `vercel.json` holds no redirect, no header rule, no trailing slash rule and no clean URL rule. Not visible from this repository: the host project's firewall and bot protection settings, kept in the host's dashboard. The owner should confirm none of them challenges a non browser agent on `/api/v1/move`.
6. **A fixed example.** `docs/move-vectors.json`, built by `node tools/move_vectors.js --write`. It holds one ask and one answer for each status (`moved`, `moved_again`, `not_sold`, `elsewhere`), each as exact text and hex, signed and unsigned, with the two keys that signed them. The keys are the public Ed25519 test keys of RFC 8032, section 7.1, TEST 1 (asker) and TEST 2 (seller): known to everyone, never to be pinned or set on a host. Ed25519 is deterministic, so the other side signs the same unsigned bytes with the same seed and must get the same signature. The tests check the file is what the tool builds, that every signature verifies and is reproduced, that the route itself answers each example ask with exactly the example answer bytes, and that the Python line of the specification gives the same bytes. The asking side can copy the file as it is.
7. **The list of sizes.** `WITNESS_MOVE_PACK_SIZES`, JSON `{"<pack id>": <pins>}`, for example `{"pins_200": 200, "pins_1000": 1000}`. The operator copies it from the signing witness's own list and keeps the two the same; whenever the signing witness's list changes, this setting changes with it. A sale whose pack and pins are not on it is refused before the mark. The safe direction: this list may be shorter than the signing witness's (a key then stays here, refused with 409), never longer (that could mark a key the signing witness then refuses).
8. **The answer key.** `WITNESS_MOVE_ANSWER_KEY`, set as an encrypted setting on the host, never in the repository; a test checks `lib/_move.js` holds no key. Whoever holds it can mint packs at the signing witness, so it is made on a trusted machine and set only on the host. To replace it: make a new one (command under Settings), give its `public_key` to the signing witness's operator for `seller.json`, and set the new seed on the host as close to the same time as they can. While the two disagree, an answer does not verify there and that pin is refused; a mark written in that window stays as it is, and the next ask is answered from it, signed with the new key. On a leak, replace it at once and have the signing witness drop the old public key.
9. **A refund after the move: needs the owner's word.** What the seller does today: nothing in code. Refunds are made by hand in the payment provider. No code reads a refund or a dispute, and nothing undoes a mark. The signing witness cannot take pins back, so a refund after the move leaves the pins spendable there. The question: after a pack has moved, does the seller refuse refunds, or refund and accept that the pins stay spendable at the signing witness?

## After the mark

| route | what spends bought pins | on a moved key |
|---|---|---|
| `POST /api/pin` and `POST /api/renew` | `api/pin.js:155` `decrementCredit`, after the month's free pins are used | 403, `reason: "pack_moved"`, `field: "key"`, `error: "this pack moved to https://arcaeon.io/witness/v1; update the package"`. Nothing spent, nothing written, no buy links. |
| `GET /api/distill` | `api/distill.js:90` `decrementCredit`, after the free pins | the same 403 |
| `POST /api/stamp` (rewrite to `api/verify.js?op=stamp`) | `lib/_stamp.js:566` reads the balance, `lib/_stamp.js:641` `debitCredits` after the write | 403 with the same words, before anything is written |
| every spend | `lib/_balance.js:476` `debitCredits` | refused with `reason: "pack_moved"` at `lib/_balance.js:493`, for any amount |

The free pins are not moved. `lib/_meter.js` counts them per key per month (10 a month, `lib/_meter.js:50`) and is not touched by the mark. A moved key keeps pinning on its free pins. Only past them does it meet the refusal.

`/api/balance` still shows the frozen balance and does not say it moved.

## Map: how pins get on a key, where they live, what spends them

Where things live, all in the private usage repository:

* Bought balance: `balance/<key_hash>.json`, written by `grantCredits` (`lib/_balance.js:559`), read by `readBalance` (`lib/_balance.js:387`). It holds `balance`, `seq`, and `applied_events`, the checkout ids already applied. It can also hold `moved`.
* Grant records: `ledger/<key_hash>/grant-<event>.json`, one per grant, with `pack`, `pins` and `source`.
* Spend records: `ledger/<key_hash>/<seq>-decrement.json`.
* Free allowance: `usage/<key_hash>/<YYYY-MM>.json`, counted by `check` (`lib/_meter.js:180`), cap 10 (`lib/_meter.js:50`).
* Owed after a move: `ledger/<key_hash>/after-move-<event>.json`, create only (`lib/_balance.js:693`): a pin refund refused after the mark.

How a purchase puts pins on a key (fulfilment):

* `GET/POST /api/fulfill` verifies the checkout session with the provider. For a top up (`client_reference_id` is a key's SHA-256) it calls `creditPack` at `api/fulfill.js:574`; on a moved key it falls through to the mint. For a new key it mints the key, writes the issued key record (`api/fulfill.js:743`), and calls `creditPack` at `api/fulfill.js:765`. Both use the checkout session id as the idempotency key.
* `POST /api/stripe-webhook` calls `creditPack` at `api/stripe-webhook.js:325`, keyed on the same session id.
* `POST /api/credit` (operator, admin key) calls `creditPack` at `api/credit.js:80`, keyed on an event id the operator gives.
* `creditPack` (`lib/_balance.js:761`) looks up the pack and calls `grantCredits`.
* A pin whose write fails after a charge gets one pin back through `grantCredits` (`api/pin.js:274`).

Every route that spends bought pins: the table under After the mark.

## Settings

`WITNESS_MOVE_ANSWER_KEY`: this host's Ed25519 answer key, the 32 byte private seed as 64 lower case hex. An encrypted setting on the host, never in the repository, never logged. To make one, on a trusted machine, from a checkout of this repository:

```bash
node -e 'console.log(require("./lib/_move.js").generateKeyHex())'
```

That prints `seed` (the setting's value), `public_key` (64 hex, for `seller.json`) and `key_id`.

`WITNESS_MOVE_PACK_SIZES`: the pack sizes the signing witness lists, JSON `{"<pack id>": <pins>}`. Not a secret.

The signing witness's origin, public key and key_id are in `ASKER` in `lib/_move.js`, the one place in code. They are never read from an ask.

## Canonical JSON

`canonicalBytes` in `lib/_move.js` is written once. Keys are sorted by code point at every depth, which is how Python sorts text and not how JavaScript sorts by default. Text is written as `JSON.stringify` writes it, which escapes exactly what Python escapes with `ensure_ascii=False`. Null, fractions, integers past 2^53 and lone surrogates are refused. `test/move.test.js` checks five fixed examples against the bytes the Python line gives, and runs the Python line here on the same examples and on every example in `docs/move-vectors.json`.

## Worked examples

All in `docs/move-vectors.json`. The first two, as text:

The ask (case `moved`), signed with the RFC 8032 TEST 1 key (public key `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`, key_id `21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9`):

```
{"asked_at":"2030-01-15T12:00:00Z","key_hash":"8431b0f8a5e5748127949730ed22b685789c2156c71ec06d2c0fed35884c218f","key_id":"21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9","kind":"move_ask","nonce":"00000000000000000000000000000001","sig":"4390217ead27e0523715e48c9b3ae719b2ffc9ad042d6555be825fc5ecc13897946145eaa0d806f90689989d77a9d14ddb16a2f9c3e04303f02ea9313d313c05","to":"arcaeon.io/witness/v1","v":1}
```

The moved answer, signed with the RFC 8032 TEST 2 key (public key `3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c`, key_id `39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f`):

```
{"credits":1195,"key_hash":"8431b0f8a5e5748127949730ed22b685789c2156c71ec06d2c0fed35884c218f","key_id":"39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f","kind":"move_answer","moved_at":"2030-01-15T12:00:00Z","nonce":"00000000000000000000000000000001","sales":[{"checkout":"cs_test_vector0001","credits":200,"pack":"pins_200"},{"checkout":"cs_test_vector0002","credits":1000,"pack":"pins_1000"}],"sig":"f78b85111b62da2553e34e1274f6c732eba3b6e46705bb06fe0a6c900142da5df3945e733edac990dcb5dcca47e871c3428b3772ac4cd33446d7d5c37c33fd05","status":"moved","to":"arcaeon.io/witness/v1","v":1}
```

Each signature is over the same bytes with the `sig` field taken out. The time is a fixed test clock.

## Tests

```bash
node --test test/move.test.js
```

Last result lines: `# tests 45`, `# pass 45`, `# fail 0`, `# skipped 0`.

```bash
npm test
```

Last result lines: `# tests 895`, `# pass 895`, `# fail 0`, `# skipped 0`.

```bash
node tools/move_vectors.js --write
```

Last result line: `wrote docs/move-vectors.json`.

Each guard was also taken out in turn and the move tests run: the spend refusal, the grant refusal, the hand grant refusal, the size check, the top up fall through to a new key and the clock line. Each time at least one test failed.

## Not done, and why

* The signing witness's public key and key_id are not pinned. The file that publishes them could not be read here. See Read first, item 2.
* A refund after the move needs the owner's word. See item 9 above.
* The host's firewall and bot protection settings cannot be seen from this repository. See item 5 above.
* The answer time is not measured against the real store. A first ask is one read of the balance file, one read per grant record (in parallel), and one write. A repeat ask is one read. If a first answer is later than 3 seconds, the signing witness refuses that pin, and its next ask gets the same mark back at once.
* `share` is left out of every answer, as the specification says for now.
* The balance page does not say a key moved.
