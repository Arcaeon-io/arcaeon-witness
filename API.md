# API reference

The witness's public endpoints, in plain words. Every answer is JSON. A refusal carries an `error` sentence, and most carry a `reason` word and, where one field is at fault, `field`.

Some parts below are behind flags and live in open pull requests; each says so. With a flag off, that part is absent and nothing else changes.

| endpoint | what it is for | auth |
|---|---|---|
| `POST /api/pin` | record a head of your log | bearer key |
| `GET /api/verify` | ask whether a head was witnessed | none |
| `POST /api/verify?op=bulk` | the same for up to 20 heads | none |
| `GET /api/latest?ns=` | the newest record of a namespace | none |
| `POST /api/pin-batch` | one entry for many small stores (flag) | bearer key |
| `GET /api/pin-batch` | one store's latest entry (flag) | none |
| `GET /.well-known/arcaeon-witness-key` | the key receipts are signed with (flag) | none |

## POST /api/pin

Record a head: how many rows your log holds and the chain value after the last one. Only fingerprints are sent; never the content of your log.

```
POST /api/pin
Authorization: Bearer <your key>
{"namespace": "acme-prod", "rows": 128, "chain": "<8 to 64 hex>"}
```

- `namespace`: 1 to 64 of `a-z 0-9 -`, and it must start with your key's prefix.
- `rows`: a whole number from 1 to 10^12.
- `chain`: 8 to 64 hex characters. Use the full 64 (a SHA-256) if you want a signed receipt.
- `intent: "renew"` (or `POST /api/renew`): restate your current head exactly, to refresh its deadline as a heartbeat without claiming new rows.

Answers:

| status | when |
|---|---|
| 201 | recorded: a new head (`record_kind: "content_head_advance"`) or a renewal (`"publisher_heartbeat"`); `pin` is the public record |
| 200 | the same head again: already witnessed, nothing written, nothing charged |
| 400 | the body is wrong, or an unknown `intent` |
| 401 | no key, or a key the witness does not know |
| 403 | the namespace does not start with your key's prefix |
| 404 | a renewal for a namespace with no pin |
| 409 | `rows` lower than the last head (a witness never goes backward); the same rows with another chain (kept as an observation, the accepted head unchanged); a renewal that does not restate the head |
| 402 / 429 | the month's free pins and your credits are spent (`reason: "over_cap"` or `"credit_exhausted"`); with agent payments on, a 402 with quotes instead (below) |
| 429 | more than 60 pins for one key in a clock hour (`reason: "key_rate_limited"`, with `Retry-After`) |
| 502 / 503 | the witness could not reach its store; nothing was recorded. A credit or a payment taken for it is given back; one free pin of the month may be spent |

Every answer that records or restates a head carries `pin`, the public record, and with signed receipts on, `receipt` (below). The record is public at once, in the pins repo's commit history.

## GET /api/verify

Ask whether a head was witnessed. No key, no charge.

```
GET /api/verify?ns=acme-prod&rows=128&chain=<hex>      (digest= is the same as chain=)
```

- `witnessed: true`: this exact head was recorded. `is_current_head` says whether it is still the newest; `pin` is that record; with signed receipts on, `receipt` is that record's receipt.
- `witnessed: false`: refuted, with a `reason`: `rows_match_chain_mismatch` (the witness holds another chain at these rows), `rows_never_witnessed`.
- `witnessed: null`: the witness cannot say either way, with a `reason`: `no_pin_recorded_for_namespace`, `exceeds_current_head` (more rows than it ever saw), `history_unreadable`, or a scan that reached its limit of 50 older records.

`POST /api/verify?op=bulk` with `{"items": [{ns, rows, chain}, ...]}` asks the same of up to 20 heads and answers each, in order. It counts against the per IP limit by the number of items.

Public reads (`/api/verify`, `/api/latest`, `/api/health`, `/status`, the badge) are limited to 30 calls per IP per 10 minutes (429 with `Retry-After`).

## Signed receipts (flag `WITNESS_RECEIPTS`, PRs 9, 12, 13)

With receipts on, a pin's answer, a witnessed `/api/verify` answer and `/api/latest` carry `receipt`, the witness's signature on the record:

```
{"head": {"chain": "<64 hex>", "kind": "head", "n": <rows>, "v": 1},
 "key_id": "<sha256 of the witness's public key>", "kind": "receipt", "namespace": "<ns>",
 "received_at": "<YYYY-MM-DDTHH:MM:SSZ>", "sig": "<Ed25519, 128 hex>", "v": 1, "witness_seq": <record number>}
```

It is the receipt of the contract between the seal, the witness and the checker: Ed25519 over the canonical JSON of everything but `sig` (keys sorted, no whitespace, integers only). The seal's bundle check accepts it.

- The key: `GET /.well-known/arcaeon-witness-key` gives `key_id`, `public_key` (64 hex), `checkpoint_verifier_key`, and the signed `witness_statement` the seal checks receipts under. The same key also signs each published checkpoint.
- No receipt, with `receipt: null` and `receipt_unavailable` saying why: a chain that is not 64 hex (`chain_not_64_hex`), a namespace that starts with `-`, a record read from the lagging raw mirror, or no key configured.
- A receipt says: this witness took in this head for this namespace as record `witness_seq` at `received_at`. It does not say your log's owner signed it (keys are bearer keys).

## The 402 flow: paying per pin (flag `WITNESS_AGENT_PAY`, PRs 7, 13)

When your free pins and credits are spent, a pin answers 402 with quotes instead of a refusal:

```
402 {"reason": "payment_required", "field": "payment",
     "binding": {"namespace", "rows", "chain", "intent"},
     "accepts": [
       {"adapter": "x402", "token", "expires_at", "scheme": "exact", "nonce", "amount", "asset", "network", "pay_to"},
       {"adapter": "l402", "token", "expires_at", "invoice", "payment_hash", "amount_sats"}]}
WWW-Authenticate: L402 token="...", invoice="..."
```

1. Pay one quote: the stablecoin terms through the payment processor, or the Lightning invoice.
2. Send the same request again, with your bearer key as before, and the proof:
   - `X-Payment: base64(JSON {"token": "<the quote's token>", "payment_id": "<the processor's id>"})`, or
   - `X-L402: <the quote's token>:<the invoice's preimage, 64 hex>`.
3. The witness checks its own token (not expired, for this exact request), asks the processor or its own node that the payment settled for the price, and records the pin. The answer says `X-Meter-Source: payment` and `X-Payment-Ref`.

Rules:

- A quote is for one request: the same key, namespace, rows, chain and intent. It expires in 15 minutes.
- One payment buys one written pin; presenting it again is 409 `payment_already_used`.
- If the write fails after the payment was accepted, the payment is released and the same request can be sent again with it, even after the quote expired.
- Your key still decides the namespace; paying never lets you write into someone else's.
- A paid record carries `payment: {method, ref}`, a reference, never who paid.
- Refusals name their reason: `payment_for_other_request`, `quote_expired`, `bad_token_signature`, `payment_not_settled`, `payment_too_small`, `preimage_mismatch`, `payment_check_unavailable` (503, retry), and others.

## POST /api/pin-batch: many stores, one entry (flag `WITNESS_STORE_BATCH`, PRs 5, 8)

Pin up to 1000 small stores in one public entry: a Merkle root over `(store_id, head)` pairs.

```
POST /api/pin-batch
Authorization: Bearer <your key>
{"namespace": "acme-memory", "entries": [{"store_id": "alice", "head": "<64 hex>"}, ...]}
```

- `store_id`: 1 to 128 of `A-Z a-z 0-9 . _ : -`, each once per batch. `head`: 64 lower case hex. Any other field is refused by name.
- 201 answers `entry` (the public file: root, count, namespace, time; no store ids, no heads), `entry_path`, and `proofs`: one per store, `{store_id, entry_path, proof}`. Keep your store's proof; check it offline with `node tools/verify_store_proof.js --proof <file> --entry <entry file>`.
- A batch is charged as one pin.

`GET /api/pin-batch?namespace=<ns>&store_id=<id>` answers one store's latest `{entry_path, leaf_index, leaf}`, so a store that lost its proof file can see an entry it holds no proof for. No key; nothing is listed; any miss is the same 404. Prefer opaque store ids: anyone who knows one can ask.

## What the witness never does

It never receives or stores the content of your log, only counts and hashes. Its public record only grows. Nothing here lets anyone change or remove a recorded head.
