# Signed receipts

Status: built behind a flag, off by default. `WITNESS_RECEIPTS=on` with `WITNESS_RECEIPT_KEY` set turns it on.
Code: `lib/_receipt.js`, used by `api/pin.js`, `api/latest.js`, `api/verify.js` (the key document) and `tools/publish_checkpoint.js`.
Tests: `test/receipt.test.js`.

## The problem

A pin's answer, and `/api/latest`, hand back the public record `pins/<ns>/latest.json`. Nothing in it is signed. Its authenticity rests on where it sits, so a phone or a desktop holding only what the witness answered cannot tell it from an answer anybody wrote, and can never turn green from it.

## The receipt

With receipts on, every answer that carries a pin record also carries `receipt`, the witness's signature on that record, in exactly the shape of the receipt in the contract between the seal, the witness and the checker (the reference witness's `docs/CONTRACT.md`, "Pins and receipts"):

```
{"head": {"chain": "<64 hex>", "kind": "head", "n": <rows>, "v": 1},
 "key_id": "<sha256 of the raw public key>", "kind": "receipt", "namespace": "<ns>",
 "received_at": "<pinned_at, whole seconds, YYYY-MM-DDTHH:MM:SSZ>",
 "sig": "<Ed25519 over the canonical bytes of the rest, 128 hex>", "v": 1, "witness_seq": <seq>}
```

`n` is the record's rows, `chain` its chain, `witness_seq` its seq, which only grows for a namespace, and `received_at` the witness's own clock when it wrote the record. The canonical bytes are the contract's: keys sorted, no whitespace, integers only, no null.

The tests carry a receipt and a witness statement made by the reference witness's own code with a throwaway key. Ed25519 signatures are deterministic, so this code must, and does, give byte for byte the same receipt for the same record and key. That is what lets a contract reader, the seal's bundle check among them, accept it.

Where receipts appear:

- `POST /api/pin`: a new head (201), a renewal (201, a new `witness_seq`) and the idempotent re-pin of the current head (200, the same receipt as before).
- `GET /api/latest`: the latest record's receipt, but only when the record was read through the contents API. A record served from the raw CDN fallback, which can lag a write by minutes, gets no receipt.

A pin the contract cannot carry gets no receipt, and the answer says why in `receipt_unavailable`: `chain_not_64_hex` (the contract's head chain is a SHA-256; this witness also takes shorter chains), `namespace_not_in_contract_form` (the contract's namespace starts with a letter or digit), `receipt_key_not_configured`, `read_from_lagging_mirror`. A receipt a contract reader would refuse is never made.

## The key

`WITNESS_RECEIPT_KEY` holds the 32 byte Ed25519 seed as 64 lower case hex characters, set by the owner's hand. Nothing in this repo creates a key, writes one, logs one, or puts one in an answer or an error; tests use a throwaway seed. A key that does not read is the same as none.

The public half is published three ways:

- `GET /.well-known/arcaeon-witness-key` (a rewrite to `/api/verify?op=witness-key`): `{algorithm, key_id, public_key, checkpoint_verifier_key}`, and, with `WITNESS_RECEIPT_STARTED_AT` set, the contract's `witness_statement`, signed by the same key: a stable document every receipt is checked against.
- The checkpoint. `tools/publish_checkpoint.js` adds one signature line by the receipt key, under the key name `arcaeon.io/witness-pins/receipts`, to every checkpoint it publishes. A checker that does not know that key ignores the line, as the signed note layout requires; one that does can tie the key every receipt names to the log's own published checkpoint. `checkpoint_verifier_key` in the key document is that key in the note's own form.
- `key_id` in every receipt.

## Checking a receipt

`lib/_receipt.js` `verify(receipt, publicRaw)` checks the shape, that `key_id` is the hash of the key, and the signature, and names the field at fault. A contract reader in another language does the same with the contract's own rules.

What a receipt proves: the holder of this key said it took in this head for this namespace as record `witness_seq` at `received_at`. It does not prove the log owner signed the head (the hosted witness is bearer key auth), and it binds a namespace and head, not one particular pin request: the contract's version 3 adds `pin_digest` for that.

## Checked end to end against the seal (Sat 2026-10-31)

A drill, run by hand, not part of this repo's suite since it needs the seal's repo:

1. A real seal store (`arcaeon-seal-sandbox`, `python -m seal write` twice) gave the head `{n: 2, chain: 5f62c094...}`.
2. That head was pinned through this repo's own `api/pin.js` with receipts on and a throwaway key; the answer's receipt was saved as `demo-seal.1.json` and the key document's `witness_statement` as the statement file.
3. `python -m seal export --receipts ... --statement ...`, then `python -m seal verify-bundle bundle.zip --witness-key-id <key_id>` printed: `receipt demo-seal.1.json: witness_seq 1, head n 2, held by the ledger in the bundle; replay table row against the bundle's head: current: may proceed`, then `OK 0 problems`, exit 0.
4. The same receipt with its head changed to n 3 was refused: `RECEIPT_UNREADABLE ... field sig: it does not verify under the witness's key`, exit 2.

## Turning it on

1. The owner makes a key by hand and sets `WITNESS_RECEIPT_KEY`, and `WITNESS_RECEIPT_STARTED_AT` to the time the key went into use.
2. Set `WITNESS_RECEIPTS=on` on the Vercel project and where the checkpoint is published.
3. Redeploy. Answers carry receipts; `/.well-known/arcaeon-witness-key` answers the key.
