# Agents pay per pin

Status: built behind flags, off by default, no live keys. Code:
`lib/_agent_pay.js` (the flow), `lib/_pay_x402.js` (stablecoin adapter),
`lib/_pay_l402.js` (Lightning adapter), wired into `api/pin.js` through two
small wrappers (`chargeFor`, `refundOrRelease`). Tests: `test/agent_pay.test.js`
against mocks of the processor and the node (`test/helpers/mock_payments.js`).

## The owner's research, as given (Fri 2026-10-30, 11:55 PM PT)

Summarized from the owner's notes, not re-checked here:

* Stripe takes stablecoins only, no Bitcoin.
* x402 style settlement costs about $0.001 a payment after 1,000 a month free.
* Lightning costs about 31 sats per pin.
* No custodial Bitcoin processor. The Lightning side is the operator's own node.

## The flow

1. **Refusal becomes a quote.** A keyed pin whose free tier and credits are
   spent used to get 429 `over_cap` or 402 `credit_exhausted`. With
   `WITNESS_AGENT_PAY=on` it gets **402 `payment_required`** instead:

   ```
   { reason: "payment_required", field: "payment", meter_reason: "over_cap",
     binding: { namespace, rows, chain, intent },
     accepts: [
       { adapter: "x402", token, expires_at, scheme: "exact", resource: "/api/pin",
         nonce, amount, asset, network, pay_to },
       { adapter: "l402", token, expires_at, invoice, payment_hash, amount_sats } ],
     how: "pay one quote, then send this same request again with X-Payment or X-L402" }
   ```

   plus `WWW-Authenticate: L402 token="...", invoice="..."` when Lightning is on.
   Nothing is written. Only a refusal a payment can answer becomes a 402: a key
   with no cap configured keeps its 401, because that is a configuration fault.

2. **The agent pays one quote** and sends the same request again with:
   * `X-Payment: base64(JSON {token, payment_id})` for the stablecoin adapter, or
   * `X-L402: <token>:<preimage hex>` for Lightning.

   These are headers of their own because `Authorization` already carries the
   key. Sending both is refused.

3. **The witness checks, in this order, and stops at the first failure:**
   1. the token is one it signed (HMAC with `WITNESS_PAY_SECRET`), for this
      adapter, not expired (15 minutes);
   2. the token's binding is this request: sha256 of the key's hash,
      namespace, rows, chain and intent. A payment for one head cannot pin
      another, and one key's payment cannot pay for another key;
   3. the adapter confirms the payment settled for at least the price, by asking
      the processor or the node, never by trusting the agent;
   4. the payment is claimed in the ledger, `payments/<adapter>/<ref>.json` in
      the private usage repo, with a create only write.

   Only then does the pin write run. The free meter is not touched.

## One pin per payment, one charge per written pin

* The ledger record is created once. The same payment presented again finds
  it claimed and gets 409 `payment_already_used`. Two concurrent retries with
  one proof race on the create; exactly one wins.
* A pin that writes nothing (a refusal, or the idempotent re-pin of the
  current head) never reaches the charge step, so its proof is not spent.
* **No write, no charge:** whenever the request ends without a numbered
  record written, for any reason (a failed write, or an early refusal on a
  later pass after a heal adopted another writer's record), the record moves to
  `released` once, in the handler's `finally`, and the same proof is accepted
  again for the same request, even after its quote expired. A record that did
  land (even if the latest pointer then failed) keeps the payment: the retry
  adopts that record and cannot buy a second one. That
  is this path's refund, and it keeps the promise the credit path keeps
  (`refundFailedWrite`): a charge that buys no write is given back. No money is
  sent back automatically. The agent's retry spends what it already paid. A
  release that itself fails is logged loudly and the record stays claimed, the
  same residual the credit refund documents.

## The key still decides the namespace

Payment replaces the meter, never the key check. An anonymous payer could
otherwise buy a write into any namespace and, through the monotonic guard,
lock the owner out of their own log. Agents get keys the way any caller does;
the account path's agent registration is the natural source.

## Failure behaviour

| case | answer | charged | written |
|---|---|---|---|
| bad, tampered or expired token | 401, reason names it, field `x-payment` or `x-l402` | no | no |
| token for another request | 409 `payment_for_other_request` | no | no |
| token for the other method | 401 `token_for_other_method` | no | no |
| payment unknown, unsettled, too small, other terms | 402 with that reason | no | no |
| wrong preimage | 402 `preimage_mismatch` | no | no |
| processor or node unreachable on the check | 503 `payment_check_unavailable`, retry safe | no | no |
| ledger unreachable | 503 `payment_ledger_unavailable`, retry safe | no | no |
| one adapter cannot quote | 402 with the other, `unavailable` names the one down | | no |
| no adapter can quote | 503 `payment_unavailable` | | no |
| write fails after the claim | 502, payment released | given back | no |
| a heal on a later pass ends in a refusal | that refusal, payment released | given back | no |
| key with no cap configured, even with a proof | 401 `no_cap_configured` | no | no |

## The adapters

**Stablecoin, x402 style** (`lib/_pay_x402.js`). The quote names scheme, network,
asset, amount in the asset's smallest unit, payee and a fresh nonce. To check, one
call to the processor:

```
POST <WITNESS_PAY_X402_API>/v1/verify  {payment_id, nonce, amount, asset, network, pay_to}
-> {settled, payment_id, nonce, amount, asset, network, pay_to}
```

Every field that comes back is compared with the quote, and amounts are
compared as whole numbers (BigInt), never floats. The ledger reference is
sha256 of the processor's payment id.

**Lightning, L402 style** (`lib/_pay_l402.js`). The quote makes an invoice on the
operator's own node and puts its payment hash in the signed token. To check:
sha256(preimage) must equal that hash (only the payer learns the preimage), and
the node must say the invoice is `SETTLED` with at least the price paid. The
node is reached over the LND REST shape, which a self hosted BTCPay with LND
also serves, with an invoice only macaroon: the witness can make and read
invoices and cannot spend.

## Settings

| setting | meaning |
|---|---|
| `WITNESS_AGENT_PAY` | on, to offer payment at all |
| (both adapters) | the processor and node addresses must be https, or the adapter is not offered |
| `WITNESS_PAY_SECRET` | token signing secret, at least 32 characters; without it nothing is offered |
| `WITNESS_PAY_X402`, `_API`, `_KEY`, `_PAY_TO`, `_ASSET`, `_NETWORK`, `_AMOUNT` | the stablecoin adapter; any missing and it is not offered |
| `WITNESS_PAY_L402`, `_NODE`, `_MACAROON`, `_SATS` | the Lightning adapter; any missing and it is not offered |

No default prices. The owner's notes put Lightning at about 31 sats a pin as a
cost; the price is the owner's to set.

## Before live keys

1. Check the processor's agent payments verification call against its own
   documentation and adjust `lib/_pay_x402.js` verify, which is one function
   and the only place that knows the processor's shape. Its fields are
   named in this file as an assumption, not a fact.
2. Bake the node's invoice only macaroon and confirm it cannot pay.
3. Decide prices and set them.
4. Decide whether a released payment should also be refundable in money after
   its quote expires, and by whom. Today it stays redeemable only by a retry
   of the same request, and the record says `released`.
5. With `WITNESS_USAGE_STORE=postgres` (the meter off GitHub pull request) the
   ledger moves with the pending store, since it uses the same two functions.

## Not touched

Account billing, cancel and refund code. `meterAndCharge` and
`refundFailedWrite` are unchanged; the new wrappers call them.
