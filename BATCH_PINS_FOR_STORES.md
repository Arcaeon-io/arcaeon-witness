# One witness entry for many small stores

Status: built behind a flag, off by default. `WITNESS_STORE_BATCH=on` turns it on.
Code: `lib/_store_batch.js`, routed from `api/pin.js` as `?op=batch_stores`
(`/api/pin-batch` rewrites there). Offline check: `tools/verify_store_proof.js`.
Tests: `test/store_batch.test.js`.

## The problem

A single pin is one namespace, one head, two public writes. That fits a log
with a steady writer. It does not fit many tiny stores, for example one
memory folder per person or per agent, each changing a few times a day. A
thousand such stores pinned one by one is two thousand commits and a thousand
metered pins for what is, to the outside world, one statement: "at this time
the witness saw these thousand heads".

## The shape

One request carries up to 1000 pairs:

```
POST /api/pin-batch            Authorization: Bearer <key>
{ "namespace": "acme-memory",
  "entries": [ { "store_id": "alice", "head": "<sha256 hex>" }, ... ] }
```

The witness makes one leaf per pair, in the order sent:

```
{ leaf_kind: "store_head:v1", namespace, store_id, head, accepted_at }
```

and builds a Merkle tree over them with the same hashing the pin batches use
(`lib/_merkle.js`: 0x00 leaf prefix and 0x01 node prefix, canonical JSON
leaves, odd nodes promoted rather than doubled). It writes **one** file to
the public pin repo:

```
store_batches/<namespace>/<root hex>.json
{ kind: "store_batch:v1", namespace, root, tree_size, accepted_at, leaf_recipe, note }
```

and answers 201 with that entry, its path and commit, and one proof per store:

```
{ store_id, entry_path,
  proof: { recipe, leaf, leaf_hash, leaf_index, tree_size, path, root } }
```

Each store keeps its own proof. That is the whole client duty.

## Checking a proof offline

`verifyStoreProof(bundle, expect, entry)` in `lib/_store_batch.js`, or from a
shell:

```
node tools/verify_store_proof.js --proof alice.json --store-id alice --head <hex> --entry entry.json
```

It needs no network and nothing of ours. It checks, in order:

1. the leaf is a store leaf (`leaf_kind`), so a pin leaf cannot pose as one;
2. the leaf's store id, head and namespace are the ones the store expects;
3. the leaf hash is derived from the leaf, never taken from the proof;
4. the sibling path walks the tree shape fixed by the index and the leaf count,
   no more and no fewer siblings, and reaches the root;
5. with the public entry given: the entry is a store batch, its namespace and
   time are the leaf's, and its root and leaf count are the proof's.

Without the entry it proves inclusion under the root in the proof; it says so
and does not claim the root was published. The entry is a plain file in the
public repo at `entry_path`, so fetching it once and keeping it beside the
proof makes every later check fully offline.

## What is public and what is not

Public: the root, the leaf count, the namespace and the witness's clock.
Not public: any store id or head. The leaves go back to the caller only. So
a reader of the public repo learns that some key for this namespace pinned N
stores at time T, and nothing about which stores or what they hold. Store ids
are the caller's own labels; an opaque id (a hash of a name) is the better
habit, and the witness never needs to know what it means.

Nothing but `store_id` and `head` is accepted in an entry. Any other field is
refused by name, because an extra field could be content and the witness
stores fingerprints only.

## What a batch proves and what it does not

Proves: the witness saw this store's head, in this namespace, at
`accepted_at`, and the public entry committing to it has not changed since its
commit. The entry file is create only: if a file already sits at that path
the batch is refused 409 and nothing is replaced.

Does not prove:

* **order between stores' versions.** Each batch is a stand alone statement.
  There is no per store sequence and no "latest" pointer, so nothing here
  stops a namespace from pinning two different heads for one store in two
  batches. A store that wants a chain keeps its proofs in order itself, or
  uses the single pin path, which has the monotonic guard.
* **that a store was left out on purpose.** The batch says what was in it,
  never what was not.
* **anything about content.** A head is a fingerprint the store computed.

## Who can do what

* The ledger owner cannot backdate: `accepted_at` is the witness's clock, it is
  inside every leaf, and the proof checks it against the public entry. An
  entry edited to an earlier time with the root kept fails (`accepted_at_mismatch`).
* The ledger owner cannot replace a batch: the path is the root, and the file
  is create only.
* A stranger cannot batch into another namespace: the key's prefix must prefix
  the namespace, the same rule as a single pin (403 naming `namespace`).
* Flooding: a batch passes the same per key rate limit and the same meter as
  a single pin, and holds at most 1000 stores.

## Cost

One public write per batch, whatever its size. Metering: a batch is charged as
one pin, the same `meterAndCharge` and the same refund on a failed write as a
single pin. That is the point of the feature, and it is also a pricing choice:
the owner may want to charge per store or per bucket of stores later. The
charge is one line in `lib/_store_batch.js` handle().

## A store's own latest

A store keeps its proofs, and a store that loses its proof file must be able to notice. So after each batch the witness keeps one private index per namespace, `store_latest/<namespace>.json` in the private usage store (or the account database with `WITNESS_USAGE_STORE=postgres`), keyed by `sha256("store-latest:v1\n" + namespace + "\n" + store_id)`, holding each store's latest `{entry_path, leaf_index, accepted_at, leaf}`. It is one private write per batch, whatever the batch's size, under the same compare and swap as the meter. A pointer is never moved back by an older batch; at the very same time, the later write wins.

The holder of a store id asks:

```
GET /api/pin-batch?namespace=acme-memory&store_id=alice
-> 200 {ok, store_id, namespace, entry_path, leaf_index, leaf}
-> 404 {reason: "not_found", field: "store_id"}
```

and compares the answer with its newest proof. The same entry and leaf: nothing is missing. Anything else: there is a later batch it holds no proof for, so a deleted proof file shows. The answer gives the leaf, not the path: the proof itself is the store's to keep.

What this does and does not show. No key is asked: the store id is the question, so an opaque one (a hash of a name) is the better habit, since anyone who knows or guesses a store id can learn when it was last pinned and its head. Nothing is listed: a store never pinned and a namespace never used get the same 404, and a per IP limit applies. The index never reaches the public repo; the public entry stays the root alone. The leaf format is unchanged: a 64 hex head, and any field but `store_id` and `head` is still refused.

Limits. The index is one file per namespace. With the GitHub store it should stay under the contents API's 1 MB read, about three thousand stores per namespace; the database store has no such limit. If the index cannot be written after the public entry landed, the batch stands and its answer says `latest_index: "not_updated"`; the next batch for that store brings the pointer up to date. An index file that is not an index is left as it is and never written over.

## Turning it on

Set `WITNESS_STORE_BATCH=on` and redeploy. With it off, `?op=batch_stores`
answers 404 `not_enabled` and writes nothing; every other pin is unchanged.
