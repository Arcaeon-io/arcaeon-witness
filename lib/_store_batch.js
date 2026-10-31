// _store_batch.js — one public entry for many small stores. Design:
// BATCH_PINS_FOR_STORES.md. Underscore prefix = not routed as a serverless
// function; reached as POST /api/pin?op=batch_stores (vercel.json rewrites
// /api/pin-batch there), because the project is at its function count.
//
// A caller holding a key for a namespace sends up to MAX_ENTRIES pairs of
// (store_id, head). The witness builds a Merkle tree over one leaf per pair
// (lib/_merkle.js, the same hashing and the same verifier as the pin batches),
// writes ONE create-only file to the public pin repo holding only the root,
// the leaf count, the namespace and its own clock, and answers with an
// inclusion proof per store. Each store keeps its own proof and can check it
// offline (verifyStoreProof below, or tools/verify_store_proof.js).
//
// What is public: the root, tree_size, namespace, accepted_at. Not the leaves.
// A store's id and head are known to the caller and to the holder of the
// proof, and nowhere else; the root reveals neither.
//
// Off unless WITNESS_STORE_BATCH is on.

"use strict";

const merkle = require("./_merkle.js");
const store = require("./_store.js");

const LEAF_KIND = "store_head:v1";
const ENTRY_KIND = "store_batch:v1";
const MAX_ENTRIES = 1000;
const STORE_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const HEAD_RE = /^[0-9a-f]{64}$/;
const NS_RE = /^[a-z0-9-]{1,64}$/;

function enabled(env = process.env) {
  const v = String(env.WITNESS_STORE_BATCH || "").toLowerCase();
  return v === "on" || v === "1" || v === "true" || v === "yes";
}

function entryPath(namespace, rootHex) {
  return `store_batches/${namespace}/${rootHex}.json`;
}

// Every refusal names the field at fault.
function refuse(field, reason, error) {
  return { field, reason, error };
}

function validate(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return refuse("body", "body_not_object", "body must be a JSON object");
  }
  if (typeof body.namespace !== "string" || !NS_RE.test(body.namespace)) {
    return refuse("namespace", "bad_namespace", "namespace must match [a-z0-9-]{1,64}");
  }
  const e = body.entries;
  if (!Array.isArray(e) || e.length === 0) {
    return refuse("entries", "entries_empty", "entries must be a non-empty array of {store_id, head}");
  }
  if (e.length > MAX_ENTRIES) {
    return refuse("entries", "too_many_entries", `entries holds at most ${MAX_ENTRIES} stores per batch`);
  }
  const seen = new Set();
  for (let i = 0; i < e.length; i++) {
    const x = e[i];
    if (!x || typeof x !== "object" || Array.isArray(x)) {
      return refuse(`entries[${i}]`, "entry_not_object", `entries[${i}] must be an object {store_id, head}`);
    }
    const extra = Object.keys(x).filter((k) => k !== "store_id" && k !== "head");
    if (extra.length) {
      // Nothing but the two fingerprints is accepted: an unknown field could
      // be content, and the witness never stores content.
      return refuse(`entries[${i}].${extra[0]}`, "unknown_field", `entries[${i}] may carry only store_id and head`);
    }
    if (typeof x.store_id !== "string" || !STORE_ID_RE.test(x.store_id)) {
      return refuse(`entries[${i}].store_id`, "bad_store_id", "store_id must match [A-Za-z0-9._:-]{1,128}");
    }
    if (typeof x.head !== "string" || !HEAD_RE.test(x.head)) {
      return refuse(`entries[${i}].head`, "bad_head", "head must be 64 lowercase hex characters (a sha256)");
    }
    if (seen.has(x.store_id)) {
      return refuse(`entries[${i}].store_id`, "duplicate_store_id", `store_id "${x.store_id}" appears twice in one batch`);
    }
    seen.add(x.store_id);
  }
  return null;
}

function leafFor(namespace, acceptedAt, entry) {
  return {
    leaf_kind: LEAF_KIND,
    namespace,
    store_id: entry.store_id,
    head: entry.head,
    accepted_at: acceptedAt,
  };
}

// Pure: the tree, the public entry and every proof, with no store and no clock.
function build(namespace, entries, acceptedAt) {
  const leaves = entries.map((e) => leafFor(namespace, acceptedAt, e));
  const hashes = leaves.map((l) => merkle.leafHash(l));
  const levels = merkle.buildLevels(hashes);
  const root = merkle.rootOf(levels);
  const rootLabel = merkle.labelled(merkle.MERKLE_RECIPE, root);
  const path = entryPath(namespace, root.toString("hex"));
  const entry = {
    kind: ENTRY_KIND,
    namespace,
    root: rootLabel,
    tree_size: leaves.length,
    accepted_at: acceptedAt,
    leaf_recipe: merkle.LEAF_RECIPE,
    note:
      "One witness entry for many stores. Only the root is public; each store holds its own leaf and " +
      "inclusion proof. See BATCH_PINS_FOR_STORES.md.",
  };
  const proofs = leaves.map((leaf, i) => ({
    store_id: leaf.store_id,
    proof: {
      recipe: merkle.MERKLE_RECIPE,
      leaf,
      leaf_hash: merkle.labelled(merkle.LEAF_RECIPE, hashes[i]),
      leaf_index: i,
      tree_size: leaves.length,
      path: merkle.proofPath(levels, i),
      root: rootLabel,
    },
    entry_path: path,
  }));
  return { entry, path, proofs };
}

// Offline check a store runs on its own proof. `expect` is what the store
// itself knows: {store_id, head, namespace?}. `entry`, when given, is the
// public entry file (fetched by the store, or kept from the answer), and binds
// tree_size and the root to what was published.
function verifyStoreProof(bundle, expect = {}, entry = null) {
  if (!bundle || typeof bundle !== "object" || !bundle.proof || typeof bundle.proof !== "object") {
    return { ok: false, reason: "malformed_proof", field: "proof" };
  }
  const leaf = bundle.proof.leaf;
  if (!leaf || typeof leaf !== "object") return { ok: false, reason: "leaf_required", field: "proof.leaf" };
  if (leaf.leaf_kind !== LEAF_KIND) return { ok: false, reason: "not_a_store_leaf", field: "proof.leaf.leaf_kind" };
  for (const f of ["store_id", "head", "namespace"]) {
    if (expect[f] !== undefined && leaf[f] !== expect[f]) {
      return { ok: false, reason: `${f}_mismatch`, field: `proof.leaf.${f}` };
    }
  }
  if (bundle.store_id !== undefined && bundle.store_id !== leaf.store_id) {
    return { ok: false, reason: "store_id_mismatch", field: "store_id" };
  }
  let published = null;
  if (entry !== null && entry !== undefined) {
    if (typeof entry !== "object" || entry.kind !== ENTRY_KIND) {
      return { ok: false, reason: "not_a_store_batch_entry", field: "entry.kind" };
    }
    if (entry.namespace !== leaf.namespace) return { ok: false, reason: "namespace_mismatch", field: "entry.namespace" };
    if (entry.accepted_at !== leaf.accepted_at) return { ok: false, reason: "accepted_at_mismatch", field: "entry.accepted_at" };
    published = { root: entry.root, tree_size: entry.tree_size };
  }
  const r = merkle.verifyInclusion(bundle.proof, published);
  if (!r.ok) return { ...r, field: "proof" };
  return { ok: true, reason: "included", store_id: leaf.store_id, head: leaf.head,
    accepted_at: leaf.accepted_at, tree_size_bound: r.tree_size_bound };
}

// The handler half. api/pin.js has already checked the key and resolved its
// prefix; it hands in its own rate limit and meter so this path is limited and
// charged by the same rules as a single pin (one batch, one public write, one
// pin's worth).
async function handle(req, res, { key, prefix, rateLimited, meterAndCharge, refundFailedWrite, applyHeaders, now = () => new Date() }) {
  if (!enabled()) {
    return res.status(404).json({ error: "store batches are not enabled on this witness", reason: "not_enabled", field: "op" });
  }
  const body = typeof req.body === "object" ? req.body : null;
  const bad = validate(body);
  if (bad) return res.status(400).json(bad);
  const { namespace, entries } = body;
  if (!namespace.startsWith(prefix)) {
    return res.status(403).json({
      error: `this key may only pin namespaces starting with "${prefix}"`,
      reason: "namespace_not_yours",
      field: "namespace",
    });
  }
  if (await rateLimited(key)) {
    return res.status(429).json({ error: "rate limit exceeded", reason: "key_rate_limited", field: "authorization" });
  }

  const acceptedAt = now().toISOString();
  const { entry, path, proofs } = build(namespace, entries, acceptedAt);

  const charge = await meterAndCharge(key);
  applyHeaders(res, charge.headers);
  if (charge.deny) return res.status(charge.deny.status).json(charge.deny.body);

  let put;
  try {
    put = await store.putFile(path, entry, `store batch ${namespace} n=${entry.tree_size}`);
  } catch (err) {
    await refundFailedWrite(key, charge.source, namespace, 0, err && err.message);
    if (err && err.conflict) {
      // The same root at the same path: the same namespace, the same pairs
      // and the same millisecond. The file is create only, so nothing was
      // replaced; the caller retries and gets a fresh accepted_at.
      return res.status(409).json({ error: "an identical batch entry already exists", reason: "entry_exists", field: "entries" });
    }
    return res.status(502).json({ error: `pin store error: ${err && err.message}`, reason: "store_error", field: "entries", retry_safe: true });
  }

  return res.status(201).json({
    ok: true,
    entry,
    entry_path: path,
    commit: put && put.commit ? put.commit.sha : null,
    proofs,
  });
}

module.exports = { handle, build, validate, verifyStoreProof, enabled, entryPath, LEAF_KIND, ENTRY_KIND, MAX_ENTRIES };
