#!/usr/bin/env node
// tools/move_vectors.js: builds docs/move-vectors.json, the fixed examples of
// the pack move route that both sides can carry. One ask and one answer for
// each status (moved, moved asked again, not_sold, elsewhere), as exact
// canonical bytes, with the test keys that signed them.
//
// The two keys are the published Ed25519 test keys of RFC 8032, section 7.1,
// TEST 1 (asker) and TEST 2 (seller). They are test values, known to everyone,
// and must never be pinned or set on a host.
//
// Ed25519 signatures are deterministic, so the other side can sign the same
// unsigned bytes with the same seed and must get the same signature.
// test/move.test.js checks that this file matches what this tool builds, that
// the route itself answers these exact bytes, and that the Python line of the
// specification gives the same canonical bytes.
//
// USAGE
//   node tools/move_vectors.js            print the JSON
//   node tools/move_vectors.js --write    write docs/move-vectors.json

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const move = require("../lib/_move.js");

const ASKER_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"; // RFC 8032 7.1 TEST 1
const SELLER_SEED = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"; // RFC 8032 7.1 TEST 2
const ORIGIN = "arcaeon.io/witness/v1";
const CLOCK = "2030-01-15T12:00:00Z";
const LATER = "2030-01-15T12:01:00Z";
const PACK_SIZES = { pins_200: 200, pins_1000: 1000 };
const OUT = path.join(__dirname, "..", "docs", "move-vectors.json");

const sha256 = (text) => crypto.createHash("sha256").update(text, "utf8").digest("hex");

function keysOf(seed) {
  const k = move.loadAnswerKey({ [move.ANSWER_KEY_ENV]: seed });
  if (!k.ok) throw new Error(k.reason);
  return k;
}

// The key texts each case asks about. key_hash is the SHA-256 of the text.
const KEYS = {
  moved: "move-vector-sold-key",
  not_sold: "move-vector-unknown-key",
  elsewhere: "move-vector-elsewhere-key",
};

// The mark the moved cases answer: two checkouts, 5 pins spent before the ask.
const MARK = {
  credits: 1195,
  moved_at: CLOCK,
  sales: [
    { checkout: "cs_test_vector0001", credits: 200, pack: "pins_200" },
    { checkout: "cs_test_vector0002", credits: 1000, pack: "pins_1000" },
  ],
};

function bytesEntry(obj) {
  const unsigned = {};
  for (const k of Object.keys(obj)) if (k !== "sig") unsigned[k] = obj[k];
  const signedBytes = move.canonicalBytes(obj);
  const unsignedBytes = move.canonicalBytes(unsigned);
  return {
    unsigned_text: unsignedBytes.toString("utf8"),
    unsigned_hex: unsignedBytes.toString("hex"),
    text: signedBytes.toString("utf8"),
    hex: signedBytes.toString("hex"),
  };
}

function buildVectors() {
  const asker = keysOf(ASKER_SEED);
  const seller = keysOf(SELLER_SEED);
  const ask = (keyText, nonce, askedAt) => {
    const a = {
      asked_at: askedAt, key_hash: sha256(keyText), key_id: asker.key_id,
      kind: "move_ask", nonce, to: ORIGIN, v: 1,
    };
    a.sig = move.signObject(a, asker.privateKey);
    return a;
  };
  const answer = (status, a, mark) =>
    JSON.parse(move.signedAnswer({ status, keyHash: a.key_hash, to: a.to, nonce: a.nonce, mark }, seller).toString("utf8"));

  const cases = [];
  const add = (name, note, a, status, mark) => {
    cases.push({ name, note, ask: bytesEntry(a), answer: bytesEntry(answer(status, a, mark)) });
  };
  add("moved",
    "the first ask for a key with two checkouts on it and 1195 pins left; the seller marks it",
    ask(KEYS.moved, "00000000000000000000000000000001", CLOCK), "moved", MARK);
  add("moved_again",
    "the same key asked again a minute later with a new nonce: the same credits, sales and moved_at",
    ask(KEYS.moved, "00000000000000000000000000000002", LATER), "moved", MARK);
  add("not_sold",
    "a key the seller holds no bought pack for",
    ask(KEYS.not_sold, "00000000000000000000000000000003", CLOCK), "not_sold", null);
  add("elsewhere",
    "a key already marked moved to another origin",
    ask(KEYS.elsewhere, "00000000000000000000000000000004", CLOCK), "elsewhere", null);

  return {
    about: "Fixed examples of the pack move route (docs/pack-move-route.md). Built by tools/move_vectors.js. " +
      "Each text is the exact canonical JSON; each hex is the same bytes. A signature is Ed25519 over unsigned_text.",
    keys_warning: "Both keys are the public Ed25519 test keys of RFC 8032, section 7.1, TEST 1 and TEST 2. Never pin or set them on a host.",
    asker: { rfc8032: "7.1 TEST 1", seed: ASKER_SEED, public_key: asker.public_key, key_id: asker.key_id, origin: ORIGIN },
    seller: { rfc8032: "7.1 TEST 2", seed: SELLER_SEED, public_key: seller.public_key, key_id: seller.key_id },
    seller_clock: CLOCK,
    pack_sizes: PACK_SIZES,
    key_texts: KEYS,
    cases,
  };
}

function render() {
  return JSON.stringify(buildVectors(), null, 2) + "\n";
}

if (require.main === module) {
  if (process.argv.includes("--write")) {
    fs.writeFileSync(OUT, render());
    console.log(`wrote ${path.relative(process.cwd(), OUT)}`);
  } else {
    process.stdout.write(render());
  }
}

module.exports = { buildVectors, render, ASKER_SEED, SELLER_SEED, ORIGIN, CLOCK, LATER, PACK_SIZES, KEYS, MARK, OUT };
