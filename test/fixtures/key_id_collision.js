"use strict";
// THE KEY-ID COLLISION (unit R-RVf3, item 2): how test/fixtures/
// key_id_collision.json was found. A key id is `<name>+<hash>`, where hash
// is the first 4 bytes (8 hex) of sha256(name, "\n", 0x01, public key)
// (lib/_checkpoint.js keyHash): 32 bits, so two keys under one name sharing
// an id are a birthday search of about 2^16 keys, not a 2^32 one. The
// search is deterministic: key i's Ed25519 seed is sha256(SEED_TAG + i), and
// it stops at the first id already seen. Run it to print the pair:
//   node test/fixtures/key_id_collision.js > test/fixtures/key_id_collision.json
// Nothing is written by the script itself.
const crypto = require("node:crypto");
const checkpoint = require("../../lib/_checkpoint.js");

const NAME = "arcaeon.io/case-test/key-id-collision";
const SEED_TAG = "arcaeon-witness key-id collision search, unit R-RVf3\n";
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_TRIES = 2000000;

function seedOf(i) {
  return crypto.createHash("sha256").update(`${SEED_TAG}${i}`).digest();
}

// key i as lib/_checkpoint.js generateKey would print it
function keyOf(i) {
  const seed = seedOf(i);
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
  const pub = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(SPKI_PREFIX.length);
  const h = checkpoint.keyHash(NAME, pub).toString("hex");
  return {
    counter: i,
    hash: h,
    signer: `PRIVATE+KEY+${NAME}+${h}+${Buffer.concat([Buffer.from([0x01]), seed]).toString("base64")}`,
    verifier: `${NAME}+${h}+${Buffer.concat([Buffer.from([0x01]), pub]).toString("base64")}`,
  };
}

function search() {
  const seen = new Map();
  for (let i = 0; i < MAX_TRIES; i += 1) {
    const k = keyOf(i);
    if (seen.has(k.hash)) return { first: keyOf(seen.get(k.hash)), second: k, tried: i + 1 };
    seen.set(k.hash, i);
  }
  throw new Error(`no collision in ${MAX_TRIES} keys`);
}

if (require.main === module) {
  const { first, second, tried } = search();
  const strip = ({ counter, signer, verifier }) => ({ counter, signer, verifier });
  process.stdout.write(`${JSON.stringify({
    how: "test/fixtures/key_id_collision.js: key i's Ed25519 seed is sha256(seed_tag + i); the search stops at the first key id already seen",
    name: NAME,
    seed_tag: SEED_TAG,
    key_id: `${NAME}+${first.hash}`,
    tried,
    keys: [strip(first), strip(second)],
  }, null, 2)}\n`);
}

module.exports = { NAME, SEED_TAG, keyOf };
