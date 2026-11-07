#!/usr/bin/env node
// tools/contract_keygen.js: make the witness's contract key, once, offline,
// on the operator's own machine.
//
//   node tools/contract_keygen.js --out <path>
//
// Writes three files, each created new (an existing one is refused):
//   <path>                  the 32 byte seed as 64 lower case hex, no
//                           newline, readable by its owner only. This is
//                           the value of WITNESS_CONTRACT_SEED, and the one
//                           secret this tool makes.
//   <path>.statement.json   the key's signed witness_statement as its
//                           canonical bytes: WITNESS_CONTRACT_STATEMENT
//   <path>.recovery.txt     the key id and public key, nothing secret
// Prints the key id and the setting names. Never prints the seed.
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const c = require("../lib/_contract.js");
const contractKey = require("../lib/_contract_key.js");

function fail(msg) {
  process.stderr.write(`contract_keygen: ${msg}\n`);
  process.exit(2);
}

const args = process.argv.slice(2);
const at = args.indexOf("--out");
const out = at >= 0 ? args[at + 1] : undefined;
if (!out || out.startsWith("--")) fail("name the seed file with --out <path>; nothing was written");

const files = [out, `${out}.statement.json`, `${out}.recovery.txt`];
for (const f of files) if (fs.existsSync(f)) fail(`${f} already exists; nothing was written`);

const seed = crypto.randomBytes(32).toString("hex");
const privateKey = c.privateFromSeed(seed);
const publicKey = c.publicRaw(privateKey).toString("hex");
const keyId = c.keyId(Buffer.from(publicKey, "hex"));
const statement = c.canonical(c.sign(privateKey, {
  kind: "witness_statement",
  public_key: publicKey,
  started_at: c.formatTime(new Date()),
  v: 1,
}));

// Check the key before keeping it: it must load exactly as the witness
// will load it, and sign a receipt that verifies.
try {
  const loaded = contractKey.load({
    WITNESS_CONTRACT_SEED: seed,
    WITNESS_CONTRACT_KEY_ID: keyId,
    WITNESS_CONTRACT_STATEMENT: statement.toString("utf8"),
  });
  const pin = { head: { chain: "0".repeat(64), kind: "head", n: 0, v: 1 }, key_id: "0".repeat(64), namespace: "check" };
  const receipt = c.makeReceipt(loaded.privateKey, { pin, received_at: c.formatTime(new Date()), seq: 1 });
  if (!c.verify(receipt, Buffer.from(publicKey, "hex"))) throw new Error("no");
} catch {
  fail("the new key did not check out; nothing was written");
}

const written = [];
try {
  fs.writeFileSync(out, seed, { flag: "wx", mode: 0o600 });
  written.push(out);
  fs.writeFileSync(files[1], statement, { flag: "wx", mode: 0o644 });
  written.push(files[1]);
  fs.writeFileSync(files[2],
    `contract key id: ${keyId}\npublic key: ${publicKey}\n` +
    "The seed file beside this note is the only secret. Keep it off every host but the witness's encrypted setting.\n",
    { flag: "wx", mode: 0o644 });
  written.push(files[2]);
} catch {
  for (const f of written) {
    try { fs.unlinkSync(f); } catch { /* left for the operator */ }
  }
  fail("the files could not all be written; none were kept");
}

process.stdout.write(
  `contract key id: ${keyId}\n` +
  `settings: WITNESS_CONTRACT_SEED (the seed file, as an encrypted setting), ` +
  `WITNESS_CONTRACT_KEY_ID (the key id above), WITNESS_CONTRACT_STATEMENT (${files[1]})\n`
);
