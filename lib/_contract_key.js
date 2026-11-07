// lib/_contract_key.js: the witness's contract key, the one key that signs
// contract receipts and the signed rows answer. It is a second key, apart
// from the log tree's signing key, with its own purpose.
//
// Settings (see README, "The join"):
//   WITNESS_CONTRACT_SEED       the key's 32 byte seed as 64 lower case hex
//                               (an encrypted setting; read here and
//                               nowhere else, never logged, never answered)
//   WITNESS_CONTRACT_KEY_ID     the key id, the SHA-256 of the public key
//   WITNESS_CONTRACT_STATEMENT  the key's signed witness_statement, as its
//                               canonical bytes
//
// load() checks all three on every call and throws a ContractError naming
// `key` or `statement` when any check fails. Every contract route then
// answers 503 naming that field, while the plain routes go on unchanged.
// So with no key set, the contract routes are off. Error text never holds
// a setting's value.
"use strict";

const c = require("./_contract.js");

function load(env = process.env) {
  const seed = env.WITNESS_CONTRACT_SEED;
  if (typeof seed !== "string" || !/^[0-9a-f]{64}$/.test(seed)) {
    throw new c.ContractError("key", "the witness has no contract key set up, so it signs nothing now; try again later");
  }
  let privateKey;
  try {
    privateKey = c.privateFromSeed(seed);
  } catch {
    throw new c.ContractError("key", "the witness's contract key cannot be loaded, so it signs nothing now");
  }
  const raw = c.publicRaw(privateKey);
  const keyId = c.keyId(raw);
  if (env.WITNESS_CONTRACT_KEY_ID !== keyId) {
    throw new c.ContractError("key", "the witness's contract key does not match its stated key id, so it signs nothing now");
  }
  const text = env.WITNESS_CONTRACT_STATEMENT;
  let statement;
  try {
    const bytes = Buffer.from(String(text === undefined ? "" : text), "utf8");
    statement = c.readStatement(c.parse(bytes, "statement"));
    if (!c.canonical(statement).equals(bytes)) throw new c.ContractError("statement", "not canonical");
  } catch {
    throw new c.ContractError("statement", "the witness's statement cannot be read as its signed witness_statement, so it signs nothing now");
  }
  if (statement.key_id !== keyId) {
    throw new c.ContractError("statement", "the witness's statement is for another key, so it signs nothing now");
  }
  return { privateKey, keyId, publicHex: raw.toString("hex"), statementBytes: c.canonical(statement) };
}

module.exports = { load };
