// test/helpers/case_registration.js — a registration as ?op=case-commit takes
// it since red-team fix A (lib/_case.js, ONE KEY PER ROLE): {case_id, role,
// commitment_sha256, verifier, sig}, signed by the registering party's key.
// Each role has its own throwaway key, made when this file loads and written
// nowhere, so the two roles of every case a test registers through here are
// two distinct key ids unless the test hands one key to both.
"use strict";

const checkpoint = require("../../lib/_checkpoint.js");
const C = require("../../lib/_case.js");

const KEYS = Object.freeze({
  a: checkpoint.generateKey("party-a.example/case-registration"),
  b: checkpoint.generateKey("party-b.example/case-registration"),
});

const keyIdOf = (k) => k.verifier.split("+").slice(0, 2).join("+");

// The registration body for {case_id, role, commitment_sha256}, signed by
// `key` (the role's own test key by default; role a's for a role that is
// neither, so a test of a bad role still reaches the role check).
function signedBody({ case_id, role, commitment_sha256 }, key = KEYS[role] || KEYS.a) {
  return { case_id, role, commitment_sha256, verifier: key.verifier, sig: C.signRegistration({ case_id, role, commitment_sha256 }, key.signer) };
}

// The three fields a registration record takes from its key: {key_id,
// verifier, sig}. A record a test builds with C.registrationRecord spreads
// these in.
function keyFields({ case_id, role, commitment_sha256 }, key = KEYS[role] || KEYS.a) {
  return { key_id: keyIdOf(key), verifier: key.verifier, sig: C.signRegistration({ case_id, role, commitment_sha256 }, key.signer) };
}

module.exports = { KEYS, keyIdOf, signedBody, keyFields };
