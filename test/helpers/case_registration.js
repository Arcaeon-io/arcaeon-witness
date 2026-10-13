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

// THE CLAIM (unit R-L4c, c4; lib/_case.js): a registration file is keyed by
// the fields a party supplies, registrations/<case_id>/<role>/<claim>.json.
// recordPath: the path of the file holding registration record `rec`.
// dirOf: role `role`'s folder of claim files. filesOf: the claim files a mock
// pins repository holds for the role. pathOf: the one claim file there (a
// path no file is at when there is none); a test that holds two claim files
// for a role names the one it means.
const recordPath = (rec) => C.registrationPath(rec.case_id, rec.role, C.claimSha256(rec));
// claimPath: the path a registration of {case_id, role, commitment_sha256}
// under `key` is written at, known before it is written.
function claimPath({ case_id, role, commitment_sha256 }, key = KEYS[role] || KEYS.a) {
  return recordPath({ case_id, role, commitment_sha256, ...keyFields({ case_id, role, commitment_sha256 }, key) });
}
const dirOf = (caseId, role) => `registrations/${caseId}/${role}`;
function filesOf(gh, caseId, role, repo = process.env.GITHUB_PIN_REPO) {
  const prefix = `${dirOf(caseId, role)}/`;
  return [...gh._repoMap(repo).keys()].filter((p) => p.startsWith(prefix)).sort();
}
function pathOf(gh, caseId, role, repo = process.env.GITHUB_PIN_REPO) {
  const files = filesOf(gh, caseId, role, repo);
  if (files.length > 1) throw new Error(`pathOf: role ${role} of case ${caseId.slice(0, 12)} has ${files.length} claim files; name the one meant`);
  return files.length ? files[0] : `${dirOf(caseId, role)}/no-claim-file.json`;
}

module.exports = { KEYS, keyIdOf, signedBody, keyFields, recordPath, claimPath, dirOf, filesOf, pathOf };
