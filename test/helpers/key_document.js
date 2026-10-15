// test/helpers/key_document.js — key documents for the case tests since
// Design I (2026-10-12): entries with a role, the deployment a document is
// bundled in, and that document served from the public repository at the
// deployment's commit, as a reader fetches it (lib/_case_seal.js
// fetchNamedDocument, the mock's raw host).
//
// A deployment is named by the commit it was built from. Here that commit is
// derived from the document itself (sha1 of its json-c14n:v1 bytes, 40 hex),
// so one document is always served at one commit, and two documents never
// share one: a test that seals under a document and reads under another
// sees two commits, as it would on GitHub.
"use strict";

const crypto = require("crypto");
const S = require("../../lib/_case_seal.js");
const { canonicalBytes } = require("../../lib/_check_record.js");

const keyIdOf = (k) => k.verifier.split("+").slice(0, 2).join("+");

// A key document entry for a throwaway key ({signer, verifier} as
// lib/_checkpoint.js generateKey makes one). `role` absent is a case key.
// Since unit R-REV a status is active or revoked, and no entry carries a
// revocation date.
function entry(k, { role, status = "active", since = "2026-10-10", note = "a test key" } = {}) {
  const e = { key_id: keyIdOf(k), verifier: k.verifier, since, note, status };
  if (role !== undefined) e.role = role;
  return e;
}
const reconcileEntry = (k, over = {}) => entry(k, { role: "reconcile", note: "a test reconcile key", ...over });

// The committed document's prose with these entries.
function docWith(...entries) {
  return { ...S.PUBLISHED_KEYS, keys: entries };
}

const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
const commitOf = (doc) => crypto.createHash("sha1").update(canonicalBytes(doc)).digest("hex");

// `doc` served from the public repository at `commit` (commitOf(doc) by
// default) on the mock store `gh`, that commit on the repository's published
// branch (unit R-I: a reader holds a named commit to the branch,
// lib/_case_seal.js commitOnBranch), after every commit served before it.
// -> the commit.
function serve(gh, doc, commit = commitOf(doc)) {
  const text = `${JSON.stringify(doc, null, 2)}\n`;
  gh.seedRaw(S.KEY_DOCUMENT_REPO, commit, S.CASE_KEYS_FILE, text);
  // since unit R-WIDE (B2) the sealer and the online checker read the
  // document at the tip of the published branch: the document served last
  publishTip(gh, doc);
  // the commit carries no text of its own: the raw host serves only what
  // seedRaw planted, so a test can still take the file away
  gh.seedCommit(S.KEY_DOCUMENT_REPO, commit, S.CASE_KEYS_FILE);
  return commit;
}

// `doc` at the tip of the key document's published branch, as the raw host
// serves a branch name (lib/_case_seal.js carriedDocumentPublished; unit
// R-WIDE, B2). `branch` is the mock's branch name for the repository unless
// given.
function publishTip(gh, doc, branch = (gh.branches && gh.branches.get(S.KEY_DOCUMENT_REPO)) || "main") {
  gh.seedRaw(S.KEY_DOCUMENT_REPO, branch, S.CASE_KEYS_FILE, `${JSON.stringify(doc, null, 2)}\n`);
  // since unit R-WIDEf (F3-c) the tip is read through the contents API
  gh.seedAtBranch(S.KEY_DOCUMENT_REPO, branch, S.CASE_KEYS_FILE, `${JSON.stringify(doc, null, 2)}\n`);
}
// The tip taken away: a branch whose head has no key document.
function unpublishTip(gh, branch = (gh.branches && gh.branches.get(S.KEY_DOCUMENT_REPO)) || "main") {
  gh.raw.delete(`${S.KEY_DOCUMENT_REPO}@${branch}:${S.CASE_KEYS_FILE}`);
  gh.seedAtBranch(S.KEY_DOCUMENT_REPO, branch, S.CASE_KEYS_FILE, null);
}

// `doc` served at `commit` by the raw host but on no branch of the
// repository (a side branch's commit, or a fork's). -> the commit.
function serveOffBranch(gh, doc, commit = commitOf(doc)) {
  gh.seedRaw(S.KEY_DOCUMENT_REPO, commit, S.CASE_KEYS_FILE, `${JSON.stringify(doc, null, 2)}\n`);
  gh.seedSideCommit(S.KEY_DOCUMENT_REPO, commit);
  return commit;
}

// `doc` served at `commit` by the raw host, on a commit AHEAD of the
// published branch (not merged yet; unit R-WIDE, C14). -> the commit.
function serveAhead(gh, doc, commit = commitOf(doc)) {
  gh.seedRaw(S.KEY_DOCUMENT_REPO, commit, S.CASE_KEYS_FILE, `${JSON.stringify(doc, null, 2)}\n`);
  gh.seedAheadCommit(S.KEY_DOCUMENT_REPO, commit);
  return commit;
}

// The environment of a deployment built with `doc` bundled: `env` plus
// VERCEL_GIT_COMMIT_SHA, with `doc` served at that commit. A document that
// is not an object is no deployment's: `env` comes back unchanged.
function deployed(gh, env, doc) {
  if (doc === null || typeof doc !== "object") return env;
  return { ...env, [S.DEPLOY_COMMIT_ENV]: serve(gh, doc) };
}

// deployed(), unless `env` already names a deployment commit (a test that
// plants a commit of its own keeps it). Since unit R-SIG the withdrawal and
// the reference confirm the document they sign under, as the reveal does.
function deployedFor(gh, env, doc) {
  return env && env[S.DEPLOY_COMMIT_ENV] !== undefined ? env : deployed(gh, env || {}, doc);
}

// signed_under for a record built by hand (lib/_case_seal.js sealCase), with
// `doc` served at its commit: exactly {document_sha256, document_commit}
// since unit R-SIG.
function signedUnder(gh, doc) {
  return { document_sha256: sha256(canonicalBytes(doc)), document_commit: serve(gh, doc) };
}

module.exports = { keyIdOf, entry, reconcileEntry, docWith, commitOf, serve, publishTip, unpublishTip, serveOffBranch, serveAhead, deployed, deployedFor, signedUnder, sha256 };
