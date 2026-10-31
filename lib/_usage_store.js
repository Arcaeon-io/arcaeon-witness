// _usage_store.js — where the private, per-pin bookkeeping lives: the meter's
// monthly usage file, the open Merkle batch, and the single-sealer claim.
// Underscore prefix = not routed as a serverless function.
//
// WITNESS_METER_OFF_GITHUB.md is the design. In short: these three documents
// used to be files in the private usage repo, written through the GitHub
// contents API, so every pin cost two private commits on top of its public
// ones. This file gives the same read and conditional-write contract over a
// second backend, a table in the Postgres database the account path already
// uses (Supabase, reached through PostgREST with the service role key).
//
// Selected per call by WITNESS_USAGE_STORE (read at call time, not at load):
//   unset | "github"   the private usage repo, exactly as before. Default.
//   "postgres"         the usage_docs table (supabase/migrations/
//                      2026_10_31_usage_docs.sql). Needs SUPABASE_URL and
//                      SUPABASE_SERVICE_ROLE_KEY, the same two the account
//                      store reads. Any other value is refused, never guessed.
//
// THE CONTRACT BOTH BACKENDS KEEP (the callers depend on every line of it):
//
//   read(path)  -> {json, sha} | null
//       null means the document is verifiably absent. Anything the store
//       cannot answer THROWS with err.unreadable = true; it never reads as
//       absent, because absent is "nothing used this month" to the meter.
//   write(path, obj, sha, message)
//       sha omitted   -> create if absent. Lost the race: err.conflict.
//       sha supplied  -> update if unchanged. Lost the race: err.conflict.
//       Any other failure throws without err.conflict.
//
// In Postgres, `sha` is the row's version counter written as "pg:<n>".
// Create is one INSERT on the primary key (a duplicate is the lost race).
// Update is one UPDATE ... WHERE path = p AND version = n, returning the row:
// Postgres locks the row, so of two updates carrying the same n exactly one
// matches, and the loser sees zero rows. That is the same arbiter the GitHub
// sha gave, with read your writes across instances, which the contents API
// never had.
//
// The service role key goes in request headers only. It never appears in a
// thrown message, a return value or a log line. `path` is redacted from thrown
// messages too: for the meter it is usage/<sha256 of the caller key>/<month>,
// and api/pin.js puts err.message into a 502 body.
//
// Not moved, on purpose: lib/_balance.js (credits) and lib/_keys.js (issued
// keys) still write the private repo. Credits are billing, owned elsewhere.

"use strict";

function backend(env = process.env) {
  const v = String(env.WITNESS_USAGE_STORE || "").trim().toLowerCase();
  if (v === "" || v === "github") return "github";
  if (v === "postgres") return "postgres";
  const err = new Error("usage store: WITNESS_USAGE_STORE must be github or postgres");
  err.unreadable = true;
  err.misconfigured = true;
  throw err;
}

// -------------------------------------------------------------- postgres

const TABLE = "usage_docs";
const VERSION_RE = /^pg:([1-9][0-9]{0,15})$/;

function pgConfig(tag) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    // Fails closed: with the flag on and no database, the meter answers 502
    // and the pending leaf is logged as missed. Nothing falls back to GitHub
    // silently, because a split store would count the same month twice.
    const err = new Error(`${tag} store not configured (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)`);
    err.unreadable = true;
    err.misconfigured = true;
    throw err;
  }
  return { base: String(url).replace(/\/+$/, "") + "/rest/v1", key };
}

async function pgCall(tag, what, method, query, { body, prefer } = {}) {
  const { base, key } = pgConfig(tag);
  const headers = {
    apikey: key,
    authorization: `Bearer ${key}`,
    "content-type": "application/json",
    accept: "application/json",
  };
  if (prefer) headers.prefer = prefer;
  let res;
  try {
    res = await fetch(`${base}/${TABLE}${query}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (_e) {
    const err = new Error(`${tag} store unreachable (${what})`);
    err.unreadable = true;
    throw err;
  }
  const text = await res.text().catch(() => "");
  let json = null;
  if (text) {
    try { json = JSON.parse(text); } catch (_e) { json = null; }
  }
  return { res, json };
}

const eq = (v) => "eq." + encodeURIComponent(String(v));

async function pgRead(path, tag) {
  const { res, json } = await pgCall(tag, "read", "GET",
    `?path=${eq(path)}&select=doc,version`);
  if (!res.ok || !Array.isArray(json)) {
    console.error(`[${tag}] pg read -> ${res.status}`);
    const err = new Error(`${tag} store read failed (${res.status})`);
    err.unreadable = true;
    throw err;
  }
  if (json.length === 0) return null;
  const row = json[0];
  if (!row || !Number.isSafeInteger(row.version) || row.version < 1) {
    // A row we cannot version is a row we cannot write over safely.
    const err = new Error(`${tag} store read failed (row has no usable version)`);
    err.unreadable = true;
    throw err;
  }
  return { json: row.doc, sha: `pg:${row.version}` };
}

async function pgWrite(path, obj, sha, message, tag) {
  // The same body the GitHub file held. `message` is kept as the row's note
  // of its last change, the nearest thing to a commit message.
  const doc = JSON.parse(JSON.stringify(obj));
  const now = new Date().toISOString();
  if (!sha) {
    const { res, json } = await pgCall(tag, "create", "POST", "", {
      body: { path, doc, version: 1, note: String(message || ""), updated_at: now },
      prefer: "return=minimal",
    });
    if (res.ok) return { json: doc, sha: "pg:1" };
    // 23505 unique_violation: somebody created this path first.
    if (res.status === 409 || (json && json.code === "23505")) {
      console.error(`[${tag}] pg create ${path} -> conflict`);
      const err = new Error(`${tag} store write conflict (concurrent writer)`);
      err.conflict = true;
      throw err;
    }
    console.error(`[${tag}] pg create ${path} -> ${res.status}`);
    throw new Error(`${tag} store write failed (${res.status})`);
  }
  const m = VERSION_RE.exec(String(sha));
  if (!m) {
    // A GitHub sha handed to the Postgres store means a document read from one
    // backend is being written to the other. Refuse; never write it blind.
    throw new Error(`${tag} store write failed (version is not a postgres version)`);
  }
  const version = Number(m[1]);
  const { res, json } = await pgCall(tag, "update", "PATCH",
    `?path=${eq(path)}&version=${eq(version)}`, {
      body: { doc, version: version + 1, note: String(message || ""), updated_at: now },
      prefer: "return=representation",
    });
  if (!res.ok || !Array.isArray(json)) {
    console.error(`[${tag}] pg update ${path} -> ${res.status}`);
    throw new Error(`${tag} store write failed (${res.status})`);
  }
  if (json.length === 0) {
    const err = new Error(`${tag} store write conflict (concurrent writer)`);
    err.conflict = true;
    throw err;
  }
  return { json: doc, sha: `pg:${version + 1}` };
}

// ------------------------------------------------------------- the verbs

// `tag` names the caller in log lines and messages ("meter", "pending"), so
// each caller's errors read as they did before. The GitHub half of the
// contract stays in the callers (lib/_meter.js, lib/_pending.js), unchanged;
// they call these only when backend() says "postgres".
// legacyRead, when given, is the caller's own GitHub read; see readAdopting.
async function read(path, tag = "usage", legacyRead = null) {
  return legacyRead ? readAdopting(path, tag, legacyRead) : pgRead(path, tag);
}

async function write(path, obj, sha, message, tag = "usage") {
  return pgWrite(path, obj, sha, message, tag);
}

// The cutover. When the flag is first turned on, the table is empty while the
// private repo still holds this month's counts and maybe an open batch. A
// plain read would answer "absent", which to the meter is "nothing used this
// month": every key would get its free pins back. So a Postgres miss falls
// back ONCE to the GitHub document (a read, never a write there) and adopts
// it into the table with a create. Two instances adopting at once: one create
// wins, the loser re-reads the winner's row. If the GitHub read fails, this
// throws unreadable, so the meter refuses rather than counting from zero.
// After the month turns, the GitHub file for the new month does not exist and
// the fallback costs one 404 per key per month.
async function readAdopting(path, tag, legacyRead) {
  const cur = await pgRead(path, tag);
  if (cur) return cur;
  let old;
  try {
    old = await legacyRead(path);
  } catch (e) {
    const err = new Error(`${tag} store read failed (cutover read of the old store)`);
    err.unreadable = true;
    throw err;
  }
  if (!old) return null;
  try {
    return await pgWrite(path, old.json, undefined, `adopted from the private usage repo at ${old.sha}`, tag);
  } catch (e) {
    if (!e.conflict) throw e;
    const won = await pgRead(path, tag);
    if (won) return won;
    throw e;
  }
}

function onPostgres() {
  return backend() === "postgres";
}

module.exports = { read, write, backend, onPostgres, TABLE };
