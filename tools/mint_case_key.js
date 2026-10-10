#!/usr/bin/env node
// tools/mint_case_key.js — mint the case-signing key (lib/_case_seal.js,
// THE SIGNATURE and SIGNED_BY: WITNESS_CASE_SIGNER_KEY).
//
// Generates ONE Ed25519 key in lib/_checkpoint.js's signer-string shape, the
// shape lib/_case_seal.js loadCaseSigner reads:
//
//   PRIVATE+KEY+<name>+<8 hex>+<base64(0x01 || seed)>
//
// writes that PRIVATE half to --out and nowhere else, and prints to stdout
// ONLY the public entry for the case key document, committed at
// public/.well-known/arcaeon/case-signing-keys.json and served at
// /.well-known/arcaeon/case-signing-keys.json:
//
//   {"key_id", "verifier", "since", "note", "status": "active"}
//
// Nothing else goes to stdout. Progress goes to stderr. The private half is
// never printed, never passed on a command line, and never written anywhere
// but --out. The file is created exclusively (an existing file is refused and
// left untouched, so a key is never silently replaced) with mode 0600; on
// Windows, where the mode bits mean little, the tool also asks icacls to strip
// inherited access and grant only the current user, and says whether that
// worked.
//
// USAGE
//
//   node tools/mint_case_key.js --out <path ending in .signer.key> [--name <key name>] [--note <text>]
//
//   --out <path>     where the private half is written. Must end in ".signer.key"
//                    (the pattern .gitignore refuses to track, as
//                    tools/logtree_keygen.js requires). Keep it OUTSIDE any
//                    repository anyway; the ignore rule is a second fence.
//   --name <name>    the key name inside key_id and verifier. One token, no
//                    whitespace, no "+". Default: arcaeon.io/case-signing/<today UTC>.
//                    A new key is a new name; cases sealed under the old one
//                    keep naming it (the document's "rotation").
//   --note <text>    the entry's note. Default: one sentence naming the key's
//                    job and the day it was minted.
//   --help           this text
//
// EXIT CODES: 0 written, 1 usage, 2 refused (file exists, bad path, self-check failed).
//
// THE ENTRY AND THE SELF-CHECK. After writing, the tool re-reads the file and
// hands it to lib/_case_seal.js loadCaseSigner as WITNESS_CASE_SIGNER_KEY,
// beside two throwaway keys as the log and reconcile keys (it signs only when
// it can show the case key differs from both). Against the committed key
// document a new key is not listed yet, so loadCaseSigner answers
// key_unpublished with the key's public half (keyId, verifier), and the entry
// is keyDocumentEntry of that answer: the path lib/_case_seal.js keeps for
// exactly this. Then the tool refuses (exit 2, file removed, nothing on
// stdout) unless all of these hold:
//   - the entry, added to the keys array of the committed
//     public/.well-known/arcaeon/case-signing-keys.json, passes checkKeyDocument;
//   - loadCaseSigner, given that document, loads the key (PUBLICATION FAILS
//     CLOSED is satisfied), with the key_id and verifier printed;
//   - a signature made with the loaded key verifies under the printed verifier.
// The operator's real log and reconcile keys are never read.
//
// AFTER IT RUNS. Add the printed entry to the keys array of
// public/.well-known/arcaeon/case-signing-keys.json (and its `updated` date), and set
// WITNESS_CASE_SIGNER_KEY on the witness project's Vercel environment to the
// file's contents. The file IS the env value: no trailing newline.
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const checkpoint = require("../lib/_checkpoint.js");
const S = require("../lib/_case_seal.js");

const REQUIRED_SUFFIX = ".signer.key";

function helpText() {
  const src = fs.readFileSync(__filename, "utf8").split("\n");
  const out = [];
  for (const line of src.slice(1)) {
    if (!line.startsWith("//")) break;
    out.push(line.replace(/^\/\/ ?/, ""));
  }
  return out.join("\n");
}

function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${t} needs a value`);
      return argv[++i];
    };
    if (t === "--help" || t === "-h") a.help = true;
    else if (t === "--out") a.out = next();
    else if (t === "--name") a.name = next();
    else if (t === "--note") a.note = next();
    else throw new Error(`unknown argument ${t}`);
  }
  return a;
}

function restrictOnWindows(file) {
  if (process.platform !== "win32") return { tried: false };
  const user = process.env.USERNAME;
  if (!user) return { tried: true, ok: false, detail: "USERNAME unset" };
  const r = spawnSync("icacls", [file, "/inheritance:r", "/grant:r", `${user}:F`], { encoding: "utf8" });
  return { tried: true, ok: r.status === 0, detail: r.status === 0 ? `icacls: only ${user}` : String(r.stderr || r.stdout).trim().slice(0, 200) };
}

// THE ENTRY AND THE SELF-CHECK, above. -> {entry} or {why} (never the key).
function entryFor(signerStr, { since, note, expect }) {
  const env = {
    [S.CASE_SIGNER_ENV]: signerStr,
    WITNESS_LOG_SIGNER_KEY: checkpoint.generateKey("mint-case-key/throwaway-log").signer,
    WITNESS_RECONCILE_SIGNER_KEY: checkpoint.generateKey("mint-case-key/throwaway-reconcile").signer,
  };
  const doc = S.PUBLISHED_KEYS;
  const committed = S.checkKeyDocument(doc);
  if (!committed.ok) return { why: `the committed key document does not read (${committed.reason} at ${committed.at})` };
  const pending = S.loadCaseSigner(env);
  if (pending.code !== "key_unpublished") return { why: `loadCaseSigner did not answer key_unpublished for a new key (${pending.code || "ok"})` };
  if (pending.keyId !== expect.keyId || pending.verifier !== expect.verifier) return { why: "loadCaseSigner resolved another key id or verifier" };
  const entry = S.keyDocumentEntry(pending, { since, note });
  const withKey = { ...doc, keys: [...committed.keys, entry] };
  const c = S.checkKeyDocument(withKey);
  if (!c.ok) return { why: `the entry does not pass checkKeyDocument in the committed document (${c.reason} at ${c.at})` };
  const signer = S.loadCaseSigner(env, { keyDocument: withKey });
  if (!signer.ok) return { why: `loadCaseSigner refused the key with its entry published (${signer.code})` };
  if (signer.keyId !== entry.key_id || signer.verifier !== entry.verifier) return { why: "loadCaseSigner, published, resolved another key id or verifier" };
  const vk = checkpoint.parseVerifierKey(entry.verifier);
  const msg = crypto.randomBytes(32);
  if (!vk.ok || !crypto.verify(null, msg, vk.publicKey, crypto.sign(null, msg, signer.privateKey))) {
    return { why: "a signature by the key does not verify under the verifier" };
  }
  return { entry };
}

function main(argv) {
  let a;
  try {
    a = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`usage: ${e.message}\n`);
    return 1;
  }
  if (a.help) {
    process.stdout.write(helpText() + "\n");
    return 0;
  }
  if (!a.out) {
    process.stderr.write("usage: --out <path ending in .signer.key> is required (--help for the rest)\n");
    return 1;
  }
  const since = new Date().toISOString().slice(0, 10);
  const name = a.name === undefined ? `arcaeon.io/case-signing/${since}` : a.name;
  const note = a.note === undefined ? `Signs sealed cases of arcaeon-case/1 (${S.CASE_SIGNER_ENV}); minted ${since}.` : a.note;
  if (typeof note !== "string" || !note.trim()) {
    process.stderr.write("usage: --note must not be empty (the document requires a note on every entry)\n");
    return 1;
  }
  const out = path.resolve(a.out);
  if (!out.endsWith(REQUIRED_SUFFIX)) {
    process.stderr.write(`REFUSED: --out must end in "${REQUIRED_SUFFIX}" so the .gitignore rule covers it\n`);
    return 2;
  }
  let pair;
  try {
    pair = checkpoint.generateKey(name);
  } catch (e) {
    process.stderr.write(`usage: ${e.message} (one token, no whitespace, no "+")\n`);
    return 1;
  }
  const pk = checkpoint.parseVerifierKey(pair.verifier);
  const expect = { keyId: `${pk.name}+${pk.hash}`, verifier: pair.verifier };
  fs.mkdirSync(path.dirname(out), { recursive: true });
  try {
    fs.writeFileSync(out, pair.signer, { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch (e) {
    process.stderr.write(`REFUSED: ${out}: ${e.code === "EEXIST" ? "already exists; a key is never replaced in place (rotation = a new name and a new file)" : e.message}\n`);
    return 2;
  }
  process.stderr.write(`private half written to ${out} (create-only, mode 0600)\n`);
  const back = fs.readFileSync(out, "utf8");
  let got;
  try {
    got = back === pair.signer ? entryFor(back, { since, note, expect }) : { why: "the file does not read back as written" };
  } catch (e) {
    got = { why: `the self-check threw (${e && e.name})` };
  }
  if (got.why) {
    fs.rmSync(out, { force: true });
    process.stderr.write(`REFUSED: self-check failed: ${got.why}; file removed\n`);
    return 2;
  }
  const entry = got.entry;
  const acl = restrictOnWindows(out);
  process.stderr.write(`self-check: the entry passes checkKeyDocument in the committed document; with it published, loadCaseSigner loads ${entry.key_id}; it signs what the verifier accepts\n`);
  process.stderr.write(`windows acl: ${acl.tried ? (acl.ok ? "restricted" : `NOT restricted: ${acl.detail}`) : "n/a (mode 0600)"}\n`);
  process.stderr.write(`next: add the entry on stdout to the keys array of ${S.CASE_KEYS_FILE}; set ${S.CASE_SIGNER_ENV} from the file\n`);
  process.stdout.write(JSON.stringify(entry, null, 2) + "\n");
  return 0;
}

if (require.main === module) process.exit(main(process.argv.slice(2)));
module.exports = { main, REQUIRED_SUFFIX };
