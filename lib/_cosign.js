// _cosign.js: ask outside witnesses to cosign this log's checkpoint, check
// what they send back, and keep the good lines beside the checkpoint.
//
// THE REQUEST (the public witness protocol, c2sp.org/tlog-witness):
//
//   POST <submission prefix>/add-checkpoint
//
//   old <size the witness last saw>\n
//   <one base64 consistency proof hash per line>\n ...
//   \n
//   <the signed checkpoint note>
//
// "old" is our best guess of the size the witness last cosigned (the
// previous checkpoint's size, or 0). A witness that holds another size
// answers 409 with that size as "text/x.tlog.size"; we rebuild the proof
// from it and send again, at most CONFLICT_RETRIES times.
//
// THE ANSWER: 200 with one or more signature lines. A cosignature line is
//
//   <U+2014 SPACE> <witness name> <base64( key_id[4] || time[8, big endian] || ed25519 sig[64] )>
//
// and the signature is Ed25519 over
//
//   "cosignature/v1\ntime <time>\n" || <the checkpoint note text>
//
// (c2sp.org/tlog-cosignature, key type 0x04). key_id is the first 4 bytes
// of SHA-256( name || "\n" || 0x04 || 32 byte public key ). Lines under any
// other key (another witness, or the same witness's ML-DSA key) are passed
// over, as the note format says; a line under the configured key that does
// not verify refuses the whole answer, and nothing from it is kept.
//
// Other answers: 404 the witness does not know this log (not listed yet),
// 403 the log signature did not verify for it, 422 the proof did not, 400 a
// bad request. Each is a logged result with a field, never an exception.
// A network failure is "unreachable". Nothing here is ever fatal to the
// checkpoint: the caller writes the checkpoint first and cosigning after.
//
// STORAGE: <date>.cosignatures next to <date>.txt, one verified line per
// witness key. Add only: a line already there is never rewritten, a key
// already there is not added twice, and the checkpoint file is never opened
// for writing.
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const { parseCheckpoint } = require("./_checkpoint.js");

const SIG_PREFIX = "\u2014 "; // signed note format byte, then a space
const ALG_COSIGNATURE_ED25519 = 0x04;
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const SIZE_TYPE = "text/x.tlog.size";
const CONFLICT_RETRIES = 3;
const FUTURE_SECONDS = 600;
const TIMEOUT_MS = 20000;
const MAX_ANSWER = 64 * 1024;

function cosignKeyId(name, pub) {
  return crypto
    .createHash("sha256")
    .update(Buffer.concat([Buffer.from(name, "utf8"), Buffer.from("\n"), Buffer.from([ALG_COSIGNATURE_ED25519]), pub]))
    .digest()
    .subarray(0, 4);
}

// "<name>+<8 hex>+<base64(0x04 || pub)>". The name may not hold "+", so
// split at the first two only (the base64 tail may hold "+").
function parseWitnessVkey(str) {
  if (typeof str !== "string") return { ok: false, field: "vkey", reason: "not a string" };
  const a = str.indexOf("+");
  const b = a < 0 ? -1 : str.indexOf("+", a + 1);
  if (a < 1 || b < 0) return { ok: false, field: "vkey", reason: "not name+hash+key" };
  const name = str.slice(0, a);
  const hashHex = str.slice(a + 1, b);
  const b64 = str.slice(b + 1);
  if (!/^[!-*,-~]+$/.test(name) || !/^[0-9a-f]{8}$/.test(hashHex)) return { ok: false, field: "vkey", reason: "bad name or key hash" };
  const raw = Buffer.from(b64, "base64");
  if (raw.toString("base64") !== b64 || raw.length !== 33) return { ok: false, field: "vkey", reason: "key is not 33 bytes of standard base64" };
  if (raw[0] !== ALG_COSIGNATURE_ED25519) return { ok: false, field: "vkey", reason: `key type 0x${raw[0].toString(16).padStart(2, "0")} is not 0x04 (Ed25519 cosignature)` };
  const pub = raw.subarray(1);
  if (cosignKeyId(name, pub).toString("hex") !== hashHex) return { ok: false, field: "vkey", reason: "key hash does not match name and key" };
  return { ok: true, name, id: hashHex, pub, publicKey: crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, pub]), format: "der", type: "spki" }) };
}

function localHost(u) {
  return u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
}

// The witness list file: {"witnesses": [{"name", "url", "vkey", "source"?, "note"?}]}.
// Refused whole, naming the field, if any entry cannot be used.
function loadWitnessConfig(text) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return { ok: false, field: "config", reason: "not JSON" };
  }
  if (!doc || !Array.isArray(doc.witnesses)) return { ok: false, field: "witnesses", reason: "missing list" };
  const out = [];
  const seen = new Set();
  for (const [i, w] of doc.witnesses.entries()) {
    const at = `witnesses[${i}]`;
    if (!w || typeof w !== "object") return { ok: false, field: at, reason: "not an object" };
    const k = parseWitnessVkey(w.vkey);
    if (!k.ok) return { ok: false, field: `${at}.${k.field}`, reason: k.reason };
    if (w.name !== k.name) return { ok: false, field: `${at}.name`, reason: "does not equal the vkey's name" };
    let u;
    try {
      u = new URL(w.url);
    } catch {
      return { ok: false, field: `${at}.url`, reason: "not a URL" };
    }
    if (!(u.protocol === "https:" || (u.protocol === "http:" && localHost(u))) || u.search || u.hash) {
      return { ok: false, field: `${at}.url`, reason: "must be https (http only for a local test witness), with no query" };
    }
    if (seen.has(`${k.name}+${k.id}`)) return { ok: false, field: `${at}.vkey`, reason: "listed twice" };
    seen.add(`${k.name}+${k.id}`);
    out.push({ name: k.name, url: w.url.replace(/\/+$/, ""), key: k });
  }
  return { ok: true, witnesses: out };
}

function requestBody(old, proof, signedNote) {
  return `old ${old}\n${proof.map((h) => Buffer.from(h).toString("base64") + "\n").join("")}\n${signedNote}`;
}

function cosignatureMessage(time, noteText) {
  return Buffer.concat([Buffer.from(`cosignature/v1\ntime ${time}\n`, "utf8"), Buffer.from(noteText, "utf8")]);
}

// Pick and check this witness's line(s) from a 200 answer body.
function checkAnswer(body, noteText, w, now) {
  if (!body.endsWith("\n")) return { ok: false, field: "cosignature", reason: "answer is not lines ending in a newline" };
  for (const line of body.slice(0, -1).split("\n")) {
    if (!line.startsWith(SIG_PREFIX)) return { ok: false, field: "cosignature", reason: "a line is not a signature line" };
    const parts = line.slice(SIG_PREFIX.length).split(" ");
    if (parts.length !== 2) return { ok: false, field: "cosignature", reason: "a line is not a signature line" };
    const blob = Buffer.from(parts[1], "base64");
    if (blob.toString("base64") !== parts[1] || blob.length < 4) return { ok: false, field: "cosignature", reason: "a line's signature is not base64" };
    if (parts[0] !== w.name || blob.subarray(0, 4).toString("hex") !== w.key.id) continue; // another key: passed over
    if (blob.length !== 4 + 8 + 64) return { ok: false, field: "cosignature", reason: "line under the configured key is not 76 bytes" };
    const time = blob.readBigUInt64BE(4);
    if (time > BigInt(now + FUTURE_SECONDS)) return { ok: false, field: "cosignature", reason: "cosignature time is more than ten minutes ahead of this clock" };
    let good = false;
    try {
      good = crypto.verify(null, cosignatureMessage(time.toString(), noteText), w.key.publicKey, blob.subarray(12));
    } catch {
      good = false;
    }
    if (!good) return { ok: false, field: "cosignature", reason: "line under the configured key does not verify over this checkpoint" };
    return { ok: true, line, time: Number(time) };
  }
  return { ok: false, field: "cosignature", reason: "answer holds no line under the configured key" };
}

// Default transport: one POST, no redirects, bounded answer. Resolves to
// {status, type, body}; rejects only when no answer came at all.
function httpPost(url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request(u, { method: "POST", timeout: TIMEOUT_MS, headers: { "content-type": "text/plain; charset=utf-8", "content-length": Buffer.byteLength(body) } }, (res) => {
      const chunks = [];
      let n = 0;
      res.on("data", (c) => {
        n += c.length;
        if (n > MAX_ANSWER) req.destroy(new Error("answer too large"));
        else chunks.push(c);
      });
      res.on("end", () => resolve({ status: res.statusCode, type: String(res.headers["content-type"] || ""), body: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error("timed out")));
    req.on("error", reject);
    req.end(body);
  });
}

const REFUSALS = { 400: "old", 403: "signature", 422: "proof" };

// One witness. Never throws: returns {witness, result, field, reason, ...}.
// result is one of: cosigned, refused, not_listed, unreachable, unavailable, would_send.
async function cosignOne({ w, signedNote, noteText, size, prevSize, proofFrom, post, now, send }) {
  const out = { witness: `${w.name}+${w.key.id}`, url: `${w.url}/add-checkpoint`, size, result: "refused", field: null, reason: null };
  let old = prevSize;
  try {
    if (!send) {
      const body = requestBody(old, proofFrom(old), signedNote);
      return { ...out, result: "would_send", old, body_bytes: Buffer.byteLength(body) };
    }
    for (let conflicts = 0; ; conflicts++) {
      let ans;
      try {
        ans = await post(out.url, requestBody(old, proofFrom(old), signedNote));
      } catch (e) {
        return { ...out, result: "unreachable", field: "url", reason: `no answer: ${e && e.message ? e.message : e}` };
      }
      const said = String(ans.body || "").slice(0, 200).replace(/[^ -~]/g, "?").trim() || "no reason";
      if (ans.status === 200) {
        const c = checkAnswer(String(ans.body), noteText, w, now);
        if (!c.ok) return { ...out, field: c.field, reason: c.reason };
        return { ...out, result: "cosigned", old, line: c.line, time: c.time };
      }
      if (ans.status === 409) {
        const t = String(ans.body);
        if (ans.type.split(";")[0].trim() !== SIZE_TYPE || !/^(0|[1-9][0-9]{0,15})\n$/.test(t)) return { ...out, field: "old", reason: "409 without a size" };
        const theirs = Number(t.slice(0, -1));
        if (theirs > size) return { ...out, field: "old", reason: `witness holds size ${theirs}, past this checkpoint's ${size}: it has seen a checkpoint of this log we did not publish here` };
        if (theirs === old) return { ...out, field: "old", reason: `409 naming the very size sent, ${old}` };
        if (conflicts >= CONFLICT_RETRIES) return { ...out, result: "unavailable", field: "old", reason: `still 409 after ${CONFLICT_RETRIES} retries` };
        old = theirs;
        continue;
      }
      if (ans.status === 404) return { ...out, result: "not_listed", field: "origin", reason: `404, the witness does not know this log: ${said}` };
      if (REFUSALS[ans.status]) return { ...out, field: REFUSALS[ans.status], reason: `${ans.status}: ${said}` };
      return { ...out, result: "unavailable", field: "witness", reason: `${ans.status}: ${said}` };
    }
  } catch (e) {
    return { ...out, field: "proof", reason: `could not build the request: ${e && e.message ? e.message : e}` };
  }
}

// Keep verified lines beside the checkpoint, add only. Returns the lines added.
function appendCosignatures(file, lines) {
  let have = "";
  try {
    have = fs.readFileSync(file, "utf8");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  const haveKeys = new Set(
    have
      .split("\n")
      .filter(Boolean)
      .map((l) => {
        const [name, b64] = l.slice(SIG_PREFIX.length).split(" ");
        return `${name}+${Buffer.from(b64 || "", "base64").subarray(0, 4).toString("hex")}`;
      })
  );
  const add = [];
  for (const l of lines) {
    const [name, b64] = l.slice(SIG_PREFIX.length).split(" ");
    const k = `${name}+${Buffer.from(b64, "base64").subarray(0, 4).toString("hex")}`;
    if (haveKeys.has(k)) continue;
    haveKeys.add(k);
    add.push(l);
  }
  if (add.length) {
    if (have && !have.endsWith("\n")) throw new Error(`${file} does not end in a newline; refusing to append to it`);
    fs.appendFileSync(file, add.map((l) => l + "\n").join(""), "utf8");
  }
  return add;
}

// The step. signedNote must carry the log's own signature (a witness checks
// it). proofFrom(old) returns the consistency proof hashes old -> size.
async function cosignCheckpoint({ signedNote, witnesses, prevSize = 0, proofFrom, post = httpPost, now = Math.floor(Date.now() / 1000), send = false, outFile = null }) {
  const p = parseCheckpoint(signedNote);
  if (!p.ok) return { ok: false, field: "checkpoint", reason: p.reason, results: [] };
  if (p.signatures.length === 0) return { ok: false, field: "checkpoint", reason: "unsigned; a witness only cosigns a note the log signed", results: [] };
  const results = [];
  for (const w of witnesses) {
    results.push(await cosignOne({ w, signedNote, noteText: p.text, size: p.size, prevSize, proofFrom, post, now, send }));
  }
  let added = [];
  let storeError = null;
  const lines = results.filter((r) => r.result === "cosigned").map((r) => r.line);
  if (send && outFile && lines.length) {
    try {
      added = appendCosignatures(outFile, lines);
    } catch (e) {
      storeError = e.message;
    }
  }
  return { ok: storeError === null, field: storeError ? "cosignatures" : null, reason: storeError, results, added };
}

module.exports = {
  SIZE_TYPE,
  cosignKeyId,
  parseWitnessVkey,
  loadWitnessConfig,
  requestBody,
  cosignatureMessage,
  checkAnswer,
  appendCosignatures,
  cosignCheckpoint,
  httpPost,
};
