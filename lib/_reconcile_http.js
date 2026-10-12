// _reconcile_http.js — POST /api/reconcile and GET /reconcile, co-hosted on
// api/verify.js. Underscore prefix = not routed as a serverless function.
//
// WHY IT RIDES ON verify.js: arcaeon-witness/api/ is at the Vercel Hobby
// 12-function cap (see api/verify.js's own header and lib/_stamp.js), so this
// cannot have an api/ file of its own. vercel.json rewrites
//   /api/reconcile -> /api/verify?op=reconcile        (POST, the verdict)
//   /reconcile     -> /api/verify?op=reconcile-page   (GET, the static page)
// and api/verify.js dispatches both before its GET-only CORS helper, the same
// way it already dispatches ?op=stamp. It shares nothing with verify's logic:
// no store reads, no bearer key, no writes of any kind.
//
// THE REQUEST. Two tapes in the exact format arcaeon-ledger reconcile reads
// (arcaeon-tape/1 JSONL, one chained row per tools/call): the agent side's
// tape (the adapter's --tape) and the tool side's tape (arcaeon-receipt's
// call_proxy --tape, or the adapter with --side tool). Either as
//   application/json      {"agent_tape": "<text>", "tool_tape": "<text>"}
//                         or {"agent_tape_b64": "...", "tool_tape_b64": "..."}
//                         (base64 when the exact bytes matter: a BOM, CRLF,
//                         invalid UTF-8, anything a JSON string cannot carry)
//   multipart/form-data   parts named agent_tape and tool_tape (files or text)
// The field names say which tape is which for the reader; reconcile itself,
// like reconcile.py, reads each tape's side from its own rows and does not
// care which slot a tape came in. `agent_tape` is reconcile's first argument.
//
// NO SIGNER, NO RECEIPT (red-team fix B; lib/_reconcile_receipt.js). With
// WITNESS_RECONCILE_SIGNER_KEY absent or unreadable, or (Design I,
// lib/_case_seal.js SIGNED UNDER ONE DOCUMENT) not an active reconcile entry
// of the key document this deployment carries, the answer is 503
// `signer_unavailable` with no verdict and no receipt, and the tapes are
// not compared: this service never hands out an unsigned receipt, nor one
// signed by a key it has not published.
//
// THE ANSWER. 200 with {ok, verdict, receipt, service_limits}: `verdict` is
// key for key the dict `arcaeon-ledger reconcile` prints (MATCHED n of n /
// MISSING at k / ALTERED at k / COULD NOT LOOK, the counts, every finding, the
// first divergence as the headline, the limits), and `receipt` is the signed
// receipt of lib/_reconcile_receipt.js. COULD NOT LOOK is an answer, so it is a
// 200 too. A request the service cannot read is a 4xx with a typed
// `error_code`, never a 500 and never a verdict.
//
// NOTHING IS KEPT. The tapes are read into memory, compared, digested, and
// dropped with the request. No store call, no log line carries their bytes.
//
// SHARED WITH THE CASE REVEAL (2026-10-10, case protocol item 2a). The joint
// reveal (lib/_case_http.js, ?op=case-reveal) takes its two tapes "exactly as
// the reconcile endpoint accepts them" and runs "the existing reconcile ...
// exactly as ?op=reconcile does". So the three steps it needs are exported
// from here rather than copied there: readFields (the body, JSON or
// multipart, with this file's caps and refusals), tapeFrom (one tape out of
// its text or base64 field, capped) and compare (the port, then the signed
// receipt, the call handleReconcile makes). handleReconcile is built from
// the same three, and answers exactly as it did before they were split out.

"use strict";

const T = require("./_reconcile_tapes.js");
const receipts = require("./_reconcile_receipt.js");
const SEAL = require("./_case_seal.js"); // loadReconcileSigner: the key document's reconcile entry
const ratelimit = require("./_ratelimit.js");
const page = require("./_reconcile_page.js");

const TAPE_MAX_BYTES = 1000000;   // per tape, decoded
const BODY_MAX_BYTES = 3000000;   // the whole request (two base64 tapes fit); Vercel's own ceiling is 4.5 MB
const MAX_PARTS = 8;

const FIELDS = Object.freeze(["agent_tape", "tool_tape", "agent_tape_b64", "tool_tape_b64"]);
const PIN_FIELDS = Object.freeze(["pin", "pins", "pin_b64"]);

const SERVICE_LIMITS = Object.freeze([
  "This service saw only the two tapes submitted with this request. It did not see the calls, the agent, or the tool.",
  "An operator-owned tape is not an outside witness. If one party wrote both tapes, MATCHED is a consistency check between two of its own recorders, not independent evidence.",
  "No witness pin was checked. Two tapes cut or rewritten in agreement still match; run `arcaeon-ledger reconcile A B --pin P` to hold them against the witness's counter.",
  "Neither tape is stored. The receipt keeps their sha256 digests, not their contents.",
]);

class Refusal extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

function refuse(res, e) {
  res.setHeader("cache-control", "no-store");
  return res.status(e.status).json({ ok: false, error_code: e.code, error: e.message, ...e.extra });
}

function mediaType(req) {
  const ct = String((req.headers && req.headers["content-type"]) || "");
  return { full: ct, type: ct.split(";")[0].trim().toLowerCase() };
}

// The request body, whatever shape the platform handed it over in. Vercel's
// default body parser has already turned JSON into an object (and throws on a
// malformed one when req.body is first touched); anything it does not parse is
// read from the stream here, capped.
async function readBody(req) {
  const declared = Number(req.headers && req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > BODY_MAX_BYTES) {
    throw new Refusal(413, "too_large", `request body is ${declared} bytes; the cap is ${BODY_MAX_BYTES}`,
      { cap_bytes: BODY_MAX_BYTES });
  }
  let body;
  try {
    body = req.body;
  } catch (e) {
    throw new Refusal(400, "malformed_json", "the request body is not valid JSON");
  }
  if (Buffer.isBuffer(body)) return { raw: body };
  if (typeof body === "string") return { raw: Buffer.from(body, "utf-8") };
  if (body && typeof body === "object") return { parsed: body };
  if (typeof req.on !== "function") return { raw: Buffer.alloc(0) };
  const raw = await new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    let done = false;
    req.on("data", (c) => {
      if (done) return;
      n += c.length;
      if (n > BODY_MAX_BYTES) {
        done = true;
        reject(new Refusal(413, "too_large", `request body exceeds the cap of ${BODY_MAX_BYTES} bytes`,
          { cap_bytes: BODY_MAX_BYTES }));
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => { if (!done) { done = true; resolve(Buffer.concat(chunks)); } });
    req.on("error", () => { if (!done) { done = true; reject(new Refusal(400, "unreadable_body", "the request body could not be read")); } });
  });
  return { raw };
}

function parseJsonBody(raw) {
  if (raw.length > BODY_MAX_BYTES) {
    throw new Refusal(413, "too_large", `request body exceeds the cap of ${BODY_MAX_BYTES} bytes`, { cap_bytes: BODY_MAX_BYTES });
  }
  try {
    return JSON.parse(raw.toString("utf-8"));
  } catch (e) {
    throw new Refusal(400, "malformed_json", "the request body is not valid JSON");
  }
}

// multipart/form-data, the small subset a browser or curl -F sends.
function parseMultipart(raw, contentType) {
  const m = /boundary=(?:"([^"]{1,200})"|([^;\s]{1,200}))/i.exec(contentType);
  if (!m) throw new Refusal(400, "malformed_multipart", "multipart body without a boundary");
  const boundary = Buffer.from(`--${m[1] || m[2]}`, "latin1");
  const fields = {};
  let pos = raw.indexOf(boundary);
  if (pos < 0) throw new Refusal(400, "malformed_multipart", "multipart body does not contain its boundary");
  let parts = 0;
  for (;;) {
    pos += boundary.length;
    if (raw.slice(pos, pos + 2).toString("latin1") === "--") break; // closing boundary
    if (raw.slice(pos, pos + 2).toString("latin1") !== "\r\n") {
      throw new Refusal(400, "malformed_multipart", "multipart boundary is not followed by CRLF");
    }
    pos += 2;
    const headEnd = raw.indexOf("\r\n\r\n", pos, "latin1");
    if (headEnd < 0) throw new Refusal(400, "malformed_multipart", "multipart part without a header end");
    const head = raw.slice(pos, headEnd).toString("latin1");
    const next = raw.indexOf(Buffer.concat([Buffer.from("\r\n", "latin1"), boundary]), headEnd + 4);
    if (next < 0) throw new Refusal(400, "malformed_multipart", "multipart part is not closed by its boundary");
    const data = raw.slice(headEnd + 4, next);
    const disp = /^content-disposition:\s*form-data\s*;(.*)$/im.exec(head);
    const name = disp && /\bname="([^"]*)"/i.exec(disp[1]);
    if (!name) throw new Refusal(400, "malformed_multipart", "multipart part without a form-data name");
    if (++parts > MAX_PARTS) throw new Refusal(400, "too_many_parts", `more than ${MAX_PARTS} multipart parts`);
    if (Object.prototype.hasOwnProperty.call(fields, name[1])) {
      throw new Refusal(400, "duplicate_field", `field ${JSON.stringify(name[1])} appears twice`);
    }
    fields[name[1]] = data;
    pos = next + 2;
  }
  return fields;
}

const B64 = /^[A-Za-z0-9+/]*={0,2}$/;
function fromB64(field, s) {
  if (typeof s !== "string" || s.length % 4 !== 0 || !B64.test(s)) {
    throw new Refusal(400, "malformed_base64", `${field} is not canonical base64`);
  }
  const b = Buffer.from(s, "base64");
  if (b.toString("base64") !== s) throw new Refusal(400, "malformed_base64", `${field} is not canonical base64`);
  return b;
}

// One tape out of the field `name` (its text) or `${name}_b64` (base64), each
// as the request carried it, capped at TAPE_MAX_BYTES. -> Buffer.
function tapeFrom(fields, name, fromMultipart) {
  const text = fields[name];
  const b64 = fields[`${name}_b64`];
  if (text !== undefined && b64 !== undefined) {
    throw new Refusal(400, "ambiguous_tape", `${name} and ${name}_b64 are both present; send one`);
  }
  if (text === undefined && b64 === undefined) {
    throw new Refusal(400, "missing_tape", `${name} is missing; reconcile needs both tapes`);
  }
  let bytes;
  if (fromMultipart) {
    bytes = b64 !== undefined ? fromB64(`${name}_b64`, b64.toString("latin1").trim()) : text;
  } else if (b64 !== undefined) {
    bytes = fromB64(`${name}_b64`, b64);
  } else if (typeof text === "string") {
    bytes = Buffer.from(text, "utf-8");
  } else {
    throw new Refusal(400, "malformed_field", `${name} must be a string (the tape's text)`);
  }
  if (bytes.length > TAPE_MAX_BYTES) {
    throw new Refusal(413, "tape_too_large", `${name} is ${bytes.length} bytes; the cap is ${TAPE_MAX_BYTES} per tape`,
      { cap_bytes: TAPE_MAX_BYTES });
  }
  return bytes;
}

// -> {agent: Buffer, tool: Buffer}
function tapesFrom(fields, fromMultipart) {
  if (fields === null || typeof fields !== "object" || Array.isArray(fields)) {
    throw new Refusal(400, "malformed_body", "the body must be an object with agent_tape and tool_tape");
  }
  for (const k of Object.keys(fields)) {
    if (PIN_FIELDS.includes(k)) {
      throw new Refusal(400, "pins_not_supported",
        "this endpoint does not check witness pins; a pin sent here would not be looked at. " +
          "Run `arcaeon-ledger reconcile A B --pin P` for the pin check.");
    }
    if (!FIELDS.includes(k)) throw new Refusal(400, "unknown_field", `unknown field ${JSON.stringify(k).slice(0, 80)}`);
  }
  const out = {};
  for (const side of ["agent", "tool"]) out[side] = tapeFrom(fields, `${side}_tape`, fromMultipart);
  return out;
}

// The request's fields, whatever shape they came in: a JSON object, or the
// parts of a multipart body (each a Buffer). -> {fields, fromMultipart}.
// Throws a Refusal for a body this file would refuse.
async function readFields(req) {
  const { type, full } = mediaType(req);
  const body = await readBody(req);
  if (type === "multipart/form-data") {
    if (!body.raw) throw new Refusal(400, "malformed_multipart", "multipart body could not be read raw");
    return { fields: parseMultipart(body.raw, full), fromMultipart: true };
  }
  if (type === "application/json" || (type === "" && body.parsed)) {
    return { fields: body.parsed !== undefined ? body.parsed : parseJsonBody(body.raw), fromMultipart: false };
  }
  throw new Refusal(415, "unsupported_media_type", "send application/json or multipart/form-data");
}

// The comparison: the port on the two tapes, then the receipt, signed with
// WITNESS_RECONCILE_SIGNER_KEY from opts.env (or the process), an active
// reconcile entry of opts.keyDocument (the committed document unless a test
// hands another). `bytesA` is reconcile's first argument (tape_a in its
// answer and in the receipt), `bytesB` its second. -> {result, receipt}.
// With no such signer (NO SIGNER, NO RECEIPT, above), this throws before the port runs:
// an Error with `signerUnavailable: true` and the loader's `reason` (never
// the key). If the port raises, this throws an Error with `portError: true`
// and the port's exception name in `causeName`, and nothing else about it:
// the caller answers 500 with no verdict and keeps the tapes out of the log.
function compare(bytesA, bytesB, opts = {}) {
  const signer = SEAL.loadReconcileSigner(opts.env || process.env, { keyDocument: opts.keyDocument });
  if (!signer.ok) {
    const err = new Error("no published reconcile signer is configured, so nothing is compared");
    err.signerUnavailable = true;
    err.reason = signer.reason;
    throw err;
  }
  let result;
  try {
    result = T.reconcileTapes(bytesA, bytesB);
  } catch (e) {
    const err = new Error("the comparison failed inside this service");
    err.portError = true;
    err.causeName = e && e.name;
    throw err;
  }
  const receipt = receipts.signReceipt(receipts.buildReceipt({ bytesA, bytesB, result, now: opts.now }), signer);
  return { result, receipt };
}

async function handleReconcile(req, res, opts = {}) {
  if (req.method !== "POST") {
    res.setHeader("allow", "POST");
    res.setHeader("cache-control", "no-store");
    return res.status(405).json({ ok: false, error_code: "method_not_allowed", error: "POST two tapes to /api/reconcile" });
  }
  res.setHeader("cache-control", "no-store");
  const rl = await ratelimit.check(req);
  if (rl.limited) {
    res.setHeader("retry-after", String(rl.retryAfterSeconds));
    return res.status(429).json({
      ok: false,
      error_code: "rate_limited",
      error: "rate limit exceeded",
      note: `naive per-instance, per-IP limiter shared with /api/verify: ~${rl.limit} calls per IP per ${Math.round(rl.windowSeconds / 60)} minutes per warm instance`,
      retry_after_seconds: rl.retryAfterSeconds,
    });
  }

  let tapes;
  try {
    const { fields, fromMultipart } = await readFields(req);
    tapes = tapesFrom(fields, fromMultipart);
  } catch (e) {
    if (e instanceof Refusal) return refuse(res, e);
    return refuse(res, new Refusal(400, "unreadable_body", "the request body could not be read"));
  }

  let compared;
  try {
    compared = compare(tapes.agent, tapes.tool, opts);
  } catch (e) {
    if (e && e.signerUnavailable) {
      return refuse(res, new Refusal(503, "signer_unavailable",
        "this deployment has no published reconcile signer, and it hands out no receipt it cannot sign with one; the tapes were not compared", { reason: e.reason }));
    }
    if (!e || !e.portError) throw e;
    // The port answers every input (the fuzz and conformance suites hold it
    // to that). If it ever throws, that is this service's defect: say so,
    // give no verdict, keep the tapes out of the log.
    console.error(`[reconcile] port raised ${e.causeName}`);
    return refuse(res, new Refusal(500, "internal_error", "the comparison failed inside this service; no verdict was reached"));
  }
  const { result, receipt } = compared;
  res.setHeader("content-type", "application/json; charset=utf-8");
  return res.status(200).send(T.wireJson({ ok: true, verdict: result, receipt, service_limits: SERVICE_LIMITS.slice() }));
}

function handlePage(req, res) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.setHeader("allow", "GET, HEAD");
    return res.status(405).json({ ok: false, error_code: "method_not_allowed", error: "GET only" });
  }
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.setHeader("cache-control", "public, max-age=300");
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("referrer-policy", "no-referrer");
  return res.status(200).send(page.HTML);
}

module.exports = {
  handleReconcile,
  handlePage,
  readFields,
  tapeFrom,
  compare,
  Refusal,
  TAPE_MAX_BYTES,
  BODY_MAX_BYTES,
  SERVICE_LIMITS,
  _internal: { parseMultipart, tapesFrom, Refusal },
};
