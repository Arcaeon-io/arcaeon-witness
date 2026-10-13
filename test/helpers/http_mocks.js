// test/helpers/http_mocks.js — minimal req/res fakes for the Vercel-shaped
// `async (req, res) => {}` handlers in api/*.js. Not a test file (no test()
// calls).

"use strict";

const { Readable } = require("stream");

function lowerHeaders(headers) {
  const out = {};
  for (const k of Object.keys(headers || {})) out[k.toLowerCase()] = headers[k];
  return out;
}

// Handlers that use Vercel's default (parsed) body: pin.js. `body` is a
// plain JS object, already "parsed" — matches req.body under Vercel's
// default bodyParser.
function makeReq({ method = "GET", headers = {}, body = null, query = {} } = {}) {
  return { method, headers: lowerHeaders(headers), body, query };
}

// stripe-webhook.js disables bodyParser and reads the raw body itself via
// req.on('data'|'end'|'error'). Give it a real Readable so that contract
// holds byte-for-byte (this is exactly the surface a raw-body signature
// check depends on — see stripe-webhook.js's own comment on why).
function makeRawReq({ method = "POST", headers = {}, rawBody = Buffer.alloc(0) } = {}) {
  const stream = new Readable({
    read() {
      this.push(rawBody);
      this.push(null);
    },
  });
  stream.method = method;
  stream.headers = lowerHeaders(headers);
  return stream;
}

// THE BODY AUDIT (unit R-N2, B2; since unit R-N3, N8, every status): with
// ARCAEON_BODY_AUDIT naming a file, every response sent is appended to it,
// one JSON line {file, status, handler, body}, for
// test/response_bodies.test.js to read. `handler` is the handle* function
// that sent it, read from the stack (the path, not the error code), or null.
// Off unless that variable is set.
function audit(res, body) {
  const file = process.env.ARCAEON_BODY_AUDIT;
  if (!file) return;
  const text = typeof body === "string" ? body : JSON.stringify(body === undefined ? null : body);
  const m = /at (?:async )?(?:Object\.)?(handle[A-Za-z]+)/.exec(new Error().stack || "");
  require("fs").appendFileSync(file, `${JSON.stringify({ file: require("path").basename(process.argv[1] || ""), status: res._status, handler: m ? m[1] : null, body: text })}\n`);
}

// res.status(code).json(body) — captures what was sent so a test can assert
// on it without a real HTTP round trip.
function makeRes() {
  const res = {
    _status: 200,
    _headers: {},
    _body: undefined,
    _sent: false,
    _ended: false,
    setHeader(k, v) {
      res._headers[String(k).toLowerCase()] = v;
      return res;
    },
    status(code) {
      res._status = code;
      return res;
    },
    json(body) {
      res._body = body;
      res._sent = true;
      audit(res, body);
      return res;
    },
    // Real http.ServerResponse#end(): sends a bodyless response. Used by
    // read endpoints answering an OPTIONS preflight (res.status(204).end()) —
    // added alongside _cors.js so that path is exercisable under this
    // harness the same as .json() is.
    send(body) {
      res._body = body;
      res._sent = true;
      audit(res, body);
      return res;
    },
    end() {
      res._sent = true;
      res._ended = true;
      return res;
    },
  };
  return res;
}

module.exports = { makeReq, makeRawReq, makeRes };
