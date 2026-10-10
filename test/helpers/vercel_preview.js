// test/helpers/vercel_preview.js — an in-process stand-in for a Vercel
// preview of this repository, for test/preview_dry_run.test.js. Not a test
// file (no test() calls). A real http server on 127.0.0.1, so
// tools/preview_dry_run.js talks to it over HTTP exactly as it talks to a
// preview, and every function it reaches runs this checkout's api/*.js
// against whatever store the test installed (test/helpers/mock_store.js).
//
// What it does, in Vercel's order:
//   1. the filesystem: a path in `files` is served as given; otherwise a
//      root-relative path `serves` allows is served from this checkout. The
//      default allows .well-known/ and favicon.svg only, which is what a
//      deployment should serve; `serves: () => true` is one that serves the
//      whole root (test (g) plants it).
//   2. the rewrites of `vercel` (this checkout's vercel.json unless a test
//      hands another), ":name" segments substituted into the destination,
//      the request's own query kept.
//   3. /api/<name> runs api/<name>.js with Vercel's request and response
//      helpers: req.query, req.body parsed by `bodyParser` (Vercel's: JSON
//      for application/json, whatever the transfer encoding), res.status,
//      res.json and res.send. x-forwarded-for is the server's own address, so
//      each server gets its own per-IP limiter budget. `wrap(fn)` may stand
//      a handler in front of the function (a platform that misbehaves).
//   4. anything else is 404.
// `protect: true` answers every request 401 text/html before any of that:
// Vercel's deployment protection. `requests` records what arrived.
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..", "..");

function readVercel() {
  return JSON.parse(fs.readFileSync(path.join(ROOT, "vercel.json"), "utf8"));
}

function publicOnly(rel) {
  return rel.startsWith(".well-known/") || rel === "favicon.svg";
}

// The destination for `pathname` under the first rewrite whose source
// matches it, or null.
function rewrite(rewrites, pathname) {
  const got = pathname.split("/");
  for (const rw of rewrites || []) {
    const src = String(rw.source).split("/");
    if (src.length !== got.length) continue;
    const params = {};
    let ok = true;
    for (let i = 0; i < src.length && ok; i += 1) {
      if (src[i].startsWith(":")) {
        if (got[i]) params[src[i].slice(1)] = got[i];
        else ok = false;
      } else if (src[i] !== got[i]) ok = false;
    }
    if (!ok) continue;
    let dest = String(rw.destination);
    for (const [k, v] of Object.entries(params)) dest = dest.split(`:${k}`).join(encodeURIComponent(v));
    return dest;
  }
  return null;
}

const MALFORMED = Symbol("malformed JSON");

// Vercel's default body parser, as the handlers here read it.
function vercelBody(req, raw) {
  if (raw.length === 0) return req.method === "GET" || req.method === "HEAD" ? undefined : "";
  const type = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  if (type === "application/json") {
    try {
      return JSON.parse(raw.toString("utf8"));
    } catch {
      return MALFORMED;
    }
  }
  if (type.startsWith("text/")) return raw.toString("utf8");
  return raw;
}

function readAll(req) {
  return new Promise((resolve, reject) => {
    const parts = [];
    req.on("data", (c) => parts.push(c));
    req.on("end", () => resolve(Buffer.concat(parts)));
    req.on("error", reject);
  });
}

function send(res, status, body, type) {
  res.statusCode = status;
  if (type) res.setHeader("content-type", type);
  res.end(body);
}

function vercelResponse(res) {
  res.status = (code) => {
    res.statusCode = code;
    return res;
  };
  res.json = (obj) => {
    if (!res.getHeader("content-type")) res.setHeader("content-type", "application/json; charset=utf-8");
    res.end(JSON.stringify(obj));
    return res;
  };
  res.send = (b) => {
    if (b !== null && typeof b === "object" && !Buffer.isBuffer(b)) return res.json(b);
    if (!res.getHeader("content-type")) res.setHeader("content-type", "text/html; charset=utf-8");
    res.end(b === undefined ? "" : b);
    return res;
  };
  return res;
}

let serverSeq = 0;

async function startPreview({ vercel = readVercel(), serves = publicOnly, files = {}, wrap = null, bodyParser = vercelBody, protect = false } = {}) {
  serverSeq += 1;
  const ip = `10.77.${(serverSeq >> 8) & 255}.${serverSeq & 255}`;
  const requests = [];
  const fns = new Map();
  const fnFor = (name) => {
    if (!fns.has(name)) {
      const p = path.join(ROOT, "api", `${name}.js`);
      fns.set(name, fs.existsSync(p) ? require(p) : null);
    }
    return fns.get(name);
  };
  const server = http.createServer(async (req, res) => {
    try {
      const raw = await readAll(req);
      const u = new URL(req.url, "http://preview.invalid");
      requests.push({ method: req.method, path: u.pathname, search: u.search, headers: { ...req.headers }, bytes: raw.length });
      if (protect) return send(res, 401, "<!doctype html><title>Authentication Required</title>", "text/html; charset=utf-8");
      let pathname = decodeURIComponent(u.pathname);
      if (Object.prototype.hasOwnProperty.call(files, pathname)) return send(res, 200, files[pathname], "application/octet-stream");
      const rel = pathname.replace(/^\/+/, "");
      if (rel && serves(rel)) {
        const abs = path.join(ROOT, rel);
        if (abs.startsWith(ROOT + path.sep) && fs.existsSync(abs) && fs.statSync(abs).isFile()) {
          return send(res, 200, fs.readFileSync(abs), "application/octet-stream");
        }
      }
      let query = new URLSearchParams(u.search);
      const dest = rewrite(vercel.rewrites, pathname);
      if (dest !== null) {
        const d = new URL(dest, "http://preview.invalid");
        pathname = d.pathname;
        const q = new URLSearchParams(d.search);
        for (const [k, v] of query) if (!q.has(k)) q.set(k, v);
        query = q;
      }
      const fm = /^\/api\/([A-Za-z0-9_-]+)$/.exec(pathname);
      const fn = fm ? fnFor(fm[1]) : null;
      if (!fn) return send(res, 404, "NOT_FOUND\n", "text/plain; charset=utf-8");
      req.query = Object.fromEntries(query);
      req.headers["x-forwarded-for"] = ip;
      const body = bodyParser(req, raw);
      Object.defineProperty(req, "body", {
        configurable: true,
        get() {
          if (body === MALFORMED) throw new SyntaxError("Invalid JSON");
          return body;
        },
      });
      vercelResponse(res);
      await (wrap ? wrap(fn) : fn)(req, res);
      if (!res.writableEnded) res.end();
    } catch {
      if (!res.headersSent) send(res, 500, "FUNCTION_INVOCATION_FAILED\n", "text/plain; charset=utf-8");
      else res.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    ip,
    requests,
    close: () => new Promise((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    }),
  };
}

module.exports = { startPreview, readVercel, publicOnly, vercelBody };
