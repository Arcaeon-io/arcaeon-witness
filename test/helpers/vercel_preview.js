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
// `signer: {env, keyDocument}` is a deployment whose environment holds the
// case key (and the two keys it must differ from) and whose bundled key
// document lists it: ?op=case-reveal runs lib/_case_http.js handleCaseReveal
// with those, so the seal is signed. Without it the reveal runs through
// api/verify.js with this process's environment and the committed document,
// which lists no key, so the seal is unsigned.
// `answers` maps a path to a fixed answer, {status, headers}, or {drop:
// true} to close the connection with no answer at all, ahead of everything.
// `protect` stands Vercel Authentication in front of all of that: a request
// is answered 401 before anything above runs, unless it carries
// x-vercel-protection-bypass equal to `protect.secret` (Protection Bypass
// for Automation). The 401 is a stand-in for Vercel's SSO page (server:
// Vercel, a _vercel_sso_nonce cookie, the title "Authentication Required",
// a link to vercel.com/sso-api), modelled on it, not copied from a live
// one; `protect: {page: "plain"}` answers a bare 401 with none of those
// marks instead. `protect: true` is protection with no secret that passes.
// `requests` records what arrived, headers included.
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..", "..");
// Required when first used, after the test has set its environment.
const caseHttp = () => require("../../lib/_case_http.js");

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

function ssoPage(res, url) {
  const nonce = Math.random().toString(36).slice(2);
  res.setHeader("server", "Vercel");
  res.setHeader("set-cookie", `_vercel_sso_nonce=${nonce}; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax`);
  const to = `https://vercel.com/sso-api?url=${encodeURIComponent(url)}&nonce=${nonce}`;
  return send(res, 401, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Authentication Required</title></head>` +
    `<body><p>Vercel Authentication</p><p>Redirecting to <a href="${to}">${to}</a></p></body></html>`, "text/html; charset=utf-8");
}

let serverSeq = 0;

async function startPreview({ vercel = readVercel(), serves = publicOnly, files = {}, answers = {}, wrap = null, bodyParser = vercelBody, protect = false, signer = null } = {}) {
  serverSeq += 1;
  const ip = `10.77.${(serverSeq >> 8) & 255}.${serverSeq & 255}`;
  const guard = protect === true ? { page: "sso" } : protect || null;
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
      if (guard && !(guard.secret && req.headers["x-vercel-protection-bypass"] === guard.secret)) {
        if (guard.page === "plain") return send(res, 401, "Unauthorized\n", "text/plain; charset=utf-8");
        return ssoPage(res, `https://preview.invalid${req.url}`);
      }
      let pathname = decodeURIComponent(u.pathname);
      if (Object.prototype.hasOwnProperty.call(answers, pathname)) {
        const a = answers[pathname];
        if (a.drop) return req.socket.destroy();
        for (const [k, v] of Object.entries(a.headers || {})) res.setHeader(k, v);
        return send(res, a.status, a.body || "", "text/plain; charset=utf-8");
      }
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
      const base = signer ? (rq, rs) => ((rq.query || {}).op === "case-reveal" ? caseHttp().handleCaseReveal(rq, rs, signer) : fn(rq, rs)) : fn;
      await (wrap ? wrap(base) : base)(req, res);
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
