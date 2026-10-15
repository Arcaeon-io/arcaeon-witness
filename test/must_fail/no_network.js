// test/must_fail/no_network.js — loaded first (NODE_OPTIONS --require) by
// every process of a planted-defect suite (test/must_fail/run.js, THE
// SUITE'S ENVIRONMENT; unit R-WIDE, B4): a fetch to any host but this
// machine's is refused, so a test that would reach a real service fails
// instead of passing or failing on the network. A test's own mock store
// replaces global.fetch while it is installed and restores this one.
// Since unit R-WIDEf (F2-d) the roads under fetch are closed the same way:
// http.request and http.get, https.request and https.get, net.connect
// (net.createConnection) and tls.connect, to any host but this machine's,
// throw. A Unix socket or named pipe (a path, no host) is this machine's.
"use strict";

const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const tls = require("node:tls");

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const real = global.fetch;
const refuse = (host) => new TypeError(`must-fail run: no network (${host || "an unparsable URL"})`);

global.fetch = async function noNetwork(input, opts) {
  let host = "";
  try {
    host = new URL(typeof input === "string" || input instanceof URL ? String(input) : String(input && input.url)).hostname;
  } catch {
    host = "";
  }
  if (LOOPBACK.has(host)) return real(input, opts);
  throw refuse(host);
};

const isObject = (v) => v !== null && typeof v === "object" && !(v instanceof URL);
// http(s).request(url[, options][, cb]) or (options[, cb]): the host the
// options name, else the URL's, else node's default, localhost.
function requestHost(a0, a1) {
  let host;
  let opts = null;
  if (typeof a0 === "string" || a0 instanceof URL) {
    try {
      host = new URL(String(a0)).hostname;
    } catch {
      return "";
    }
    if (isObject(a1)) opts = a1;
  } else if (isObject(a0)) {
    opts = a0;
  }
  if (opts) {
    if (opts.socketPath) return "localhost";
    if (opts.hostname) host = String(opts.hostname);
    else if (opts.host) host = String(opts.host);
  }
  return host || "localhost";
}
// net.connect(options[, cb]) | (port[, host][, cb]) | (path[, cb]), and
// tls.connect's same forms: a path is this machine's.
function connectHost(a0, a1) {
  if (isObject(a0)) return a0.path ? "localhost" : String(a0.host || "localhost");
  if (typeof a0 === "number" || (typeof a0 === "string" && /^\d+$/.test(a0))) return typeof a1 === "string" ? a1 : "localhost";
  return "localhost";
}
function guard(mod, name, hostOf) {
  const orig = mod[name];
  mod[name] = function noNetwork(...args) {
    const host = hostOf(args[0], args[1]);
    if (!LOOPBACK.has(host)) throw refuse(host);
    return orig.apply(this, args);
  };
}
for (const mod of [http, https]) {
  guard(mod, "request", requestHost);
  guard(mod, "get", requestHost);
}
guard(net, "connect", connectHost);
guard(net, "createConnection", connectHost);
guard(tls, "connect", connectHost);
