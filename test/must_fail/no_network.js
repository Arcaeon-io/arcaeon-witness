// test/must_fail/no_network.js — loaded first (NODE_OPTIONS --require) by
// every process of a planted-defect suite (test/must_fail/run.js, THE
// SUITE'S ENVIRONMENT; unit R-WIDE, B4): a fetch to any host but this
// machine's is refused, so a test that would reach a real service fails
// instead of passing or failing on the network. A test's own mock store
// replaces global.fetch while it is installed and restores this one.
"use strict";

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const real = global.fetch;

global.fetch = async function noNetwork(input, opts) {
  let host = "";
  try {
    host = new URL(typeof input === "string" || input instanceof URL ? String(input) : String(input && input.url)).hostname;
  } catch {
    host = "";
  }
  if (LOOPBACK.has(host)) return real(input, opts);
  throw new TypeError(`must-fail run: no network (${host || "an unparsable URL"})`);
};
