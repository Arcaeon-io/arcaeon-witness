#!/usr/bin/env node
// tools/loadtest.js — a local load test of POST /api/pin against a mocked
// store (owner job 19): many concurrent pinners, and what each pin costs in
// writes. Nothing reaches a network: the store is the test suite's fake of
// the GitHub contents API (test/helpers/mock_store.js), with a small random
// delay on every call so concurrent requests really interleave.
//
//   node tools/loadtest.js [--pinners 100] [--pins 3] [--shadow] [--delay-ms 4] [--json]
//
//   --pinners  concurrent pinners, each with its own key and namespace
//   --pins     pins each pinner makes, one after another, rows growing
//   --shadow   with the shadow batch run on: every accepted pin also adds a
//              leaf to the one shared pending document, the contended path
//   --delay-ms the most a store call waits, picked at random per call
//
// It reports pins by answer, writes per accepted pin to the public and the
// private repo (only the writes that landed), every write attempt including
// compare and swap conflicts, and pin latency (p50, p95, max). The numbers
// are of this code against a fake; they say what the write path does under
// contention, not how fast GitHub is.

"use strict";

const PIN_REPO = "load/pins";
const USAGE_REPO = "load/usage";

async function run({ pinners = 100, pins = 3, shadow = false, delayMs = 4, seed = 1 } = {}) {
  process.env.GITHUB_PIN_REPO = PIN_REPO;
  process.env.GITHUB_PIN_BRANCH = "main";
  process.env.GITHUB_USAGE_REPO = USAGE_REPO;
  process.env.GITHUB_PIN_TOKEN = "load-token";
  process.env.WITNESS_KEYS = Array.from({ length: pinners }, (_, i) => `loadkey${i}:load-${i}-`).join(",");
  process.env.WITNESS_PLANS = "{}";
  if (shadow) process.env.WITNESS_BATCH_SHADOW = "on";
  else delete process.env.WITNESS_BATCH_SHADOW;
  for (const m of ["../api/pin.js", "../lib/_store.js", "../lib/_meter.js", "../lib/_pending.js", "../lib/_balance.js", "../lib/_keys.js"]) {
    try { delete require.cache[require.resolve(m)]; } catch (_e) { /* not loaded */ }
  }
  const { MockGitHubStore } = require("../test/helpers/mock_store.js");
  const { makeReq, makeRes } = require("../test/helpers/http_mocks.js");
  const store = require("../lib/_store.js");
  store._putRetry.sleep = async (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 20)));
  const pin = require("../api/pin.js");

  let s = seed;
  const rand = () => { s = (s * 1103515245 + 12345) % 2147483648; return s / 2147483648; };
  const gh = new MockGitHubStore();
  const attempts = { put: 0, conflict: 0, get: 0 };
  const original = global.fetch;
  global.fetch = async (url, opts) => {
    await new Promise((r) => setTimeout(r, Math.floor(rand() * (delayMs + 1))));
    const method = (opts && opts.method) || "GET";
    const res = await gh.handleFetch(url, opts);
    if (method === "PUT") {
      attempts.put++;
      if (res.status === 409 || res.status === 422) attempts.conflict++;
    } else {
      attempts.get++;
    }
    return res;
  };
  const statuses = {};
  const latencies = [];
  // The code under test logs every lost race and every dropped leaf; they
  // are counted here, not printed, and reported in the summary.
  const logged = { leaf_not_accumulated: 0, other: 0 };
  const realError = console.error;
  console.error = (...a) => {
    const line = a.join(" ");
    if (line.includes("leaf NOT accumulated")) logged.leaf_not_accumulated++;
    else if (!/\] PUT .* -> (409|422)/.test(line)) logged.other++;
  };
  try {
    await Promise.all(Array.from({ length: pinners }, async (_, i) => {
      for (let j = 1; j <= pins; j++) {
        const res = makeRes();
        const t = process.hrtime.bigint();
        await pin(makeReq({ method: "POST", headers: { authorization: `Bearer loadkey${i}` },
          body: { namespace: `load-${i}-ns`, rows: j, chain: (`${i}`.padStart(4, "0") + `${j}`.padStart(4, "0")) } }), res);
        latencies.push(Number(process.hrtime.bigint() - t) / 1e6);
        statuses[res._status] = (statuses[res._status] || 0) + 1;
      }
    }));
  } finally {
    global.fetch = original;
    console.error = realError;
  }
  const accepted = statuses[201] || 0;
  const landed = (repo) => gh.putLog.filter((p) => p.repo === repo).length;
  const pub = landed(PIN_REPO);
  const priv = landed(USAGE_REPO);
  latencies.sort((a, b) => a - b);
  const pct = (p) => latencies.length ? Math.round(latencies[Math.min(latencies.length - 1, Math.floor(p * latencies.length))]) : null;
  const pendingDoc = gh.read(USAGE_REPO, "pending/open_batch.json");
  return {
    pinners, pins_each: pins, shadow, delay_ms: delayMs,
    pins_sent: pinners * pins, answers: statuses, accepted,
    writes: { public: pub, private: priv, total: pub + priv },
    writes_per_accepted_pin: accepted ? { public: +(pub / accepted).toFixed(3), private: +(priv / accepted).toFixed(3),
      total: +((pub + priv) / accepted).toFixed(3) } : null,
    put_attempts: attempts.put, put_conflicts: attempts.conflict, gets: attempts.get,
    pending_leaves: pendingDoc ? pendingDoc.open.leaves.length : null,
    leaves_dropped: logged.leaf_not_accumulated,
    other_errors_logged: logged.other,
    latency_ms: { p50: pct(0.5), p95: pct(0.95), max: latencies.length ? Math.round(latencies[latencies.length - 1]) : null },
  };
}

function words(r) {
  const w = r.writes_per_accepted_pin;
  return [
    `${r.pinners} pinners x ${r.pins_each} pins, shadow batch run ${r.shadow ? "on" : "off"}, store calls delayed up to ${r.delay_ms} ms`,
    `answers: ${Object.entries(r.answers).map(([k, v]) => `${k} x${v}`).join(", ")}`,
    w ? `writes per accepted pin: ${w.public} public + ${w.private} private = ${w.total}` : "no pin was accepted",
    `write attempts: ${r.put_attempts}, of which ${r.put_conflicts} lost a compare and swap race; reads: ${r.gets}`,
    r.shadow ? `pending batch leaves: ${r.pending_leaves} of ${r.accepted} accepted pins; ${r.leaves_dropped} dropped after losing every compare and swap retry` : null,
    r.other_errors_logged ? `other errors logged: ${r.other_errors_logged}` : null,
    `latency: p50 ${r.latency_ms.p50} ms, p95 ${r.latency_ms.p95} ms, max ${r.latency_ms.max} ms`,
  ].filter(Boolean).join("\n");
}

async function main(argv = process.argv.slice(2), print = console.log) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === "--pinners") o.pinners = Number(argv[++i]);
    else if (k === "--pins") o.pins = Number(argv[++i]);
    else if (k === "--delay-ms") o.delayMs = Number(argv[++i]);
    else if (k === "--shadow") o.shadow = true;
    else if (k === "--json") o.json = true;
    else { print(`usage: unknown argument ${k}`); return 2; }
  }
  for (const k of ["pinners", "pins", "delayMs"]) {
    if (o[k] !== undefined && (!Number.isInteger(o[k]) || o[k] < (k === "delayMs" ? 0 : 1) || o[k] > 10000)) {
      print(`usage: --${k === "delayMs" ? "delay-ms" : k} must be a whole number`);
      return 2;
    }
  }
  const r = await run(o);
  print(o.json ? JSON.stringify(r) : words(r));
  return 0;
}

if (require.main === module) main().then((c) => process.exit(c));

module.exports = { run, words, main };
