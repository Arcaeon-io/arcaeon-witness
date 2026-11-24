#!/usr/bin/env node
// tools/tsa_stamp.js — stamp ONE file at DigiCert's free RFC 3161 time stamp
// server and check the answer with stock openssl. An outside clock beside the
// Bitcoin anchor (README "Anchoring"): it says "this file's sha256 existed at
// time T" in DigiCert's signature, checkable by anyone with openssl.
//
//   node tools/tsa_stamp.js --file anchors/2026-11-22-head.txt --out stamps/ \
//        [--ca-file /etc/ssl/certs/ca-certificates.crt] [--untrusted chain.pem] \
//        [--expect-signer "O = DigiCert"] [--json]
//
// It writes <file>.tsq (the request) and <file>.tsr (the authority's answer)
// into --out, and nothing anywhere else. Check a kept answer later with
// openssl alone:
//
//   openssl ts -verify -data <file> -in <file>.tsr -CAfile <roots> [-untrusted <chain>]
//
// FREE SERVICES ONLY. The one authority this tool will ask is DigiCert's free
// server, http://timestamp.digicert.com (plain http is how RFC 3161 servers
// are reached; the answer is signed, so the transport adds nothing to trust).
// No paid time stamp service is used. --tsa-url accepts that host, or a local
// test server on 127.0.0.1 / localhost (the tests run one with stock
// `openssl ts -reply`); anything else is refused before anything is sent.
//
// WHO SIGNED. openssl's chain check against the system roots says that SOME
// trusted authority signed the token: the TLS root bundle holds about 140
// roots. So the tool also finds the certificate the token's signature names
// (issuer and serial number, matched byte for byte, in the token or the
// --untrusted file), reports its subject, issuer and sha256 fingerprint, and
// requires its subject to contain --expect-signer. For DigiCert's server that
// defaults to "O = DigiCert"; a local test server must say whom it expects.
// (Found 2026-11-22 reading another time stamp client, which checks a token
// against the certificate the token itself carries.)
//
// VERDICTS (exit code): VERIFIED (0) the answer is for this file and this
// request, and `openssl ts -verify` says "Verification: OK" against --ca-file;
// BROKEN (2) an answer came back and it is not that; COULD NOT LOOK (3) the
// server could not be reached, or openssl is not installed, so nothing is
// claimed; usage error (1).
//
// WHAT IT DOES NOT PROVE: that the file's contents are true, or anything
// before T. It does not schedule itself: running it every hour is the job of
// whatever runs the daily anchor (see the README), and it says nothing about
// a run that did not happen.
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const rfc = require("../lib/_rfc3161.js");

const DIGICERT_URL = "http://timestamp.digicert.com";
const FREE_HOSTS = new Set(["timestamp.digicert.com"]);
const LOCAL_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const DEFAULT_CA_FILE = "/etc/ssl/certs/ca-certificates.crt";
const DEFAULT_SIGNER = { "timestamp.digicert.com": "O = DigiCert" };
const TIMEOUT_MS = 15_000;

function usage(msg) {
  if (msg) process.stderr.write(`tsa_stamp: ${msg}\n`);
  process.stderr.write(
    "usage: node tools/tsa_stamp.js --file <path> --out <dir> [--tsa-url <url>] [--ca-file <pem>] [--untrusted <pem>] [--expect-signer <text>] [--json]\n" +
      "  --expect-signer: text the signing certificate's subject must contain (default for DigiCert: \"O = DigiCert\")\n" +
      `  the only time stamp service used is DigiCert's free server, ${DIGICERT_URL} (free list; no paid service)\n`
  );
  process.exit(1);
}

function parseArgs(argv) {
  const a = { file: null, out: null, tsaUrl: DIGICERT_URL, caFile: null, untrusted: null, expectSigner: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) usage(`${k} needs a value`);
      return argv[++i];
    };
    if (k === "--file") a.file = next();
    else if (k === "--out") a.out = next();
    else if (k === "--tsa-url") a.tsaUrl = next();
    else if (k === "--ca-file") a.caFile = next();
    else if (k === "--untrusted") a.untrusted = next();
    else if (k === "--expect-signer") a.expectSigner = next();
    else if (k === "--json") a.json = true;
    else if (k === "--help" || k === "-h") usage();
    else usage(`unknown argument ${k}`);
  }
  return a;
}

function checkTsaUrl(raw) {
  let u;
  try { u = new URL(raw); } catch (_) { usage(`--tsa-url ${raw} is not a URL`); }
  if (u.protocol !== "http:" && u.protocol !== "https:") usage(`--tsa-url ${raw} is not on this tool's free list`);
  if (FREE_HOSTS.has(u.hostname) || LOCAL_HOSTS.has(u.hostname)) return u;
  usage(`--tsa-url ${raw} is not on this tool's free list (only ${[...FREE_HOSTS].join(", ")}; no paid service)`);
}

function post(u, body) {
  return new Promise((resolve, reject) => {
    // node:http only: DigiCert's server is plain http, and a local test server is too.
    if (u.protocol !== "http:") return reject(new Error("only http time stamp servers are supported"));
    const req = http.request(u, {
      method: "POST",
      headers: { "content-type": "application/timestamp-query", "content-length": body.length },
      timeout: TIMEOUT_MS,
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.on("timeout", () => req.destroy(new Error(`no answer in ${TIMEOUT_MS / 1000}s`)));
    req.on("error", reject);
    req.end(body);
  });
}

// Every certificate in a PEM file, as DER.
function pemCertificates(text) {
  const out = [];
  for (const m of text.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)) {
    out.push(Buffer.from(m[1].replace(/\s+/g, ""), "base64"));
  }
  return out;
}

function finish(args, summary) {
  if (args.json) process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
  else {
    const lines = [`tsa_stamp: ${summary.verdict} — ${summary.file}`];
    if (summary.gen_time) lines.push(`  authority time ${summary.gen_time}, sha256 ${summary.sha256}`);
    if (summary.openssl_verify) lines.push(`  openssl: ${summary.openssl_verify}`);
    if (summary.signer) lines.push(`  signed by: ${summary.signer.subject} (issuer ${summary.signer.issuer}; sha256 ${summary.signer.sha256})`);
    for (const p of summary.problems) lines.push(`  - ${p}`);
    if (summary.tsr) lines.push(`  kept: ${summary.tsr}`);
    process.stdout.write(lines.join("\n") + "\n");
  }
  process.exit({ VERIFIED: 0, BROKEN: 2, "COULD NOT LOOK": 3 }[summary.verdict]);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.file) usage("--file is required");
  if (!args.out) usage("--out is required");
  const u = checkTsaUrl(args.tsaUrl);
  const expectSigner = args.expectSigner || DEFAULT_SIGNER[u.hostname] || null;
  if (!expectSigner) usage(`--expect-signer is required for ${u.hostname} (whose certificate should have signed?)`);
  const file = path.resolve(args.file);
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) usage(`--file ${args.file} is not a file`);
  const caFile = args.caFile ? path.resolve(args.caFile) : DEFAULT_CA_FILE;

  const data = fs.readFileSync(file);
  const hash = crypto.createHash("sha256").update(data).digest();
  const nonce = rfc.makeNonce();
  const request = rfc.buildRequest({ hash, nonce, certReq: true });
  const summary = {
    verdict: "COULD NOT LOOK",
    file,
    sha256: hash.toString("hex"),
    tsa: u.href,
    nonce: nonce.toString("hex"),
    gen_time: null,
    serial: null,
    policy: null,
    openssl_verify: null,
    expect_signer: expectSigner,
    signer: null,
    tsq: null,
    tsr: null,
    problems: [],
  };

  let answer;
  try {
    answer = await post(u, request);
  } catch (err) {
    summary.problems.push(`could not reach ${u.host}: ${err.message}`);
    return finish(args, summary);
  }

  fs.mkdirSync(args.out, { recursive: true });
  const base = path.join(path.resolve(args.out), path.basename(file));
  summary.tsq = `${base}.tsq`;
  fs.writeFileSync(summary.tsq, request);
  summary.verdict = "BROKEN";
  if (answer.status !== 200) {
    summary.problems.push(`the server answered HTTP ${answer.status}`);
    return finish(args, summary);
  }
  summary.tsr = `${base}.tsr`;
  fs.writeFileSync(summary.tsr, answer.body);

  let resp;
  try {
    resp = rfc.parseResponse(answer.body);
  } catch (err) {
    summary.problems.push(err instanceof rfc.Rfc3161Error ? err.message : `unreadable answer: ${err.message}`);
    return finish(args, summary);
  }
  if (resp.tst) {
    summary.gen_time = resp.tst.genTime;
    summary.serial = resp.tst.serial;
    summary.policy = resp.tst.policy;
  }
  const check = rfc.checkResponse(resp, { hash, nonce });
  summary.problems.push(...check.problems);
  if (!check.ok) return finish(args, summary);

  // The signature and the chain: stock openssl, not our code.
  const vArgs = ["ts", "-verify", "-data", file, "-in", summary.tsr, "-CAfile", caFile];
  if (args.untrusted) vArgs.push("-untrusted", path.resolve(args.untrusted));
  const v = spawnSync("openssl", vArgs, { encoding: "utf8" });
  if (v.error) {
    summary.verdict = "COULD NOT LOOK";
    summary.problems.push(`openssl could not be run: ${v.error.message}; the kept .tsr can be checked later`);
    return finish(args, summary);
  }
  const said = `${v.stdout || ""}${v.stderr || ""}`;
  const line = said.split(/\r?\n/).find((l) => /^Verification: /.test(l));
  summary.openssl_verify = line || said.trim().split(/\r?\n/).slice(-1)[0] || `openssl exited ${v.status}`;
  if (!(v.status === 0 && line === "Verification: OK")) {
    summary.problems.push("openssl ts -verify did not accept the token against the CA file");
    return finish(args, summary);
  }

  // Who signed: the certificate the signature names, not any trusted one.
  const candidates = [...resp.certificates];
  if (args.untrusted) candidates.push(...pemCertificates(fs.readFileSync(path.resolve(args.untrusted), "utf8")));
  const found = rfc.findSignerCertificate(resp, candidates);
  if (!found.cert) {
    summary.problems.push(found.problem);
    return finish(args, summary);
  }
  const x = spawnSync("openssl", ["x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-fingerprint", "-sha256"], { input: found.cert, encoding: "utf8" });
  const field = (re) => { const m = (x.stdout || "").match(re); return m ? m[1].trim() : null; };
  summary.signer = {
    subject: field(/^subject=(.*)$/m),
    issuer: field(/^issuer=(.*)$/m),
    sha256: field(/^sha256 Fingerprint=(.*)$/m),
  };
  if (!summary.signer.subject) {
    summary.problems.push("the signing certificate could not be read by openssl x509");
  } else if (!summary.signer.subject.includes(expectSigner)) {
    summary.problems.push(`signed by "${summary.signer.subject}", not by a certificate whose subject contains "${expectSigner}"`);
  } else {
    summary.verdict = "VERIFIED";
  }
  return finish(args, summary);
}

main().catch((err) => {
  process.stderr.write(`tsa_stamp: ${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
