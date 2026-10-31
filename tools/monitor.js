#!/usr/bin/env node
// tools/monitor.js — a monitor anyone can run, over time, against the public
// checkpoints of the Arcaeon witness log. tools/follow.js checks one pair of
// checkpoints and the proof between them; this keeps what it has seen in a
// state file and, on every run, checks every checkpoint published since
// against the last one it kept.
//
// USAGE
//
//   node tools/monitor.js --state <file> --key "<name>+<8 hex>+<base64>" [--since YYYY-MM-DD]
//        [--source <base URL>]... [--allow-unsigned] [--today YYYY-MM-DD] [--json]
//
//   --state <file>   where the monitor keeps what it saw; made on the first run
//   --since <day>    the first day to look at, on the first run only (a state file says where to go on from)
//   --source <url>   a base URL serving checkpoints/<day>.txt and proofs/<day>-consistency.json;
//                    repeat it to compare mirrors (default: the public pins repo)
//   --key <verifier> the log's public verifier key; without it, --allow-unsigned is needed
//   --today <day>    the last day to look at (default: today, UTC); for replays and tests
//
// WHAT IT REPORTS, one word, and the exit code
//
//   VERIFIED        exit 0   every new checkpoint extends the last one kept, unaltered
//   BROKEN          exit 1   evidence of a split or a rollback, named:
//                              rollback        a checkpoint smaller than one already seen
//                              split           the same size with another root, or two
//                                              sources serving different checkpoints for one day
//                              changed         a checkpoint already seen now reads differently
//                              plus anything tools/follow.js calls BROKEN (a bad signature,
//                              a proof that does not hold)
//   COULD NOT LOOK  exit 2   a source could not be read, a proof is missing or starts from a
//                            checkpoint this monitor never saw, a signature cannot be attributed
//
// The state file only moves forward on VERIFIED. On BROKEN or COULD NOT LOOK
// it is left as it was, so the next run checks the same hop again and the
// finding does not go away by itself.
//
// What it does not do: it watches the checkpoints, not the pins. It cannot
// see a pin the witness refused at the door, or anything before the first
// checkpoint it kept. Comparing two sources catches a split only between those
// sources; a split shown to someone else is caught only when monitors compare
// notes, or by a cosigning witness.

"use strict";

const fs = require("fs");
const path = require("path");
const { follow, parseCheckpoint } = require("./follow.js");

const DEFAULT_SOURCE = "https://raw.githubusercontent.com/dan8433-user/arcaeon-witness-pins/main";
const MAX_DAYS = 400;
const MAX_BYTES = 1 << 20;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

function parseDay(s) {
  if (typeof s !== "string" || !DAY_RE.test(s)) return null;
  const t = Date.parse(`${s}T00:00:00Z`);
  return Number.isFinite(t) && new Date(t).toISOString().slice(0, 10) === s ? t : null;
}

function dayOf(t) {
  return new Date(t).toISOString().slice(0, 10);
}

// -> {status: "ok", text} | {status: "absent"} | {status: "error", detail}
async function get(fetchImpl, url) {
  let r;
  try {
    r = await fetchImpl(url, { signal: AbortSignal.timeout(15000) });
  } catch (e) {
    return { status: "error", detail: `could not reach ${url}` };
  }
  if (r.status === 404) return { status: "absent" };
  if (!r.ok) return { status: "error", detail: `${url} answered ${r.status}` };
  const text = await r.text();
  if (text.length > MAX_BYTES) return { status: "error", detail: `${url} is larger than ${MAX_BYTES} bytes` };
  return { status: "ok", text };
}

function noteText(text) {
  const p = parseCheckpoint(text);
  return p.ok ? p : null;
}

// One run. Returns {verdict, code, lines, state} where state is what to keep
// (the same object given, unchanged, unless the verdict is VERIFIED).
async function run({ state, sources, key = null, allowUnsigned = false, since = null, today, fetchImpl = fetch }) {
  const lines = [];
  // Anything but VERIFIED keeps the state given, untouched.
  const out = (verdict, code, reason, detail) => ({ verdict, code, reason, detail, lines, state });
  let next = state ? JSON.parse(JSON.stringify(state)) : null;
  const todayT = parseDay(today);
  if (todayT === null) return out("COULD NOT LOOK", 2, "bad_today", String(today));

  // Each day's checkpoint, from every source; they must agree on the note.
  async function fetchDay(day) {
    const got = [];
    for (const src of sources) {
      const r = await get(fetchImpl, `${src}/checkpoints/${day}.txt`);
      if (r.status === "error") return { error: r.detail };
      if (r.status === "ok") got.push({ src, text: r.text });
    }
    if (got.length === 0) return { none: true };
    const parsed = got.map((g) => ({ ...g, p: noteText(g.text) }));
    const bad = parsed.find((g) => !g.p);
    if (bad) return { error: `the checkpoint for ${day} at ${bad.src} cannot be read` };
    const first = parsed[0];
    const other = parsed.find((g) => g.p.text !== first.p.text);
    if (other) {
      return { split: `for ${day}, ${first.src} serves size ${first.p.size} root ${first.p.root.toString("base64")} and ` +
        `${other.src} serves size ${other.p.size} root ${other.p.root.toString("base64")}` };
    }
    if (got.length < sources.length) lines.push(`${day}: only ${got.length} of ${sources.length} sources serve a checkpoint`);
    return { text: first.text, p: first.p };
  }

  let startT;
  if (!next) {
    startT = parseDay(since);
    if (startT === null) return out("COULD NOT LOOK", 2, "no_state", "a first run needs --since YYYY-MM-DD");
  } else {
    // Is the last kept checkpoint still what it was?
    const again = await fetchDay(next.last.day);
    if (again.error) return out("COULD NOT LOOK", 2, "source_unreadable", again.error);
    if (again.split) return out("BROKEN", 1, "split", again.split);
    const kept = noteText(next.last.text);
    if (again.none) return out("COULD NOT LOOK", 2, "kept_checkpoint_gone", `no source serves the checkpoint of ${next.last.day} any more`);
    if (again.p.text !== kept.text) {
      return out("BROKEN", 1, "changed", `the checkpoint of ${next.last.day} was size ${kept.size} root ` +
        `${kept.root.toString("base64")} when kept, and now reads size ${again.p.size} root ${again.p.root.toString("base64")}`);
    }
    startT = parseDay(next.last.day) + 86400000;
  }
  if ((todayT - startT) / 86400000 > MAX_DAYS) {
    return out("COULD NOT LOOK", 2, "too_far", `more than ${MAX_DAYS} days to look at; give a later --since`);
  }

  let checked = 0;
  for (let t = startT; t <= todayT; t += 86400000) {
    const day = dayOf(t);
    const got = await fetchDay(day);
    if (got.error) return out("COULD NOT LOOK", 2, "source_unreadable", got.error);
    if (got.split) return out("BROKEN", 1, "split", got.split);
    if (got.none) continue;
    if (!next) {
      // The first checkpoint is taken as it is: there is nothing before it to check it against.
      const s = follow({ oldText: got.text, newText: got.text, proofText: JSON.stringify(selfProof(got.p)), key, allowUnsigned });
      if (s.code !== 0) return out(s.verdict, s.code, s.reason, `${day}: ${s.detail || s.reason}`);
      next = { origin: got.p.origin, last: { day, text: got.text },
        seen: [{ day, size: got.p.size, root: got.p.root.toString("base64") }] };
      lines.push(`${day}: first checkpoint kept, size ${got.p.size}`);
      checked++;
      continue;
    }
    const kept = noteText(next.last.text);
    if (got.p.origin !== kept.origin) return out("BROKEN", 1, "split", `${day}: origin ${got.p.origin}, not ${kept.origin}`);
    if (got.p.size < kept.size) {
      return out("BROKEN", 1, "rollback", `${day}: size ${got.p.size}, but ${next.last.day} was already size ${kept.size}`);
    }
    if (got.p.size === kept.size && !got.p.root.equals(kept.root)) {
      return out("BROKEN", 1, "split", `${day}: size ${got.p.size} with root ${got.p.root.toString("base64")}, ` +
        `but ${next.last.day} had the same size with root ${kept.root.toString("base64")}`);
    }
    if (got.p.text === kept.text) {
      lines.push(`${day}: the same checkpoint as ${next.last.day}, size ${kept.size}`);
    } else {
      const pr = await (async () => {
        for (const src of sources) {
          const r = await get(fetchImpl, `${src}/proofs/${day}-consistency.json`);
          if (r.status === "ok") return r;
          if (r.status === "error") return r;
        }
        return { status: "absent" };
      })();
      if (pr.status === "error") return out("COULD NOT LOOK", 2, "source_unreadable", pr.detail);
      if (pr.status === "absent") return out("COULD NOT LOOK", 2, "no_proof", `${day}: no consistency proof is published`);
      let doc;
      try { doc = JSON.parse(pr.text); } catch { doc = null; }
      if (doc && (doc.old_size !== kept.size || doc.old_root !== kept.root.toString("base64"))) {
        return out("COULD NOT LOOK", 2, "proof_from_unseen_checkpoint",
          `${day}: the proof starts at size ${doc.old_size}, not at the checkpoint this monitor kept, size ${kept.size}`);
      }
      const f = follow({ oldText: next.last.text, newText: got.text, proofText: pr.text, key, allowUnsigned });
      if (f.code !== 0) return out(f.verdict, f.code, f.reason, `${day}: ${f.detail || f.reason}`);
      lines.push(`${day}: size ${kept.size} -> ${got.p.size}, consistent`);
    }
    next.last = { day, text: got.text };
    next.seen.push({ day, size: got.p.size, root: got.p.root.toString("base64") });
    checked++;
  }
  if (!next) return out("COULD NOT LOOK", 2, "nothing_published", `no checkpoint from ${dayOf(startT)} to ${today}`);
  return { verdict: "VERIFIED", code: 0, reason: "consistent", lines, state: next,
    detail: `${checked} new checkpoint${checked === 1 ? "" : "s"} checked up to ${today}; the log at size ` +
      `${noteText(next.last.text).size} extends everything this monitor kept` };
}

// A proof from a checkpoint to itself, so the first checkpoint's signature
// is checked by the same code as every later one.
function selfProof(p) {
  return { recipe: "rfc9162-consistency:sha256:v1", origin: p.origin, old_size: p.size, old_root: p.root.toString("base64"),
    new_size: p.size, new_root: p.root.toString("base64"), path: [] };
}

function readState(file) {
  if (!fs.existsSync(file)) return null;
  const s = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!s || typeof s !== "object" || !s.last || typeof s.last.day !== "string" || typeof s.last.text !== "string" ||
      !Array.isArray(s.seen)) {
    throw new Error("the state file is not one this monitor wrote");
  }
  return s;
}

function writeState(file, s) {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(s, null, 1) + "\n");
  fs.renameSync(tmp, file);
}

async function main(argv = process.argv.slice(2), { fetchImpl = fetch, print = console.log } = {}) {
  const a = { sources: [] };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    const next = () => argv[++i];
    if (t === "--state") a.state = next();
    else if (t === "--since") a.since = next();
    else if (t === "--source") a.sources.push(String(next()).replace(/\/+$/, ""));
    else if (t === "--key") a.key = next();
    else if (t === "--allow-unsigned") a.allowUnsigned = true;
    else if (t === "--today") a.today = next();
    else if (t === "--json") a.json = true;
    else { print(`usage: unknown argument ${t}`); return 2; }
  }
  if (!a.state) { print("usage: --state <file> is required"); return 2; }
  if (!a.key && !a.allowUnsigned) { print("usage: pass --key <verifier key>, or --allow-unsigned"); return 2; }
  if (a.sources.length === 0) a.sources.push(DEFAULT_SOURCE);
  let state;
  try {
    state = readState(a.state);
  } catch (e) {
    print(`COULD NOT LOOK: the state file ${a.state} cannot be read: ${e.message}`);
    return 2;
  }
  const r = await run({ state, sources: a.sources, key: a.key || null, allowUnsigned: !!a.allowUnsigned,
    since: a.since || null, today: a.today || new Date().toISOString().slice(0, 10), fetchImpl });
  if (r.verdict === "VERIFIED") writeState(a.state, r.state);
  if (a.json) {
    print(JSON.stringify({ verdict: r.verdict, reason: r.reason, detail: r.detail, lines: r.lines }));
  } else {
    for (const l of r.lines) print(l);
    print(`${r.verdict}: ${r.reason}${r.detail ? `: ${r.detail}` : ""}`);
  }
  return r.code;
}

if (require.main === module) {
  main().then((code) => process.exit(code));
}

module.exports = { run, main, DEFAULT_SOURCE };
