// lib/_witness_log_health.js: the witness log's own health, for the status
// board and /api/status.json (the JSON the owner's hourly report reads).
// Underscore prefix = not routed as a serverless function by Vercel.
//
// Owner item (3), 2026-11-07: an alert that goes red when a UTC day has no
// checkpoint, or when the newest checkpoint has gone without an outside
// cosignature for over 36 hours. 2026-11-05 had no checkpoint and nothing
// anywhere said so; this is the reader that would have.
//
// status is ALWAYS one of "current" | "red" | "cannot_determine", and every
// red names its field in `red[]` ({ field, reason }):
//   field "missing_days": a UTC day from the first dated checkpoint to
//     yesterday has no log/checkpoints/<day>.txt, and no published gap record
//     (log/gaps/<date>.json, written by tools/publish_checkpoint.js) names it.
//     A day a gap record names is listed in missed_days_declared, and stays
//     listed for good, but is not red: the miss is on the public record and a
//     checkpoint is never backdated to close it, so red could never clear.
//     Today is not judged until it is over.
//   field "outside_cosignature": more than 36 hours since the start of the
//     UTC day of the newest checkpoint that carries an outside cosignature,
//     or no checkpoint carries one at all. Measured from the start of that
//     day, so the alert errs early, never late.
// "cannot_determine" (the listing could not be read, or holds no dated
// checkpoint) folds into the board's `indeterminate`, never into ok.
//
// HOW COSIGNATURES ARE READ (item (2) is built in parallel and was not pushed
// when this was written, so this is the file this reader expects):
//   log/checkpoints/<day>.cosignatures beside log/checkpoints/<day>.txt,
//   one signature line per cosigner, in the checkpoint's own signed note line
//   form: an em dash, a space, the key name, a space, base64. A line counts as
//   outside when its key name does not start with OWN_KEY_PREFIX (the
//   operator's checkpoint key). This reader checks presence and shape only. It
//   does NOT verify the signatures (it holds no cosigner keys), so green here
//   means "an outside line is on file", not "an outside witness verified".
//   The signed proof is for tools/follow.js and the cosigners' own keys.

"use strict";

const store = require("./_store.js");

const COSIGN_STALE_HOURS = 36;
const OWN_KEY_PREFIX = "arcaeon.io/witness-log/";
const CHECKPOINT_DIR = "log/checkpoints";
const GAPS_DIR = "log/gaps";
const MAX_GAP_RECORDS = 60; // bounded reads per request
const MAX_COSIGN_READS = 3;
const SIG_LINE = /^— (\S+) ([A-Za-z0-9+/]+={0,2})$/;

const DAY_TXT = /^(\d{4}-\d{2}-\d{2})\.txt$/;
const DAY_COSIGN = /^(\d{4}-\d{2}-\d{2})\.cosignatures$/;
const DAY_JSON = /^(\d{4}-\d{2}-\d{2})\.json$/;

function utcDay(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

// Outside cosignature lines in one .cosignatures text.
function outsideCosigners(text) {
  const names = [];
  for (const raw of String(text || "").split("\n")) {
    const m = SIG_LINE.exec(raw.replace(/\r$/, ""));
    if (m && !m[1].startsWith(OWN_KEY_PREFIX)) names.push(m[1]);
  }
  return names;
}

// Pure judgment over what was read. `declared` is a Set of days, or null when
// the gap records could not be read (then nothing counts as declared).
function judgeWitnessLog({ checkpointDays, declared, newestCosigned, nowMs }) {
  const days = [...checkpointDays].sort();
  const out = {
    status: "cannot_determine",
    red: [],
    first_day: days[0] || null,
    newest_day: days.length ? days[days.length - 1] : null,
    checkpoint_count: days.length,
    missing_days: [],
    missed_days_declared: [],
    newest_cosigned_day: newestCosigned ? newestCosigned.day : null,
    outside_cosigners: newestCosigned ? newestCosigned.names : [],
    cosignature_age_hours: null,
    cosignature_stale_hours: COSIGN_STALE_HOURS,
  };
  if (!days.length) return out;

  const have = new Set(days);
  const yesterday = utcDay(nowMs - 86400000);
  for (let t = Date.parse(`${days[0]}T00:00:00Z`); utcDay(t) <= yesterday; t += 86400000) {
    const d = utcDay(t);
    if (have.has(d)) continue;
    if (declared && declared.has(d)) out.missed_days_declared.push(d);
    else out.missing_days.push(d);
  }
  if (out.missing_days.length) {
    out.red.push({
      field: "missing_days",
      reason: `${out.missing_days.length} UTC day${out.missing_days.length === 1 ? " has" : "s have"} no checkpoint and no published gap record: ${out.missing_days.join(", ")}`,
    });
  }

  if (newestCosigned) {
    const age = (nowMs - Date.parse(`${newestCosigned.day}T00:00:00Z`)) / 3600000;
    out.cosignature_age_hours = Math.round(age * 10) / 10;
    if (age > COSIGN_STALE_HOURS) {
      out.red.push({
        field: "outside_cosignature",
        reason: `the newest checkpoint with an outside cosignature is ${newestCosigned.day}, ${out.cosignature_age_hours} hours ago (over ${COSIGN_STALE_HOURS})`,
      });
    }
  } else {
    out.red.push({ field: "outside_cosignature", reason: "no checkpoint carries an outside cosignature" });
  }
  out.status = out.red.length ? "red" : "current";
  return out;
}

async function gatherWitnessLog(nowMs = Date.now()) {
  const base = {
    cosignatures_read_from: `${CHECKPOINT_DIR}/<day>.cosignatures`,
    cosignatures_verified: false,
    gap_records_read_from: `${GAPS_DIR}/<date>.json`,
    error: null,
  };
  let names;
  try {
    names = (await store.listDir(CHECKPOINT_DIR)).filter((e) => e.type === "file").map((e) => e.name);
  } catch (err) {
    return { ...judgeWitnessLog({ checkpointDays: [], declared: null, newestCosigned: null, nowMs }), ...base, error: err.message };
  }
  const checkpointDays = names.map((n) => DAY_TXT.exec(n)).filter(Boolean).map((m) => m[1]);
  const cosignDays = names.map((n) => DAY_COSIGN.exec(n)).filter(Boolean).map((m) => m[1]).sort().reverse();

  const errors = [];
  let newestCosigned = null;
  for (const day of cosignDays.slice(0, MAX_COSIGN_READS)) {
    try {
      const raw = await store.getRawFile(`${CHECKPOINT_DIR}/${day}.cosignatures`);
      const who = raw ? outsideCosigners(raw.text) : [];
      if (who.length) {
        newestCosigned = { day, names: who };
        break;
      }
    } catch (err) {
      errors.push(`cosignatures ${day}: ${err.message}`);
    }
  }

  // A gap record that cannot be read declares nothing: its days stay red.
  let declared = new Set();
  try {
    const gapNames = (await store.listDir(GAPS_DIR))
      .filter((e) => e.type === "file" && DAY_JSON.test(e.name))
      .map((e) => e.name)
      .sort()
      .reverse()
      .slice(0, MAX_GAP_RECORDS);
    for (const n of gapNames) {
      try {
        const got = await store.getFile(`${GAPS_DIR}/${n}`);
        const list = got && got.json && Array.isArray(got.json.missed_days) ? got.json.missed_days : [];
        for (const d of list) if (typeof d === "string" && /^\d{4}-\d{2}-\d{2}$/.test(d)) declared.add(d);
      } catch (err) {
        errors.push(`gap record ${n}: ${err.message}`);
      }
    }
  } catch (err) {
    declared = null;
    errors.push(`gap records: ${err.message}`);
  }

  return {
    ...judgeWitnessLog({ checkpointDays, declared, newestCosigned, nowMs }),
    ...base,
    error: errors.length ? errors.join("; ") : null,
  };
}

module.exports = { gatherWitnessLog, judgeWitnessLog, outsideCosigners, COSIGN_STALE_HOURS, OWN_KEY_PREFIX };
