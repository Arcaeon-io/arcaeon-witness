// _plain_promises.js — the merge delay promise and the capacity view, in plain
// words, for the public status page (owner job 12). Underscore prefix = not
// routed as a serverless function.
//
// THE MERGE DELAY PROMISE. What this witness promises about how soon an
// accepted pin is in a signed checkpoint of its log. A pin is in the public
// record the moment it is accepted (its commit); a signed checkpoint covers it
// only when the next checkpoint is published (tools/publish_checkpoint.js).
// The promise is the operator's word, set as an input, never assumed:
//
//   WITNESS_MERGE_DELAY_HOURS   a whole number of hours, 1 to 8760
//   WITNESS_MERGE_DELAY_LABEL   optional: where the number comes from
//
// Unset, the page says plainly that no promise is published. Not a positive
// whole number, it says the setting is not readable, and promises nothing.
//
// THE CAPACITY VIEW is lib/_capacity.js's: GitHub writes in the last hour
// against a labelled budget. These words never turn a count that could not be
// read into 0, and never give a fraction when no budget is set.

"use strict";

function promiseFromEnv(env = process.env) {
  const raw = env.WITNESS_MERGE_DELAY_HOURS;
  if (raw === undefined || String(raw).trim() === "") return { set: false };
  const n = Number(String(raw).trim());
  if (!Number.isSafeInteger(n) || n < 1 || n > 8760) {
    return { set: false, error: "WITNESS_MERGE_DELAY_HOURS is not a whole number of hours from 1 to 8760",
      field: "WITNESS_MERGE_DELAY_HOURS" };
  }
  const label = String(env.WITNESS_MERGE_DELAY_LABEL || "").trim();
  return { set: true, hours: n, label: label || null };
}

function promiseWords(p) {
  if (p.error) return `The merge delay setting cannot be read (${p.field}), so this witness promises nothing about it.`;
  if (!p.set) {
    return "This witness publishes no merge delay promise. A pin is in the public record the moment it is " +
      "accepted; how soon a signed checkpoint covers it is not promised.";
  }
  return `A pin is in the public record the moment it is accepted, and this witness promises it is in a signed ` +
    `checkpoint of its log within ${p.hours} hour${p.hours === 1 ? "" : "s"}.` +
    (p.label ? ` (${p.label})` : "") +
    " Anyone can check it: the checkpoint's size counts every pin it covers.";
}

function capacityWords(c) {
  if (!c) return "The capacity view could not be gathered just now.";
  const w = c.writes || {};
  const parts = [];
  if (!c.complete) {
    const which = Object.keys(c.could_not_count || {}).join(" and ") || "some";
    parts.push(`In the last hour the ${which} write count could not be read, so no total is given.`);
  } else {
    parts.push(`In the last hour this witness made ${w.total} GitHub write${w.total === 1 ? "" : "s"}: ` +
      `${w.public} to the public record and ${w.private} to its private bookkeeping.`);
  }
  const b = c.budget || {};
  if (b.error) {
    parts.push(`The write budget setting cannot be read (${b.field}), so no headroom is given.`);
  } else if (!b.set) {
    parts.push("No write budget is set, so no headroom is given.");
  } else if (c.complete) {
    const pct = Math.round(c.used_fraction * 100);
    parts.push(`Against a budget of ${b.per_hour} an hour (${b.label}), that is ${pct} percent, ` +
      `leaving ${c.headroom}.`);
  } else {
    parts.push(`The budget is ${b.per_hour} an hour (${b.label}).`);
  }
  return parts.join(" ");
}

module.exports = { promiseFromEnv, promiseWords, capacityWords };
