// _capacity.js — the capacity view behind GET /api/health?view=capacity:
// GitHub writes in the last hour against a write budget per hour.
// Underscore prefix = not routed as a serverless function.
//
// USED is counted, not estimated: the number of commits on each repo's branch
// in the last 60 minutes, from the commits API, one request per repo (asked
// for one commit per page, the "last" page number in the Link header is the
// count). Every pin, batch root and meter update is one commit, so commits are
// writes. Two honest edges:
//   - a commit made by hand (the owner editing a file) counts too;
//   - with WITNESS_USAGE_STORE=postgres the meter and pending writes are not
//     GitHub commits any more and so are not counted here, which is the point.
// A count that cannot be read is null with a reason, never 0.
//
// THE BUDGET is an input, not a fact this code claims to know about GitHub:
// WITNESS_WRITE_BUDGET_PER_HOUR (a positive integer) and
// WITNESS_WRITE_BUDGET_LABEL (where the number came from, in the operator's
// words). Unset budget: the view reports usage and says no budget is set.

"use strict";

const store = require("./_store.js");

const API = "https://api.github.com";
const WINDOW_MS = 3600_000;

function usageTarget() {
  // The private usage repo uses the same PAT as the pins repo (lib/_meter.js:
  // "Reuses GITHUB_PIN_TOKEN"), so the same token env is named here.
  return {
    repo: process.env.GITHUB_USAGE_REPO || "dan8433-user/arcaeon-witness-usage",
    branch: process.env.GITHUB_USAGE_BRANCH || "main",
    tokenEnv: "GITHUB_PIN_TOKEN",
    ua: "arcaeon-witness-capacity",
  };
}

function lastPage(link) {
  if (typeof link !== "string") return null;
  for (const part of link.split(",")) {
    if (/rel="last"/.test(part)) {
      const m = /[?&]page=(\d+)/.exec(part);
      if (m) return Number(m[1]);
    }
  }
  return null;
}

// -> {count} | {count:null, reason}
async function commitsSince(target, sinceIso) {
  const url = `${API}/repos/${target.repo}/commits?sha=${encodeURIComponent(target.branch)}` +
    `&since=${encodeURIComponent(sinceIso)}&per_page=1`;
  let r;
  try {
    r = await fetch(url, { headers: store.ghHeadersFor(target) });
  } catch (_e) {
    return { count: null, reason: "unreachable" };
  }
  if (r.status === 409) return { count: 0 }; // an empty repo has no commits at all
  if (!r.ok) return { count: null, reason: `http_${r.status}` };
  let body;
  try { body = await r.json(); } catch (_e) { return { count: null, reason: "unreadable" }; }
  if (!Array.isArray(body)) return { count: null, reason: "unreadable" };
  if (body.length === 0) return { count: 0 };
  const link = r.headers && typeof r.headers.get === "function" ? r.headers.get("link") : null;
  const last = lastPage(link);
  return { count: last === null ? body.length : last };
}

// -> {per_hour, label} | null | {error, field}
function budgetFromEnv(env = process.env) {
  const raw = env.WITNESS_WRITE_BUDGET_PER_HOUR;
  if (raw === undefined || String(raw).trim() === "") return null;
  const n = Number(String(raw).trim());
  if (!Number.isSafeInteger(n) || n < 1) {
    return { error: "WITNESS_WRITE_BUDGET_PER_HOUR must be a positive whole number", field: "WITNESS_WRITE_BUDGET_PER_HOUR" };
  }
  const label = String(env.WITNESS_WRITE_BUDGET_LABEL || "").trim();
  return { per_hour: n, label: label || "unlabelled: set WITNESS_WRITE_BUDGET_LABEL to say where this number comes from" };
}

async function capacityView({ now = Date.now() } = {}) {
  const since = new Date(now - WINDOW_MS).toISOString();
  const [pub, priv] = await Promise.all([
    commitsSince(store.PINS_TARGET, since),
    commitsSince(usageTarget(), since),
  ]);
  const counted = pub.count !== null && priv.count !== null;
  const total = counted ? pub.count + priv.count : null;
  const budget = budgetFromEnv();
  const view = {
    window: { since, until: new Date(now).toISOString(), minutes: 60 },
    writes: {
      public: pub.count,
      private: priv.count,
      total,
      counted_by: "commits on each repo's branch in the window",
    },
    budget: null,
    used_fraction: null,
    headroom: null,
    complete: counted,
  };
  if (!counted) {
    view.could_not_count = {};
    if (pub.count === null) view.could_not_count.public = pub.reason;
    if (priv.count === null) view.could_not_count.private = priv.reason;
  }
  if (budget === null) {
    view.budget = { set: false, note: "no budget set: WITNESS_WRITE_BUDGET_PER_HOUR and WITNESS_WRITE_BUDGET_LABEL" };
  } else if (budget.error) {
    view.budget = { set: false, error: budget.error, field: budget.field };
  } else {
    view.budget = { set: true, per_hour: budget.per_hour, label: budget.label, source: "WITNESS_WRITE_BUDGET_PER_HOUR" };
    if (counted) {
      view.used_fraction = Math.round((total / budget.per_hour) * 1000) / 1000;
      view.headroom = budget.per_hour - total;
    }
  }
  return view;
}

module.exports = { capacityView, commitsSince, budgetFromEnv, lastPage, WINDOW_MS };
