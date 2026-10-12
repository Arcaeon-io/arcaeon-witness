// test/helpers/mock_store.js — in-memory stand-in for the GitHub contents API
// that api/_store.js, api/_balance.js, and api/_meter.js all talk to over
// `fetch`. Not a test file itself (no `test()` calls) — a fixture the real
// test files require and drive.
//
// Contract mirrored from the real GitHub Contents API, as consumed by the
// three modules under test (read their getFile/putFile pairs before touching
// this — the CAS conflict shape is load-bearing to every regression here):
//
//   GET  /repos/<repo>/contents/<path>?ref=<branch>
//        -> 200 {content:<base64>, sha:<hex>}   | 404 if missing
//
//   PUT  /repos/<repo>/contents/<path>
//        body {message, branch, content:<base64>, sha?}
//        - sha OMITTED  + file exists     -> 422 {message:'..."sha" wasn\'t supplied...'}
//                                             (the CREATE-race shape; _store.js /
//                                             _balance.js / _meter.js all regex-match
//                                             this to set err.conflict = true)
//        - sha OMITTED  + file absent     -> 200, file created
//        - sha PROVIDED + doesn't match   -> 409 (the UPDATE-race shape)
//        - sha PROVIDED + matches         -> 200, file updated
//        on success: {content:{sha}, commit:{sha}}  (real shape; pin.js reads
//        `put.commit.sha` off exactly this)
//
// `forceConflict(repo, path, n)` lets a regression test simulate n concurrent
// writers colliding on one path — the shape that made THE money bug possible
// (two overlapping Stripe deliveries both winning a stale read).
//
//   GET  /repos/<repo>/commits?path=<path>&sha=<branch>&per_page=<n>
//        -> 200 [{sha, commit:{message, author:{date}, committer:{date}}}]
//        the commits that touched <path>, NEWEST FIRST, at most per_page
//        (2026-10-10, case protocol item 2a: lib/_store.js listCommits, read
//        by ?op=case-commit to fill a registration's stamp_commit). Every
//        successful PUT and DELETE is one commit touching its path, and its
//        sha is the `commit.sha` the PUT answered with. seed() gives its path
//        a history of exactly ONE commit (a file that "exists before any
//        handler runs" was committed once), replacing whatever history the
//        path had, so re-seeding a path to change its content in a test never
//        plants a second commit by accident. addCommit() plants one on
//        purpose; forceCommitsFailure() makes the read itself fail.
//
//   GET  https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>
//        -> 200 <the file's text> | 404
//        a public repository's file at one commit, read with no credentials
//        (2026-10-12, case protocol Design I: lib/_case_seal.js reads the key
//        document a sealed case names, at the commit it names). Served from
//        seedRaw(repo, ref, path, text), so one path can hold different text
//        at different commits; nothing else answers on this host. rawLog
//        records every read, and forceRawFailure() makes reads fail.

"use strict";

const crypto = require("crypto");
const ratelimit = require("../../lib/_ratelimit.js");

function textResponse(status, text) {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => JSON.parse(text),
    text: async () => text,
  };
}

function fakeResponse(status, bodyObj) {
  const bodyText = JSON.stringify(bodyObj);
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => bodyObj,
    text: async () => bodyText,
  };
}

class MockGitHubStore {
  constructor() {
    this.repos = new Map(); // repo -> Map(path -> {content, sha})
    this.commitCounter = 0;
    this.putLog = []; // [{repo, path, sha}] — every successful write, in order
    // Every GET, in order. Reader-side evidence: the STORE records what was asked
    // for, so a test can assert which records a handler actually walked instead of
    // trusting a count the handler itself printed. Added 2026-08-22 on ColonistOne's
    // and Rowan Adeyemi's push: `scanned === 50` binds to a field the code under test
    // authors, so a handler halting for the wrong cause and reporting 50 still passes.
    // This log is authored by the fixture, not by the handler.
    this.getLog = []; // [path] — every GET attempted, hit or miss, in order
    this._forced = new Map(); // "repo::path" -> remaining forced-conflict count
    this._forcedFailure = new Map(); // "repo::path" -> {remaining, status}
    // GET /repos/<repo>/git/trees/<branch>?recursive=1 -> {tree:[{path,type}], truncated}
    // Added 2026-09-20 for tools/reconcile_batches.js: the reconciler walks the
    // whole repo through store.getTreeMeta, and `truncated` is the field that
    // makes it say "could not look" instead of "clean". A fixture that could
    // not represent a truncated tree could not test that distinction at all.
    this.treeTruncated = false;
    this.treeStatus = 200; // set to 5xx to make the tree unreadable
    // Commit history (see the header): repo -> [{sha, path, message, date}],
    // oldest first. Commit shas are 40 lowercase hex, like git's.
    this.commits = new Map();
    this._commitSeq = 0;
    this.commitsLog = []; // [path] — every commits-for-path read, in order
    this._forcedCommitsFailure = new Map(); // "repo::path" -> {remaining, status}
    // Raw reads (see the header): "repo@ref:path" -> text.
    this.raw = new Map();
    this.rawLog = []; // ["repo@ref:path"] — every raw read, hit or miss, in order
    this._forcedRawFailure = null; // {remaining, status} for every raw path
  }

  // A public file's text at one commit, served on the raw host.
  seedRaw(repo, ref, path, text) {
    this.raw.set(`${repo}@${ref}:${path}`, String(text));
  }

  // Force the next `n` raw reads to fail with `status` (0: a network error).
  forceRawFailure(n = 1, status = 500) {
    this._forcedRawFailure = { remaining: n, status };
  }

  _commitsOf(repo) {
    if (!this.commits.has(repo)) this.commits.set(repo, []);
    return this.commits.get(repo);
  }

  _recordCommit(repo, path, message) {
    this._commitSeq += 1;
    const sha = crypto.createHash("sha1").update(`mock-commit-${this._commitSeq}`).digest("hex");
    this._commitsOf(repo).push({ sha, path, message: String(message || ""), date: new Date().toISOString() });
    return sha;
  }

  // Plant one more commit touching `path` (a second write to a path that
  // should have been written once). Returns its sha.
  addCommit(repo, path, message = "mock: an extra commit touching this path") {
    return this._recordCommit(repo, path, message);
  }

  // The commits that touched `path`, newest first (test assertions).
  commitsFor(repo, path) {
    return this._commitsOf(repo).filter((c) => c.path === path).slice().reverse();
  }

  // Force the next `n` commits-for-path reads of `path` to fail with `status`.
  forceCommitsFailure(repo, path, n = 1, status = 500) {
    this._forcedCommitsFailure.set(`${repo}::${path}`, { remaining: n, status });
  }

  _repoMap(repo) {
    if (!this.repos.has(repo)) this.repos.set(repo, new Map());
    return this.repos.get(repo);
  }

  _newSha() {
    return crypto.randomBytes(20).toString("hex");
  }

  // Seed a file as it would exist BEFORE any handler under test runs.
  seed(repo, path, obj) {
    this._repoMap(repo).set(path, {
      content: JSON.stringify(obj, null, 2) + "\n",
      sha: this._newSha(),
    });
    // exactly one commit for a seeded path (see the header)
    const list = this._commitsOf(repo);
    for (let i = list.length - 1; i >= 0; i -= 1) if (list[i].path === path) list.splice(i, 1);
    this._recordCommit(repo, path, "mock: seeded");
  }

  // Read back the current stored JSON for a path (test assertions).
  read(repo, path) {
    const rec = this._repoMap(repo).get(path);
    return rec ? JSON.parse(rec.content) : null;
  }

  has(repo, path) {
    return this._repoMap(repo).has(path);
  }

  // Force the next `n` PUTs to `path` to fail as a 409 conflict, regardless
  // of the sha sent — simulates n-1 losers of a concurrent-write race.
  forceConflict(repo, path, n = 1) {
    this._forced.set(`${repo}::${path}`, n);
  }

  // Force the next `n` PUTs to `path` to fail as a GENUINE (non-conflict)
  // store failure — a transient GitHub 5xx, not a racing writer. Distinct
  // from forceConflict on purpose: `err.conflict` must stay false so callers
  // exercise their real-failure path (2026-09-05 audit: pin.js charged a
  // credit/meter count and then hit exactly this shape with no compensating
  // refund — this fixture is what makes that regression reproducible).
  forceFailure(repo, path, n = 1, status = 500) {
    this._forcedFailure.set(`${repo}::${path}`, { remaining: n, status });
  }

  async handleFetch(url, opts) {
    const u = new URL(String(url));

    // Raw reads: see the header.
    if (u.hostname === "raw.githubusercontent.com") {
      const parts = u.pathname.split("/").filter(Boolean);
      const key = `${parts[0]}/${parts[1]}@${parts[2]}:${parts.slice(3).join("/")}`;
      this.rawLog.push(key);
      const forced = this._forcedRawFailure;
      if (forced && forced.remaining > 0) {
        forced.remaining -= 1;
        if (forced.status === 0) throw new TypeError("mock: fetch failed (forced network error)");
        return textResponse(forced.status, "mock: forced raw read failure");
      }
      if (((opts && opts.method) || "GET") !== "GET" || !this.raw.has(key)) return textResponse(404, "404: Not Found");
      return textResponse(200, this.raw.get(key));
    }

    // Recursive tree read (_store.js getTree / getTreeMeta):
    // GET /repos/<repo>/git/trees/<ref> -> {sha, tree:[{path,type:"blob",sha}...], truncated}.
    // Two lineages grew this on 2026-09-20/22 and both are kept: the sealer
    // reconciler's forced failure (treeStatus) and truncation (treeTruncated),
    // and the audit-state column's per-entry sha + GET-only routing. Every
    // seeded file is a blob; directories are not listed (the real API lists
    // them as "tree" entries, and nothing under test reads those).
    const tm = u.pathname.match(/^\/repos\/([^/]+\/[^/]+)\/git\/trees\/[^/]+$/);
    if (tm && ((opts && opts.method) || "GET") === "GET") {
      if (this.treeStatus !== 200) {
        return fakeResponse(this.treeStatus, { message: "mock: forced tree read failure" });
      }
      const tree = [];
      for (const [p, r] of this._repoMap(tm[1])) tree.push({ path: p, type: "blob", sha: r.sha });
      return fakeResponse(200, { sha: "mock-tree", tree, truncated: this.treeTruncated === true });
    }

    // Commits-for-path read (_store.js listCommits): see the header.
    const cm = u.pathname.match(/^\/repos\/([^/]+\/[^/]+)\/commits$/);
    if (cm && ((opts && opts.method) || "GET") === "GET") {
      const p = u.searchParams.get("path");
      this.commitsLog.push(p);
      const forced = this._forcedCommitsFailure.get(`${cm[1]}::${p}`);
      if (forced && forced.remaining > 0) {
        forced.remaining -= 1;
        return fakeResponse(forced.status, { message: "mock: forced commits read failure" });
      }
      const perPage = Math.max(1, Math.min(100, Number(u.searchParams.get("per_page")) || 30));
      const list = this._commitsOf(cm[1]).filter((c) => p === null || c.path === p).slice().reverse().slice(0, perPage);
      return fakeResponse(200, list.map((c) => ({
        sha: c.sha,
        commit: { message: c.message, author: { date: c.date }, committer: { date: c.date } },
      })));
    }

    const m = u.pathname.match(/^\/repos\/([^/]+\/[^/]+)\/contents\/(.+)$/);
    if (!m) return fakeResponse(404, { message: `mock: unhandled path ${u.pathname}` });

    const repo = m[1];
    const path = decodeURIComponent(m[2]);
    const method = (opts && opts.method) || "GET";
    const map = this._repoMap(repo);

    if (method === "GET") {
      this.getLog.push(path);
      const rec = map.get(path);
      if (rec) {
        return fakeResponse(200, {
          content: Buffer.from(rec.content, "utf-8").toString("base64"),
          sha: rec.sha,
        });
      }
      // Real GitHub contents API shape: GET on a DIRECTORY path returns an
      // ARRAY of entries (name/path/sha/type), not a {content} object.
      // lib/_keys.js listDir() consumes exactly this for prefix validation.
      const dirPrefix = path.endsWith("/") ? path : `${path}/`;
      const entries = [];
      const seenDirs = new Set();
      for (const [p, r] of map) {
        if (!p.startsWith(dirPrefix)) continue;
        const rest = p.slice(dirPrefix.length);
        if (rest && !rest.includes("/")) {
          entries.push({ name: rest, path: p, sha: r.sha, type: "file" });
        } else if (rest) {
          // 2026-09-19: the real contents API lists immediate SUBDIRECTORIES
          // too (type "dir"). Without this the mock could not represent
          // pins/<namespace>/latest.json at all, so nothing that walks the
          // namespace tree (the status page) could be tested against it.
          const seg = rest.split("/")[0];
          if (!seenDirs.has(seg)) {
            seenDirs.add(seg);
            entries.push({ name: seg, path: dirPrefix + seg, sha: null, type: "dir" });
          }
        }
      }
      if (entries.length) return fakeResponse(200, entries);
      return fakeResponse(404, { message: "Not Found" });
    }

    if (method === "PUT") {
      const body = JSON.parse(opts.body);
      const cur = map.get(path);
      const forceKey = `${repo}::${path}`;
      const forced = this._forced.get(forceKey);
      if (forced && forced > 0) {
        this._forced.set(forceKey, forced - 1);
        return fakeResponse(409, { message: "mock: forced conflict (simulated racing writer)" });
      }
      const forcedFail = this._forcedFailure.get(forceKey);
      if (forcedFail && forcedFail.remaining > 0) {
        forcedFail.remaining -= 1;
        return fakeResponse(forcedFail.status, { message: "mock: forced non-conflict store failure" });
      }

      if (body.sha) {
        if (!cur || cur.sha !== body.sha) {
          return fakeResponse(409, { message: "sha does not match current file sha" });
        }
      } else if (cur) {
        // Create-race shape: two writers both tried to create the same
        // not-yet-existing file. GitHub's real error text for this.
        return fakeResponse(422, { message: 'Invalid request.\n\n"sha" wasn\'t supplied.' });
      }

      const decoded = Buffer.from(body.content, "base64").toString("utf-8");
      const newSha = this._newSha();
      map.set(path, { content: decoded, sha: newSha });
      this.commitCounter += 1;
      this.putLog.push({ repo, path, sha: newSha });
      const commitSha = this._recordCommit(repo, path, body.message);
      return fakeResponse(200, {
        content: { sha: newSha, path },
        commit: { sha: commitSha },
      });
    }

    if (method === "DELETE") {
      map.delete(path);
      this._recordCommit(repo, path, "mock: delete");
      return fakeResponse(200, { ok: true });
    }

    return fakeResponse(405, { message: `mock: unsupported method ${method}` });
  }
}

// Patches global.fetch to route through `store`, and gives the test a fresh
// lib/_ratelimit.js limiter (per-instance memory): every address's and every
// key's budget starts unspent, as on a fresh instance. The budgets are kept
// on the real clock, so without this one key's opens add up across a whole
// test file (lib/_ratelimit.js, PER-KEY BUCKETS). Returns a restore function —
// ALWAYS call it in an afterEach, or one test's mock store leaks into the next.
function install(store) {
  const original = global.fetch;
  global.fetch = (url, opts) => store.handleFetch(url, opts);
  ratelimit.setStore(null);
  return function restore() {
    global.fetch = original;
  };
}

module.exports = { MockGitHubStore, install };
