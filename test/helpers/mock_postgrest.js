// test/helpers/mock_postgrest.js — in-memory stand-in for the PostgREST
// usage_docs table that lib/_usage_store.js talks to when
// WITNESS_USAGE_STORE=postgres. A fixture, not a test file.
//
// Mirrors only what lib/_usage_store.js sends:
//   GET    /rest/v1/usage_docs?path=eq.<p>&select=doc,version  -> 200 [row] | 200 []
//   POST   /rest/v1/usage_docs   body {path, doc, version, note, updated_at}
//          -> 201 | 409 {code:"23505"} when the path exists (unique violation)
//   PATCH  /rest/v1/usage_docs?path=eq.<p>&version=eq.<n>   body {doc, version, ...}
//          -> 200 [updated row] | 200 [] when no row matched (the lost race)
//   POST   /rest/v1/rpc/pin_rate_hit   body {p_key_hash, p_window_start}
//          -> 200 <hits after this one>, one atomic increment per call
//
// installBoth(gh, pg) routes one global fetch to the GitHub mock or to this
// one by host, so a pin can run against both stores at once and a test can
// count the writes each one took.

"use strict";

const PG_URL = "https://pg.test.invalid";

function fakeResponse(status, bodyObj) {
  const bodyText = bodyObj === undefined ? "" : JSON.stringify(bodyObj);
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => bodyObj,
    text: async () => bodyText,
  };
}

class MockPostgrest {
  constructor() {
    this.rows = new Map(); // path -> {path, doc, version, note, updated_at}
    this.writeLog = []; // [{method, path}] every successful write, in order
    this.requests = []; // [{method, url, headers}] every request, for header checks
    this._failNext = 0;
    this._failStatus = 500;
    this._failSkip = 0;
    this._raceNext = 0;
    this.rateWindows = new Map(); // "hash|window_start" -> hits
    this.rpcLog = []; // [{fn, args}] every database function call, in order
  }

  // The next n requests answer `status` (a database outage), after letting
  // `skip` requests through first.
  failNext(n = 1, status = 500, skip = 0) {
    this._failNext = n;
    this._failStatus = status;
    this._failSkip = skip;
  }

  // The next n PATCHes find no row at their version, as if another writer
  // moved it first.
  raceNext(n = 1) {
    this._raceNext = n;
  }

  read(path) {
    const r = this.rows.get(path);
    return r ? JSON.parse(JSON.stringify(r.doc)) : null;
  }

  seed(path, doc, version = 1) {
    this.rows.set(path, { path, doc, version, note: "seed", updated_at: new Date().toISOString() });
  }

  async handleFetch(url, opts = {}) {
    const u = new URL(String(url));
    const method = opts.method || "GET";
    this.requests.push({ method, url: String(url), headers: { ...(opts.headers || {}) } });
    if (this._failNext > 0 && this._failSkip > 0) {
      this._failSkip -= 1;
    } else if (this._failNext > 0) {
      this._failNext -= 1;
      return fakeResponse(this._failStatus, { message: "mock: forced database failure" });
    }
    if (u.pathname === "/rest/v1/rpc/pin_rate_hit" && method === "POST") {
      const args = JSON.parse(opts.body);
      this.rpcLog.push({ fn: "pin_rate_hit", args });
      const k = `${args.p_key_hash}|${args.p_window_start}`;
      const n = (this.rateWindows.get(k) || 0) + 1;
      this.rateWindows.set(k, n);
      return fakeResponse(200, n);
    }
    if (u.pathname !== "/rest/v1/usage_docs") {
      return fakeResponse(404, { message: `mock: unhandled path ${u.pathname}` });
    }
    const filt = (name) => {
      const v = u.searchParams.get(name);
      if (v === null) return null;
      if (!v.startsWith("eq.")) throw new Error(`mock: unsupported filter ${name}=${v}`);
      return v.slice(3);
    };
    const path = filt("path");

    if (method === "GET") {
      const r = this.rows.get(path);
      return fakeResponse(200, r ? [{ doc: JSON.parse(JSON.stringify(r.doc)), version: r.version }] : []);
    }
    if (method === "POST") {
      const body = JSON.parse(opts.body);
      if (this.rows.has(body.path)) {
        return fakeResponse(409, { code: "23505", message: "duplicate key value violates unique constraint" });
      }
      this.rows.set(body.path, { ...body });
      this.writeLog.push({ method, path: body.path });
      return fakeResponse(201, undefined);
    }
    if (method === "PATCH") {
      const body = JSON.parse(opts.body);
      const want = Number(filt("version"));
      const r = this.rows.get(path);
      if (this._raceNext > 0) {
        this._raceNext -= 1;
        if (r) r.version += 1; // the racing writer's update
        return fakeResponse(200, []);
      }
      if (!r || r.version !== want) return fakeResponse(200, []);
      Object.assign(r, body);
      this.writeLog.push({ method, path });
      return fakeResponse(200, [{ ...r }]);
    }
    return fakeResponse(405, { message: `mock: unsupported method ${method}` });
  }
}

function installBoth(gh, pg) {
  const original = global.fetch;
  global.fetch = (url, opts) =>
    String(url).startsWith(PG_URL) ? pg.handleFetch(url, opts) : gh.handleFetch(url, opts);
  return function restore() {
    global.fetch = original;
  };
}

module.exports = { MockPostgrest, installBoth, PG_URL };
