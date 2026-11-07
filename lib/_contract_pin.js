// lib/_contract_pin.js: POST /witness/v1/pins, the join's pin route (W-J1,
// first slice). Reached by a rewrite onto /api/pin?op=contract, so the
// count of functions under api/ does not grow.
//
// It takes the desktop's contract pin exactly as the reference witness
// does (its canonical bytes as the body, the pinner's public key in the
// Public-Key header) and answers with exactly a contract receipt signed by
// the witness's contract key (lib/_contract_key.js).
//
// It is paid from ONE balance: the bearer key in Authorization pays through
// the very same charge the plain pin path uses (api/pin.js meterAndCharge):
// that key's free allowance for the month first, then its bought credits.
// So a pack bought once is spent once, whether the pin comes from the
// desktop, the pip client or the MCP server. Nothing on this route reads or
// writes the account service: the account's record only grants are kept
// there as records and never spent here or anywhere.
//
// The charge is taken only once every check that can refuse the pin has
// passed, right before the row is written. A replay of the newest row is
// answered with its receipt and charged nothing. A credit taken for a row
// whose write then failed, or lost a race to the same pin, is given back.
//
// Every refusal is {"field", "reason", "status": "REFUSED"} and names the
// field at fault. No refusal carries a balance or a buy link, and no
// billing fact travels in a header (both are open questions for the owner).
// One log line per request: method, path, status, namespace. Never the
// body, the Public-Key value, the bearer key or its hash, or any setting.
"use strict";

const c = require("./_contract.js");
const contractKey = require("./_contract_key.js");
const cstore = require("./_contract_store.js");
const storeLib = require("./_store.js");
const issuedKeys = require("./_keys.js");

const MAX_BODY = 8192;
const MAX_PIN = 2048;
const MAX_BEARER = 256;

function send(res, status, obj) {
  const bytes = c.canonical(obj);
  res.setHeader("content-type", "application/json");
  res.setHeader("content-length", String(bytes.length));
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("cache-control", "no-store");
  res.status(status);
  res.send(bytes);
}

function headerCount(req, name) {
  if (Array.isArray(req.rawHeaders)) {
    let n = 0;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if (String(req.rawHeaders[i]).toLowerCase() === name) n += 1;
    }
    return n;
  }
  return req.headers[name] === undefined ? 0 : 1;
}

// The body's bytes, read from the request stream itself. Returns null when
// the runtime has no unread stream to give, so a parsed body is never
// written out again and taken for the bytes sent.
function readRaw(req, size) {
  return new Promise((resolve) => {
    if (typeof req.on !== "function" || req.readableEnded) return resolve(null);
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total <= size + 1) chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", () => resolve(null));
  });
}

async function handle(req, res, deps) {
  let ns = "-";
  const refuse = (status, field, reason) => {
    send(res, status, { field, reason, status: "REFUSED" });
    return status;
  };
  const answer = async () => {
    // 1. method and query
    if (req.method !== "POST") {
      res.setHeader("allow", "POST");
      return refuse(405, "method", "send the pin with POST");
    }
    const query = req.query || {};
    if (Object.keys(query).some((k) => k !== "op")) {
      return refuse(400, "query", "this path takes no query");
    }

    // 2. the body's length, then its bytes
    if (req.headers["transfer-encoding"] !== undefined) {
      return refuse(400, "transfer-encoding", "send the body with a Content-Length instead");
    }
    const len = req.headers["content-length"];
    if (len === undefined) return refuse(411, "content-length", "the Content-Length header is missing");
    if (headerCount(req, "content-length") > 1 || !/^[0-9]{1,6}$/.test(String(len))) {
      return refuse(400, "content-length", "the Content-Length header must be one whole number");
    }
    const size = Number(len);
    if (size > MAX_BODY) return refuse(413, "content-length", `the body is larger than ${MAX_BODY} bytes`);
    const raw = await readRaw(req, size);
    if (raw === null) return refuse(503, "body", "the witness could not read the bytes sent; nothing was written; try again later");
    if (raw.length !== size) return refuse(400, "body", "the body does not hold Content-Length bytes");

    // 3. the witness key
    let wkey;
    try {
      wkey = contractKey.load();
    } catch (err) {
      return refuse(503, err.field === "statement" ? "statement" : "key", err.reason);
    }

    // 4. the bearer key pays; it is required in this slice
    const auths = headerCount(req, "authorization");
    const auth = req.headers.authorization;
    const m = typeof auth === "string" ? /^Bearer (\S{1,256})$/.exec(auth) : null;
    if (auths !== 1 || !m || m[1].length > MAX_BEARER) {
      return refuse(401, "bearer", "send the pack's key once as Authorization: Bearer <key>; it pays for the pin");
    }
    const key = m[1];
    let prefix = storeLib.keyPrefixFor(key);
    if (prefix === null) {
      let looked;
      try {
        looked = await issuedKeys.lookupIssuedPrefix(req, key);
      } catch {
        return refuse(503, "bearer", "the witness cannot check keys now; nothing was written; try again later");
      }
      if (looked.limited) {
        res.setHeader("retry-after", String(looked.retryAfterSeconds));
        return refuse(429, "bearer", "too many unknown keys came from your network address; try again later");
      }
      prefix = looked.prefix;
    }
    if (prefix === null) return refuse(401, "bearer", "this key is not a key the witness issued");

    // 5. the same per key rate limit as the plain path
    if (deps.rateLimited(key)) return refuse(429, "bearer", "too many pins for this key this hour; try again later");

    // 6. the pin's shape, and the bytes it came as
    let pin;
    try {
      pin = c.readPin(c.parse(raw, "pin"));
    } catch (err) {
      return refuse(422, err.field || "pin", err.reason || "the pin cannot be read");
    }
    if (!c.canonical(pin).equals(raw)) {
      return refuse(422, "pin", "the body is not the pin's canonical bytes: no white space, keys in order, no needless escape and no trailing newline");
    }
    if (raw.length > MAX_PIN) return refuse(422, "pin", `the pin is larger than ${MAX_PIN} bytes`);
    ns = pin.namespace;
    const pkCount = headerCount(req, "public-key");
    const pk = req.headers["public-key"];
    if (pkCount > 1 || (typeof pk === "string" && pk.includes(","))) {
      return refuse(400, "public_key", "the Public-Key header must be sent once");
    }
    if (typeof pk !== "string" || !/^[0-9a-f]{64}$/.test(pk)) {
      return refuse(422, "public_key", "the pinner's public key must travel beside the pin as exactly 64 lower case hex characters");
    }

    // 7. the signature
    const pub = Buffer.from(pk, "hex");
    if (c.keyId(pub) !== pin.key_id) return refuse(422, "key_id", "is not the SHA-256 of the public key that came with the pin");
    if (!c.verify(pin, pub)) return refuse(422, "sig", "does not verify under the key named by key_id");

    // 8. the bearer key's namespace prefix (the conservative reading; an
    // open question for the owner)
    if (!pin.namespace.startsWith(prefix)) {
      return refuse(403, "namespace", "this key pays only for namespaces that start with its prefix");
    }

    // 9. the namespace and the sequence, before any charge
    const judge = (newest) => {
      if (!newest) return { add: true };
      if (newest.pin.key_id !== pin.key_id) {
        return { refuse: [422, "key_id", "this namespace belongs to another pinner's key"] };
      }
      if (c.samePoint(newest.pin, pin)) return { replay: newest };
      const last = newest.pin.head;
      if (pin.head.n === last.n && pin.head.chain !== last.chain) {
        return { refuse: [422, "head.chain", `this witness already holds a pin for n ${last.n} with another chain; a pin is never replaced`] };
      }
      if (pin.head.n === last.n) {
        return { refuse: [422, "root", `this witness already holds a pin for this head, n ${last.n}, ${"root" in newest.pin ? "with" : "without"} a root; a pin is never replaced`] };
      }
      if (pin.head.n < last.n) {
        return { refuse: [422, "head.n", `must be greater than the n of the last pin held, ${last.n}`] };
      }
      return { add: true };
    };

    let state;
    try {
      state = await cstore.readNewest(ns);
    } catch (err) {
      if (err instanceof cstore.Broken) return refuse(409, "namespace", err.reason);
      return refuse(503, "storage", err.reason || "the witness cannot read its store now; try again later");
    }
    const verdict = judge(state.newest);
    if (verdict.refuse) return refuse(...verdict.refuse);
    if (verdict.replay) {
      send(res, 200, c.makeReceipt(wkey.privateKey, verdict.replay));
      return 200;
    }

    // 10. the charge, from the one balance
    const charge = await deps.meterAndCharge(key);
    if (charge.deny) {
      const s = charge.deny.status;
      if (s === 402 || s === 429) {
        return refuse(402, "plan", "this key has no pins left this month; nothing was pinned. Top up to go on, or wait for the first of the month");
      }
      if (s === 401) return refuse(403, "bearer", "this key has no usage plan set up, so it pays for nothing");
      return refuse(503, "plan", "the witness cannot read its usage store now; nothing was pinned; try again later");
    }

    // 11. the row, create only
    const seq = state.newest ? state.newest.seq + 1 : 1;
    const prev = state.newest ? state.newest.chain : c.ZERO_ROW_CHAIN;
    const row = c.makeRow(seq, c.formatTime(new Date()), pin, prev, pk);
    try {
      await cstore.createRow(ns, row);
    } catch (err) {
      await deps.refundFailedWrite(key, charge.source, ns, seq, err);
      if (err && err.conflict) {
        // Another pin took this place first. If it was this same pin, its
        // receipt is the answer; nothing more is spent.
        try {
          const again = await cstore.readNewest(ns);
          const v = judge(again.newest);
          if (v.replay) {
            send(res, 200, c.makeReceipt(wkey.privateKey, v.replay));
            return 200;
          }
          if (v.refuse) return refuse(...v.refuse);
        } catch {
          // fall through to the plain answer below
        }
        return refuse(503, "storage", "another pin took this place in the log first; nothing was charged; send the pin again");
      }
      return refuse(503, "storage", "the witness could not write the row; nothing was charged; try again later");
    }

    // 12. the pointer, best effort, then the receipt
    await cstore.movePointer(ns, row, state.pointerSha);
    send(res, 201, c.makeReceipt(wkey.privateKey, row));
    return 201;
  };

  let status;
  try {
    status = await answer();
  } catch {
    status = refuse(503, "storage", "the witness could not finish this pin; try again later");
  }
  console.log(`[contract] POST /witness/v1/pins ${status} ${ns}`);
}

module.exports = { handle };
