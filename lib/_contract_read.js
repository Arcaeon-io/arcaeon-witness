// lib/_contract_read.js: the join's reads (W-J1, first slice), reached by
// rewrites onto /api/latest?op=contract-*, so the count of functions under
// api/ does not grow:
//
//   GET /witness/v1/key               {"key_id", "public_key"} of the contract key
//   GET /witness/v1/statement         the key's signed witness_statement, its bytes
//   GET /witness/v1/pins/<ns>/receipt the contract receipt of the newest row
//   GET /witness/v1/pins/<ns>         the signed rows answer, newest first,
//                                     with an optional limit from 1 to 1000
//
// The rows answer is the reference witness's answer form: every row as
// stored, each signed by the witness key, and an envelope that signs the
// count, the newest chain and the time it was served. Every row is checked
// from row 1 before anything is signed, so an edited row is refused naming
// namespace and never signed. No query beyond what the route sets is taken.
"use strict";

const c = require("./_contract.js");
const contractKey = require("./_contract_key.js");
const cstore = require("./_contract_store.js");

const ALLOWED = {
  "contract-key": ["op"],
  "contract-statement": ["op"],
  "contract-receipt": ["op", "ns"],
  "contract-rows": ["op", "ns", "limit"],
};

function send(res, status, bytes) {
  res.setHeader("content-type", "application/json");
  res.setHeader("content-length", String(bytes.length));
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("cache-control", "no-store");
  res.status(status);
  res.send(bytes);
}

function isOp(op) {
  return Object.prototype.hasOwnProperty.call(ALLOWED, op);
}

async function handle(req, res) {
  const query = req.query || {};
  const op = query.op;
  const refuse = (status, field, reason) => send(res, status, c.canonical({ field, reason, status: "REFUSED" }));

  if (Object.keys(query).some((k) => !ALLOWED[op].includes(k))) return refuse(400, "query", "this path takes no query");

  let wkey;
  try {
    wkey = contractKey.load();
  } catch (err) {
    return refuse(503, err.field === "statement" ? "statement" : "key", err.reason);
  }
  if (op === "contract-key") return send(res, 200, c.canonical({ key_id: wkey.keyId, public_key: wkey.publicHex }));
  if (op === "contract-statement") return send(res, 200, wkey.statementBytes);

  const ns = query.ns;
  if (!c.isNamespace(ns)) return refuse(404, "namespace", "no such namespace");
  let limit = null;
  if (op === "contract-rows" && query.limit !== undefined) {
    if (typeof query.limit !== "string" || !/^[1-9][0-9]{0,3}$/.test(query.limit) || Number(query.limit) > 1000) {
      return refuse(400, "limit", "limit must be a whole number from 1 to 1000");
    }
    limit = Number(query.limit);
  }
  try {
    const { newest } = await cstore.readNewest(ns);
    if (!newest) return refuse(404, "namespace", "this witness holds no contract pin for this namespace");
    if (op === "contract-receipt") return send(res, 200, c.canonical(c.makeReceipt(wkey.privateKey, newest)));
    let rows = await cstore.readAll(ns, newest);
    if (limit !== null) rows = rows.slice(0, limit);
    return send(res, 200, c.canonical(c.makeAnswer(wkey.privateKey, ns, rows, c.formatTime(new Date()))));
  } catch (err) {
    if (err instanceof cstore.Broken) return refuse(409, "namespace", err.reason);
    return refuse(503, "storage", (err && err.reason) || "the witness cannot read its store now; try again later");
  }
}

module.exports = { handle, isOp };
