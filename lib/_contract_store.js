// lib/_contract_store.js: where contract rows are kept, in the public pin
// store, beside and apart from the plain pins (which stay under pins/).
//
//   contract/<ns>/rows/<seq as 12 digits>.json   the row: the record. Created
//                                                once, never written again.
//   contract/<ns>/head.json                      a pointer: a copy of the
//                                                newest row. A hint, never
//                                                the record; it only moves
//                                                forward.
//
// A row is exactly the reference witness's contract row:
//   {chain, pin, prev, public_key, received_at, seq}
// seq counts from 1 per namespace with no gap, prev is the previous row's
// chain (32 zeros for row 1), and chain is the first 32 hex of SHA-256 over
// prev followed by the canonical row without chain.
//
// Nothing here deletes or rewrites a row. A read that finds a row it cannot
// trust throws a Broken error (the namespace is refused naming namespace),
// and a store that cannot be read throws an Unavailable error (refused
// naming storage). Neither is ever read as an empty namespace.
"use strict";

const store = require("./_store.js");
const c = require("./_contract.js");

const ROW_KEYS = ["chain", "pin", "prev", "public_key", "received_at", "seq"];
// How many rows past the pointer a read looks for. A row is past the
// pointer only when a pin's pointer move failed after its row was made.
const MAX_AHEAD = 32;
// The most rows one rows answer reads, one store read each.
const MAX_ROWS_READ = 1000;

class Broken extends Error {
  constructor(reason) {
    super(reason);
    this.field = "namespace";
    this.reason = reason;
  }
}

class Unavailable extends Error {
  constructor(reason) {
    super(reason);
    this.field = "storage";
    this.reason = reason;
  }
}

function rowPath(ns, seq) {
  return `contract/${ns}/rows/${String(seq).padStart(12, "0")}.json`;
}

function headPath(ns) {
  return `contract/${ns}/head.json`;
}

async function read(path) {
  try {
    return await store.getFile(path);
  } catch {
    throw new Unavailable("the witness cannot read its store now; nothing was written; try again later");
  }
}

// Judge one stored row. `prev` is the chain the row must follow, or null
// when the row before it was not read (the pointer's row).
function checkRow(row, ns, seq, prev) {
  const bad = (why) => new Broken(`the stored row ${seq} of this namespace ${why}, so nothing more is added to it or signed for it`);
  if (row === null || typeof row !== "object" || Array.isArray(row)) throw bad("is not a row");
  const keys = Object.keys(row).sort();
  if (keys.length !== ROW_KEYS.length || keys.some((k, i) => k !== ROW_KEYS[i])) throw bad("does not hold the fields of a row");
  if (row.seq !== seq) throw bad("names another place in the log");
  if (prev !== null && row.prev !== prev) throw bad("does not follow the row before it");
  if (seq === 1 && row.prev !== c.ZERO_ROW_CHAIN) throw bad("does not start the log");
  if (!c.isTime(row.received_at)) throw bad("holds no readable time");
  try {
    c.readPin(row.pin);
    c.canonical(row);
  } catch {
    throw bad("holds a pin that cannot be read");
  }
  if (row.pin.namespace !== ns) throw bad("holds a pin for another namespace");
  if (typeof row.public_key !== "string" || !/^[0-9a-f]{64}$/.test(row.public_key)) throw bad("holds no readable key");
  const raw = Buffer.from(row.public_key, "hex");
  if (c.keyId(raw) !== row.pin.key_id || !c.verify(row.pin, raw)) throw bad("holds a pin its key did not sign");
  if (c.rowChain(row) !== row.chain) throw bad("does not match its own chain");
  return row;
}

// The newest row of a namespace, or null for a namespace with none.
// Returns {newest, pointerSha}.
async function readNewest(ns) {
  const ptr = await read(headPath(ns));
  let seq = 0;
  let newest = null;
  if (ptr) {
    const pseq = ptr.json && ptr.json.seq;
    if (!Number.isInteger(pseq) || pseq < 1) throw new Broken("the stored pointer of this namespace cannot be read, so nothing more is added to it");
    const got = await read(rowPath(ns, pseq));
    if (!got) throw new Broken("the stored pointer of this namespace names a row that is not there, so nothing more is added to it");
    newest = checkRow(got.json, ns, pseq, null);
    seq = pseq;
  }
  for (let i = 0; i < MAX_AHEAD; i++) {
    const got = await read(rowPath(ns, seq + 1));
    if (!got) return { newest, pointerSha: ptr ? ptr.sha : undefined };
    newest = checkRow(got.json, ns, seq + 1, newest ? newest.chain : c.ZERO_ROW_CHAIN);
    seq += 1;
  }
  throw new Broken("this namespace holds more rows past its pointer than the witness reads at once, so nothing more is added to it");
}

// Every row up to `newest`, newest first, each checked against the one
// before it. At most `limit` rows are returned, the newest ones, but every
// row is read so that the chain is checked from row 1.
async function readAll(ns, newest) {
  if (newest.seq > MAX_ROWS_READ) {
    throw new Unavailable(`this namespace holds more than ${MAX_ROWS_READ} rows, more than the witness serves in one answer now`);
  }
  const rows = [];
  let prev = c.ZERO_ROW_CHAIN;
  for (let seq = 1; seq <= newest.seq; seq++) {
    const got = seq === newest.seq ? { json: newest } : await read(rowPath(ns, seq));
    if (!got) throw new Broken(`the stored row ${seq} of this namespace is missing`);
    const row = checkRow(got.json, ns, seq, prev);
    prev = row.chain;
    rows.push(row);
  }
  return rows.reverse();
}

// Create a row. Create only: a slot already taken throws with
// err.conflict true, and is never written over.
async function createRow(ns, row) {
  return store.putFile(rowPath(ns, row.seq), row, `contract pin ${ns} n=${row.pin.head.n} seq=${row.seq}`);
}

// Move the pointer to `row`, forward only. A failure is not a refusal: the
// row is the record, and every read looks past the pointer for it.
async function movePointer(ns, row, sha) {
  const ahead = (fresh) => fresh && fresh.json && Number.isInteger(fresh.json.seq) && fresh.json.seq >= row.seq;
  const put = (s) => store.putFile(headPath(ns), row, `contract head ${ns} seq=${row.seq}`, s, {
    rebuild: (fresh) => (ahead(fresh) ? null : row),
  });
  try {
    try {
      await put(sha);
    } catch (err) {
      // Two writers both made the pointer at once: judge the one that landed.
      if (!err || !err.conflict) throw err;
      const fresh = await store.getFile(headPath(ns));
      if (!fresh || ahead(fresh)) return true;
      await put(fresh.sha);
    }
    return true;
  } catch {
    console.error(`[contract] the pointer of ${ns} was not moved to seq ${row.seq}; reads look past it`);
    return false;
  }
}

module.exports = { Broken, Unavailable, rowPath, headPath, readNewest, readAll, createRow, movePointer, MAX_ROWS_READ };
