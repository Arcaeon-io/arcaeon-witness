// _balance.js — a real, decrementing per-key CREDIT BALANCE, with an
// append-only ledger for every mutation. This is the enabling mechanism
// for COUNCIL_PRICING_REVIEW_2026-08-14 §4 decision #5 (the "hard gate,"
// ratified same day): the free monthly cap in lib/_meter.js (100/mo then; 10/mo since
// the owner's Fri 2026-10-30 call) resets monthly
// and cannot honestly back a prepaid, non-expiring per-pin credit promise.
// This module is the thing that makes the promise true.
//
// This module does NOT decide pricing, does NOT touch offers.json, and
// does NOT make credit packs purchasable. It only makes a purchased
// credit real, auditable, and correctly enforced once one exists. The
// pack catalogue below (PACKS) mirrors the ratified sizes so the crediting
// math is right when the human wiring step (Stripe Price IDs / Payment
// Link metadata) lands -- naming the SKUs here is not the same as selling
// them; offers.json remains the single source of truth for what's for sale.
//
// Storage: same PRIVATE GitHub repo api/_meter.js already uses
// (dan8433-user/arcaeon-witness-usage), same GITHUB_PIN_TOKEN, same
// contents-API CAS pattern -- reused on purpose, not reinvented. Three
// kinds of file live there for this module:
//
//   balance/<key_hash>.json          current balance (the fast-read state)
//   ledger/<key_hash>/grant-<event_id>.json   one per top-up, keyed by the
//                                     Stripe event id (or admin-supplied
//                                     event_id) for webhook-replay safety
//   ledger/<key_hash>/<seq>-decrement.json    one per pin-consumption
//
// A balance you can't audit contradicts the brand this repo is selling
// (PRACTICES.md: "the answer lives in a public git history... not in a
// database only we can read"). The ledger is that audit trail for the
// PRIVATE side of the store, same spirit as the public pin log's own
// append-only observations/ directory.
//
// Idempotent top-up, explained (grantCredits, below): GitHub's contents
// API only gives us single-file compare-and-swap, not a real multi-file
// transaction. A naive "check balance, add, write" is not safe against a
// webhook retry landing between the check and the write.
//
// THE FIX (2026-08-14 billing audit, CEO-authorized). The idempotency claim
// and the balance mutation must be ONE compare-and-swap, not two. The earlier
// design kept a separate ledger file whose `applied:false -> true` flag was the
// claim; but "read the flag" and "write the new balance" were two GitHub round-
// trips, so two overlapping deliveries of the SAME event_id could both read
// applied:false and both add the pack -- demonstrated live, 10 pins purchased,
// 20 granted. Now the set of already-applied event ids lives INSIDE the balance
// file itself (`applied_events`, bounded to the last MAX_APPLIED_EVENTS), and
// "is this event already applied? / add the pins / record the event" happen as
// a single CAS against the balance file's sha. A losing writer 409s, re-reads,
// sees the event_id already in `applied_events`, and returns already_credited
// WITHOUT adding a second time. The append-only ledger/ grant file is still
// written afterward as an audit record, but it is no longer the idempotency
// gate -- the balance file's own CAS is.
//
// SCHEMA NOTE for the not-yet-existent cutover: balance/<hash>.json now carries
// an `applied_events: [...]` array. This is a PURELY ADDITIVE field on a store
// with ZERO live balances today (no pack has ever been sold, the webhook is not
// wired) -- there is nothing to migrate. Any balance file written before this
// field existed reads as `applied_events: []` (treated as "no events applied
// yet"), which is correct.

"use strict";

const crypto = require("crypto");
const verdict = require("./_verdict.js");

const USAGE_REPO = process.env.GITHUB_USAGE_REPO || "dan8433-user/arcaeon-witness-usage";
const USAGE_BRANCH = process.env.GITHUB_USAGE_BRANCH || "main";
const API = "https://api.github.com";

// The balance file remembers the last N applied Stripe event ids so a delivery
// retry is a no-op. Bounded so the file can't grow without limit: Stripe never
// retries an event for more than ~3 days, and N=500 top-ups is far more history
// than that window can hold, so an id can never age out of the set while a
// retry of it is still possible.
const MAX_APPLIED_EVENTS = 500;

// The contents API shows observable read-after-write lag (a GET right after a
// successful create-only PUT can still 404). A short pause before re-reading on
// a CAS conflict lets it settle so the retry sees the winner's write instead of
// racing it again. Bounded, tiny, and only on the contended path.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Pack catalogue -- SKU id -> pins. CURRENT packs (owner's prices, Thu
// 2026-10-29, ship with the 2026-11-03 release): 200 pins for $5 and 1,000
// pins for $20. Packs never expire and are spent only after the month's free
// pins. price_usd is what a checkout is EXPECTED to charge; this module never
// talks to Stripe, it only maps a pack id to pins.
//
// PACKS is the PUBLIC catalogue: the only packs the 402/429 bodies advertise
// (via publicPacks). New checkout links carry metadata.pack = pins_200 /
// pins_1000. A pack is credited ONLY when it is named (price map or
// metadata.pack); the amount paid never picks a pack.
const PACKS = Object.freeze({
  pins_200: Object.freeze({ price_usd: 5, pins: 200 }),
  pins_1000: Object.freeze({ price_usd: 20, pins: 1000 }),
});

// LEGACY_PACKS: the retired 2026-08 catalogue. Not sold, never advertised.
// Kept ONLY so a buyer whose old link names one of these ids EXPLICITLY
// (metadata.pack, or a Price id in WITNESS_STRIPE_PRICE_MAP) still gets what
// that link sold.
const LEGACY_PACKS = Object.freeze({
  mini: Object.freeze({ price_usd: 5, pins: 1000 }),
  starter: Object.freeze({ price_usd: 15, pins: 3000 }),
  standard: Object.freeze({ price_usd: 50, pins: 12000 }),
  bulk: Object.freeze({ price_usd: 150, pins: 40000 }),
});

const ownKey = (o, k) => typeof k === "string" && Object.prototype.hasOwnProperty.call(o, k);

// lookupPack(id) -> pack def for an EXPLICITLY named id (current or legacy),
// else null. Own-property lookup, so "constructor"/"__proto__" are not packs.
function lookupPack(id) {
  if (ownKey(PACKS, id)) return PACKS[id];
  if (ownKey(LEGACY_PACKS, id)) return LEGACY_PACKS[id];
  return null;
}

// publicPacks() -> what an out-of-pins body shows a caller: current packs
// only, price and pins only (fresh objects, so no internal field can leak).
function publicPacks() {
  const out = {};
  for (const [id, p] of Object.entries(PACKS)) out[id] = { price_usd: p.price_usd, pins: p.pins };
  return out;
}

// ---- buying more, for the out-of-pins (402/429) bodies ----
// PACK_BUY_URL: the general pricing page. Used only when WITNESS_PACK_LINKS
// is unset, and stated plainly: buying there makes a NEW key.
const PACK_BUY_URL = "https://arcaeon.io/pricing";

// WITNESS_PACK_LINKS: JSON {"pins_200": "<payment link url>", "pins_1000":
// "<payment link url>"}. Not secrets (public payment links). Only current
// pack ids and https URLs are kept; anything else is ignored.
function loadPackLinks() {
  let raw;
  try {
    raw = JSON.parse(process.env.WITNESS_PACK_LINKS || "{}");
  } catch {
    console.error("[balance] WITNESS_PACK_LINKS is not valid JSON; ignored");
    return {};
  }
  const out = {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
  for (const id of Object.keys(PACKS)) {
    if (!ownKey(raw, id) || typeof raw[id] !== "string") continue;
    try {
      const u = new URL(raw[id].trim());
      if (u.protocol === "https:") out[id] = u.toString();
    } catch { /* not a URL: ignored */ }
  }
  return out;
}

// buyFor(key) -> what an out-of-pins body carries so the caller can buy
// more pins ON THIS KEY. Each pack's payment link gets
// ?client_reference_id=<sha256(key)>, the hash /api/fulfill and the webhook
// already credit by. Only the HASH ever goes in a URL; the key never does.
//   { buy: { pins_200: url, ... }, buy_note }   when WITNESS_PACK_LINKS is set
//   { buy: null, buy_url, buy_note }            otherwise (pricing page, new key)
function buyFor(key) {
  const hash = keyHash(String(key));
  const links = loadPackLinks();
  const buy = {};
  for (const [id, url] of Object.entries(links)) {
    const u = new URL(url);
    u.searchParams.set("client_reference_id", hash);
    buy[id] = u.toString();
  }
  if (Object.keys(buy).length) {
    return {
      buy,
      buy_note: 'Each link in "buy" adds that pack to this key; no new key is made.',
    };
  }
  return {
    buy: null,
    buy_url: PACK_BUY_URL,
    buy_note:
      `Buying at ${PACK_BUY_URL} makes a NEW key. To add pins to this key instead, ` +
      `open a pack's payment link with ?client_reference_id=${hash} added to the end ` +
      `(that is this key's SHA-256, not the key).`,
  };
}

// overCapMessage(plan, cap, buyInfo) -> the plain sentence a 429 (monthly
// free pins used up, no pack bought) carries. Keys that were under the old
// 100 a month hit this the day the 10 a month allowance ships, so it says
// what changed and how to get more, and asks nothing else of the key holder.
function overCapMessage(plan, cap, buyInfo = null) {
  const packs = Object.values(PACKS)
    .map((p) => `${p.pins.toLocaleString("en-US")} pins for $${p.price_usd}`)
    .join(" or ");
  const allowance = plan === "free"
    ? `The free allowance is now ${cap} pins a month per key, and this key has used this month's ${cap}.`
    : `This key has used its ${cap} pins for this month.`;
  return `${allowance} It resets on the 1st of next month (UTC). ` +
    `To keep pinning now, buy a pin pack: ${packs}. ` +
    `Packs never expire and are used only after the month's free pins. The packs are listed in "packs".` +
    (buyInfo && buyInfo.buy_note ? ` ${buyInfo.buy_note}` : "");
}

// WITNESS_STRIPE_PRICE_MAP: JSON object, Stripe Price id -> pack id, e.g.
// {"price_1AbCdE...":"pins_200"}. Optional. Unparseable -> empty map.
function loadPriceMap() {
  const raw = process.env.WITNESS_STRIPE_PRICE_MAP || "{}";
  try {
    const p = JSON.parse(raw);
    return p && typeof p === "object" && !Array.isArray(p) ? p : {};
  } catch {
    return {};
  }
}

// resolvePack(session, { priceMap = true }) -> one of
//   { pack, source }                 a named, known pack ("price_map" | "metadata")
//   { pack: null, reason, detail }   nothing creditable; reason is
//                                    "not_named" | "unknown_pack" | "pack_conflict"
// The ONE resolver both api/fulfill.js and api/stripe-webhook.js use. A pack
// is credited ONLY when it is NAMED; the amount paid never picks a pack (an
// unnamed $5 or $20 session, including one from another product, gets
// nothing automatically and goes to the manual step).
//   - price map: line-item Price ids mapped by WITNESS_STRIPE_PRICE_MAP.
//     Only fulfill has line_items (expand[]=line_items); the webhook passes
//     { priceMap: false } and goes by metadata.pack alone.
//   - metadata.pack, trimmed and lower-cased.
//   Current or legacy ids are both accepted when named. If the price map and
//   metadata.pack are both present and disagree (or line items map to two
//   different packs, or one names an unknown pack), nothing is credited.
// The caller still checks amount and currency against the resolved pack.
function resolvePack(session, opts = {}) {
  const usePriceMap = opts.priceMap !== false;
  const mapped = new Set();
  if (usePriceMap) {
    const priceMap = loadPriceMap();
    const items =
      session && session.line_items && Array.isArray(session.line_items.data)
        ? session.line_items.data
        : [];
    for (const it of items) {
      const pid = it && it.price && it.price.id;
      if (pid && ownKey(priceMap, pid) && priceMap[pid]) mapped.add(String(priceMap[pid]).trim().toLowerCase());
    }
  }
  const meta =
    session && session.metadata && session.metadata.pack
      ? String(session.metadata.pack).trim().toLowerCase()
      : "";
  const named = new Set(mapped);
  if (meta) named.add(meta);
  const detail = `price_map=${mapped.size ? [...mapped].join("|") : "(none)"} metadata.pack=${meta || "(none)"}`;
  if (named.size === 0) return { pack: null, reason: "not_named", detail };
  if (named.size > 1) return { pack: null, reason: "pack_conflict", detail };
  const only = [...named][0];
  if (!lookupPack(only)) return { pack: null, reason: "unknown_pack", detail };
  return { pack: only, source: mapped.size ? "price_map" : "metadata" };
}

function ghHeaders() {
  const h = {
    accept: "application/vnd.github+json",
    "user-agent": "arcaeon-witness-balance",
    "x-github-api-version": "2022-11-28",
  };
  const tok = process.env.GITHUB_PIN_TOKEN;
  if (tok) h.authorization = `Bearer ${tok}`;
  return h;
}

function keyHash(secret) {
  return crypto.createHash("sha256").update(secret, "utf8").digest("hex");
}

async function getFile(path) {
  const r = await fetch(
    `${API}/repos/${USAGE_REPO}/contents/${path}?ref=${USAGE_BRANCH}`,
    { headers: ghHeaders() }
  );
  if (r.status === 404) return null;
  if (!r.ok) {
    // Path redacted from the thrown message (2026-08-14 audit): it is
    // `balance/<sha256(key)>.json` / `ledger/<sha256(key)>/...` in a PRIVATE
    // repo, and callers see err.message verbatim in a 502 body.
    console.error(`[balance] GET ${path} -> ${r.status}`);
    throw new Error(`balance store read failed (${r.status})`);
  }
  const body = await r.json();
  const text = Buffer.from(body.content, "base64").toString("utf-8");
  return { json: JSON.parse(text), sha: body.sha };
}

// PUT (create if `sha` omitted, update if present). Same conflict
// detection as api/_meter.js: a 409 (update race) or a 422 whose message
// says a sha "wasn't supplied" (create race -- the file was created by a
// concurrent writer between our read and our write) both get tagged
// `err.conflict = true` so callers can retry-once against a fresh read,
// exactly like the existing meter's CAS loop.
async function putFile(path, obj, message, sha) {
  const payload = {
    message,
    branch: USAGE_BRANCH,
    content: Buffer.from(JSON.stringify(obj, null, 2) + "\n").toString("base64"),
  };
  if (sha) payload.sha = sha;
  const r = await fetch(`${API}/repos/${USAGE_REPO}/contents/${path}`, {
    method: "PUT",
    headers: { ...ghHeaders(), "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (r.status === 409) {
    console.error(`[balance] PUT ${path} -> 409 sha conflict`);
    const err = new Error("balance store write conflict (concurrent writer)");
    err.conflict = true;
    throw err;
  }
  if (!r.ok) {
    const detail = await r.text().catch(() => "");
    const isCreateRace = r.status === 422 && /sha.*wasn't supplied/i.test(detail);
    console.error(`[balance] PUT ${path} -> ${r.status}: ${detail.slice(0, 400)}`);
    const err = new Error(`balance store write failed (${r.status})`);
    if (isCreateRace) err.conflict = true;
    throw err;
  }
  return r.json();
}

// DELETE — used only by the test-cleanup path (never called by any
// production request handler). Requires the current sha.
async function deleteFile(path, sha, message) {
  const r = await fetch(`${API}/repos/${USAGE_REPO}/contents/${path}`, {
    method: "DELETE",
    headers: { ...ghHeaders(), "content-type": "application/json" },
    body: JSON.stringify({ message, branch: USAGE_BRANCH, sha }),
  });
  if (!r.ok) {
    const detail = await r.text().catch(() => "");
    throw new Error(`balance store DELETE ${path} -> ${r.status} ${detail.slice(0, 200)}`);
  }
  return r.json();
}

function sanitizeEventId(id) {
  // Stripe event ids (evt_XXXXXXXX) are already path-safe; this is a
  // defensive clamp for the internal/admin path, where a caller could in
  // principle hand in an arbitrary string as the idempotency key.
  return String(id).replace(/[^a-zA-Z0-9_.-]/g, "_").slice(0, 128);
}

function balancePath(hash) {
  return `balance/${hash}.json`;
}
function ledgerGrantPath(hash, eventId) {
  return `ledger/${hash}/grant-${sanitizeEventId(eventId)}.json`;
}
function ledgerDecrementPath(hash, seq) {
  return `ledger/${hash}/${String(seq).padStart(8, "0")}-decrement.json`;
}

// ---- read ----
// readBalance(hash) -> {key_id, key_hash, balance, seq, ever_purchased, updated_at}
// `ever_purchased` distinguishes "never bought credits" (balance file
// doesn't exist) from "bought credits, spent them all" (balance file
// exists, balance is 0) -- pin.js uses this to choose 429 vs 402.
// The number comes out of a verdict or not at all (lib/_verdict.js): 404 is a
// verified-empty 0, a readable number is that number, and a document that is
// present without one THROWS. `Number(x) || 0` could not tell the last two
// apart from the first.
function balanceOf(cur) {
  return verdict.counterValue(verdict.judgeCounter(cur, "balance", { what: "credit balance" }), "balance");
}

async function readBalance(hash) {
  const cur = await getFile(balancePath(hash));
  const balance = balanceOf(cur); // throws on a damaged balance file — before the 404 branch, so neither branch can skip it
  if (cur === null) {
    return { key_id: hash.slice(0, 12), key_hash: hash, balance: 0, seq: 0, ever_purchased: false, updated_at: null };
  }
  return {
    key_id: cur.json.key_id || hash.slice(0, 12),
    key_hash: hash,
    balance,
    seq: Number(cur.json.seq) || 0,
    ever_purchased: true,
    updated_at: cur.json.updated_at || null,
  };
}

// ---- fractional amounts (2026-09-20, the stamps lane) ----
//
// A pin costs exactly one credit. A stamp costs a FRACTION of one
// (lib/_stamp.js's STAMP_PRICE_CREDITS), because a stamp is one commit with
// none of the cadence/deadline/verification machinery a pin carries. So the
// debit primitive had to stop being hardwired to 1.
//
// Balances are therefore no longer guaranteed integral, and float subtraction
// is not associative: 1000 - 0.1 ten times is 999.0000000000001, and a
// balance file that drifts is a balance file a customer can catch us on.
// Every stored balance is rounded to CREDIT_DP decimal places on write. Six
// places is far below any price we would ever set and far above the drift a
// few million subtractions can introduce.
const CREDIT_DP = 6;
function roundCredits(n) {
  return Math.round(n * 10 ** CREDIT_DP) / 10 ** CREDIT_DP;
}

// ---- decrement (one pin consumed from a purchased balance) ----
// decrementCredit(secret, reason) ->
//   {ok:true, key_hash, balance, seq}
// | {ok:false, reason:"insufficient_credit", key_hash, balance:0, ever_purchased}
//
// Thin alias for debitCredits(secret, 1, reason) — ONE implementation of the
// CAS loop, not two. The behaviour for amount=1 over an integral balance is
// identical to what it was before the amount became a parameter (the old
// `bal <= 0` guard and the new `bal < amount` guard agree for every integer
// balance; they differ only on a fractional balance below 1, where refusing
// is the correct answer and the old guard would have gone negative).
async function decrementCredit(secret, reason) {
  return debitCredits(secret, 1, reason);
}

// ---- debit an arbitrary amount (>=0) from a purchased balance ----
// debitCredits(secret, amount, reason) ->
//   {ok:true, key_hash, balance, seq, amount}
// | {ok:false, reason:"insufficient_credit", key_hash, balance, ever_purchased, amount}
//
// Fails CLOSED, same philosophy as api/_meter.js's own denial vocabulary:
// a balance below the amount (or no balance record at all) is refused, never
// waved through as free.
async function debitCredits(secret, amount, reason) {
  const amt = roundCredits(Number(amount));
  if (!Number.isFinite(amt) || amt <= 0) {
    // A zero or negative "debit" is a caller bug, and a caller bug must not be
    // able to turn a charge into a top-up.
    throw new Error(`debitCredits: amount must be a positive number (got ${amount})`);
  }
  const hash = keyHash(secret);
  const path = balancePath(hash);
  let lastErr = null;

  for (let attempt = 0; attempt < 2; attempt++) {
    const cur = await getFile(path);
    const bal = balanceOf(cur);
    const everPurchased = !!cur;

    if (bal < amt) {
      return { ok: false, reason: "insufficient_credit", key_hash: hash, balance: bal, ever_purchased: everPurchased, amount: amt };
    }

    const seq = cur && Number.isInteger(cur.json.seq) ? cur.json.seq + 1 : 1;
    const next = roundCredits(bal - amt);
    const nowIso = new Date().toISOString();
    // CARRY applied_events THROUGH THE REBUILD (fix 2026-08-16, found by the
    // overhaul scrutiny pass): this object literal previously dropped the
    // applied Stripe event-id set, so ANY spend wiped the double-credit
    // idempotency guard — a Stripe retry after one spend re-granted the full
    // pack ($15 bought 5,999 pins in the mechanical replay) while the grant
    // ledger silently disagreed with the balance. Spread the prior record's
    // set forward; grantCredit at :320 stays the only place that ADDS to it.
    const appliedEvents = (cur && Array.isArray(cur.json.applied_events)) ? cur.json.applied_events : [];
    const obj = { key_id: hash.slice(0, 12), key_hash: hash, balance: next, seq, updated_at: nowIso, applied_events: appliedEvents };

    try {
      await putFile(path, obj, `credit decrement ${hash.slice(0, 12)} seq=${seq} -${amt} balance=${next}`, cur ? cur.sha : undefined);
    } catch (err) {
      if (err.conflict && attempt === 0) {
        lastErr = err;
        continue; // one retry with a freshly re-read sha, same as _meter.check
      }
      throw err;
    }

    // Ledger entry for this decrement. Its filename is seq-derived, and
    // seq only advances once the CAS write above already succeeded, so a
    // duplicate write here can't happen under normal operation -- create-
    // only is still used (not update) so a genuine collision throws
    // instead of silently overwriting a prior audit record.
    const ledgerPath = ledgerDecrementPath(hash, seq);
    const entry = { seq, type: "decrement", amount: amt, balance_before: bal, balance_after: next, reason: reason || "pin", at: nowIso };
    try {
      await putFile(ledgerPath, entry, `ledger decrement ${hash.slice(0, 12)} seq=${seq}`);
    } catch (err) {
      // The balance number itself already moved and is the source of
      // truth; a failed ledger write here is the same documented class of
      // gap as pin.js's own "two commits, not atomic" note -- surfaced in
      // the return value, not swallowed.
      return { ok: true, key_hash: hash, balance: next, seq, amount: amt, ledger_write_failed: err.message };
    }

    return { ok: true, key_hash: hash, balance: next, seq, amount: amt };
  }

  throw lastErr || new Error("balance store: exhausted CAS retries on debit");
}

// ---- grant (top-up) — the low-level primitive ----
// grantCredits(hash, pins, pack, eventId, source) -> idempotent on eventId.
// Exposed directly (not just via creditPack) so tests can grant an
// arbitrary small amount without needing a full $15+ pack.
//
// Idempotency and the balance mutation are ONE compare-and-swap against
// balance/<hash>.json (see the header comment). The event id is recorded in
// the balance file's `applied_events` set in the SAME write that adds the
// pins, so a concurrent replay of the same event can never add twice: the
// loser of the CAS re-reads, finds the id already applied, and returns
// already_credited without touching the balance.
async function grantCredits(hash, pins, pack, eventId, source) {
  const evt = sanitizeEventId(eventId);
  const path = balancePath(hash);

  let alreadyApplied = false;
  let finalBalance = null;
  let finalSeq = null;
  let lastErr = null;

  // A few more attempts than the meter's 2: a create-race on a brand-new
  // balance file plus read-after-write lag can need one or two extra re-reads
  // before the loser sees the winner's write. Bounded, with backoff — no spiral.
  const MAX_ATTEMPTS = 6;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const cur = await getFile(path);
    const curJson = cur ? cur.json : null;
    // Most of all here: this function WRITES bal + pins back. With `|| 0` a
    // damaged balance file was replaced by a fresh one holding only this
    // grant — the customer's prior credit gone and seq restarted at 1
    // (observed 2026-09-21 with the default put back). Now it throws, the webhook answers non-2xx, and Stripe retries
    // until a person has looked at the file.
    const bal = balanceOf(cur);
    const appliedEvents =
      curJson && Array.isArray(curJson.applied_events) ? curJson.applied_events : [];

    if (appliedEvents.includes(evt)) {
      // This exact event is already folded into the balance. Idempotent.
      alreadyApplied = true;
      finalBalance = bal;
      finalSeq = curJson && Number.isInteger(curJson.seq) ? curJson.seq : null;
      break;
    }

    const seq = curJson && Number.isInteger(curJson.seq) ? curJson.seq + 1 : 1;
    const newBalance = bal + pins;
    const newApplied = appliedEvents.concat([evt]).slice(-MAX_APPLIED_EVENTS);
    const obj = {
      key_id: hash.slice(0, 12),
      key_hash: hash,
      balance: newBalance,
      seq,
      applied_events: newApplied,
      updated_at: new Date().toISOString(),
    };
    try {
      await putFile(
        path, obj,
        `credit grant ${hash.slice(0, 12)} ${pack} +${pins} seq=${seq} evt=${evt}`,
        cur ? cur.sha : undefined
      );
      finalBalance = newBalance;
      finalSeq = seq;
      break;
    } catch (err) {
      if (err.conflict && attempt < MAX_ATTEMPTS - 1) {
        lastErr = err;
        await sleep(120 * (attempt + 1)); // let read-after-write settle, then re-read
        continue;
      }
      throw err;
    }
  }
  if (finalBalance === null) {
    throw lastErr || new Error("balance store: exhausted CAS retries on grant");
  }

  if (alreadyApplied) {
    // Report what was ACTUALLY granted for this event (perhaps by the other
    // path: webhook vs fulfill), read from its ledger record, never the pins
    // this caller would have granted. Unreadable -> null (unknown), and no
    // ledger record is written in its place (it could carry the wrong size).
    let prior = null;
    try {
      const lf = await getFile(ledgerGrantPath(hash, eventId));
      prior = lf && lf.json ? lf.json : null;
    } catch (err) {
      console.error(`[balance] could not read the prior grant record for evt=${evt}: ${err.message}`);
    }
    const grantedPins = prior && Number.isFinite(Number(prior.pins)) ? Number(prior.pins) : null;
    return {
      ok: true, already_credited: true, key_hash: hash, pins, pack,
      granted_pins: grantedPins, granted_pack: prior && prior.pack ? prior.pack : null,
      balance_after: finalBalance,
    };
  }

  // Append-only audit record for this top-up. NOT the idempotency gate anymore
  // (the balance file's applied_events set is) — a create-only write, best
  // effort. A conflict here just means a prior/concurrent delivery already
  // wrote the audit line, which is fine; a genuine write failure is surfaced
  // but does NOT fail the grant, because the balance is already correct and the
  // event is already recorded as applied in the source-of-truth balance file.
  const ledgerPath = ledgerGrantPath(hash, eventId);
  const record = {
    event_id: evt, key_hash: hash, pack, pins, source,
    applied: true, balance_after: finalBalance, balance_seq: finalSeq,
    at: new Date().toISOString(),
  };
  try {
    await putFile(ledgerPath, record, `credit ledger ${hash.slice(0, 12)} ${pack} evt=${evt}`);
  } catch (err) {
    if (!err.conflict) {
      return {
        ok: true, already_credited: false, key_hash: hash,
        pins, pack, granted_pins: pins, granted_pack: pack,
        balance_after: finalBalance, ledger_write_failed: err.message,
      };
    }
  }

  return { ok: true, already_credited: false, key_hash: hash, pins, pack, granted_pins: pins, granted_pack: pack, balance_after: finalBalance };
}

// ---- grant by SKU — the entry point api/credit.js and api/stripe-webhook.js call ----
// Accepts a current OR legacy id: callers only pass an id that was named
// explicitly (price map, metadata, admin body).
async function creditPack(hash, packId, eventId, source) {
  const pack = lookupPack(packId);
  if (!pack) return { ok: false, reason: "unknown_pack", pack_id: packId };
  if (!eventId) return { ok: false, reason: "missing_event_id" };
  return grantCredits(hash, pack.pins, packId, eventId, source);
}

module.exports = {
  PACKS,
  LEGACY_PACKS,
  lookupPack,
  publicPacks,
  overCapMessage,
  PACK_BUY_URL,
  loadPackLinks,
  buyFor,
  loadPriceMap,
  resolvePack,
  keyHash,
  readBalance,
  decrementCredit,
  debitCredits,
  roundCredits,
  CREDIT_DP,
  grantCredits,
  creditPack,
  // exported for the test harness's cleanup pass only:
  getFile,
  deleteFile,
  balancePath,
  ledgerGrantPath,
  ledgerDecrementPath,
  USAGE_REPO,
  USAGE_BRANCH,
};
