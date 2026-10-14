// _case.js — the arcaeon-case/1 schema: the case object, the case id rule and
// the commitment rule. Underscore prefix = not routed as a serverless function.
// This file does no I/O of any kind: no store, no fetch, and no clock it is not
// handed as an argument. lib/_case_http.js is the part that reads and writes.
//
// WHAT A CASE IS (CASE_PROTOCOL_DESIGN_2026-10-10.md, velouria
// projects/arcaeon/, version 2, the design this was built from). Two parties,
// an agent side and a tool side, want their two tapes compared by this
// service, and want each tape fixed before the comparison. So each party
// computes a commitment hash locally, stamps it (lib/_stamp.js: a public,
// dated commit), and registers it to the case under its role. Item two of the
// design is one request carrying both reveals and both tapes; this file gives
// that request the rules it will check against. It does not implement it.
//
// THE CLAIM, AND ONLY THIS (design, "The claim this item makes, and only
// this"): "Each accepted reveal matched a public commitment registered to this
// case and role before the deadline; the service ran its recorded comparison
// after receiving both accepted tapes in one request; the commitments, the
// comparison and the times are sealed and anchored." Item one builds the
// registration that sentence starts from, and nothing here claims more (since
// unit R-PIN no page or answer says anchored: a sealed case is pinned, and
// the daily anchor records are pointed to, never checked here). LIMITS
// below carries the design's four non-claims, one sentence each, and every
// case object carries them.
//
// THE CASE ID RULE (design, case object table, `case_id`):
//   case_id = sha256( json-c14n:v1( {protocol_version, policy_version,
//             scope_digest, party_a, party_b, opened_at} ) )
// with party_a and party_b "in canonical order (sorted by `label`, then
// `side`)" and opened_at "normalized to UTC seconds". GPT-5.6's review is why
// the ordering and the normalization are part of the rule: "Require canonical
// ordering of party_a and party_b, exact timestamp normalization ...
// Otherwise 'both can derive it' is not reliable across implementations." So:
//   - labels compare by Unicode CODE POINT, which is how Python compares str
//     and how json-c14n:v1 sorts keys. JavaScript's own `<` compares UTF-16
//     code units, and the two disagree as soon as a label holds a character
//     outside the Basic Multilingual Plane (test 1 plants exactly that);
//   - a tie on label AND side is refused (`parties_not_distinct`): the rule
//     has nothing left to order by, and a key_id does not break the tie,
//     because the design does not say it does;
//   - opened_at may arrive with a fraction or an offset; it is converted to
//     UTC and the fraction is dropped (truncated, never rounded), and the id
//     is taken over YYYY-MM-DDTHH:MM:SSZ;
//   - `deadline` is NOT in the id. A retried case with a new deadline is the
//     same opening only if every id field is the same, and then it is refused
//     as a duplicate, not given a second id.
// Role a binds to party_a and role b to party_b, exactly (design: "Commitment
// role `a` binds to `party_a` and `b` to `party_b`, exactly (GPT: role binding
// was underspecified)"). Since party_a is whichever party sorts first, a party
// learns its role from the canonical order, not from where it listed itself.
//
// THE COMMITMENT RULE (design, "The commitment format"):
//   commitment = sha256( json-c14n:v1( {case_id, role, tape_sha256, salt,
//                protocol_version: "case/1"} ) )
// salt is 32 random bytes as 64 hex characters. There is no manifest hash:
// "the witness never sees an evidence manifest in this item, so hashing one
// into the commitment proved nothing to anyone (Gemini)". tape_sha256 stays,
// strict: "without it the witness proves only that something was committed,
// not that the exact tape compared was fixed before disclosure." Every value
// in the preimage is a fixed-length ASCII string, so its canonical bytes are
// always COMMITMENT_BYTES_LENGTH long: that is the `size` a party stamps.
// Unknown fields in a commitment input are refused: a caller who passes a
// manifest hash believes it is bound, and it is not.
//
// ONE CANONICALIZER. Both hashes go through lib/_check_record.js's
// canonicalBytes, the json-c14n:v1 signing rule, which is lib/_merkle.js's
// serializer, which is the JS side of arcaeon_ledger.artefact._canon_json
// (json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False,
// allow_nan=False).encode("utf-8")). test/fixtures/case/c14n_cases.json holds
// bytes written by that Python function, and test 2 compares them byte for
// byte. Two input rules exist only so the two sides cannot diverge: a label
// or key_id holding a lone surrogate is refused (JSON.stringify escapes one,
// Python's strict UTF-8 encode raises on it), and so is one holding a control
// character (it would otherwise be an escape-sequence edge on a public page).
//
// TYPED ERRORS. Every refusal in this file is a CaseError with `code` from
// CASE_ERROR_CODES and `field` naming the offender, so the HTTP layer can turn
// it into a typed 4xx without reading the message. validateCase never throws;
// it answers {ok:false, code, field, error}.
//
// THE CASE OBJECT (design table, authoritative). Unknown top-level fields are
// refused, the lib/_check_record.js rule: "A field the verifier does not know
// about is a field a reader might trust that nobody checked." `sig_reason` is
// declared for that reason (GPT: "otherwise _check_record.js should reject the
// reason as an unknown top-level field"). An open or committed case is not
// sealed and carries `sig: null` with UNSEALED_SIG_REASON, and only such a
// case carries a sig_reason that is not null. Every record the service
// signs (a sealed case, a withdrawal record, a reference row, a refusal
// receipt) carries a signature: `sig` a string, `sig_reason` null, and a
// `sig` of null is malformed_field (unit R-SIG; no record is ever unsigned). A stored status of EXPIRED is refused: "Expiry writes nothing; the page
// computes EXPIRED from deadline against the service clock". A WITHDRAWN case
// is the fixed redacted form and nothing else (no labels; since unit R-L5 it
// keeps the root's commitments, THE WITHDRAWAL below).
//
// NEVER HELD HERE: a tape, a salt, a manifest. The commitment functions take a
// salt because a party computes its commitment with them; nothing in this
// file or lib/_case_http.js writes one anywhere, and a registration body that
// carries one is refused as an unknown field.
//
// THE JOINT REVEAL'S BODY (item 2a; design, "The joint reveal and its
// refusals"): {case_id, reveals: {a: {tape_sha256, salt}, b: {tape_sha256,
// salt}}, cross_reference?} beside the two tapes. validateRevealBody checks
// that shape and nothing else; lib/_case_http.js reads the tapes and does
// every check that needs the store. The tapes are named by ROLE, tape_a and
// tape_b (REVEAL_TAPE_FIELDS), never by side: a commitment binds a role, and
// either party may be either side (design decision 10), so a side-named slot
// could not say whose tape it holds. A caller's revealed_at, salt_sha256 or
// cross_reference.recorded_at is refused as an unknown field: every time in a
// sealed case is this service's clock (design decision 11). Once sealed, a
// case keeps each salt only as `salt_sha256` (saltSha256: the sha256 of the
// salt's 32 bytes, the bytes its 64 hex characters encode), and a stored
// VERDICT must show one joint reveal: one revealed_at for both roles, before
// the deadline (since unit R-RVf3, 4b, not compared with registered_at).
//
// SIGNED_BY (item 2b; design "After item 2a": "the case object gains
// signed_by (the key id)"). Every full case object carries `signed_by`: the
// key id of the key that signed it, `<key name>+<8 hex>`, the way
// lib/_checkpoint.js names a key (the verifier string without its base64
// tail), or null when `sig` is null. An open or committed case is never
// signed, so it carries null; the seal sets it, once, in the same step that
// signs (lib/_case_seal.js signCase), so it sits inside the signed bytes and
// a reader can pick the published verifier for it
// (.well-known/arcaeon/case-signing-keys.json) without trusting the reveal's
// answer. A signed case with no key id, or a key id on an unsigned case, is
// refused. Since item 2c the redacted WITHDRAWN form carries signed_by too
// (THE WITHDRAWAL, below), and so does a reference row.
//
// THE DEADLINE HORIZON (item 2b; design decisions 5 and 12): an opening whose
// deadline is more than MAX_DEADLINE_DAYS (30) days after its opened_at is
// refused `deadline_too_far`. Exactly 30 days is accepted. The rule is the
// opening's, checked at open; both times are the normalized UTC seconds the
// case stores.
//
// THE WITHDRAWAL (item 2c; design "After item 2b": "Withdrawal is
// authorized, not asserted"). A registered role withdraws an OPEN or
// COMMITTED case by presenting its commitment preimage, {case_id, role,
// tape_sha256, salt} (validateWithdrawBody; lib/_case_http.js recomputes
// the commitment under the NAMED role and matches the registration file).
// The case object is replaced by the fixed redacted form, WITHDRAWN_FIELDS,
// "and nothing else" (design, "Withdrawal and expiry records"): v, case_id,
// protocol_version, status WITHDRAWN, opened_at, withdrawal, limits,
// signed_by, sig, sig_reason, and since unit R-L5 `commitments`: the case
// root's projection exactly as it stood when the withdrawal was written
// (each role's entry, or null), inside the signed record, so every reader of
// a withdrawn case takes standing from it. No label. `withdrawal` is
// {by_role, at, salt_sha256}: the role, this service's time, and the sha256
// of the presenting salt's 32 bytes (saltSha256), the one trace of the
// preimage kept ("the redacted record carries salt_sha256 only"), so the
// party holding the salt can show it was the one who withdrew. Presenting
// the preimage spends the commitment: a withdrawn case cannot be revealed.
//   THE REASON (Design N, 2026-10-12). Beside by_role and at, `withdrawal`
// carries `reason`, a code from the request's optional `reason`: one of
// WITHDRAWAL_REASONS, party_choice | deadline | other. Since unit R-SIG
// there is no default: a request that names none records none, and the
// field is absent (the service never signs a reason the party did not
// give). A code, never free text: the redacted record identifies no party
// and says nothing a party wrote.
// The redacted form is signed with the case key like a seal, under the key
// document it names in signed_under (unit R-SIG). A case is withdrawn after
// it is opened, never before.
//
// THE REFERENCE ROW (item 2c; design "After item 2b", "Addendum"). A second
// operator's reference is appended to a SEALED case as a create-only row,
// cases/<case_id>/references/<8-digit seq>.json, record type
// case_reference, exactly REFERENCE_FIELDS:
//   {kind: "case_reference", v: 1, case_id, seq, cross_reference: {operator,
//    reference, url}, recorded_at, appended_by: "preimage:a" | "preimage:b"
//    | "operator", anchor_note, note_version: 4, signed_under, signed_by,
//    sig, sig_reason: null}
// The design's list is kept, and four fields are added: anchor_note,
// because the row must say in words what anchors it and no listed field can
// hold words (REFERENCE_ANCHOR_NOTE, verbatim), note_version, the version of
// that sentence, signed_under (unit R-SIG: the key document it was signed
// under), and sig_reason, null, as on every signed record. appended_by
// (unit R-SIG) says what the service read: a role's commitment preimage,
// which both parties hold after the reveal, or the operator's key; never a
// party. THE ROW'S SENTENCE, VERSION 4
// (unit R-PIN, an architect correction): "This row has no pin of its own. It
// is recorded by the pins-repository commit that writes it, and no
// anchoring is asserted here." No pin of the case ever lists a row (a case
// has one pin), so the sentence no longer says a later pin may. The first
// sentence (no note_version) said the row is anchored by the commit that
// writes it and by the daily anchor of the head, which no reader computes.
// Version 2 (unit R-J, J1) said the row is "listed by the case's next pin",
// a future event stated as fact. Version 3 (unit R-J2, B2) said a later pin
// of the case may list the row's commit. VERSIONS 2 AND 3 WERE NEVER ISSUED
// (nothing was deployed under them). Only version 4 is a row (unit R-SIG,
// the architect's ruling: note_version must equal 4): a row with
// note_version 3 keeps its own reading, `row_note_v3`, and is not rewritten;
// any other value, or none, is malformed_field. Neither is counted. The
// row never changes the sealed case: its `records` is the count at seal time;
// the live count is read from valid rows (lib/_case_seal.js liveRecords).
// The request is {case_id, cross_reference, role?, tape_sha256?, salt?}
// (validateReferenceBody): the three proof fields together or not at all,
// and without them the request is the operator's.
//
// ONE KEY PER ROLE (red-team fix A; GPT-5.6's red-team review, §2A: "Create
// a seemingly bilateral case using an honest party's label": one requester
// opened, registered both roles and revealed, and the page showed a sealed
// verdict naming the other party's label). The two roles of a case are
// registered by two distinct key ids. A registration names its key and proves
// it: the body is {case_id, role, commitment_sha256, verifier, sig}, where
// `verifier` is an Ed25519 verifier string in lib/_checkpoint.js's shape,
// <name>+<8 hex>+<base64(0x01 || public key)>, and `sig` is that key's
// signature over registrationSigningBytes: the json-c14n:v1 bytes of
// {kind: "case-registration-signature", v: 1, case_id, role,
// commitment_sha256}. The key id is the verifier's first two segments,
// <name>+<8 hex> (lib/_checkpoint.js names a key so; the 8 hex are a hash of
// the name and the public key, so one key id is one key). The registration
// record keeps key_id, verifier and sig, so anyone can check the signature,
// and the case's commitment entry keeps key_id. lib/_case_http.js refuses a
// signature its verifier does not confirm (403 registration_unauthorized) and
// a registration whose key id is the other role's registered key id (409
// same_key_both_roles). The commitment itself is unchanged: the same
// preimage, the same 272 bytes, the same hash.
//   A case whose two commitments still share a key id (two registrations that
// raced past that check, each first write wins, or a record no build of this
// service wrote) is SINGLE PARTY (singleParty). The schema reads it, so it can
// be shown for what it is, and it never reaches sealed: the joint reveal
// refuses it (409 single_party), the seal refuses it, and every reader of a
// stored case (lib/_case_seal.js sealedRecordReason and anchorCase, the case
// page) treats it as not sealed. Two key ids show two keys, not two holders:
// one holder can make a second key. What the rule removes is the one-key
// case, and the use of a key the registrant does not hold.
//
// SIGNED_UNDER (Design I, 2026-10-12; lib/_case_seal.js SIGNED UNDER ONE
// DOCUMENT; since unit R-SIG on every signed record). Every record the
// service signs records the key document it was signed under: `signed_under`
// {document_sha256, document_commit}, exactly those two fields
// (document_sha256 64 hex, document_commit a 40-hex git commit), inside the
// signed bytes. It is REQUIRED on a sealed case (VERDICT), a withdrawal
// record (WITHDRAWN), a reference row and a refusal receipt, and an open or
// committed case never carries it. Since unit R-SIG it carries no
// service-clock time: any other field in it is refused unknown_field.

"use strict";

const crypto = require("node:crypto");
const { canonicalBytes } = require("./_check_record.js");
const checkpoint = require("./_checkpoint.js"); // parseVerifierKey, parseSignerKey: ONE KEY PER ROLE
const T = require("./_reconcile_tapes.js"); // PORT_VERSION only

const SCHEMA = "arcaeon-case/1";
const CASE_VERSION = 1;
const PROTOCOL_VERSION = "case/1";

// "policy_version: the reconcile port's method version as its receipt reports
// it" — lib/_reconcile_receipt.js methodBlock().port_version. A deployment can
// only run the port it has, so an opening naming another version is refused.
const SUPPORTED_POLICY_VERSION = T.PORT_VERSION;

const ROLES = Object.freeze(["a", "b"]);
const SIDES = Object.freeze(["agent", "tool"]);
const STATUSES = Object.freeze(["OPEN", "COMMITTED", "VERDICT", "WITHDRAWN", "EXPIRED"]);
const STORED_STATUSES = Object.freeze(["OPEN", "COMMITTED", "VERDICT", "WITHDRAWN"]);
const REGISTERABLE_STATUSES = Object.freeze(["OPEN", "COMMITTED"]);

// SIGNED_UNDER, above: required on a VERDICT and absent from an open or
// committed case, so the full form lists it apart; and its fields.
const OPTIONAL_TOP_LEVEL_FIELDS = Object.freeze(["signed_under"]);
// Since unit R-RV the reveal writes the case root once, the seal, and a
// failed reveal writes nothing: no case records a reveal attempt, and a root
// that carries a list of them is refused as an unknown field.
const SIGNED_UNDER_FIELDS = Object.freeze(["document_sha256", "document_commit"]);
const TOP_LEVEL_FIELDS = Object.freeze([
  "v", "case_id", "protocol_version", "policy_version", "scope_digest", "party_a", "party_b",
  "opened_at", "deadline", "commitments", "reveals", "verdict", "records", "cross_reference",
  "status", "withdrawal", "limits", "signed_by", "sig", "sig_reason",
]);
// SIGNED_BY, above: a key id as lib/_checkpoint.js formats one, <key name>+<8
// lowercase hex>. The name is one printable token with no "+" (that file's
// validName).
const KEY_ID = /^[!-*,-~]{1,180}\+[0-9a-f]{8}$/;
// THE DEADLINE HORIZON, above.
const MAX_DEADLINE_DAYS = 30;
// design, "Withdrawal and expiry records": the redacted form, "and nothing
// else", plus signed_by (item 2c: "the redacted form gains signed_by and
// sig"). THE WITHDRAWAL, above.
const WITHDRAWN_FIELDS = Object.freeze([
  "v", "case_id", "protocol_version", "status", "opened_at", "commitments", "withdrawal", "limits", "signed_under", "signed_by", "sig",
  "sig_reason",
]);
const OPENING_FIELDS = Object.freeze([
  "protocol_version", "policy_version", "scope_digest", "party_a", "party_b", "opened_at", "deadline",
]);
const CASE_ID_FIELDS = Object.freeze([
  "protocol_version", "policy_version", "scope_digest", "party_a", "party_b", "opened_at",
]);
const PARTY_FIELDS = Object.freeze(["side", "label", "key_id"]);
const COMMITMENT_INPUT_FIELDS = Object.freeze(["case_id", "role", "tape_sha256", "salt", "protocol_version"]);
const COMMITMENT_ENTRY_FIELDS = Object.freeze(["commitment_sha256", "registered_at", "stamp_commit", "stamped_at", "key_id"]);
// THE PROJECTION (unit R-L4): a role's entry in the case root is its
// registration's entry, the sha256 of the registration file's bytes as the
// pins repository holds them, and (unit R-L4c, c4) the file's claim, which
// names its path (THE CLAIM, below). A file is a claim, inert until the
// case root projects it; every reader takes a registration from this entry
// and checks the file at the claim's path against this sha256
// (lib/_case_seal.js projectedRegistrations).
const CASE_ENTRY_FIELDS = Object.freeze([...COMMITMENT_ENTRY_FIELDS, "registration_sha256", "claim_sha256"]);
const REVEAL_ENTRY_FIELDS = Object.freeze(["tape_sha256", "salt_sha256", "revealed_at"]);
const CROSS_REFERENCE_FIELDS = Object.freeze(["operator", "reference", "url", "recorded_at"]);
// THE WITHDRAWAL, above: the role, the service's time, and the sha256 of the
// salt that proved the role (nothing else of the preimage).
const WITHDRAWAL_FIELDS = Object.freeze(["by_role", "at", "salt_sha256"]);
// THE REASON (Design N), above.
const WITHDRAWAL_OPTIONAL = Object.freeze(["reason"]);
const WITHDRAWAL_REASONS = Object.freeze(["party_choice", "deadline", "other"]);
// What a caller may send to ?op=case-withdraw, and nothing else.
const WITHDRAW_BODY_FIELDS = Object.freeze(["case_id", "role", "tape_sha256", "salt"]);
const WITHDRAW_BODY_OPTIONAL = Object.freeze(["reason"]);
// THE REFERENCE ROW, above: what a caller may send to ?op=case-reference.
const REFERENCE_BODY_FIELDS = Object.freeze(["case_id", "role", "tape_sha256", "salt", "cross_reference"]);
const REFERENCE_PROOF_FIELDS = Object.freeze(["role", "tape_sha256", "salt"]);
// The row cases/<case_id>/references/<seq>.json, record type case_reference.
const REFERENCE_KIND = "case_reference";
const REFERENCE_FIELDS = Object.freeze([
  "kind", "v", "case_id", "seq", "cross_reference", "recorded_at", "appended_by", "anchor_note", "note_version", "signed_under", "signed_by",
  "sig", "sig_reason",
]);
const REFERENCE_ROW_CROSS_FIELDS = Object.freeze(["operator", "reference", "url"]);
// unit R-SIG: what the service read, the role's commitment preimage or the
// operator's key; never a party's name
const APPENDED_BY = Object.freeze(["preimage:a", "preimage:b", "operator"]);
const MAX_REFERENCE_SEQ = 99999999; // eight digits
// The row's own words about its anchor, version 4 (THE ROW'S SENTENCE,
// above). Verbatim in every row, with note_version 4; the judge refuses any
// other text.
const REFERENCE_ANCHOR_NOTE =
  "This row has no pin of its own. It is recorded by the pins-repository commit that writes it, and no anchoring is asserted here.";
const REFERENCE_NOTE_VERSION = 4;

// The public registration record, at its claim's path (THE CLAIM, below):
// registrations/<case_id>/<role>/<claim>.json.
const REGISTRATION_KIND = "case-commitment";
const REGISTRATION_FIELDS = Object.freeze([
  "kind", "v", "case_id", "role", "commitment_sha256", "registered_at", "stamp_commit", "stamped_at", "key_id", "verifier", "sig",
]);
// What a caller may send to ?op=case-commit, and nothing else.
const REGISTRATION_BODY_FIELDS = Object.freeze(["case_id", "role", "commitment_sha256", "verifier", "sig"]);
// ONE KEY PER ROLE, above: the kind inside the bytes a registration key signs.
const REGISTRATION_SIG_KIND = "case-registration-signature";
// What a caller may send to ?op=case-reveal beside the two tapes (THE JOINT
// REVEAL'S BODY, above), and the tapes' own field names, by role.
// `role` (unit R-N, N3): optional; on a withdrawn case it names the
// requester, whose own opening alone is read.
const REVEAL_BODY_FIELDS = Object.freeze(["case_id", "reveals", "cross_reference", "role"]);
const REVEAL_INPUT_FIELDS = Object.freeze(["tape_sha256", "salt"]);
const CROSS_REFERENCE_INPUT_FIELDS = Object.freeze(["operator", "reference", "url"]);
const REVEAL_TAPE_FIELDS = Object.freeze(["tape_a", "tape_b", "tape_a_b64", "tape_b_b64"]);
const SIDE_TAPE_FIELDS = Object.freeze(["agent_tape", "tool_tape", "agent_tape_b64", "tool_tape_b64"]);

// The four non-claims (design, the claim section: "The service does not
// establish who the parties are (labels are recorded, never verified), that
// either tape is complete or true, that the parties did not exchange tapes
// privately before committing, or fault. The page carries those four
// sentences."). Inside every case object, and so inside the signed bytes once
// item two signs one.
const LIMITS = Object.freeze([
  "This service does not establish who the parties are. Labels are recorded, never verified.",
  "This service does not establish that either tape is complete or true.",
  "This service does not establish that the parties did not exchange tapes privately before committing.",
  "This service does not establish fault.",
]);

const UNSEALED_SIG_REASON = "This case is not sealed. An open or committed case object carries no signature.";

const CASE_ERROR_CODES = Object.freeze([
  "not_an_object",
  "unknown_field",
  "missing_field",
  "malformed_field",
  "unknown_version",
  "unsupported_protocol_version",
  "unsupported_policy_version",
  "bad_role",
  "parties_not_distinct",
  "parties_not_canonical",
  "deadline_not_after_opened_at",
  "deadline_too_far",
  "case_id_mismatch",
  "duplicate_commitment",
  "status_inconsistent",
  "limits_altered",
  "sig_reason_missing",
  "role_already_committed",
  "case_not_open",
  "row_note_v3", // a reference row with note_version 3, never issued (unit R-PIN), read with its own reading (unit R-SIG)
]);

class CaseError extends Error {
  constructor(code, field, message) {
    super(message);
    this.name = "CaseError";
    if (!CASE_ERROR_CODES.includes(code)) throw new TypeError(`CaseError: unknown code ${code}`);
    this.code = code;
    this.field = field;
  }
}

// ---------------------------------------------------------------------------
// small checks
// ---------------------------------------------------------------------------
const HEX64 = /^[0-9a-f]{64}$/;
// A git object id: sha1 (40) or sha256 (64), lowercase.
const GIT_SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const MAX_TEXT_CODE_POINTS = 200;
// A cross-reference URL as a caller may send it: https, printable ASCII only
// (no space, no control character, no lone surrogate), bounded.
const HTTPS_URL_IN = /^https:\/\/[\x21-\x7e]+$/;
const MAX_URL_LENGTH = 2048;
// Times this service writes: UTC, whole seconds, literal Z.
const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
// A time this service copies from another record verbatim (a stamp's
// stamped_at is toISOString(), milliseconds included): the lib/_check_record.js
// ISO_UTC rule.
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
// What an opening may send for opened_at / deadline before normalization.
const ISO_IN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/;
const MAX_TIME_MS = Date.UTC(9999, 11, 31, 23, 59, 59);

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function sha256hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function checkHex64(v, field) {
  if (typeof v !== "string" || !HEX64.test(v)) {
    throw new CaseError("malformed_field", field, `${field} must be exactly 64 lowercase hex characters`);
  }
  return v;
}

// A label, key id or version string: recorded as given, so it has to be a
// string both canonicalizers encode to the same bytes.
function checkText(v, field) {
  if (typeof v !== "string" || v.length === 0) {
    throw new CaseError("malformed_field", field, `${field} must be a non-empty string`);
  }
  if (LONE_SURROGATE.test(v)) {
    throw new CaseError("malformed_field", field, `${field} holds a lone surrogate, which json-c14n:v1 cannot encode`);
  }
  if (CONTROL.test(v)) {
    throw new CaseError("malformed_field", field, `${field} holds a control character`);
  }
  if (Array.from(v).length > MAX_TEXT_CODE_POINTS) {
    throw new CaseError("malformed_field", field, `${field} is longer than ${MAX_TEXT_CODE_POINTS} characters`);
  }
  return v;
}

function onlyFields(obj, allowed, where) {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) {
      throw new CaseError("unknown_field", where ? `${where}.${k}` : k, `unknown field ${JSON.stringify(k).slice(0, 80)}${where ? ` in ${where}` : ""}`);
    }
  }
}

function requireFields(obj, required, where) {
  for (const k of required) {
    if (!Object.prototype.hasOwnProperty.call(obj, k)) {
      throw new CaseError("missing_field", where ? `${where}.${k}` : k, `${where ? `${where}.` : ""}${k} is required`);
    }
  }
}

// Python's str ordering: by code point, not by UTF-16 code unit.
function compareCodePoints(a, b) {
  const ai = Array.from(a);
  const bi = Array.from(b);
  const n = Math.min(ai.length, bi.length);
  for (let i = 0; i < n; i += 1) {
    const d = ai[i].codePointAt(0) - bi[i].codePointAt(0);
    if (d !== 0) return d;
  }
  return ai.length - bi.length;
}

// ---------------------------------------------------------------------------
// time
// ---------------------------------------------------------------------------
// -> epoch milliseconds (whole seconds, the fraction truncated), or null.
function parseIsoToUtcSecondsMs(s) {
  if (typeof s !== "string") return null;
  const m = ISO_IN.exec(s);
  if (!m) return null;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  if (y < 1970 || mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59) return null;
  const wall = Date.UTC(y, mo - 1, d, h, mi, se);
  const back = new Date(wall);
  if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d) return null; // 30 February
  let offsetMinutes = 0;
  if (m[8] !== "Z") {
    const oh = Number(m[10]);
    const om = Number(m[11]);
    if (oh > 23 || om > 59) return null;
    offsetMinutes = (m[9] === "-" ? -1 : 1) * (oh * 60 + om);
  }
  const utc = wall - offsetMinutes * 60000;
  if (utc < 0 || utc > MAX_TIME_MS) return null;
  return utc;
}

function utcSeconds(ms) {
  if (!Number.isFinite(ms)) throw new TypeError("utcSeconds: not a time");
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

// "opened_at normalized to UTC seconds": any accepted form -> YYYY-MM-DDTHH:MM:SSZ.
function normalizeUtcSeconds(s, field = "time") {
  const ms = parseIsoToUtcSecondsMs(s);
  if (ms === null) {
    throw new CaseError("malformed_field", field,
      `${field} must be an ISO 8601 time with a date, hours, minutes, seconds and Z or a +HH:MM offset`);
  }
  return utcSeconds(ms);
}

function isUtcSeconds(s) {
  return typeof s === "string" && UTC_SECONDS.test(s) && parseIsoToUtcSecondsMs(s) !== null;
}

function isIsoUtc(s) {
  return typeof s === "string" && ISO_UTC.test(s) && Number.isFinite(Date.parse(s));
}

// ---------------------------------------------------------------------------
// parties
// ---------------------------------------------------------------------------
// -> a clean copy {side, label[, key_id]}. key_id, when absent, is ABSENT in
// the canonical bytes (not null): one spelling for "no key id".
function cleanParty(p, field) {
  if (!isPlainObject(p)) throw new CaseError("malformed_field", field, `${field} must be an object {side, label, key_id?}`);
  onlyFields(p, PARTY_FIELDS, field);
  requireFields(p, ["side", "label"], field);
  if (!SIDES.includes(p.side)) throw new CaseError("malformed_field", `${field}.side`, `${field}.side must be "agent" or "tool"`);
  const out = { side: p.side, label: checkText(p.label, `${field}.label`) };
  if (Object.prototype.hasOwnProperty.call(p, "key_id")) out.key_id = checkText(p.key_id, `${field}.key_id`);
  return out;
}

function compareParties(p, q) {
  const byLabel = compareCodePoints(p.label, q.label);
  return byLabel !== 0 ? byLabel : compareCodePoints(p.side, q.side);
}

// -> {party_a, party_b, reordered}. Throws parties_not_distinct on a tie.
function canonicalParties(p, q) {
  const c = compareParties(p, q);
  if (c === 0) {
    throw new CaseError("parties_not_distinct", "party_b",
      "the two parties have the same label and the same side, so the rule (label, then side) cannot order them");
  }
  return c < 0 ? { party_a: p, party_b: q, reordered: false } : { party_a: q, party_b: p, reordered: true };
}

// ---------------------------------------------------------------------------
// the case id
// ---------------------------------------------------------------------------
// The preimage object for the id, from opening-shaped fields in any party
// order and any accepted time form. Reads the six id fields and nothing else
// (an opening's `deadline` is not part of the id).
function caseIdPreimage(fields) {
  if (!isPlainObject(fields)) throw new CaseError("not_an_object", "$", "the opening must be a JSON object");
  requireFields(fields, CASE_ID_FIELDS);
  if (fields.protocol_version !== PROTOCOL_VERSION) {
    throw new CaseError("unsupported_protocol_version", "protocol_version", `protocol_version must be "${PROTOCOL_VERSION}"`);
  }
  const policy = checkText(fields.policy_version, "policy_version");
  const scope = checkHex64(fields.scope_digest, "scope_digest");
  const { party_a, party_b } = canonicalParties(cleanParty(fields.party_a, "party_a"), cleanParty(fields.party_b, "party_b"));
  return {
    protocol_version: PROTOCOL_VERSION,
    policy_version: policy,
    scope_digest: scope,
    party_a,
    party_b,
    opened_at: normalizeUtcSeconds(fields.opened_at, "opened_at"),
  };
}

function caseIdBytes(fields) {
  return canonicalBytes(caseIdPreimage(fields));
}

function deriveCaseId(fields) {
  return sha256hex(caseIdBytes(fields));
}

// ---------------------------------------------------------------------------
// the opening
// ---------------------------------------------------------------------------
// -> {opening: {the seven fields, normalized, parties in canonical order},
//     parties_reordered}. The clock checks (future-dated, deadline already
// past) need a clock, so they are the HTTP layer's.
function validateOpening(body, { policyVersion = SUPPORTED_POLICY_VERSION } = {}) {
  if (!isPlainObject(body)) throw new CaseError("not_an_object", "$", "the opening must be a JSON object");
  onlyFields(body, OPENING_FIELDS);
  requireFields(body, OPENING_FIELDS);
  if (body.protocol_version !== PROTOCOL_VERSION) {
    throw new CaseError("unsupported_protocol_version", "protocol_version", `protocol_version must be "${PROTOCOL_VERSION}"`);
  }
  checkText(body.policy_version, "policy_version");
  if (body.policy_version !== policyVersion) {
    throw new CaseError("unsupported_policy_version", "policy_version",
      `this service runs reconcile port version ${policyVersion}; a case opened under another version could not be compared under it`);
  }
  const pre = caseIdPreimage(body);
  const { reordered } = canonicalParties(cleanParty(body.party_a, "party_a"), cleanParty(body.party_b, "party_b"));
  const deadline = normalizeUtcSeconds(body.deadline, "deadline");
  if (Date.parse(deadline) <= Date.parse(pre.opened_at)) {
    throw new CaseError("deadline_not_after_opened_at", "deadline", "deadline must be later than opened_at");
  }
  if (Date.parse(deadline) - Date.parse(pre.opened_at) > MAX_DEADLINE_DAYS * 86400000) {
    throw new CaseError("deadline_too_far", "deadline",
      `deadline must be at most ${MAX_DEADLINE_DAYS} days after opened_at (THE DEADLINE HORIZON)`);
  }
  return { opening: { ...pre, deadline }, parties_reordered: reordered };
}

// The OPEN case object for a validated opening.
function newCase(opening, caseId) {
  const id = caseId === undefined ? deriveCaseId(opening) : caseId;
  return {
    v: CASE_VERSION,
    case_id: id,
    protocol_version: opening.protocol_version,
    policy_version: opening.policy_version,
    scope_digest: opening.scope_digest,
    party_a: opening.party_a,
    party_b: opening.party_b,
    opened_at: opening.opened_at,
    deadline: opening.deadline,
    commitments: { a: null, b: null },
    reveals: null,
    verdict: null,
    records: 1,
    cross_reference: null,
    status: "OPEN",
    withdrawal: null,
    limits: LIMITS.slice(),
    signed_by: null,
    sig: null,
    sig_reason: UNSEALED_SIG_REASON,
  };
}

// ---------------------------------------------------------------------------
// the commitment
// ---------------------------------------------------------------------------
function commitmentPreimage(input) {
  if (!isPlainObject(input)) throw new CaseError("not_an_object", "$", "the commitment input must be an object");
  onlyFields(input, COMMITMENT_INPUT_FIELDS);
  requireFields(input, ["case_id", "role", "tape_sha256", "salt"]);
  const protocol = Object.prototype.hasOwnProperty.call(input, "protocol_version") ? input.protocol_version : PROTOCOL_VERSION;
  if (protocol !== PROTOCOL_VERSION) {
    throw new CaseError("unsupported_protocol_version", "protocol_version", `protocol_version must be "${PROTOCOL_VERSION}"`);
  }
  checkHex64(input.case_id, "case_id");
  if (!ROLES.includes(input.role)) throw new CaseError("bad_role", "role", 'role must be "a" or "b"');
  checkHex64(input.tape_sha256, "tape_sha256");
  checkHex64(input.salt, "salt");
  return {
    case_id: input.case_id,
    role: input.role,
    tape_sha256: input.tape_sha256,
    salt: input.salt,
    protocol_version: PROTOCOL_VERSION,
  };
}

function commitmentBytes(input) {
  return canonicalBytes(commitmentPreimage(input));
}

function commitmentSha256(input) {
  return sha256hex(commitmentBytes(input));
}

// 32 random bytes as hex: the salt a party keeps until the joint reveal.
function newSalt() {
  return crypto.randomBytes(32).toString("hex");
}

const COMMITMENT_BYTES_LENGTH = commitmentBytes({
  case_id: "0".repeat(64), role: "a", tape_sha256: "0".repeat(64), salt: "0".repeat(64),
}).length;

// What a sealed case keeps of a salt: the sha256 of its 32 bytes.
function saltSha256(salt) {
  checkHex64(salt, "salt");
  return sha256hex(Buffer.from(salt, "hex"));
}

// ---------------------------------------------------------------------------
// the joint reveal (THE JOINT REVEAL'S BODY, above)
// ---------------------------------------------------------------------------
function checkUrlIn(v, field) {
  if (typeof v !== "string" || !HTTPS_URL_IN.test(v) || v.length > MAX_URL_LENGTH) {
    throw new CaseError("malformed_field", field,
      `${field} must be an https URL of printable ASCII, at most ${MAX_URL_LENGTH} characters`);
  }
  return v;
}

// The reveal's top level, before the case is read (unit R-N, N3): an
// object, no unknown field, and its case_id. Nothing under reveals is read
// here. -> the case_id.
function revealCaseId(body) {
  if (!isPlainObject(body)) throw new CaseError("not_an_object", "$", "the reveal must be a JSON object");
  for (const k of Object.keys(body)) {
    if (REVEAL_BODY_FIELDS.includes(k)) continue;
    if (SIDE_TAPE_FIELDS.includes(k)) {
      throw new CaseError("unknown_field", k,
        `unknown field ${k}: a reveal names each tape by its role (tape_a and tape_b, or tape_a_b64 and tape_b_b64), ` +
          "because a commitment binds a role, not a side");
    }
    throw new CaseError("unknown_field", k,
      `unknown field ${JSON.stringify(k).slice(0, 80)}: a reveal carries case_id, reveals, cross_reference, role and the two tapes, ` +
        "and every time in it is this service's clock");
  }
  requireFields(body, ["case_id"]);
  return checkHex64(body.case_id, "case_id");
}

// THE REFUSAL'S ONE OPENING (unit R-N, N3): on a withdrawn case, the
// requester's role (`role`) and its own opening, reveals[role], and nothing
// else: the other role's entry is never read. -> {role, tape_sha256, salt},
// or null when the body names no role "a" or "b", or holds no opening
// {tape_sha256, salt} of 64 lowercase hex each for it.
function refusalOpening(body) {
  if (!isPlainObject(body) || !ROLES.includes(body.role)) return null;
  const rv = body.reveals;
  if (!isPlainObject(rv) || !Object.prototype.hasOwnProperty.call(rv, body.role)) return null;
  const e = rv[body.role];
  if (!isPlainObject(e) || Object.keys(e).length !== REVEAL_INPUT_FIELDS.length) return null;
  for (const k of REVEAL_INPUT_FIELDS) {
    if (typeof e[k] !== "string" || !HEX64.test(e[k])) return null;
  }
  return { role: body.role, tape_sha256: e.tape_sha256, salt: e.salt };
}

// -> {case_id, reveals: {a: {tape_sha256, salt}, b: {...}}, cross_reference:
//    {operator, reference, url} or null, role: "a" | "b" | null}. The tapes
// are not this function's: the caller strips REVEAL_TAPE_FIELDS out before it
// calls. A joint reveal reads both openings; `role`, when present, is "a" or
// "b" and changes nothing.
function validateRevealBody(body) {
  revealCaseId(body);
  requireFields(body, ["case_id", "reveals"]);
  if (Object.prototype.hasOwnProperty.call(body, "role") && !ROLES.includes(body.role)) {
    throw new CaseError("bad_role", "role", 'role must be "a" or "b"');
  }
  const rv = body.reveals;
  if (!isPlainObject(rv)) {
    throw new CaseError("malformed_field", "reveals", "reveals must be an object {a: {tape_sha256, salt}, b: {tape_sha256, salt}}");
  }
  onlyFields(rv, ROLES, "reveals");
  requireFields(rv, ROLES, "reveals");
  const reveals = {};
  for (const r of ROLES) {
    const f = `reveals.${r}`;
    const e = rv[r];
    if (!isPlainObject(e)) throw new CaseError("malformed_field", f, `${f} must be an object {tape_sha256, salt}`);
    onlyFields(e, REVEAL_INPUT_FIELDS, f);
    requireFields(e, REVEAL_INPUT_FIELDS, f);
    reveals[r] = { tape_sha256: checkHex64(e.tape_sha256, `${f}.tape_sha256`), salt: checkHex64(e.salt, `${f}.salt`) };
  }
  let cross = null;
  if (Object.prototype.hasOwnProperty.call(body, "cross_reference") && body.cross_reference !== null) {
    cross = crossReferenceInput(body.cross_reference, false);
  }
  return { case_id: body.case_id, reveals, cross_reference: cross, role: Object.prototype.hasOwnProperty.call(body, "role") ? body.role : null };
}

// A caller's cross_reference, {operator, reference, url}, cleaned: the
// reveal's (optional) and the reference row's (required) use one rule.
function crossReferenceInput(x, required) {
  if (!isPlainObject(x)) {
    throw new CaseError("malformed_field", "cross_reference", required
      ? "cross_reference must be an object {operator, reference, url}"
      : "cross_reference must be absent, null, or an object {operator, reference, url}");
  }
  onlyFields(x, CROSS_REFERENCE_INPUT_FIELDS, "cross_reference");
  requireFields(x, CROSS_REFERENCE_INPUT_FIELDS, "cross_reference");
  return {
    operator: checkText(x.operator, "cross_reference.operator"),
    reference: checkText(x.reference, "cross_reference.reference"),
    url: checkUrlIn(x.url, "cross_reference.url"),
  };
}

// ---------------------------------------------------------------------------
// registrations
// ---------------------------------------------------------------------------
function validateRegistrationBody(body) {
  if (!isPlainObject(body)) throw new CaseError("not_an_object", "$", "the registration must be a JSON object");
  for (const k of Object.keys(body)) {
    if (!REGISTRATION_BODY_FIELDS.includes(k)) {
      throw new CaseError("unknown_field", k,
        `unknown field ${JSON.stringify(k).slice(0, 80)}: a registration carries case_id, role, commitment_sha256, verifier and sig only; ` +
          "the stamp's commit and time are read from the stamp record, never taken from a caller");
    }
  }
  requireFields(body, REGISTRATION_BODY_FIELDS);
  checkHex64(body.case_id, "case_id");
  if (!ROLES.includes(body.role)) throw new CaseError("bad_role", "role", 'role must be "a" or "b"');
  checkHex64(body.commitment_sha256, "commitment_sha256");
  const key_id = checkRegistrationKey(body.verifier, body.sig);
  return { case_id: body.case_id, role: body.role, commitment_sha256: body.commitment_sha256, verifier: body.verifier, sig: body.sig, key_id };
}

// ONE KEY PER ROLE, above. The bytes a registration key signs.
function registrationSigningBytes({ case_id, role, commitment_sha256 }) {
  return canonicalBytes({ kind: REGISTRATION_SIG_KIND, v: 1, case_id, role, commitment_sha256 });
}

// The verifier's shape and the signature's (64 bytes, canonical base64).
// Not the signature's truth: registrationSignatureReason. -> the key id,
// <name>+<8 hex>, one KEY_ID reads (lib/_checkpoint.js caps no name, KEY_ID
// caps it at 180 characters, so a longer one is refused here, never later).
function checkRegistrationKey(verifier, sig) {
  const vk = checkpoint.parseVerifierKey(verifier);
  if (!vk.ok || !KEY_ID.test(`${vk.name}+${vk.hash}`)) {
    throw new CaseError("malformed_field", "verifier",
      "verifier must be an Ed25519 verifier string, <name>+<8 hex>+<base64(0x01 || public key)> (lib/_checkpoint.js), its name at most 180 characters");
  }
  if (typeof sig !== "string" || Buffer.from(sig, "base64").length !== 64 || Buffer.from(sig, "base64").toString("base64") !== sig) {
    throw new CaseError("malformed_field", "sig", "sig must be a 64-byte Ed25519 signature in base64");
  }
  return `${vk.name}+${vk.hash}`;
}

// Whether `sig` is the signature of `verifier`'s key over this
// registration's signing bytes. Shapes already checked (checkRegistrationKey).
// -> null when it holds, else "bad_signature".
function registrationSignatureReason({ case_id, role, commitment_sha256, verifier, sig }) {
  const vk = checkpoint.parseVerifierKey(verifier);
  let good = false;
  try {
    good = vk.ok && crypto.verify(null, registrationSigningBytes({ case_id, role, commitment_sha256 }), vk.publicKey, Buffer.from(sig, "base64"));
  } catch {
    good = false;
  }
  return good ? null : "bad_signature";
}

// A party's signature over its registration, with its signer string
// (PRIVATE+KEY+..., lib/_checkpoint.js). For parties and tools; this service
// never holds a registration key. -> base64.
function signRegistration({ case_id, role, commitment_sha256 }, signerString) {
  const k = checkpoint.parseSignerKey(signerString);
  if (!k.ok) throw new TypeError(`signRegistration: the signer key does not parse (${k.reason})`);
  return crypto.sign(null, registrationSigningBytes({ case_id, role, commitment_sha256 }), k.privateKey).toString("base64");
}

function checkCommitmentEntry(e, field, fields = COMMITMENT_ENTRY_FIELDS) {
  if (!isPlainObject(e)) throw new CaseError("malformed_field", field, `${field} must be null or an object`);
  onlyFields(e, fields, field);
  requireFields(e, fields, field);
  checkHex64(e.commitment_sha256, `${field}.commitment_sha256`);
  if (!isUtcSeconds(e.registered_at)) throw new CaseError("malformed_field", `${field}.registered_at`, `${field}.registered_at must be UTC seconds`);
  // since unit R-RV stamp_commit is required: null (the item-one form) is malformed
  if (typeof e.stamp_commit !== "string" || !GIT_SHA.test(e.stamp_commit)) {
    throw new CaseError("malformed_field", `${field}.stamp_commit`, `${field}.stamp_commit must be a git commit id`);
  }
  if (!isIsoUtc(e.stamped_at)) throw new CaseError("malformed_field", `${field}.stamped_at`, `${field}.stamped_at must be an ISO 8601 UTC time`);
  if (typeof e.key_id !== "string" || !KEY_ID.test(e.key_id)) {
    throw new CaseError("malformed_field", `${field}.key_id`, `${field}.key_id must be a key id, <name>+<8 hex>`);
  }
}

function registrationRecord({ case_id, role, commitment_sha256, registered_at, stamp_commit, stamped_at, key_id, verifier, sig }) {
  const rec = { kind: REGISTRATION_KIND, v: 1, case_id, role, commitment_sha256, registered_at, stamp_commit, stamped_at, key_id, verifier, sig };
  const r = validateRegistrationRecord(rec);
  if (!r.ok) throw new CaseError(r.code, r.field, r.error);
  return rec;
}

function validateRegistrationRecord(rec) {
  try {
    if (!isPlainObject(rec)) throw new CaseError("not_an_object", "$", "a registration record must be an object");
    onlyFields(rec, REGISTRATION_FIELDS);
    requireFields(rec, REGISTRATION_FIELDS);
    if (rec.kind !== REGISTRATION_KIND) throw new CaseError("malformed_field", "kind", `kind must be "${REGISTRATION_KIND}"`);
    if (rec.v !== 1) throw new CaseError("unknown_version", "v", "v must be 1");
    checkHex64(rec.case_id, "case_id");
    if (!ROLES.includes(rec.role)) throw new CaseError("bad_role", "role", 'role must be "a" or "b"');
    const { kind, v, case_id, role, verifier, sig, ...entry } = rec; // eslint-disable-line no-unused-vars
    checkCommitmentEntry(entry, "registration");
    // ONE KEY PER ROLE, above: the key the record names, and its proof.
    if (checkRegistrationKey(verifier, sig) !== rec.key_id) {
      throw new CaseError("malformed_field", "key_id", "key_id must be its verifier's key id, the verifier's first two segments");
    }
    if (registrationSignatureReason(rec) !== null) {
      throw new CaseError("malformed_field", "sig", "sig is not the signature of the verifier's key over this registration");
    }
    return { ok: true };
  } catch (e) {
    if (e instanceof CaseError) return { ok: false, code: e.code, field: e.field, error: e.message };
    throw e;
  }
}

// A registration's entry, from a registration record: what the case root
// projects of it, but for the file's sha256 (caseEntry).
// THE CLAIM (unit R-L4c, c4, as the architect ruled). A registration file
// is a claim, and more than one claim for a role may exist: each is keyed by
// the fields a party supplies, and these are exactly the fields a party
// supplies: the case id, the role and the commitment (the fields its key
// signs), and the registering key (its verifier, and the key id that
// verifier names) with the party's signature. The fields this service adds
// when it writes a registration (registered_at, stamp_commit, stamped_at;
// the record's kind and version) are never part of it, so the same
// registration sent again is the same claim. The claim is the sha256 of the
// json-c14n:v1 bytes of those fields; the file lives at
// registrations/<case_id>/<role>/<claim>.json, written create-only. The case
// root projects at most one claim per role.
const PARTY_SUPPLIED_FIELDS = Object.freeze(["case_id", "role", "commitment_sha256", "verifier", "key_id", "sig"]);
function claimSha256(reg) {
  return sha256hex(canonicalBytes(Object.fromEntries(PARTY_SUPPLIED_FIELDS.map((k) => [k, reg[k]]))));
}
// THE SAME REGISTRATION: null when `held` (a file's JSON) is a registration
// record with the same party-supplied fields as `asked`, else the first
// field that differs, or "record" when it is not a registration record.
function partySuppliedDiffers(held, asked) {
  if (!validateRegistrationRecord(held).ok) return "record";
  for (const k of PARTY_SUPPLIED_FIELDS) if (held[k] !== asked[k]) return k;
  return null;
}

function commitmentEntry(reg) {
  return {
    commitment_sha256: reg.commitment_sha256,
    registered_at: reg.registered_at,
    stamp_commit: reg.stamp_commit,
    stamped_at: reg.stamped_at,
    key_id: reg.key_id,
  };
}

// The per-role entry of the case root (THE PROJECTION, above): the
// registration's entry, `registrationSha256`, the sha256 of the bytes of the
// registration file the root projects, and its claim (THE CLAIM).
function caseEntry(reg, registrationSha256) {
  return { ...commitmentEntry(reg), registration_sha256: registrationSha256, claim_sha256: claimSha256(reg) };
}

// ONE KEY PER ROLE, above: both roles registered, under one key id. A
// WITHDRAWN record is never single party (since unit R-L5 it keeps its
// projection, and the withdrawal is what it shows).
function singleParty(caseObj) {
  const c = isPlainObject(caseObj) && caseObj.status !== "WITHDRAWN" ? caseObj.commitments : null;
  return isPlainObject(c) && isPlainObject(c.a) && isPlainObject(c.b) && c.a.key_id === c.b.key_id;
}

function sameEntry(x, y) {
  return !!x && !!y && COMMITMENT_ENTRY_FIELDS.every((k) => x[k] === y[k]);
}

// A NEW case object with `reg` projected into commitments[reg.role], with
// `registrationSha256`, the sha256 of its file's bytes (THE PROJECTION,
// above). Refuses a case that is not OPEN or COMMITTED, and a role that
// already holds an entry. Pure: no I/O, and the argument is not mutated.
//
// STATUS NEVER REGRESSES (item 1b, after Gemini's code review: "If this
// function is somehow called on a case that has already advanced to VERDICT
// ... it will regress the status to COMMITTED"). Every status other than OPEN
// or COMMITTED (VERDICT, WITHDRAWN, a stored EXPIRED, anything unknown) is
// refused `case_not_open` before anything is computed; that guard was here in
// the item-one build. What item 1b changes is the status itself: it is no
// longer computed from the commitments, which could turn a COMMITTED case
// with an empty slot back into OPEN. The one move this function makes is
// OPEN to COMMITTED, when the second role lands; a COMMITTED case stays
// COMMITTED.
function applyRegistration(caseObj, reg, registrationSha256) {
  if (!REGISTERABLE_STATUSES.includes(caseObj.status)) {
    throw new CaseError("case_not_open", "status", `the case is ${caseObj.status}, not OPEN or COMMITTED`);
  }
  if (caseObj.case_id !== reg.case_id) throw new CaseError("case_id_mismatch", "case_id", "the registration is for another case");
  if (caseObj.commitments[reg.role] !== null) {
    throw new CaseError("role_already_committed", "role", `role ${reg.role} already has a registered commitment`);
  }
  if (typeof registrationSha256 !== "string" || !HEX64.test(registrationSha256)) {
    throw new CaseError("malformed_field", "registration_sha256", "a projection carries the sha256 of the registration file's bytes");
  }
  const commitments = { ...caseObj.commitments, [reg.role]: caseEntry(reg, registrationSha256) };
  const both = commitments.a !== null && commitments.b !== null;
  const status = caseObj.status === "OPEN" && both ? "COMMITTED" : caseObj.status;
  return { ...caseObj, commitments, status };
}

function pastDeadline(caseObj, nowMs) {
  return nowMs >= Date.parse(caseObj.deadline);
}

// ---------------------------------------------------------------------------
// the case object: validation (never throws)
// ---------------------------------------------------------------------------
// THE SIGNATURE BY KIND (unit R-SIG). `signed` is true for every record
// the service signs (a VERDICT, a WITHDRAWN record, a reference row): sig a
// non-empty string, sig_reason null, signed_by a key id. Otherwise (an OPEN
// or COMMITTED root) sig and signed_by are null and sig_reason is exactly
// UNSEALED_SIG_REASON.
function checkSig(rec, signed) {
  if (signed) {
    if (typeof rec.sig !== "string" || rec.sig === "") throw new CaseError("malformed_field", "sig", "a signed record carries its signature: sig is a non-empty string");
    if (rec.sig_reason !== null) throw new CaseError("malformed_field", "sig_reason", "a signed record carries sig_reason null");
    return;
  }
  if (rec.sig !== null) throw new CaseError("malformed_field", "sig", "an open or committed case carries no signature: sig is null");
  if (rec.sig_reason === null) throw new CaseError("sig_reason_missing", "sig_reason", "an unsigned case must say why (sig_reason)");
  if (rec.sig_reason !== UNSEALED_SIG_REASON) {
    throw new CaseError("malformed_field", "sig_reason", "an open or committed case carries the one fixed sig_reason, UNSEALED_SIG_REASON");
  }
}

// SIGNED_BY, above.
function checkSignedBy(rec, signed) {
  const k = rec.signed_by;
  if (signed && (typeof k !== "string" || !KEY_ID.test(k))) {
    throw new CaseError("malformed_field", "signed_by", "a signed record names its key in signed_by, a key id, <key name>+<8 lowercase hex>");
  }
  if (!signed && k !== null) throw new CaseError("malformed_field", "signed_by", "an unsigned case carries signed_by null");
}

function checkLimits(rec) {
  const l = rec.limits;
  if (!Array.isArray(l) || l.length !== LIMITS.length || l.some((s, i) => s !== LIMITS[i])) {
    throw new CaseError("limits_altered", "limits", "limits must be the four non-claims, unaltered and in order");
  }
}

function checkWithdrawal(w, field) {
  if (!isPlainObject(w)) throw new CaseError("malformed_field", field, `${field} must be an object {by_role, at, salt_sha256, reason}`);
  onlyFields(w, [...WITHDRAWAL_FIELDS, ...WITHDRAWAL_OPTIONAL], field);
  requireFields(w, WITHDRAWAL_FIELDS, field);
  if (!ROLES.includes(w.by_role)) throw new CaseError("bad_role", `${field}.by_role`, 'by_role must be "a" or "b"');
  if (!isUtcSeconds(w.at)) throw new CaseError("malformed_field", `${field}.at`, `${field}.at must be UTC seconds`);
  checkHex64(w.salt_sha256, `${field}.salt_sha256`);
  if (Object.prototype.hasOwnProperty.call(w, "reason") && !WITHDRAWAL_REASONS.includes(w.reason)) {
    throw new CaseError("malformed_field", `${field}.reason`, `${field}.reason must be one of ${WITHDRAWAL_REASONS.join(", ")}`);
  }
}

function checkWithdrawn(rec) {
  onlyFields(rec, WITHDRAWN_FIELDS);
  requireFields(rec, WITHDRAWN_FIELDS);
  if (rec.v !== CASE_VERSION) throw new CaseError("unknown_version", "v", "v must be 1");
  checkHex64(rec.case_id, "case_id");
  if (rec.protocol_version !== PROTOCOL_VERSION) throw new CaseError("unsupported_protocol_version", "protocol_version", `protocol_version must be "${PROTOCOL_VERSION}"`);
  if (!isUtcSeconds(rec.opened_at)) throw new CaseError("malformed_field", "opened_at", "opened_at must be UTC seconds");
  checkWithdrawal(rec.withdrawal, "withdrawal");
  if (Date.parse(rec.withdrawal.at) < Date.parse(rec.opened_at)) {
    throw new CaseError("status_inconsistent", "withdrawal.at", "a case is withdrawn after it is opened");
  }
  // THE PROJECTION KEPT (unit R-L5): the root's commitments as they stood,
  // each a case entry or null; the role that withdrew proved one of them
  const c = rec.commitments;
  if (!isPlainObject(c)) throw new CaseError("malformed_field", "commitments", "commitments must be an object {a, b}");
  onlyFields(c, ROLES, "commitments");
  requireFields(c, ROLES, "commitments");
  for (const r of ROLES) {
    if (c[r] === null) continue;
    checkCommitmentEntry(c[r], `commitments.${r}`, CASE_ENTRY_FIELDS);
    checkHex64(c[r].registration_sha256, `commitments.${r}.registration_sha256`);
    checkHex64(c[r].claim_sha256, `commitments.${r}.claim_sha256`);
  }
  if (c[rec.withdrawal.by_role] === null) {
    throw new CaseError("status_inconsistent", `commitments.${rec.withdrawal.by_role}`, "the role that withdrew proved a registration the case projected");
  }
  if (c.a !== null && c.b !== null && c.a.commitment_sha256 === c.b.commitment_sha256) {
    throw new CaseError("duplicate_commitment", "commitments.b", "one commitment hash cannot be registered to both roles");
  }
  checkLimits(rec);
  checkSig(rec, true);
  checkSignedBy(rec, true);
  checkSignedUnder(rec.signed_under);
}

function checkFull(rec) {
  onlyFields(rec, [...TOP_LEVEL_FIELDS, ...OPTIONAL_TOP_LEVEL_FIELDS]);
  requireFields(rec, TOP_LEVEL_FIELDS);
  if (rec.v !== CASE_VERSION) throw new CaseError("unknown_version", "v", "v must be 1");
  checkHex64(rec.case_id, "case_id");
  if (rec.protocol_version !== PROTOCOL_VERSION) throw new CaseError("unsupported_protocol_version", "protocol_version", `protocol_version must be "${PROTOCOL_VERSION}"`);
  checkText(rec.policy_version, "policy_version");
  checkHex64(rec.scope_digest, "scope_digest");
  const pa = cleanParty(rec.party_a, "party_a");
  const pb = cleanParty(rec.party_b, "party_b");
  const order = compareParties(pa, pb);
  if (order === 0) throw new CaseError("parties_not_distinct", "party_b", "the two parties cannot be ordered");
  if (order > 0) throw new CaseError("parties_not_canonical", "party_a", "party_a must be the party that sorts first (label, then side)");
  for (const f of ["opened_at", "deadline"]) {
    if (!isUtcSeconds(rec[f])) throw new CaseError("malformed_field", f, `${f} must be UTC seconds (YYYY-MM-DDTHH:MM:SSZ)`);
  }
  if (Date.parse(rec.deadline) <= Date.parse(rec.opened_at)) {
    throw new CaseError("deadline_not_after_opened_at", "deadline", "deadline must be later than opened_at");
  }
  if (deriveCaseId(rec) !== rec.case_id) {
    throw new CaseError("case_id_mismatch", "case_id", "case_id is not the id this case's own opening fields derive");
  }

  const c = rec.commitments;
  if (!isPlainObject(c)) throw new CaseError("malformed_field", "commitments", "commitments must be an object {a, b}");
  onlyFields(c, ROLES, "commitments");
  requireFields(c, ROLES, "commitments");
  for (const r of ROLES) {
    if (c[r] === null) continue;
    checkCommitmentEntry(c[r], `commitments.${r}`, CASE_ENTRY_FIELDS);
    checkHex64(c[r].registration_sha256, `commitments.${r}.registration_sha256`);
    checkHex64(c[r].claim_sha256, `commitments.${r}.claim_sha256`);
    if (Date.parse(c[r].registered_at) >= Date.parse(rec.deadline)) {
      throw new CaseError("status_inconsistent", `commitments.${r}.registered_at`, "a registration must be received before the deadline");
    }
  }
  if (c.a !== null && c.b !== null && c.a.commitment_sha256 === c.b.commitment_sha256) {
    throw new CaseError("duplicate_commitment", "commitments.b", "one commitment hash cannot be registered to both roles");
  }

  if (rec.reveals !== null) {
    if (!isPlainObject(rec.reveals)) throw new CaseError("malformed_field", "reveals", "reveals must be null or an object {a, b}");
    onlyFields(rec.reveals, ROLES, "reveals");
    requireFields(rec.reveals, ROLES, "reveals");
    for (const r of ROLES) {
      const e = rec.reveals[r];
      const f = `reveals.${r}`;
      if (!isPlainObject(e)) throw new CaseError("malformed_field", f, `${f} must be an object`);
      onlyFields(e, REVEAL_ENTRY_FIELDS, f);
      requireFields(e, REVEAL_ENTRY_FIELDS, f);
      checkHex64(e.tape_sha256, `${f}.tape_sha256`);
      checkHex64(e.salt_sha256, `${f}.salt_sha256`);
      if (!isUtcSeconds(e.revealed_at)) throw new CaseError("malformed_field", `${f}.revealed_at`, `${f}.revealed_at must be UTC seconds`);
    }
  }
  // The receipt in full (lib/_reconcile_receipt.js). Item two writes it and
  // owns its deeper check; here it must at least be an object.
  if (rec.verdict !== null && !isPlainObject(rec.verdict)) {
    throw new CaseError("malformed_field", "verdict", "verdict must be null or the reconcile receipt object");
  }
  // unit R-SIG: a stored receipt carries its signature
  if (rec.verdict !== null) {
    if (typeof rec.verdict.sig !== "string" || rec.verdict.sig === "") {
      throw new CaseError("malformed_field", "verdict.sig", "a stored reconcile receipt carries its signature");
    }
    if (Object.prototype.hasOwnProperty.call(rec.verdict, "unsigned_reason")) {
      throw new CaseError("malformed_field", "verdict.unsigned_reason", "a stored reconcile receipt is signed and says no unsigned_reason");
    }
  }

  if (rec.cross_reference !== null) {
    const x = rec.cross_reference;
    if (!isPlainObject(x)) throw new CaseError("malformed_field", "cross_reference", "cross_reference must be null or an object");
    onlyFields(x, CROSS_REFERENCE_FIELDS, "cross_reference");
    requireFields(x, CROSS_REFERENCE_FIELDS, "cross_reference");
    checkText(x.operator, "cross_reference.operator");
    checkText(x.reference, "cross_reference.reference");
    if (typeof x.url !== "string" || !/^https:\/\/\S+$/.test(x.url)) {
      throw new CaseError("malformed_field", "cross_reference.url", "cross_reference.url must be an https URL");
    }
    if (!isUtcSeconds(x.recorded_at)) throw new CaseError("malformed_field", "cross_reference.recorded_at", "cross_reference.recorded_at must be UTC seconds");
  }
  if (rec.records !== (rec.cross_reference === null ? 1 : 2)) {
    throw new CaseError("status_inconsistent", "records", "records is 2 only with a cross_reference, and 1 without one");
  }

  if (!STATUSES.includes(rec.status)) throw new CaseError("malformed_field", "status", `status must be one of ${STATUSES.join(", ")}`);
  if (!STORED_STATUSES.includes(rec.status)) {
    throw new CaseError("malformed_field", "status", "EXPIRED is computed on read from the deadline; it is never stored");
  }
  if (rec.withdrawal !== null) {
    throw new CaseError("status_inconsistent", "withdrawal", "a withdrawn case is the redacted record, never a full case object");
  }
  const both = c.a !== null && c.b !== null;
  const bad = (why) => { throw new CaseError("status_inconsistent", "status", `${rec.status}: ${why}`); };
  if (rec.status === "OPEN") {
    if (both) bad("both roles are registered, so the status is COMMITTED");
    if (rec.reveals !== null || rec.verdict !== null) bad("an open case has no reveals and no verdict");
  } else if (rec.status === "COMMITTED") {
    if (!both) bad("both roles must be registered");
    if (rec.reveals !== null || rec.verdict !== null) bad("a committed case has no reveals and no verdict");
  } else if (rec.status === "VERDICT") {
    if (!both) bad("both roles must be registered");
    if (rec.reveals === null || rec.verdict === null) bad("a verdict needs both reveals and the receipt");
    // One joint reveal (item 2a): one request, so one time for both roles,
    // received before the deadline. The order of registration and reveal is
    // judged on the root the reveal read, COMMITTED, not on registered_at and
    // revealed_at: revealed_at is the arrival clock, and a registration that
    // arrives after it may be projected before the reveal reads the case
    // (unit R-RVf3, 4b, the architect's ruling).
    const at = rec.reveals.a.revealed_at;
    if (rec.reveals.b.revealed_at !== at) bad("both reveals arrive in one request, at one time");
    if (Date.parse(at) >= Date.parse(rec.deadline)) bad("the joint reveal must be received before the deadline");
  }

  checkLimits(rec);
  const sealed = rec.status === "VERDICT";
  checkSig(rec, sealed);
  checkSignedBy(rec, sealed);
  // SIGNED_UNDER, above: required on a sealed case, absent from any other
  if (sealed) {
    if (!Object.prototype.hasOwnProperty.call(rec, "signed_under")) {
      throw new CaseError("missing_field", "signed_under", "a sealed case records the key document it was signed under");
    }
    checkSignedUnder(rec.signed_under);
  } else if (Object.prototype.hasOwnProperty.call(rec, "signed_under")) {
    throw new CaseError("status_inconsistent", "signed_under", "only a signed record (a sealed case) names the key document it was signed under");
  }
}

// SIGNED_UNDER, above: exactly {document_sha256, document_commit}.
function checkSignedUnder(u) {
  if (!isPlainObject(u)) throw new CaseError("malformed_field", "signed_under", "signed_under must be {document_sha256, document_commit}");
  onlyFields(u, SIGNED_UNDER_FIELDS, "signed_under");
  requireFields(u, SIGNED_UNDER_FIELDS, "signed_under");
  checkHex64(u.document_sha256, "signed_under.document_sha256");
  if (typeof u.document_commit !== "string" || !/^[0-9a-f]{40}$/.test(u.document_commit)) {
    throw new CaseError("malformed_field", "signed_under.document_commit", "signed_under.document_commit must be a 40-hex git commit id");
  }
}

function validateCase(rec) {
  try {
    if (!isPlainObject(rec)) throw new CaseError("not_an_object", "$", "a case must be a JSON object");
    if (rec.status === "WITHDRAWN") checkWithdrawn(rec);
    else checkFull(rec);
    return { ok: true };
  } catch (e) {
    if (e instanceof CaseError) return { ok: false, code: e.code, field: e.field, error: e.message };
    throw e;
  }
}

// ---------------------------------------------------------------------------
// the withdrawal and the reference row (item 2c)
// ---------------------------------------------------------------------------
// {case_id, role, tape_sha256, salt}: the role and its commitment preimage
// (THE WITHDRAWAL, above). Shape only; lib/_case_http.js recomputes the
// commitment and matches the registration.
function validateWithdrawBody(body) {
  if (!isPlainObject(body)) throw new CaseError("not_an_object", "$", "the withdrawal must be a JSON object");
  for (const k of Object.keys(body)) {
    if (!WITHDRAW_BODY_FIELDS.includes(k) && !WITHDRAW_BODY_OPTIONAL.includes(k)) {
      throw new CaseError("unknown_field", k,
        `unknown field ${JSON.stringify(k).slice(0, 80)}: a withdrawal carries case_id, role, tape_sha256, salt and, optionally, reason only. ` +
          "The role proves itself with its commitment preimage, and every time in the record is this service's clock");
    }
  }
  requireFields(body, WITHDRAW_BODY_FIELDS);
  checkHex64(body.case_id, "case_id");
  if (!ROLES.includes(body.role)) throw new CaseError("bad_role", "role", 'role must be "a" or "b"');
  checkHex64(body.tape_sha256, "tape_sha256");
  checkHex64(body.salt, "salt");
  const hasReason = Object.prototype.hasOwnProperty.call(body, "reason");
  if (hasReason && !WITHDRAWAL_REASONS.includes(body.reason)) {
    throw new CaseError("malformed_field", "reason", `reason, when given, is one of ${WITHDRAWAL_REASONS.join(", ")}`);
  }
  // unit R-SIG: no default; a reason not given is absent
  return { case_id: body.case_id, role: body.role, tape_sha256: body.tape_sha256, salt: body.salt, ...(hasReason ? { reason: body.reason } : {}) };
}

// {case_id, role?, tape_sha256?, salt?, cross_reference: {operator,
// reference, url}} (THE REFERENCE ROW, above). The three proof fields come
// together or not at all: without them the request is the operator's, and
// lib/_case_http.js asks for the operator's bearer key.
// -> {case_id, proof: {role, tape_sha256, salt} or null, cross_reference}.
function validateReferenceBody(body) {
  if (!isPlainObject(body)) throw new CaseError("not_an_object", "$", "the reference must be a JSON object");
  for (const k of Object.keys(body)) {
    if (!REFERENCE_BODY_FIELDS.includes(k)) {
      throw new CaseError("unknown_field", k,
        `unknown field ${JSON.stringify(k).slice(0, 80)}: a reference carries case_id, cross_reference, and either a role's ` +
          "proof (role, tape_sha256, salt) or none (the operator's bearer key); every time in the row is this service's clock");
    }
  }
  requireFields(body, ["case_id", "cross_reference"]);
  checkHex64(body.case_id, "case_id");
  const given = REFERENCE_PROOF_FIELDS.filter((k) => Object.prototype.hasOwnProperty.call(body, k));
  let proof = null;
  if (given.length) {
    const missing = REFERENCE_PROOF_FIELDS.find((k) => !given.includes(k));
    if (missing) {
      throw new CaseError("missing_field", missing,
        `${missing} is required: a role proves itself with role, tape_sha256 and salt together`);
    }
    if (!ROLES.includes(body.role)) throw new CaseError("bad_role", "role", 'role must be "a" or "b"');
    proof = { role: body.role, tape_sha256: checkHex64(body.tape_sha256, "tape_sha256"), salt: checkHex64(body.salt, "salt") };
  }
  return { case_id: body.case_id, proof, cross_reference: crossReferenceInput(body.cross_reference, true) };
}

// A reference row's shape (record type case_reference). The signature is
// lib/_case_seal.js's; the case it belongs to, and the seal's time, are the
// reader's (lib/_case_seal.js judgeReferenceRow). Never throws.
function validateReferenceRow(rec) {
  try {
    if (!isPlainObject(rec)) throw new CaseError("not_an_object", "$", "a reference row must be an object");
    // THE ROW'S SENTENCE, above (the architect's ruling on unit R-SIG): a
    // row at version 3 keeps its own reading, and any other version but 4,
    // or none, is malformed. Since unit R-RVf3 (5c) a version-3 row's other
    // fields are read as a row's, its own sentence aside, and its reading
    // comes last, so that its signature can be verified (lib/_case_seal.js
    // judgeReferenceRow).
    const v3 = rec.note_version === 3;
    if (!v3 && rec.note_version !== REFERENCE_NOTE_VERSION) {
      throw new CaseError("malformed_field", "note_version", `note_version must be ${REFERENCE_NOTE_VERSION}`);
    }
    onlyFields(rec, REFERENCE_FIELDS);
    requireFields(rec, REFERENCE_FIELDS);
    if (rec.kind !== REFERENCE_KIND) throw new CaseError("malformed_field", "kind", `kind must be "${REFERENCE_KIND}"`);
    if (rec.v !== 1) throw new CaseError("unknown_version", "v", "v must be 1");
    checkHex64(rec.case_id, "case_id");
    if (!Number.isSafeInteger(rec.seq) || rec.seq < 1 || rec.seq > MAX_REFERENCE_SEQ) {
      throw new CaseError("malformed_field", "seq", `seq must be a whole number from 1 to ${MAX_REFERENCE_SEQ}`);
    }
    const x = rec.cross_reference;
    if (!isPlainObject(x)) throw new CaseError("malformed_field", "cross_reference", "cross_reference must be an object {operator, reference, url}");
    onlyFields(x, REFERENCE_ROW_CROSS_FIELDS, "cross_reference");
    requireFields(x, REFERENCE_ROW_CROSS_FIELDS, "cross_reference");
    checkText(x.operator, "cross_reference.operator");
    checkText(x.reference, "cross_reference.reference");
    checkUrlIn(x.url, "cross_reference.url");
    if (!isUtcSeconds(rec.recorded_at)) throw new CaseError("malformed_field", "recorded_at", "recorded_at must be UTC seconds");
    if (!APPENDED_BY.includes(rec.appended_by)) {
      throw new CaseError("malformed_field", "appended_by", `appended_by must be one of ${APPENDED_BY.join(", ")}`);
    }
    if (!v3 && rec.anchor_note !== REFERENCE_ANCHOR_NOTE) {
      throw new CaseError("malformed_field", "anchor_note", "anchor_note must be the row's fixed sentence");
    }
    checkSignedUnder(rec.signed_under);
    checkSig(rec, true);
    checkSignedBy(rec, true);
    if (v3) throw new CaseError("row_note_v3", "note_version", "note_version 3 of the anchor sentence was never issued, and is not accepted");
    return { ok: true };
  } catch (e) {
    if (e instanceof CaseError) return { ok: false, code: e.code, field: e.field, error: e.message };
    throw e;
  }
}

// ---------------------------------------------------------------------------
// where things live (the pins repository, design "The commitment format")
// ---------------------------------------------------------------------------
function casePath(caseId) {
  checkHex64(caseId, "case_id");
  return `cases/${caseId}.json`;
}

// THE CLAIM, above: role `role`'s registration file whose claim is `claim`.
function registrationPath(caseId, role, claim) {
  checkHex64(caseId, "case_id");
  if (!ROLES.includes(role)) throw new CaseError("bad_role", "role", 'role must be "a" or "b"');
  checkHex64(claim, "claim_sha256");
  return `registrations/${caseId}/${role}/${claim}.json`;
}

// The withdrawal's marker (item 2c): written create-only after the redacted
// record, so a tree listing shows a withdrawn case without a fetch.
function withdrawnMarkerPath(caseId) {
  checkHex64(caseId, "case_id");
  return `cases/${caseId}/withdrawn`;
}

// THE REFERENCE ROW (item 2c): cases/<case_id>/references/<8-digit seq>.json.

function referencesDir(caseId) {
  checkHex64(caseId, "case_id");
  return `cases/${caseId}/references`;
}
function referencePath(caseId, seq) {
  if (!Number.isSafeInteger(seq) || seq < 1 || seq > MAX_REFERENCE_SEQ) throw new TypeError("referencePath: seq must be 1 to 99999999");
  return `${referencesDir(caseId)}/${String(seq).padStart(8, "0")}.json`;
}

module.exports = {
  WITHDRAWAL_REASONS,
  SCHEMA,
  CASE_VERSION,
  PROTOCOL_VERSION,
  SUPPORTED_POLICY_VERSION,
  ROLES,
  SIDES,
  STATUSES,
  STORED_STATUSES,
  REGISTERABLE_STATUSES,
  TOP_LEVEL_FIELDS,
  OPTIONAL_TOP_LEVEL_FIELDS,
  SIGNED_UNDER_FIELDS,
  WITHDRAWN_FIELDS,
  OPENING_FIELDS,
  CASE_ID_FIELDS,
  REGISTRATION_KIND,
  REGISTRATION_FIELDS,
  REGISTRATION_BODY_FIELDS,
  REVEAL_BODY_FIELDS,
  REVEAL_INPUT_FIELDS,
  CROSS_REFERENCE_INPUT_FIELDS,
  REVEAL_TAPE_FIELDS,
  LIMITS,
  UNSEALED_SIG_REASON,
  CASE_ERROR_CODES,
  COMMITMENT_BYTES_LENGTH,
  KEY_ID,
  MAX_DEADLINE_DAYS,
  CaseError,
  compareCodePoints,
  normalizeUtcSeconds,
  utcSeconds,
  isUtcSeconds,
  isIsoUtc,
  canonicalParties,
  caseIdPreimage,
  caseIdBytes,
  deriveCaseId,
  validateOpening,
  newCase,
  commitmentPreimage,
  commitmentBytes,
  commitmentSha256,
  newSalt,
  saltSha256,
  validateRevealBody,
  revealCaseId,
  refusalOpening,
  validateRegistrationBody,
  REGISTRATION_SIG_KIND,
  registrationSigningBytes,
  registrationSignatureReason,
  signRegistration,
  singleParty,
  registrationRecord,
  validateRegistrationRecord,
  commitmentEntry,
  caseEntry,
  CASE_ENTRY_FIELDS,
  PARTY_SUPPLIED_FIELDS,
  claimSha256,
  partySuppliedDiffers,
  sameEntry,
  applyRegistration,
  pastDeadline,
  validateCase,
  casePath,
  registrationPath,
  // item 2c
  WITHDRAWAL_FIELDS,
  WITHDRAW_BODY_FIELDS,
  REFERENCE_BODY_FIELDS,
  REFERENCE_KIND,
  REFERENCE_FIELDS,
  APPENDED_BY,
  MAX_REFERENCE_SEQ,
  REFERENCE_ANCHOR_NOTE,
  REFERENCE_NOTE_VERSION,
  validateWithdrawBody,
  validateReferenceBody,
  validateReferenceRow,
  withdrawnMarkerPath,
  referencesDir,
  referencePath,
};
