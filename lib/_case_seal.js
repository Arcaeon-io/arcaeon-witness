// _case_seal.js — the seal of a case: the sealed case object, its signature,
// its chain, its pin, and the check of the reconcile receipt it carries;
// since item 2c also the two other records the case key signs (a
// withdrawal record and a reference row) and the published key document
// every signature is checked against.
// Underscore prefix = not routed as a serverless function.
//
// WHAT THIS IS (CASE_PROTOCOL_DESIGN_2026-10-10.md, velouria
// projects/arcaeon/, "The joint reveal and its refusals", step 5, and the
// decisions after the item-one build, 2, 7 and 11). lib/_case_http.js's
// ?op=case-reveal checks a joint reveal, runs the existing reconcile once,
// and hands this file the reconcile receipt. This file checks that receipt,
// builds the sealed case object (status VERDICT), signs it, writes nothing
// itself except the pin, and answers the one question the page will ask of
// a seal: is it pinned yet, and is it anchored (THE ANCHOR WORDS, below).
// The case file write is lib/_case_http.js's.
//
// THE SEALED OBJECT. The COMMITTED case, plus:
//   status: "VERDICT";
//   reveals: per role {tape_sha256, salt_sha256, revealed_at}. salt_sha256
//     is lib/_case.js saltSha256, the sha256 of the salt's 32 bytes; the
//     salt itself is never stored (design: "Never a tape, never a salt");
//     revealed_at is this service's clock when the request arrived, one time
//     for both roles because there is one request;
//   verdict: the reconcile receipt in full (lib/_reconcile_receipt.js),
//     exactly as ?op=reconcile would have signed it for these two tapes;
//   records: 1, or 2 when the reveal carried a cross_reference, which is
//     recorded as {operator, reference, url, recorded_at} with recorded_at
//     the same service clock (design decision 11);
//   sig / sig_reason (THE SIGNATURE, below).
// After this the object never changes (design decision 2: "The sealed object
// never changes after sealing"). There is no `anchor` field: whether the
// seal is anchored is read from the pin, at render time, never stored.
//
// THE SIGNATURE. The lib/_check_record.js rule: Ed25519 over the json-c14n:v1
// bytes of the whole case minus `sig` (that file's `preimage`), so every
// field, the four limits and the receipt included, is inside the signed
// bytes. The key is its own key (design decision 7): WITNESS_CASE_SIGNER_KEY,
// in the signer-string shape of lib/_checkpoint.js and the reconcile signer,
//   PRIVATE+KEY+<name>+<8 hex>+<base64(0x01 || seed)>,
// and it is never the witness log's key (WITNESS_LOG_SIGNER_KEY) or the
// reconcile receipt's key (WITNESS_RECONCILE_SIGNER_KEY). A receipt says
// "these two tapes compared like this"; a sealed case says "these
// commitments, these reveals and that receipt belong to this case". A reader
// who could not tell the two signatures apart could carry one claim's
// strength onto the other, so the keys stay apart.
//   SEPARATION FAILS CLOSED (item 2b; GPT-5.6's review of 2a: "If
// WITNESS_CASE_SIGNER_KEY is configured to the same private key as the
// reconcile signer but WITNESS_RECONCILE_SIGNER_KEY is missing in that
// function's environment, the guard cannot detect reuse and signs the
// case"). The case key is used only when it can be SHOWN different from
// both other keys: each of WITNESS_LOG_SIGNER_KEY and
// WITNESS_RECONCILE_SIGNER_KEY must be present in this environment and
// parse, and its public verifier string and its public key bytes must both
// differ from the case key's (the bytes too, because one key under two names
// has two verifier strings). A case key that IS one of them is refused by
// name (`case_key_is_other_key`). When either other key is absent or does
// not parse, the difference cannot be established and the seal goes out
// unsigned, `key_separation_unverifiable`, never signed. (The log key does
// live on the witness project's Vercel environment: docs/LOGTREE_KEY_RUNBOOK.md,
// "the signer key lives on Vercel, as an environment variable on the
// witness project".)
//   PUBLICATION FAILS CLOSED (item 2c; GPT-5.6's review of 2b: "A configured
// signer may sign cases although its public verifier is absent from the
// published key document"). After separation, the key must be an ACTIVE
// entry of the committed key document (PUBLISHED_KEYS below, loaded with
// require() when this module loads, so the function bundle carries it),
// holding exactly the key's verifier string. A key that is not listed, is
// listed retired or revoked, or is listed with another verifier, or a
// document that does not read, is not used: the seal goes out unsigned,
// `key_unpublished`. So a signature this service makes is always one the
// public document confirms. The document lists no key until item three
// mints one, so until then every seal is unsigned.
// Unset, unparseable or refused, signCase writes `sig: null` with
// `sig_reason` naming the reason (never the key), in the form
//   "This case is sealed and not signed (<code>): <why>."
// with <code> one of case_key_unset, case_key_unparseable,
// case_key_is_other_key, key_separation_unverifiable, key_unpublished. Since
// ONE SIGNATURE RULE (below) such a record is never a seal: the reveal does
// not write one, and a reader that finds one reads it case_signature_invalid
// (unsigned_seal).
//   SIGNED_BY (item 2b). The sealed case names its key in `signed_by`, the
// key id <name>+<8 hex> (lib/_checkpoint.js's key naming), set by signCase
// in the step that signs, so it is inside the signed bytes; null when
// unsigned. The verifier, <name>+<8 hex>+<base64(0x01 || pub)>, is
// published in a version-controlled public document served at
// /.well-known/arcaeon/case-signing-keys.json (CASE_KEYS_DOC below; the
// snapshot keys' pattern), committed at
// public/.well-known/arcaeon/case-signing-keys.json (CASE_KEYS_FILE; public/
// is vercel.json's outputDirectory, README "Deploy shape"), one entry
// {key_id, verifier, since, note, status} per key. A reader looks signed_by
// up there and checks the signature (THE SEALED CHECK, below, the one
// routine every reader runs; signatureReason also requires that the
// verifier it is handed is the key signed_by names). The reveal's answer
// still carries `sealed_by`.
//   ONE SIGNATURE RULE (2026-10-12; two items flagged on earlier reports).
// There is one check of a stored seal, THE SEALED CHECK. The function
// verifyCase checked a case under a verifier its caller chose and passed an
// unsigned receipt; it had no caller outside the tests and is deleted. A
// seal with sig null never reads valid: it is case_signature_invalid, reason
// unsigned_seal. So the reveal seals only signed: without a case key the
// document it carries lists (loadCaseSigner), it refuses 503
// case_signer_unavailable before anything is written or compared, the way
// it refuses without a reconcile signer (red-team fix B).
//   EVERYWHERE (unit R-N, N1): seals, reference rows, withdrawal records and
// refusal receipts are each signed or not written (not issued). A reference
// row and a withdrawal without a case key, and a refusal receipt without a
// reconcile key, are 503; an unsigned row a reader finds is `row_unsigned`,
// not a record; and a key verifies only in its own role
// (publishedSignatureReason). No signer's reason, which may name an
// environment variable, reaches a caller: the server log has it.
//
// SIGNED UNDER ONE DOCUMENT (Design I, 2026-10-12; GPT-5.6's red-team
// review, §1.4 and §3.3: the verdict on a sealed case changed when the key
// document changed, and no sealed case recorded which document it was
// signed under). The key document lists two kinds of key, by an entry's
// `role`: "case" (absent means case) and "reconcile", the key that signs the
// reconcile receipt (lib/_reconcile_receipt.js). A revoked entry carries
// `revoked_since`, an ISO date, beside status revoked, and no other entry
// carries one. A key signs only in its role: the case key must be an active
// case entry (loadCaseSigner) and the reconcile key an active reconcile
// entry (loadReconcileSigner), of the document the deployment carries. With
// no such reconcile entry, ?op=reconcile and the reveal refuse 503
// signer_unavailable and compare nothing (lib/_reconcile_http.js compare),
// which is the production state until the reconcile key is published.
//   The sealed case records the document in `signed_under`, inside the
// signed bytes (sealCase): {document_sha256, document_commit, retrieved_at}.
// document_sha256 is the sha256 of the json-c14n:v1 form of the document the
// sealer carried; document_commit is the sealing deployment's own git
// commit, VERCEL_GIT_COMMIT_SHA (DEPLOY_COMMIT_ENV): this repository is
// public, so the commit is a public fact. Since unit R-I the bundled
// document is not taken to be the document at that commit: the reveal reads
// it there and compares (THE TRUST ROOT, below). retrieved_at is the service
// clock, the reveal's time: unverified, since a dishonest service could
// backdate its own clock, and since unit R-I display only: no reader orders
// anything by it. One document commit binds both keys: the case key that
// signed the seal and the reconcile key that signed its receipt. A sealer
// that cannot read its document or its commit seals nothing: the reveal
// refuses 503 document_unavailable before anything is compared.
//
// THE TRUST ROOT (unit R-I, 2026-10-13; a second-model review of Design I:
// B1 "revocation is decided on service-written dates", B2 "the reveal never
// reads the document it names", M1 "a key absent from the CURRENT document
// reads valid_under_document", and any 40-hex commit the raw host serves was
// a document a case could name). The rules, as built:
//   THE BRANCH. A named document commit is on the published branch of this
// repository, KEY_DOCUMENT_BRANCH (main unless set; a preview names its
// own): commitOnBranch, one compare read, compare/<branch>...<commit>,
// identical or behind, kept for the instance once on. Anything else, or a
// read that fails, is document_unavailable: could-not-look, never valid.
// Since unit R-I2 (m4) a compare 404 reads "off the branch" only when the
// branch itself exists (one branch read, kept once it does): a branch that
// does not exist, or a repository the token cannot see, is unknown
// (branch_unreadable), and the page says a commit off the branch is not a
// read to retry.
// commitOnBranch takes another repository and branch by name, so Design J's
// commits (case_commit, anchor heads, row commits) can be held to the pins
// repository's branch the same way.
//   THE SEALER READS WHAT IT NAMES. Before it writes anything the reveal
// reads the document at its own commit from the raw host, as a reader does,
// and compares it to the bundled copy (confirmSealingDocument): a commit not
// on the branch, a document there that cannot be read, or one that is not
// the bundle is 503 document_unavailable, nothing compared and no attempt
// written. A fetched document is kept for the instance only once its sha256
// matches the one it is held to (fetchNamedDocument).
//   THE CURRENT DOCUMENT LISTS BOTH KEYS. A key that signed a seal must be
// listed in the reader's current document, in its role, with the same
// verifier; else signer_unlisted, which does not hold. A document the
// sealer named never makes a stranger's key valid.
//   REVOCATION BY COMMIT ORDER. retrieved_at, since and revoked_since are
// never compared: a key is active in the named document by its status. A
// key the current document lists as revoked is ordered against the case by
// commits of ONE repository, the pins repository, since a pin is a commit
// there and git orders commits only within a repository: P is the
// case_commit of the case's pin (Design J), read pinned; R is a commit of the
// key's REVOCATION MARKER, revocations/<fingerprint>.json, which
// tools/record_key_revocation.js writes create-only after the document's
// revocation is on the branch, naming the key id, the key's fingerprint
// (sha256 of the public key) and the commit of this repository at which the
// document first lists it revoked. Since unit R-I2 (B1, M1) R is the OLDEST
// commit on the marker's path at which the file reads as a valid marker for
// the key (the reader's whole check, checkRevocationMarker, which the tool
// also runs before it writes): every page of the path's commits is walked
// (allCommitsOf, bounded; past the bound, unreadable), content that is not
// a valid marker is skipped, and an earlier valid marker always wins, so no
// later write moves R. P strictly before R (compare/<R>...<P> behind) is
// signer_since_revoked: sealed, under a banner that says exactly that (the
// case file was written at P, before the revocation was recorded at R; the
// document lists the key revoked from W), and nothing about when W was
// committed or deployed. Anything else (P at or after R, no pin, no marker,
// no valid one, a read that cannot be made) is signer_revoked: not holding,
// no verdict, no pin, a reference refused; the reason says which (a pin
// that is not pinned: case_not_pinned, pin_commit_mismatch or
// pin_unreadable:<reason>). A pin that could not be read is neither:
// pin_unavailable, could-not-look (unit R-J3, F4). A key whose marker's R
// comes before the case's P never holds. A marker counts only beside the
// current document's revocation: one without it is ignored, and the
// sealer's run reports it as marker_without_revocation.
//   ONE KEY, ONE ENTRY. The document lists a public key once, across roles
// (checkKeyDocument: duplicate_public_key), and the case signer is held
// apart from the document's reconcile keys as well as the environment's
// (loadCaseSigner: case_key_is_other_key).
//
// THE CHAIN AND THE PIN (design: "pins {namespace: "case/<case_id>", rows:
// 3, chain: sha256(json-c14n(case minus sig))}. The case file is
// authoritative; the pin is its anchor."). The chain is the sha256 of the
// SAME bytes the signature covers, so a pinned chain fixes the signed bytes.
// The pin goes through the store, not through POST /api/pin (no bearer key,
// no meter, no credit: it is this service's own record of its own seal), on
// the two paths api/pin.js writes a pin to and in the same order:
//   pins/case/<case_id>/00000001.json   the numbered record, create-only,
//   pins/case/<case_id>/latest.json     then the pointer,
// each read back through lib/_verdict.js judgeCaseSeal. One pin per case,
// ever, so seq is 1. rows is 3: the case's three records, its two
// registration files and the sealed case file.
//   THE case_seal RECORD TYPE (item 2b). The record is exactly {namespace,
// rows, chain, pinned_at, seq, record_kind: "case_seal", auth_level:
// "case-seal", auth_note}, judged by its own judge (lib/_verdict.js
// judgeCaseSeal: an unknown field, a missing field or a wrong value is
// refused by name). It carries none of api/pin.js's cadence fields, because
// a seal promises no next pin. The generic judgePin refuses a case seal by
// name, so no generic reader can take one for a namespace's head.
//   "case/<case_id>" is not a namespace api/pin.js accepts (lib/_store.js
// validatePin: [a-z0-9-]{1,64}, and the bare namespace "case" is reserved
// there too, so pins/case/ holds case seals and nothing else), so no bearer
// key can ever write a pin into a case's namespace, before or after the
// seal. THE READERS (item 2b) know it: the status page skips pins/case in
// its namespace listing and shows case anchors as their own row
// (caseAnchorSummary below, counted from the repository tree ALONE since
// item 2c: no case file and no pin is fetched per render, and a truncated
// tree makes the row `partial`), and lib/_logtree.js is unchanged, because
// its v1 leaf table reads pins/<ns>/<seq>.json one level deep and widening
// it would move every position. So, in words, ANCHOR_NOTE below: a case is
// pinned by the pins-repository commit that writes its pin, and anchored
// only when a daily anchor record in this repository names a head that
// holds that pin (THE ANCHOR WORDS, below; the OpenTimestamps proof is not
// checked: unit R-J, J2), not as a log-tree leaf. The reveal's answer carries
// that sentence as `anchor_note`, and so does the case page
// (lib/_case_page.js).
//
// THE ANCHOR WORDS (Design J, 2026-10-12; GPT-5.6's red-team review, §3.4
// and §5: "pinChain(), anchorState(), and the page only establish that
// latest.json exists and has the matching chain. They do not establish
// inclusion in any daily anchor"). What a reader says of a sealed case's pin
// is one of three words, each said only after the reads it names
// (anchorState):
//   pinned          the pointer pins/case/<case_id>/latest.json holds this
//                   case's chain, and so does the numbered record read AT
//                   the commit that wrote it (the oldest commit touching it:
//                   it is create-only), which is named beside the word with
//                   its commit time;
//   anchored        pinned, and a daily anchor record holds the pin: the
//                   record anchors/<YYYY-MM-DD>-head.txt names a head commit
//                   of the pins repository (README "Anchoring": written by
//                   the operator's daily job, outside this repository), and
//                   the numbered record read at that head holds this chain.
//                   The record's own commit, the one that wrote the text
//                   read, is read and named beside the word, and the record
//                   read at that commit names the same head: anchored is
//                   never said without it;
//   could_not_look  a read the answer needs failed: no claim.
// A case that is pinned and whose anchor could not be looked up stays
// pinned (that much was read) and says the anchor could not be looked up
// (`anchor: {could_not_look: reason}`); it never reads as anchored. The other
// answers are not anchor words: commit_unrecorded (no pin yet, or a pin
// that names no case commit: THE PIN IS THE SECOND PHASE, below),
// pin_commit_mismatch, conflict (a pin under
// the case holds another chain: at the pointer, at the commit that wrote it,
// or in a head a daily record names) and unreadable. The writers (pinChain,
// the reveal's answer, the sealer's report, the status row) say pinned:
// they read or write the pin and nothing beyond it.
//   A file at a commit is read from the public pins repository on the raw
// host (raw.githubusercontent.com/<repo>/<commit>/<path>, no credentials),
// the way THE SEALED CHECK reads the key document at its commit. A file at a
// commit never changes, so an answered read is kept for the life of the
// instance (commitFiles); a failed one is not. Records are looked up from
// the day before the pin's commit on, oldest first, at most
// ANCHOR_RECORD_READS of them: the first whose head holds the pin anchors
// it. The OpenTimestamps proof beside a record is not checked here.
//
// TWO WRITES, AND WHICH ONE IS AUTHORITATIVE. The case file first, then the
// pin. A case file write that fails leaves no pin (the pin is never
// attempted) and the case COMMITTED. A pin that fails after the case file
// landed leaves the case standing, sealed: the reveal answers with
// `pin: "commit_unrecorded"`, and anchorState computes the same answer from
// the pin's absence. anchorCase(case_id) is the retry: it reads the stored
// case file, recomputes the chain from it, and pins that, so a retry cannot
// change the chain. A numbered record left by an earlier attempt whose
// pointer write failed is adopted when it holds this chain (api/pin.js's
// healIfWedged adopts a verified orphan the same way). A pin under the
// case's namespace with any other chain is never written over:
// `pin: "conflict"`.
//   THE PIN IS THE SECOND PHASE (Design J, 2026-10-12; GPT-5.6's red-team
// review, §3.2: "The public case does not bind them [the service-clock
// fields] to a Git commit ID"). The pin records `case_commit`, the commit
// the pins repository assigned to the write of the sealed case file: the
// reveal takes it from that write's own answer (lib/_store.js putFile
// returns GitHub's {commit: {sha}}), and with none it writes no pin. The
// case file cannot name the commit that writes it, so the pin, written after
// it and already read by the page, does. A write whose second phase has not
// completed (no pin, or a pin from before Design J that names no commit)
// reads `commit_unrecorded`, a could-not-look class answer like THE SEALED
// CHECK's document_unrecorded: never pinned, never anchored. The sealer's
// next run is the retry (caseCommitOf): it reads the commit back (the newest
// commit touching the case file), reads the case file AT that commit from
// the public pins repository, and pins only when that file's chain is the
// chain it pins; otherwise `pin_commit_mismatch` and nothing is written (a
// file swapped meanwhile). Nothing is backfilled: the case file is never
// written again, and the run's report names each commit it recorded
// (`commits_recorded`).
//   THE VERIFIER NEVER TRUSTS case_commit AS AN ID. Every reader (anchorState;
// anchorCase, for a pin it finds) reads the case file at the commit the pin
// names and requires its chain to be the pin's chain. A pin naming a commit
// whose case file is another case is `pin_commit_mismatch`: never pinned,
// never anchored, whatever a daily anchor record says. A commit it could not
// read the file at is could_not_look.
//   THE ROW'S TWO WRITES (Design J; GPT-5.6 §5: "No reference row stores its
// write commit"). A reference row is written first; its own answer then
// names `row_commit`, the commit its write answered with (lib/_case_http.js).
// The second phase is the case's NEXT PIN: on each run the sealer lists, for
// a pinned case, the rows no pin of the case lists yet (at most
// REFERENCE_ROW_READS a run), reads each row's commit back (the newest
// touching it) and the row AT that commit, and writes pins/case/<case_id>/
// <seq + 1>.json, a case_seal record with the case's chain, its case_commit
// and `reference_commits: [{seq, commit}]` for those rows, then moves the
// pointer to it (create-only record, pointer moved only from the record it
// was read at). A row whose read-back finds another row there is not listed
// (`rows_unrecorded`, pin_commit_mismatch); one that cannot be read waits for
// the next run. So a row read without its pin still has its commit in its
// answer, and a row read with its pin has it in two places. A pin from
// before that names no case commit gets one the same way: the next pin
// records it, read back and checked (caseCommitOf). The seal's own pin stays
// seq 1: pinned and anchored are said of it; a next pin carries the same
// chain, so the pointer always holds the case's chain.
//   Every reader of a row's commit (referenceCommitStates, for the page) walks
// the case's pins down from the pointer and reads the row AT the commit a pin
// lists for it: the same row is `recorded`, another row there is
// `pin_commit_mismatch`, a row no pin lists is `commit_unrecorded`, and a read
// that fails is could_not_look. Since unit R-J3 a row whose commit was not
// read is `not_read`: the case not shown pinned, or a walk that stopped on a
// record it read.
//   Before it pins, anchorCase holds the stored case to the full sealed-
// receipt check (item 2b; GPT-5.6: "anchorCase anchors structurally valid but
// receipt-unbound verdicts"): checkSealedReceipt, the receipt's binding to
// the case's reveals, compared_at and policy, and its signature (since
// red-team fix B, A RECEIPT IS THE SERVICE'S, below: by the service's
// reconcile signer). A schema-valid VERDICT that fails is refused
// `verdict_unbound` (or `receipt_unsigned`) and nothing is written.
//   Then the stored case's OWN signature (item 2c, fix 1; GPT-5.6's review of
// 2b: "A pending signed case whose sig is replaced with garbage still has a
// bound receipt and can be anchored"): a signed case must verify under the
// verifier its signed_by names in the key document, and that entry must be
// listed and not revoked (publishedSignatureReason). A case whose sig does
// not verify is refused `case_signature_invalid` and nothing is written. An
// unsigned seal is refused the same way, reason unsigned_seal (ONE SIGNATURE
// RULE, above).
//   Since item 2d those two checks are one routine, sealedRecordReason (THE
// SEALED CHECK, below), and every reader of a stored VERDICT runs it before
// treating it as sealed: anchorCase before it pins, ?op=case-reference
// before it appends a row (a typed 409 by the same two codes), and the case
// page before it shows a verdict (a does-not-verify state instead).
//   TERMINAL STATES (item 2c, fix 6). A root read as WITHDRAWN, or as OPEN
// or COMMITTED at or past its deadline (EXPIRED, computed, never stored),
// will never be sealed: anchorCase answers `terminal` with that status and
// reads and writes nothing more.
//   SINGLE PARTY (red-team fix A; lib/_case.js ONE KEY PER ROLE). A case
// whose two commitments share a key id never reaches sealed: sealCase
// refuses to build one, THE SEALED CHECK refuses a stored VERDICT that is one
// (`single_party`, its first check), and anchorCase answers `not_sealed` with
// reason `single_party` for one read as COMMITTED or VERDICT, after the
// terminal states and before any other check, with nothing written. anchorPending counts it in
// `not_sealed` and lists it in `single_party`.
//   THE TRIGGER (item 2b; design "After item 2a": "anchorCase runs from the
// sealer's authenticated run, never from a public read"). lib/_sealer.js
// sealOnce, the operator's own command (tools/seal_batch.js, which needs
// the pins token to run at all), calls anchorPending on every run: one tree
// read lists the case files with no withdrawn marker (since unit R-L4 no
// registration file decides it: a registration stands only by the case
// root's projection, which anchorCase reads), PINNED ONES INCLUDED (item
// 2c, fix 5: a squatter or an unreadable pin under a pinned case is judged
// with the case_seal judge and reported as `conflict` or `unreadable`, never
// skipped forever), and anchorCase runs for each, at most SEALER_CASE_READS
// per run, the window's start derived from the run's full timestamp so
// that no fixed run period leaves one waiting forever behind the rest (THE
// WINDOW'S START, unit R-N3). A case with the marker cases/<case_id>/withdrawn
// is not considered at all, by the tree alone (fix 6). Idempotent: a pinned
// case is only read and judged, and a retry never changes the chain. No
// public ?op writes a pin.
//
// THE WITHDRAWAL RECORD AND THE REFERENCE ROW (item 2c). The case key signs
// two more records with the same rule and the same routine (signRecord): the
// redacted record a withdrawal publishes (withdrawnRecord; lib/_case.js THE
// WITHDRAWAL), and a reference row appended to a sealed case (referenceRow;
// lib/_case.js THE REFERENCE ROW). Each carries signed_by and sig, or
// sig: null with its sig_reason, exactly like a sealed case, and PUBLICATION
// FAILS CLOSED holds for both. A reference row has its own judge
// (judgeReferenceRow) and no pin of its own; THE LIVE RECORD COUNT
// (liveRecords) is 2 when the sealed case carries its cross_reference or a
// valid row exists, 1 only when every listed row was read and none is
// valid, and not established when a read that found no valid row was cut
// short (item 2d); the sealed case's own `records` never changes.
//
// THE RECEIPT CHECK (design decision 11: "the reveal validates the reconcile
// receipt's structure and signature and takes reveal and addendum times
// from the service clock"). Before anything is sealed, checkReceipt holds
// the receipt to: exactly the receipt's fields; its kind, version, claim
// and five non-claims verbatim; this build's method block, whose port
// version is the case's policy_version; each received-tape digest equal to
// the tape_sha256 committed for its role (tape_a is role a's), and its byte
// count the submitted tape's; the verdict block and verdict_digest equal to
// the comparison's own result; compared_at equal to the reveal's service
// time; and a signature that verifies under WITNESS_RECONCILE_SIGNER_KEY
// (lib/_reconcile_receipt.js verifyReceiptText). With no signer, or an
// unsigned receipt, it is `receipt_unsigned` (red-team fix B: the reveal
// never gets that far, since the comparison itself refuses to run without a
// signer). A receipt that fails is this service's defect, not the caller's:
// nothing is sealed.
//
// A RECEIPT IS THE SERVICE'S (red-team fix B; GPT-5.6's red-team review,
// §3.1: "Fabricate a case verdict without actually running reconcile ... If
// the reconcile receipt is unsigned, checkStoredReceipt() accepts it"). A
// stored receipt holds only with a signature by the service's reconcile
// signer over its canonical bytes (lib/_reconcile_receipt.js preimage). Before
// this, a receipt was checked under the verifier it carried itself, so a
// receipt signed by any key, or by none, passed. Since Design I the
// service's verifier is the reconcile entry of the key document the case
// NAMES (THE SEALED CHECK, below), never the reader's environment
// (WITNESS_RECONCILE_VERIFIER is only the private-side pointer the
// operator's tools read to know which published entry is the service's).
// Unsigned, signed by a key the named document does not list as a
// reconcile key, or by one not active at retrieved_at, it is
// `receipt_unsigned` (reason `unsigned`, `unknown_signer` or
// `signer_not_active`). A receipt by that key whose signature does not
// verify was altered after signing: `verdict_unbound`, its
// verifyReceiptText reason, as before. checkStoredReceipt holds a receipt
// to a verifier its caller GIVES, and with none refuses every signed one.
// The page shows such a case as not verifying; the sealer refuses it
// (`refused`, code receipt_unsigned) and pins nothing; ?op=case-reference
// refuses it 409.
//
// JSON. The receipt holds the verdict's call index as a BigInt (the port
// keeps Python's arbitrary-precision ints). A case file is JSON, and JSON
// read by this service is read as doubles, so storableReceipt turns each
// BigInt into a Number only when that is exact (at most 2^53 - 1), and
// proves the stored form signs the same bytes. A verdict at a call index
// past that cannot be sealed without changing the receipt's signed bytes;
// it is refused, and the tapes, already committed, stay unsealed.
//
// NOTHING ELSE IS KEPT. No tape and no salt reaches anything this file
// writes or logs; a withdrawal record keeps the salt only as salt_sha256.

"use strict";

const crypto = require("node:crypto");
const C = require("./_case.js");
const store = require("./_store.js");
const verdict = require("./_verdict.js");
const checkpoint = require("./_checkpoint.js");
const checkRecord = require("./_check_record.js");
const receipts = require("./_reconcile_receipt.js");
const T = require("./_reconcile_tapes.js");

const CASE_SIGNER_ENV = "WITNESS_CASE_SIGNER_KEY";
// The two keys a case is never signed with (THE SIGNATURE, above).
const OTHER_KEYS = Object.freeze([
  ["WITNESS_LOG_SIGNER_KEY", "the witness log's key"],
  [receipts.SIGNER_ENV, "the reconcile receipt key"],
]);

const PIN_ROWS = verdict.CASE_SEAL.rows;
const PIN_SEQ = verdict.CASE_SEAL.seq;
const PIN_RECORD_KIND = verdict.CASE_SEAL.record_kind;
const PIN_AUTH_LEVEL = verdict.CASE_SEAL.auth_level;
const RAW_DIGEST_PREFIX = "sha256:raw-bytes:v1:";

// THE READERS, above: the sentence the reveal's answer and the case page carry.
// Since unit R-J (J2) it says what "anchored" checks, and that the
// OpenTimestamps proof is not checked.
const ANCHOR_NOTE =
  "A case is pinned by the pins-repository commit that writes its pin, and anchored only when a daily anchor record in this " +
  "repository names a head that holds that pin; this service does not check the OpenTimestamps proof. The record's own commit is " +
  "named beside the word. It is pinned and anchored as its own record, not as a log-tree leaf: the witness log's v1 leaves are " +
  "pins/<namespace>/<seq>.json one level deep, and a case pin sits at pins/case/<case_id>/.";

// THE ANCHOR WORDS, above: where the daily anchor records are, their names
// and text (README "Anchoring": `<sha> <iso-timestamp>`), and how many one
// answer reads.
const ANCHORS_DIR = "anchors";
const ANCHOR_RECORD_RE = /^(\d{4}-\d{2}-\d{2})-head\.txt$/;
const ANCHOR_TEXT_RE = /^([0-9a-f]{40})[ \t]+(\S+)\s*$/;
const ANCHOR_RECORD_READS = 3;

// SIGNED_BY, above: the published key document. CASE_KEYS_DOC is where the
// domain serves it, relative to the domain's root (the way the snapshot
// signing keys are served at arcaeon.io), and the name every message and the
// case page use for it. CASE_KEYS_FILE is where it is committed, relative to
// the repository: public/ is vercel.json's outputDirectory, so the domain
// serves public/<path> at /<path> and nothing outside public/ statically
// (README "Deploy shape"). The functions that load this module carry the
// same file through vercel.json's includeFiles.
const CASE_KEYS_DOC = ".well-known/arcaeon/case-signing-keys.json";
const CASE_KEYS_FILE = `public/${CASE_KEYS_DOC}`;
const CASE_KEYS_SCHEMA = "arcaeon-signing-keys/1";
const CASE_KEYS_TOP_FIELDS = Object.freeze(["schema", "issuer", "description", "matching", "status_meaning", "rotation", "updated", "keys"]);
const CASE_KEY_ENTRY_FIELDS = Object.freeze(["key_id", "verifier", "since", "note", "status"]);
// SIGNED UNDER ONE DOCUMENT, above: an entry's optional fields.
const CASE_KEY_ENTRY_OPTIONAL = Object.freeze(["role", "revoked_since"]);
const CASE_KEY_STATUSES = Object.freeze(["active", "retired", "revoked"]);
const KEY_ROLES = Object.freeze(["case", "reconcile"]);
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
// SIGNED UNDER ONE DOCUMENT, above: the public repository the document is
// committed in, and the variable naming the commit a deployment was built
// from (Vercel sets it on every deployment of a git commit).
const KEY_DOCUMENT_REPO = "dan8433-user/arcaeon-witness";
const DEPLOY_COMMIT_ENV = "VERCEL_GIT_COMMIT_SHA";
const GIT_COMMIT = /^[0-9a-f]{40}$/;
// THE TRUST ROOT (unit R-I, above): the branch of KEY_DOCUMENT_REPO a named
// document commit must be on, KEY_DOCUMENT_BRANCH, main unless set (a
// preview deployment names its own branch). A name is letters, digits and
// . _ / -, with no "..".
const KEY_DOCUMENT_BRANCH_ENV = "KEY_DOCUMENT_BRANCH";
const DEFAULT_KEY_DOCUMENT_BRANCH = "main";
const BRANCH_NAME = /^(?!.*\.\.)[A-Za-z0-9._/-]{1,100}$/;
function keyDocumentBranch(env = process.env) {
  const b = env && env[KEY_DOCUMENT_BRANCH_ENV];
  return typeof b === "string" && b.trim() ? b.trim() : DEFAULT_KEY_DOCUMENT_BRANCH;
}

// THE PUBLISHED KEYS (item 2c, fix 2). The committed key document, loaded
// with require() when this module loads, so the function bundle carries it
// (a file read by path at request time depends on the bundler tracing it; a
// required module is always in the bundle), and named again in vercel.json's
// includeFiles for every function that loads this module, so the bundle
// holds the same bytes the domain serves. A frozen copy: nothing here can
// change the trust anchor at runtime. If the file does not load, this is
// null, checkKeyDocument refuses null, and every seal goes out unsigned
// (key_unpublished): fail closed, never a crash of verify.js.
function deepFreeze(v) {
  if (v && typeof v === "object") {
    for (const k of Object.keys(v)) deepFreeze(v[k]);
    Object.freeze(v);
  }
  return v;
}
const PUBLISHED_KEYS = (() => {
  try {
    return deepFreeze(JSON.parse(JSON.stringify(require("../public/.well-known/arcaeon/case-signing-keys.json"))));
  } catch (e) {
    console.error(`[case] the committed case key document did not load (${e && e.message}); every seal is unsigned`);
    return null;
  }
})();

// THE TRIGGER, above: case files read per sealer run, at most.
const SEALER_CASE_READS = 25;

const CASE_FILE_RE = /^cases\/([0-9a-f]{64})\.json$/;
const CASE_PIN_LATEST_RE = /^pins\/case\/([0-9a-f]{64})\/latest\.json$/;
// The withdrawal's marker (item 2c): lib/_case.js withdrawnMarkerPath.
const CASE_WITHDRAWN_RE = /^cases\/([0-9a-f]{64})\/withdrawn$/;
const C14N_DIGEST = /^sha256:json-c14n:v1:[0-9a-f]{64}$/;

const RECEIPT_REQUIRED = Object.freeze([
  "kind", "v", "claim", "tapes", "method", "verdict", "verdict_digest", "compared_at", "does_not_claim", "signer", "sig",
]);
const RECEIPT_OPTIONAL = Object.freeze(["verdict_digest_note", "unsigned_reason"]);
const RECEIPT_VERDICT_FIELDS = Object.freeze(["verdict", "at", "side", "matched", "counts", "findings", "could_not_look", "exit_code"]);
const VERDICT_WORDS = Object.freeze([T.MATCHED, T.MISSING, T.ALTERED, T.COULD_NOT_LOOK]);

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function has(o, k) {
  return Object.prototype.hasOwnProperty.call(o, k);
}

function sha256hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// json-c14n:v1 equality (BigInt and Number of one value are the same bytes).
function sameC14n(x, y) {
  const a = T.c14nBytes(x);
  const b = T.c14nBytes(y);
  return a !== null && b !== null && a.equals(b);
}

// ---------------------------------------------------------------------------
// the key
// ---------------------------------------------------------------------------
// A parsed key's public verifier string and key id (lib/_checkpoint.js).
function verifierOf(k) {
  return `${k.name}+${k.hash}+${Buffer.concat([Buffer.from([0x01]), k.pub]).toString("base64")}`;
}
function keyIdOf(k) {
  return `${k.name}+${k.hash}`;
}

// Reads WITNESS_CASE_SIGNER_KEY and the two keys it must be shown different
// from (SEPARATION FAILS CLOSED, above), then requires the key to be an
// active entry of the key document (PUBLICATION FAILS CLOSED, above).
// `keyDocument` is the committed document (PUBLISHED_KEYS) unless a test
// hands it another; the verify.js dispatch never does. Never logs or
// returns a private key:
// -> {ok:true, name, keyId, verifier, privateKey, entry} or
//    {ok:false, code, reason[, keyId, verifier]} (the public half only,
//    when the key parsed, so the entry for it can be printed).
function loadCaseSigner(env = process.env, { keyDocument = PUBLISHED_KEYS } = {}) {
  const no = (code, reason) => ({ ok: false, code, reason });
  const raw = env[CASE_SIGNER_ENV];
  if (!raw) return no("case_key_unset", `no case signing key is configured (${CASE_SIGNER_ENV} is not set)`);
  const mine = String(raw).trim();
  const k = checkpoint.parseSignerKey(mine);
  if (!k.ok) return no("case_key_unparseable", `the configured case signing key does not parse (${k.reason})`);
  const verifier = verifierOf(k);
  const unshown = [];
  for (const [name, what] of OTHER_KEYS) {
    const other = env[name];
    if (!other) {
      unshown.push(`${what} (${name} is not set in this environment)`);
      continue;
    }
    const theirs = String(other).trim();
    const o = checkpoint.parseSignerKey(theirs);
    if (theirs === mine || (o.ok && (o.pub.equals(k.pub) || verifierOf(o) === verifier))) {
      return no("case_key_is_other_key", `the configured case signing key is ${what} (${name}), and a case is never signed with it`);
    }
    if (!o.ok) unshown.push(`${what} (${name} does not parse)`);
  }
  if (unshown.length) {
    return no("key_separation_unverifiable",
      `the case signing key cannot be shown different from ${unshown.join(" or ")}, so it is not used`);
  }
  // ... and from every reconcile key the document lists (unit R-I, I4): the
  // document is read as given, before its shape is checked, so a document
  // that lists the case key's bytes as a reconcile key says so by name.
  const listed = keyDocument && Array.isArray(keyDocument.keys) ? keyDocument.keys : [];
  for (const e of listed) {
    if (!isPlainObject(e) || roleOf(e) !== "reconcile" || typeof e.verifier !== "string") continue;
    const o = checkpoint.parseVerifierKey(e.verifier);
    if (o.ok && o.pub.equals(k.pub)) {
      return no("case_key_is_other_key", "the configured case signing key is a reconcile key the key document lists, and a case is never signed with it");
    }
  }
  const keyId = keyIdOf(k);
  const pub = activeEntry(keyDocument, keyId, verifier, "case");
  if (!pub.ok) return { ok: false, code: "key_unpublished", reason: pub.reason, keyId, verifier };
  return { ok: true, name: k.name, keyId, verifier, privateKey: k.privateKey, entry: pub.entry };
}

// The reconcile signer (lib/_reconcile_receipt.js loadSigner), used only when
// it is an active RECONCILE entry of the key document the deployment carries
// (SIGNED UNDER ONE DOCUMENT, above). Never logs or returns a private key
// except as the KeyObject signReceipt needs:
// -> {ok:true, name, keyId, verifier, privateKey, entry} or {ok:false, code,
//    reason}: code reconcile_key_unset, reconcile_key_unparseable or
//    reconcile_key_unpublished (a response body carries the code only).
function loadReconcileSigner(env = process.env, { keyDocument = PUBLISHED_KEYS } = {}) {
  const s = receipts.loadSigner(env);
  // unit R-N2 (B2): a CODE for a response body; the reason, which names the
  // variable, is for the server log only
  if (!s.ok) return { ...s, code: env[receipts.SIGNER_ENV] ? "reconcile_key_unparseable" : "reconcile_key_unset" };
  const keyId = s.verifier.split("+").slice(0, 2).join("+");
  const pub = activeEntry(keyDocument, keyId, s.verifier, "reconcile");
  if (!pub.ok) return { ok: false, code: "reconcile_key_unpublished", reason: pub.reason };
  return { ...s, keyId, entry: pub.entry };
}

// An entry's role (SIGNED UNDER ONE DOCUMENT, above): absent is "case".
function roleOf(e) {
  return e.role === undefined ? "case" : e.role;
}

// The document the sealer carries, and the commit it was built from
// (SIGNED UNDER ONE DOCUMENT, above): the bundled document (`keyDocument`,
// PUBLISHED_KEYS unless a test hands another) and env's
// VERCEL_GIT_COMMIT_SHA. -> {ok:true, doc, document_sha256, document_commit}
// or {ok:false, code, reason} (code: carried_document_unreadable,
// deploy_commit_unknown, deploy_commit_malformed; a response body carries
// the code only, unit R-N2 B2).
function sealingDocument(env = process.env, { keyDocument = PUBLISHED_KEYS } = {}) {
  const c = checkKeyDocument(keyDocument);
  if (!c.ok) return { ok: false, code: "carried_document_unreadable", reason: `the key document this deployment carries does not read (${c.reason} at ${c.at})` };
  const commit = env[DEPLOY_COMMIT_ENV];
  if (typeof commit !== "string" || !GIT_COMMIT.test(commit)) {
    return { ok: false, code: commit ? "deploy_commit_malformed" : "deploy_commit_unknown",
      reason: `the commit this deployment was built from is not known (${DEPLOY_COMMIT_ENV} is ${commit ? "not a 40-hex commit id" : "not set"})` };
  }
  return { ok: true, doc: keyDocument, document_sha256: sha256hex(checkRecord.canonicalBytes(keyDocument)), document_commit: commit };
}

// THE SEALER READS WHAT IT NAMES (unit R-I, I2): the commit sealingDocument
// names is on the published branch (KEY_DOCUMENT_BRANCH of `env`), and the
// document at that commit, read from the public repository as a reader reads
// it, is the bundled one, byte for byte in json-c14n:v1. Otherwise every
// case it sealed would name a document no reader can hold it to. One read
// per reveal, kept for the instance only once it matches.
// -> {ok:true} or {ok:false, reason}: commit_not_on_branch, a branch read's
//    reason, document_at_commit_<fetch reason>, bundled_document_differs.
async function confirmSealingDocument(sealing, env = process.env) {
  const on = await commitOnBranch(sealing.document_commit, { branch: keyDocumentBranch(env) });
  if (on.unknown) return { ok: false, reason: on.unknown };
  if (!on.on) return { ok: false, reason: "commit_not_on_branch" };
  const at = await fetchNamedDocument(sealing.document_commit, sealing.document_sha256);
  if (!at.ok) return { ok: false, reason: `document_at_commit_${at.reason}` };
  if (at.document_sha256 !== sealing.document_sha256) return { ok: false, reason: "bundled_document_differs" };
  return { ok: true };
}

// PUBLICATION FAILS CLOSED, above: the document's entry for `keyId`, of
// `role` (SIGNED UNDER ONE DOCUMENT, above), active, holding exactly
// `verifier` (the whole string: a key id is the name and a 32-bit hash, and
// only the verifier names the key's bytes).
// -> {ok:true, entry} or {ok:false, reason}.
function activeEntry(doc, keyId, verifier, role = "case") {
  const what = role === "case" ? "case signing key" : `${role} key`;
  const c = checkKeyDocument(doc);
  if (!c.ok) {
    return { ok: false, reason: `the case key document does not read (${c.reason} at ${c.at}), so no ${what} is published and the configured key is not used` };
  }
  const e = c.keys.find((x) => x.key_id === keyId);
  if (!e) return { ok: false, reason: `the configured ${what} ${keyId} is not listed in ${CASE_KEYS_DOC}, so it is not used` };
  if (roleOf(e) !== role) {
    return { ok: false, reason: `the configured ${what} ${keyId} is listed in ${CASE_KEYS_DOC} as a ${roleOf(e)} key, not a ${role} key, so it is not used` };
  }
  if (e.status !== "active") return { ok: false, reason: `the configured ${what} ${keyId} is listed in ${CASE_KEYS_DOC} as ${e.status}, not active, so it is not used` };
  if (e.verifier !== verifier) return { ok: false, reason: `the entry for ${keyId} in ${CASE_KEYS_DOC} holds another verifier, so the configured key is not used` };
  return { ok: true, entry: e };
}

// ---------------------------------------------------------------------------
// the signed bytes, the chain, the signature
// ---------------------------------------------------------------------------
// The json-c14n:v1 bytes of the case minus `sig` (lib/_check_record.js).
function sealPreimage(rec) {
  return checkRecord.preimage(rec);
}

// sha256 of the signed bytes: the pin's chain.
function caseChain(rec) {
  return sha256hex(sealPreimage(rec));
}

// A NEW object: `unsigned` signed with `signer`, or unsigned with the reason
// in the form "<unsignedWords> (<code>): <why>.". One routine for every
// record the case key signs (a sealed case, a withdrawal record, a reference
// row: item 2c). signed_by is set here and nowhere else, before the
// signature is taken, so it is inside the signed bytes (SIGNED_BY, above).
function signRecord(unsigned, signer, unsignedWords) {
  const rec = { ...unsigned };
  if (signer && signer.ok) {
    rec.signed_by = signer.keyId;
    rec.sig_reason = null;
    rec.sig = null;
    rec.sig = crypto.sign(null, sealPreimage(rec), signer.privateKey).toString("base64");
  } else {
    rec.signed_by = null;
    rec.sig = null;
    const code = signer && signer.code ? signer.code : "case_key_unset";
    rec.sig_reason = `${unsignedWords} (${code}): ${signer && signer.reason ? signer.reason : "no signer"}.`;
  }
  return rec;
}

function signCase(unsigned, signer) {
  return signRecord(unsigned, signer, "This case is sealed and not signed");
}

// ---------------------------------------------------------------------------
// the receipt
// ---------------------------------------------------------------------------
// The receipt's binding to a case, the part a reader can check from the
// sealed case alone. Returns a reason, or null when it holds.
//   policyVersion  the case's policy_version (the receipt's port version)
//   tapeSha256     {a, b}: the committed tape hashes, role a = tape_a
//   comparedAt     the reveal's service time (UTC seconds)
//   exactMethod    true at seal time: the method block is this build's own
function receiptBinding(r, { policyVersion, tapeSha256, comparedAt, exactMethod }) {
  if (!isPlainObject(r)) return "receipt_not_an_object";
  for (const k of Object.keys(r)) {
    if (!RECEIPT_REQUIRED.includes(k) && !RECEIPT_OPTIONAL.includes(k)) return "receipt_unknown_field";
  }
  for (const k of RECEIPT_REQUIRED) if (!has(r, k)) return "receipt_missing_field";
  if (r.kind !== receipts.RECEIPT_KIND || r.v !== receipts.RECEIPT_VERSION) return "receipt_not_a_reconcile_receipt";
  if (r.claim !== receipts.CLAIM) return "receipt_claim_altered";
  if (!Array.isArray(r.does_not_claim) || !sameC14n(r.does_not_claim, receipts.DOES_NOT_CLAIM)) return "receipt_limits_altered";
  if (!isPlainObject(r.method) || r.method.port_version !== policyVersion) return "receipt_policy_mismatch";
  if (exactMethod && !sameC14n(r.method, receipts.methodBlock())) return "receipt_method_altered";

  const t = r.tapes;
  if (!isPlainObject(t) || Object.keys(t).length !== 2 || !has(t, "tape_a") || !has(t, "tape_b")) return "receipt_tapes_unreadable";
  for (const [slot, role] of [["tape_a", "a"], ["tape_b", "b"]]) {
    const e = t[slot];
    if (!isPlainObject(e) || Object.keys(e).length !== 2 || !has(e, "digest") || !has(e, "bytes")) return "receipt_tapes_unreadable";
    if (!Number.isSafeInteger(e.bytes) || e.bytes < 0) return "receipt_tapes_unreadable";
    if (e.digest !== `${RAW_DIGEST_PREFIX}${tapeSha256[role]}`) return `receipt_${slot}_mismatch`;
  }

  const vb = r.verdict;
  if (!isPlainObject(vb) || Object.keys(vb).length !== RECEIPT_VERDICT_FIELDS.length || !RECEIPT_VERDICT_FIELDS.every((k) => has(vb, k))) {
    return "receipt_verdict_unreadable";
  }
  if (!VERDICT_WORDS.includes(vb.verdict)) return "receipt_verdict_unreadable";

  if (r.verdict_digest === null) {
    if (typeof r.verdict_digest_note !== "string" || !r.verdict_digest_note) return "receipt_verdict_digest_unreadable";
  } else if (typeof r.verdict_digest !== "string" || !C14N_DIGEST.test(r.verdict_digest) || has(r, "verdict_digest_note")) {
    return "receipt_verdict_digest_unreadable";
  }
  if (r.compared_at !== comparedAt) return "receipt_time_mismatch";

  if (r.sig === null) {
    if (r.signer !== null || typeof r.unsigned_reason !== "string" || !r.unsigned_reason) return "receipt_signature_unreadable";
  } else {
    const s = r.signer;
    if (typeof r.sig !== "string" || has(r, "unsigned_reason") || !isPlainObject(s) || Object.keys(s).length !== 3 ||
      typeof s.name !== "string" || typeof s.verifier !== "string" || s.alg !== "ed25519") {
      return "receipt_signature_unreadable";
    }
  }
  return null;
}

// The deep check at seal time (THE RECEIPT CHECK, above).
//   kase         the COMMITTED case being sealed
//   tapeSha256   {a, b}: the committed tape hashes
//   tapeBytes    {a, b}: the submitted tapes' byte counts
//   result       the comparison's own result (lib/_reconcile_tapes.js)
//   revealedAt   the reveal's service time, UTC seconds
//   signer       lib/_reconcile_receipt.js loadSigner() for this request
// -> {ok:true} or {ok:false, reason}.
function checkReceipt(r, { kase, tapeSha256, tapeBytes, result, revealedAt, signer }) {
  const no = (reason) => ({ ok: false, reason });
  const why = receiptBinding(r, { policyVersion: kase.policy_version, tapeSha256, comparedAt: revealedAt, exactMethod: true });
  if (why) return no(why);
  if (r.tapes.tape_a.bytes !== tapeBytes.a || r.tapes.tape_b.bytes !== tapeBytes.b) return no("receipt_tape_size_mismatch");
  const vb = r.verdict;
  if (vb.verdict !== result.verdict || vb.at !== result.at || vb.side !== result.side || vb.matched !== result.matched ||
    !sameC14n(vb.counts, result.counts) || vb.findings !== result.findings.length ||
    vb.could_not_look !== result.could_not_look.length || vb.exit_code !== result.exit_code) {
    return no("receipt_verdict_mismatch");
  }
  if (r.verdict_digest !== T.digestC14n(result)) return no("receipt_verdict_digest_mismatch");
  // A RECEIPT IS THE SERVICE'S, above: no signer, or an unsigned receipt, never seals.
  if (!signer || !signer.ok || r.sig === null) return no("receipt_unsigned");
  if (r.signer.verifier !== signer.verifier || r.signer.name !== signer.name) return no("receipt_signer_mismatch");
  const v = receipts.verifyReceiptText(T.wireJson(r), signer.verifier);
  if (!v.ok) return no(`receipt_${v.reason}`);
  return { ok: true };
}

// The receipt as a case file can hold it (JSON, above).
// -> {ok:true, receipt} or {ok:false, reason}.
function storableReceipt(r) {
  let beyond = false;
  function walk(v) {
    if (typeof v === "bigint") {
      if (v > BigInt(Number.MAX_SAFE_INTEGER) || v < -BigInt(Number.MAX_SAFE_INTEGER)) beyond = true;
      return Number(v);
    }
    if (Array.isArray(v)) return v.map(walk);
    if (isPlainObject(v)) {
      const out = {};
      for (const k of Object.keys(v)) out[k] = walk(v[k]);
      return out;
    }
    return v;
  }
  const copy = walk(r);
  if (beyond) return { ok: false, reason: "integer_beyond_json" };
  let stored;
  try {
    stored = JSON.parse(JSON.stringify(copy));
  } catch {
    return { ok: false, reason: "not_json" };
  }
  if (!sameC14n(stored, r)) return { ok: false, reason: "not_json" };
  if (r.sig !== null) {
    const v = receipts.verifyReceiptText(T.wireJson(stored), r.signer.verifier);
    if (!v.ok) return { ok: false, reason: `stored_receipt_${v.reason}` };
  }
  return { ok: true, receipt: stored };
}

// The stored receipt's binding to the sealed case it is in.
function checkSealedReceipt(rec) {
  return receiptBinding(rec.verdict, {
    policyVersion: rec.policy_version,
    tapeSha256: { a: rec.reveals.a.tape_sha256, b: rec.reveals.b.tape_sha256 },
    comparedAt: rec.reveals.a.revealed_at,
    exactMethod: false,
  });
}

// A RECEIPT IS THE SERVICE'S, above. Why a bound receipt `r` is not signed
// by the service's reconcile signer, `expected` (a verifier string, or null
// when the reader knows none): one of RECEIPT_UNSIGNED_REASONS, or a
// verifyReceiptText reason under `expected` (the receipt was altered after
// signing), or null when it holds.
const RECEIPT_UNSIGNED_REASONS = Object.freeze(["unsigned", "no_reconcile_verifier", "unknown_signer", "signer_not_active"]);
function receiptSignerReason(r, expected) {
  if (r.sig === null) return "unsigned";
  if (typeof expected !== "string" || !expected) return "no_reconcile_verifier";
  if (r.signer.verifier !== expected) return "unknown_signer";
  const v = receipts.verifyReceiptText(T.wireJson(r), expected);
  return v.ok ? null : v.reason;
}

// The stored receipt's binding, then its signature under a GIVEN reconcile
// verifier, `opts.receiptVerifier` (A RECEIPT IS THE SERVICE'S, above), on
// the stored form, the bytes storableReceipt proved at seal time. With no
// verifier given, every signed receipt is refused: since Design I a reader
// takes the verifier from the document the case names (sealedRecordReason),
// never from its own environment. Returns a reason ("receipt_unsigned" for a
// receipt that verifier did not sign), or null when it holds.
function checkStoredReceipt(rec, opts = {}) {
  const why = checkSealedReceipt(rec);
  if (why) return why;
  const signed = receiptSignerReason(rec.verdict, opts && typeof opts.receiptVerifier === "string" ? opts.receiptVerifier : null);
  if (signed === null) return null;
  return RECEIPT_UNSIGNED_REASONS.includes(signed) ? "receipt_unsigned" : `receipt_${signed}`;
}

// ---------------------------------------------------------------------------
// the seal
// ---------------------------------------------------------------------------
// The sealed case (THE SEALED OBJECT, above), signed. Pure. Throws CaseError
// if the result would not be a valid record: this service's defect.
//   kase            the COMMITTED case, as stored and validated
//   reveals         {a: {tape_sha256, salt}, b: {...}} as validated
//   receipt         storableReceipt(...).receipt
//   crossReference  {operator, reference, url} or null
//   revealedAt      the service clock, UTC seconds
//   signedUnder     {document_sha256, document_commit, retrieved_at}
//                   (SIGNED UNDER ONE DOCUMENT, above); required
function sealCase(kase, { reveals, receipt, crossReference, revealedAt, signedUnder }, signer) {
  if (!isPlainObject(signedUnder)) {
    throw new C.CaseError("missing_field", "signed_under", "a seal records the key document it was signed under (SIGNED UNDER ONE DOCUMENT)");
  }
  if (kase.status !== "COMMITTED") {
    throw new C.CaseError("status_inconsistent", "status", `only a COMMITTED case is sealed; this one is ${kase.status}`);
  }
  if (C.singleParty(kase)) {
    throw new C.CaseError("status_inconsistent", "commitments", "one key id registered both roles: a single-party case is never sealed (SINGLE PARTY)");
  }
  const entry = (r) => ({ tape_sha256: reveals[r].tape_sha256, salt_sha256: C.saltSha256(reveals[r].salt), revealed_at: revealedAt });
  const unsigned = JSON.parse(JSON.stringify({
    ...kase,
    reveals: { a: entry("a"), b: entry("b") },
    verdict: receipt,
    records: crossReference ? 2 : 1,
    cross_reference: crossReference
      ? { operator: crossReference.operator, reference: crossReference.reference, url: crossReference.url, recorded_at: revealedAt }
      : null,
    status: "VERDICT",
    signed_under: { document_sha256: signedUnder.document_sha256, document_commit: signedUnder.document_commit, retrieved_at: signedUnder.retrieved_at },
  }));
  const sealed = signCase(unsigned, signer);
  const v = C.validateCase(sealed);
  if (!v.ok) throw new C.CaseError(v.code, v.field, `the sealed case would not be a valid record (${v.error})`);
  const why = checkSealedReceipt(sealed);
  if (why) throw new C.CaseError("status_inconsistent", "verdict", `the sealed receipt is not bound to this case (${why})`);
  return sealed;
}

// A signed record's signature (a case, a withdrawal record, a reference
// row: the lib/_check_record.js rule, Ed25519 over json-c14n:v1 of the
// record minus sig) under `verifierStr`, and the key the record names in
// signed_by is that verifier's key (SIGNED_BY, above). No schema, no clock.
// -> null when it holds, else {reason, field}.
function signatureReason(rec, verifierStr) {
  const sigBytes = Buffer.from(String(rec.sig), "base64");
  if (typeof rec.sig !== "string" || sigBytes.length !== 64 || sigBytes.toString("base64") !== rec.sig) {
    return { reason: "malformed_signature", field: "sig" };
  }
  const vk = checkpoint.parseVerifierKey(verifierStr);
  if (!vk.ok) return { reason: "bad_verifier", field: "verifier" };
  let good = false;
  try {
    good = crypto.verify(null, sealPreimage(rec), vk.publicKey, sigBytes);
  } catch {
    good = false;
  }
  if (!good) return { reason: "bad_signature", field: "sig" };
  if (keyIdOf(vk) !== rec.signed_by) return { reason: "signer_mismatch", field: "signed_by" };
  return null;
}

// A signed record's signature checked against the key document (fix 1 of
// item 2c, and every reader after it): the entry signed_by names must be
// listed IN `role` (unit R-N, N1: a reconcile key never verifies a case
// record, a case key never a reconcile one) and not revoked (a retired key's
// records stay trusted: the document's status_meaning), and the signature
// must verify under that entry's verifier. An unsigned record (sig null) is
// not this function's: the caller decides what unsigned means. `doc`
// defaults to the committed document, `role` to "case".
// -> null when it holds, else a reason.
function publishedSignatureReason(rec, doc = PUBLISHED_KEYS, role = "case") {
  if (rec.sig === null) return "unsigned";
  const c = checkKeyDocument(doc);
  if (!c.ok) return "key_document_unreadable";
  const e = c.keys.find((x) => x.key_id === rec.signed_by && roleOf(x) === role);
  if (!e) return "signer_unpublished";
  if (e.status === "revoked") return "signer_revoked";
  const sr = signatureReason(rec, e.verifier);
  return sr ? sr.reason : null;
}

// THE SEALED CHECK (item 2d; since Design I, under the document the case
// NAMES; since unit R-I, on the published branch, against the CURRENT
// document's listing, and revocation by commit order): what every reader of
// a stored VERDICT holds it to before treating it as sealed, one routine so
// the readers cannot drift. anchorCase runs it before it pins,
// ?op=case-reference before it appends a row, and the case page before it
// shows a verdict. Asynchronous: it reads the named document. In order:
//   0. one key per role (red-team fix A): `single_party`.
//   1. signed_under: none recorded is `document_unrecorded` (a seal made
//      before Design I; never valid under any document).
//   2. the receipt's binding to the case's reveals, compared_at and policy:
//      else `verdict_unbound`; an unsigned receipt is `receipt_unsigned`; an
//      unsigned seal is `case_signature_invalid` (unsigned_seal; ONE
//      SIGNATURE RULE, above).
//   3. the NAMED document: signed_under.document_commit must be on the
//      published branch (commitOnBranch), and the key document there
//      (fetchNamedDocument) must be the one named. A commit that is not on
//      the branch, a branch read or a fetch that fails, is
//      `document_unavailable` (document: "named"): could-not-look, never a
//      yes and never a no. A document there whose json-c14n:v1 sha256 is not
//      signed_under.document_sha256, or that is not a key document, is
//      `case_signature_invalid` (document_sha256_mismatch,
//      named_document_unreadable).
//   4. under the named document, both keys ACTIVE there, by status (since
//      unit R-I no date is read: retrieved_at is display only): the
//      receipt's signer a reconcile entry (else `receipt_unsigned`:
//      unknown_signer, signer_not_active) whose signature verifies (else
//      `verdict_unbound`), the case's signer a case entry (else
//      `case_signature_invalid`: signer_unpublished; signer_revoked or
//      signer_not_active when the named document already lists it revoked or
//      retired) whose signature verifies.
//   5. the CURRENT document, `doc` (the reader's own bundled copy): one that
//      does not read is `document_unavailable` (document: "current",
//      current_document_unreadable). Each key must be listed there in its
//      role, with the same verifier: else `signer_unlisted` (unit R-I, I3).
//      Neither marked revoked: `valid_under_document`.
//   6. a key the current document marks revoked (unit R-I, I1; THE TRUST
//      ROOT, above) is ordered against the case's pin by its revocation
//      marker (revocationOrder): the case pinned strictly before the marker's
//      commit is `signer_since_revoked`, which holds, naming both commits;
//      a pin that could not be read is `pin_unavailable` (could-not-look,
//      never a yes and never a no; unit R-J3, F4); anything else is
//      `signer_revoked`, which does not.
// Both holding answers carry the three signed_under fields. A later document
// never makes a formerly unverifiable stored signature verify: steps 3 and 4
// read only the named document. `rec` is a case the schema already accepts,
// with status VERDICT.
// -> {code, ...}: valid_under_document | signer_since_revoked {case_commit,
//    revoked: [{role, key_id, revoked_since, revoking_commit,
//    revoked_in_document_commit}]} (sealHolds), document_unavailable
//    {reason, document, document_commit}, pin_unavailable {reason, revoked},
//    or a refusal {code, reason}:
//    single_party, document_unrecorded, verdict_unbound, receipt_unsigned,
//    case_signature_invalid, signer_unlisted {key_id}, signer_revoked
//    {case_commit, revoked}.
const HOLDS = Object.freeze(["valid_under_document", "signer_since_revoked"]);
function sealHolds(answer) {
  return !!answer && HOLDS.includes(answer.code);
}

async function sealedRecordReason(rec, doc = PUBLISHED_KEYS) {
  if (C.singleParty(rec)) return { code: "single_party", reason: "same_key_both_roles" };
  const su = rec.signed_under;
  if (!isPlainObject(su)) return { code: "document_unrecorded", reason: "no_signed_under" };
  const unbound = checkSealedReceipt(rec);
  if (unbound) return { code: "verdict_unbound", reason: unbound };
  const r = rec.verdict;
  if (r.sig === null) return { code: "receipt_unsigned", reason: "unsigned" };
  // ONE SIGNATURE RULE (above): an unsigned seal never verifies, under any
  // document
  if (rec.sig === null) return { code: "case_signature_invalid", reason: "unsigned_seal" };
  const unavailable = (reason, document) => ({ code: "document_unavailable", reason, document, document_commit: su.document_commit });
  const nc = await namedDocumentOf(su);
  if (nc.unavailable) return unavailable(nc.unavailable, "named");
  if (nc.invalid) return { code: "case_signature_invalid", reason: nc.invalid };
  const re = nc.keys.find((e) => roleOf(e) === "reconcile" && e.verifier === r.signer.verifier);
  if (!re) return { code: "receipt_unsigned", reason: "unknown_signer" };
  if (re.status !== "active") return { code: "receipt_unsigned", reason: "signer_not_active" };
  const v = receipts.verifyReceiptText(T.wireJson(r), re.verifier);
  if (!v.ok) return { code: "verdict_unbound", reason: `receipt_${v.reason}` };
  const ce = nc.keys.find((e) => roleOf(e) === "case" && e.key_id === rec.signed_by);
  if (!ce) return { code: "case_signature_invalid", reason: "signer_unpublished" };
  if (ce.status !== "active") return { code: "case_signature_invalid", reason: ce.status === "revoked" ? "signer_revoked" : "signer_not_active" };
  const sr = signatureReason(rec, ce.verifier);
  if (sr) return { code: "case_signature_invalid", reason: sr.reason };
  const cc = checkKeyDocument(doc);
  if (!cc.ok) return unavailable("current_document_unreadable", "current");
  const nowCase = cc.keys.find((e) => roleOf(e) === "case" && e.key_id === ce.key_id && e.verifier === ce.verifier);
  if (!nowCase) return { code: "signer_unlisted", reason: "case_key_not_listed", key_id: ce.key_id };
  const nowReconcile = cc.keys.find((e) => roleOf(e) === "reconcile" && e.verifier === re.verifier);
  if (!nowReconcile) return { code: "signer_unlisted", reason: "reconcile_key_not_listed", key_id: re.key_id };
  const under = { document_sha256: su.document_sha256, document_commit: su.document_commit, retrieved_at: su.retrieved_at };
  const revoked = [nowCase, nowReconcile].filter((e) => e.status === "revoked");
  if (!revoked.length) return { code: "valid_under_document", ...under };
  return revocationOrder(rec, revoked, under);
}

// THE NAMED DOCUMENT, READ (THE SEALED CHECK, step 3; since unit R-N2, m6,
// the one reader a seal and a refusal receipt both use): `su`'s
// document_commit on the published branch (commitOnBranch), and the key
// document there (fetchNamedDocument) the one su.document_sha256 names.
// -> {ok:true, keys} (checkKeyDocument's) | {unavailable: reason, off} (could
//    not look; `off` when the commit is definitely not on the branch: ahead
//    or diverged, never a 404) | {invalid: reason} (document_sha256_mismatch,
//    named_document_unreadable).
async function namedDocumentOf(su) {
  const on = await commitOnBranch(su.document_commit);
  if (!on.on) return { unavailable: on.unknown || "commit_not_on_branch", off: !on.unknown && !on.not_found };
  const named = await fetchNamedDocument(su.document_commit, su.document_sha256);
  if (!named.ok) return { unavailable: named.reason, off: false };
  if (named.document_sha256 !== su.document_sha256) return { invalid: "document_sha256_mismatch" };
  const nc = checkKeyDocument(named.doc);
  if (!nc.ok) return { invalid: "named_document_unreadable" };
  return { ok: true, keys: nc.keys };
}

// THE SEALED CHECK, step 6 (unit R-I, I1): each key in `revoked` (entries of
// the current document, marked revoked) against the case's pin. P is the
// case_commit of the case's pin, read as anchorState reads it (pinned: the
// pin holds the chain, and the case file at P is this case); R is the commit
// that wrote the key's revocation marker (revocationMarkerOf). Every key
// with P strictly before R (pinnedBefore) is `signer_since_revoked`;
// otherwise `signer_revoked`, with the first reason found: case_not_pinned
// (no pin, or one that does not read pinned), no_revocation_marker,
// revocation_marker_unreadable, revocation_marker_invalid,
// pinned_at_or_after_revocation (the compare shows P at or after R: ahead or
// identical), order_not_shown (the compare shows no order: a 404, or
// diverged; unit R-N, n6), revocation_order_unreadable (the compare failed).
async function revocationOrder(rec, revoked, under) {
  const listed = revoked.map((e) => ({ role: roleOf(e), key_id: e.key_id, revoked_since: e.revoked_since }));
  const refused = (reason, P = null) => ({ code: "signer_revoked", reason, case_commit: P, revoked: listed });
  const st = await anchorState(rec.case_id, rec, { anchor: false });
  // unit R-J3 (F4): a pin that could not be read is neither a yes nor a no
  if (st.pin === "could_not_look") return { code: "pin_unavailable", reason: st.reason, revoked: listed };
  // unit R-I2 (m2): the reason says which state the pin is in; a legacy pin
  // with no case_commit is case_not_pinned, and a key revoked keeps the
  // sealer from writing the next pin that would record one
  if (st.pin !== "pinned") return refused(notPinnedReason(st));
  const P = st.case_commit;
  const out = [];
  for (let i = 0; i < revoked.length; i += 1) {
    const m = await revocationMarkerOf(revoked[i]);
    if (!m.ok) return refused(m.reason, P);
    const order = await pinnedBefore(m.commit, P);
    if (order.unknown) return refused("revocation_order_unreadable", P);
    if (!order.before) return refused(order.status === "ahead" || order.status === "identical" ? "pinned_at_or_after_revocation" : "order_not_shown", P);
    out.push({ ...listed[i], revoking_commit: m.commit, revoked_in_document_commit: m.marker.revoked_in_commit });
  }
  return { code: "signer_since_revoked", ...under, case_commit: P, revoked: out };
}

// Why a case under a revoked key is not pinned, from anchorState's answer
// (unit R-I2, m2): no pin, a legacy pin with no case_commit, or a pin under
// the case holding another chain is case_not_pinned; a pin naming a commit
// whose case file is another case is pin_commit_mismatch; a pin pointer read
// that is not a case seal record is pin_unreadable:<reason>. A pin that
// could not be read never reaches here (pin_unavailable; unit R-J3, F4).
function notPinnedReason(st) {
  if (st.pin === "pin_commit_mismatch") return "pin_commit_mismatch";
  if (st.pin === "unreadable") return `pin_unreadable:${st.reason}`;
  return "case_not_pinned";
}

// THE NAMED DOCUMENT (THE SEALED CHECK, step 3): the key document at
// `commit` in this public repository, read with no credentials from GitHub's
// raw host. A commit's file never changes, but a read is kept for the life
// of the instance (namedDocuments) only once its sha256 is `wantSha256`, the
// sha256 the reader holds it to (unit R-I, I5): a mismatching read and a
// failed read are not kept. A read with nothing to match (the marker's
// check, the marker tool's walk) is kept by its commit for the instance
// (documentsByCommit; unit R-N, n4), apart: a read held to a sha256 never
// takes it.
// -> {ok:true, doc, document_sha256} (the sha256 of its json-c14n:v1 form)
//    or {ok:false, reason}: fetch_failed, http_<status>, not_json.
const RAW_BASE = "https://raw.githubusercontent.com";
const DOCUMENT_FETCH_TIMEOUT_MS = 8000;
const namedDocuments = new Map();
const documentsByCommit = new Map();
async function fetchNamedDocument(commit, wantSha256) {
  const matching = typeof wantSha256 === "string";
  const kept = namedDocuments.get(commit) || (matching ? undefined : documentsByCommit.get(commit));
  if (kept) return { ok: true, ...kept };
  let r;
  try {
    r = await fetch(`${RAW_BASE}/${KEY_DOCUMENT_REPO}/${commit}/${CASE_KEYS_FILE}`, { signal: AbortSignal.timeout(DOCUMENT_FETCH_TIMEOUT_MS) });
  } catch {
    return { ok: false, reason: "fetch_failed" };
  }
  if (r.status !== 200) return { ok: false, reason: `http_${r.status}` };
  let got;
  try {
    const doc = JSON.parse(await r.text());
    got = { doc, document_sha256: sha256hex(checkRecord.canonicalBytes(doc)) };
  } catch {
    return { ok: false, reason: "not_json" };
  }
  if (!matching) documentsByCommit.set(commit, got);
  else if (got.document_sha256 === wantSha256) namedDocuments.set(commit, got);
  return { ok: true, ...got };
}

// THE ANCESTRY (unit R-I; also for Design J's commits, later): `commit` is
// on `branch` of `repo` (KEY_DOCUMENT_REPO and KEY_DOCUMENT_BRANCH unless
// named; the pins repository is {repo: store.REPO, branch: store.BRANCH}):
// one compare read, compare/<branch>...<commit>, status identical or behind.
// An answer that is on is kept for the instance; off (ahead, diverged), a
// 404 and a failed read are read again (unit R-N2, m2: the branch moves, so
// only an answer that cannot change between two fixed commits is kept).
// -> {on:true} | {on:false} (ahead or diverged) | {on:false, not_found:true}
//    (a commit the repository does not have, or does not show yet: a walk
//    that skips on it reads it again, unit R-N n1) | {unknown: reason}
//    (compare_http_<status>, compare_failed, branch_name_invalid,
//    branch_unreadable).
const onBranch = new Set();
async function commitOnBranch(commit, { repo = KEY_DOCUMENT_REPO, branch } = {}) {
  const b = branch === undefined ? (repo === KEY_DOCUMENT_REPO ? keyDocumentBranch() : store.BRANCH) : branch;
  if (typeof b !== "string" || !BRANCH_NAME.test(b)) return { unknown: "branch_name_invalid" };
  if (typeof commit !== "string" || !GIT_COMMIT.test(commit)) return { on: false };
  const key = `${repo}@${b}:${commit}`;
  if (onBranch.has(key)) return { on: true };
  let cmp;
  try {
    cmp = await store.compareCommits(b, commit, { repo, branch: b, tokenEnv: store.PINS_TARGET.tokenEnv });
  } catch (e) {
    return { unknown: e && Number.isInteger(e.status) ? `compare_http_${e.status}` : "compare_failed" };
  }
  // unit R-I2 (m4): a 404 names "a commit the repository does not have" only
  // when the branch exists; a branch that does not, or that cannot be read
  // (a token that cannot see the repository), is unknown
  if (cmp.status === "not_found") return (await branchExists(repo, b)) ? { on: false, not_found: true } : { unknown: "branch_unreadable" };
  const on = cmp.status === "identical" || cmp.status === "behind";
  if (on) onBranch.add(key);
  return { on };
}

// Whether branch `b` of `repo` exists: one read, kept for the instance once
// it does (unit R-I2, m4). -> true, or false when it does not or the read failed.
const branchesSeen = new Set();
async function branchExists(repo, b) {
  const key = `${repo}@${b}`;
  if (branchesSeen.has(key)) return true;
  let got;
  try {
    got = await store.branchExists(b, { repo, branch: b, tokenEnv: store.PINS_TARGET.tokenEnv });
  } catch {
    return false;
  }
  if (!got.exists) return false;
  branchesSeen.add(key);
  return true;
}

// THE TRUST ROOT, I1 (above): pins-repository commit `P` strictly before
// `R` (compare/<R>...<P> behind; identical is not before). The compare's
// status is kept for the instance, whatever it is (unit R-N, n4), except a
// 404 (a commit the host does not show yet), which is read again.
// -> {before:true} | {before:false, status} (status: ahead, identical,
//    diverged or not_found; unit R-N, n6) | {unknown:true}.
const pinOrder = new Map();
async function pinnedBefore(R, P) {
  const key = `${R}...${P}`;
  let status = pinOrder.get(key);
  if (status === undefined) {
    let cmp;
    try {
      cmp = await store.compareCommits(R, P);
    } catch {
      return { unknown: true };
    }
    status = cmp.status;
    if (status !== "not_found") pinOrder.set(key, status);
  }
  return status === "behind" ? { before: true } : { before: false, status };
}

// THE REVOCATION MARKER (unit R-I; THE TRUST ROOT, above). A key's
// fingerprint is the sha256 of its 32-byte Ed25519 public key, lowercase
// hex; its marker lives in the pins repository at
// revocations/<fingerprint>.json and is exactly {kind: "key-revocation",
// v: 1, key_id, key_fingerprint, revoked_in_commit}, revoked_in_commit
// being the commit of this repository (KEY_DOCUMENT_REPO) at which the key
// document first lists the key revoked. tools/record_key_revocation.js
// writes it, create-only.
const REVOCATION_MARKER_KIND = "key-revocation";
const REVOCATION_MARKER_FIELDS = Object.freeze(["kind", "v", "key_id", "key_fingerprint", "revoked_in_commit"]);
const REVOCATIONS_DIR = "revocations";
const HEX64 = /^[0-9a-f]{64}$/;
function keyFingerprint(verifier) {
  const vk = checkpoint.parseVerifierKey(verifier);
  if (!vk.ok) throw new TypeError("keyFingerprint: not a verifier");
  return sha256hex(vk.pub);
}
function revocationMarkerPath(verifier) {
  return `${REVOCATIONS_DIR}/${keyFingerprint(verifier)}.json`;
}
function revocationMarkerFor(entry, revokedInCommit) {
  return { kind: REVOCATION_MARKER_KIND, v: 1, key_id: entry.key_id, key_fingerprint: keyFingerprint(entry.verifier), revoked_in_commit: revokedInCommit };
}
// -> {ok:true} or {ok:false, reason}.
function validateRevocationMarker(m) {
  if (!isPlainObject(m)) return { ok: false, reason: "not_an_object" };
  for (const k of Object.keys(m)) if (!REVOCATION_MARKER_FIELDS.includes(k)) return { ok: false, reason: `unknown_field:${k}` };
  for (const k of REVOCATION_MARKER_FIELDS) if (!has(m, k)) return { ok: false, reason: `missing_field:${k}` };
  if (m.kind !== REVOCATION_MARKER_KIND || m.v !== 1) return { ok: false, reason: "malformed_field:kind" };
  if (typeof m.key_id !== "string" || !m.key_id) return { ok: false, reason: "malformed_field:key_id" };
  if (typeof m.key_fingerprint !== "string" || !HEX64.test(m.key_fingerprint)) return { ok: false, reason: "malformed_field:key_fingerprint" };
  if (typeof m.revoked_in_commit !== "string" || !GIT_COMMIT.test(m.revoked_in_commit)) return { ok: false, reason: "malformed_field:revoked_in_commit" };
  return { ok: true };
}

// Whether `m` is a valid revocation marker for `entry` (a current-document
// entry marked revoked), the reader's whole check, which the marker tool runs
// too before it writes one: the schema, this key's id and fingerprint, and
// the key document at the commit it names on the published branch (the
// readers', KEY_DOCUMENT_BRANCH) listing this key, in its role, revoked.
// -> {ok:true} or {ok:false, reason}: revocation_marker_invalid, or
//    revocation_marker_unreadable when a read it needs failed. An invalid
//    answer on a compare 404 (a revoking commit the branch does not show)
//    carries not_found: true (unit R-N, n1).
async function checkRevocationMarker(entry, m) {
  const no = (reason) => ({ ok: false, reason });
  if (!validateRevocationMarker(m).ok || m.key_id !== entry.key_id || m.key_fingerprint !== keyFingerprint(entry.verifier)) return no("revocation_marker_invalid");
  const on = await commitOnBranch(m.revoked_in_commit);
  if (on.unknown) return no("revocation_marker_unreadable");
  if (on.not_found) return { ...no("revocation_marker_invalid"), not_found: true };
  if (!on.on) return no("revocation_marker_invalid");
  const d = await fetchNamedDocument(m.revoked_in_commit);
  if (!d.ok) return no(d.reason === "not_json" ? "revocation_marker_invalid" : "revocation_marker_unreadable");
  const dc = checkKeyDocument(d.doc);
  const there = dc.ok ? dc.keys.find((e) => e.key_id === entry.key_id && e.verifier === entry.verifier && roleOf(e) === roleOf(entry)) : null;
  if (!there || there.status !== "revoked") return no("revocation_marker_invalid");
  return { ok: true };
}

// The marker of `entry`, read as it names (unit R-I2, B1 and M1): R is the
// OLDEST commit on its path at which the file reads as a valid marker for
// this key (checkRevocationMarker), found by walking every page of the
// path's commits (allCommitsOf) oldest to newest. Content at an earlier
// commit that is not a valid marker (a stray or wrong first write) is
// skipped; an earlier valid marker always wins, so no later commit moves R.
// A read that fails before the first valid marker is found answers
// unreadable, never a later commit: R could only move later.
//
// A 404 IS NOT PROOF (unit R-N, n1): a candidate skipped on a 404 (nothing
// on the raw host at that commit, or a revoking commit the branch's compare
// does not show) may be the real R, read before the host had it. When a
// marker is found after any such skip, each skipped candidate is read once
// more, and it must then read as something that is not a valid marker
// (content, or not JSON): one that is still a 404 (unit R-N2, m1), or is now
// a valid marker, or cannot be read, makes the answer unreadable. A marker
// found after such a skip is never kept; one found with no such skip is
// kept for the instance, per key.
//
// THE BOUND (unit R-N, n4): at most MARKER_CANDIDATES_READ candidate reads
// per key per request, the second reads of n1 included; one more is
// unreadable.
// -> {ok:true, commit: R, marker} or {ok:false, reason}: no_revocation_marker,
//    revocation_marker_unreadable (a read failed, the history is longer
//    than the walk's bound, or the candidates are more than it reads),
//    revocation_marker_invalid (no commit holds one).
const MARKER_CANDIDATES_READ = 200;
const markers = new Map();
async function revocationMarkerOf(entry) {
  const fp = keyFingerprint(entry.verifier);
  const unreadable = { ok: false, reason: "revocation_marker_unreadable" };
  const mpath = revocationMarkerPath(entry.verifier);
  // A KEY ONCE SHOWN REVOKED STAYS REVOKED (unit R-L, L6): a marker file
  // removed after it was written reads as a marker that cannot be read,
  // never as no marker and never as a key trusted again. So the file is read
  // on the branch at each look, a marker kept for the instance included.
  const present = async () => {
    try {
      return (await store.getFile(mpath)) !== null;
    } catch {
      return false;
    }
  };
  if (markers.has(fp)) return (await present()) ? { ok: true, ...markers.get(fp) } : unreadable;
  const all = await allCommitsOf(mpath);
  if (!all.ok) return unreadable;
  if (!all.list.length) return { ok: false, reason: "no_revocation_marker" };
  let reads = 0;
  // one candidate -> {marker} | {skip} | {soft} (skipped on a 404) | {unreadable}
  const candidate = async (R) => {
    reads += 1;
    const at = await jsonAtCommit(R, mpath);
    // nothing there (a commit that removed the file, or one the host does not show yet)
    if (at.absent) return { soft: true };
    if (!at.ok && at.reason !== "not_json") return { unreadable: true };
    // not JSON: no marker at this commit
    if (!at.ok) return { skip: true };
    const check = await checkRevocationMarker(entry, at.json);
    if (check.reason === "revocation_marker_unreadable") return { unreadable: true };
    if (check.not_found) return { soft: true };
    if (!check.ok) return { skip: true };
    return { marker: at.json };
  };
  const softly = [];
  for (let i = all.list.length - 1; i >= 0; i -= 1) {
    if (reads >= MARKER_CANDIDATES_READ) return unreadable;
    const R = all.list[i].sha;
    const got = await candidate(R);
    if (got.unreadable) return unreadable;
    if (got.soft) softly.push(R);
    if (!got.marker) continue;
    for (const skipped of softly) {
      if (reads >= MARKER_CANDIDATES_READ) return unreadable;
      const again = await candidate(skipped);
      if (!again.skip) return unreadable;
    }
    if (!(await present())) return unreadable;
    if (!softly.length) markers.set(fp, { commit: R, marker: got.marker });
    return { ok: true, commit: R, marker: got.marker };
  }
  // no valid marker found: invalid, unless a candidate was skipped on a 404,
  // which may be a valid one the host does not show yet (unit R-N2, m1)
  return softly.length ? unreadable : { ok: false, reason: "revocation_marker_invalid" };
}

// THE BOUNDS ON THE MARKER (unit R-I, 2026-10-13): a marker counts only
// beside the current document's revocation. Each marker in the pins
// repository whose key `doc` does not list as revoked (or that does not
// read as a marker) is listed here, for the sealer's run to report as
// marker_without_revocation; the sealed check never reads it.
// `paths` are the marker files the sealer's tree read lists.
// -> {ok:true, list: [{path, key_id}]} or {ok:false, reason}.
const REVOCATION_MARKER_RE = /^revocations\/([0-9a-f]{64})\.json$/;
async function markersWithoutRevocation(doc, paths) {
  const c = checkKeyDocument(doc);
  const revokedFingerprints = new Set(c.ok ? c.keys.filter((e) => e.status === "revoked").map((e) => keyFingerprint(e.verifier)) : []);
  const list = [];
  for (const mpath of paths) {
    const name = REVOCATION_MARKER_RE.exec(mpath);
    if (!name) continue;
    let got;
    try {
      got = await store.getFile(mpath);
    } catch {
      return { ok: false, reason: "revocations_unreadable" };
    }
    const m = got && got.json;
    const valid = validateRevocationMarker(m).ok && m.key_fingerprint === name[1];
    if (valid && revokedFingerprints.has(m.key_fingerprint)) continue;
    list.push({ path: mpath, key_id: valid ? m.key_id : null });
  }
  return { ok: true, list };
}

// ---------------------------------------------------------------------------
// the pin (THE CHAIN AND THE PIN, TWO WRITES, above)
// ---------------------------------------------------------------------------
function pinNamespace(caseId) {
  C.casePath(caseId); // the id check
  return `case/${caseId}`;
}

function pinPaths(caseId) {
  const ns = pinNamespace(caseId);
  return { ns, seq: pinPath(caseId, PIN_SEQ), latest: `pins/${ns}/latest.json` };
}

// The case's numbered pin record `n` (1: the seal's own; 2 and on: its next
// pins, THE ROW'S TWO WRITES).
function pinPath(caseId, n) {
  return `pins/${pinNamespace(caseId)}/${String(n).padStart(8, "0")}.json`;
}

// A numbered record read for `chain`: judged, this case's, at its own seq.
function pinAt(json, ns, chain, n, path) {
  return judgeSeal({ json }, path, ns).ok && isOurPin(json, ns, chain) && json.seq === n;
}

// Without `caseCommit` the record has no case_commit: the shape of a pin
// written before Design J (pinChain never writes one).
function pinRecord(caseId, chain, nowMs, caseCommit) {
  const rec = {
    namespace: pinNamespace(caseId),
    rows: PIN_ROWS,
    chain,
    pinned_at: new Date(nowMs).toISOString(),
    seq: PIN_SEQ,
    record_kind: PIN_RECORD_KIND,
    auth_level: PIN_AUTH_LEVEL,
    auth_note:
      `Written by this service when it sealed ${C.casePath(caseId)} (POST ?op=case-reveal), not by POST /api/pin: ` +
      "no bearer key wrote it. chain is the sha256 of the case's json-c14n:v1 bytes minus sig; rows counts the case's " +
      "three records, its two registration files and the sealed case file; case_commit is the pins-repository commit " +
      "that wrote the sealed case file.",
  };
  if (caseCommit !== undefined) rec.case_commit = caseCommit;
  return rec;
}

// A stored pin record, already judged a case_seal record for `ns`
// (lib/_verdict.js judgeCaseSeal), is this case's anchor for `chain`.
// Since Design J any seq: a next pin carries the case's chain too (THE ROW'S
// TWO WRITES); the judge reads the seq, and a numbered record is also held to
// its own (pinAt).
function isOurPin(json, ns, chain) {
  return isPlainObject(json) && json.namespace === ns && json.rows === PIN_ROWS &&
    json.record_kind === PIN_RECORD_KIND && json.chain === chain;
}

function judgeSeal(got, what, ns) {
  return verdict.judgeCaseSeal(got, { what, namespace: ns });
}

// -> one of
//   {pin: "pinned", existing, record, pin_commit}
//                                         the pointer holds this chain (THE ANCHOR
//                                         WORDS: the writer says pinned, never
//                                         anchored); pin_commit is the commit that
//                                         wrote the numbered record when this call
//                                         wrote it, else null (not read here)
//   {pin: "commit_unrecorded", reason}    not pinned; a retry may pin it (TWO
//                                         WRITES: the second phase did not complete)
//   {pin: "could_not_look" | "pin_commit_mismatch", reason}
//                                         from `caseCommit` when it is a resolver
//   {pin: "conflict", record}             another chain is pinned here; never overwritten
//   {pin: "unreadable", reason}           a pin record is present and unreadable
// A "pinned" answer carries `written`: true only when this call wrote the
// numbered record.
//   caseCommit  the commit that wrote the sealed case file (THE PIN IS THE
//               SECOND PHASE): a string, or a function resolving to {ok:true,
//               commit} or {ok:false, pin, reason}, called only when a record
//               is to be written. Without a commit no record is written.
async function pinChain(caseId, chain, nowMs = Date.now(), caseCommit = null) {
  const { ns, seq, latest } = pinPaths(caseId);
  const judged = (got, what) => judgeSeal(got, what, ns);
  const unrecorded = (reason) => ({ pin: "commit_unrecorded", reason });

  let cur;
  try {
    cur = await store.getFile(latest);
  } catch {
    return unrecorded("store_unreachable");
  }
  if (cur !== null) {
    const v = judged(cur, latest);
    if (!v.ok) return { pin: "unreadable", reason: v.reason };
    return isOurPin(cur.json, ns, chain) ? { pin: "pinned", existing: true, written: false, record: cur.json, pin_commit: null } : { pin: "conflict", record: cur.json };
  }

  // The numbered record first: an earlier attempt may have written it and
  // then failed the pointer.
  let prior;
  try {
    prior = await store.getFile(seq);
  } catch {
    return unrecorded("store_unreachable");
  }
  let record;
  let pinCommit = null;
  let written = false;
  if (prior !== null) {
    const v = judged(prior, seq);
    if (!v.ok) return { pin: "unreadable", reason: v.reason };
    if (!isOurPin(prior.json, ns, chain) || prior.json.seq !== PIN_SEQ) return { pin: "conflict", record: prior.json };
    record = prior.json;
  } else {
    let commit = caseCommit;
    if (typeof caseCommit === "function") {
      const got = await caseCommit();
      if (!got.ok) return { pin: got.pin, reason: got.reason };
      commit = got.commit;
    }
    if (typeof commit !== "string" || !GIT_COMMIT.test(commit)) return unrecorded("case_commit_unknown");
    record = pinRecord(caseId, chain, nowMs, commit);
    try {
      const wrote = await store.putFile(seq, record, `case ${caseId.slice(0, 16)}: seal pin rows=${PIN_ROWS} seq=${PIN_SEQ}`);
      pinCommit = commitOfPut(wrote);
      written = true;
    } catch (e) {
      if (!(e && e.conflict)) {
        console.error(`[case] seal: pin record write failed (${e && e.message})`);
        return unrecorded("store_error");
      }
      let won;
      try {
        won = await store.getFile(seq);
      } catch {
        return unrecorded("store_unreachable");
      }
      if (!won || !judged(won, seq).ok || !isOurPin(won.json, ns, chain) || won.json.seq !== PIN_SEQ) return { pin: "conflict", record: won ? won.json : null };
      record = won.json;
      pinCommit = null; // another writer's record: its commit is not ours to name
      written = false;
    }
  }

  let put;
  try {
    put = await store.putFile(latest, record, `latest case/${caseId.slice(0, 16)} rows=${PIN_ROWS} seq=${PIN_SEQ} (case seal)`, undefined, {
      rebuild: () => null, // a pointer that appeared meanwhile is judged below, never written over
    });
  } catch (e) {
    if (!(e && e.conflict)) {
      console.error(`[case] seal: pin pointer write failed (${e && e.message})`);
      return unrecorded("store_error");
    }
    put = { abandoned: true };
  }
  if (put && put.abandoned) {
    let won;
    try {
      won = await store.getFile(latest);
    } catch {
      return unrecorded("store_unreachable");
    }
    if (won && judged(won, latest).ok && isOurPin(won.json, ns, chain)) return { pin: "pinned", existing: true, written, record: won.json, pin_commit: pinCommit };
    return { pin: "conflict", record: won ? won.json : null };
  }
  return { pin: "pinned", existing: false, written, record, pin_commit: pinCommit };
}

// The commit a successful contents-API PUT answered with (lib/_store.js
// putFile returns GitHub's body: {content, commit: {sha}}), or null.
function commitOfPut(put) {
  const c = put && put.commit && put.commit.sha;
  return typeof c === "string" && GIT_COMMIT.test(c) ? c : null;
}

// ---------------------------------------------------------------------------
// THE ANCHOR WORDS (above): files at a commit, and the reader
// ---------------------------------------------------------------------------
// The pins repository's file `path` at `commit`, read on the raw host with
// no credentials. -> {ok:true, text} or {ok:false, reason, absent?}, where
// absent marks a 404 (nothing at that path at that commit, or a commit the
// host does not know yet). Answered reads are kept (commitFiles).
const commitFiles = new Map();
async function fileAtCommit(commit, path) {
  if (typeof commit !== "string" || !GIT_COMMIT.test(commit)) return { ok: false, reason: "not_a_commit" };
  const key = `${store.REPO}@${commit}:${path}`;
  if (commitFiles.has(key)) return { ok: true, text: commitFiles.get(key) };
  let r;
  try {
    r = await fetch(`${RAW_BASE}/${store.REPO}/${commit}/${path}`, { signal: AbortSignal.timeout(DOCUMENT_FETCH_TIMEOUT_MS) });
  } catch {
    return { ok: false, reason: "fetch_failed" };
  }
  if (r.status === 404) return { ok: false, reason: "http_404", absent: true };
  if (r.status !== 200) return { ok: false, reason: `http_${r.status}` };
  let text;
  try {
    text = await r.text();
  } catch {
    return { ok: false, reason: "fetch_failed" };
  }
  commitFiles.set(key, text);
  return { ok: true, text };
}

// The same, parsed as JSON. -> {ok:true, json} or {ok:false, reason, absent?}.
async function jsonAtCommit(commit, path) {
  const f = await fileAtCommit(commit, path);
  if (!f.ok) return f;
  try {
    return { ok: true, json: JSON.parse(f.text) };
  } catch {
    return { ok: false, reason: "not_json" };
  }
}

// Every commit touching `path`, newest first, walking every page of the
// commits list (lib/_store.js listCommitsPage; unit R-I2, B1: one page is the
// newest 100 only, and "the oldest" read from it is not), at most
// COMMIT_LIST_PAGES pages of 100. The walk follows the Link header's next
// page; a short page is not the last (unit R-N, n2), and a full page with
// no next page named is not either (unit R-N2, m3: the page after it is
// read). A history longer than that cannot be walked here: it is not
// answered from the part read.
// -> {ok:true, list} or {ok:false, reason}: commits_unreadable, commits_beyond_bound.
const COMMIT_LIST_PAGES = 50;
async function allCommitsOf(path) {
  const list = [];
  let page = 1;
  for (let n = 0; n < COMMIT_LIST_PAGES; n += 1) {
    let got;
    try {
      got = await store.listCommitsPage(path, { perPage: 100, page });
    } catch {
      return { ok: false, reason: "commits_unreadable" };
    }
    list.push(...got.list);
    if (got.next === null && got.list.length < 100) return { ok: true, list };
    page = got.next === null ? page + 1 : got.next;
  }
  return { ok: false, reason: "commits_beyond_bound" };
}

// The commits touching `path`: the newest and the oldest, every page walked
// (allCommitsOf). -> {ok:true, newest, oldest} (each {sha, date}) or
// {ok:false, reason}: commits_unreadable (a read failed), and, where no read
// failed (unit R-L, g5), commits_beyond_bound or commits_none (the
// repository lists no commit for it).
async function commitsOf(path) {
  const all = await allCommitsOf(path);
  if (!all.ok) return { ok: false, reason: all.reason };
  if (!all.list.length) return { ok: false, reason: "commits_none" };
  return { ok: true, newest: all.list[0], oldest: all.list[all.list.length - 1] };
}

// A commit list's failure as a reader's reason (unit R-L, g5): a read that
// failed keeps its old name, `failed`; one where no read failed is
// <prefix>_commits_beyond_bound or <prefix>_commits_none.
function commitsReason(c, prefix, failed) {
  return c.reason === "commits_unreadable" ? failed : `${prefix}_${c.reason}`;
}

// Why the seal's own pin record (seq 1), read at a commit, is not this
// case's for `chain`, by what was read (unit R-J3, BL2): "not_a_pin" (it
// fails the seal judge, or its seq is not the seal's), "holds_another_chain"
// (a pin record of this case's namespace at the seal's seq, with another
// chain), or null (it is this case's).
function notHeldAtCommit(json, ns, chain, path) {
  if (!judgeSeal({ json }, path, ns).ok || json.seq !== PIN_SEQ) return "not_a_pin";
  return isOurPin(json, ns, chain) ? null : "holds_another_chain";
}

// The chain of a record read at a commit, or null when it is not one.
function chainOrNull(json) {
  if (!isPlainObject(json)) return null;
  try {
    return caseChain(json);
  } catch {
    return null;
  }
}

// Whether `commit` exists in the pins repository (unit R-J, J3): one read of
// the commits API, kept for the instance once it does. -> {exists:true},
// {exists:false}, or {unknown: reason} (the read failed).
const commitsSeen = new Set();
async function commitExists(commit) {
  const key = `${store.REPO}@${commit}`;
  if (commitsSeen.has(key)) return { exists: true };
  let got;
  try {
    got = await store.commitExists(commit);
  } catch (e) {
    return { unknown: e && Number.isInteger(e.status) ? `exists_http_${e.status}` : "exists_read_failed" };
  }
  if (got.exists) commitsSeen.add(key);
  return { exists: got.exists === true };
}

// ONE STANDARD FOR THE CASE AND ITS ROWS (unit R-J, J3, J4, J6): the record
// a reader serves, `served`, is the file at `path` in `commit` of the pins
// repository's branch, byte for byte in json-c14n:v1, signature included
// (sameRecord). `what` names it in the reasons ("case", "reference").
//   A file there that is not the served record (other bytes, or not JSON),
// a commit at which the file is absent, a commit the repository does not
// have (its existence read once from the commits API), and a commit
// definitely off the branch (commitOnBranch) are each pin_commit_mismatch.
// A read that failed (a 5xx, the network, a rate limit), and a commit the
// host does not show on the branch yet (a compare 404 on a branch that
// exists: unit R-J2, M1), are could_not_look.
// -> {ok:true} | {ok:false, pin: "pin_commit_mismatch" | "could_not_look", reason}.
async function servedAtCommit(commit, path, served, what) {
  const mismatch = (reason) => ({ ok: false, pin: "pin_commit_mismatch", reason: `${what}_${reason}` });
  const couldNotLook = (reason) => ({ ok: false, pin: "could_not_look", reason: `${what}_${reason}` });
  const at = await fileAtCommit(commit, path);
  if (!at.ok && !at.absent) return couldNotLook(`at_commit_${at.reason}`);
  if (!at.ok) {
    const ex = await commitExists(commit);
    if (ex.unknown) return couldNotLook(`commit_${ex.unknown}`);
    return mismatch(ex.exists ? "absent_at_commit" : "commit_not_found");
  }
  let json;
  try {
    json = JSON.parse(at.text);
  } catch {
    return mismatch("at_commit_differs");
  }
  if (!sameRecord(json, served)) return mismatch("at_commit_differs");
  const on = await commitOnBranch(commit, { repo: store.REPO, branch: store.BRANCH });
  if (on.unknown) return couldNotLook(`commit_${on.unknown}`);
  if (on.not_found) return couldNotLook("commit_not_shown");
  if (!on.on) return mismatch("commit_off_branch");
  return { ok: true };
}

// THE VERIFIER NEVER TRUSTS case_commit AS AN ID (above): the case file at
// `commit` is the case served, byte for byte (servedAtCommit).
async function caseAtCommit(caseId, commit, served) {
  return servedAtCommit(commit, C.casePath(caseId), served, "case");
}

// THE PIN IS THE SECOND PHASE (above): the sealer's retry reads back the
// commit that wrote the case file (the newest touching it) and checks the
// file at it against the case it read. -> {ok:true, commit} or {ok:false,
// pin, reason}.
async function caseCommitOf(caseId, served) {
  const c = await commitsOf(C.casePath(caseId));
  if (!c.ok) return { ok: false, pin: "could_not_look", reason: "case_commit_unreadable" };
  const held = await caseAtCommit(caseId, c.newest.sha, served);
  return held.ok ? { ok: true, commit: c.newest.sha } : held;
}

// ---------------------------------------------------------------------------
// THE ROW'S TWO WRITES (above): the case's next pin, and the rows' commits
// ---------------------------------------------------------------------------
// At most this many numbered records are read below the pointer, by the
// sealer and by a page, to find which rows the case's pins list.
const PIN_WALK_READS = 20;

// THE ROW CAP (unit R-L2, M3): a case holds at most this many reference
// rows; the next is refused 409 row_limit (lib/_case_http.js). Every next
// pin carries the index of the rows its chain lists (listed_by), so a pin
// grows with the rows, and it must stay readable. lib/_store.js getFile
// reads a file through the contents API, whose answer carries a file's
// content inline only up to 1 MB (1,048,576 bytes); a larger file comes back
// with no content, its JSON parse fails, and the pin could not be read. A
// pin is written as JSON with a two-space indent (lib/_store.js putOnce):
// one listed_by entry, {seq, pin_seq} with both at their eight-digit bound,
// takes 62 bytes in place, so 500 take 31,000; reference_commits holds at
// most REFERENCE_ROW_READS (20) entries, about 2,000 bytes; every other field,
// about 1,500. A pin at the cap is under 35 KB, about a thirtieth of the
// limit (the limit would be met near 16,000 rows).
const MAX_REFERENCE_ROWS = 500;

// The same record, byte for byte in json-c14n:v1.
function sameRecord(a, b) {
  try {
    return Buffer.compare(checkRecord.canonicalBytes(a), checkRecord.canonicalBytes(b)) === 0;
  } catch {
    return false;
  }
}

// The rows the case's pins list, from the pointer's record `top`: seq ->
// {commit, pin_seq}. A pin written since unit R-L (L5) carries its index,
// listed_by: each wanted row's listing pin is read once, directly, and
// nothing is walked (listedByIndex). A pin from before it is walked down,
// stopping once every seq in `want` (when given) is found. -> {ok:true, listed} or {ok:false, listed, reason}:
// pin_unreadable (a record below could not be read), pin_below_absent,
// pin_below_not_a_pin (one read is not this case's pin at its seq), or
// pins_not_read (more than PIN_WALK_READS were needed).
async function listedReferences(caseId, chain, top, want = null) {
  if (Array.isArray(top.listed_by)) return listedByIndex(caseId, chain, top, want);
  const { ns } = pinPaths(caseId);
  const listed = new Map();
  let rec = top;
  for (let reads = 0; ; reads += 1) {
    for (const e of rec.reference_commits || []) if (!listed.has(e.seq)) listed.set(e.seq, { commit: e.commit, pin_seq: rec.seq });
    if (rec.seq <= PIN_SEQ || (want && [...want].every((n) => listed.has(n)))) return { ok: true, listed };
    if (reads >= PIN_WALK_READS) return { ok: false, listed, reason: "pins_not_read" };
    const n = rec.seq - 1;
    const path = pinPath(caseId, n);
    let got;
    try {
      got = await store.getFile(path);
    } catch {
      return { ok: false, listed, reason: "pin_unreadable" };
    }
    // unit R-J3: a record read is never "unreadable": absent, or not this
    // case's pin at its seq
    if (!got) return { ok: false, listed, reason: "pin_below_absent" };
    if (!pinAt(got.json, ns, chain, n, path)) return { ok: false, listed, reason: "pin_below_not_a_pin" };
    rec = got.json;
  }
}

// THE INDEX (unit R-L, L5): the rows `top`'s listed_by names (only those in
// `want`, when given), each from the pin it names, read once (the pointer's
// own rows from the pointer), held to that pin (pinAt) and to its own
// reference_commits. -> as listedReferences; a reason past the walk's:
// index_not_in_pin (the pin the index names does not list the row).
async function listedByIndex(caseId, chain, top, want) {
  const { ns } = pinPaths(caseId);
  const listed = new Map();
  const pins = new Map([[top.seq, top]]);
  for (const e of top.listed_by) {
    if (want && !want.has(e.seq)) continue;
    let rec = pins.get(e.pin_seq);
    if (!rec) {
      const path = pinPath(caseId, e.pin_seq);
      let got;
      try {
        got = await store.getFile(path);
      } catch {
        return { ok: false, listed, reason: "pin_unreadable" };
      }
      if (!got) return { ok: false, listed, reason: "pin_below_absent" };
      if (!pinAt(got.json, ns, chain, e.pin_seq, path)) return { ok: false, listed, reason: "pin_below_not_a_pin" };
      rec = got.json;
      pins.set(e.pin_seq, rec);
    }
    const r = (rec.reference_commits || []).find((x) => x.seq === e.seq);
    if (!r) return { ok: false, listed, reason: "index_not_in_pin" };
    listed.set(e.seq, { commit: r.commit, pin_seq: e.pin_seq });
  }
  return { ok: true, listed };
}

// THE CHAIN ALWAYS ADVANCES (unit R-L, L5): the rows the case's pins list,
// seq -> the pin that lists it, for the next pin. From the pointer's index
// alone when it carries one: no other pin is read, so writing pin N+1 costs
// the same at any N. A pointer from before the index is walked (bounded); a
// walk past its bound is not a failure: the rows it did not reach are listed
// again, read back at their commits, and the next pin carries the index.
// -> {ok:true, index: Map seq -> pin_seq, partial} (partial: the walk did
// not reach the chain's start, so an earlier pin may list a row the index
// lacks) or {ok:false, reason}.
async function listedIndexOf(caseId, chain, top) {
  if (Array.isArray(top.listed_by)) return { ok: true, index: new Map(top.listed_by.map((e) => [e.seq, e.pin_seq])), partial: false };
  const walked = await listedReferences(caseId, chain, top);
  if (!walked.ok && walked.reason !== "pins_not_read") return { ok: false, reason: walked.reason };
  return { ok: true, index: new Map([...walked.listed].map(([n, l]) => [n, l.pin_seq])), partial: !walked.ok };
}

// The case's next pin record (THE ROW'S TWO WRITES, above). `partial`: the
// rows it records are those the pins read below it do not list (a chain
// written before listed_by, walked within its bound and not to its start;
// unit R-L2), and its auth_note says an earlier pin may list some of them too.
function nextPinRecord(caseId, chain, nowMs, seq, caseCommit, referenceCommits, listedBy = [], partial = false) {
  const rec = {
    namespace: pinNamespace(caseId),
    rows: PIN_ROWS,
    chain,
    pinned_at: new Date(nowMs).toISOString(),
    seq,
    record_kind: PIN_RECORD_KIND,
    auth_level: PIN_AUTH_LEVEL,
    auth_note:
      `Written by this service's sealer run after ${C.casePath(caseId)} was sealed, not by POST /api/pin: no bearer key wrote it. ` +
      `It is the case's next pin after pin ${seq - 1}: chain is the case's chain, unchanged; case_commit is the pins-repository ` +
      "commit that wrote the sealed case file; reference_commits, when present, lists the commits that wrote the case's reference " +
      (partial
        ? "rows that the pins read below this one do not list; the pins below were written before listed_by and were not read to the " +
          "chain's start, so an earlier pin may list some of them too; "
        : "rows that no earlier pin lists; ") +
      "listed_by, when present, names for every row this pin or a pin below it lists the pin that lists it.",
    case_commit: caseCommit,
  };
  if (referenceCommits.length) rec.reference_commits = referenceCommits;
  if (listedBy.length) rec.listed_by = listedBy;
  return rec;
}

// The pointer, moved to `record` only from the pointer as read (its blob sha
// `fromSha`).
async function movePointer(caseId, record, fromSha) {
  const { latest } = pinPaths(caseId);
  try {
    const put = await store.putFile(latest, record, `latest case/${caseId.slice(0, 16)} seq=${record.seq} (next pin)`, fromSha, { rebuild: () => null });
    if (put && put.abandoned) return { ok: false, reason: "pin_pointer_moved" };
  } catch {
    return { ok: false, reason: "pin_pointer_not_moved" };
  }
  return { ok: true };
}

// The sealer's second phase for a pinned case (THE ROW'S TWO WRITES, above):
// the rows no pin lists yet, each read back at its commit, and, for a
// pointer that names no case commit, `caseCommit` (read back and checked by
// the caller); with any to record, the next pin, and the pointer moved to it.
// -> {ok:true, written, record?, recorded, rows_unrecorded} or {ok:false,
// reason} (nothing more written; the next run tries again).
async function nextPin(caseId, chain, nowMs, caseCommit) {
  const { ns, latest } = pinPaths(caseId);
  let cur;
  try {
    cur = await store.getFile(latest);
  } catch {
    return { ok: false, reason: "pin_pointer_unreadable" };
  }
  if (!cur || !judgeSeal(cur, latest, ns).ok || !isOurPin(cur.json, ns, chain)) return { ok: false, reason: "pin_pointer_moved" };
  const known = await listedIndexOf(caseId, chain, cur.json);
  if (!known.ok) return { ok: false, reason: known.reason };
  let seqs;
  try {
    seqs = await referenceSeqs(caseId);
  } catch {
    return { ok: false, reason: "references_unreadable" };
  }
  const recorded = [];
  const unrecorded = [];
  for (const n of seqs.filter((x) => !known.index.has(x)).slice(0, REFERENCE_ROW_READS)) {
    const p = C.referencePath(caseId, n);
    let row;
    try {
      row = await store.getFile(p);
    } catch {
      unrecorded.push({ seq: n, code: "could_not_look", reason: "reference_unreadable" });
      continue;
    }
    if (row === null) continue; // listed, then gone
    const c = await commitsOf(p);
    if (!c.ok) {
      unrecorded.push({ seq: n, code: "could_not_look", reason: "reference_commit_unreadable" });
      continue;
    }
    // the readers' routine (unit R-J2, n2): the row as read, at its commit
    const held = await servedAtCommit(c.newest.sha, p, row.json, "reference");
    if (!held.ok) {
      unrecorded.push({ seq: n, code: held.pin, reason: held.reason });
      continue;
    }
    recorded.push({ seq: n, commit: c.newest.sha });
  }
  const commitWanted = cur.json.case_commit === undefined;
  if (!recorded.length && !commitWanted) return { ok: true, written: false, recorded, rows_unrecorded: unrecorded };
  const commit = commitWanted ? caseCommit : cur.json.case_commit;
  if (typeof commit !== "string" || !GIT_COMMIT.test(commit)) return { ok: false, reason: "case_commit_unknown" };
  const seq = cur.json.seq + 1;
  // the index carried forward, and this pin's own rows in it
  const index = new Map(known.index);
  for (const r of recorded) index.set(r.seq, seq);
  const listedBy = [...index].sort((x, y) => x[0] - y[0]).map(([n, pinSeq]) => ({ seq: n, pin_seq: pinSeq }));
  const record = nextPinRecord(caseId, chain, nowMs, seq, commit, recorded, listedBy, known.partial);
  const path = pinPath(caseId, seq);
  try {
    await store.putFile(path, record, `case ${caseId.slice(0, 16)}: next pin seq=${seq}, ${recorded.length} reference commit(s)`);
  } catch (e) {
    if (!(e && e.conflict)) return { ok: false, reason: "store_error" };
    // An earlier run wrote this record and lost the pointer: adopted when it
    // is this case's; what it lists counts from now on, and anything it does
    // not list waits for the next run.
    let won;
    try {
      won = await store.getFile(path);
    } catch {
      return { ok: false, reason: "store_unreachable" };
    }
    if (!won || !pinAt(won.json, ns, chain, seq, path)) return { ok: false, reason: "next_pin_conflict" };
    const adopted = await movePointer(caseId, won.json, cur.sha);
    return adopted.ok ? { ok: true, written: false, adopted: true, record: won.json, recorded: [], rows_unrecorded: unrecorded } : adopted;
  }
  const moved = await movePointer(caseId, record, cur.sha);
  if (!moved.ok) return moved;
  return { ok: true, written: true, record, recorded, rows_unrecorded: unrecorded };
}

// What the case's pins say about each of `rows` (valid rows, as read) for
// the page (THE ROW'S TWO WRITES, above), given the case's anchor state
// `st`. -> Map seq -> {state: "recorded" | "commit_unrecorded" |
// "pin_commit_mismatch" | "could_not_look" | "not_read", commit?, pin_seq?,
// reason?, case_pin?}. Since unit R-J3 a row whose commit was not read says
// so (not_read), with the case's state and reason (case_pin) when the case
// is not shown pinned, or the walk's reason when the walk stopped on a
// record it read; could_not_look is only a read that failed.
async function referenceCommitStates(caseId, chain, st, rows) {
  const out = new Map();
  if (!rows.length) return out;
  const all = (v) => {
    for (const r of rows) out.set(r.seq, v);
    return out;
  };
  if (st.pin === "commit_unrecorded" && st.reason === "not_pinned") return all({ state: "commit_unrecorded", reason: "case_not_pinned" });
  if (st.pin !== "pinned" && st.pin !== "anchored") return all({ state: "not_read", case_pin: st.pin, reason: st.reason });
  const walked = await listedReferences(caseId, chain, st.record, new Set(rows.map((r) => r.seq)));
  await Promise.all(rows.map(async (r) => {
    const l = walked.listed.get(r.seq);
    if (!l) {
      out.set(r.seq, walked.ok ? { state: "commit_unrecorded" }
        : { state: walked.reason === "pin_unreadable" ? "could_not_look" : "not_read", reason: walked.reason });
      return;
    }
    const held = await servedAtCommit(l.commit, C.referencePath(caseId, r.seq), r, "reference");
    out.set(r.seq, held.ok ? { state: "recorded", commit: l.commit, pin_seq: l.pin_seq }
      : { state: held.pin, reason: held.reason, commit: l.commit, pin_seq: l.pin_seq });
  }));
  return out;
}

// The day before an ISO date's day, YYYY-MM-DD.
function dayBefore(iso) {
  const t = Date.parse(`${String(iso).slice(0, 10)}T00:00:00Z`);
  return Number.isFinite(t) ? new Date(t - 86400000).toISOString().slice(0, 10) : "0000-00-00";
}

// The daily anchor record that holds this case's pin (THE ANCHOR WORDS,
// above). -> {found: {path, head_commit, claimed_at, record_commit, proof:
// "unchecked"}}, {conflict: true, reason, found: {path, head_commit}} (a head
// a record names holds another chain for the pin, holds a record there that
// is not a pin record for this case or no JSON, or is off the branch: unit
// R-J, J5 and J6; unit R-J3, BL2), {couldNotLook: reason[, head]} (head: a
// head not shown, unit R-L, g2), or {} (no record read holds it). A record
// that could not be read, an unread pin at its head, a head the repository
// does not show or whose existence could not be read, a head whose branch
// answer is unknown, a record whose own commit or whose text at it could not
// be read, and a record whose newest commit names another head or none are
// misses: the records after it are read, so a later record's proven
// conflict is still found, and the first miss is the answer only when none
// holds the pin (unit R-L, g2; unit R-L2, M4; unit R-L3, a). The OpenTimestamps proof is never
// opened (J2).
async function dailyAnchorOf(caseId, chain, pinCommit, record) {
  const { ns, seq } = pinPaths(caseId);
  const from = dayBefore(pinCommit.date || record.pinned_at);
  let entries;
  try {
    entries = await store.listDir(ANCHORS_DIR);
  } catch {
    return { couldNotLook: "anchors_unreadable" };
  }
  const names = entries
    .map((e) => (e && e.type === "file" && typeof e.name === "string" ? ANCHOR_RECORD_RE.exec(e.name) : null))
    .filter((m) => m && m[1] >= from)
    .map((m) => m[0])
    .sort()
    .slice(0, ANCHOR_RECORD_READS);
  // the first record not read through, and the head it names when that
  // head is not shown (unit R-L, g2): the records after it are still read
  let missed = null;
  const miss = (reason, head) => {
    if (!missed) missed = head ? { couldNotLook: reason, head } : { couldNotLook: reason };
  };
  for (const name of names) {
    const path = `${ANCHORS_DIR}/${name}`;
    let got;
    try {
      got = await store.getRawFile(path);
    } catch {
      miss("anchor_record_unreadable");
      continue;
    }
    const m = got ? ANCHOR_TEXT_RE.exec(got.text) : null;
    if (!m) continue; // gone since the listing, or names no head: it anchors nothing
    const head = m[1];
    const there = await jsonAtCommit(head, seq);
    if (!there.ok && there.reason === "not_json") return { conflict: true, reason: "anchored_head_not_json", found: { path, head_commit: head } };
    if (!there.ok && !there.absent) {
      miss(`pin_at_head_${there.reason}`);
      continue;
    }
    if (!there.ok) {
      // a head from before the pin, only once the repository is read to
      // have it (unit R-J3, F3); a head it does not show, or whose
      // existence could not be read, is a miss, and the records after it
      // are read (unit R-L, g2: one record naming a commit that never
      // exists holds no case back)
      const ex = await commitExists(head);
      if (ex.unknown) miss(`anchor_head_${ex.unknown}`);
      else if (!ex.exists) miss("anchor_head_not_shown", head);
      continue;
    }
    // by what was read at the head (unit R-J3, BL2)
    const not = notHeldAtCommit(there.json, ns, chain, seq);
    if (not) return { conflict: true, reason: `anchored_head_${not}`, found: { path, head_commit: head } };
    const on = await commitOnBranch(head, { repo: store.REPO, branch: store.BRANCH });
    // the branch's answer unknown, the record's own commit or the record at
    // it unread: misses, and the records after it are read (unit R-L3, a)
    if (on.unknown) {
      miss(`anchor_head_${on.unknown}`);
      continue;
    }
    // a head the host does not show yet (unit R-J2, M1): a miss, and the
    // records after it are read (unit R-L2, M4)
    if (on.not_found) {
      miss("anchor_head_not_shown", head);
      continue;
    }
    if (!on.on) return { conflict: true, reason: "anchored_head_off_branch", found: { path, head_commit: head } };
    // anchored is never said without the record's own commit
    const rc = await commitsOf(path);
    if (!rc.ok) {
      miss(commitsReason(rc, "anchor_record", "anchor_record_commit_unreadable"));
      continue;
    }
    const at = await fileAtCommit(rc.newest.sha, path);
    if (!at.ok) {
      miss(`anchor_record_at_commit_${at.reason}`);
      continue;
    }
    // the record at its newest commit names no head, or another: a miss,
    // and the records after it are read (unit R-L2, M4)
    const m2 = ANCHOR_TEXT_RE.exec(at.text);
    if (!m2) {
      miss("anchor_record_names_no_head");
      continue;
    }
    if (m2[1] !== head) {
      miss("anchor_record_changed");
      continue;
    }
    return { found: { path, head_commit: head, claimed_at: m[2], record_commit: rc.newest, proof: "unchecked" } };
  }
  return missed || {};
}

// THE CONFLICT, IN WORDS (unit R-J2, B1): what a conflict's reason says,
// for the page and the reference's 409. "holds another chain" is said only
// for the three *_holds_another_chain reasons: since unit R-J3 (BL2) only of
// a record the seal judge passes at the seal's seq; any other record there
// is *_not_a_pin.
const CONFLICT_WORDS = Object.freeze({
  pointer_holds_another_chain: "the pin pointer under this case's namespace holds another chain",
  pin_at_its_commit_holds_another_chain: "the pin record, read at the commit that wrote it, holds another chain",
  pin_at_its_commit_not_a_pin: "the record at this case's pin path, read at the commit that wrote it, is not a pin record for this case",
  anchored_head_holds_another_chain: "the head a daily anchor record names holds another chain for this case's pin",
  anchored_head_not_a_pin: "the record at this case's pin path, at the head a daily anchor record names, is not a pin record for this case",
  anchored_head_off_branch: "a daily anchor record names a head that is not on the published branch of the pins repository",
  anchored_head_not_json: "the pin record at the head a daily anchor record names could not be read as a pin",
  pin_at_its_commit_not_json: "the pin record at the commit that wrote it could not be read as a pin",
});
function conflictWords(reason) {
  return Object.prototype.hasOwnProperty.call(CONFLICT_WORDS, reason) ? CONFLICT_WORDS[reason]
    : "a pin under this case's namespace is in conflict with this case";
}

// The anchor state of a sealed case, COMPUTED from the pin (design decision
// 2): never a field of the case. Reads only. THE ANCHOR WORDS, above.
// `served` is the case as the caller serves it, held to the bytes at the
// commit its pin names (unit R-J, J4), or its chain: then the case is read
// from the branch (one read) and served when it has that chain. -> one of
//   {pin: "anchored", record, pin_commit, anchor: {path, head_commit,
//     claimed_at, record_commit, proof: "unchecked"}}
//   {pin: "pinned", record, pin_commit, case_commit, anchor: null |
//     {could_not_look[, head_commit]}}
//   {pin: "could_not_look", reason[, case_commit]}
//   {pin: "commit_unrecorded", reason[, record]}
//                                          no pin yet (not_pinned), or a pin
//                                          that names no case commit
//                                          (no_case_commit): THE PIN IS THE
//                                          SECOND PHASE
//   {pin: "pin_commit_mismatch", reason, case_commit, record}
//   {pin: "conflict", reason, record[, anchor]}
//   {pin: "unreadable", reason}
// pin_commit and record_commit are {sha, date}: the date is the commit time
// the pins repository reports; case_commit is the sha the pin names, read.
// anchored also carries case_commit.
//   opts.anchor  false: stop at pinned, reading no daily anchor record; the
//                answer is never anchored, and a pinned one carries
//                `anchor: {not_looked_up: true}` (red-team fix D: a reference
//                needs pinned, and the anchor lookup is reads it does not)
async function anchorState(caseId, served, opts = {}) {
  const chain = typeof served === "string" ? served : caseChain(served);
  const { ns, seq, latest } = pinPaths(caseId);
  const couldNotLook = (reason) => ({ pin: "could_not_look", reason });
  let cur;
  try {
    cur = await store.getFile(latest);
  } catch {
    return couldNotLook("pin_pointer_unreadable");
  }
  if (cur === null) return { pin: "commit_unrecorded", reason: "not_pinned" };
  const v = judgeSeal(cur, latest, ns);
  if (!v.ok) return { pin: "unreadable", reason: v.reason };
  if (!isOurPin(cur.json, ns, chain)) return { pin: "conflict", reason: "pointer_holds_another_chain", record: cur.json };
  const caseCommit = cur.json.case_commit;
  if (caseCommit === undefined) return { pin: "commit_unrecorded", reason: "no_case_commit", record: cur.json };
  // pinned: the numbered record, read at the commit that wrote it
  const wrote = await commitsOf(seq);
  if (!wrote.ok) return couldNotLook(commitsReason(wrote, "pin", "pin_commit_unreadable"));
  const there = await jsonAtCommit(wrote.oldest.sha, seq);
  if (!there.ok && there.reason === "not_json") return { pin: "conflict", reason: "pin_at_its_commit_not_json", record: cur.json };
  if (!there.ok) return couldNotLook(`pin_at_commit_${there.reason}`);
  // by what was read at that commit (unit R-J3, BL2)
  const not = notHeldAtCommit(there.json, ns, chain, seq);
  if (not) return { pin: "conflict", reason: `pin_at_its_commit_${not}`, record: cur.json };
  // and the case file, read at the commit the pin names, is the case served
  let record = served;
  if (typeof served === "string") {
    let head;
    try {
      head = await store.getFile(C.casePath(caseId));
    } catch {
      return couldNotLook("case_unreadable");
    }
    record = head && chainOrNull(head.json) === chain ? head.json : null;
    // the case served does not have the pin's chain: a mismatch, and the
    // case file is not read at the commit (unit R-J2, n5)
    if (record === null) return { pin: "pin_commit_mismatch", reason: "case_served_differs", case_commit: caseCommit, record: cur.json };
  }
  const held = await caseAtCommit(caseId, caseCommit, record);
  // the commit the pin names was read, and is named (unit R-L, g3)
  if (!held.ok && held.pin === "could_not_look") return { pin: "could_not_look", reason: held.reason, case_commit: caseCommit };
  if (!held.ok) return { pin: "pin_commit_mismatch", reason: held.reason, case_commit: caseCommit, record: cur.json };
  const pinned = { record: cur.json, pin_commit: wrote.oldest, case_commit: caseCommit };
  if (opts.anchor === false) return { pin: "pinned", ...pinned, anchor: { not_looked_up: true } };
  // anchored: a daily anchor record whose head holds the pin
  const a = await dailyAnchorOf(caseId, chain, wrote.oldest, cur.json);
  if (a.conflict) return { pin: "conflict", reason: a.reason, record: cur.json, anchor: a.found };
  if (a.found) return { pin: "anchored", ...pinned, anchor: a.found };
  if (!a.couldNotLook) return { pin: "pinned", ...pinned, anchor: null };
  return { pin: "pinned", ...pinned, anchor: a.head ? { could_not_look: a.couldNotLook, head_commit: a.head } : { could_not_look: a.couldNotLook } };
}

// The retry by case_id: read the stored case file, recompute its chain from
// it, and pin that. Before any pin write: the schema; the root's state
// (TERMINAL STATES, above: WITHDRAWN, or OPEN or COMMITTED at or past its
// deadline, is `terminal`, and nothing more is read or written); a single
// party (not_sealed); the projected registration files (unit R-L4:
// `damaged` when one is missing or is not the file projected, never pinned;
// could_not_look when one could not be read); the full
// sealed-receipt check; and the stored case's own signature under the
// verifier its signed_by names in the key document (item 2c, fix 1).
//   opts.now          the run's clock, epoch milliseconds
//   opts.keyDocument  the key document the signature is checked against;
//                     the committed one unless a test hands another
// Since Design I it pins on valid_under_document and signer_since_revoked;
// a named document it cannot read is `could_not_look` (no pin; the next run
// tries again).
// -> {ok:true, chain, pin, ...} or {ok:false, code[, status, reason]}.
async function anchorCase(caseId, opts = {}) {
  const nowMs = opts.now !== undefined ? Number(opts.now) : Date.now();
  const cpath = C.casePath(caseId);
  let got;
  try {
    got = await store.getFile(cpath);
  } catch {
    return { ok: false, code: "store_unreachable" };
  }
  if (got === null) return { ok: false, code: "case_not_found" };
  const v = verdict.judgeWith(got, cpath, (json) => {
    const r = C.validateCase(json);
    if (!r.ok) return `case_${r.code}`;
    return json.case_id === caseId ? true : "case_not_at_its_path";
  });
  if (!v.ok) return { ok: false, code: "case_record_unreadable", reason: v.reason };
  const status = got.json.status;
  // TERMINAL STATES (item 2c, fix 6): never sealed, so never anchored.
  if (status === "WITHDRAWN") return { ok: false, code: "terminal", status: "WITHDRAWN" };
  if (status !== "VERDICT" && C.pastDeadline(got.json, nowMs)) return { ok: false, code: "terminal", status: "EXPIRED" };
  // SINGLE PARTY (red-team fix A): never sealed, whatever its status reads.
  if (C.singleParty(got.json)) return { ok: false, code: "not_sealed", status, reason: "single_party" };
  // THE PROJECTION IS THE REGISTRATION (unit R-L4): a case whose projected
  // registration file is missing or is not the file projected is DAMAGED,
  // and never pinned; a file that could not be read is could-not-look
  const proj = await projectedRegistrations(got.json);
  if (!proj.ok && proj.damaged) return { ok: false, code: "damaged", role: proj.role, reason: proj.reason };
  if (!proj.ok) return { ok: false, code: "could_not_look", reason: proj.reason };
  // THE TWO-PHASE REVEAL (red-team fix E): a COMMITTED case that records a
  // reveal attempt is a reveal that did not complete, never a clean COMMITTED.
  if (status !== "VERDICT") return { ok: false, code: "not_sealed", status, ...(Array.isArray(got.json.reveal_attempts) ? { reason: "reveal_incomplete" } : {}) };
  // THE SEALED CHECK, before any pin write (TWO WRITES, above): the full
  // sealed-receipt check, then the stored case's own signature (item 2c, fix
  // 1). An unsigned seal is never pinned (ONE SIGNATURE RULE, above).
  const answer = await sealedRecordReason(got.json, opts.keyDocument === undefined ? PUBLISHED_KEYS : opts.keyDocument);
  // The named document could not be read, or under a revoked key the pin
  // (unit R-J3, F4): neither a yes nor a no. Nothing this run; the next run
  // tries again (Design I).
  if (answer.code === "document_unavailable" || answer.code === "pin_unavailable") return { ok: false, code: "could_not_look", reason: answer.reason };
  if (!sealHolds(answer)) return { ok: false, code: answer.code, reason: answer.reason };
  const chain = caseChain(got.json);
  // THE PIN IS THE SECOND PHASE (Design J): a record written now records the
  // commit read back and checked; a record found is checked like any
  // reader's.
  const p = await pinChain(caseId, chain, nowMs, () => caseCommitOf(caseId, got.json));
  if (p.pin === "could_not_look" || p.pin === "pin_commit_mismatch") return { ok: false, code: p.pin, reason: p.reason };
  if (p.pin !== "pinned") return { ok: true, chain, ...p };
  let caseCommit = p.record.case_commit;
  if (!p.written) {
    // a pin found is checked like any reader's; one from before that names no
    // case commit gets it read back and checked, for the next pin to record
    // (THE ROW'S TWO WRITES)
    const held = caseCommit === undefined ? await caseCommitOf(caseId, got.json) : await caseAtCommit(caseId, caseCommit, got.json);
    if (!held.ok) return { ok: false, code: held.pin, reason: held.reason };
    if (caseCommit === undefined) caseCommit = held.commit;
  }
  const next = await nextPin(caseId, chain, nowMs, caseCommit);
  return { ok: true, chain, ...p, next };
}

// A pin pointer under a case that is not sealed: a pin no seal backs. Read
// and judged, never written over. -> {pin: "unreadable" | "conflict" |
// "absent" | "unknown", reason?}.
async function strayPin(caseId) {
  const { ns, latest } = pinPaths(caseId);
  let cur;
  try {
    cur = await store.getFile(latest);
  } catch {
    return { pin: "unknown", reason: "store_unreachable" };
  }
  if (cur === null) return { pin: "absent" };
  const v = judgeSeal(cur, latest, ns);
  if (!v.ok) return { pin: "unreadable", reason: v.reason };
  return { pin: "conflict", reason: "pin_without_seal" };
}

// ---------------------------------------------------------------------------
// the readers: the pins tree, the sealer's pass, the status row
// ---------------------------------------------------------------------------
// What a recursive tree listing (lib/_store.js getTree / getTreeMeta entries)
// says about the cases, by path alone: which case files exist, which cases
// hold a pin pointer, and which carry the withdrawn marker
// cases/<case_id>/withdrawn (item 2c). No registration file is read here:
// a registration stands only by the case root's projection (unit R-L4,
// THE PROJECTION IS THE REGISTRATION), which no tree shows, so every case
// file is one the sealer reads (`sealable`).
function caseTreeIndex(entries) {
  const cases = new Set();
  const pinned = new Set();
  const withdrawn = new Set();
  for (const e of entries || []) {
    if (!e || (e.type !== undefined && e.type !== "blob") || typeof e.path !== "string") continue;
    let m = CASE_FILE_RE.exec(e.path);
    if (m) {
      cases.add(m[1]);
      continue;
    }
    m = CASE_WITHDRAWN_RE.exec(e.path);
    if (m) {
      withdrawn.add(m[1]);
      continue;
    }
    m = CASE_PIN_LATEST_RE.exec(e.path);
    if (m) pinned.add(m[1]);
  }
  const sealable = [...cases].sort();
  return { cases, pinned, withdrawn, sealable };
}

// At most `max` of `ids`: `max` entries in a row from a start set by the
// run's clock (THE WINDOW'S START, below; THE TRIGGER, above).
//   THE WINDOW'S START (unit R-N3, N6). The start is derived from the run's
// full timestamp, every millisecond of it: x = nowMs * G mod 2^64 and
// start = floor(x * n / 2^64), with G = 2^64 * (sqrt(5) - 1) / 2 / 60000,
// rounded down and made odd, so the clock turns x by the golden ratio's
// fraction (0.618...) of a full turn each minute. At a fixed run period of
// P ms, x moves on by the same d = P * G mod 2^64 each run, and d is not
// zero for any P below 2^64 ms because G is odd. Over enough runs x takes
// every value x0 + j * 2^v mod 2^64, with 2^v the largest power of two
// dividing P, so for any period under 2^40 ms (about 35 years) it comes
// within 2^-24 of a turn of every point, and every entry of a list shorter
// than 2^24 is read: no fixed period reads one slice forever. The start
// before this unit, floor(nowMs / 1 min) * max mod n, stood still whenever
// the period in minutes times max was a multiple of n (an hourly run with 12
// entries or 30). How many runs it takes depends on the period. With 30
// entries, 5 a run, an hourly run reads every entry within 12 runs and a
// daily run within 28, from any start time, and some start times need all of
// them (unit R-N4, R6: the most is the first count of runs whose x leave no
// gap longer than 5/30 of a turn). One whose turn falls near a half, a third
// or another fraction with a small denominator moves slowly (30 entries, 5 a
// run, every 1292 minutes: thousands of runs), and no start that is a
// function of the clock alone avoids such stretches for every period.
const WINDOW_TURN = (0x9E3779B97F4A7C15n / 60000n) | 1n;
const WINDOW_MASK = (1n << 64n) - 1n;
function rotatingWindow(ids, max, nowMs) {
  if (ids.length <= max) return ids.slice();
  const x = (BigInt(Number.isFinite(nowMs) ? Math.floor(nowMs) : 0) * WINDOW_TURN) & WINDOW_MASK;
  const start = Number((x * BigInt(ids.length)) >> 64n);
  const out = [];
  for (let i = 0; i < max; i += 1) out.push(ids[(start + i) % ids.length]);
  return out;
}

// The sealer's pass (THE TRIGGER, above). Never throws. The candidates are
// every case file with no withdrawn marker (since unit R-L4 no registration
// file decides it: caseTreeIndex), PINNED ONES INCLUDED (item 2c, fix 5; Gemini's review of 2b: with pinned
// cases left out, a squatter or unreadable pin was never looked at again),
// so the rotating window reaches a pinned case too and judges its
// latest.json with the case_seal judge (through anchorCase and pinChain, or
// strayPin for a case that is not sealed), and reports what it found. A case
// with the withdrawn marker is not considered at all, by the tree alone
// (fix 6), and a root read as WITHDRAWN or past its deadline unrevealed is
// skipped and reported as `terminal`.
// -> a report:
//   {ok:true, candidates, pinned, withdrawn_skipped, read, deferred,
//    newly_pinned: [ids pinned now], already: [ids found pinned],
//    commits_recorded: [{case_id, pin_seq, case_commit[, reference_commits]}]
//    (each pin record this run wrote, with the commits it records: THE PIN
//    IS THE SECOND PHASE and THE ROW'S TWO WRITES, nothing backfilled
//    silently; a next pin's entry always carries reference_commits, possibly
//    []),
//    rows_unrecorded: [{case_id, seq, code, reason}] (rows no pin lists yet
//    whose commit this run could not record: could_not_look, or
//    pin_commit_mismatch when the row at its commit is another row),
//    not_sealed, single_party: [ids, each also counted in not_sealed],
//    reveal_incomplete: [ids, each also counted in not_sealed: a COMMITTED
//    case recording a reveal attempt, red-team fix E],
//    could_not_look: [{case_id, reason}] (the named document did not read;
//    Design I), terminal: [{case_id, status}],
//    marker_without_revocation: [{path, key_id}] (unit R-I: a revocation
//    marker whose key the current document does not list as revoked, or that
//    does not read as a marker, key_id null; read from the tree this run
//    already read), markers_unread (null, or why the markers could not be read),
//    pending: [{case_id, reason}] (commit_unrecorded: a retry may record
//    it), refused: [{case_id, code, reason}] (pin_commit_mismatch among them),
//    conflict: [ids], unreadable: [ids], truncated,
//    damaged: [{case_id, role, reason}] (unit R-L4: a projected
//    registration file missing or not the file projected; never pinned),
//    withdrawn_repaired: [repairWithdrawn's answers] (unit R-N, C1: a
//    candidate whose root read WITHDRAWN, its marker not in the tree, gets
//    its marker)}
//   or {ok:false, reason, detail} when the tree cannot be read (nothing
//   written).
async function anchorPending({ now = Date.now(), maxReads = SEALER_CASE_READS, keyDocument, env = process.env } = {}) {
  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  let meta;
  try {
    meta = await store.getTreeMeta();
  } catch (e) {
    return { ok: false, reason: "tree_unreadable", detail: e && e.message ? e.message : null };
  }
  const idx = caseTreeIndex(meta.entries);
  const candidates = idx.sealable.filter((id) => !idx.withdrawn.has(id));
  const picked = rotatingWindow(candidates, maxReads, nowMs);
  const out = {
    ok: true,
    candidates: candidates.length,
    pinned: candidates.filter((id) => idx.pinned.has(id)).length,
    withdrawn_skipped: idx.sealable.length - candidates.length,
    read: picked.length,
    deferred: candidates.length - picked.length,
    newly_pinned: [],
    already: [],
    commits_recorded: [],
    rows_unrecorded: [],
    not_sealed: 0,
    single_party: [],
    reveal_incomplete: [],
    could_not_look: [],
    terminal: [],
    pending: [],
    refused: [],
    marker_without_revocation: [],
    markers_unread: null,
    conflict: [],
    unreadable: [],
    truncated: meta.truncated === true,
    damaged: [],
    withdrawn_repaired: [],
  };
  for (const id of picked) {
    let r;
    try {
      r = await anchorCase(id, { now: nowMs, keyDocument });
    } catch (e) {
      out.refused.push({ case_id: id, code: "threw", reason: e && e.message ? e.message : null });
      continue;
    }
    if (!r.ok && r.code === "damaged") {
      out.damaged.push({ case_id: id, role: r.role, reason: r.reason });
      continue;
    }
    if (!r.ok) {
      // A pin pointer under a case that is not sealed is judged, not skipped.
      if ((r.code === "not_sealed" || r.code === "terminal") && idx.pinned.has(id)) {
        const s = await strayPin(id);
        if (s.pin === "unreadable") {
          out.unreadable.push(id);
          continue;
        }
        if (s.pin === "conflict") {
          out.conflict.push(id);
          continue;
        }
        if (s.pin === "unknown") {
          out.pending.push({ case_id: id, reason: s.reason });
          continue;
        }
      }
      if (r.code === "terminal") {
        out.terminal.push({ case_id: id, status: r.status });
        // a withdrawn root whose marker the tree does not show (it failed)
        if (r.status === "WITHDRAWN") {
          const fixed = await repairWithdrawn(id);
          if (fixed) out.withdrawn_repaired.push(fixed);
        }
      }
      else if (r.code === "not_sealed") {
        out.not_sealed += 1;
        if (r.reason === "single_party") out.single_party.push(id);
        if (r.reason === "reveal_incomplete") out.reveal_incomplete.push(id);
      } else if (r.code === "store_unreachable") out.pending.push({ case_id: id, reason: r.code });
      else if (r.code === "could_not_look") out.could_not_look.push({ case_id: id, reason: r.reason || null });
      else out.refused.push({ case_id: id, code: r.code, reason: r.reason || null });
      continue;
    }
    if (r.pin === "pinned") {
      (r.existing ? out.already : out.newly_pinned).push(id);
      if (r.written) out.commits_recorded.push({ case_id: id, pin_seq: r.record.seq, case_commit: r.record.case_commit });
      const n = r.next;
      if (n && n.ok && n.written) {
        out.commits_recorded.push({ case_id: id, pin_seq: n.record.seq, case_commit: n.record.case_commit, reference_commits: n.recorded });
      }
      if (n && n.ok) for (const u of n.rows_unrecorded) out.rows_unrecorded.push({ case_id: id, ...u });
      if (n && !n.ok) out.pending.push({ case_id: id, reason: n.reason });
    } else if (r.pin === "commit_unrecorded") out.pending.push({ case_id: id, reason: r.reason || null });
    else if (r.pin === "conflict") out.conflict.push(id);
    else out.unreadable.push(id);
  }
  // THE BOUNDS ON THE MARKER (unit R-I): markers without the current
  // document's revocation, from the tree already read
  const markerPaths = (meta.entries || []).filter((e) => e && (e.type === undefined || e.type === "blob") && typeof e.path === "string" &&
    REVOCATION_MARKER_RE.test(e.path)).map((e) => e.path);
  const mw = await markersWithoutRevocation(keyDocument === undefined ? PUBLISHED_KEYS : keyDocument, markerPaths);
  if (mw.ok) out.marker_without_revocation = mw.list;
  else out.markers_unread = mw.reason;
  return out;
}

// The status page's case row (THE READERS, above), from the tree the page
// already read and from nothing else: it never fetches a case file or a pin
// (item 2c, fix 3; Gemini's review of 2b: up to 100 sequential reads a
// render). By path alone:
//   case_files  the cases/<case_id>.json files
//   pinned      a case file with a pin pointer, pins/case/<case_id>/latest.json,
//               and no withdrawn marker, by path alone (THE ANCHOR WORDS:
//               never "anchored", which no tree can say)
//   pending     a case file with no pin pointer and no withdrawn marker. The
//               tree cannot tell which this is: open, committed, sealed and
//               waiting for the sealer's pin, or past its deadline with no
//               reveal. No registration file is counted (unit R-L4: a
//               registration stands only by the case root's projection).
//   withdrawn   a case file with the marker cases/<case_id>/withdrawn, never
//               counted as pending
//   partial     the tree read was truncated (lib/_store.js getTree's
//               `truncated`), so every count above may be short
// Never throws; feeds no verdict.
function caseAnchorSummary(entries, { truncated = false } = {}) {
  const idx = caseTreeIndex(entries);
  let pinned = 0;
  let pending = 0;
  let withdrawn = 0;
  for (const id of idx.cases) {
    if (idx.withdrawn.has(id)) {
      withdrawn += 1;
      continue;
    }
    if (idx.pinned.has(id)) pinned += 1;
    else pending += 1;
  }
  return { case_files: idx.cases.size, pinned, pending, withdrawn, partial: truncated === true };
}

// ---------------------------------------------------------------------------
// the withdrawal record and the reference row (item 2c)
// ---------------------------------------------------------------------------
// The sentence a withdrawal's answer and a WITHDRAWN case's page carry
// (design decision 3: "the page for a WITHDRAWN case says in words that
// registrations, if any, remain in the public record").
const WITHDRAWN_REGISTRATIONS_NOTE =
  "The registration files of this case, if any, remain in the public record of the pins repository, and this withdrawal " +
  "record does not list them. A registration under a withdrawn case does not stand: no reader counts it.";

// THE PUBLIC CLAIM (unit R-L, L2), verbatim on the WITHDRAWN case page, in
// the withdrawal's answer and in the README: what a withdrawal does, and no
// more. Nothing this service says may claim more.
const WITHDRAWAL_CLAIM = "Withdrawal before the reveal closes that case; it does not recall a tape a counterparty already holds, and no " +
  "verdict ever binds a key that did not sign in the case that produced it.";

// The redacted record that replaces an OPEN or COMMITTED case (lib/_case.js,
// THE WITHDRAWAL), signed with the case key like a seal, or unsigned with
// its reason. Pure; `salt` is hashed here and goes nowhere else. Throws
// CaseError if the result would not be a valid record (this service's
// defect).
//   kase    the OPEN or COMMITTED case, as stored and validated
//   role    the role whose commitment preimage proved it
//   at      the service clock, UTC seconds
//   salt    the role's salt, already matched to its registration
//   reason  the reason code (lib/_case.js THE REASON, Design N); the
//           default when the caller names none
function withdrawnRecord(kase, { role, at, salt, reason = C.DEFAULT_WITHDRAWAL_REASON }, signer) {
  if (!C.REGISTERABLE_STATUSES.includes(kase.status)) {
    throw new C.CaseError("status_inconsistent", "status", `only an OPEN or COMMITTED case is withdrawn; this one is ${kase.status}`);
  }
  const unsigned = {
    v: C.CASE_VERSION,
    case_id: kase.case_id,
    protocol_version: kase.protocol_version,
    status: "WITHDRAWN",
    opened_at: kase.opened_at,
    withdrawal: { by_role: role, at, salt_sha256: C.saltSha256(salt), reason },
    limits: C.LIMITS.slice(),
  };
  const rec = signRecord(unsigned, signer, "This withdrawal record is not signed");
  const v = C.validateCase(rec);
  if (!v.ok) throw new C.CaseError(v.code, v.field, `the withdrawal record would not be a valid record (${v.error})`);
  return rec;
}

// A create-only write, said truthfully (unit R-N2, B1): "written" when the
// store answered the write; otherwise (a write abandoned on a path found
// taken, or one refused as a conflict, which is also what four 409s of
// branch-ref contention on an absent path look like) the path is READ BACK,
// and only a file there is "existing"; no file, or a read that fails, is
// "failed", as is any other error. Never throws.
async function createOnly(path, obj, message, what) {
  try {
    const put = await store.putFile(path, obj, message, undefined, { rebuild: () => null });
    if (!(put && put.abandoned)) return "written";
  } catch (e) {
    if (!(e && e.conflict)) {
      console.error(`[case] ${what} write failed (${e && e.message})`);
      return "failed";
    }
  }
  try {
    return (await store.getFile(path)) !== null ? "existing" : "failed";
  } catch (e) {
    console.error(`[case] ${what} could not be read back (${e && e.message})`);
    return "failed";
  }
}

// THE WITHDRAWN MARKER (item 2c): cases/<case_id>/withdrawn, create-only,
// so a tree listing shows the withdrawal without a fetch (caseTreeIndex).
// The withdrawal handler writes it, and a retried withdrawal and the
// sealer's withdrawn path (repairWithdrawn) write it again when it failed
// (unit R-N, C1 and C3). -> "written", "existing" (a marker is there,
// read back; never written over) or "failed" (createOnly).
async function writeWithdrawnMarker(caseId, at) {
  return createOnly(C.withdrawnMarkerPath(caseId), { kind: "case-withdrawn-marker", v: 1, case_id: caseId, withdrawn_at: at },
    `case ${caseId.slice(0, 16)}: withdrawn marker`, "withdrawn marker");
}

// THE ROOT BEFORE THE WITHDRAWAL (unit R-L4). A withdrawn case's root is
// the redacted record, which projects no registration, and nothing writes
// over it. The version of the root its withdrawal wrote over is the newest
// one in the root's history that does not read WITHDRAWN, and its
// projection is what stood when the case was withdrawn: a registration file
// it does not project (written after the withdrawal, or never confirmed) is
// not in it. At most WITHDRAWAL_COMMIT_READS versions are read.
// -> {ok:true, kase} or {ok:false, reason}.
const WITHDRAWAL_COMMIT_READS = 5;
async function rootBeforeWithdrawal(caseId) {
  const cpath = C.casePath(caseId);
  const all = await allCommitsOf(cpath);
  if (!all.ok) return { ok: false, reason: all.reason };
  for (let i = 0; i < all.list.length; i += 1) {
    if (i >= WITHDRAWAL_COMMIT_READS) return { ok: false, reason: "withdrawal_commit_beyond_bound" };
    const at = await jsonAtCommit(all.list[i].sha, cpath);
    if (!at.ok) return { ok: false, reason: `case_at_commit_${at.reason}` };
    if (isPlainObject(at.json) && at.json.status === "WITHDRAWN") continue;
    if (!C.validateCase(at.json).ok || at.json.case_id !== caseId) return { ok: false, reason: "case_before_withdrawal_unreadable" };
    return { ok: true, kase: at.json };
  }
  return { ok: false, reason: "no_root_before_withdrawal" };
}

// THE PROJECTION IS THE REGISTRATION (unit R-L4). A registration file is a
// claim, inert until the case root projects it (lib/_case.js THE
// PROJECTION). Every reader of a case's registrations (the commit path, the
// reveal and its refusal receipt, the withdrawal and the reference in
// lib/_case_http.js; the sealer, anchorCase; the case page) takes them from
// the root's projection by this one helper, which reads the file at each
// projected role's path and checks its bytes against the sha256 the
// projection carries. No reader lists or reads a registration file to decide
// whether it stands, and nothing is ever deleted.
//   DAMAGED: a projected file that is missing (registration_file_missing),
// is not the file projected (registration_file_differs), or does not hold
// the registration the root's entry says it does
// (projection_differs_from_file). It is its own state, said plainly: never
// sealed, never pinned, and nothing here resolves it. A read that fails is
// could-not-look, never DAMAGED.
// -> {ok:true, entries: {a, b}, texts: {a, b}} (each the projected entry,
//    and its file's text as checked, or null)
//    | {ok:false, damaged:true, role, reason}
//    | {ok:false, role, reason: "registration_unreadable"}.
async function projectedRegistrations(kase) {
  const c = isPlainObject(kase) && isPlainObject(kase.commitments) ? kase.commitments : {};
  const entries = { a: c.a || null, b: c.b || null };
  const texts = { a: null, b: null };
  for (const r of C.ROLES) {
    if (!entries[r]) continue;
    // the file at the projected claim's path (lib/_case.js THE CLAIM)
    const path = C.registrationPath(kase.case_id, r, entries[r].claim_sha256);
    let got;
    try {
      got = await store.getRawFile(path);
    } catch {
      return { ok: false, role: r, path, reason: "registration_unreadable" };
    }
    if (got === null) return { ok: false, damaged: true, role: r, path, reason: "registration_file_missing" };
    if (sha256hex(Buffer.from(got.text, "utf8")) !== entries[r].registration_sha256) {
      return { ok: false, damaged: true, role: r, path, reason: "registration_file_differs" };
    }
    let held;
    try {
      held = JSON.parse(got.text);
    } catch {
      held = null;
    }
    if (!C.validateRegistrationRecord(held).ok || !C.sameEntry(entries[r], C.commitmentEntry(held)) ||
      C.claimSha256(held) !== entries[r].claim_sha256) {
      return { ok: false, damaged: true, role: r, path, reason: "projection_differs_from_file" };
    }
    texts[r] = got.text;
  }
  return { ok: true, entries, texts };
}

// What DAMAGED says (projectedRegistrations), in one sentence without its
// full stop.
function damagedWords(caseId, d) {
  const path = d.path;
  if (d.reason === "registration_file_missing") {
    return `role ${d.role}'s registration file, ${path}, is missing, and the case root projects it (registration_file_missing)`;
  }
  if (d.reason === "projection_differs_from_file") {
    return `the case root's entry for role ${d.role} is not the registration its file, ${path}, holds (projection_differs_from_file)`;
  }
  return `role ${d.role}'s registration file, ${path}, is not the file the case root projects (registration_file_differs)`;
}

// THE SEALER'S WITHDRAWN PATH (unit R-N, C1; since unit R-L4 the marker
// alone): a withdrawn case whose marker write failed gets its marker, a
// create. Nothing else is written, and nothing is removed. Never throws.
// -> null when the case does not read WITHDRAWN, else {case_id, marker:
//    "written" | "existing" | "failed"}, or {case_id, marker: null, reason:
//    "case_unreadable"}.
async function repairWithdrawn(caseId) {
  let got;
  try {
    got = await store.getFile(C.casePath(caseId));
  } catch {
    return { case_id: caseId, marker: null, reason: "case_unreadable" };
  }
  if (!got || !C.validateCase(got.json).ok || got.json.case_id !== caseId || got.json.status !== "WITHDRAWN") return null;
  return { case_id: caseId, marker: await writeWithdrawnMarker(caseId, got.json.withdrawal.at) };
}

// THE REFUSAL RECEIPT (Design N, 2026-10-12; since unit R-N, N1 and N3). A
// joint reveal that arrives after a withdrawal is refused 409
// case_withdrawn, its tapes never decoded or hashed (lib/_case_http.js), and the
// refusing answer carries this receipt, which the requester may show to
// anyone: {kind: "comparison_refused", v: 1, case_id, at (this service's
// clock), reason: "consent_not_jointly_held", role (the requester's), commitment_sha256
// (the requester's registered commitment, which its own opening recomputed),
// signed_under (the key document the deployment carries and its commit, as
// a seal records them)}, signed with the RECONCILE key (signRecord:
// signed_by, sig, and sig_reason null). A receipt is signed or it is not
// issued: the caller refuses 503 when it has no reconcile signer, so no
// receipt is ever unsigned and no sig_reason ever says why. It is written
// nowhere: the public case record and page do not change.
//   verifyRefusalReceipt checks one the way the sealed check reads a seal
// (unit R-I's reader): exactly its fields and fixed values; signed_under's
// commit on the published branch and the document there the one named;
// signed_by an ACTIVE reconcile entry of that named document whose
// signature verifies; and the key still listed in its role with the same
// verifier in the CURRENT document, not revoked.
const REFUSAL_RECEIPT_KIND = "comparison_refused";
const REFUSAL_RECEIPT_REASON = "consent_not_jointly_held";
const REFUSAL_RECEIPT_FIELDS = Object.freeze(["kind", "v", "case_id", "at", "reason", "role", "commitment_sha256", "signed_under",
  "signed_by", "sig", "sig_reason"]);
const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

// `signer` is the reconcile signer (loadReconcileSigner), loaded: the caller
// issues no receipt without one. Pure.
function refusalReceipt({ caseId, at, role, commitmentSha256, signedUnder }, signer) {
  return signRecord({
    kind: REFUSAL_RECEIPT_KIND, v: 1, case_id: caseId, at, reason: REFUSAL_RECEIPT_REASON, role, commitment_sha256: commitmentSha256,
    signed_under: { document_sha256: signedUnder.document_sha256, document_commit: signedUnder.document_commit, retrieved_at: signedUnder.retrieved_at },
  }, signer, "This refusal receipt is not signed");
}

// -> {ok:true} or {ok:false, reason}: not_an_object, unknown_field,
//    missing_field, malformed_field, unsigned, document_not_on_branch (its
//    commit is definitely not on the published branch: ahead or diverged;
//    unit R-N2, m6), document_unavailable (the named document could not be
//    read: could not look), document_sha256_mismatch,
//    named_document_unreadable, signer_unpublished, signer_not_active, a
//    signature reason (bad_signature, signer_mismatch, ...),
//    current_document_unreadable, signer_unlisted, signer_revoked.
// The receipt's own form, read with no document (shared with
// tools/check_refusal_receipt.js): exactly its fields and fixed values,
// signed. -> null, or the reason it is not one.
function refusalReceiptFormReason(rec) {
  if (!isPlainObject(rec)) return "not_an_object";
  for (const k of Object.keys(rec)) if (!REFUSAL_RECEIPT_FIELDS.includes(k)) return "unknown_field";
  for (const k of REFUSAL_RECEIPT_FIELDS) if (!has(rec, k)) return "missing_field";
  if (rec.kind !== REFUSAL_RECEIPT_KIND || rec.v !== 1 || rec.reason !== REFUSAL_RECEIPT_REASON) return "malformed_field";
  if (typeof rec.case_id !== "string" || !HEX64.test(rec.case_id)) return "malformed_field";
  if (typeof rec.at !== "string" || !UTC_SECONDS.test(rec.at)) return "malformed_field";
  if (!C.ROLES.includes(rec.role) || typeof rec.commitment_sha256 !== "string" || !HEX64.test(rec.commitment_sha256)) return "malformed_field";
  const su = rec.signed_under;
  if (!isPlainObject(su) || Object.keys(su).length !== 3 || typeof su.document_sha256 !== "string" || !HEX64.test(su.document_sha256) ||
    typeof su.document_commit !== "string" || !GIT_COMMIT.test(su.document_commit) || typeof su.retrieved_at !== "string" || !UTC_SECONDS.test(su.retrieved_at)) {
    return "malformed_field";
  }
  if (rec.sig === null) return "unsigned";
  if (rec.sig_reason !== null) return "malformed_field";
  return null;
}

async function verifyRefusalReceipt(rec, doc = PUBLISHED_KEYS) {
  const no = (reason) => ({ ok: false, reason });
  const form = refusalReceiptFormReason(rec);
  if (form) return no(form);
  const su = rec.signed_under;
  // the named document, read as a seal's is (namedDocumentOf; unit R-N2, m6)
  const nc = await namedDocumentOf(su);
  if (nc.unavailable) return no(nc.off ? "document_not_on_branch" : "document_unavailable");
  if (nc.invalid) return no(nc.invalid);
  const e = nc.keys.find((x) => x.key_id === rec.signed_by && roleOf(x) === "reconcile");
  if (!e) return no("signer_unpublished");
  if (e.status !== "active") return no("signer_not_active");
  const sr = signatureReason(rec, e.verifier);
  if (sr) return no(sr.reason);
  const cc = checkKeyDocument(doc);
  if (!cc.ok) return no("current_document_unreadable");
  const now = cc.keys.find((x) => roleOf(x) === "reconcile" && x.key_id === e.key_id && x.verifier === e.verifier);
  if (!now) return no("signer_unlisted");
  if (now.status === "revoked") return no("signer_revoked");
  return { ok: true };
}

// A reference row (lib/_case.js, THE REFERENCE ROW), signed with the case
// key, or unsigned with its reason. Pure. Throws CaseError on a row the
// schema refuses.
function referenceRow({ caseId, seq, crossReference, recordedAt, appendedBy }, signer) {
  const unsigned = {
    kind: C.REFERENCE_KIND,
    v: 1,
    case_id: caseId,
    seq,
    cross_reference: { operator: crossReference.operator, reference: crossReference.reference, url: crossReference.url },
    recorded_at: recordedAt,
    appended_by: appendedBy,
    anchor_note: C.REFERENCE_ANCHOR_NOTE,
    note_version: C.REFERENCE_NOTE_VERSION,
  };
  const rec = signRecord(unsigned, signer, "This reference row is not signed");
  const v = C.validateReferenceRow(rec);
  if (!v.ok) throw new C.CaseError(v.code, v.field, `the reference row would not be a valid row (${v.error})`);
  return rec;
}

// The case_reference judge: a stored row, read through the store, against
// its path and the sealed case it belongs to. Exactly the row's fields (the
// schema), its case and seq the path's, recorded no earlier than the seal,
// and a signature the key document confirms under a CASE key
// (publishedSignatureReason). ONE SIGNATURE RULE EVERYWHERE (unit R-N, N1):
// an unsigned row is not a record, `row_unsigned`, never counted; a signed
// row the document cannot confirm is not valid either. -> a lib/_verdict.js
// verdict.
function judgeReferenceRow(got, { path, caseId, seq, sealed, keyDocument = PUBLISHED_KEYS }) {
  return verdict.judgeWith(got, path, (json) => {
    const r = C.validateReferenceRow(json);
    // a row with no note_version, or version 2 (never issued), says so by
    // name (unit R-J, J1; unit R-J2, B2)
    if (!r.ok) return r.code === "row_note_v1" || r.code === "row_note_v2" ? r.code : `reference_${r.code}`;
    if (json.case_id !== caseId || json.seq !== seq) return "reference_not_at_its_path";
    if (sealed && sealed.reveals && Date.parse(json.recorded_at) < Date.parse(sealed.reveals.a.revealed_at)) return "reference_before_seal";
    if (json.sig === null) return "row_unsigned";
    const bad = publishedSignatureReason(json, keyDocument);
    if (bad) return `reference_signature_${bad}`;
    return true;
  });
}

const REFERENCE_NAME_RE = /^([0-9]{8})\.json$/;
// Reference rows read per live count, at most (the page's read bound).
const REFERENCE_ROW_READS = 20;

// The seqs the references directory holds, ascending, by name alone. A
// listing that cannot be read throws (the caller says so; it is never read
// as "no rows").
async function referenceSeqs(caseId) {
  const entries = await store.listDir(C.referencesDir(caseId));
  const seqs = [];
  for (const e of entries) {
    const m = e && e.type === "file" && typeof e.name === "string" ? REFERENCE_NAME_RE.exec(e.name) : null;
    if (m && Number(m[1]) >= 1) seqs.push(Number(m[1]));
  }
  return seqs.sort((x, y) => x - y);
}

// THE LIVE RECORD COUNT (design, "After item 2b": "the sealed records field
// is the count at seal time and never changes; the page derives the live
// count from valid addenda"). 2 when the sealed case carries its
// cross_reference or at least one valid reference row exists, else 1:
// records counts operators that hold a record of this case, one or two,
// never rows. Reads the references directory and at most `maxRows` rows, in
// seq order. Never throws.
//   NEVER A COUNT FROM A TRUNCATED READ (item 2d; the code review of 2c: with
// twenty invalid rows before a valid one, the window read only the twenty
// and said "one record"). The count is 2 as soon as the seal carries its
// cross_reference or one valid row is read, whatever was left unread: a
// record is at most two, so no unread row can change it. It is 1 only when
// the read was whole, every listed row read and judged, and none is valid.
// When the read ends without a valid row and a listed row was not seen (left
// past the window, or a read of it that failed, which is not an invalid
// row), that row might be valid, so the count is NOT ESTABLISHED:
// `indeterminate: true` and `records: null`, never 1. A caller says so in
// words; it never reads null as one.
// -> {ok:true, records: 1 | 2 | null, indeterminate, sealed_records, rows:
//     [valid rows], invalid: [{seq, reason}], unreadable: [seqs whose read
//     failed], unread, partial} or {ok:false, reason}.
async function liveRecords(sealed, { keyDocument = PUBLISHED_KEYS, maxRows = REFERENCE_ROW_READS } = {}) {
  if (!sealed || sealed.status !== "VERDICT") return { ok: false, reason: "not_sealed" };
  let seqs;
  try {
    seqs = await referenceSeqs(sealed.case_id);
  } catch {
    return { ok: false, reason: "references_unreadable" };
  }
  const picked = seqs.slice(0, maxRows);
  const rows = [];
  const invalid = [];
  const unreadable = [];
  for (const seq of picked) {
    const p = C.referencePath(sealed.case_id, seq);
    let got;
    try {
      got = await store.getFile(p);
    } catch {
      unreadable.push(seq); // not seen, so not judged: never counted as invalid
      continue;
    }
    if (got === null) continue; // listed, then gone
    const v = judgeReferenceRow(got, { path: p, caseId: sealed.case_id, seq, sealed, keyDocument });
    if (v.ok) rows.push(got.json);
    else invalid.push({ seq, reason: v.reason });
  }
  const unread = seqs.length - picked.length;
  const whole = unread === 0 && unreadable.length === 0;
  const two = sealed.cross_reference !== null || rows.length > 0;
  const indeterminate = !two && !whole;
  return {
    ok: true,
    records: two ? 2 : indeterminate ? null : 1,
    indeterminate,
    sealed_records: sealed.records,
    rows,
    invalid,
    unreadable,
    unread,
    partial: unread > 0,
  };
}

// ---------------------------------------------------------------------------
// the published key document (SIGNED_BY, above)
// ---------------------------------------------------------------------------
// The entry the document carries for a case key: a loaded signer, or
// loadCaseSigner's key_unpublished answer, which carries the public half
// (keyId, verifier) of a key that parsed and is not listed yet. Only the
// public half is read.
function keyDocumentEntry(signer, { since, note, status = "active" }) {
  if (!signer || typeof signer.keyId !== "string" || typeof signer.verifier !== "string") {
    throw new TypeError("keyDocumentEntry: a case key that parsed (keyId and verifier) is required");
  }
  const vk = checkpoint.parseVerifierKey(signer.verifier);
  if (!vk.ok || keyIdOf(vk) !== signer.keyId) throw new TypeError("keyDocumentEntry: keyId is not the key the verifier names");
  return { key_id: signer.keyId, verifier: signer.verifier, since, note, status };
}

// The document's shape. -> {ok:true, keys} or {ok:false, reason, at}.
function checkKeyDocument(doc) {
  const no = (reason, at) => ({ ok: false, reason, at });
  if (!isPlainObject(doc)) return no("not_an_object", "$");
  // Exact fields, like every record here (item 2c, fix 4): a top-level field
  // the checker does not know is a field a reader might trust that nobody
  // checked.
  for (const k of Object.keys(doc)) if (!CASE_KEYS_TOP_FIELDS.includes(k)) return no("unknown_field", k);
  for (const k of CASE_KEYS_TOP_FIELDS) if (!has(doc, k)) return no("missing_field", k);
  if (doc.schema !== CASE_KEYS_SCHEMA) return no("wrong_schema", "schema");
  for (const k of ["issuer", "description", "matching", "rotation"]) {
    if (typeof doc[k] !== "string" || !doc[k].trim()) return no("malformed_field", k);
  }
  if (!isPlainObject(doc.status_meaning) || !CASE_KEY_STATUSES.every((s) => typeof doc.status_meaning[s] === "string")) {
    return no("malformed_field", "status_meaning");
  }
  if (typeof doc.updated !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(doc.updated)) return no("malformed_field", "updated");
  if (!Array.isArray(doc.keys)) return no("malformed_field", "keys");
  const seen = new Set();
  const seenPub = new Set();
  for (let i = 0; i < doc.keys.length; i += 1) {
    const e = doc.keys[i];
    const at = `keys[${i}]`;
    if (!isPlainObject(e)) return no("malformed_entry", at);
    for (const k of Object.keys(e)) {
      if (!CASE_KEY_ENTRY_FIELDS.includes(k) && !CASE_KEY_ENTRY_OPTIONAL.includes(k)) return no("unknown_field", `${at}.${k}`);
    }
    for (const k of CASE_KEY_ENTRY_FIELDS) if (!has(e, k)) return no("missing_field", `${at}.${k}`);
    const vk = checkpoint.parseVerifierKey(e.verifier);
    if (!vk.ok) return no("bad_verifier", `${at}.verifier`);
    if (e.key_id !== keyIdOf(vk)) return no("key_id_mismatch", `${at}.key_id`);
    if (typeof e.since !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(e.since)) return no("malformed_field", `${at}.since`);
    if (typeof e.note !== "string" || !e.note.trim()) return no("malformed_field", `${at}.note`);
    if (!CASE_KEY_STATUSES.includes(e.status)) return no("malformed_field", `${at}.status`);
    // SIGNED UNDER ONE DOCUMENT, above: the role, and revoked_since beside
    // status revoked and nowhere else.
    if (has(e, "role") && !KEY_ROLES.includes(e.role)) return no("malformed_field", `${at}.role`);
    if (e.status === "revoked" && !has(e, "revoked_since")) return no("missing_field", `${at}.revoked_since`);
    if (has(e, "revoked_since") && (e.status !== "revoked" || typeof e.revoked_since !== "string" || !ISO_DATE.test(e.revoked_since))) {
      return no("malformed_field", `${at}.revoked_since`);
    }
    if (seen.has(e.key_id)) return no("duplicate_key_id", `${at}.key_id`);
    seen.add(e.key_id);
    // one public key, one entry, across roles (unit R-I, I4): the same bytes
    // under another name are the same key
    const pubHex = vk.pub.toString("hex");
    if (seenPub.has(pubHex)) return no("duplicate_public_key", `${at}.verifier`);
    seenPub.add(pubHex);
  }
  return { ok: true, keys: doc.keys.slice() };
}

// The document's entry for a key id, or null.
function publishedEntry(doc, keyId) {
  const c = checkKeyDocument(doc);
  if (!c.ok) return null;
  return c.keys.find((e) => e.key_id === keyId) || null;
}

module.exports = {
  CASE_SIGNER_ENV,
  OTHER_KEYS,
  PIN_ROWS,
  PIN_RECORD_KIND,
  ANCHOR_NOTE,
  ANCHOR_RECORD_READS,
  conflictWords,
  commitOfPut,
  referenceCommitStates,
  PIN_WALK_READS,
  CASE_KEYS_DOC,
  CASE_KEYS_FILE,
  CASE_KEYS_SCHEMA,
  CASE_KEY_ENTRY_FIELDS,
  CASE_KEY_ENTRY_OPTIONAL,
  KEY_ROLES,
  KEY_DOCUMENT_REPO,
  DEPLOY_COMMIT_ENV,
  PUBLISHED_KEYS,
  SEALER_CASE_READS,
  loadCaseSigner,
  loadReconcileSigner,
  sealingDocument,
  confirmSealingDocument,
  KEY_DOCUMENT_BRANCH_ENV,
  keyDocumentBranch,
  commitOnBranch,
  REVOCATION_MARKER_KIND,
  COMMIT_LIST_PAGES,
  MARKER_CANDIDATES_READ,
  checkRevocationMarker,
  keyFingerprint,
  revocationMarkerPath,
  revocationMarkerFor,
  validateRevocationMarker,
  markersWithoutRevocation,
  roleOf,
  sealPreimage,
  caseChain,
  signCase,
  checkReceipt,
  storableReceipt,
  checkSealedReceipt,
  checkStoredReceipt,
  RECEIPT_UNSIGNED_REASONS,
  sealedRecordReason,
  sealHolds,
  fetchNamedDocument,
  sealCase,
  signatureReason,
  publishedSignatureReason,
  signRecord,
  WITHDRAWN_REGISTRATIONS_NOTE,
  WITHDRAWAL_CLAIM,
  withdrawnRecord,
  refusalReceipt,
  verifyRefusalReceipt,
  refusalReceiptFormReason,
  writeWithdrawnMarker,
  rootBeforeWithdrawal,
  projectedRegistrations,
  damagedWords,
  repairWithdrawn,
  MAX_REFERENCE_ROWS,
  REFUSAL_RECEIPT_KIND,
  REFUSAL_RECEIPT_REASON,
  referenceRow,
  judgeReferenceRow,
  referenceSeqs,
  liveRecords,
  REFERENCE_ROW_READS,
  pinNamespace,
  pinPaths,
  pinChain,
  anchorState,
  anchorCase,
  caseTreeIndex,
  anchorPending,
  caseAnchorSummary,
  keyDocumentEntry,
  checkKeyDocument,
  publishedEntry,
  _internal: {
    // every per-instance cache of the document, the branch, the order and the markers (unit R-I)
    clearDocumentCache: () => {
      namedDocuments.clear();
      documentsByCommit.clear();
      onBranch.clear();
      branchesSeen.clear();
      pinOrder.clear();
      markers.clear();
    },
    clearCommitFiles: () => commitFiles.clear(), COMMIT_LIST_PAGES, fileAtCommit, dailyAnchorOf, caseAtCommit, caseCommitOf, pinPath, nextPin, listedReferences, receiptBinding, pinRecord, isOurPin, rotatingWindow, verifierOf, keyIdOf, activeEntry, strayPin },
};
