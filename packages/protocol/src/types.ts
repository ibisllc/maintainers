/**
 * Maintainers protocol v1 — type definitions.
 *
 * All envelopes are signed by Ed25519. Pubkeys and signatures are
 * hex-encoded strings; canonical-bytes derivations validate that no
 * field contains the separator character `|` or any control byte.
 */

export type Hex = string;
export type Iso8601 = string;
export type Uuid = string;
export type Pubkey = Hex;
export type Signature = Hex;

export interface SignatureEntry {
  pubkey: Pubkey;
  sig: Signature;
}

export interface EmailHistoryEntry {
  email: string;
  from: Iso8601;
  to: Iso8601 | null;
}

export interface KeyMetadata {
  photo?: string | null;
  github?: string | null;
  role?: string | null;
}

export interface KeyFile {
  kind: "KeyFile";
  version: 1;
  pubkey: Pubkey;
  displayName: string;
  currentEmail: string;
  emailHistory: EmailHistoryEntry[];
  metadata: KeyMetadata;
  introductionMandate: Uuid;
  signature: Signature;
}

export interface KeyRedirect {
  kind: "KeyRedirect";
  version: 1;
  fromEmail: string;
  renamedTo: string;
  renamedAt: Iso8601;
  pubkey: Pubkey;
  signature: Signature;
}

export interface EmailRotation {
  kind: "EmailRotation";
  version: 1;
  pubkey: Pubkey;
  fromEmail: string;
  toEmail: string;
  rotatedAt: Iso8601;
  signature: Signature;
}

export interface KeyIntroductionRequest {
  kind: "KeyIntroductionRequest";
  version: 1;
  pubkey: Pubkey;
  displayName: string;
  currentEmail: string;
  metadata: KeyMetadata;
  requestedAt: Iso8601;
  signature: Signature;
}

export interface ReleaseEndorsement {
  kind: "ReleaseEndorsement";
  version: 1;
  releaseId: Uuid;
  semverTag: string;
  commitHash: Hex;
  previousReleaseId: Uuid | null;
  previousCommitHash: Hex | null;
  intermediateCommits: Hex[];
  intermediateMerkleRoot: Hex;
  endorsedNotes: string | null;
  issuedAt: Iso8601;
  signedBy: Pubkey;
  signatures: SignatureEntry[];
}

/**
 * CaEndorsement — a present-tense, liveness-sensitive lease authorizing
 * a hot operational key (e.g. a server CA) for a bounded window.
 *
 * Deliberately NOT a ReleaseEndorsement: it carries no predecessor
 * chain and is judged against the ca-track authority at the verifier's
 * own clock (NOW), never at an attacker-controllable `issuedAt`. A
 * leaked operational key is bounded to one lease window and killed by
 * simply withholding the next endorsement — no revocation list. See
 * docs/spec/v1.md §2.6 / §3.7 / §5.1.
 */
export interface CaEndorsement {
  kind: "CaEndorsement";
  version: 1;
  endorsementId: Uuid;
  /** the ca-class track this is scoped to (e.g. "ca"). */
  track: string;
  /** the hot operational key being authorized. */
  caPubkey: Pubkey;
  /** free-form consumer scope, e.g. "flagship/directory-attestation". */
  scope: string;
  /** lease window start (inclusive). */
  notBefore: Iso8601;
  /** lease window end (exclusive) — the cadence knob. */
  notAfter: Iso8601;
  issuedAt: Iso8601;
  /** must be the ca-track authority at NOW (not at issuedAt). */
  signedBy: Pubkey;
  signatures: SignatureEntry[];
}

// ---------------------------------------------------------------------------
// Mandate v2 — LOCKED Phase-2 v2 model (docs/spec/v1.md; flagship
// docs/v1-launch-program.md "Phase-2 DESIGN DECISION — LOCKED v2").
//
// Three changes vs v1, all in one envelope:
//   L1  the pinned mandate is an INDEPENDENT trust anchor; consumers
//       verify FORWARD from whatever mandate's canonical hash they baked.
//       Genesis is merely "the first pin"; multiple pins coexist forever.
//   L2  the succession policy lives INSIDE the mandate (no policy.json,
//       no SignedPolicy): `approvalRule` + `successors` + `minSuccessors`
//       + `maxDurationSeconds` govern the NEXT mandate, signed into THIS
//       one.
//   L3  ONE uniform succession rule, no privileged self-renewal: K+1 is
//       valid iff its signatures satisfy K's `approvalRule` over K's
//       `successors` set AND K+1 obeys K's `minSuccessors`/`maxDuration`.
//       Renewal = rotation = takeover = repolicy = that one mechanism.
// ---------------------------------------------------------------------------

/**
 * v2 approval rule: a threshold over the *predecessor's* `successors`
 * set. `successors` IS the named pubkey set; `threshold` is the N. The
 * v1 `of: "anyAuthorizedSigner" | Pubkey[]` ambiguity is gone — the rule
 * is fully self-contained inside the signed mandate.
 */
export interface ApprovalRule {
  kind: "threshold";
  /** distinct `successors` signatures required to authorise the NEXT mandate. */
  threshold: number;
}

/** Project-level metadata, present ONLY on a from-scratch (root) mandate. */
export interface MandateProject {
  name: string;
  contact?: string;
  homepage?: string;
  /** the project's declared track list (informational; replaces RootPolicy). */
  tracks?: string[];
}

export interface Mandate {
  kind: "Mandate";
  version: 1;
  mandateId: Uuid;
  track: string;
  /** operational authority for the track (signs ReleaseEndorsement / CaEndorsement). */
  holder: Pubkey;
  issuedAt: Iso8601;
  expiresAt: Iso8601;
  /** the authorised signer set for the NEXT mandate (K+1). */
  successors: Pubkey[];
  /** how many distinct `successors` signatures K+1 needs. */
  approvalRule: ApprovalRule;
  /** K+1.successors.length MUST be >= this (anti-rubber-hose floor). */
  minSuccessors: number;
  /** (K+1.expiresAt - K+1.issuedAt) seconds MUST be <= this. */
  maxDurationSeconds: number;
  /** the tool's default K+1 window in seconds (signed, NOT verifier-load-bearing). */
  defaultDurationSeconds: number;
  /** present only on the from-scratch (root) mandate. */
  project?: MandateProject;
  signedBy: Pubkey;
  signatures: SignatureEntry[];
}

// `Envelope` is the generic storage-adapter union (the §6 StorageAdapter
// passes the parsed envelope alongside the raw bytes so an adapter can
// enforce per-envelope policy). It is NOT the trust path — that is
// pin-anchored and self-contained (canonicalMandate / signMandate /
// verifyMandateChainFromPin). With v1 removed (c4.5e) the mandate member
// is `Mandate`, the only mandate envelope that now exists.
export type Envelope =
  | Mandate
  | KeyFile
  | KeyRedirect
  | EmailRotation
  | KeyIntroductionRequest
  | ReleaseEndorsement
  | CaEndorsement;

/** Derived from observation; not signed. */
export interface TakeoverAlarm {
  kind: "TakeoverAlarm";
  project: string;
  track: string;
  previousMandate: Uuid;
  newMandate: Uuid;
  previousHolder: { displayName: string; email: string; pubkey: Pubkey };
  newHolder: { displayName: string; email: string; pubkey: Pubkey };
  detectedAt: Iso8601;
}
