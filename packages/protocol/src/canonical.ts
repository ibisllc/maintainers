/**
 * Canonical-bytes derivation for maintainers envelopes.
 *
 * Convention: `maintainers/<envelope-kind>/v1|<field1>|<field2>|...`
 *
 * Every field is validated to not contain `|` (0x7C), the separator, or
 * any C0 control byte (0x00-0x1F) or DEL (0x7F). This forecloses the
 * canonicalization-ambiguity attack class (H1 in the Flagship audit).
 *
 * Each envelope kind has its own canonical*() function; we never feed
 * raw envelopes through a generic serializer.
 */

import { sha256Hex } from "./crypto.js";
import type {
  Mandate,
  KeyFile,
  KeyRedirect,
  EmailRotation,
  KeyIntroductionRequest,
  ReleaseEndorsement,
  CaEndorsement,
  CheckpointRequest,
  Pubkey,
} from "./types.js";

const SEP = "|";
const TAG_PREFIX = "maintainers";
const VERSION = "v1";

export class CanonicalBytesError extends Error {
  constructor(
    public readonly field: string,
    public readonly reason: "contains-separator" | "contains-control-char" | "empty-required" | "wrong-shape",
    message: string,
  ) {
    super(message);
    this.name = "CanonicalBytesError";
  }
}

/**
 * Validate that a string field is safe to embed in canonical-bytes.
 * Rejects `|`, all C0 control chars, and DEL.
 */
function validateField(name: string, value: string): void {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c === 0x7c) {
      throw new CanonicalBytesError(
        name,
        "contains-separator",
        `field "${name}" contains the canonical-bytes separator '|' at index ${i}`,
      );
    }
    if (c <= 0x1f || c === 0x7f) {
      throw new CanonicalBytesError(
        name,
        "contains-control-char",
        `field "${name}" contains control character 0x${c.toString(16).padStart(2, "0")} at index ${i}`,
      );
    }
  }
}

function joinTagged(kind: string, parts: string[]): Uint8Array {
  const tag = `${TAG_PREFIX}/${kind}/${VERSION}`;
  const all = [tag, ...parts];
  for (let i = 1; i < all.length; i++) {
    // i=0 is the tag; tags are controlled by us, no validation needed
    const p = all[i];
    if (p === undefined) {
      throw new CanonicalBytesError(
        `position ${i}`,
        "wrong-shape",
        `canonical-bytes part at position ${i} is undefined`,
      );
    }
  }
  return new TextEncoder().encode(all.join(SEP));
}

/**
 * KeyFile canonical bytes.
 * Order: pubkey | displayName | currentEmail | introductionMandate | metadata-fingerprint
 *
 * Email history is not in canonical bytes — it's an append-only log
 * maintained out-of-band; each EmailRotation envelope is independently
 * signed.
 */
export function canonicalKeyFile(k: Omit<KeyFile, "signature">): Uint8Array {
  validateHex("pubkey", k.pubkey, 64);
  validateField("displayName", k.displayName);
  validateField("currentEmail", k.currentEmail);
  validateField("introductionMandate", k.introductionMandate);
  const metaFingerprint = canonicalMetaFingerprint(k.metadata);
  return joinTagged("keyfile", [
    k.pubkey,
    k.displayName,
    k.currentEmail,
    k.introductionMandate,
    metaFingerprint,
  ]);
}

function canonicalMetaFingerprint(meta: KeyFile["metadata"]): string {
  const photo = meta.photo ?? "";
  const github = meta.github ?? "";
  const role = meta.role ?? "";
  validateField("metadata.photo", photo);
  validateField("metadata.github", github);
  validateField("metadata.role", role);
  return [photo, github, role].join(",");
}

/**
 * KeyRedirect canonical bytes.
 * Order: fromEmail | renamedTo | renamedAt | pubkey
 */
export function canonicalKeyRedirect(r: Omit<KeyRedirect, "signature">): Uint8Array {
  validateField("fromEmail", r.fromEmail);
  validateField("renamedTo", r.renamedTo);
  validateField("renamedAt", r.renamedAt);
  validateHex("pubkey", r.pubkey, 64);
  return joinTagged("keyredirect", [r.fromEmail, r.renamedTo, r.renamedAt, r.pubkey]);
}

/**
 * EmailRotation canonical bytes.
 * Order: pubkey | fromEmail | toEmail | rotatedAt
 */
export function canonicalEmailRotation(r: Omit<EmailRotation, "signature">): Uint8Array {
  validateHex("pubkey", r.pubkey, 64);
  validateField("fromEmail", r.fromEmail);
  validateField("toEmail", r.toEmail);
  validateField("rotatedAt", r.rotatedAt);
  return joinTagged("emailrotation", [r.pubkey, r.fromEmail, r.toEmail, r.rotatedAt]);
}

/**
 * KeyIntroductionRequest canonical bytes.
 * Order: pubkey | displayName | currentEmail | requestedAt | metadata-fingerprint
 */
export function canonicalKeyIntroductionRequest(
  r: Omit<KeyIntroductionRequest, "signature">,
): Uint8Array {
  validateHex("pubkey", r.pubkey, 64);
  validateField("displayName", r.displayName);
  validateField("currentEmail", r.currentEmail);
  validateField("requestedAt", r.requestedAt);
  const metaFingerprint = canonicalMetaFingerprint(r.metadata);
  return joinTagged("keyintro", [
    r.pubkey,
    r.displayName,
    r.currentEmail,
    r.requestedAt,
    metaFingerprint,
  ]);
}

/**
 * ReleaseEndorsement canonical bytes.
 * Order:
 *   releaseId | semverTag | commitHash | previousReleaseId | previousCommitHash
 *   | intermediateMerkleRoot | endorsedNotes | issuedAt | signedBy
 *
 * intermediateCommits are NOT directly in canonical bytes; their root
 * is, and the verifier re-derives the root from the field to confirm.
 * This keeps canonical bytes compact regardless of commit-count.
 */
export function canonicalReleaseEndorsement(
  e: Omit<ReleaseEndorsement, "signatures">,
): Uint8Array {
  validateField("releaseId", e.releaseId);
  validateField("semverTag", e.semverTag);
  validateHex("commitHash", e.commitHash, 40);
  validateField("previousReleaseId", e.previousReleaseId ?? "");
  validateHexOrEmpty("previousCommitHash", e.previousCommitHash, 40);
  validateHex("intermediateMerkleRoot", e.intermediateMerkleRoot, 64);
  validateField("endorsedNotes", e.endorsedNotes ?? "");
  validateField("issuedAt", e.issuedAt);
  validateHex("signedBy", e.signedBy, 64);
  return joinTagged("release", [
    e.releaseId,
    e.semverTag,
    e.commitHash,
    e.previousReleaseId ?? "",
    e.previousCommitHash ?? "",
    e.intermediateMerkleRoot,
    e.endorsedNotes ?? "",
    e.issuedAt,
    e.signedBy,
  ]);
}

/**
 * CaEndorsement canonical bytes.
 * Order:
 *   endorsementId | track | caPubkey | scope | notBefore | notAfter
 *   | issuedAt | signedBy
 *
 * No predecessor / chain fields by design — a CaEndorsement is an
 * independent short lease, not append-only history (§5.1).
 */
export function canonicalCaEndorsement(
  e: Omit<CaEndorsement, "signatures">,
): Uint8Array {
  validateField("endorsementId", e.endorsementId);
  validateField("track", e.track);
  validateHex("caPubkey", e.caPubkey, 64);
  validateField("scope", e.scope);
  validateField("notBefore", e.notBefore);
  validateField("notAfter", e.notAfter);
  validateField("issuedAt", e.issuedAt);
  validateHex("signedBy", e.signedBy, 64);
  return joinTagged("ca-endorsement", [
    e.endorsementId,
    e.track,
    e.caPubkey,
    e.scope,
    e.notBefore,
    e.notAfter,
    e.issuedAt,
    e.signedBy,
  ]);
}

/**
 * CheckpointRequest canonical bytes.
 * Tag: maintainers/checkpoint-request/v1
 * Order (spec docs/maintainers-checkpoints-spec-v0.1.md open-detail
 *   item 2): canonicalRepo | maintainersPath | currentMandateHash
 *   | sourceCommit
 *
 * No predecessor / chain fields by design — like a CaEndorsement it is
 * an independent statement; the §11 continuity rule is enforced by the
 * registry bot over the project's public `.maintainers/` chain, not in
 * these bytes. Authorisation is holder-signs (open-detail item 1).
 */
export function canonicalCheckpointRequest(
  r: Omit<CheckpointRequest, "signatures">,
): Uint8Array {
  validateField("canonicalRepo", r.canonicalRepo);
  if (r.canonicalRepo.length === 0) {
    throw new CanonicalBytesError(
      "canonicalRepo",
      "empty-required",
      'field "canonicalRepo" must not be empty',
    );
  }
  validateField("maintainersPath", r.maintainersPath);
  if (r.maintainersPath.length === 0) {
    throw new CanonicalBytesError(
      "maintainersPath",
      "empty-required",
      'field "maintainersPath" must not be empty',
    );
  }
  validateSha256Prefixed("currentMandateHash", r.currentMandateHash);
  validateField("sourceCommit", r.sourceCommit);
  if (r.sourceCommit.length === 0) {
    throw new CanonicalBytesError(
      "sourceCommit",
      "empty-required",
      'field "sourceCommit" must not be empty',
    );
  }
  return joinTagged("checkpoint-request", [
    r.canonicalRepo,
    r.maintainersPath,
    r.currentMandateHash,
    r.sourceCommit,
  ]);
}

/**
 * `sha256:<hex>` format check — the spec §7.1 / §9 mandate-hash form.
 * Requires the literal `sha256:` prefix then exactly 64 lower-case hex
 * digits (the {@link sha256Hex} / {@link mandatePinHash} output width),
 * consistent with {@link validateHex}'s lower-case-hex discipline. No
 * new hash format is invented — this is exactly the pin hash, prefixed.
 */
export function validateSha256Prefixed(name: string, value: string): void {
  if (typeof value !== "string") {
    throw new CanonicalBytesError(name, "wrong-shape", `field "${name}" must be a string`);
  }
  const prefix = "sha256:";
  if (!value.startsWith(prefix)) {
    throw new CanonicalBytesError(
      name,
      "wrong-shape",
      `field "${name}" must be a "sha256:<hex>" string`,
    );
  }
  validateHex(name, value.slice(prefix.length), 64);
}

/** Hex format check: ensures the string is exactly `length` lower-case hex digits. */
export function validateHex(name: string, value: Pubkey, length: number): void {
  if (typeof value !== "string") {
    throw new CanonicalBytesError(
      name,
      "wrong-shape",
      `field "${name}" must be a string`,
    );
  }
  if (value.length !== length) {
    throw new CanonicalBytesError(
      name,
      "wrong-shape",
      `field "${name}" must be exactly ${length} hex characters; got ${value.length}`,
    );
  }
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    const ok = (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66);
    if (!ok) {
      throw new CanonicalBytesError(
        name,
        "wrong-shape",
        `field "${name}" must be lower-case hex; offending char at index ${i}`,
      );
    }
  }
}

function validateHexOrEmpty(name: string, value: string | null, length: number): void {
  if (value === null || value === "") return;
  validateHex(name, value, length);
}

// ---------------------------------------------------------------------------
// Mandate canonical bytes.  Tag: maintainers/mandate/v1
//
// Field order (fixed; one slot per logical field — no nested
// fingerprints, so a missing `project` is just four empty slots and the
// layout stays a constant length regardless of optionality):
//
//   mandateId | track | holder | issuedAt | expiresAt
//   | successors(,) | approvalThreshold | minSuccessors
//   | maxDurationSeconds | defaultDurationSeconds
//   | projectName | projectContact | projectHomepage | projectTracks(,)
//   | signedBy
//
// `approvalRule.kind` is the constant "threshold" so only the integer
// `threshold` is in the bytes. Numbers are serialized via the
// non-negative-integer encoder so the canonical bytes are byte-stable
// across languages (the v2 spec is consumed by Swift/Kotlin/fetch()
// reimplementations against the published conformance vectors).
// ---------------------------------------------------------------------------

/** Reject `,` in addition to `|`/control — for fields embedded in a `,`-joined slot. */
function validateNoComma(name: string, value: string): void {
  validateField(name, value);
  const idx = value.indexOf(",");
  if (idx !== -1) {
    throw new CanonicalBytesError(
      name,
      "wrong-shape",
      `field "${name}" must not contain ',' (it is embedded in a comma-joined slot) at index ${idx}`,
    );
  }
}

/** Deterministic encoding of a non-negative safe integer. */
function canonicalUint(name: string, n: number): string {
  if (typeof n !== "number" || !Number.isInteger(n) || n < 0 || n > Number.MAX_SAFE_INTEGER) {
    throw new CanonicalBytesError(
      name,
      "wrong-shape",
      `field "${name}" must be a non-negative safe integer; got ${String(n)}`,
    );
  }
  return String(n);
}

export function canonicalMandate(m: Omit<Mandate, "signatures">): Uint8Array {
  if (m.kind !== "Mandate" || m.version !== 1) {
    throw new CanonicalBytesError("kind/version", "wrong-shape", "not a Mandate envelope");
  }
  validateField("mandateId", m.mandateId);
  validateField("track", m.track);
  validateHex("holder", m.holder, 64);
  validateField("issuedAt", m.issuedAt);
  validateField("expiresAt", m.expiresAt);
  for (const s of m.successors) validateHex("successor", s, 64);
  if (m.approvalRule.kind !== "threshold") {
    throw new CanonicalBytesError("approvalRule.kind", "wrong-shape", "approvalRule.kind must be \"threshold\"");
  }
  const threshold = canonicalUint("approvalRule.threshold", m.approvalRule.threshold);
  const minSucc = canonicalUint("minSuccessors", m.minSuccessors);
  const maxDur = canonicalUint("maxDurationSeconds", m.maxDurationSeconds);
  const defDur = canonicalUint("defaultDurationSeconds", m.defaultDurationSeconds);
  const p = m.project;
  const projName = p?.name ?? "";
  const projContact = p?.contact ?? "";
  const projHome = p?.homepage ?? "";
  const projTracks = p?.tracks ?? [];
  validateField("project.name", projName);
  validateField("project.contact", projContact);
  validateField("project.homepage", projHome);
  for (const t of projTracks) validateNoComma("project.track", t);
  validateHex("signedBy", m.signedBy, 64);
  return joinTaggedMandate("mandate", [
    m.mandateId,
    m.track,
    m.holder,
    m.issuedAt,
    m.expiresAt,
    m.successors.join(","),
    threshold,
    minSucc,
    maxDur,
    defDur,
    projName,
    projContact,
    projHome,
    projTracks.join(","),
    m.signedBy,
  ]);
}

/** Like {@link joinTagged} but stamps the `v1` version segment. */
function joinTaggedMandate(kind: string, parts: string[]): Uint8Array {
  const tag = `${TAG_PREFIX}/${kind}/v1`;
  const all = [tag, ...parts];
  for (let i = 1; i < all.length; i++) {
    const part = all[i];
    if (part === undefined) {
      throw new CanonicalBytesError(`position ${i}`, "wrong-shape", `canonical-bytes part at position ${i} is undefined`);
    }
  }
  return new TextEncoder().encode(all.join(SEP));
}

/**
 * The pin: SHA-256 (lower-hex) of a mandate's canonical bytes — the
 * exact bytes that are signed. This is the value baked per surface
 * (#30 generalised). It commits to the mandate's content + inline
 * policy (NOT its signatures, which the forward-walk re-verifies
 * anyway); a mandate whose bytes hash to a baked pin is therefore
 * bit-identical to the pinned one (sha256 collision-resistance) — that
 * is what makes L1 "the pin IS the floor" sound.
 */
export function mandatePinHash(m: Omit<Mandate, "signatures">): string {
  return sha256Hex(canonicalMandate(m));
}
