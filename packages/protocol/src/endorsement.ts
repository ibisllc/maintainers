/**
 * ReleaseEndorsement verification — v2 (LOCKED Phase-2 v2 model).
 *
 * Identical structural + cryptographic checks as v1 endorsement.ts
 * (predecessor chaining, intermediateMerkleRoot re-derivation, signature
 * over canonical bytes, duplicate-id, genesis-vs-non-genesis), with ONE
 * change — the authority source:
 *
 *   v1: the track's signed `TrackPolicy.approvalRule` decided who could
 *       sign an endorsement (a per-endorsement quorum, separate from the
 *       mandate chain).
 *   v2: there is no `policy.json` / `TrackPolicy` (L2 dissolved it). The
 *       only signed authority statement is the mandate itself: its
 *       `holder` IS "the operational authority for the track (signs
 *       ReleaseEndorsement / CaEndorsement)". So a ReleaseEndorsement is
 *       authorised iff `signedBy` equals the holder of the v2 mandate
 *       current at the endorsement's `issuedAt` ({@link
 *       currentAuthority} over a {@link verifyMandateChainFromPin}
 *       chain). The succession quorum (`approvalRule`/`minSuccessors`/
 *       `maxDurationSeconds`) governs K→K+1 ONLY — never per-endorsement.
 *
 * Fail-closed everywhere: a chain anchored at an absent/forked pin has
 * `validMandates: []`, so `currentAuthority` yields null and EVERY
 * endorsement is rejected `no-authority-at-issuance`.
 *
 * The git-history portion (each intermediate commit existing locally and
 * the first-parent walk visiting exactly those commits) is unchanged and
 * still layered on top by the consumer (releaseVerifier.ts).
 */

import { canonicalReleaseEndorsement } from "./canonical.js";
import { intermediateMerkleRoot, verify } from "./crypto.js";
import { currentAuthority, type VerifiedChain } from "./verifier.js";
import type { ReleaseEndorsement } from "./types.js";

/**
 * Why a ReleaseEndorsement was rejected. Re-homed here from the removed
 * v1 endorsement.ts (c4.5e): the result/reason shapes are unchanged so
 * consumers that swapped the v1 call for the v2 one keep the identical
 * downstream types; this module is now their canonical home.
 */
export type EndorsementFailReason =
  | "signature-invalid"
  | "approval-rule-unsatisfied"
  | "signer-not-authorized"
  | "no-authority-at-issuance"
  | "merkle-root-mismatch"
  | "predecessor-mismatch"
  | "genesis-must-have-no-predecessor"
  | "non-genesis-must-have-predecessor"
  | "duplicate-release-id";

export interface VerifiedEndorsements {
  endorsements: ReleaseEndorsement[];
  validEndorsements: ReleaseEndorsement[];
  rejections: { endorsement: ReleaseEndorsement; reason: EndorsementFailReason; detail?: string }[];
}

type SingleResult =
  | { ok: true }
  | { ok: false; reason: EndorsementFailReason; detail?: string };

function verifySingleEndorsement(
  e: ReleaseEndorsement,
  prev: ReleaseEndorsement | undefined,
  releaseChain: VerifiedChain,
  seenIds: Set<string>,
): SingleResult {
  if (seenIds.has(e.releaseId)) {
    return { ok: false, reason: "duplicate-release-id" };
  }

  // Genesis-vs-non-genesis structural check (verbatim from v1).
  if (!prev) {
    if (e.previousReleaseId !== null || e.previousCommitHash !== null) {
      return { ok: false, reason: "genesis-must-have-no-predecessor" };
    }
  } else {
    if (e.previousReleaseId === null || e.previousCommitHash === null) {
      return { ok: false, reason: "non-genesis-must-have-predecessor" };
    }
    if (e.previousReleaseId !== prev.releaseId || e.previousCommitHash !== prev.commitHash) {
      return {
        ok: false,
        reason: "predecessor-mismatch",
        detail: `expected previousReleaseId=${prev.releaseId} previousCommitHash=${prev.commitHash}; got ${e.previousReleaseId}/${e.previousCommitHash}`,
      };
    }
  }

  // Merkle-root re-derivation (adversarial input must never throw out).
  let expectedRoot: string;
  try {
    expectedRoot = intermediateMerkleRoot(e.intermediateCommits);
  } catch (err) {
    return {
      ok: false,
      reason: "merkle-root-mismatch",
      detail: err instanceof Error ? err.message : String(err),
    };
  }
  if (expectedRoot !== e.intermediateMerkleRoot) {
    return {
      ok: false,
      reason: "merkle-root-mismatch",
      detail: `recomputed root ${expectedRoot} does not match field ${e.intermediateMerkleRoot}`,
    };
  }

  // Signature verification over canonical bytes.
  let bytes: Uint8Array;
  try {
    bytes = canonicalReleaseEndorsement(e);
  } catch (err) {
    return {
      ok: false,
      reason: "signature-invalid",
      detail: `canonical-bytes: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  for (let i = 0; i < e.signatures.length; i++) {
    const s = e.signatures[i]!;
    if (!verify(s.sig, bytes, s.pubkey)) {
      return { ok: false, reason: "signature-invalid", detail: `signature ${i} did not verify` };
    }
  }

  // v2 authority: the holder of the mandate current at e.issuedAt.
  const authority = currentAuthority(releaseChain, new Date(Date.parse(e.issuedAt)));
  if (!authority) {
    return { ok: false, reason: "no-authority-at-issuance" };
  }

  const signerPubkeys = new Set(e.signatures.map((s) => s.pubkey));
  if (!signerPubkeys.has(e.signedBy)) {
    return {
      ok: false,
      reason: "signer-not-authorized",
      detail: "signedBy field not present in signatures",
    };
  }
  // Holder-signs: the operational authority signs releases. Extra
  // co-signatures are permitted (already cryptographically verified
  // above) but not required — the quorum is a succession control, not a
  // per-release one.
  if (e.signedBy !== authority.holder) {
    return {
      ok: false,
      reason: "signer-not-authorized",
      detail: `endorsement signedBy ${e.signedBy} but the v2 authority holder at issuedAt is ${authority.holder}`,
    };
  }

  return { ok: true };
}

/**
 * Verify a chain of release endorsements against a v2 release-track
 * chain (the output of {@link verifyMandateChainFromPin} for the release
 * track). Endorsements MUST be in canonical-log order (oldest first).
 * Result shape is identical to v1 {@link verifyChainOfEndorsements} so
 * consumers swap the call with no downstream change.
 */
export function verifyChainOfEndorsements(
  endorsements: ReleaseEndorsement[],
  releaseChain: VerifiedChain,
): VerifiedEndorsements {
  const seenIds = new Set<string>();
  const valid: ReleaseEndorsement[] = [];
  const rejections: VerifiedEndorsements["rejections"] = [];

  for (let i = 0; i < endorsements.length; i++) {
    const e = endorsements[i]!;
    const prev = valid[valid.length - 1];
    const result = verifySingleEndorsement(e, prev, releaseChain, seenIds);
    if (result.ok) {
      valid.push(e);
      seenIds.add(e.releaseId);
    } else {
      rejections.push({ endorsement: e, reason: result.reason, detail: result.detail });
    }
  }

  return { endorsements, validEndorsements: valid, rejections };
}
