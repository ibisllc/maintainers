/**
 * CheckpointRequest verification — holder-signs (open-detail item 1,
 * RESOLVED 2026-05-18 owner).
 *
 * A CheckpointRequest is the first-class signed proof a project's
 * current maintainer authority asks the public Maintainers Checkpoints
 * registry (docs/maintainers-checkpoints-spec-v0.1.md) to witness a
 * publicly available current mandate hash. Its authority source is
 * EXACTLY the CaEndorsement / ReleaseEndorsement v2 model — there is no
 * `policy.json` / quorum here:
 *
 *   A CheckpointRequest is authorised iff `signedBy`-style holder
 *   authority holds: a signature over {@link canonicalCheckpointRequest}
 *   verifies under the holder of the project's mandate current at `now`
 *   ({@link currentAuthority} over a {@link verifyMandateChainFromPin}
 *   chain). The succession quorum governs K→K+1 ONLY — never this
 *   request. §13's literal "satisfy the current mandate approval rule"
 *   wording is superseded by this decision for protocol-wide
 *   consistency (the security-state change being witnessed is already
 *   quorum-signed by construction — it is a new mandate).
 *
 * Unlike a CaEndorsement this envelope carries NO time window of its
 * own: the §11 continuity rule and freshness are enforced by the
 * registry bot over the project's public `.maintainers/` chain, not in
 * this envelope. Authority is still judged at the verifier's clock
 * `now` (the holder of the mandate current then), mirroring the
 * CaEndorsement "authority at NOW" deviation.
 *
 * Total / fail-closed exactly like the sibling verifiers: a chain
 * anchored at an absent/forked pin yields no authority at `now` ⇒
 * `no-authority-at-now`; a malformed field that makes canonicalization
 * throw is CAUGHT and recorded as `signature-invalid`, never an
 * exception.
 */

import { canonicalCheckpointRequest } from "./canonical.js";
import { verify } from "./crypto.js";
import { currentAuthority, type VerifiedChain } from "./verifier.js";
import type { CheckpointRequest } from "./types.js";

export type CheckpointRequestFailReason =
  | "wrong-envelope"
  | "signature-invalid"
  | "no-authority-at-now"
  | "signer-not-the-holder";

export type CheckpointRequestResult =
  | { ok: true }
  | { ok: false; reason: CheckpointRequestFailReason; detail?: string };

/**
 * Verify a single CheckpointRequest against a verified mandate chain at
 * `now`. Holder-signs: valid iff a presented signature over the request's
 * canonical bytes verifies AND the request was signed by the holder of
 * the mandate current at `now`. Never throws on adversarial input.
 */
export function verifyCheckpointRequest(
  req: CheckpointRequest,
  chain: VerifiedChain,
  now: Date,
): CheckpointRequestResult {
  if (req.kind !== "CheckpointRequest" || req.version !== 1) {
    return { ok: false, reason: "wrong-envelope" };
  }
  if (!Array.isArray(req.signatures) || req.signatures.length === 0) {
    return { ok: false, reason: "signature-invalid", detail: "no signatures" };
  }

  let bytes: Uint8Array;
  try {
    bytes = canonicalCheckpointRequest(req);
  } catch (err) {
    return {
      ok: false,
      reason: "signature-invalid",
      detail: `canonical-bytes: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  for (let i = 0; i < req.signatures.length; i++) {
    const s = req.signatures[i]!;
    if (typeof s?.pubkey !== "string" || typeof s?.sig !== "string") {
      return { ok: false, reason: "signature-invalid", detail: `signature ${i} malformed` };
    }
    if (!verify(s.sig, bytes, s.pubkey)) {
      return { ok: false, reason: "signature-invalid", detail: `signature ${i}` };
    }
  }

  const authority = currentAuthority(chain, now);
  if (!authority) return { ok: false, reason: "no-authority-at-now" };

  // Holder-signs: the current mandate's holder must be among the
  // (already cryptographically verified) signers. Extra co-signatures
  // are permitted but not required — the quorum is a succession control,
  // not a per-request one.
  const signerPubkeys = new Set(req.signatures.map((s) => s.pubkey));
  if (!signerPubkeys.has(authority.holder)) {
    return {
      ok: false,
      reason: "signer-not-the-holder",
      detail: `no signature from the current mandate holder ${authority.holder}`,
    };
  }
  return { ok: true };
}
