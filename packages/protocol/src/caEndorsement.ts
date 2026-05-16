/**
 * CaEndorsement verification — implements §5.1 of docs/spec/v1.md.
 *
 * The one deliberate deviation from ReleaseEndorsement verification:
 * a CaEndorsement is judged against the ca-track authority at the
 * VERIFIER'S clock (`now`), never at the endorsement's own `issuedAt`.
 * It is an independent short lease, not append-only history — there is
 * no predecessor chain. Consequences:
 *
 *   - A leaked hot key is bounded to one lease window; withholding the
 *     next endorsement kills it globally with no revocation list.
 *   - Backdating `issuedAt` is defeated: the signer must be the
 *     ca-track authority *now*, so a stale/rotated maintainer cannot
 *     resurrect a key by re-dating an endorsement.
 *   - The CA never signs its own authority; only the cold ca-track
 *     maintainer does.
 *
 * `authorizedCaKeys(now)` is §9 link-3: the set of operational keys a
 * consumer may currently accept artifacts under. An empty set means
 * "reject ALL CA artifacts" (fail closed) — callers MUST treat it so.
 */

import { canonicalCaEndorsement } from "./canonical.js";
import { verify } from "./crypto.js";
import { currentAuthority, type VerifiedTrack } from "./verifier.js";
import type { ApprovalRule, CaEndorsement, Pubkey } from "./types.js";

export type CaEndorsementFailReason =
  | "wrong-envelope"
  | "lease-window-malformed"
  | "lease-not-yet"
  | "lease-expired"
  | "signature-invalid"
  | "no-ca-authority-at-now"
  | "signer-not-authorized"
  | "approval-rule-unsatisfied";

export interface VerifiedCaEndorsements {
  endorsements: CaEndorsement[];
  validEndorsements: CaEndorsement[];
  rejections: {
    endorsement: CaEndorsement;
    reason: CaEndorsementFailReason;
    detail?: string;
  }[];
  /**
   * The single operational key authorized *now*: the caPubkey of the
   * most recently issued still-in-window valid endorsement (§5.1 step
   * 4). `null` ⇒ no live lease ⇒ fail closed.
   */
  currentCaPubkey: Pubkey | null;
}

/** ±5 min window-edge tolerance — spec §7 default; override for tests. */
export const DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1000;

type OneResult =
  | { ok: true }
  | { ok: false; reason: CaEndorsementFailReason; detail?: string };

function verifyOne(
  e: CaEndorsement,
  caTrack: VerifiedTrack,
  approvalRule: ApprovalRule,
  now: Date,
  skewMs: number,
): OneResult {
  if (e.kind !== "CaEndorsement" || e.version !== 1) {
    return { ok: false, reason: "wrong-envelope" };
  }

  const nb = Date.parse(e.notBefore);
  const na = Date.parse(e.notAfter);
  if (!isFinite(nb) || !isFinite(na) || na <= nb) {
    return { ok: false, reason: "lease-window-malformed" };
  }
  const nowMs = now.getTime();
  if (nowMs < nb - skewMs) return { ok: false, reason: "lease-not-yet" };
  if (nowMs >= na + skewMs) return { ok: false, reason: "lease-expired" };

  // Canonical bytes + every signature. A malformed field throws inside
  // canonicalCaEndorsement; an adversarial envelope must never crash
  // the verifier, so map that to a signature rejection.
  let bytes: Uint8Array;
  try {
    bytes = canonicalCaEndorsement(e);
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
      return { ok: false, reason: "signature-invalid", detail: `signature ${i}` };
    }
  }

  // THE deviation: authority at `now`, not at e.issuedAt.
  const authority = currentAuthority(caTrack, now);
  if (!authority) return { ok: false, reason: "no-ca-authority-at-now" };

  const signerPubkeys = new Set(e.signatures.map((s) => s.pubkey));
  if (!signerPubkeys.has(e.signedBy)) {
    return {
      ok: false,
      reason: "signer-not-authorized",
      detail: "signedBy not present in signatures",
    };
  }
  if (approvalRule.kind === "threshold" && approvalRule.of === "anyAuthorizedSigner") {
    if (e.signedBy !== authority.holder) {
      return {
        ok: false,
        reason: "signer-not-authorized",
        detail: `signedBy ${e.signedBy} is not the ca authority at now (${authority.holder})`,
      };
    }
    if (signerPubkeys.size < approvalRule.threshold) {
      return { ok: false, reason: "approval-rule-unsatisfied" };
    }
  } else if (approvalRule.kind === "threshold") {
    const required = new Set(approvalRule.of);
    let matches = 0;
    for (const pk of signerPubkeys) if (required.has(pk)) matches++;
    if (matches < approvalRule.threshold) {
      return { ok: false, reason: "approval-rule-unsatisfied" };
    }
  }
  return { ok: true };
}

/**
 * Verify a set of CaEndorsements against a verified ca-track at `now`.
 * Order does not matter (no chain); each is judged independently.
 */
export function verifyCaEndorsements(
  endorsements: CaEndorsement[],
  caTrack: VerifiedTrack,
  approvalRule: ApprovalRule,
  now: Date,
  opts: { clockSkewMs?: number } = {},
): VerifiedCaEndorsements {
  const skewMs = opts.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
  const validEndorsements: CaEndorsement[] = [];
  const rejections: VerifiedCaEndorsements["rejections"] = [];

  for (const e of endorsements) {
    const r = verifyOne(e, caTrack, approvalRule, now, skewMs);
    if (r.ok) validEndorsements.push(e);
    else rejections.push({ endorsement: e, reason: r.reason, detail: r.detail });
  }

  let current: CaEndorsement | null = null;
  for (const e of validEndorsements) {
    if (!current || Date.parse(e.issuedAt) > Date.parse(current.issuedAt)) {
      current = e;
    }
  }

  return {
    endorsements,
    validEndorsements,
    rejections,
    currentCaPubkey: current ? current.caPubkey : null,
  };
}

/**
 * §9 link-3: the operational keys a consumer may currently accept
 * CA-signed artifacts under. Empty array ⇒ fail closed (reject all).
 * Deduped, insertion order preserved.
 */
export function authorizedCaKeys(
  endorsements: CaEndorsement[],
  caTrack: VerifiedTrack,
  approvalRule: ApprovalRule,
  now: Date,
  opts: { clockSkewMs?: number } = {},
): Pubkey[] {
  const { validEndorsements } = verifyCaEndorsements(
    endorsements,
    caTrack,
    approvalRule,
    now,
    opts,
  );
  const seen = new Set<Pubkey>();
  const out: Pubkey[] = [];
  for (const e of validEndorsements) {
    if (!seen.has(e.caPubkey)) {
      seen.add(e.caPubkey);
      out.push(e.caPubkey);
    }
  }
  return out;
}
