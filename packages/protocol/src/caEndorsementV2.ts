/**
 * CaEndorsement verification — v2 (LOCKED Phase-2 v2 model).
 *
 * Same lease semantics as v1 caEndorsement.ts (the §5.1 deviation: judged
 * against the ca-track authority at the VERIFIER'S clock `now`, never at
 * the endorsement's own `issuedAt`; no predecessor chain). The only
 * change is the authority source — exactly as for ReleaseEndorsement v2:
 *
 *   v1: the signed `TrackPolicy.approvalRule` decided the authorised
 *       signer set.
 *   v2: there is no `policy.json` / `TrackPolicy`. The mandate's `holder`
 *       IS the operational authority that signs CaEndorsements. A
 *       CaEndorsement is authorised iff `signedBy` equals the holder of
 *       the v2 ca-track mandate current at `now` ({@link
 *       currentAuthorityV2} over a {@link verifyMandateChainFromPin}
 *       chain). D3 (freshness) is unchanged: the lease window judged at
 *       NOW + the authority judged at NOW together bound a leaked hot key
 *       to one window and kill it by simply withholding the next lease.
 *
 * Fail-closed: a chain anchored at an absent/forked pin yields no
 * authority at now ⇒ every lease is rejected `no-ca-authority-at-now` ⇒
 * `authorizedCaKeysV2` is `[]` ⇒ the #30 chokepoint rejects all CA
 * artifacts. Never a fall-back to a previously-seen key.
 */

import { canonicalCaEndorsement } from "./canonical.js";
import { verify } from "./crypto.js";
import { currentAuthorityV2, type VerifiedChainV2 } from "./verifierV2.js";
import {
  DEFAULT_CLOCK_SKEW_MS,
  type CaEndorsementFailReason,
  type VerifiedCaEndorsements,
} from "./caEndorsement.js";
import type { CaEndorsement, Pubkey } from "./types.js";

type OneResult =
  | { ok: true }
  | { ok: false; reason: CaEndorsementFailReason; detail?: string };

function verifyOneV2(
  e: CaEndorsement,
  caChain: VerifiedChainV2,
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

  // THE deviation, v2: authority at `now` (never at e.issuedAt), taken
  // from the verify-forward-from-pin chain.
  const authority = currentAuthorityV2(caChain, now);
  if (!authority) return { ok: false, reason: "no-ca-authority-at-now" };

  const signerPubkeys = new Set(e.signatures.map((s) => s.pubkey));
  if (!signerPubkeys.has(e.signedBy)) {
    return {
      ok: false,
      reason: "signer-not-authorized",
      detail: "signedBy not present in signatures",
    };
  }
  if (e.signedBy !== authority.holder) {
    return {
      ok: false,
      reason: "signer-not-authorized",
      detail: `signedBy ${e.signedBy} is not the v2 ca authority at now (${authority.holder})`,
    };
  }
  return { ok: true };
}

/**
 * Verify a set of CaEndorsements against a verified v2 ca-track chain at
 * `now`. Order does not matter (no chain); each is judged independently.
 * Result shape identical to v1 {@link verifyCaEndorsements}.
 */
export function verifyCaEndorsementsV2(
  endorsements: CaEndorsement[],
  caChain: VerifiedChainV2,
  now: Date,
  opts: { clockSkewMs?: number } = {},
): VerifiedCaEndorsements {
  const skewMs = opts.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
  const validEndorsements: CaEndorsement[] = [];
  const rejections: VerifiedCaEndorsements["rejections"] = [];

  for (const e of endorsements) {
    const r = verifyOneV2(e, caChain, now, skewMs);
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
 * §9 link-3, v2: the operational keys a consumer may currently accept
 * CA-signed artifacts under. Empty array ⇒ fail closed (reject all).
 * Deduped, insertion order preserved.
 */
export function authorizedCaKeysV2(
  endorsements: CaEndorsement[],
  caChain: VerifiedChainV2,
  now: Date,
  opts: { clockSkewMs?: number } = {},
): Pubkey[] {
  const { validEndorsements } = verifyCaEndorsementsV2(endorsements, caChain, now, opts);
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
