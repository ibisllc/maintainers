/**
 * Verifier algorithm for the maintainers protocol — v2 (LOCKED
 * Phase-2 v2 model). Implements §4 of docs/spec/v2.md.
 *
 * The whole model in one sentence: "pin a mandate, verify FORWARD; the
 * mandate carries its own succession rule; there is no privileged
 * self-renewal."
 *
 *   L1  A pinned mandate is an INDEPENDENT trust anchor. The consumer
 *       bakes ONE mandate's canonical hash ({@link mandatePinHash}) and
 *       walks forward from it. Nothing requires walking back to
 *       "genesis"; multiple pins coexist forever. No baked pin ⇒ reject
 *       everything (the #30 invariant, generalised).
 *   L2  Succession policy lives INSIDE the mandate: K embeds the rule
 *       (approvalRule + successors + minSuccessors + maxDurationSeconds)
 *       that governs K+1. There is no policy.json / SignedPolicy.
 *   L3  ONE uniform rule, no self-renewal. K+1 is valid iff every
 *       signature is from K.successors, the distinct count meets
 *       K.approvalRule.threshold, K+1.successors.length ≥
 *       K.minSuccessors, and K+1's window ≤ K.maxDurationSeconds. There
 *       is NO holder-in-window vs successor-after-expiry split — that
 *       branch (and the entire self-renewal path) is gone.
 *
 * This function is TOTAL: it never throws on adversarial input. A field
 * that fails canonicalization, an unparseable timestamp, a malformed
 * number — every such case is recorded as a rejection (or a rootError),
 * never propagated. Fail-closed is a return value, not an exception.
 */

import { canonicalMandateV2, mandatePinHash } from "./canonical.js";
import { verify } from "./crypto.js";
import type { Iso8601, MandateV2, Pubkey } from "./types.js";

export type V2FailReason =
  | "envelope-shape-invalid"
  | "duplicate-mandate-id"
  | "wrong-track"
  | "expires-before-issuance"
  | "issued-before-predecessor"
  | "signature-invalid"
  | "signed-by-not-in-signatures"
  | "signer-not-in-successor-set"
  | "approval-threshold-unmet"
  | "under-min-successors"
  | "over-max-duration";

/** Why no forward chain could be anchored at all (the L1 fail-closed cases). */
export type V2RootFailReason =
  | "no-pin" // nothing baked — fail closed (#30 generalised)
  | "pin-not-in-log" // no mandate's canonical hash equals the baked pin (incl. a forked/tampered pin)
  | "root-shape-invalid"
  | "root-expires-before-issuance"
  | "root-signature-invalid"
  | "root-not-self-signed"; // signedBy ∉ signatures

export interface V2Rejection {
  mandate: MandateV2;
  reason: V2FailReason;
  detail?: string;
}

export interface VerifiedChainV2 {
  /** the baked pin this chain was anchored at (echoed for the caller). */
  pin: string;
  /** the matched root mandate, or null if no chain could be anchored. */
  root: MandateV2 | null;
  /** present iff `root` is null — why L1 fail-closed. */
  rootError?: V2RootFailReason;
  /** `[root, ...accepted forward suffix]`, oldest first. Empty when fail-closed. */
  validMandates: MandateV2[];
  /** rejected forward mandates (recorded; they never become a predecessor). */
  rejections: V2Rejection[];
}

function isV2Shape(m: unknown): m is MandateV2 {
  if (typeof m !== "object" || m === null) return false;
  const x = m as Record<string, unknown>;
  return (
    x.kind === "Mandate" &&
    x.version === 2 &&
    typeof x.mandateId === "string" &&
    typeof x.track === "string" &&
    typeof x.holder === "string" &&
    typeof x.issuedAt === "string" &&
    typeof x.expiresAt === "string" &&
    Array.isArray(x.successors) &&
    typeof x.approvalRule === "object" &&
    x.approvalRule !== null &&
    typeof x.minSuccessors === "number" &&
    typeof x.maxDurationSeconds === "number" &&
    typeof x.signedBy === "string" &&
    Array.isArray(x.signatures)
  );
}

/** Canonical bytes or null (never throws — adversarial fields ⇒ reject). */
function canonicalOrNull(m: MandateV2): Uint8Array | null {
  try {
    return canonicalMandateV2(m);
  } catch {
    return null;
  }
}

function pinHashOrNull(m: MandateV2): string | null {
  try {
    return mandatePinHash(m);
  } catch {
    return null;
  }
}

function windowMs(issuedAt: Iso8601, expiresAt: Iso8601): number | null {
  const i = Date.parse(issuedAt);
  const e = Date.parse(expiresAt);
  if (!isFinite(i) || !isFinite(e)) return null;
  return e - i;
}

/** Every signature verifies over the mandate's canonical bytes? */
function allSignaturesValid(m: MandateV2): boolean {
  const bytes = canonicalOrNull(m);
  if (bytes === null) return false;
  if (m.signatures.length === 0) return false;
  for (const s of m.signatures) {
    if (typeof s?.pubkey !== "string" || typeof s?.sig !== "string") return false;
    if (!verify(s.sig, bytes, s.pubkey)) return false;
  }
  return true;
}

/**
 * Verify a single forward step K → K+1 against the predecessor's
 * embedded policy (the L3 ONE rule). Returns the fail reason or null.
 */
function verifyForwardStep(pred: MandateV2, m: MandateV2): V2FailReason | null {
  if (!isV2Shape(m)) return "envelope-shape-invalid";
  if (m.track !== pred.track) return "wrong-track";
  const w = windowMs(m.issuedAt, m.expiresAt);
  if (w === null) return "envelope-shape-invalid";
  if (w <= 0) return "expires-before-issuance";
  if (Date.parse(m.issuedAt) < Date.parse(pred.issuedAt)) return "issued-before-predecessor";
  if (!allSignaturesValid(m)) return "signature-invalid";

  const signerPubkeys = m.signatures.map((s) => s.pubkey);
  if (!signerPubkeys.includes(m.signedBy)) return "signed-by-not-in-signatures";

  const successorSet = new Set<Pubkey>(pred.successors);
  for (const pk of signerPubkeys) {
    if (!successorSet.has(pk)) return "signer-not-in-successor-set";
  }
  const distinctAuthorised = new Set<Pubkey>();
  for (const pk of signerPubkeys) {
    if (successorSet.has(pk)) distinctAuthorised.add(pk);
  }
  if (
    pred.approvalRule.kind !== "threshold" ||
    !Number.isInteger(pred.approvalRule.threshold) ||
    pred.approvalRule.threshold < 1 ||
    distinctAuthorised.size < pred.approvalRule.threshold
  ) {
    return "approval-threshold-unmet";
  }
  if (m.successors.length < pred.minSuccessors) return "under-min-successors";
  if (
    !Number.isInteger(pred.maxDurationSeconds) ||
    pred.maxDurationSeconds < 0 ||
    w > pred.maxDurationSeconds * 1000
  ) {
    return "over-max-duration";
  }
  return null;
}

/**
 * Verify a track's mandate log FORWARD from a baked pin.
 *
 * `pinnedHash` is the {@link mandatePinHash} the consumer compiled into
 * its signed build (#30 generalised). `mandates` is the track's log in
 * canonical (oldest-first) order; mandates of other tracks are ignored
 * (each track is an independent timeline; the pin anchors exactly one).
 *
 * Fail-closed everywhere: an empty/absent pin, a pin that matches no
 * mandate (incl. a forked/tampered one — the hash binds the exact
 * canonical bytes), or a malformed root ⇒ `validMandates: []`, so
 * {@link currentAuthorityV2} yields null and the consumer rejects.
 */
export function verifyMandateChainFromPin(
  pinnedHash: string,
  mandates: MandateV2[],
): VerifiedChainV2 {
  const base: VerifiedChainV2 = {
    pin: pinnedHash,
    root: null,
    validMandates: [],
    rejections: [],
  };

  if (typeof pinnedHash !== "string" || pinnedHash.length === 0) {
    return { ...base, rootError: "no-pin" };
  }

  // L1: find the FIRST mandate whose canonical hash equals the pin.
  let rootIdx = -1;
  for (let i = 0; i < mandates.length; i++) {
    const m = mandates[i]!;
    if (!isV2Shape(m)) continue;
    if (pinHashOrNull(m) === pinnedHash) {
      rootIdx = i;
      break;
    }
  }
  if (rootIdx === -1) {
    return { ...base, rootError: "pin-not-in-log" };
  }

  const root = mandates[rootIdx]!;
  // The root is trusted via the PIN, not via a predecessor — so it
  // carries no threshold/successor obligation. It must only be
  // internally well-formed: a valid shape, a sane window, every
  // declared signature verifies, and signedBy is among them (so a
  // matched-by-hash root can't be a malformed blob).
  if (!isV2Shape(root)) return { ...base, rootError: "root-shape-invalid" };
  const rw = windowMs(root.issuedAt, root.expiresAt);
  if (rw === null) return { ...base, rootError: "root-shape-invalid" };
  if (rw <= 0) return { ...base, rootError: "root-expires-before-issuance" };
  if (!allSignaturesValid(root)) return { ...base, rootError: "root-signature-invalid" };
  if (!root.signatures.some((s) => s.pubkey === root.signedBy)) {
    return { ...base, rootError: "root-not-self-signed" };
  }

  const accepted: MandateV2[] = [root];
  const rejections: V2Rejection[] = [];
  const seenIds = new Set<string>([root.mandateId]);

  for (let i = rootIdx + 1; i < mandates.length; i++) {
    const m = mandates[i]!;
    if (!isV2Shape(m) || m.track !== root.track) {
      // not part of this track's forward chain — silently skip
      // (cross-track interleave is legitimate). A malformed object
      // claiming this track is caught by verifyForwardStep below.
      if (isV2Shape(m) && m.track !== root.track) continue;
      if (!isV2Shape(m)) continue;
    }
    if (seenIds.has(m.mandateId)) {
      rejections.push({ mandate: m, reason: "duplicate-mandate-id" });
      continue;
    }
    const pred = accepted[accepted.length - 1]!;
    const fail = verifyForwardStep(pred, m);
    if (fail === null) {
      accepted.push(m);
      seenIds.add(m.mandateId);
    } else {
      rejections.push({ mandate: m, reason: fail });
    }
  }

  return { pin: pinnedHash, root, validMandates: accepted, rejections };
}

/**
 * The operational authority at `now`: the holder of the most-recent
 * valid mandate whose [issuedAt, expiresAt) contains `now`. null ⇒ the
 * track has no live authority right now (consumers fail closed). Same
 * operational semantics as v1's `currentAuthority`; only the chain it
 * runs over changed (verify-forward-from-pin instead of genesis-walk).
 */
export function currentAuthorityV2(
  chain: VerifiedChainV2,
  now: Date,
): { holder: Pubkey; mandate: MandateV2; successors: Pubkey[] } | null {
  const nowMs = now.getTime();
  for (let i = chain.validMandates.length - 1; i >= 0; i--) {
    const m = chain.validMandates[i]!;
    const issued = Date.parse(m.issuedAt);
    const expiry = Date.parse(m.expiresAt);
    if (isFinite(issued) && isFinite(expiry) && issued <= nowMs && nowMs < expiry) {
      return { holder: m.holder, mandate: m, successors: m.successors };
    }
  }
  return null;
}
