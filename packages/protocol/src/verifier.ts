/**
 * Verifier algorithm for the maintainers protocol.
 *
 * Implements §4 of docs/spec/v1.md.
 *
 * One rule: most-recent-valid-mandate-wins. No grace period, no notice
 * window, no override. Holders renew before expiry; if they don't,
 * named successors can unilaterally take over the moment the timer hits
 * zero. First successor to publish wins.
 */

import { canonicalMandate } from "./canonical.js";
import { verify } from "./crypto.js";
import type {
  ApprovalRule,
  Iso8601,
  Mandate,
  Pubkey,
  TrackPolicy,
  Uuid,
} from "./types.js";

export type VerifyResult =
  | { ok: true; mandate: Mandate }
  | { ok: false; reason: VerifyFailReason; index: number; detail?: string };

export type VerifyFailReason =
  | "duplicate-mandate-id"
  | "expires-before-issuance"
  | "no-predecessor"
  | "signature-invalid"
  | "approval-rule-unsatisfied"
  | "signer-not-authorized"
  | "issued-before-predecessor"
  | "genesis-not-self-signed"
  | "wrong-track";

export interface VerifiedTrack {
  track: string;
  mandates: Mandate[];
  validMandates: Mandate[];
  rejections: { mandate: Mandate; reason: VerifyFailReason; detail?: string }[];
}

/**
 * Validate an entire ordered sequence of mandates for a single track.
 *
 * `mandates` MUST be in canonical-log order (oldest first). The function
 * walks the list once, validating each mandate against the prior
 * accepted mandates; rejected mandates are recorded but do not affect
 * subsequent verification.
 */
export function verifyTrack(
  trackName: string,
  policy: TrackPolicy,
  mandates: Mandate[],
): VerifiedTrack {
  if (policy.track !== trackName) {
    throw new Error(
      `verifyTrack: policy.track "${policy.track}" does not match expected "${trackName}"`,
    );
  }

  const seenIds = new Set<string>();
  const accepted: Mandate[] = [];
  const rejections: VerifiedTrack["rejections"] = [];

  for (let i = 0; i < mandates.length; i++) {
    const m = mandates[i]!;
    const result = verifySingleMandate(m, policy, accepted, seenIds);
    if (result.ok) {
      accepted.push(m);
      seenIds.add(m.mandateId);
    } else {
      rejections.push({ mandate: m, reason: result.reason, detail: result.detail });
    }
  }

  return {
    track: trackName,
    mandates,
    validMandates: accepted,
    rejections,
  };
}

function verifySingleMandate(
  m: Mandate,
  policy: TrackPolicy,
  prior: Mandate[],
  seenIds: Set<string>,
): VerifyResult {
  if (m.kind !== "Mandate" || m.version !== 1) {
    return { ok: false, reason: "wrong-track", index: -1, detail: "envelope kind/version mismatch" };
  }
  if (m.track !== policy.track) {
    return { ok: false, reason: "wrong-track", index: -1, detail: `mandate.track=${m.track}` };
  }
  if (seenIds.has(m.mandateId)) {
    return { ok: false, reason: "duplicate-mandate-id", index: -1 };
  }
  if (Date.parse(m.expiresAt) <= Date.parse(m.issuedAt)) {
    return { ok: false, reason: "expires-before-issuance", index: -1 };
  }

  const bytes = canonicalMandate(m);
  const signatureValidity = m.signatures.map((s) => verify(s.sig, bytes, s.pubkey));
  for (let i = 0; i < signatureValidity.length; i++) {
    if (!signatureValidity[i]) {
      return {
        ok: false,
        reason: "signature-invalid",
        index: -1,
        detail: `signature at index ${i} did not verify`,
      };
    }
  }

  // Determine authority and approval rule
  if (prior.length === 0) {
    // Genesis: holder must self-sign
    const issuedAtMs = Date.parse(m.issuedAt);
    const holderSignedPresent = m.signatures.some((s) => s.pubkey === m.holder);
    if (!holderSignedPresent || m.signedBy !== m.holder) {
      return {
        ok: false,
        reason: "genesis-not-self-signed",
        index: -1,
        detail: "genesis mandate must be self-signed by its holder",
      };
    }
    if (!isFinite(issuedAtMs)) {
      return { ok: false, reason: "expires-before-issuance", index: -1, detail: "issuedAt unparseable" };
    }
    if (
      !satisfiesApprovalRule(m.signatures.map((s) => s.pubkey), policy.approvalRule, { holder: m.holder })
    ) {
      return { ok: false, reason: "approval-rule-unsatisfied", index: -1 };
    }
    return { ok: true, mandate: m };
  }

  // Non-genesis: find the latest prior mandate for this track
  const pred = lastInTrack(prior, m.track);
  if (!pred) {
    return { ok: false, reason: "no-predecessor", index: -1 };
  }

  const predIssued = Date.parse(pred.issuedAt);
  const predExpiry = Date.parse(pred.expiresAt);
  const mIssued = Date.parse(m.issuedAt);

  if (mIssued < predIssued) {
    return { ok: false, reason: "issued-before-predecessor", index: -1 };
  }

  let authorizedSigners: Set<Pubkey>;
  if (mIssued < predExpiry) {
    // m issued during pred's active window — only pred.holder can sign
    authorizedSigners = new Set([pred.holder]);
  } else {
    // m issued at or after pred's expiry — any pred.successor can sign
    authorizedSigners = new Set(pred.successors);
  }

  if (!authorizedSigners.has(m.signedBy)) {
    return {
      ok: false,
      reason: "signer-not-authorized",
      index: -1,
      detail: `signedBy ${shortHex(m.signedBy)} not in authorized set`,
    };
  }
  for (const s of m.signatures) {
    if (!authorizedSigners.has(s.pubkey)) {
      return {
        ok: false,
        reason: "signer-not-authorized",
        index: -1,
        detail: `signature from ${shortHex(s.pubkey)} not in authorized set`,
      };
    }
  }

  if (
    !satisfiesApprovalRule(
      m.signatures.map((s) => s.pubkey),
      policy.approvalRule,
      { holder: pred.holder, authorized: authorizedSigners },
    )
  ) {
    return { ok: false, reason: "approval-rule-unsatisfied", index: -1 };
  }

  return { ok: true, mandate: m };
}

function lastInTrack(prior: Mandate[], track: string): Mandate | undefined {
  for (let i = prior.length - 1; i >= 0; i--) {
    const p = prior[i]!;
    if (p.track === track) return p;
  }
  return undefined;
}

function satisfiesApprovalRule(
  signerPubkeys: Pubkey[],
  rule: ApprovalRule,
  context: { holder: Pubkey; authorized?: Set<Pubkey> },
): boolean {
  if (rule.kind !== "threshold") return false;
  const unique = new Set(signerPubkeys);
  if (unique.size < rule.threshold) return false;
  if (rule.of === "anyAuthorizedSigner") {
    if (context.authorized) {
      let count = 0;
      for (const pk of unique) {
        if (context.authorized.has(pk)) count++;
      }
      return count >= rule.threshold;
    }
    // Genesis case: only the holder is "authorized"
    return unique.has(context.holder) && rule.threshold === 1;
  }
  // Specific pubkey list
  const required = new Set(rule.of);
  let matches = 0;
  for (const pk of unique) if (required.has(pk)) matches++;
  return matches >= rule.threshold;
}

function shortHex(h: string): string {
  return h.length > 12 ? `${h.slice(0, 8)}…` : h;
}

/**
 * Given a verified track, return the current authority at time `now`.
 * The current authority is the holder of the most recent valid mandate
 * whose [issuedAt, expiresAt) contains `now`. If no such mandate
 * exists, returns null — the track is in "expired pending succession"
 * state and any named successor of the most-recently-expired mandate
 * may issue a new one.
 */
export function currentAuthority(
  track: VerifiedTrack,
  now: Date,
): { holder: Pubkey; mandate: Mandate; successors: Pubkey[] } | null {
  const nowMs = now.getTime();
  for (let i = track.validMandates.length - 1; i >= 0; i--) {
    const m = track.validMandates[i]!;
    const issued = Date.parse(m.issuedAt);
    const expiry = Date.parse(m.expiresAt);
    if (issued <= nowMs && nowMs < expiry) {
      return { holder: m.holder, mandate: m, successors: m.successors };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Checkpointed verification (spec §5.2) — a performance optimization,
// NEVER a trust floor.
//
// A consumer that has already verified a track from the pinned genesis
// persists the resulting authority as a TrackCheckpoint and, on the
// next sync, asks the (untrusted) server only for the *suffix* of
// mandates after that point. Three invariants make this safe:
//
//   1. Optimization-not-floor — genesis stays the only anchor. The
//      checkpoint is something the client itself derived from a
//      genesis walk; a corrupt or wrong-track checkpoint is a hard
//      error here, and the caller MUST fall back to a full re-walk
//      from the pinned genesis (never silently trust the checkpoint).
//   2. Suffix cryptographically chained — every suffix mandate's
//      Ed25519 signatures are verified over its canonical bytes and
//      its signer must be authorized by the checkpoint (the synthetic
//      predecessor). A forged or non-chaining suffix is rejected.
//   3. Alarms unskippable — a takeover is derived from the *observed
//      holder change at the checkpoint boundary*, so a server that
//      drops the intermediate takeover mandate (presenting only the
//      post-takeover state) still surfaces the alarm. It may drop only
//      benign same-holder renewals, which by construction change no
//      authority and hide nothing.
// ---------------------------------------------------------------------------

export interface TrackCheckpoint {
  track: string;
  mandateId: Uuid;
  holder: Pubkey;
  successors: Pubkey[];
  issuedAt: Iso8601;
  expiresAt: Iso8601;
  /** newMandate ids of takeover alarms the user already acknowledged. */
  ackedAlarms: Uuid[];
}

export interface CheckpointTakeoverAlarm {
  track: string;
  previousMandate: Uuid;
  newMandate: Uuid;
  previousHolder: Pubkey;
  newHolder: Pubkey;
}

export interface CheckpointVerifyResult {
  /**
   * A VerifiedTrack whose validMandates are
   * `[synthetic-checkpoint, ...accepted suffix]`, so `currentAuthority`
   * yields the identical result a full genesis walk would.
   */
  verified: VerifiedTrack;
  /** Every holder transition observed, including the boundary. */
  alarms: CheckpointTakeoverAlarm[];
  /** `alarms` minus `checkpoint.ackedAlarms` — what to surface now. */
  unacknowledgedAlarms: CheckpointTakeoverAlarm[];
}

/**
 * Derive the persistable checkpoint from a fully (genesis-anchored)
 * verified track. Returns null if the track has no valid mandate.
 */
export function checkpointFromVerifiedTrack(
  track: VerifiedTrack,
  ackedAlarms: Uuid[] = [],
): TrackCheckpoint | null {
  const last = track.validMandates[track.validMandates.length - 1];
  if (!last) return null;
  return {
    track: track.track,
    mandateId: last.mandateId,
    holder: last.holder,
    successors: last.successors,
    issuedAt: last.issuedAt,
    expiresAt: last.expiresAt,
    ackedAlarms,
  };
}

function syntheticMandateFromCheckpoint(cp: TrackCheckpoint): Mandate {
  // Its signature was already verified when the checkpoint was minted
  // from a genesis walk, so it is seeded as accepted and not re-checked
  // — that is the entire optimization.
  return {
    kind: "Mandate",
    version: 1,
    mandateId: cp.mandateId,
    track: cp.track,
    holder: cp.holder,
    issuedAt: cp.issuedAt,
    expiresAt: cp.expiresAt,
    successors: cp.successors,
    signedBy: cp.holder,
    signatures: [],
  };
}

/**
 * Verify a suffix of mandates continuing from a checkpoint instead of
 * from genesis. The checkpoint MUST be for `trackName` (a mismatch
 * throws — invariant 1: the caller must then re-walk from genesis).
 */
export function verifyTrackFromCheckpoint(
  trackName: string,
  policy: TrackPolicy,
  checkpoint: TrackCheckpoint,
  suffixMandates: Mandate[],
): CheckpointVerifyResult {
  if (policy.track !== trackName) {
    throw new Error(
      `verifyTrackFromCheckpoint: policy.track "${policy.track}" does not match expected "${trackName}"`,
    );
  }
  if (checkpoint.track !== trackName) {
    throw new Error(
      `verifyTrackFromCheckpoint: checkpoint.track "${checkpoint.track}" does not match expected "${trackName}" — re-walk from genesis`,
    );
  }

  const synthetic = syntheticMandateFromCheckpoint(checkpoint);
  const accepted: Mandate[] = [synthetic];
  const seenIds = new Set<string>([checkpoint.mandateId]);
  const rejections: VerifiedTrack["rejections"] = [];

  for (let i = 0; i < suffixMandates.length; i++) {
    const m = suffixMandates[i]!;
    const result = verifySingleMandate(m, policy, accepted, seenIds);
    if (result.ok) {
      accepted.push(m);
      seenIds.add(m.mandateId);
    } else {
      rejections.push({ mandate: m, reason: result.reason, detail: result.detail });
    }
  }

  const verified: VerifiedTrack = {
    track: trackName,
    mandates: suffixMandates,
    validMandates: accepted,
    rejections,
  };

  // Takeover = a valid mandate signed by someone other than the prior
  // holder. The synthetic checkpoint is index 0, so i=1 is the
  // boundary — a takeover there is detected even if the server dropped
  // the real takeover mandate, because the holder visibly changed
  // relative to the checkpoint.
  const alarms: CheckpointTakeoverAlarm[] = [];
  for (let i = 1; i < accepted.length; i++) {
    const prev = accepted[i - 1]!;
    const cur = accepted[i]!;
    if (cur.signedBy !== prev.holder) {
      alarms.push({
        track: trackName,
        previousMandate: prev.mandateId,
        newMandate: cur.mandateId,
        previousHolder: prev.holder,
        newHolder: cur.holder,
      });
    }
  }
  const acked = new Set(checkpoint.ackedAlarms);
  const unacknowledgedAlarms = alarms.filter((a) => !acked.has(a.newMandate));

  return { verified, alarms, unacknowledgedAlarms };
}

/**
 * Given a verified track, return the most recently expired valid
 * mandate (its successors hold standing to take over).
 */
export function lastExpiredMandate(
  track: VerifiedTrack,
  now: Date,
): Mandate | null {
  const nowMs = now.getTime();
  for (let i = track.validMandates.length - 1; i >= 0; i--) {
    const m = track.validMandates[i]!;
    const expiry = Date.parse(m.expiresAt);
    if (expiry <= nowMs) return m;
  }
  return null;
}
