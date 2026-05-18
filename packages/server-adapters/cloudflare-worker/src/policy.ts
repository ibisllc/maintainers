/**
 * Per-envelope policy enforcement for the Model A Worker.
 * **LOCKED Phase-2 v2 model** (Mandate v2; verify FORWARD from the
 * first on-repo mandate; no policy.json; holder-signs endorsements).
 *
 * The Worker holds a PAT capable of pushing to the target repo. Policy
 * is therefore the gate: every commit is gated on the request's signed
 * envelope verifying against the current on-repo `.maintainers/` state.
 *
 * Defense-in-depth fences (each independently sufficient to refuse the
 * commit):
 *
 *   1. Path-prefix fence — the target path MUST begin with
 *      `.maintainers/` and MUST NOT contain `..` or `//`.
 *   2. Envelope-shape fence — body MUST parse as one of the known
 *      envelope kinds at the expected version (Mandate = v2; the
 *      identity/endorsement envelopes = v1). Unknown kinds are refused.
 *   3. Canonical-bytes fence — the request's `envelopeBytes` MUST
 *      re-derive to the same canonical bytes the policy module computes.
 *   4. Signature fence — every signature MUST verify against those
 *      canonical bytes.
 *   5. Authority fence — for a Mandate, appending it must keep a valid
 *      forward chain anchored at the first on-repo mandate (an empty
 *      track ⇒ a valid self-signed v2 root — "from-scratch" is
 *      protocol-unauthenticated by design; the trust is the baked pin
 *      downstream, see the v2 security boundary). For a Release/Ca
 *      endorsement, the signer MUST be the v2 authority `holder` at the
 *      relevant clock (issuedAt / NOW respectively).
 *
 * This file holds the pure policy. The Worker entrypoint wraps it with
 * I/O against the GitHub Contents API and with rate-limiting.
 */

import {
  canonicalMandateV2,
  canonicalKeyFile,
  canonicalKeyRedirect,
  canonicalEmailRotation,
  canonicalKeyIntroductionRequest,
  canonicalReleaseEndorsement,
  canonicalCaEndorsement,
  mandatePinHash,
  verify,
  bytesToHex,
  verifyMandateChainFromPin,
  currentAuthorityV2,
  type MandateV2,
  type KeyFile,
  type KeyRedirect,
  type EmailRotation,
  type KeyIntroductionRequest,
  type ReleaseEndorsement,
  type CaEndorsement,
  type Pubkey,
} from "@maintainers/protocol";

export const MAINTAINERS_PREFIX = ".maintainers/";

/**
 * The worker's envelope union. Deliberately NOT the protocol `Envelope`
 * (which still carries the v1 `Mandate` member until c4.5e): the worker
 * is v2-only, so a Mandate here is always a `MandateV2`.
 */
type WorkerEnvelope =
  | MandateV2
  | KeyFile
  | KeyRedirect
  | EmailRotation
  | KeyIntroductionRequest
  | ReleaseEndorsement
  | CaEndorsement;

export type PolicyDecision =
  | { ok: true; commitMessage: string }
  | { ok: false; status: number; reason: string; detail?: string };

export interface RepoState {
  /**
   * v2 mandates per track, in canonical-log order (the Worker
   * entrypoint sorts by issuedAt ascending — the same canonical-log
   * substitute the on-disk reader uses; backdating is defeated by the
   * signed `issuedAt` + the forward verifier's predecessor checks).
   * There is NO policy.json in v2 (root or track).
   */
  tracks: Map<string, MandateV2[]>;
  /** Known KeyFiles indexed by pubkey. */
  keyFiles: Map<Pubkey, KeyFile>;
}

/**
 * Decide whether a candidate envelope-bearing write is acceptable.
 *
 * Pure function: all I/O lives in the Worker entrypoint, so every
 * branch is unit-testable from a synthetic RepoState.
 */
export function decide(input: {
  path: string;
  envelope: unknown;
  envelopeBytesHex: string;
  state: RepoState;
  now: Date;
}): PolicyDecision {
  const pathCheck = checkPath(input.path);
  if (!pathCheck.ok) return pathCheck;

  const shaped = parseEnvelope(input.envelope);
  if (!shaped.ok) return shaped;
  const envelope = shaped.envelope;

  let expectedBytes: Uint8Array;
  try {
    expectedBytes = canonicalBytesFor(envelope);
  } catch (err) {
    return {
      ok: false,
      status: 400,
      reason: "canonical-bytes-error",
      detail: err instanceof Error ? err.message : String(err),
    };
  }
  const expectedHex = bytesToHex(expectedBytes);
  if (input.envelopeBytesHex.toLowerCase() !== expectedHex) {
    return {
      ok: false,
      status: 400,
      reason: "canonical-bytes-mismatch",
      detail: "request envelopeBytes do not match canonical derivation",
    };
  }

  const sigCheck = checkSignatures(envelope, expectedBytes);
  if (!sigCheck.ok) return sigCheck;

  const authorityCheck = checkAuthority(envelope, input.state, input.now);
  if (!authorityCheck.ok) return authorityCheck;

  return {
    ok: true,
    commitMessage: commitMessageFor(envelope, input.now),
  };
}

function checkPath(p: string): { ok: true } | { ok: false; status: number; reason: string; detail?: string } {
  if (typeof p !== "string" || p.length === 0) {
    return { ok: false, status: 400, reason: "path-empty" };
  }
  if (!p.startsWith(MAINTAINERS_PREFIX)) {
    return {
      ok: false,
      status: 403,
      reason: "path-outside-maintainers",
      detail: `path must start with "${MAINTAINERS_PREFIX}"`,
    };
  }
  if (p.includes("..") || p.includes("//") || p.includes("\\")) {
    return { ok: false, status: 400, reason: "path-traversal" };
  }
  if (p.endsWith("/")) {
    return { ok: false, status: 400, reason: "path-is-directory" };
  }
  if (p.length > 512) {
    return { ok: false, status: 400, reason: "path-too-long" };
  }
  return { ok: true };
}

type ParsedEnvelope =
  | { ok: true; envelope: WorkerEnvelope }
  | { ok: false; status: number; reason: string; detail?: string };

function parseEnvelope(raw: unknown): ParsedEnvelope {
  if (typeof raw !== "object" || raw === null) {
    return { ok: false, status: 400, reason: "envelope-not-object" };
  }
  const obj = raw as Record<string, unknown>;
  const kind = obj["kind"];
  const version = obj["version"];
  switch (kind) {
    case "Mandate":
      // v2 is THE Mandate version; v1 is retired.
      if (version !== 2) {
        return { ok: false, status: 400, reason: "mandate-version-unsupported" };
      }
      return shapeMandateV2(obj);
    case "KeyFile":
      if (version !== 1) return { ok: false, status: 400, reason: "envelope-version-unsupported" };
      return shapeKeyFile(obj);
    case "KeyRedirect":
      if (version !== 1) return { ok: false, status: 400, reason: "envelope-version-unsupported" };
      return shapeKeyRedirect(obj);
    case "EmailRotation":
      if (version !== 1) return { ok: false, status: 400, reason: "envelope-version-unsupported" };
      return shapeEmailRotation(obj);
    case "KeyIntroductionRequest":
      if (version !== 1) return { ok: false, status: 400, reason: "envelope-version-unsupported" };
      return shapeKeyIntroductionRequest(obj);
    case "ReleaseEndorsement":
      if (version !== 1) return { ok: false, status: 400, reason: "envelope-version-unsupported" };
      return shapeReleaseEndorsement(obj);
    case "CaEndorsement":
      if (version !== 1) return { ok: false, status: 400, reason: "envelope-version-unsupported" };
      return shapeCaEndorsement(obj);
    default:
      return { ok: false, status: 400, reason: "envelope-kind-unknown" };
  }
}

function shapeMandateV2(obj: Record<string, unknown>): ParsedEnvelope {
  if (
    typeof obj["mandateId"] !== "string" ||
    typeof obj["track"] !== "string" ||
    typeof obj["holder"] !== "string" ||
    typeof obj["issuedAt"] !== "string" ||
    typeof obj["expiresAt"] !== "string" ||
    !Array.isArray(obj["successors"]) ||
    typeof obj["approvalRule"] !== "object" ||
    obj["approvalRule"] === null ||
    typeof obj["minSuccessors"] !== "number" ||
    typeof obj["maxDurationSeconds"] !== "number" ||
    typeof obj["defaultDurationSeconds"] !== "number" ||
    typeof obj["signedBy"] !== "string" ||
    !Array.isArray(obj["signatures"])
  ) {
    return { ok: false, status: 400, reason: "mandate-shape" };
  }
  for (const s of obj["successors"]) {
    if (typeof s !== "string") return { ok: false, status: 400, reason: "mandate-successors-shape" };
  }
  const ar = obj["approvalRule"] as Record<string, unknown>;
  if (ar["kind"] !== "threshold" || typeof ar["threshold"] !== "number") {
    return { ok: false, status: 400, reason: "mandate-approvalrule-shape" };
  }
  for (const s of obj["signatures"]) {
    if (
      typeof s !== "object" ||
      s === null ||
      typeof (s as Record<string, unknown>)["pubkey"] !== "string" ||
      typeof (s as Record<string, unknown>)["sig"] !== "string"
    ) {
      return { ok: false, status: 400, reason: "mandate-signatures-shape" };
    }
  }
  return { ok: true, envelope: obj as unknown as MandateV2 };
}

function shapeKeyFile(obj: Record<string, unknown>): ParsedEnvelope {
  if (
    typeof obj["pubkey"] !== "string" ||
    typeof obj["displayName"] !== "string" ||
    typeof obj["currentEmail"] !== "string" ||
    !Array.isArray(obj["emailHistory"]) ||
    typeof obj["metadata"] !== "object" ||
    obj["metadata"] === null ||
    typeof obj["introductionMandate"] !== "string" ||
    typeof obj["signature"] !== "string"
  ) {
    return { ok: false, status: 400, reason: "keyfile-shape" };
  }
  return { ok: true, envelope: obj as unknown as KeyFile };
}

function shapeKeyRedirect(obj: Record<string, unknown>): ParsedEnvelope {
  if (
    typeof obj["fromEmail"] !== "string" ||
    typeof obj["renamedTo"] !== "string" ||
    typeof obj["renamedAt"] !== "string" ||
    typeof obj["pubkey"] !== "string" ||
    typeof obj["signature"] !== "string"
  ) {
    return { ok: false, status: 400, reason: "keyredirect-shape" };
  }
  return { ok: true, envelope: obj as unknown as KeyRedirect };
}

function shapeEmailRotation(obj: Record<string, unknown>): ParsedEnvelope {
  if (
    typeof obj["pubkey"] !== "string" ||
    typeof obj["fromEmail"] !== "string" ||
    typeof obj["toEmail"] !== "string" ||
    typeof obj["rotatedAt"] !== "string" ||
    typeof obj["signature"] !== "string"
  ) {
    return { ok: false, status: 400, reason: "emailrotation-shape" };
  }
  return { ok: true, envelope: obj as unknown as EmailRotation };
}

function shapeKeyIntroductionRequest(obj: Record<string, unknown>): ParsedEnvelope {
  if (
    typeof obj["pubkey"] !== "string" ||
    typeof obj["displayName"] !== "string" ||
    typeof obj["currentEmail"] !== "string" ||
    typeof obj["metadata"] !== "object" ||
    obj["metadata"] === null ||
    typeof obj["requestedAt"] !== "string" ||
    typeof obj["signature"] !== "string"
  ) {
    return { ok: false, status: 400, reason: "keyintro-shape" };
  }
  return { ok: true, envelope: obj as unknown as KeyIntroductionRequest };
}

function shapeReleaseEndorsement(obj: Record<string, unknown>): ParsedEnvelope {
  if (
    typeof obj["releaseId"] !== "string" ||
    typeof obj["semverTag"] !== "string" ||
    typeof obj["commitHash"] !== "string" ||
    !Array.isArray(obj["intermediateCommits"]) ||
    typeof obj["intermediateMerkleRoot"] !== "string" ||
    typeof obj["issuedAt"] !== "string" ||
    typeof obj["signedBy"] !== "string" ||
    !Array.isArray(obj["signatures"])
  ) {
    return { ok: false, status: 400, reason: "endorsement-shape" };
  }
  return { ok: true, envelope: obj as unknown as ReleaseEndorsement };
}

function shapeCaEndorsement(obj: Record<string, unknown>): ParsedEnvelope {
  if (
    typeof obj["endorsementId"] !== "string" ||
    typeof obj["track"] !== "string" ||
    typeof obj["caPubkey"] !== "string" ||
    typeof obj["scope"] !== "string" ||
    typeof obj["notBefore"] !== "string" ||
    typeof obj["notAfter"] !== "string" ||
    typeof obj["issuedAt"] !== "string" ||
    typeof obj["signedBy"] !== "string" ||
    !Array.isArray(obj["signatures"])
  ) {
    return { ok: false, status: 400, reason: "ca-endorsement-shape" };
  }
  return { ok: true, envelope: obj as unknown as CaEndorsement };
}

function canonicalBytesFor(e: WorkerEnvelope): Uint8Array {
  switch (e.kind) {
    case "Mandate":
      return canonicalMandateV2(e);
    case "KeyFile":
      return canonicalKeyFile(e);
    case "KeyRedirect":
      return canonicalKeyRedirect(e);
    case "EmailRotation":
      return canonicalEmailRotation(e);
    case "KeyIntroductionRequest":
      return canonicalKeyIntroductionRequest(e);
    case "ReleaseEndorsement":
      return canonicalReleaseEndorsement(e);
    case "CaEndorsement":
      return canonicalCaEndorsement(e);
  }
}

function checkSignatures(
  e: WorkerEnvelope,
  bytes: Uint8Array,
): { ok: true } | { ok: false; status: number; reason: string; detail?: string } {
  if (
    e.kind === "Mandate" ||
    e.kind === "ReleaseEndorsement" ||
    e.kind === "CaEndorsement"
  ) {
    if (e.signatures.length === 0) {
      return { ok: false, status: 400, reason: "no-signatures" };
    }
    const signedByPresent = e.signatures.some((s) => s.pubkey === e.signedBy);
    if (!signedByPresent) {
      return { ok: false, status: 400, reason: "signedBy-not-in-signatures" };
    }
    for (let i = 0; i < e.signatures.length; i++) {
      const s = e.signatures[i]!;
      if (!verify(s.sig, bytes, s.pubkey)) {
        return { ok: false, status: 400, reason: "signature-invalid", detail: `signature ${i}` };
      }
    }
    return { ok: true };
  }
  // Single-signature envelopes (KeyFile, KeyRedirect, EmailRotation,
  // KeyIntroductionRequest): the `pubkey` field is the signer.
  const pub = (e as { pubkey: Pubkey }).pubkey;
  const sig = (e as { signature: string }).signature;
  if (!verify(sig, bytes, pub)) {
    return { ok: false, status: 400, reason: "signature-invalid" };
  }
  return { ok: true };
}

function checkAuthority(
  e: WorkerEnvelope,
  state: RepoState,
  now: Date,
): { ok: true } | { ok: false; status: number; reason: string; detail?: string } {
  switch (e.kind) {
    case "Mandate":
      return checkMandateAuthority(e, state);
    case "ReleaseEndorsement":
      return checkEndorsementAuthority(e, state);
    case "CaEndorsement":
      return checkCaEndorsementAuthority(e, state, now);
    case "KeyFile":
    case "KeyRedirect":
    case "EmailRotation":
    case "KeyIntroductionRequest":
      return checkKeyEnvelopeAuthority(e, state);
  }
}

/**
 * v2 Mandate write-gate. Empty track ⇒ the candidate must be a valid
 * self-signed v2 ROOT (from-scratch; protocol-unauthenticated by design
 * — the trust is the baked pin downstream). Non-empty ⇒ appending the
 * candidate must keep a valid forward chain anchored at the first
 * on-repo mandate (i.e. the candidate satisfies the predecessor's
 * embedded approvalRule / minSuccessors / maxDuration — the L3 one
 * rule). The Worker has no baked pin; the on-repo first mandate IS the
 * anchor for "is this a legitimate continuation of what's there".
 */
function checkMandateAuthority(
  m: MandateV2,
  state: RepoState,
): { ok: true } | { ok: false; status: number; reason: string; detail?: string } {
  const existing = state.tracks.get(m.track) ?? [];
  if (existing.length === 0) {
    // From-scratch root: well-formed + self-signed (signedBy ∈
    // signatures) + sane window + every signature verifies.
    const chain = verifyMandateChainFromPin(mandatePinHash(m), [m]);
    const accepted =
      chain.root !== null &&
      chain.validMandates.length === 1 &&
      chain.validMandates[0]!.mandateId === m.mandateId;
    if (!accepted) {
      return {
        ok: false,
        status: 403,
        reason: "mandate-rejected",
        detail: chain.rootError ?? "from-scratch-root-invalid",
      };
    }
    return { ok: true };
  }
  // Succession: anchor at the first on-repo mandate, verify forward
  // including the candidate.
  const log = [...existing, m];
  const chain = verifyMandateChainFromPin(mandatePinHash(existing[0]!), log);
  const accepted = chain.validMandates.some((vm) => vm.mandateId === m.mandateId);
  if (!accepted) {
    const rej = chain.rejections.find((r) => r.mandate.mandateId === m.mandateId);
    return {
      ok: false,
      status: 403,
      reason: "mandate-rejected",
      detail: rej?.reason ?? chain.rootError ?? "not-in-valid-forward-chain",
    };
  }
  return { ok: true };
}

function checkEndorsementAuthority(
  e: ReleaseEndorsement,
  state: RepoState,
): { ok: true } | { ok: false; status: number; reason: string; detail?: string } {
  const releaseMandates = state.tracks.get("release");
  if (!releaseMandates || releaseMandates.length === 0) {
    return { ok: false, status: 403, reason: "release-track-not-declared" };
  }
  const chain = verifyMandateChainFromPin(
    mandatePinHash(releaseMandates[0]!),
    releaseMandates,
  );
  const authority = currentAuthorityV2(chain, new Date(Date.parse(e.issuedAt)));
  if (!authority) {
    return { ok: false, status: 403, reason: "no-active-release-authority" };
  }
  // v2 holder-signs: the operational authority signs releases.
  if (e.signedBy !== authority.holder) {
    return { ok: false, status: 403, reason: "endorsement-signer-not-holder" };
  }
  return { ok: true };
}

/**
 * CaEndorsement authority — the §5.1 deviation: the signer is checked
 * against the v2 ca-track authority at the verifier's clock `now`, NOT
 * at the endorsement's `issuedAt`, and the lease window is enforced. A
 * backdated `issuedAt` cannot resurrect a key whose ca-track authority
 * has since rotated; a lapsed lease is rejected with no revocation list.
 */
function checkCaEndorsementAuthority(
  e: CaEndorsement,
  state: RepoState,
  now: Date,
): { ok: true } | { ok: false; status: number; reason: string; detail?: string } {
  const SKEW_MS = 5 * 60 * 1000; // ±5 min clock-skew tolerance (spec §7)
  const nb = Date.parse(e.notBefore);
  const na = Date.parse(e.notAfter);
  if (!isFinite(nb) || !isFinite(na) || na <= nb) {
    return { ok: false, status: 400, reason: "ca-endorsement-window-malformed" };
  }
  const nowMs = now.getTime();
  if (nowMs < nb - SKEW_MS) {
    return { ok: false, status: 403, reason: "ca-endorsement-lease-not-yet" };
  }
  if (nowMs >= na + SKEW_MS) {
    return { ok: false, status: 403, reason: "ca-endorsement-lease-expired" };
  }
  const caMandates = state.tracks.get(e.track);
  if (!caMandates || caMandates.length === 0) {
    return { ok: false, status: 403, reason: "ca-track-not-declared" };
  }
  const chain = verifyMandateChainFromPin(mandatePinHash(caMandates[0]!), caMandates);
  // NOW, not issuedAt — the entire CaEndorsement security argument.
  const authority = currentAuthorityV2(chain, now);
  if (!authority) {
    return { ok: false, status: 403, reason: "no-active-ca-authority" };
  }
  if (e.signedBy !== authority.holder) {
    return { ok: false, status: 403, reason: "ca-endorsement-signer-not-holder" };
  }
  return { ok: true };
}

function checkKeyEnvelopeAuthority(
  e: KeyFile | KeyRedirect | EmailRotation | KeyIntroductionRequest,
  state: RepoState,
): { ok: true } | { ok: false; status: number; reason: string; detail?: string } {
  if (e.kind === "KeyIntroductionRequest") {
    // Always permitted: anyone may publish a self-signed candidacy
    // claim. Acceptance happens at the next mandate that names them.
    return { ok: true };
  }
  if (e.kind === "KeyFile") {
    // A KeyFile is a non-load-bearing identity label (verification
    // operates on the pubkey, never the email). Self-signed ⇒ accept;
    // a later mandate naming an illegitimate pubkey is what the forward
    // verifier catches.
    return { ok: true };
  }
  // EmailRotation / KeyRedirect require the pubkey to already exist.
  if (!state.keyFiles.has(e.pubkey)) {
    return {
      ok: false,
      status: 403,
      reason: "unknown-pubkey",
      detail: `${e.kind} from pubkey not present in .maintainers/keys/`,
    };
  }
  return { ok: true };
}

function commitMessageFor(e: WorkerEnvelope, now: Date): string {
  let pubkeyShort = "";
  switch (e.kind) {
    case "Mandate":
    case "ReleaseEndorsement":
    case "CaEndorsement":
      pubkeyShort = e.signedBy.slice(0, 8);
      break;
    case "KeyFile":
    case "KeyRedirect":
    case "EmailRotation":
    case "KeyIntroductionRequest":
      pubkeyShort = e.pubkey.slice(0, 8);
      break;
  }
  return `maintainers: ${e.kind} by ${pubkeyShort} at ${now.toISOString()}`;
}

/**
 * Compute the verified `.maintainers/` summary view returned by /verify.
 * Per-track current authority + takeover alarms, all over the v2
 * verify-forward chain (anchored at each track's first on-repo mandate).
 */
export function summarizeState(state: RepoState, now: Date): RepoSummary {
  const tracks: RepoSummary["tracks"] = [];
  const alarms: RepoSummary["takeoverAlarms"] = [];

  for (const [name, mandates] of state.tracks) {
    if (mandates.length === 0) {
      tracks.push({
        name,
        currentHolder: null,
        currentMandateId: null,
        currentExpiresAt: null,
        successors: [],
        mandateCount: 0,
        rejectedCount: 0,
      });
      continue;
    }
    const chain = verifyMandateChainFromPin(mandatePinHash(mandates[0]!), mandates);
    const current = currentAuthorityV2(chain, now);
    const last = chain.validMandates[chain.validMandates.length - 1];

    tracks.push({
      name,
      currentHolder: current?.holder ?? null,
      currentMandateId: current?.mandate.mandateId ?? null,
      currentExpiresAt: current?.mandate.expiresAt ?? null,
      successors: current?.successors ?? last?.successors ?? [],
      mandateCount: chain.validMandates.length,
      rejectedCount:
        chain.rejections.length + (chain.rootError ? 1 : 0),
    });

    // Takeover = a valid mandate signed by someone other than the prior
    // holder (the v2 chain has no holder-in-window/after-expiry split —
    // succession is the single mechanism).
    for (let i = 1; i < chain.validMandates.length; i++) {
      const prev = chain.validMandates[i - 1]!;
      const cur = chain.validMandates[i]!;
      if (cur.signedBy !== prev.holder) {
        alarms.push({
          track: name,
          previousMandate: prev.mandateId,
          newMandate: cur.mandateId,
          previousHolder: prev.holder,
          newHolder: cur.holder,
          detectedAt: now.toISOString(),
        });
      }
    }
  }

  return {
    tracks,
    keys: Array.from(state.keyFiles.values()).map((k) => ({
      pubkey: k.pubkey,
      displayName: k.displayName,
      currentEmail: k.currentEmail,
      emailHistoryLength: k.emailHistory.length,
    })),
    takeoverAlarms: alarms,
    verifiedAt: now.toISOString(),
  };
}

export interface RepoSummary {
  tracks: {
    name: string;
    currentHolder: Pubkey | null;
    currentMandateId: string | null;
    currentExpiresAt: string | null;
    successors: Pubkey[];
    mandateCount: number;
    rejectedCount: number;
  }[];
  keys: {
    pubkey: Pubkey;
    displayName: string;
    currentEmail: string;
    emailHistoryLength: number;
  }[];
  takeoverAlarms: {
    track: string;
    previousMandate: string;
    newMandate: string;
    previousHolder: Pubkey;
    newHolder: Pubkey;
    detectedAt: string;
  }[];
  verifiedAt: string;
}
