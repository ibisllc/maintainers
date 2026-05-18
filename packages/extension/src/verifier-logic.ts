/**
 * Wraps the @ibisllc/maintainers v2 verifier into a UI-ready shape.
 * **LOCKED Phase-2 v2 model** (Mandate v2; verify FORWARD from a pinned
 * mandate; no policy.json; holder-signs endorsements).
 *
 * **#31 — STATUS / PREVIEW ONLY.** The browser extension verifies
 * arbitrary repos in-browser and has NO compiled-in
 * `MAINTAINER_PINNED_MANDATE_HASH`. It therefore anchors each track's
 * forward verification at the FIRST on-repo mandate's
 * `mandatePinHash` — the read-only-preview anchor (the same no-baked-pin
 * pattern as the worker's `summarizeState` / the web-ui project view).
 * This is inspection only: the v2 security boundary is UNCHANGED — real
 * trust is the pin a downstream consumer BAKES into its signed build and
 * walks forward from. An empty mandate list ⇒
 * `verifyMandateChainFromPin("", …)` ⇒ `rootError:"no-pin"` ⇒
 * fail-closed (the #30 invariant, generalised).
 *
 * Inputs: per-track v2 Mandates + KeyFiles + ReleaseEndorsements.
 * Outputs: per-track current holder card + named successors with display
 * info + recent activity timeline + derived alarms (takeover, email
 * rotation, chain gap, expiring-soon).
 */
import {
  currentAuthority,
  mandatePinHash,
  verifyChainOfEndorsements,
  verifyMandateChainFromPin,
  type KeyFile,
  type Mandate,
  type Pubkey,
  type ReleaseEndorsement,
  type TakeoverAlarm,
  type VerifiedChain,
} from "@ibisllc/maintainers";

export type AlarmLevel = "red" | "yellow" | "info";

export interface Alarm {
  level: AlarmLevel;
  kind: "takeover" | "email-rotation" | "chain-gap" | "expiring-soon";
  track?: string;
  message: string;
  detail?: string;
  /** Best-effort emails for out-of-band confirmation. */
  contactEmails?: string[];
}

export interface PersonCard {
  pubkey: Pubkey;
  displayName: string;
  email: string;
  photo: string | null;
  github: string | null;
  role: string | null;
}

export interface TrackView {
  track: string;
  current: { holder: PersonCard; mandate: Mandate; expiresAt: string; expiresInMs: number } | null;
  successors: PersonCard[];
  /**
   * v2 has no holder-in-window-vs-after-expiry split. When there is no
   * live authority, this is the most-recent valid mandate (its window
   * has elapsed); its `successors` are who may continue the track.
   * Informational for this read-only view.
   */
  lastExpired: Mandate | null;
  recentMandates: Mandate[];
  rejections: VerifiedChain["rejections"];
}

export interface OverlayState {
  projectName: string;
  /** True once at least one track anchored a forward chain. */
  policyPresent: boolean;
  tracks: TrackView[];
  recentEndorsements: ReleaseEndorsement[];
  endorsementRejections: ReturnType<typeof verifyChainOfEndorsements>["rejections"];
  alarms: Alarm[];
  computedAt: number;
}

const EXPIRY_SOON_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Forward-verify a track anchored at its first on-repo mandate. An
 * empty log ⇒ empty-pin ⇒ `rootError:"no-pin"` ⇒ fail-closed.
 */
function verifyTrackChain(mandates: Mandate[]): VerifiedChain {
  const pin = mandates.length > 0 ? safePinHash(mandates[0]!) : "";
  return verifyMandateChainFromPin(pin, mandates);
}

function safePinHash(m: Mandate): string {
  try {
    return mandatePinHash(m);
  } catch {
    // An adversarial first mandate that won't canonicalize ⇒ no anchor
    // ⇒ pin-not-in-log ⇒ fail-closed.
    return "";
  }
}

export function computeOverlayState(input: {
  mandates: Record<string, Mandate[]>;
  keys: KeyFile[];
  endorsements: ReleaseEndorsement[];
  now: Date;
}): OverlayState {
  const { mandates, keys, endorsements, now } = input;
  const alarms: Alarm[] = [];

  // Build a pubkey → KeyFile map; unknown pubkeys synthesize a card.
  const keyByPubkey = new Map<Pubkey, KeyFile>();
  for (const k of keys) keyByPubkey.set(k.pubkey, k);

  // v2: project metadata lives inline on a from-scratch (root) mandate;
  // there is no RootPolicy. Surface the first one we can verify.
  let projectName = "(unnamed project)";

  const tracks: TrackView[] = [];
  const trackNames = Object.keys(mandates).sort();

  for (const trackName of trackNames) {
    const trackMandates = mandates[trackName] ?? [];
    let chain: VerifiedChain;
    try {
      chain = verifyTrackChain(trackMandates);
    } catch (err) {
      alarms.push({
        level: "red",
        kind: "chain-gap",
        track: trackName,
        message: `Forward verification threw on "${trackName}"`,
        detail: err instanceof Error ? err.message : String(err),
      });
      tracks.push({
        track: trackName,
        current: null,
        successors: [],
        lastExpired: null,
        recentMandates: [],
        rejections: [],
      });
      continue;
    }

    if (chain.root === null) {
      // L1 fail-closed (no-pin / pin-not-in-log / malformed root).
      alarms.push({
        level: "red",
        kind: "chain-gap",
        track: trackName,
        message: `Track "${trackName}" could not be anchored`,
        detail: chain.rootError ?? "no forward chain",
      });
      tracks.push({
        track: trackName,
        current: null,
        successors: [],
        lastExpired: null,
        recentMandates: [],
        rejections: chain.rejections,
      });
      continue;
    }

    // Project name from the first root mandate that carries it.
    if (projectName === "(unnamed project)" && chain.root.project?.name) {
      projectName = chain.root.project.name;
    }

    const auth = currentAuthority(chain, now);
    const last: Mandate | null =
      chain.validMandates[chain.validMandates.length - 1] ?? null;
    const expired = !auth ? last : null;

    // Detect takeover: a valid mandate signed by someone other than the
    // prior holder (v2 succession is the single mechanism — no
    // holder-in-window/after-expiry split).
    const takeover = detectTakeover(chain.validMandates, keyByPubkey);
    if (takeover) {
      alarms.push({
        level: "red",
        kind: "takeover",
        track: trackName,
        message: `Track "${trackName}" was taken over by a successor.`,
        detail: `Previous holder: ${takeover.previousHolder.displayName} <${takeover.previousHolder.email}> → new holder: ${takeover.newHolder.displayName} <${takeover.newHolder.email}>`,
        contactEmails: [takeover.previousHolder.email, takeover.newHolder.email].filter(Boolean),
      });
    }

    if (auth) {
      const expiresInMs = Date.parse(auth.mandate.expiresAt) - now.getTime();
      if (expiresInMs < EXPIRY_SOON_MS) {
        const holderCard = personFromKey(auth.holder, keyByPubkey);
        alarms.push({
          level: "yellow",
          kind: "expiring-soon",
          track: trackName,
          message: `Track "${trackName}" mandate expires in ${formatDuration(expiresInMs)}`,
          contactEmails: holderCard.email ? [holderCard.email] : [],
        });
      }
    }

    for (const rej of chain.rejections) {
      alarms.push({
        level: "red",
        kind: "chain-gap",
        track: trackName,
        message: `Rejected mandate ${rej.mandate.mandateId.slice(0, 8)}…: ${rej.reason}`,
        detail: rej.detail,
      });
    }

    tracks.push({
      track: trackName,
      current: auth
        ? {
            holder: personFromKey(auth.holder, keyByPubkey),
            mandate: auth.mandate,
            expiresAt: auth.mandate.expiresAt,
            expiresInMs: Date.parse(auth.mandate.expiresAt) - now.getTime(),
          }
        : null,
      successors: auth
        ? auth.successors.map((pk) => personFromKey(pk, keyByPubkey))
        : (expired?.successors.map((pk) => personFromKey(pk, keyByPubkey)) ?? []),
      lastExpired: expired,
      recentMandates: chain.validMandates.slice(-5).reverse(),
      rejections: chain.rejections,
    });
  }

  // Email-rotation banner: any KeyFile whose emailHistory grew in the
  // last 14 days. The history is sorted by `from`; the latest "to:null"
  // entry should have a `from` newer than the threshold to trigger.
  const ROTATION_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;
  for (const k of keys) {
    const live = k.emailHistory.find((e) => e.to === null);
    if (!live) continue;
    const fromMs = Date.parse(live.from);
    if (!isFinite(fromMs)) continue;
    if (now.getTime() - fromMs < ROTATION_WINDOW_MS && k.emailHistory.length > 1) {
      const previous = k.emailHistory.filter((e) => e.to !== null).at(-1);
      alarms.push({
        level: "yellow",
        kind: "email-rotation",
        message: `Key for ${k.displayName} rotated email recently`,
        detail: `From ${previous?.email ?? "(unknown)"} → ${live.email} at ${live.from}`,
        contactEmails: previous?.email ? [previous.email, live.email] : [live.email],
      });
    }
  }

  // Endorsements chain (release track if it has a valid chain).
  const releaseMandates = mandates["release"] ?? [];
  let endorsementRejections: ReturnType<typeof verifyChainOfEndorsements>["rejections"] = [];
  let recentEndorsements: ReleaseEndorsement[] = [];
  const policyPresent = tracks.some((t) => t.current !== null || t.lastExpired !== null);
  if (releaseMandates.length > 0 && endorsements.length > 0) {
    const releaseChain = verifyTrackChain(releaseMandates);
    const chain = verifyChainOfEndorsements(endorsements, releaseChain);
    endorsementRejections = chain.rejections;
    recentEndorsements = chain.validEndorsements.slice(-5).reverse();
    for (const rej of chain.rejections) {
      alarms.push({
        level: "red",
        kind: "chain-gap",
        message: `Endorsement ${rej.endorsement.semverTag} rejected: ${rej.reason}`,
        detail: rej.detail,
      });
    }
  }

  return {
    projectName,
    policyPresent,
    tracks,
    recentEndorsements,
    endorsementRejections,
    alarms,
    computedAt: now.getTime(),
  };
}

function personFromKey(pubkey: Pubkey, keyByPubkey: Map<Pubkey, KeyFile>): PersonCard {
  const k = keyByPubkey.get(pubkey);
  if (!k) {
    return {
      pubkey,
      displayName: `(unknown key ${pubkey.slice(0, 8)}…)`,
      email: "",
      photo: null,
      github: null,
      role: null,
    };
  }
  return {
    pubkey,
    displayName: k.displayName,
    email: k.currentEmail,
    photo: k.metadata.photo ?? null,
    github: k.metadata.github ?? null,
    role: k.metadata.role ?? null,
  };
}

/**
 * Detect the most recent takeover event in a track's valid mandates.
 * A takeover is when mandate[i].signedBy !== mandate[i-1].holder.
 * Returns the synthetic TakeoverAlarm (NOT signed) for UI display.
 */
function detectTakeover(
  validMandates: Mandate[],
  keyByPubkey: Map<Pubkey, KeyFile>,
): TakeoverAlarm | null {
  for (let i = validMandates.length - 1; i >= 1; i--) {
    const m = validMandates[i]!;
    const pred = validMandates[i - 1]!;
    if (m.signedBy !== pred.holder && m.holder !== pred.holder) {
      const prevPerson = personFromKey(pred.holder, keyByPubkey);
      const newPerson = personFromKey(m.holder, keyByPubkey);
      return {
        kind: "TakeoverAlarm",
        project: "",
        track: m.track,
        previousMandate: pred.mandateId,
        newMandate: m.mandateId,
        previousHolder: {
          displayName: prevPerson.displayName,
          email: prevPerson.email,
          pubkey: pred.holder,
        },
        newHolder: {
          displayName: newPerson.displayName,
          email: newPerson.email,
          pubkey: m.holder,
        },
        detectedAt: new Date().toISOString(),
      };
    }
  }
  return null;
}

export function formatDuration(ms: number): string {
  if (ms < 0) return "expired";
  const seconds = Math.floor(ms / 1000);
  const days = Math.floor(seconds / 86400);
  if (days >= 1) return `${days}d`;
  const hours = Math.floor(seconds / 3600);
  if (hours >= 1) return `${hours}h`;
  const mins = Math.floor(seconds / 60);
  if (mins >= 1) return `${mins}m`;
  return `${seconds}s`;
}

/** Exported for tests: forward-verify a track's v2 mandate log. */
export function _verifyChainForTest(mandates: Mandate[]): VerifiedChain {
  return verifyTrackChain(mandates);
}
