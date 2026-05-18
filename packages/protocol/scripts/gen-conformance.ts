/**
 * Conformance test-vector GENERATOR (the portable artifact, c5).
 *
 * Emits a language-agnostic, self-describing, DETERMINISTIC JSON vector
 * set under `maintainers/conformance/` — the primary portable artifact
 * a non-TS port (#9 webapp, #10 iOS/Android) is proven against. An
 * independent implementation is conformant IFF it produces the expected
 * verdict for EVERY vector, INCLUDING every fail-closed negative (so no
 * port can pass while silently weakening fail-closed).
 *
 * Determinism: fixed Ed25519 seeds, fixed ISO timestamps, fixed UUIDs.
 * Re-running the generator is byte-stable across runs (the
 * `scripts/bootstrap-flagship-maintainers.mjs` discipline). The
 * accompanying `tests/conformance.test.ts` regenerates, writes the
 * committed dir, asserts byte-stability, and asserts every vector's
 * `expect` against the LANDED verifier — it FAILS if any expected
 * reject silently turns into an accept.
 *
 * Each vector is self-contained. Field names reflect what the landed
 * verifier actually consumes/emits:
 *
 *   {
 *     "name": "...",
 *     "description": "what this proves",
 *     "input": {
 *       "pin": "<hex|''>",
 *       "now": "<ISO8601 — the consumer's OWN clock>",
 *       "track": "<the track under assertion>",
 *       "mandatesByTrack": { "<track>": [ <Mandate>, ... ] },
 *       "endorsements":   [ <ReleaseEndorsement>, ... ],
 *       "caEndorsements": [ <CaEndorsement>, ... ]
 *     },
 *     "expect": {
 *       "accepted": <bool>,
 *       "rejectReason": "<exact landed reason | null>",
 *       "subject": "mandate-chain" | "release-endorsement" | "ca-endorsement",
 *       "track": "<track>"
 *     }
 *   }
 *
 * `subject` selects WHICH landed result the verdict is read from:
 *   - "mandate-chain": verifyMandateChainFromPin(pin, mandatesByTrack[track])
 *       → accepted iff currentAuthority(chain, now) !== null;
 *         rejectReason = chain.rootError (L1) ?? first chain.rejections[].reason
 *         ?? "no-authority-at-now".
 *   - "release-endorsement": verifyChainOfEndorsements over the release
 *       track's chain → accepted iff zero rejections; rejectReason =
 *       first rejection's reason.
 *   - "ca-endorsement": verifyCaEndorsements at `now` over the ca track's
 *       chain → accepted iff zero rejections; rejectReason = first
 *       rejection's reason.
 *
 * The schema is documented in docs/spec/v1.md §12 (Conformance) and is
 * exercised verbatim by tests/conformance.test.ts.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { generateKeypair, intermediateMerkleRoot } from "../src/crypto.js";
import {
  signMandate,
  signReleaseEndorsement,
  signCaEndorsement,
} from "../src/signing.js";
import { mandatePinHash } from "../src/canonical.js";
import type {
  CaEndorsement,
  Mandate,
  ReleaseEndorsement,
} from "../src/types.js";

// ---------------------------------------------------------------------------
// Deterministic key material + fixed clock constants.
// ---------------------------------------------------------------------------

function kp(seedByte: number): { privKey: string; pubKey: string } {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

const founder = kp(1);
const backup = kp(2);
const alice = kp(3);
const bob = kp(4);
const carol = kp(5);
const eve = kp(99);

const DAY = 86_400;
const HOT_CA = "ab".repeat(32);

// ---------------------------------------------------------------------------
// Vector schema (mirrors docs/spec/v1.md §12).
// ---------------------------------------------------------------------------

export type ConformanceSubject =
  | "mandate-chain"
  | "release-endorsement"
  | "ca-endorsement";

export interface ConformanceVector {
  name: string;
  description: string;
  input: {
    pin: string;
    now: string;
    track: string;
    mandatesByTrack: Record<string, Mandate[]>;
    endorsements: ReleaseEndorsement[];
    caEndorsements: CaEndorsement[];
  };
  expect: {
    accepted: boolean;
    rejectReason: string | null;
    subject: ConformanceSubject;
    track: string;
  };
}

interface MkOpts {
  id: string;
  track?: string;
  holder: string;
  issuedAt: string;
  expiresAt: string;
  successors: string[];
  threshold?: number;
  minSuccessors?: number;
  maxDurationSeconds?: number;
  defaultDurationSeconds?: number;
  project?: Mandate["project"];
  signedBy: string;
  signWith: string[];
}

function mk(o: MkOpts): Mandate {
  const unsigned: Omit<Mandate, "signatures"> = {
    kind: "Mandate",
    version: 1,
    mandateId: o.id,
    track: o.track ?? "release",
    holder: o.holder,
    issuedAt: o.issuedAt,
    expiresAt: o.expiresAt,
    successors: o.successors,
    approvalRule: { kind: "threshold", threshold: o.threshold ?? 1 },
    minSuccessors: o.minSuccessors ?? 1,
    maxDurationSeconds: o.maxDurationSeconds ?? 60 * DAY,
    defaultDurationSeconds: o.defaultDurationSeconds ?? 60 * DAY,
    ...(o.project ? { project: o.project } : {}),
    signedBy: o.signedBy,
  };
  return signMandate(
    unsigned,
    o.signWith.map((privKey) => ({ privKey })),
  );
}

/** A from-scratch (root) mandate: self-signed by founder, project set. */
function root(over: Partial<MkOpts> = {}): Mandate {
  return mk({
    id: "00000000-0000-4000-8000-000000000000",
    holder: founder.pubKey,
    issuedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2026-03-02T00:00:00Z", // 60d
    successors: [founder.pubKey, backup.pubKey],
    threshold: 1,
    minSuccessors: 1,
    maxDurationSeconds: 60 * DAY,
    project: {
      name: "conformance-fixture",
      contact: "security@example.org",
      tracks: ["release", "ca"],
    },
    signedBy: founder.pubKey,
    signWith: [founder.privKey],
    ...over,
  });
}

const HASH = (n: number): string =>
  n.toString(16).padStart(2, "0").repeat(20); // 40 hex

interface MkEndo {
  releaseId: string;
  semverTag: string;
  commitHash: string;
  intermediateCommits: string[];
  previousReleaseId: string | null;
  previousCommitHash: string | null;
  issuedAt: string;
  signedBy?: string;
}

function mkEndorsement(
  signer: { privKey: string; pubKey: string },
  o: MkEndo,
): ReleaseEndorsement {
  return signReleaseEndorsement(
    {
      kind: "ReleaseEndorsement",
      version: 1,
      releaseId: o.releaseId,
      semverTag: o.semverTag,
      commitHash: o.commitHash,
      previousReleaseId: o.previousReleaseId,
      previousCommitHash: o.previousCommitHash,
      intermediateCommits: o.intermediateCommits,
      intermediateMerkleRoot: intermediateMerkleRoot(o.intermediateCommits),
      endorsedNotes: null,
      issuedAt: o.issuedAt,
      signedBy: o.signedBy ?? signer.pubKey,
    },
    [{ privKey: signer.privKey }],
  );
}

function mkCa(
  signer: { privKey: string; pubKey: string },
  o: Partial<CaEndorsement> & { caPubkey: string },
): CaEndorsement {
  return signCaEndorsement(
    {
      kind: "CaEndorsement",
      version: 1,
      endorsementId: o.endorsementId ?? "ca-e1",
      track: "ca",
      caPubkey: o.caPubkey,
      scope: o.scope ?? "flagship/directory-attestation",
      notBefore: o.notBefore ?? "2026-03-01T00:00:00Z",
      notAfter: o.notAfter ?? "2026-03-08T00:00:00Z",
      issuedAt: o.issuedAt ?? "2026-03-01T00:00:00Z",
      signedBy: signer.pubKey,
    },
    [{ privKey: signer.privKey }],
  );
}

// ---------------------------------------------------------------------------
// The vectors.  Happy paths + EVERY mandatory fail-closed negative.
// ---------------------------------------------------------------------------

export function buildConformanceVectors(): ConformanceVector[] {
  const v: ConformanceVector[] = [];

  // ---- HAPPY PATHS -------------------------------------------------------

  {
    const r = root();
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: founder.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [founder.pubKey, backup.pubKey],
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    v.push({
      name: "happy-solo-founder-renewal",
      description:
        "Solo-founder renewal chain pinned at the root; at a `now` inside k1's window a live authority exists ⇒ accepted.",
      input: {
        pin: mandatePinHash(r),
        now: "2026-04-01T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [r, k1] },
        endorsements: [],
        caEndorsements: [],
      },
      expect: {
        accepted: true,
        rejectReason: null,
        subject: "mandate-chain",
        track: "release",
      },
    });
  }

  {
    const r = root({
      successors: [alice.pubKey, bob.pubKey, carol.pubKey],
      threshold: 2,
      minSuccessors: 1,
    });
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [alice.pubKey],
      signedBy: alice.pubKey,
      signWith: [alice.privKey, bob.privKey], // 2-of-3 satisfied
    });
    v.push({
      name: "happy-2-of-3-threshold",
      description:
        "A 2-of-3 threshold is satisfied by any two named successors ⇒ the successor chain is accepted.",
      input: {
        pin: mandatePinHash(r),
        now: "2026-03-01T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [r, k1] },
        endorsements: [],
        caEndorsements: [],
      },
      expect: {
        accepted: true,
        rejectReason: null,
        subject: "mandate-chain",
        track: "release",
      },
    });
  }

  {
    // Happy ReleaseEndorsement: signed by the v2 holder, in-window.
    const r = mk({
      id: "00000000-0000-4000-8000-0000000000e0",
      holder: founder.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2027-01-01T00:00:00Z",
      successors: [founder.pubKey, alice.pubKey],
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    const e = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
      issuedAt: "2026-02-01T00:00:00Z",
    });
    v.push({
      name: "happy-release-endorsement-holder-signed",
      description:
        "A genesis ReleaseEndorsement signed by the v2 release-track holder, issuedAt inside the mandate window ⇒ accepted.",
      input: {
        pin: mandatePinHash(r),
        now: "2026-02-02T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [r] },
        endorsements: [e],
        caEndorsements: [],
      },
      expect: {
        accepted: true,
        rejectReason: null,
        subject: "release-endorsement",
        track: "release",
      },
    });
  }

  {
    // Happy CaEndorsement: lease contains the caller's own `now`.
    const caRoot = mk({
      id: "00000000-0000-4000-8000-0000000000ca",
      track: "ca",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-06-01T00:00:00Z",
      successors: [backup.pubKey],
      maxDurationSeconds: 365 * DAY,
      defaultDurationSeconds: 180 * DAY,
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const ca = mkCa(alice, { caPubkey: HOT_CA });
    v.push({
      name: "happy-ca-endorsement-fresh-lease",
      description:
        "An in-window CaEndorsement signed by the v2 ca-track holder, the lease [notBefore,notAfter) containing the caller's own NOW ⇒ accepted (D3 freshness).",
      input: {
        pin: mandatePinHash(caRoot),
        now: "2026-03-04T00:00:00Z",
        track: "ca",
        mandatesByTrack: { ca: [caRoot] },
        endorsements: [],
        caEndorsements: [ca],
      },
      expect: {
        accepted: true,
        rejectReason: null,
        subject: "ca-endorsement",
        track: "ca",
      },
    });
  }

  // ---- MANDATORY FAIL-CLOSED NEGATIVES (1..10) ---------------------------

  // (1) absent/empty baked pin ⇒ reject (no-pin). [verifier.ts]
  {
    const r = root();
    v.push({
      name: "neg-1-absent-pin",
      description:
        "No baked pin (empty string) ⇒ verifyMandateChainFromPin yields rootError 'no-pin' ⇒ no authority ⇒ reject (the #30 invariant, generalised).",
      input: {
        pin: "",
        now: "2026-01-10T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [r] },
        endorsements: [],
        caEndorsements: [],
      },
      expect: {
        accepted: false,
        rejectReason: "no-pin",
        subject: "mandate-chain",
        track: "release",
      },
    });
  }

  // (2) forked/unknown pin (pin not anchoring any on-log mandate). [verifier.ts]
  {
    const r = root();
    const other = root({ id: "ffffffff-0000-4000-8000-000000000000" });
    v.push({
      name: "neg-2-forked-unknown-pin",
      description:
        "A pin that matches no mandate's canonical hash in the served log ⇒ rootError 'pin-not-in-log' ⇒ reject (forked/unknown pin).",
      input: {
        pin: mandatePinHash(other),
        now: "2026-01-10T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [r] },
        endorsements: [],
        caEndorsements: [],
      },
      expect: {
        accepted: false,
        rejectReason: "pin-not-in-log",
        subject: "mandate-chain",
        track: "release",
      },
    });
  }

  // (3) pin-not-in-log via tampered bytes (post-sign mutation no longer
  //     hashes to the pin). [verifier.ts]
  {
    const r = root();
    const pin = mandatePinHash(r);
    const tampered: Mandate = { ...r, holder: eve.pubKey }; // bytes changed; pin no longer matches
    v.push({
      name: "neg-3-pin-not-in-log-tampered-bytes",
      description:
        "A mandate mutated after signing no longer hashes to the baked pin (SHA-256 binds exact canonical bytes) ⇒ rootError 'pin-not-in-log' ⇒ reject.",
      input: {
        pin,
        now: "2026-01-10T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [tampered] },
        endorsements: [],
        caEndorsements: [],
      },
      expect: {
        accepted: false,
        rejectReason: "pin-not-in-log",
        subject: "mandate-chain",
        track: "release",
      },
    });
  }

  // (4) self-renewal attempt: holder not in predecessor.successors. [verifier.ts]
  {
    const r = root({ successors: [backup.pubKey], threshold: 1 }); // founder NOT a successor
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: founder.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [backup.pubKey],
      signedBy: founder.pubKey,
      signWith: [founder.privKey], // the holder trying to extend itself
    });
    v.push({
      name: "neg-4-self-renewal-attempt",
      description:
        "There is NO privileged self-renewal: a successor mandate signed only by the prior holder, who is NOT in the predecessor's `successors` set ⇒ forward step rejects 'signer-not-in-successor-set'; only the root remains ⇒ no live authority at `now` ⇒ reject.",
      input: {
        pin: mandatePinHash(r),
        // After the root window (root expires 2026-03-02) AND after the
        // rejected successor's would-be window: only the root could be
        // authority, it has lapsed, and the bad successor is rejected ⇒
        // a real consumer at this `now` fails closed with the specific
        // forward-step reason.
        now: "2026-05-01T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [r, k1] },
        endorsements: [],
        caEndorsements: [],
      },
      expect: {
        accepted: false,
        rejectReason: "signer-not-in-successor-set",
        subject: "mandate-chain",
        track: "release",
      },
    });
  }

  // (5) sub-threshold signers (< approvalRule.threshold). [verifier.ts]
  {
    const r = root({
      successors: [alice.pubKey, bob.pubKey, carol.pubKey],
      threshold: 2,
    });
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [alice.pubKey],
      signedBy: alice.pubKey,
      signWith: [alice.privKey], // only 1 of the required 2
    });
    v.push({
      name: "neg-5-sub-threshold-signers",
      description:
        "Fewer distinct predecessor-successor signatures than `approvalRule.threshold` ⇒ forward step rejects 'approval-threshold-unmet'; the successor is dropped ⇒ reject at `now` past the root window.",
      input: {
        pin: mandatePinHash(r),
        // Past the root window; the sub-threshold successor is dropped ⇒
        // no live authority ⇒ fail closed with the threshold reason.
        now: "2026-05-01T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [r, k1] },
        endorsements: [],
        caEndorsements: [],
      },
      expect: {
        accepted: false,
        rejectReason: "approval-threshold-unmet",
        subject: "mandate-chain",
        track: "release",
      },
    });
  }

  // (6) under-minSuccessors (K+1.successors.length < K.minSuccessors). [verifier.ts]
  {
    const r = root({
      minSuccessors: 2,
      successors: [founder.pubKey, backup.pubKey],
    });
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: founder.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [founder.pubKey], // only 1, need >= 2
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    v.push({
      name: "neg-6-under-min-successors",
      description:
        "K+1.successors.length < K.minSuccessors (anti-rubber-hose floor) ⇒ forward step rejects 'under-min-successors' ⇒ reject.",
      input: {
        pin: mandatePinHash(r),
        // Past the root window; the under-minSuccessors successor is
        // dropped ⇒ no live authority ⇒ fail closed with that reason.
        now: "2026-05-01T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [r, k1] },
        endorsements: [],
        caEndorsements: [],
      },
      expect: {
        accepted: false,
        rejectReason: "under-min-successors",
        subject: "mandate-chain",
        track: "release",
      },
    });
  }

  // (7) over-maxDuration (K+1 window > K.maxDurationSeconds). [verifier.ts]
  {
    const r = root({ maxDurationSeconds: 30 * DAY });
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: founder.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-16T00:00:00Z", // 60d > 30d cap
      successors: [founder.pubKey],
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    v.push({
      name: "neg-7-over-max-duration",
      description:
        "K+1's window exceeds K.maxDurationSeconds ⇒ forward step rejects 'over-max-duration' ⇒ reject.",
      input: {
        pin: mandatePinHash(r),
        // Past the root window; the over-maxDuration successor is
        // dropped ⇒ no live authority ⇒ fail closed with that reason.
        now: "2026-05-01T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [r, k1] },
        endorsements: [],
        caEndorsements: [],
      },
      expect: {
        accepted: false,
        rejectReason: "over-max-duration",
        subject: "mandate-chain",
        track: "release",
      },
    });
  }

  // (8) endorsement-gap: a missing/substituted intermediate
  //     ReleaseEndorsement (predecessor mismatch). [endorsement.ts]
  {
    const r = mk({
      id: "00000000-0000-4000-8000-0000000000e8",
      holder: founder.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2027-01-01T00:00:00Z",
      successors: [founder.pubKey],
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    const e1 = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
      issuedAt: "2026-02-01T00:00:00Z",
    });
    // e2 points at a previousReleaseId that is NOT e1 (a substituted /
    // skipped intermediate endorsement).
    const e2 = mkEndorsement(founder, {
      releaseId: "r3",
      semverTag: "v0.3.0",
      commitHash: HASH(3),
      intermediateCommits: [HASH(1)],
      previousReleaseId: "r2-MISSING",
      previousCommitHash: HASH(2),
      issuedAt: "2026-03-01T00:00:00Z",
    });
    v.push({
      name: "neg-8-endorsement-gap",
      description:
        "A ReleaseEndorsement whose previousReleaseId/previousCommitHash do not match the prior accepted endorsement (a missing/substituted intermediate) ⇒ verifyChainOfEndorsements rejects 'predecessor-mismatch'.",
      input: {
        pin: mandatePinHash(r),
        now: "2026-03-02T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [r] },
        endorsements: [e1, e2],
        caEndorsements: [],
      },
      expect: {
        accepted: false,
        rejectReason: "predecessor-mismatch",
        subject: "release-endorsement",
        track: "release",
      },
    });
  }

  // (9) lapsed-lease-at-NOW: newest CaEndorsement lease does NOT contain
  //     the consumer's own `now`. [caEndorsement.ts]
  {
    const caRoot = mk({
      id: "00000000-0000-4000-8000-0000000000c9",
      track: "ca",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-12-01T00:00:00Z",
      successors: [backup.pubKey],
      maxDurationSeconds: 365 * DAY,
      defaultDurationSeconds: 180 * DAY,
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const ca = mkCa(alice, {
      caPubkey: HOT_CA,
      notBefore: "2026-03-01T00:00:00Z",
      notAfter: "2026-03-08T00:00:00Z",
    });
    v.push({
      name: "neg-9-lapsed-lease-at-now",
      description:
        "The CaEndorsement lease window [notBefore,notAfter) does NOT contain the consumer's own NOW (host withheld the next lease) ⇒ verifyCaEndorsements rejects 'lease-expired' at the caller's clock (D3 — fail-closed within one window).",
      input: {
        pin: mandatePinHash(caRoot),
        now: "2026-04-01T00:00:00Z", // well after notAfter (skew is ±5min)
        track: "ca",
        mandatesByTrack: { ca: [caRoot] },
        endorsements: [],
        caEndorsements: [ca],
      },
      expect: {
        accepted: false,
        rejectReason: "lease-expired",
        subject: "ca-endorsement",
        track: "ca",
      },
    });
  }

  // (10a) rolled-back history: an intermediate mandate dropped so the
  //       suffix no longer chains to its real predecessor. [verifier.ts]
  {
    const r = root({ successors: [founder.pubKey], threshold: 1, minSuccessors: 1 });
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [alice.pubKey], // only `alice` may sign k2
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    const k2 = mk({
      id: "00000000-0000-4000-8000-000000000002",
      holder: alice.pubKey,
      issuedAt: "2026-04-10T00:00:00Z",
      expiresAt: "2026-06-09T00:00:00Z",
      successors: [alice.pubKey],
      signedBy: alice.pubKey,
      signWith: [alice.privKey], // valid only w.r.t. k1.successors, NOT root.successors
    });
    // Server drops k1 and serves only [r, k2]: k2's predecessor is now
    // root, whose successors are [founder]; alice ∉ that set ⇒ reject.
    v.push({
      name: "neg-10a-rolled-back-dropped-intermediate",
      description:
        "Dropping an intermediate mandate so the suffix re-chains to the wrong predecessor is detected: k2 signed by `alice` is not in root.successors ⇒ rejects 'signer-not-in-successor-set'; at `now` past the root window there is no live authority ⇒ reject.",
      input: {
        pin: mandatePinHash(r),
        now: "2026-05-01T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [r, k2] },
        endorsements: [],
        caEndorsements: [],
      },
      expect: {
        accepted: false,
        rejectReason: "signer-not-in-successor-set",
        subject: "mandate-chain",
        track: "release",
      },
    });
  }

  // (10b) tampered history: the pinned root's signed bytes were mutated
  //       in a signature-invalidating way while keeping the pin matching
  //       (pin is content-bound, so we tamper the SIGNATURE). [verifier.ts]
  {
    const r = root();
    const pin = mandatePinHash(r); // content-bound ⇒ still matches
    const badSig: Mandate = {
      ...r,
      signatures: [{ pubkey: founder.pubKey, sig: "00".repeat(64) }],
    };
    v.push({
      name: "neg-10b-tampered-root-signature",
      description:
        "A pinned root whose declared signature was replaced with a forged one (pin still matches — it binds content, not signatures) ⇒ the root self-validity check rejects rootError 'root-signature-invalid' ⇒ reject.",
      input: {
        pin,
        now: "2026-01-10T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [badSig] },
        endorsements: [],
        caEndorsements: [],
      },
      expect: {
        accepted: false,
        rejectReason: "root-signature-invalid",
        subject: "mandate-chain",
        track: "release",
      },
    });
  }

  // ---- Extra fail-closed coverage (totality / cross-cutting) -------------

  {
    // Totality: an adversarial non-canonicalizable mandate in the suffix
    // is recorded as a rejection, never an exception.
    const r = root({ successors: [founder.pubKey] });
    const evil = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: founder.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [founder.pubKey],
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    const poisoned: Mandate = { ...evil, holder: "zz" + "00".repeat(31) };
    v.push({
      name: "neg-totality-adversarial-canonicalization",
      description:
        "A non-hex holder injected after signing reaches the forward step; canonicalization throws internally and MUST be caught (totality) ⇒ recorded as a 'signature-invalid' rejection, never an exception; only the root remains ⇒ reject at `now` past the root window.",
      input: {
        pin: mandatePinHash(r),
        now: "2026-05-01T00:00:00Z",
        track: "release",
        mandatesByTrack: { release: [r, poisoned] },
        endorsements: [],
        caEndorsements: [],
      },
      expect: {
        accepted: false,
        rejectReason: "signature-invalid",
        subject: "mandate-chain",
        track: "release",
      },
    });
  }

  {
    // CA fail-closed: an absent pin on the ca track ⇒ no ca authority at
    // now ⇒ every lease rejected 'no-ca-authority-at-now'.
    const caRoot = mk({
      id: "00000000-0000-4000-8000-0000000000cb",
      track: "ca",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-06-01T00:00:00Z",
      successors: [backup.pubKey],
      maxDurationSeconds: 365 * DAY,
      defaultDurationSeconds: 180 * DAY,
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const ca = mkCa(alice, { caPubkey: HOT_CA });
    v.push({
      name: "neg-ca-no-pin-fail-closed",
      description:
        "An absent baked pin on the ca track ⇒ the chain never anchors ⇒ no ca authority at NOW ⇒ verifyCaEndorsements rejects 'no-ca-authority-at-now' even though the lease window itself contains NOW (fail-closed; never a fall-back to a previously-seen key).",
      input: {
        pin: "",
        now: "2026-03-04T00:00:00Z",
        track: "ca",
        mandatesByTrack: { ca: [caRoot] },
        endorsements: [],
        caEndorsements: [ca],
      },
      expect: {
        accepted: false,
        rejectReason: "no-ca-authority-at-now",
        subject: "ca-endorsement",
        track: "ca",
      },
    });
  }

  return v;
}

// ---------------------------------------------------------------------------
// Filesystem emission (the committed portable artifact).
// ---------------------------------------------------------------------------

const HERE = path.dirname(fileURLToPath(import.meta.url));
// scripts/ -> packages/protocol -> packages -> <maintainers repo root>
export const CONFORMANCE_DIR = path.resolve(HERE, "..", "..", "..", "conformance");

/** Deterministic, sorted, 2-space JSON + trailing newline (commit-clean). */
function stableJson(value: unknown): string {
  return JSON.stringify(value, null, 2) + "\n";
}

export interface ConformanceManifest {
  schemaVersion: 1;
  description: string;
  count: number;
  vectors: { name: string; file: string; subject: ConformanceSubject; accepted: boolean; rejectReason: string | null }[];
}

/**
 * Write the vector set + a manifest to `maintainers/conformance/`.
 * Returns the list of repo-relative paths written. Idempotent / byte
 * stable: identical inputs ⇒ identical bytes (verified by the test).
 */
export function writeConformanceVectors(): string[] {
  const vectors = buildConformanceVectors();
  fs.mkdirSync(path.join(CONFORMANCE_DIR, "vectors"), { recursive: true });

  const written: string[] = [];
  for (const vec of vectors) {
    const file = path.join("vectors", `${vec.name}.json`);
    fs.writeFileSync(path.join(CONFORMANCE_DIR, file), stableJson(vec), "utf8");
    written.push(file);
  }

  const manifest: ConformanceManifest = {
    schemaVersion: 1,
    description:
      "Maintainers protocol conformance vectors. An implementation is conformant iff it produces the expected verdict for EVERY vector, including every fail-closed negative. Schema: docs/spec/v1.md §12.",
    count: vectors.length,
    vectors: vectors.map((vec) => ({
      name: vec.name,
      file: `vectors/${vec.name}.json`,
      subject: vec.expect.subject,
      accepted: vec.expect.accepted,
      rejectReason: vec.expect.rejectReason,
    })),
  };
  fs.writeFileSync(
    path.join(CONFORMANCE_DIR, "manifest.json"),
    stableJson(manifest),
    "utf8",
  );
  written.unshift("manifest.json");

  fs.writeFileSync(
    path.join(CONFORMANCE_DIR, "README.md"),
    [
      "# Maintainers protocol — conformance vectors",
      "",
      "Language-agnostic, deterministically-generated test vectors for the",
      "maintainers trust protocol. This directory is the **primary portable",
      "artifact** for non-TypeScript adopters (the webapp browser verifier,",
      "the iOS Swift port, the Android Kotlin port).",
      "",
      "An independent implementation is **conformant if and only if** it",
      "produces the expected verdict for **every** vector here — including",
      "**every fail-closed negative**. A port that accepts an input a",
      "negative vector expects to be rejected is NOT conformant (it has",
      "silently weakened fail-closed).",
      "",
      "## Layout",
      "",
      "- `manifest.json` — the index: every vector, its file, subject,",
      "  expected `accepted`, and the exact landed `rejectReason`.",
      "- `vectors/<name>.json` — one self-contained vector each.",
      "",
      "## Vector schema",
      "",
      "Defined normatively in",
      "[`maintainers/docs/spec/v1.md` §12 (Conformance)](../docs/spec/v1.md).",
      "Each vector is `{ name, description, input, expect }` where `input`",
      "is `{ pin, now, track, mandatesByTrack, endorsements,",
      "caEndorsements }` and `expect` is `{ accepted, rejectReason,",
      "subject, track }`.",
      "",
      "## Regeneration (deterministic)",
      "",
      "These files are generated by",
      "`packages/protocol/scripts/gen-conformance.ts` and asserted by",
      "`packages/protocol/tests/conformance.test.ts`. Regeneration is",
      "byte-stable (fixed seeds / timestamps / UUIDs). To regenerate, run",
      "the protocol test suite:",
      "",
      "```",
      "npx vitest run packages/protocol/tests/conformance.test.ts",
      "```",
      "",
      "The test rewrites this directory and FAILS if any expected reject",
      "silently turns into an accept, or if regeneration is not",
      "byte-identical.",
      "",
    ].join("\n"),
    "utf8",
  );
  written.unshift("README.md");

  return written;
}

const invokedDirectly =
  typeof process !== "undefined" &&
  Array.isArray(process.argv) &&
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  const files = writeConformanceVectors();
  // eslint-disable-next-line no-console
  console.log(`wrote ${files.length} files under ${CONFORMANCE_DIR}`);
}
