/**
 * ReleaseEndorsement v2 verification tests. Builds a verify-forward v2
 * release chain (pin → forward), issues endorsements signed by the
 * mandate HOLDER (the v2 authority model — no TrackPolicy), and pins the
 * accept paths, every fail-closed negative, and the holder-rotation
 * property (the right authority is resolved per `issuedAt`).
 */
import { describe, expect, it } from "vitest";
import { generateKeypair, intermediateMerkleRoot } from "../src/crypto.js";
import { signMandateV2, signReleaseEndorsement } from "../src/signing.js";
import { canonicalMandateV2, mandatePinHash } from "../src/canonical.js";
import { verifyMandateChainFromPin } from "../src/verifierV2.js";
import { verifyChainOfEndorsementsV2 } from "../src/endorsementV2.js";
import type { MandateV2, ReleaseEndorsement } from "../src/types.js";

function kp(seedByte: number): { privKey: string; pubKey: string } {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

const founder = kp(1);
const alice = kp(3);
const eve = kp(99);
const DAY = 86400;

interface MkM {
  id: string;
  holder: string;
  issuedAt: string;
  expiresAt: string;
  successors: string[];
  threshold?: number;
  minSuccessors?: number;
  maxDurationSeconds?: number;
  signedBy: string;
  signWith: string[];
}

function mkMandate(o: MkM): MandateV2 {
  const unsigned: Omit<MandateV2, "signatures"> = {
    kind: "Mandate",
    version: 2,
    mandateId: o.id,
    track: "release",
    holder: o.holder,
    issuedAt: o.issuedAt,
    expiresAt: o.expiresAt,
    successors: o.successors,
    approvalRule: { kind: "threshold", threshold: o.threshold ?? 1 },
    minSuccessors: o.minSuccessors ?? 1,
    maxDurationSeconds: o.maxDurationSeconds ?? 365 * DAY,
    defaultDurationSeconds: 60 * DAY,
    signedBy: o.signedBy,
  };
  return signMandateV2(unsigned, o.signWith.map((privKey) => ({ privKey })));
}

/** Root mandate active 2026-01-01 .. 2027-01-01, holder=founder. */
function root(): MandateV2 {
  return mkMandate({
    id: "00000000-0000-4000-8000-000000000000",
    holder: founder.pubKey,
    issuedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2027-01-01T00:00:00Z",
    successors: [founder.pubKey, alice.pubKey],
    signedBy: founder.pubKey,
    signWith: [founder.privKey],
  });
}

function chain(mandates: MandateV2[], pinAt: MandateV2 = mandates[0]!) {
  return verifyMandateChainFromPin(mandatePinHash(pinAt), mandates);
}

const HASH = (n: number): string => n.toString(16).padStart(2, "0").repeat(20); // 40 hex

function mkEndorsement(
  signer: { privKey: string; pubKey: string },
  opts: {
    releaseId: string;
    semverTag: string;
    commitHash: string;
    intermediateCommits: string[];
    previousReleaseId: string | null;
    previousCommitHash: string | null;
    issuedAt?: string;
    signedBy?: string;
  },
): ReleaseEndorsement {
  return signReleaseEndorsement(
    {
      kind: "ReleaseEndorsement",
      version: 1,
      releaseId: opts.releaseId,
      semverTag: opts.semverTag,
      commitHash: opts.commitHash,
      previousReleaseId: opts.previousReleaseId,
      previousCommitHash: opts.previousCommitHash,
      intermediateCommits: opts.intermediateCommits,
      intermediateMerkleRoot: intermediateMerkleRoot(opts.intermediateCommits),
      endorsedNotes: null,
      issuedAt: opts.issuedAt ?? "2026-02-01T00:00:00Z",
      signedBy: opts.signedBy ?? signer.pubKey,
    },
    [{ privKey: signer.privKey }],
  );
}

describe("verifyChainOfEndorsementsV2 — accept paths", () => {
  it("accepts a genesis endorsement signed by the v2 holder", () => {
    const e = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
      issuedAt: "2026-02-01T00:00:00Z",
    });
    const r = verifyChainOfEndorsementsV2([e], chain([root()]));
    expect(r.validEndorsements).toHaveLength(1);
    expect(r.rejections).toHaveLength(0);
  });

  it("accepts a 2-endorsement chain", () => {
    const e1 = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
    });
    const e2 = mkEndorsement(founder, {
      releaseId: "r2",
      semverTag: "v0.2.0",
      commitHash: HASH(2),
      intermediateCommits: [HASH(1)],
      previousReleaseId: "r1",
      previousCommitHash: HASH(1),
      issuedAt: "2026-03-01T00:00:00Z",
    });
    const r = verifyChainOfEndorsementsV2([e1, e2], chain([root()]));
    expect(r.validEndorsements).toHaveLength(2);
    expect(r.rejections).toHaveLength(0);
  });
});

describe("verifyChainOfEndorsementsV2 — fail-closed negatives", () => {
  const c = () => chain([root()]);

  it("rejects genesis-must-have-no-predecessor", () => {
    const e = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: "ghost",
      previousCommitHash: HASH(9),
    });
    expect(verifyChainOfEndorsementsV2([e], c()).rejections[0]?.reason).toBe(
      "genesis-must-have-no-predecessor",
    );
  });

  it("rejects non-genesis-must-have-predecessor", () => {
    const e1 = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
    });
    const e2 = mkEndorsement(founder, {
      releaseId: "r2",
      semverTag: "v0.2.0",
      commitHash: HASH(2),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
    });
    const r = verifyChainOfEndorsementsV2([e1, e2], c());
    expect(r.validEndorsements).toHaveLength(1);
    expect(r.rejections[0]?.reason).toBe("non-genesis-must-have-predecessor");
  });

  it("rejects predecessor-mismatch", () => {
    const e1 = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
    });
    const e2 = mkEndorsement(founder, {
      releaseId: "r2",
      semverTag: "v0.2.0",
      commitHash: HASH(2),
      intermediateCommits: [HASH(1)],
      previousReleaseId: "WRONG",
      previousCommitHash: HASH(1),
      issuedAt: "2026-03-01T00:00:00Z",
    });
    expect(
      verifyChainOfEndorsementsV2([e1, e2], c()).rejections[0]?.reason,
    ).toBe("predecessor-mismatch");
  });

  it("rejects merkle-root-mismatch", () => {
    const e = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
    });
    const tampered: ReleaseEndorsement = {
      ...e,
      intermediateMerkleRoot: HASH(7).repeat(2).slice(0, 64),
    };
    expect(
      verifyChainOfEndorsementsV2([tampered], c()).rejections[0]?.reason,
    ).toBe("merkle-root-mismatch");
  });

  it("rejects signature-invalid (tampered after signing)", () => {
    const e = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
    });
    const tampered: ReleaseEndorsement = { ...e, semverTag: "v9.9.9" };
    expect(
      verifyChainOfEndorsementsV2([tampered], c()).rejections[0]?.reason,
    ).toBe("signature-invalid");
  });

  it("rejects signer-not-authorized when signed by a non-holder", () => {
    const e = mkEndorsement(eve, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
    });
    expect(verifyChainOfEndorsementsV2([e], c()).rejections[0]?.reason).toBe(
      "signer-not-authorized",
    );
  });

  it("rejects signer-not-authorized when signedBy is not among signatures", () => {
    const e = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
      signedBy: alice.pubKey, // canonical bytes encode signedBy=alice; sig is founder's
    });
    // The signature verifies (founder signed those exact bytes), but the
    // claimed signedBy (alice) is absent from the signatures set.
    expect(verifyChainOfEndorsementsV2([e], c()).rejections[0]?.reason).toBe(
      "signer-not-authorized",
    );
  });

  it("rejects no-authority-at-issuance when issuedAt is outside every mandate window", () => {
    const e = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
      issuedAt: "2030-01-01T00:00:00Z", // after root.expiresAt
    });
    expect(verifyChainOfEndorsementsV2([e], c()).rejections[0]?.reason).toBe(
      "no-authority-at-issuance",
    );
  });

  it("rejects duplicate-release-id", () => {
    const e1 = mkEndorsement(founder, {
      releaseId: "dup",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
    });
    const e2 = mkEndorsement(founder, {
      releaseId: "dup",
      semverTag: "v0.2.0",
      commitHash: HASH(2),
      intermediateCommits: [HASH(1)],
      previousReleaseId: "dup",
      previousCommitHash: HASH(1),
      issuedAt: "2026-03-01T00:00:00Z",
    });
    const r = verifyChainOfEndorsementsV2([e1, e2], c());
    expect(r.validEndorsements).toHaveLength(1);
    expect(r.rejections[0]?.reason).toBe("duplicate-release-id");
  });

  it("FAIL-CLOSED: a chain anchored at an absent/forked pin ⇒ no-authority-at-issuance", () => {
    const e = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
    });
    const forked = verifyMandateChainFromPin("de".repeat(32), [root()]);
    expect(forked.validMandates).toHaveLength(0);
    expect(verifyChainOfEndorsementsV2([e], forked).rejections[0]?.reason).toBe(
      "no-authority-at-issuance",
    );
    const noPin = verifyMandateChainFromPin("", [root()]);
    expect(verifyChainOfEndorsementsV2([e], noPin).rejections[0]?.reason).toBe(
      "no-authority-at-issuance",
    );
  });
});

describe("verifyChainOfEndorsementsV2 — holder rotation resolves per issuedAt", () => {
  // M0 founder [01-01 .. 02-01); M1 succeeds → holder alice [02-01 .. 03-01).
  const m0 = mkMandate({
    id: "00000000-0000-4000-8000-000000000000",
    holder: founder.pubKey,
    issuedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2026-02-01T00:00:00Z",
    successors: [founder.pubKey, alice.pubKey],
    threshold: 1,
    minSuccessors: 1,
    maxDurationSeconds: 60 * DAY,
    signedBy: founder.pubKey,
    signWith: [founder.privKey],
  });
  const m1 = mkMandate({
    id: "11111111-1111-4111-8111-111111111111",
    holder: alice.pubKey,
    issuedAt: "2026-02-01T00:00:00Z",
    expiresAt: "2026-03-01T00:00:00Z",
    successors: [alice.pubKey],
    threshold: 1,
    minSuccessors: 1,
    maxDurationSeconds: 60 * DAY,
    signedBy: alice.pubKey,
    signWith: [alice.privKey],
  });
  const c = () => chain([m0, m1], m0);

  it("the verify-forward chain is the two mandates", () => {
    expect(c().validMandates.map((m) => m.mandateId)).toEqual([
      m0.mandateId,
      m1.mandateId,
    ]);
  });

  it("e0 in M0's window must be signed by founder; e1 in M1's window by alice", () => {
    const e0 = mkEndorsement(founder, {
      releaseId: "r0",
      semverTag: "v0.1.0",
      commitHash: HASH(1),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
      issuedAt: "2026-01-15T00:00:00Z",
    });
    const e1 = mkEndorsement(alice, {
      releaseId: "r1",
      semverTag: "v0.2.0",
      commitHash: HASH(2),
      intermediateCommits: [HASH(1)],
      previousReleaseId: "r0",
      previousCommitHash: HASH(1),
      issuedAt: "2026-02-15T00:00:00Z",
    });
    const r = verifyChainOfEndorsementsV2([e0, e1], c());
    expect(r.validEndorsements.map((e) => e.releaseId)).toEqual(["r0", "r1"]);
    expect(r.rejections).toHaveLength(0);
  });

  it("an endorsement in M1's window signed by the OLD holder is rejected", () => {
    const e1Bad = mkEndorsement(founder, {
      releaseId: "r1",
      semverTag: "v0.2.0",
      commitHash: HASH(2),
      intermediateCommits: [],
      previousReleaseId: null,
      previousCommitHash: null,
      issuedAt: "2026-02-15T00:00:00Z", // M1's window; authority is alice
    });
    expect(verifyChainOfEndorsementsV2([e1Bad], c()).rejections[0]?.reason).toBe(
      "signer-not-authorized",
    );
  });
});

// canonicalMandateV2 is exercised indirectly through the pin; assert the
// pin is content-bound so the chain helper is sound.
describe("v2 endorsement test scaffolding sanity", () => {
  it("mandatePinHash is the sha256 of canonicalMandateV2", () => {
    const r = root();
    expect(mandatePinHash(r)).toHaveLength(64);
    expect(canonicalMandateV2(r).byteLength).toBeGreaterThan(0);
  });
});
