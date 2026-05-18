/**
 * Mandate v2 verify-forward-from-pin (LOCKED Phase-2 v2). This file is
 * the security assurance for the load-bearing trust path: it pins the
 * happy path AND every fail-closed negative the v2 model promises
 * (absent/forked pin, pin-not-in-log, self-renewal-attempt,
 * sub-threshold signers, under-minSuccessors, over-maxDuration,
 * rolled-back/tampered history) plus totality (never throws on
 * adversarial input).
 */
import { describe, expect, it } from "vitest";
import { generateKeypair } from "../src/crypto.js";
import { canonicalMandateV2, mandatePinHash } from "../src/canonical.js";
import { signMandateV2, signMandateV2With, privKeySigner } from "../src/signing.js";
import {
  verifyMandateChainFromPin,
  currentAuthorityV2,
} from "../src/verifierV2.js";
import type { MandateV2 } from "../src/types.js";

function kp(seedByte: number): { privKey: string; pubKey: string } {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

const founder = kp(1);
const backup = kp(2);
const a = kp(3);
const b = kp(4);
const c = kp(5);
const eve = kp(99);

const DAY = 86400;

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
  project?: MandateV2["project"];
  signedBy: string;
  signWith: string[]; // privKeys
}

function mk(o: MkOpts): MandateV2 {
  const unsigned: Omit<MandateV2, "signatures"> = {
    kind: "Mandate",
    version: 2,
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
  return signMandateV2(unsigned, o.signWith.map((privKey) => ({ privKey })));
}

// A from-scratch (root) mandate: self-signed by its holder, project set.
function root(over: Partial<MkOpts> = {}): MandateV2 {
  return mk({
    id: "00000000-0000-4000-8000-000000000000",
    holder: founder.pubKey,
    issuedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2026-03-02T00:00:00Z", // 60d
    successors: [founder.pubKey, backup.pubKey],
    threshold: 1,
    minSuccessors: 1,
    maxDurationSeconds: 60 * DAY,
    project: { name: "flagship", contact: "harry@flagship.services", tracks: ["release", "ca"] },
    signedBy: founder.pubKey,
    signWith: [founder.privKey],
    ...over,
  });
}

describe("verify-forward-from-pin — happy path", () => {
  it("solo-founder renewal chain; currentAuthority tracks the window", () => {
    const r = root();
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: founder.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [founder.pubKey, backup.pubKey],
      signedBy: founder.pubKey,
      signWith: [founder.privKey], // founder ∈ root.successors, threshold 1 ⇒ valid
    });
    const pin = mandatePinHash(r);
    const chain = verifyMandateChainFromPin(pin, [r, k1]);
    expect(chain.rootError).toBeUndefined();
    expect(chain.validMandates.map((m) => m.mandateId)).toEqual([r.mandateId, k1.mandateId]);
    expect(chain.rejections).toEqual([]);

    // before any mandate
    expect(currentAuthorityV2(chain, new Date("2025-12-31T00:00:00Z"))).toBeNull();
    // inside root only
    expect(currentAuthorityV2(chain, new Date("2026-01-10T00:00:00Z"))?.mandate.mandateId).toBe(
      r.mandateId,
    );
    // overlap: most-recent valid wins → k1
    expect(currentAuthorityV2(chain, new Date("2026-02-20T00:00:00Z"))?.mandate.mandateId).toBe(
      k1.mandateId,
    );
    // inside k1 only
    expect(currentAuthorityV2(chain, new Date("2026-04-01T00:00:00Z"))?.holder).toBe(
      founder.pubKey,
    );
    // after k1 expiry → fail closed
    expect(currentAuthorityV2(chain, new Date("2026-05-01T00:00:00Z"))).toBeNull();
  });

  it("L1 multi-pin: pinning at root vs at k1 both verify; same authority at now", () => {
    const r = root();
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: backup.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [backup.pubKey],
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    const k2 = mk({
      id: "00000000-0000-4000-8000-000000000002",
      holder: backup.pubKey,
      issuedAt: "2026-04-10T00:00:00Z",
      expiresAt: "2026-06-09T00:00:00Z",
      successors: [backup.pubKey],
      signedBy: backup.pubKey,
      signWith: [backup.privKey], // backup ∈ k1.successors
    });
    const log = [r, k1, k2];
    const now = new Date("2026-05-01T00:00:00Z");
    const fromRoot = verifyMandateChainFromPin(mandatePinHash(r), log);
    const fromK1 = verifyMandateChainFromPin(mandatePinHash(k1), log);
    expect(fromRoot.validMandates.map((m) => m.mandateId)).toEqual([
      r.mandateId,
      k1.mandateId,
      k2.mandateId,
    ]);
    expect(fromK1.validMandates.map((m) => m.mandateId)).toEqual([k1.mandateId, k2.mandateId]);
    // The pin moved the floor but not the answer at `now`.
    expect(currentAuthorityV2(fromRoot, now)?.mandate.mandateId).toBe(k2.mandateId);
    expect(currentAuthorityV2(fromK1, now)?.mandate.mandateId).toBe(k2.mandateId);
  });

  it("2-of-3 threshold is satisfied by any two named successors", () => {
    const r = root({
      successors: [a.pubKey, b.pubKey, c.pubKey],
      threshold: 2,
      minSuccessors: 1,
    });
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: a.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [a.pubKey],
      signedBy: a.pubKey,
      signWith: [a.privKey, b.privKey],
    });
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, k1]);
    expect(chain.validMandates.length).toBe(2);
  });
});

describe("L1 fail-closed: the pin is the floor", () => {
  it("no baked pin ⇒ reject everything (#30 generalised)", () => {
    const r = root();
    const chain = verifyMandateChainFromPin("", [r]);
    expect(chain.rootError).toBe("no-pin");
    expect(chain.validMandates).toEqual([]);
    expect(currentAuthorityV2(chain, new Date("2026-01-10T00:00:00Z"))).toBeNull();
  });

  it("pin matches no mandate in the log ⇒ pin-not-in-log", () => {
    const r = root();
    const other = root({ id: "ffffffff-0000-4000-8000-000000000000" });
    const chain = verifyMandateChainFromPin(mandatePinHash(other), [r]);
    expect(chain.rootError).toBe("pin-not-in-log");
    expect(chain.validMandates).toEqual([]);
  });

  it("forked/tampered pin: a mandate mutated post-signing no longer hashes to the pin", () => {
    const r = root();
    const pin = mandatePinHash(r);
    const tampered: MandateV2 = { ...r, holder: eve.pubKey }; // signature now stale; hash differs
    const chain = verifyMandateChainFromPin(pin, [tampered]);
    expect(chain.rootError).toBe("pin-not-in-log");
    expect(chain.validMandates).toEqual([]);
  });

  it("root with an invalid signature ⇒ root-signature-invalid", () => {
    const r = root();
    const pin = mandatePinHash(r); // pin is content-bound, so it still matches
    const bad: MandateV2 = {
      ...r,
      signatures: [{ pubkey: founder.pubKey, sig: "00".repeat(64) }],
    };
    const chain = verifyMandateChainFromPin(pin, [bad]);
    expect(chain.rootError).toBe("root-signature-invalid");
  });

  it("root whose signedBy is not among its signatures ⇒ root-not-self-signed", () => {
    // backup validly signs bytes that declare signedBy=founder.
    const unsigned: Omit<MandateV2, "signatures"> = {
      kind: "Mandate",
      version: 2,
      mandateId: "00000000-0000-4000-8000-0000000000aa",
      track: "release",
      holder: founder.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-03-02T00:00:00Z",
      successors: [founder.pubKey],
      approvalRule: { kind: "threshold", threshold: 1 },
      minSuccessors: 1,
      maxDurationSeconds: 60 * DAY,
      defaultDurationSeconds: 60 * DAY,
      signedBy: founder.pubKey,
    };
    const m = signMandateV2(unsigned, [{ privKey: backup.privKey }]); // signer ≠ signedBy
    const chain = verifyMandateChainFromPin(mandatePinHash(m), [m]);
    expect(chain.rootError).toBe("root-not-self-signed");
  });
});

describe("L3 one-rule: no self-renewal, threshold/minSucc/maxDur enforced", () => {
  it("self-renewal-attempt: holder not in predecessor.successors ⇒ rejected", () => {
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
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, k1]);
    expect(chain.validMandates.map((m) => m.mandateId)).toEqual([r.mandateId]);
    expect(chain.rejections[0]?.reason).toBe("signer-not-in-successor-set");
  });

  it("sub-threshold signers ⇒ approval-threshold-unmet", () => {
    const r = root({ successors: [a.pubKey, b.pubKey, c.pubKey], threshold: 2 });
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: a.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [a.pubKey],
      signedBy: a.pubKey,
      signWith: [a.privKey], // only 1 of the required 2
    });
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, k1]);
    expect(chain.rejections[0]?.reason).toBe("approval-threshold-unmet");
  });

  it("under-minSuccessors ⇒ rejected", () => {
    const r = root({ minSuccessors: 2, successors: [founder.pubKey, backup.pubKey] });
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: founder.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [founder.pubKey], // only 1, need ≥ 2
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, k1]);
    expect(chain.rejections[0]?.reason).toBe("under-min-successors");
  });

  it("over-maxDuration ⇒ rejected", () => {
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
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, k1]);
    expect(chain.rejections[0]?.reason).toBe("over-max-duration");
  });

  it("issued-before-predecessor ⇒ rejected", () => {
    const r = root();
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: founder.pubKey,
      issuedAt: "2025-12-01T00:00:00Z", // before root.issuedAt
      expiresAt: "2026-02-01T00:00:00Z",
      successors: [founder.pubKey],
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, k1]);
    expect(chain.rejections[0]?.reason).toBe("issued-before-predecessor");
  });

  it("signedBy not among signatures ⇒ rejected", () => {
    const r = root({ successors: [founder.pubKey, backup.pubKey] });
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: founder.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [founder.pubKey],
      signedBy: backup.pubKey, // claims backup, but only founder signed
      signWith: [founder.privKey],
    });
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, k1]);
    expect(chain.rejections[0]?.reason).toBe("signed-by-not-in-signatures");
  });
});

describe("rolled-back / tampered history & totality", () => {
  it("dropping an intermediate mandate is detected: the suffix no longer chains", () => {
    const r = root({ successors: [founder.pubKey], threshold: 1, minSuccessors: 1 });
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: a.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [a.pubKey], // ONLY a may sign k2
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    const k2 = mk({
      id: "00000000-0000-4000-8000-000000000002",
      holder: a.pubKey,
      issuedAt: "2026-04-10T00:00:00Z",
      expiresAt: "2026-06-09T00:00:00Z",
      successors: [a.pubKey],
      signedBy: a.pubKey,
      signWith: [a.privKey], // valid only w.r.t. k1.successors, NOT root.successors
    });
    // Full chain: fine.
    expect(
      verifyMandateChainFromPin(mandatePinHash(r), [r, k1, k2]).validMandates.length,
    ).toBe(3);
    // Server drops k1 and serves only the suffix: k2's predecessor is
    // now root, whose successors are [founder]; a ∉ that set ⇒ reject.
    const rolledBack = verifyMandateChainFromPin(mandatePinHash(r), [r, k2]);
    expect(rolledBack.validMandates.map((m) => m.mandateId)).toEqual([r.mandateId]);
    expect(rolledBack.rejections[0]?.reason).toBe("signer-not-in-successor-set");
  });

  it("duplicate mandateId is rejected (no double-spend in the log)", () => {
    const r = root();
    const k1 = mk({
      id: "00000000-0000-4000-8000-000000000001",
      holder: founder.pubKey,
      issuedAt: "2026-02-15T00:00:00Z",
      expiresAt: "2026-04-15T00:00:00Z",
      successors: [founder.pubKey],
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    const dup = mk({
      id: "00000000-0000-4000-8000-000000000001", // same id
      holder: eve.pubKey,
      issuedAt: "2026-03-01T00:00:00Z",
      expiresAt: "2026-05-01T00:00:00Z",
      successors: [founder.pubKey],
      signedBy: founder.pubKey,
      signWith: [founder.privKey],
    });
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, k1, dup]);
    expect(chain.validMandates.map((m) => m.mandateId)).toEqual([r.mandateId, k1.mandateId]);
    expect(chain.rejections[0]?.reason).toBe("duplicate-mandate-id");
  });

  it("cross-track mandates in the same log are ignored, not rejected", () => {
    const r = root();
    const caTrack = mk({
      id: "00000000-0000-4000-8000-0000000000ca",
      track: "ca",
      holder: backup.pubKey,
      issuedAt: "2026-02-01T00:00:00Z",
      expiresAt: "2026-04-01T00:00:00Z",
      successors: [backup.pubKey],
      signedBy: backup.pubKey,
      signWith: [backup.privKey],
    });
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, caTrack]);
    expect(chain.validMandates.map((m) => m.mandateId)).toEqual([r.mandateId]);
    expect(chain.rejections).toEqual([]);
  });

  it("adversarial canonicalization input never throws — it is recorded as a rejection", () => {
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
    // inject a non-hex holder AFTER signing — same track, so it reaches
    // the forward step; canonicalization throws internally and MUST be
    // caught (totality), surfacing as a rejection, never an exception.
    const poisoned: MandateV2 = { ...evil, holder: "zz" + "00".repeat(31) };
    expect(() =>
      verifyMandateChainFromPin(mandatePinHash(r), [r, poisoned]),
    ).not.toThrow();
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, poisoned]);
    expect(chain.validMandates.map((m) => m.mandateId)).toEqual([r.mandateId]);
    expect(chain.rejections[0]?.reason).toBe("signature-invalid");
  });
});

describe("canonical/pin/signing invariants", () => {
  it("the pin is content-bound and signature-independent", () => {
    const unsigned: Omit<MandateV2, "signatures"> = {
      kind: "Mandate",
      version: 2,
      mandateId: "00000000-0000-4000-8000-0000000000bb",
      track: "release",
      holder: founder.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-03-02T00:00:00Z",
      successors: [founder.pubKey, backup.pubKey],
      approvalRule: { kind: "threshold", threshold: 1 },
      minSuccessors: 1,
      maxDurationSeconds: 60 * DAY,
      defaultDurationSeconds: 60 * DAY,
      signedBy: founder.pubKey,
    };
    const oneSig = signMandateV2(unsigned, [{ privKey: founder.privKey }]);
    const twoSig = signMandateV2(unsigned, [
      { privKey: founder.privKey },
      { privKey: backup.privKey },
    ]);
    expect(mandatePinHash(oneSig)).toBe(mandatePinHash(twoSig));
    expect(mandatePinHash(oneSig)).toBe(mandatePinHash(unsigned));
  });

  it("signMandateV2With (external signer) is byte-identical to signMandateV2", async () => {
    const unsigned: Omit<MandateV2, "signatures"> = {
      kind: "Mandate",
      version: 2,
      mandateId: "00000000-0000-4000-8000-0000000000cc",
      track: "release",
      holder: founder.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-03-02T00:00:00Z",
      successors: [founder.pubKey],
      approvalRule: { kind: "threshold", threshold: 1 },
      minSuccessors: 1,
      maxDurationSeconds: 60 * DAY,
      defaultDurationSeconds: 60 * DAY,
      signedBy: founder.pubKey,
    };
    const sync = signMandateV2(unsigned, [{ privKey: founder.privKey }]);
    const ext = await signMandateV2With(unsigned, [privKeySigner(founder.privKey)]);
    expect(ext.signatures).toEqual(sync.signatures);
    expect(canonicalMandateV2(ext)).toEqual(canonicalMandateV2(sync));
  });

  it("successor order is part of canonical bytes (reordering changes the pin)", () => {
    const r1 = root({ successors: [founder.pubKey, backup.pubKey] });
    const r2 = root({ successors: [backup.pubKey, founder.pubKey] });
    expect(mandatePinHash(r1)).not.toBe(mandatePinHash(r2));
  });
});
