/**
 * Checkpointed verification (spec §5.2). Pins the three invariants:
 * optimization-not-floor (parity with a full genesis walk),
 * suffix-cryptographically-chained, and alarms-unskippable.
 */
import { describe, expect, it } from "vitest";
import { generateKeypair } from "../src/crypto.js";
import { signMandate } from "../src/signing.js";
import {
  verifyTrack,
  currentAuthority,
  checkpointFromVerifiedTrack,
  verifyTrackFromCheckpoint,
} from "../src/verifier.js";
import type { Mandate, TrackPolicy } from "../src/types.js";

function keypair(seedByte: number): { privKey: string; pubKey: string } {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

const alice = keypair(1);
const bob = keypair(2); // named successor
const eve = keypair(99);

const policy: TrackPolicy = {
  track: "release",
  defaultMandateDuration: "60d",
  approvalRule: { kind: "threshold", threshold: 1, of: "anyAuthorizedSigner" },
};

const genesis: Mandate = signMandate(
  {
    kind: "Mandate",
    version: 1,
    mandateId: "g",
    track: "release",
    holder: alice.pubKey,
    issuedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2026-03-01T00:00:00Z",
    successors: [bob.pubKey],
    signedBy: alice.pubKey,
  },
  [{ privKey: alice.privKey }],
);

// alice self-renews within the genesis window.
const renewal: Mandate = signMandate(
  {
    kind: "Mandate",
    version: 1,
    mandateId: "r",
    track: "release",
    holder: alice.pubKey,
    issuedAt: "2026-02-15T00:00:00Z",
    expiresAt: "2026-05-01T00:00:00Z",
    successors: [bob.pubKey],
    signedBy: alice.pubKey,
  },
  [{ privKey: alice.privKey }],
);

// bob takes over after the renewal expires (gap takeover).
const takeover: Mandate = signMandate(
  {
    kind: "Mandate",
    version: 1,
    mandateId: "t",
    track: "release",
    holder: bob.pubKey,
    issuedAt: "2026-05-02T00:00:00Z",
    expiresAt: "2026-08-01T00:00:00Z",
    successors: [alice.pubKey],
    signedBy: bob.pubKey,
  },
  [{ privKey: bob.privKey }],
);

function cpAtGenesis(ackedAlarms: string[] = []) {
  const cp = checkpointFromVerifiedTrack(
    verifyTrack("release", policy, [genesis]),
    ackedAlarms,
  );
  if (!cp) throw new Error("checkpoint should exist");
  return cp;
}

describe("verifyTrackFromCheckpoint", () => {
  it("optimization-not-floor: parity with a full genesis walk", () => {
    const full = verifyTrack("release", policy, [genesis, renewal, takeover]);
    const at = new Date("2026-06-01T00:00:00Z");
    expect(currentAuthority(full, at)?.holder).toBe(bob.pubKey);

    const r = verifyTrackFromCheckpoint("release", policy, cpAtGenesis(), [
      renewal,
      takeover,
    ]);
    expect(currentAuthority(r.verified, at)?.holder).toBe(bob.pubKey);
  });

  it("empty suffix yields the checkpoint's own authority", () => {
    const r = verifyTrackFromCheckpoint("release", policy, cpAtGenesis(), []);
    expect(
      currentAuthority(r.verified, new Date("2026-02-01T00:00:00Z"))?.holder,
    ).toBe(alice.pubKey);
    expect(r.alarms).toHaveLength(0);
  });

  it("accepts a same-holder renewal suffix with no alarm", () => {
    const r = verifyTrackFromCheckpoint("release", policy, cpAtGenesis(), [
      renewal,
    ]);
    expect(r.verified.rejections).toHaveLength(0);
    expect(r.verified.validMandates).toHaveLength(2); // synthetic + renewal
    expect(r.alarms).toHaveLength(0);
  });

  it("invariant 2: a suffix not chained to the checkpoint is rejected", () => {
    const forged: Mandate = signMandate(
      {
        kind: "Mandate",
        version: 1,
        mandateId: "x",
        track: "release",
        holder: eve.pubKey,
        issuedAt: "2026-02-20T00:00:00Z", // inside genesis window ⇒ only alice may sign
        expiresAt: "2026-09-01T00:00:00Z",
        successors: [],
        signedBy: eve.pubKey,
      },
      [{ privKey: eve.privKey }],
    );
    const r = verifyTrackFromCheckpoint("release", policy, cpAtGenesis(), [
      forged,
    ]);
    expect(r.verified.rejections[0]?.reason).toBe("signer-not-authorized");
    expect(r.verified.validMandates).toHaveLength(1); // only the synthetic
  });

  it("invariant 3: a dropped intermediate cannot hide a boundary takeover", () => {
    // Real history was genesis → renewal → takeover. A malicious server
    // serves the consumer (checkpointed at genesis) ONLY the takeover,
    // dropping the renewal. The takeover still chains (bob ∈ genesis
    // successors, issued after genesis expiry) so it's accepted — and
    // the holder change alice→bob raises the alarm regardless.
    const r = verifyTrackFromCheckpoint("release", policy, cpAtGenesis(), [
      takeover,
    ]);
    expect(r.verified.rejections).toHaveLength(0);
    expect(r.alarms).toHaveLength(1);
    expect(r.alarms[0]).toMatchObject({
      previousMandate: "g",
      newMandate: "t",
      previousHolder: alice.pubKey,
      newHolder: bob.pubKey,
    });
    expect(r.unacknowledgedAlarms).toHaveLength(1);
  });

  it("ackedAlarms suppresses an acknowledged alarm but keeps it observable", () => {
    const r = verifyTrackFromCheckpoint(
      "release",
      policy,
      cpAtGenesis(["t"]),
      [takeover],
    );
    expect(r.alarms).toHaveLength(1); // still observable
    expect(r.unacknowledgedAlarms).toHaveLength(0); // but not re-surfaced
  });

  it("a benign same-holder renewal may be dropped without hiding anything", () => {
    // Server drops `renewal` and serves a later same-holder renewal.
    const renewal2: Mandate = signMandate(
      {
        kind: "Mandate",
        version: 1,
        mandateId: "r2",
        track: "release",
        holder: alice.pubKey,
        issuedAt: "2026-02-20T00:00:00Z",
        expiresAt: "2026-06-01T00:00:00Z",
        successors: [bob.pubKey],
        signedBy: alice.pubKey,
      },
      [{ privKey: alice.privKey }],
    );
    const r = verifyTrackFromCheckpoint("release", policy, cpAtGenesis(), [
      renewal2,
    ]);
    expect(r.verified.rejections).toHaveLength(0);
    expect(r.alarms).toHaveLength(0); // holder never changed
    expect(
      currentAuthority(r.verified, new Date("2026-05-01T00:00:00Z"))?.holder,
    ).toBe(alice.pubKey);
  });

  it("invariant 1: a wrong-track checkpoint throws (caller must re-walk)", () => {
    const cp = cpAtGenesis();
    expect(() =>
      verifyTrackFromCheckpoint("ca", { ...policy, track: "ca" }, cp, []),
    ).toThrow(/checkpoint\.track/);
  });

  it("rejects a suffix mandate that reuses the checkpoint's mandateId", () => {
    const dup: Mandate = signMandate(
      {
        kind: "Mandate",
        version: 1,
        mandateId: "g", // same as the checkpoint mandate
        track: "release",
        holder: alice.pubKey,
        issuedAt: "2026-02-20T00:00:00Z",
        expiresAt: "2026-06-01T00:00:00Z",
        successors: [bob.pubKey],
        signedBy: alice.pubKey,
      },
      [{ privKey: alice.privKey }],
    );
    const r = verifyTrackFromCheckpoint("release", policy, cpAtGenesis(), [dup]);
    expect(r.verified.rejections[0]?.reason).toBe("duplicate-mandate-id");
  });
});
