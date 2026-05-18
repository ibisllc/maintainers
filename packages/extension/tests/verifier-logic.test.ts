/**
 * Overlay-state tests — LOCKED Phase-2 v2 model.
 *
 * #31: the extension is a READ-ONLY status/preview surface with NO
 * baked pin. It verifies each track's mandate log FORWARD from the
 * first on-repo mandate (the read-only-preview anchor) via
 * verifyMandateChainFromPin + currentAuthority. These tests pin the
 * v2 path AND its fail-closed negatives (empty pin ⇒ no-pin ⇒ reject;
 * pin-not-in-log/forked ⇒ reject; unauthorised successor ⇒
 * signer-not-in-successor-set) — mirroring the c4.5b project.test.ts
 * rewrite.
 */
import { describe, expect, it } from "vitest";
import {
  currentAuthority,
  generateKeypair,
  mandatePinHash,
  verifyMandateChainFromPin,
} from "@ibisllc/maintainers";
import {
  computeOverlayState,
  formatDuration,
  _verifyChainForTest,
} from "../src/verifier-logic.js";
import { buildFixture, mk } from "./fixtures/build-fixture.js";

function kp(seedByte: number): { privKey: string; pubKey: string } {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

const NOW = new Date("2026-05-15T12:00:00Z");

describe("computeOverlayState — happy path (continuous rotation, no alarms)", () => {
  const fx = buildFixture({ takeover: false, recentEmailRotation: false, expiresInDays: 30, now: NOW });

  const state = computeOverlayState({
    mandates: fx.mandates,
    keys: fx.keys,
    endorsements: fx.endorsements,
    now: NOW,
  });

  it("reports the project name from the inline root-mandate project", () => {
    expect(state.projectName).toBe("fixture-project");
  });

  it("returns both tracks (sorted)", () => {
    expect(state.tracks.map((t) => t.track)).toEqual(["ca", "release"]);
  });

  it("identifies Alice as the current release holder", () => {
    const release = state.tracks.find((t) => t.track === "release")!;
    expect(release.current?.holder.displayName).toBe("Alice");
    expect(release.current?.holder.email).toBe("alice@example.com");
  });

  it("lists the named successors on the release track", () => {
    const release = state.tracks.find((t) => t.track === "release")!;
    expect(release.successors.map((s) => s.displayName).sort()).toEqual([
      "Alice",
      "Bob",
      "Carol",
    ]);
  });

  it("reports a positive time-to-expiry", () => {
    const release = state.tracks.find((t) => t.track === "release")!;
    expect(release.current?.expiresInMs).toBeGreaterThan(0);
  });

  it("has no red alarms", () => {
    expect(state.alarms.filter((a) => a.level === "red")).toEqual([]);
  });

  it("includes the latest endorsement in recentEndorsements", () => {
    expect(state.recentEndorsements).toHaveLength(1);
    expect(state.recentEndorsements[0]?.semverTag).toBe("v0.1.0");
  });
});

describe("computeOverlayState — takeover triggers a red alarm", () => {
  const fx = buildFixture({ takeover: true, recentEmailRotation: false, expiresInDays: 30, now: NOW });
  const state = computeOverlayState({
    mandates: fx.mandates,
    keys: fx.keys,
    endorsements: fx.endorsements,
    now: NOW,
  });

  it("marks Bob as the current release holder", () => {
    const release = state.tracks.find((t) => t.track === "release")!;
    expect(release.current?.holder.displayName).toBe("Bob");
  });

  it("surfaces a red takeover alarm", () => {
    const takeover = state.alarms.find((a) => a.kind === "takeover");
    expect(takeover).toBeDefined();
    expect(takeover?.level).toBe("red");
    expect(takeover?.detail).toMatch(/Alice.*Bob/);
  });

  it("includes both Alice's and Bob's emails as contact targets", () => {
    const takeover = state.alarms.find((a) => a.kind === "takeover");
    expect(takeover?.contactEmails).toContain("alice@example.com");
    expect(takeover?.contactEmails).toContain("bob@example.com");
  });
});

describe("computeOverlayState — recent email rotation triggers a yellow alarm", () => {
  const fx = buildFixture({ takeover: false, recentEmailRotation: true, expiresInDays: 30, now: NOW });
  const state = computeOverlayState({
    mandates: fx.mandates,
    keys: fx.keys,
    endorsements: fx.endorsements,
    now: NOW,
  });

  it("surfaces a yellow email-rotation alarm for Bob", () => {
    const rot = state.alarms.find((a) => a.kind === "email-rotation");
    expect(rot).toBeDefined();
    expect(rot?.level).toBe("yellow");
    expect(rot?.message).toMatch(/Bob/);
    expect(rot?.detail).toMatch(/bob-old@example.com.*bob-new@example.com/);
  });
});

describe("computeOverlayState — expiring-soon banner", () => {
  const fx = buildFixture({ takeover: false, recentEmailRotation: false, expiresInDays: 3, now: NOW });
  const state = computeOverlayState({
    mandates: fx.mandates,
    keys: fx.keys,
    endorsements: fx.endorsements,
    now: NOW,
  });
  it("fires when the active mandate expires within 7 days", () => {
    const expiring = state.alarms.find((a) => a.kind === "expiring-soon");
    expect(expiring).toBeDefined();
    expect(expiring?.level).toBe("yellow");
    expect(expiring?.contactEmails).toContain("alice@example.com");
  });
});

describe("computeOverlayState — no mandates", () => {
  it("returns an empty state with policyPresent=false", () => {
    const state = computeOverlayState({
      mandates: {},
      keys: [],
      endorsements: [],
      now: NOW,
    });
    expect(state.policyPresent).toBe(false);
    expect(state.tracks).toEqual([]);
    expect(state.alarms).toEqual([]);
  });
});

describe("computeOverlayState — FAIL-CLOSED negatives (#30/#31 v2)", () => {
  it("an empty track ⇒ no-pin ⇒ red chain-gap, no authority", () => {
    const state = computeOverlayState({
      mandates: { release: [] },
      keys: [],
      endorsements: [],
      now: NOW,
    });
    expect(state.policyPresent).toBe(false);
    const release = state.tracks.find((t) => t.track === "release")!;
    expect(release.current).toBeNull();
    const gap = state.alarms.find((a) => a.kind === "chain-gap");
    expect(gap?.level).toBe("red");
    expect(gap?.detail).toBe("no-pin");
  });

  it("pin-not-in-log (forked/tampered) ⇒ rootError, no chain", () => {
    const alice = kp(1);
    const eve = kp(99);
    const real = mk({
      id: "r-0000-0000-0000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-12-01T00:00:00Z",
      successors: [alice.pubKey],
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const forged = mk({
      id: "r-0000-0000-0000-000000000099",
      holder: eve.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-12-01T00:00:00Z",
      successors: [eve.pubKey],
      signedBy: eve.pubKey,
      signWith: [eve.privKey],
    });
    // Anchor at the REAL pin but feed only the forged log.
    const chain = verifyMandateChainFromPin(mandatePinHash(real), [forged]);
    expect(chain.root).toBeNull();
    expect(chain.rootError).toBe("pin-not-in-log");
    expect(currentAuthority(chain, NOW)).toBeNull();
  });

  it("the view helper fail-closes on an empty mandate list", () => {
    expect(_verifyChainForTest([]).rootError).toBe("no-pin");
  });

  it("rejects an unauthorised successor (signer not in predecessor's successors)", () => {
    const alice = kp(1);
    const eve = kp(99);
    const root = mk({
      id: "r-0000-0000-0000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-06-01T00:00:00Z",
      successors: [], // nobody is authorised to succeed
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const stolen = mk({
      id: "r-0000-0000-0000-000000000099",
      holder: eve.pubKey,
      issuedAt: "2026-02-01T00:00:00Z",
      expiresAt: "2026-07-01T00:00:00Z",
      successors: [eve.pubKey],
      signedBy: eve.pubKey,
      signWith: [eve.privKey],
    });
    const chain = _verifyChainForTest([root, stolen]);
    expect(chain.validMandates).toHaveLength(1);
    expect(chain.rejections).toHaveLength(1);
    expect(chain.rejections[0]!.reason).toBe("signer-not-in-successor-set");
  });

  it("computeOverlayState surfaces a rejected successor as a red chain-gap", () => {
    const alice = kp(1);
    const eve = kp(99);
    const root = mk({
      id: "r-0000-0000-0000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-12-01T00:00:00Z",
      successors: [],
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const stolen = mk({
      id: "r-0000-0000-0000-000000000099",
      holder: eve.pubKey,
      issuedAt: "2026-02-01T00:00:00Z",
      expiresAt: "2026-07-01T00:00:00Z",
      successors: [eve.pubKey],
      signedBy: eve.pubKey,
      signWith: [eve.privKey],
    });
    const state = computeOverlayState({
      mandates: { release: [root, stolen] },
      keys: [],
      endorsements: [],
      now: new Date("2026-03-01T00:00:00Z"),
    });
    const release = state.tracks.find((t) => t.track === "release")!;
    // The root is still the live authority; the stolen successor was rejected.
    expect(release.current?.holder.pubkey).toBe(alice.pubKey);
    const gap = state.alarms.find((a) => a.kind === "chain-gap");
    expect(gap?.level).toBe("red");
    expect(gap?.message).toMatch(/signer-not-in-successor-set/);
  });
});

describe("formatDuration", () => {
  it("formats days", () => {
    expect(formatDuration(3 * 86400000)).toBe("3d");
  });
  it("formats hours", () => {
    expect(formatDuration(5 * 3600 * 1000)).toBe("5h");
  });
  it("formats minutes", () => {
    expect(formatDuration(7 * 60 * 1000)).toBe("7m");
  });
  it("formats seconds", () => {
    expect(formatDuration(15 * 1000)).toBe("15s");
  });
  it("returns 'expired' for negatives", () => {
    expect(formatDuration(-1000)).toBe("expired");
  });
});
