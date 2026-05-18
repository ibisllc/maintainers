/**
 * Policy enforcement tests for the Cloudflare Worker adapter — LOCKED
 * Phase-2 v2 model.
 *
 * Synthetic RepoStates are built in-process and fed through `decide()`.
 * Every defense-in-depth fence is covered: path-prefix, envelope shape
 * (Mandate = v2), canonical-bytes mismatch, bad signatures, the
 * from-scratch root path, v2 forward-succession authority, and
 * holder-signs endorsement authority.
 *
 * No network — never test against real GitHub.
 */

import { describe, expect, it } from "vitest";
import {
  generateKeypair,
  signMandate,
  signKeyFile,
  signEmailRotation,
  signReleaseEndorsement,
  canonicalMandate,
  canonicalKeyFile,
  canonicalEmailRotation,
  canonicalReleaseEndorsement,
  intermediateMerkleRoot,
  bytesToHex,
  type Mandate,
  type KeyFile,
  type ReleaseEndorsement,
} from "@ibisllc/maintainers";
import { decide, summarizeState, type RepoState } from "../src/policy.js";

const DAY = 86400;

function kp(seed: number): { privKey: string; pubKey: string } {
  const s = new Uint8Array(32);
  s[0] = seed;
  return generateKeypair(s);
}

interface Mk {
  id: string;
  track?: string;
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

function mk(o: Mk): Mandate {
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
    minSuccessors: o.minSuccessors ?? 0,
    maxDurationSeconds: o.maxDurationSeconds ?? 1000 * DAY,
    defaultDurationSeconds: 60 * DAY,
    signedBy: o.signedBy,
  };
  return signMandate(unsigned, o.signWith.map((privKey) => ({ privKey })));
}

function emptyState(): RepoState {
  return { tracks: new Map(), keyFiles: new Map() };
}

/** A self-signed v2 root on the release track. */
function stateWithRoot(
  holder: { privKey: string; pubKey: string },
  successors: string[] = [],
): { state: RepoState; mandate: Mandate } {
  const m = mk({
    id: "g1-00000000-0000-0000-0000-000000000001",
    holder: holder.pubKey,
    issuedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2026-12-01T00:00:00Z",
    successors,
    signedBy: holder.pubKey,
    signWith: [holder.privKey],
  });
  const state: RepoState = {
    tracks: new Map([["release", [m]]]),
    keyFiles: new Map(),
  };
  return { state, mandate: m };
}

describe("decide() — path-prefix fence", () => {
  const alice = kp(1);
  const m = mk({
    id: "id-00000000-0000-0000-0000-000000000010",
    holder: alice.pubKey,
    issuedAt: "2026-02-01T00:00:00Z",
    expiresAt: "2026-04-01T00:00:00Z",
    successors: [],
    signedBy: alice.pubKey,
    signWith: [alice.privKey],
  });
  const bytes = bytesToHex(canonicalMandate(m));

  it("rejects a path outside .maintainers/", () => {
    const r = decide({ path: "src/whatever.json", envelope: m, envelopeBytesHex: bytes, state: emptyState(), now: new Date("2026-02-01T01:00:00Z") });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe("path-outside-maintainers");
      expect(r.status).toBe(403);
    }
  });

  it("rejects path traversal segments", () => {
    const r = decide({ path: ".maintainers/../etc/passwd", envelope: m, envelopeBytesHex: bytes, state: emptyState(), now: new Date() });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("path-traversal");
  });

  it("rejects directory-like paths", () => {
    const r = decide({ path: ".maintainers/keys/", envelope: m, envelopeBytesHex: bytes, state: emptyState(), now: new Date() });
    expect(r.ok).toBe(false);
  });
});

describe("decide() — envelope-shape fence", () => {
  it("rejects non-object envelopes", () => {
    const r = decide({ path: ".maintainers/x.json", envelope: "not-an-object", envelopeBytesHex: "00", state: emptyState(), now: new Date() });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("envelope-not-object");
  });

  it("rejects unknown envelope kinds", () => {
    const r = decide({ path: ".maintainers/x.json", envelope: { kind: "MaliciousKind", version: 1 }, envelopeBytesHex: "00", state: emptyState(), now: new Date() });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("envelope-kind-unknown");
  });

  it("rejects an unsupported Mandate version (v1 is THE Mandate version)", () => {
    const r = decide({ path: ".maintainers/x.json", envelope: { kind: "Mandate", version: 2 }, envelopeBytesHex: "00", state: emptyState(), now: new Date() });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("mandate-version-unsupported");
  });

  it("rejects a malformed Mandate (correct version, bad shape)", () => {
    const r = decide({ path: ".maintainers/x.json", envelope: { kind: "Mandate", version: 1 }, envelopeBytesHex: "00", state: emptyState(), now: new Date() });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("mandate-shape");
  });

  it("rejects an unsupported version for an identity envelope", () => {
    const r = decide({ path: ".maintainers/x.json", envelope: { kind: "KeyFile", version: 2 }, envelopeBytesHex: "00", state: emptyState(), now: new Date() });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("envelope-version-unsupported");
  });
});

describe("decide() — canonical-bytes fence", () => {
  it("rejects envelopes whose bytes don't match", () => {
    const alice = kp(1);
    const m = mk({ id: "id-00000000-0000-0000-0000-000000000020", holder: alice.pubKey, issuedAt: "2026-02-01T00:00:00Z", expiresAt: "2026-04-01T00:00:00Z", successors: [], signedBy: alice.pubKey, signWith: [alice.privKey] });
    const r = decide({ path: ".maintainers/tracks/release/mandates/m.json", envelope: m, envelopeBytesHex: "deadbeef", state: emptyState(), now: new Date("2026-02-01T01:00:00Z") });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("canonical-bytes-mismatch");
  });
});

describe("decide() — signature fence", () => {
  it("rejects a Mandate whose signature was forged", () => {
    const alice = kp(1);
    const m: Mandate = {
      kind: "Mandate",
      version: 1,
      mandateId: "id-00000000-0000-0000-0000-000000000030",
      track: "release",
      holder: alice.pubKey,
      issuedAt: "2026-02-01T00:00:00Z",
      expiresAt: "2026-04-01T00:00:00Z",
      successors: [],
      approvalRule: { kind: "threshold", threshold: 1 },
      minSuccessors: 0,
      maxDurationSeconds: 1000 * DAY,
      defaultDurationSeconds: 60 * DAY,
      signedBy: alice.pubKey,
      signatures: [{ pubkey: alice.pubKey, sig: "00".repeat(64) }],
    };
    const r = decide({ path: ".maintainers/tracks/release/mandates/m.json", envelope: m, envelopeBytesHex: bytesToHex(canonicalMandate(m)), state: emptyState(), now: new Date("2026-02-01T01:00:00Z") });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("signature-invalid");
  });

  it("rejects when signedBy is not present in signatures", () => {
    const alice = kp(1);
    const bob = kp(2);
    const m = mk({ id: "id-00000000-0000-0000-0000-000000000031", holder: alice.pubKey, issuedAt: "2026-02-01T00:00:00Z", expiresAt: "2026-04-01T00:00:00Z", successors: [], signedBy: alice.pubKey, signWith: [bob.privKey] });
    const r = decide({ path: ".maintainers/tracks/release/mandates/m.json", envelope: m, envelopeBytesHex: bytesToHex(canonicalMandate(m)), state: emptyState(), now: new Date("2026-02-01T01:00:00Z") });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("signedBy-not-in-signatures");
  });
});

describe("decide() — from-scratch root acceptance", () => {
  it("accepts a well-formed self-signed v2 root when state is empty", () => {
    const alice = kp(1);
    const m = mk({ id: "g1-00000000-0000-0000-0000-000000000040", holder: alice.pubKey, issuedAt: "2026-01-01T00:00:00Z", expiresAt: "2026-07-01T00:00:00Z", successors: [], signedBy: alice.pubKey, signWith: [alice.privKey] });
    const r = decide({ path: ".maintainers/tracks/release/mandates/2026-01-01-root.json", envelope: m, envelopeBytesHex: bytesToHex(canonicalMandate(m)), state: emptyState(), now: new Date("2026-01-01T01:00:00Z") });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.commitMessage).toMatch(/^maintainers: Mandate by /);
  });

  it("rejects a from-scratch root with expiresAt <= issuedAt", () => {
    const alice = kp(1);
    const m = mk({ id: "g1-00000000-0000-0000-0000-000000000041", holder: alice.pubKey, issuedAt: "2026-07-01T00:00:00Z", expiresAt: "2026-01-01T00:00:00Z", successors: [], signedBy: alice.pubKey, signWith: [alice.privKey] });
    const r = decide({ path: ".maintainers/tracks/release/mandates/2026-01-01-root.json", envelope: m, envelopeBytesHex: bytesToHex(canonicalMandate(m)), state: emptyState(), now: new Date() });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("mandate-rejected");
  });
});

describe("decide() — v2 forward-succession authority", () => {
  it("accepts a renewal that satisfies the predecessor's embedded rule", () => {
    const alice = kp(1);
    const { state } = stateWithRoot(alice, [alice.pubKey]);
    const renewal = mk({ id: "r1-00000000-0000-0000-0000-000000000050", holder: alice.pubKey, issuedAt: "2026-06-01T00:00:00Z", expiresAt: "2027-01-01T00:00:00Z", successors: [alice.pubKey], signedBy: alice.pubKey, signWith: [alice.privKey] });
    const r = decide({ path: ".maintainers/tracks/release/mandates/2026-06-01-renewal.json", envelope: renewal, envelopeBytesHex: bytesToHex(canonicalMandate(renewal)), state, now: new Date("2026-06-01T01:00:00Z") });
    expect(r.ok).toBe(true);
  });

  it("rejects a successor whose signer is not in the predecessor's successor set", () => {
    const alice = kp(1);
    const eve = kp(99);
    const { state } = stateWithRoot(alice, [alice.pubKey]);
    const hostile = mk({ id: "h1-00000000-0000-0000-0000-000000000051", holder: eve.pubKey, issuedAt: "2026-06-01T00:00:00Z", expiresAt: "2027-01-01T00:00:00Z", successors: [], signedBy: eve.pubKey, signWith: [eve.privKey] });
    const r = decide({ path: ".maintainers/tracks/release/mandates/2026-06-01-hostile.json", envelope: hostile, envelopeBytesHex: bytesToHex(canonicalMandate(hostile)), state, now: new Date("2026-06-01T01:00:00Z") });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("mandate-rejected");
  });

  it("accepts a named-successor takeover (v2 has no in-window/after-expiry split)", () => {
    const alice = kp(1);
    const bob = kp(2);
    const { state } = stateWithRoot(alice, [bob.pubKey]);
    const takeover = mk({ id: "t1-00000000-0000-0000-0000-000000000052", holder: bob.pubKey, issuedAt: "2027-01-01T00:00:00Z", expiresAt: "2027-06-01T00:00:00Z", successors: [bob.pubKey], signedBy: bob.pubKey, signWith: [bob.privKey] });
    const r = decide({ path: ".maintainers/tracks/release/mandates/2027-01-01-takeover.json", envelope: takeover, envelopeBytesHex: bytesToHex(canonicalMandate(takeover)), state, now: new Date("2027-01-01T01:00:00Z") });
    expect(r.ok).toBe(true);
  });

  it("rejects a non-successor's takeover attempt", () => {
    const alice = kp(1);
    const bob = kp(2);
    const eve = kp(99);
    const { state } = stateWithRoot(alice, [bob.pubKey]);
    const fake = mk({ id: "h2-00000000-0000-0000-0000-000000000053", holder: eve.pubKey, issuedAt: "2027-01-01T00:00:00Z", expiresAt: "2027-06-01T00:00:00Z", successors: [], signedBy: eve.pubKey, signWith: [eve.privKey] });
    const r = decide({ path: ".maintainers/tracks/release/mandates/2027-01-01-attack.json", envelope: fake, envelopeBytesHex: bytesToHex(canonicalMandate(fake)), state, now: new Date("2027-01-01T01:00:00Z") });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("mandate-rejected");
  });

  it("accepts a from-scratch root for a NEW track even when another track has mandates (independent timelines)", () => {
    const alice = kp(1);
    const { state } = stateWithRoot(alice, [alice.pubKey]); // release track populated
    const opsRoot = mk({ id: "o1-00000000-0000-0000-0000-000000000054", track: "ops", holder: alice.pubKey, issuedAt: "2026-02-01T00:00:00Z", expiresAt: "2026-08-01T00:00:00Z", successors: [], signedBy: alice.pubKey, signWith: [alice.privKey] });
    const r = decide({ path: ".maintainers/tracks/ops/mandates/2026-02-01-root.json", envelope: opsRoot, envelopeBytesHex: bytesToHex(canonicalMandate(opsRoot)), state, now: new Date("2026-02-01T01:00:00Z") });
    expect(r.ok).toBe(true);
  });
});

describe("decide() — ReleaseEndorsement authority (holder-signs)", () => {
  it("accepts an endorsement signed by the current release-track holder", () => {
    const alice = kp(1);
    const { state } = stateWithRoot(alice, [alice.pubKey]);
    const commits = ["aa".repeat(20), "bb".repeat(20), "cc".repeat(20)];
    const endo = signReleaseEndorsement(
      {
        kind: "ReleaseEndorsement",
        version: 1,
        releaseId: "e1-00000000-0000-0000-0000-000000000060",
        semverTag: "v0.1.0",
        commitHash: "cc".repeat(20),
        previousReleaseId: null,
        previousCommitHash: null,
        intermediateCommits: commits,
        intermediateMerkleRoot: intermediateMerkleRoot(commits),
        endorsedNotes: null,
        issuedAt: "2026-02-15T00:00:00Z",
        signedBy: alice.pubKey,
      },
      [{ privKey: alice.privKey }],
    );
    const r = decide({ path: ".maintainers/endorsements/v0.1.0.json", envelope: endo, envelopeBytesHex: bytesToHex(canonicalReleaseEndorsement(endo)), state, now: new Date("2026-02-15T01:00:00Z") });
    expect(r.ok).toBe(true);
  });

  it("rejects an endorsement signed by a non-holder", () => {
    const alice = kp(1);
    const eve = kp(99);
    const { state } = stateWithRoot(alice, []);
    const commits = ["aa".repeat(20)];
    const endo = signReleaseEndorsement(
      {
        kind: "ReleaseEndorsement",
        version: 1,
        releaseId: "e2-00000000-0000-0000-0000-000000000061",
        semverTag: "v0.2.0",
        commitHash: "aa".repeat(20),
        previousReleaseId: null,
        previousCommitHash: null,
        intermediateCommits: commits,
        intermediateMerkleRoot: intermediateMerkleRoot(commits),
        endorsedNotes: null,
        issuedAt: "2026-02-15T00:00:00Z",
        signedBy: eve.pubKey,
      },
      [{ privKey: eve.privKey }],
    );
    const r = decide({ path: ".maintainers/endorsements/v0.2.0.json", envelope: endo, envelopeBytesHex: bytesToHex(canonicalReleaseEndorsement(endo)), state, now: new Date("2026-02-15T01:00:00Z") });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("endorsement-signer-not-holder");
  });
});

describe("decide() — KeyFile / EmailRotation", () => {
  it("accepts a self-signed KeyFile", () => {
    const alice = kp(1);
    const kf: KeyFile = signKeyFile(
      {
        kind: "KeyFile",
        version: 1,
        pubkey: alice.pubKey,
        displayName: "Alice",
        currentEmail: "alice@example.com",
        emailHistory: [{ email: "alice@example.com", from: "2026-01-01T00:00:00Z", to: null }],
        metadata: { photo: null, github: "alice", role: "maintainer" },
        introductionMandate: "g1-00000000-0000-0000-0000-000000000001",
      },
      alice.privKey,
    );
    const r = decide({ path: ".maintainers/keys/alice@example.com.json", envelope: kf, envelopeBytesHex: bytesToHex(canonicalKeyFile(kf)), state: emptyState(), now: new Date() });
    expect(r.ok).toBe(true);
  });

  it("rejects an EmailRotation whose pubkey is unknown", () => {
    const alice = kp(1);
    const rot = signEmailRotation(
      {
        kind: "EmailRotation",
        version: 1,
        pubkey: alice.pubKey,
        fromEmail: "old@example.com",
        toEmail: "new@example.com",
        rotatedAt: "2026-03-01T00:00:00Z",
      },
      alice.privKey,
    );
    const r = decide({ path: ".maintainers/keys/old@example.com.json", envelope: rot, envelopeBytesHex: bytesToHex(canonicalEmailRotation(rot)), state: emptyState(), now: new Date() });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("unknown-pubkey");
  });
});

describe("summarizeState()", () => {
  it("reports current holder and successors", () => {
    const alice = kp(1);
    const bob = kp(2);
    const { state } = stateWithRoot(alice, [bob.pubKey]);
    const s = summarizeState(state, new Date("2026-06-01T00:00:00Z"));
    expect(s.tracks).toHaveLength(1);
    expect(s.tracks[0]?.name).toBe("release");
    expect(s.tracks[0]?.currentHolder).toBe(alice.pubKey);
    expect(s.tracks[0]?.successors).toEqual([bob.pubKey]);
  });

  it("emits a takeover alarm when a successor signs", () => {
    const alice = kp(1);
    const bob = kp(2);
    const { state, mandate: m1 } = stateWithRoot(alice, [bob.pubKey]);
    const m2 = mk({ id: "t1-00000000-0000-0000-0000-000000000070", holder: bob.pubKey, issuedAt: "2027-01-01T00:00:00Z", expiresAt: "2027-06-01T00:00:00Z", successors: [], signedBy: bob.pubKey, signWith: [bob.privKey] });
    state.tracks.get("release")!.push(m2);
    const s = summarizeState(state, new Date("2027-02-01T00:00:00Z"));
    expect(s.takeoverAlarms).toHaveLength(1);
    expect(s.takeoverAlarms[0]?.previousMandate).toBe(m1.mandateId);
    expect(s.takeoverAlarms[0]?.newMandate).toBe(m2.mandateId);
    expect(s.takeoverAlarms[0]?.previousHolder).toBe(alice.pubKey);
    expect(s.takeoverAlarms[0]?.newHolder).toBe(bob.pubKey);
  });
});
