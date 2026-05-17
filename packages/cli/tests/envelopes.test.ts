/**
 * Envelope-construction tests for each command's `build*` function.
 *
 * The build* functions are pure: they take parsed options + an in-memory key
 * source + a clock + a uuid factory, and return a fully signed envelope. We
 * cross-check the output against the protocol library's verifier so the CLI
 * is guaranteed to emit envelopes that verify back-to-back (the same property
 * the web UI must hold).
 *
 * `build*` is async (it may drive a YubiKey PIV transport). One test drives
 * `buildGenesis` through an injected fake PIV transport to prove the
 * maintainer-root path produces a mandate byte-identical to the hex path
 * and that the protocol verifier accepts it — the §11.1 linchpin end to end.
 */

import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  canonicalMandate,
  canonicalReleaseEndorsement,
  generateKeypair,
  intermediateMerkleRoot,
  sign,
  verify,
  verifyTrack,
  type TrackPolicy,
} from "@maintainers/protocol";
import { buildGenesis } from "../src/commands/genesis.js";
import { buildRenewal } from "../src/commands/mandate.js";
import { buildTakeover } from "../src/commands/takeover.js";
import { buildEndorsement } from "../src/commands/endorsement.js";
import { writeMandate, writeTrackPolicyIfMissing } from "../src/lib/store.js";

function keypair(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

function fakeFs(files: Record<string, string>) {
  return {
    readFileSync(p: string): string {
      const v = files[p];
      if (v === undefined) throw new Error(`ENOENT: ${p}`);
      return v;
    },
  };
}

function mkTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

const RELEASE_POLICY: TrackPolicy = {
  track: "release",
  defaultMandateDuration: "60d",
  approvalRule: { kind: "threshold", threshold: 1, of: "anyAuthorizedSigner" },
};

describe("buildGenesis", () => {
  it("produces a self-signed genesis mandate that verifies against the protocol verifier", async () => {
    const alice = keypair(1);
    const bob = keypair(2);
    const io = fakeFs({
      "./alice.pub": alice.pubKey,
      "./alice.priv": alice.privKey,
      "./bob.pub": bob.pubKey,
    });
    const m = await buildGenesis({
      track: "release",
      duration: "60d",
      holderKeySource: "file:./alice.pub",
      signingKeySource: "file:./alice.priv",
      successorsSource: "file:./bob.pub",
      outputDir: undefined,
      now: () => new Date("2026-01-01T00:00:00Z"),
      io,
      uuid: () => "11111111-1111-1111-1111-111111111111",
    });
    expect(m.kind).toBe("Mandate");
    expect(m.track).toBe("release");
    expect(m.holder).toBe(alice.pubKey);
    expect(m.signedBy).toBe(alice.pubKey);
    expect(m.successors).toEqual([bob.pubKey]);
    expect(m.issuedAt).toBe("2026-01-01T00:00:00.000Z");
    expect(m.expiresAt).toBe("2026-03-02T00:00:00.000Z");
    expect(m.signatures.length).toBe(1);

    const verified = verifyTrack("release", RELEASE_POLICY, [m]);
    expect(verified.validMandates).toHaveLength(1);
    expect(verified.rejections).toHaveLength(0);
  });

  it("rejects a signing key that does not match --holder-key", async () => {
    const alice = keypair(1);
    const bob = keypair(2);
    const io = fakeFs({
      "./alice.pub": alice.pubKey,
      "./bob.priv": bob.privKey,
    });
    await expect(
      buildGenesis({
        track: "release",
        duration: "60d",
        holderKeySource: "file:./alice.pub",
        signingKeySource: "file:./bob.priv",
        successorsSource: undefined,
        outputDir: undefined,
        now: () => new Date("2026-01-01T00:00:00Z"),
        io,
        uuid: () => "x",
      }),
    ).rejects.toThrow(/genesis must be self-signed/);
  });

  it("defaults successors to [holder] when --successors not provided", async () => {
    const alice = keypair(7);
    const io = fakeFs({
      "./alice.pub": alice.pubKey,
      "./alice.priv": alice.privKey,
    });
    const m = await buildGenesis({
      track: "release",
      duration: "30d",
      holderKeySource: "file:./alice.pub",
      signingKeySource: "file:./alice.priv",
      successorsSource: undefined,
      outputDir: undefined,
      now: () => new Date("2026-01-01T00:00:00Z"),
      io,
      uuid: () => "u",
    });
    expect(m.successors).toEqual([alice.pubKey]);
  });

  it("YubiKey-PIV genesis (injected token) is byte-identical to the hex path and verifies", async () => {
    const root = keypair(42); // the maintainer root key, resident on the token
    // holder + signer + the named successor are all read from the PIV slot
    // here (genesis is self-signed; a single fake token stands in for both
    // the no-PIN public reads and the signing tap).
    const m = await buildGenesis({
      track: "ca",
      duration: "180d",
      holderKeySource: "yubikey-piv:slot=9c",
      signingKeySource: "yubikey-piv:slot=9c",
      successorsSource: "yubikey-piv:slot=9c",
      outputDir: undefined,
      now: () => new Date("2026-05-17T00:00:00Z"),
      io: fakeFs({}),
      uuid: () => "deadbeef-dead-beef-dead-beefdeadbeef",
      // genesis reads holder (no PIN), reads successor (no PIN), then signs.
      pivTransport: {
        async getPublicKey() {
          return root.pubKey;
        },
        async signEd25519(_slot, _pin, message) {
          return sign(message, root.privKey);
        },
        async generateEd25519() {
          return root.pubKey;
        },
      },
      pivPin: async () => "424242",
    });
    expect(m.holder).toBe(root.pubKey);
    expect(m.signedBy).toBe(root.pubKey);
    // Same canonical bytes ⇒ same signature as the in-process hex path.
    const bytes = canonicalMandate(m);
    expect(verify(m.signatures[0]!.sig, bytes, root.pubKey)).toBe(true);
    expect(m.signatures[0]!.sig).toBe(sign(bytes, root.privKey));
    const policy: TrackPolicy = { ...RELEASE_POLICY, track: "ca" };
    const verified = verifyTrack("ca", policy, [m]);
    expect(verified.validMandates).toHaveLength(1);
    expect(verified.rejections).toHaveLength(0);
  });
});

describe("buildRenewal", () => {
  it("produces a holder-signed renewal that the verifier accepts as a continuation", async () => {
    const alice = keypair(1);
    const bob = keypair(2);
    const tmp = mkTmp("maintainers-cli-renewal-");
    writeTrackPolicyIfMissing(tmp, RELEASE_POLICY);
    const genesis = await buildGenesis({
      track: "release",
      duration: "60d",
      holderKeySource: "file:./alice.pub",
      signingKeySource: "file:./alice.priv",
      successorsSource: "file:./bob.pub",
      outputDir: undefined,
      now: () => new Date("2026-01-01T00:00:00Z"),
      io: fakeFs({
        "./alice.pub": alice.pubKey,
        "./alice.priv": alice.privKey,
        "./bob.pub": bob.pubKey,
      }),
      uuid: () => "g1g1g1g1-g1g1-g1g1-g1g1-g1g1g1g1g1g1",
    });
    writeMandate(tmp, genesis);

    const renewal = await buildRenewal({
      track: "release",
      duration: "60d",
      signingKeySource: "file:./alice.priv",
      successorsSource: undefined,
      rootDir: tmp,
      now: () => new Date("2026-02-01T00:00:00Z"),
      io: fakeFs({ "./alice.priv": alice.privKey }),
      uuid: () => "r1r1r1r1-r1r1-r1r1-r1r1-r1r1r1r1r1r1",
    });

    expect(renewal.holder).toBe(alice.pubKey);
    expect(renewal.signedBy).toBe(alice.pubKey);
    expect(renewal.successors).toEqual([bob.pubKey]);
    const verified = verifyTrack("release", RELEASE_POLICY, [genesis, renewal]);
    expect(verified.validMandates).toHaveLength(2);
    expect(verified.rejections).toHaveLength(0);
  });

  it("rejects a renewal signed by someone who is not the current holder", async () => {
    const alice = keypair(1);
    const bob = keypair(2);
    const tmp = mkTmp("maintainers-cli-renewal-bad-");
    writeTrackPolicyIfMissing(tmp, RELEASE_POLICY);
    const genesis = await buildGenesis({
      track: "release",
      duration: "60d",
      holderKeySource: "file:./alice.pub",
      signingKeySource: "file:./alice.priv",
      successorsSource: "file:./bob.pub",
      outputDir: undefined,
      now: () => new Date("2026-01-01T00:00:00Z"),
      io: fakeFs({
        "./alice.pub": alice.pubKey,
        "./alice.priv": alice.privKey,
        "./bob.pub": bob.pubKey,
      }),
      uuid: () => "gx",
    });
    writeMandate(tmp, genesis);
    await expect(
      buildRenewal({
        track: "release",
        duration: "60d",
        signingKeySource: "file:./bob.priv",
        successorsSource: undefined,
        rootDir: tmp,
        now: () => new Date("2026-02-01T00:00:00Z"),
        io: fakeFs({ "./bob.priv": bob.privKey }),
        uuid: () => "rx",
      }),
    ).rejects.toThrow(/not the current holder/);
  });
});

describe("buildTakeover", () => {
  it("named successor produces a takeover after expiry that verifies", async () => {
    const alice = keypair(1);
    const bob = keypair(2);
    const tmp = mkTmp("maintainers-cli-takeover-");
    writeTrackPolicyIfMissing(tmp, RELEASE_POLICY);
    const genesis = await buildGenesis({
      track: "release",
      duration: "30d",
      holderKeySource: "file:./alice.pub",
      signingKeySource: "file:./alice.priv",
      successorsSource: "file:./bob.pub",
      outputDir: undefined,
      now: () => new Date("2026-01-01T00:00:00Z"),
      io: fakeFs({
        "./alice.pub": alice.pubKey,
        "./alice.priv": alice.privKey,
        "./bob.pub": bob.pubKey,
      }),
      uuid: () => "g",
    });
    writeMandate(tmp, genesis);

    const takeover = await buildTakeover({
      track: "release",
      duration: "60d",
      successorKeySource: "file:./bob.priv",
      newHolderSource: "file:./bob.pub",
      successorsSource: undefined,
      rootDir: tmp,
      now: () => new Date("2026-02-15T00:00:00Z"), // after the 30-day expiry
      io: fakeFs({
        "./bob.priv": bob.privKey,
        "./bob.pub": bob.pubKey,
      }),
      uuid: () => "t",
    });

    expect(takeover.holder).toBe(bob.pubKey);
    expect(takeover.signedBy).toBe(bob.pubKey);
    expect(takeover.successors).toEqual([bob.pubKey]);
    const verified = verifyTrack("release", RELEASE_POLICY, [genesis, takeover]);
    expect(verified.validMandates).toHaveLength(2);
    expect(verified.rejections).toHaveLength(0);
  });

  it("rejects a takeover before the predecessor expires", async () => {
    const alice = keypair(1);
    const bob = keypair(2);
    const tmp = mkTmp("maintainers-cli-takeover-early-");
    writeTrackPolicyIfMissing(tmp, RELEASE_POLICY);
    const genesis = await buildGenesis({
      track: "release",
      duration: "30d",
      holderKeySource: "file:./alice.pub",
      signingKeySource: "file:./alice.priv",
      successorsSource: "file:./bob.pub",
      outputDir: undefined,
      now: () => new Date("2026-01-01T00:00:00Z"),
      io: fakeFs({
        "./alice.pub": alice.pubKey,
        "./alice.priv": alice.privKey,
        "./bob.pub": bob.pubKey,
      }),
      uuid: () => "g",
    });
    writeMandate(tmp, genesis);
    await expect(
      buildTakeover({
        track: "release",
        duration: "60d",
        successorKeySource: "file:./bob.priv",
        newHolderSource: "file:./bob.pub",
        successorsSource: undefined,
        rootDir: tmp,
        now: () => new Date("2026-01-15T00:00:00Z"),
        io: fakeFs({
          "./bob.priv": bob.privKey,
          "./bob.pub": bob.pubKey,
        }),
        uuid: () => "t",
      }),
    ).rejects.toThrow(/has not yet expired/);
  });

  it("rejects a takeover signed by a non-successor", async () => {
    const alice = keypair(1);
    const bob = keypair(2);
    const eve = keypair(3);
    const tmp = mkTmp("maintainers-cli-takeover-eve-");
    writeTrackPolicyIfMissing(tmp, RELEASE_POLICY);
    const genesis = await buildGenesis({
      track: "release",
      duration: "30d",
      holderKeySource: "file:./alice.pub",
      signingKeySource: "file:./alice.priv",
      successorsSource: "file:./bob.pub",
      outputDir: undefined,
      now: () => new Date("2026-01-01T00:00:00Z"),
      io: fakeFs({
        "./alice.pub": alice.pubKey,
        "./alice.priv": alice.privKey,
        "./bob.pub": bob.pubKey,
      }),
      uuid: () => "g",
    });
    writeMandate(tmp, genesis);
    await expect(
      buildTakeover({
        track: "release",
        duration: "60d",
        successorKeySource: "file:./eve.priv",
        newHolderSource: "file:./eve.pub",
        successorsSource: undefined,
        rootDir: tmp,
        now: () => new Date("2026-02-15T00:00:00Z"),
        io: fakeFs({
          "./eve.priv": eve.privKey,
          "./eve.pub": eve.pubKey,
        }),
        uuid: () => "t",
      }),
    ).rejects.toThrow(/not a named successor/);
  });
});

describe("buildEndorsement", () => {
  it("produces a genesis release endorsement with correct merkle root", async () => {
    const alice = keypair(1);
    const tmp = mkTmp("maintainers-cli-endorsement-");
    writeTrackPolicyIfMissing(tmp, RELEASE_POLICY);
    const genesis = await buildGenesis({
      track: "release",
      duration: "60d",
      holderKeySource: "file:./alice.pub",
      signingKeySource: "file:./alice.priv",
      successorsSource: undefined,
      outputDir: undefined,
      now: () => new Date("2026-01-01T00:00:00Z"),
      io: fakeFs({
        "./alice.pub": alice.pubKey,
        "./alice.priv": alice.privKey,
      }),
      uuid: () => "g",
    });
    writeMandate(tmp, genesis);

    const commit = "a".repeat(40);
    const e = buildEndorsement({
      commit,
      tag: "v0.1.0",
      previousId: null,
      previousCommit: null,
      intermediatesSpec: commit,
      signingKeySource: "file:./alice.priv",
      track: "release",
      rootDir: tmp,
      now: () => new Date("2026-01-15T00:00:00Z"),
      io: fakeFs({ "./alice.priv": alice.privKey }),
      uuid: () => "e1e1e1e1-e1e1-e1e1-e1e1-e1e1e1e1e1e1",
    });

    expect(e.semverTag).toBe("v0.1.0");
    expect(e.commitHash).toBe(commit);
    expect(e.previousReleaseId).toBeNull();
    expect(e.previousCommitHash).toBeNull();
    expect(e.intermediateCommits).toEqual([commit]);
    expect(e.intermediateMerkleRoot).toBe(intermediateMerkleRoot([commit]));
    const bytes = canonicalReleaseEndorsement(e);
    expect(verify(e.signatures[0]!.sig, bytes, alice.pubKey)).toBe(true);
  });

  it("verifies inline csv intermediates produce a correct merkle root", async () => {
    const alice = keypair(1);
    const tmp = mkTmp("maintainers-cli-endorsement-csv-");
    writeTrackPolicyIfMissing(tmp, RELEASE_POLICY);
    const genesis = await buildGenesis({
      track: "release",
      duration: "60d",
      holderKeySource: "file:./alice.pub",
      signingKeySource: "file:./alice.priv",
      successorsSource: undefined,
      outputDir: undefined,
      now: () => new Date("2026-01-01T00:00:00Z"),
      io: fakeFs({
        "./alice.pub": alice.pubKey,
        "./alice.priv": alice.privKey,
      }),
      uuid: () => "g",
    });
    writeMandate(tmp, genesis);

    const c1 = "1".repeat(40);
    const c2 = "2".repeat(40);
    const c3 = "3".repeat(40);
    const e = buildEndorsement({
      commit: c3,
      tag: "v0.2.0",
      previousId: "e1e1e1e1-e1e1-e1e1-e1e1-e1e1e1e1e1e1",
      previousCommit: c1,
      intermediatesSpec: `${c2},${c3}`,
      signingKeySource: "file:./alice.priv",
      track: "release",
      rootDir: tmp,
      now: () => new Date("2026-02-01T00:00:00Z"),
      io: fakeFs({ "./alice.priv": alice.privKey }),
      uuid: () => "e2",
    });
    expect(e.intermediateCommits).toEqual([c2, c3]);
    expect(e.intermediateMerkleRoot).toBe(intermediateMerkleRoot([c2, c3]));
  });

  it("rejects a non-hex commit hash", async () => {
    const alice = keypair(1);
    const tmp = mkTmp("maintainers-cli-endorsement-bad-");
    writeTrackPolicyIfMissing(tmp, RELEASE_POLICY);
    const genesis = await buildGenesis({
      track: "release",
      duration: "60d",
      holderKeySource: "file:./alice.pub",
      signingKeySource: "file:./alice.priv",
      successorsSource: undefined,
      outputDir: undefined,
      now: () => new Date("2026-01-01T00:00:00Z"),
      io: fakeFs({
        "./alice.pub": alice.pubKey,
        "./alice.priv": alice.privKey,
      }),
      uuid: () => "g",
    });
    writeMandate(tmp, genesis);

    expect(() =>
      buildEndorsement({
        commit: "zzz",
        tag: "v0.0.1",
        previousId: null,
        previousCommit: null,
        intermediatesSpec: "auto",
        signingKeySource: "file:./alice.priv",
        track: "release",
        rootDir: tmp,
        now: () => new Date("2026-01-15T00:00:00Z"),
        io: fakeFs({ "./alice.priv": alice.privKey }),
        uuid: () => "e",
      }),
    ).toThrow(/commit must be a 40-character commit hash/);
  });
});

describe("canonical-bytes parity with the protocol library", () => {
  it("canonicalMandate over a CLI-built mandate matches what the signer signed", async () => {
    const alice = keypair(11);
    const io = fakeFs({
      "./alice.pub": alice.pubKey,
      "./alice.priv": alice.privKey,
    });
    const m = await buildGenesis({
      track: "release",
      duration: "60d",
      holderKeySource: "file:./alice.pub",
      signingKeySource: "file:./alice.priv",
      successorsSource: undefined,
      outputDir: undefined,
      now: () => new Date("2026-01-01T00:00:00Z"),
      io,
      uuid: () => "deadbeef-dead-beef-dead-beefdeadbeef",
    });
    const bytes = canonicalMandate(m);
    expect(verify(m.signatures[0]!.sig, bytes, alice.pubKey)).toBe(true);
  });
});
