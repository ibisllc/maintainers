/**
 * Signing helpers — verify that each sign* function produces an
 * envelope whose canonical bytes verify against the produced signature.
 */
import { describe, expect, it } from "vitest";
import { generateKeypair, sign, verify } from "../src/crypto.js";
import {
  signEmailRotation,
  signKeyFile,
  signKeyIntroductionRequest,
  signKeyRedirect,
  signMandate,
  signReleaseEndorsement,
  signCaEndorsement,
  privKeySigner,
  signMandateWith,
  signReleaseEndorsementWith,
  signCaEndorsementWith,
  signKeyFileWith,
  signKeyRedirectWith,
  signEmailRotationWith,
  type Ed25519Signer,
} from "../src/signing.js";
import {
  canonicalEmailRotation,
  canonicalKeyFile,
  canonicalKeyIntroductionRequest,
  canonicalKeyRedirect,
  canonicalMandate,
  canonicalReleaseEndorsement,
  canonicalCaEndorsement,
} from "../src/canonical.js";

function keypair(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

describe("sign* roundtrips", () => {
  it("signMandate signature verifies against canonicalMandate", () => {
    const alice = keypair(1);
    const bob = keypair(2);
    const m = signMandate(
      {
        kind: "Mandate",
        version: 1,
        mandateId: "g1",
        track: "release",
        holder: alice.pubKey,
        issuedAt: "2026-01-01T00:00:00Z",
        expiresAt: "2026-03-01T00:00:00Z",
        successors: [bob.pubKey],
        signedBy: alice.pubKey,
      },
      [{ privKey: alice.privKey }],
    );
    const bytes = canonicalMandate(m);
    expect(verify(m.signatures[0]!.sig, bytes, m.signatures[0]!.pubkey)).toBe(true);
  });

  it("signKeyFile self-signs against canonicalKeyFile", () => {
    const alice = keypair(1);
    const k = signKeyFile(
      {
        kind: "KeyFile",
        version: 1,
        pubkey: alice.pubKey,
        displayName: "Alice",
        currentEmail: "alice@example.com",
        emailHistory: [],
        metadata: { photo: null, github: null, role: null },
        introductionMandate: "intro-1",
      },
      alice.privKey,
    );
    const bytes = canonicalKeyFile(k);
    expect(verify(k.signature, bytes, alice.pubKey)).toBe(true);
  });

  it("signKeyFile rejects mismatched priv/pub", () => {
    const alice = keypair(1);
    const bob = keypair(2);
    expect(() =>
      signKeyFile(
        {
          kind: "KeyFile",
          version: 1,
          pubkey: alice.pubKey,
          displayName: "Alice",
          currentEmail: "alice@example.com",
          emailHistory: [],
          metadata: { photo: null, github: null, role: null },
          introductionMandate: "intro-1",
        },
        bob.privKey, // wrong key
      ),
    ).toThrow(/does not correspond/);
  });

  it("signKeyRedirect signs against canonical bytes", () => {
    const alice = keypair(1);
    const r = signKeyRedirect(
      {
        kind: "KeyRedirect",
        version: 1,
        fromEmail: "old@example.com",
        renamedTo: "new@example.com",
        renamedAt: "2026-05-01T00:00:00Z",
        pubkey: alice.pubKey,
      },
      alice.privKey,
    );
    const bytes = canonicalKeyRedirect(r);
    expect(verify(r.signature, bytes, alice.pubKey)).toBe(true);
  });

  it("signEmailRotation signs against canonical bytes", () => {
    const alice = keypair(1);
    const r = signEmailRotation(
      {
        kind: "EmailRotation",
        version: 1,
        pubkey: alice.pubKey,
        fromEmail: "old@example.com",
        toEmail: "new@example.com",
        rotatedAt: "2026-05-01T00:00:00Z",
      },
      alice.privKey,
    );
    const bytes = canonicalEmailRotation(r);
    expect(verify(r.signature, bytes, alice.pubKey)).toBe(true);
  });

  it("signKeyIntroductionRequest signs against canonical bytes", () => {
    const alice = keypair(1);
    const r = signKeyIntroductionRequest(
      {
        kind: "KeyIntroductionRequest",
        version: 1,
        pubkey: alice.pubKey,
        displayName: "Alice",
        currentEmail: "alice@example.com",
        metadata: { photo: null, github: null, role: null },
        requestedAt: "2026-05-01T00:00:00Z",
      },
      alice.privKey,
    );
    const bytes = canonicalKeyIntroductionRequest(r);
    expect(verify(r.signature, bytes, alice.pubKey)).toBe(true);
  });

  it("signReleaseEndorsement signs against canonical bytes", () => {
    const alice = keypair(1);
    const e = signReleaseEndorsement(
      {
        kind: "ReleaseEndorsement",
        version: 1,
        releaseId: "r1",
        semverTag: "v0.1.0",
        commitHash: "0".repeat(40),
        previousReleaseId: null,
        previousCommitHash: null,
        intermediateCommits: [],
        intermediateMerkleRoot: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        endorsedNotes: null,
        issuedAt: "2026-02-01T00:00:00Z",
        signedBy: alice.pubKey,
      },
      [{ privKey: alice.privKey }],
    );
    const bytes = canonicalReleaseEndorsement(e);
    expect(verify(e.signatures[0]!.sig, bytes, alice.pubKey)).toBe(true);
  });
});

describe("external Ed25519Signer (#28 — YubiKey-PIV seam)", () => {
  const mandate = (holder: string) => ({
    kind: "Mandate" as const,
    version: 1 as const,
    mandateId: "m1",
    track: "ca",
    holder,
    issuedAt: "2026-03-01T00:00:00Z",
    expiresAt: "2026-09-01T00:00:00Z",
    successors: [holder],
    signedBy: holder,
  });
  const caEndorsement = (signedBy: string) => ({
    kind: "CaEndorsement" as const,
    version: 1 as const,
    endorsementId: "ca-e1",
    track: "ca",
    caPubkey: "ab".repeat(32),
    scope: "flagship/directory-attestation",
    notBefore: "2026-03-01T00:00:00Z",
    notAfter: "2026-03-08T00:00:00Z",
    issuedAt: "2026-03-01T00:00:00Z",
    signedBy,
  });
  const releaseEndorsement = (signedBy: string) => ({
    kind: "ReleaseEndorsement" as const,
    version: 1 as const,
    releaseId: "r1",
    semverTag: "v0.1.0",
    commitHash: "0".repeat(40),
    previousReleaseId: null,
    previousCommitHash: null,
    intermediateCommits: [],
    intermediateMerkleRoot:
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    endorsedNotes: null,
    issuedAt: "2026-02-01T00:00:00Z",
    signedBy,
  });

  /**
   * A signer that mimics a hardware token: it holds the key "out of
   * process" (the test closes over it, the protocol code never sees a
   * privKey) and is async, like a PC/SC/NFC round-trip. It still emits
   * standard RFC-8032 Ed25519 over the presented bytes.
   */
  function fakeTokenSigner(priv: string, pub: string): Ed25519Signer {
    return {
      pubKey: pub,
      async sign(message) {
        await Promise.resolve();
        return sign(message, priv);
      },
    };
  }

  it("privKeySigner produces byte-identical output to the sync path (Mandate)", async () => {
    const a = keypair(1);
    const sync = signMandate(mandate(a.pubKey), [{ privKey: a.privKey }]);
    const viaSigner = await signMandateWith(mandate(a.pubKey), [
      privKeySigner(a.privKey),
    ]);
    expect(viaSigner).toEqual(sync);
  });

  it("privKeySigner is byte-identical for CaEndorsement (the weekly lease)", async () => {
    const a = keypair(2);
    const sync = signCaEndorsement(caEndorsement(a.pubKey), [
      { privKey: a.privKey },
    ]);
    const viaSigner = await signCaEndorsementWith(caEndorsement(a.pubKey), [
      privKeySigner(a.privKey),
    ]);
    expect(viaSigner).toEqual(sync);
    expect(
      verify(
        viaSigner.signatures[0]!.sig,
        canonicalCaEndorsement(viaSigner),
        a.pubKey,
      ),
    ).toBe(true);
  });

  it("privKeySigner is byte-identical for ReleaseEndorsement", async () => {
    const a = keypair(3);
    const sync = signReleaseEndorsement(releaseEndorsement(a.pubKey), [
      { privKey: a.privKey },
    ]);
    const viaSigner = await signReleaseEndorsementWith(
      releaseEndorsement(a.pubKey),
      [privKeySigner(a.privKey)],
    );
    expect(viaSigner).toEqual(sync);
  });

  it("an external async (token-shaped) signer produces a verifiable envelope", async () => {
    const a = keypair(4);
    const ca = await signCaEndorsementWith(caEndorsement(a.pubKey), [
      fakeTokenSigner(a.privKey, a.pubKey),
    ]);
    // Identical to having signed with the raw key — the wire format,
    // canonical bytes and verifier are untouched (the §11.1 linchpin).
    expect(ca).toEqual(
      signCaEndorsement(caEndorsement(a.pubKey), [{ privKey: a.privKey }]),
    );
    expect(
      verify(ca.signatures[0]!.sig, canonicalCaEndorsement(ca), a.pubKey),
    ).toBe(true);
  });

  it("collects multiple signers in order (M-of-N), token + hex mixed", async () => {
    const a = keypair(5);
    const b = keypair(6);
    const m = await signMandateWith(mandate(a.pubKey), [
      fakeTokenSigner(a.privKey, a.pubKey),
      privKeySigner(b.privKey),
    ]);
    expect(m.signatures.map((s) => s.pubkey)).toEqual([a.pubKey, b.pubKey]);
    const bytes = canonicalMandate(m);
    expect(verify(m.signatures[0]!.sig, bytes, a.pubKey)).toBe(true);
    expect(verify(m.signatures[1]!.sig, bytes, b.pubKey)).toBe(true);
  });

  // ── identity envelopes: single SELF-signature (register / rotate-email)
  const keyFile = (pub: string) => ({
    kind: "KeyFile" as const,
    version: 1 as const,
    pubkey: pub,
    displayName: "Harry Winner",
    currentEmail: "harry@harrywinner.com",
    emailHistory: [
      { email: "harry@harrywinner.com", from: "2026-03-01T00:00:00Z", to: null },
    ],
    metadata: { photo: null, github: "hwinner", role: "maintainer" },
    introductionMandate: "11111111-1111-4111-8111-111111111111",
  });
  const keyRedirect = (pub: string) => ({
    kind: "KeyRedirect" as const,
    version: 1 as const,
    fromEmail: "harry@old.example",
    renamedTo: "harry@harrywinner.com",
    renamedAt: "2026-03-01T00:00:00Z",
    pubkey: pub,
  });
  const emailRotation = (pub: string) => ({
    kind: "EmailRotation" as const,
    version: 1 as const,
    pubkey: pub,
    fromEmail: "harry@old.example",
    toEmail: "harry@harrywinner.com",
    rotatedAt: "2026-03-01T00:00:00Z",
  });

  it("signKeyFileWith is byte-identical to the sync self-signed path", async () => {
    const a = keypair(7);
    const sync = signKeyFile(keyFile(a.pubKey), a.privKey);
    const viaSigner = await signKeyFileWith(keyFile(a.pubKey), [
      privKeySigner(a.privKey),
    ]);
    expect(viaSigner).toEqual(sync);
    expect(
      verify(viaSigner.signature, canonicalKeyFile(viaSigner), a.pubKey),
    ).toBe(true);
  });

  it("signKeyRedirectWith / signEmailRotationWith byte-identical + a token-shaped signer verifies", async () => {
    const a = keypair(8);
    expect(
      await signKeyRedirectWith(keyRedirect(a.pubKey), [
        privKeySigner(a.privKey),
      ]),
    ).toEqual(signKeyRedirect(keyRedirect(a.pubKey), a.privKey));
    const rot = await signEmailRotationWith(emailRotation(a.pubKey), [
      fakeTokenSigner(a.privKey, a.pubKey),
    ]);
    expect(rot).toEqual(signEmailRotation(emailRotation(a.pubKey), a.privKey));
    expect(
      verify(rot.signature, canonicalEmailRotation(rot), a.pubKey),
    ).toBe(true);
  });

  it("self-signed envelopes fail closed: wrong signer pubkey is rejected", async () => {
    const a = keypair(9);
    const b = keypair(10);
    // b signs a KeyFile that claims a's pubkey — must reject (not self).
    await expect(
      signKeyFileWith(keyFile(a.pubKey), [fakeTokenSigner(b.privKey, b.pubKey)]),
    ).rejects.toThrow(/does not correspond to the envelope's pubkey/);
  });

  it("self-signed envelopes fail closed: must have exactly one signer", async () => {
    const a = keypair(11);
    const b = keypair(12);
    await expect(signKeyFileWith(keyFile(a.pubKey), [])).rejects.toThrow(
      /exactly one self-signer/,
    );
    await expect(
      signEmailRotationWith(emailRotation(a.pubKey), [
        privKeySigner(a.privKey),
        privKeySigner(b.privKey),
      ]),
    ).rejects.toThrow(/exactly one self-signer/);
  });
});
