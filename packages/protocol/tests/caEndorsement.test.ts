/**
 * CaEndorsement verification tests. A CaEndorsement is a present-tense
 * lease judged against the ca-track authority at the verifier's clock
 * (NOW), with no predecessor chain — these tests pin that deviation
 * from ReleaseEndorsement and the fail-closed authorizedCaKeys set.
 */
import { describe, expect, it } from "vitest";
import { generateKeypair } from "../src/crypto.js";
import { signMandate, signCaEndorsement } from "../src/signing.js";
import { verifyTrack } from "../src/verifier.js";
import {
  verifyCaEndorsements,
  authorizedCaKeys,
  DEFAULT_CLOCK_SKEW_MS,
} from "../src/caEndorsement.js";
import type { CaEndorsement, Mandate, TrackPolicy } from "../src/types.js";

function keypair(seedByte: number): { privKey: string; pubKey: string } {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

const caPolicy: TrackPolicy = {
  track: "ca",
  defaultMandateDuration: "180d",
  approvalRule: { kind: "threshold", threshold: 1, of: "anyAuthorizedSigner" },
};

const alice = keypair(1); // ca-track maintainer (cold key)
const eve = keypair(99);

/** ca-track mandate active 2026-01-01 .. 2026-06-01. */
function caTrack(expiresAt = "2026-06-01T00:00:00Z") {
  const genesis: Mandate = signMandate(
    {
      kind: "Mandate",
      version: 1,
      mandateId: "ca-g1",
      track: "ca",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt,
      successors: [keypair(2).pubKey],
      signedBy: alice.pubKey,
    },
    [{ privKey: alice.privKey }],
  );
  return verifyTrack("ca", caPolicy, [genesis]);
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

const HOT_CA = "ab".repeat(32); // 64-hex operational CA pubkey
const NOW_IN = new Date("2026-03-04T00:00:00Z"); // inside the lease window

describe("verifyCaEndorsements", () => {
  it("accepts an in-window endorsement signed by the ca authority at now", () => {
    const r = verifyCaEndorsements(
      [mkCa(alice, { caPubkey: HOT_CA })],
      caTrack(),
      caPolicy.approvalRule,
      NOW_IN,
    );
    expect(r.validEndorsements).toHaveLength(1);
    expect(r.rejections).toHaveLength(0);
    expect(r.currentCaPubkey).toBe(HOT_CA);
  });

  it("authorizedCaKeys returns the in-window key; empty input is fail-closed", () => {
    expect(
      authorizedCaKeys(
        [mkCa(alice, { caPubkey: HOT_CA })],
        caTrack(),
        caPolicy.approvalRule,
        NOW_IN,
      ),
    ).toEqual([HOT_CA]);
    expect(
      authorizedCaKeys([], caTrack(), caPolicy.approvalRule, NOW_IN),
    ).toEqual([]);
  });

  it("rejects lease-not-yet (now well before notBefore)", () => {
    const r = verifyCaEndorsements(
      [mkCa(alice, { caPubkey: HOT_CA })],
      caTrack(),
      caPolicy.approvalRule,
      new Date("2026-02-01T00:00:00Z"),
    );
    expect(r.rejections[0]?.reason).toBe("lease-not-yet");
    expect(r.currentCaPubkey).toBeNull();
  });

  it("rejects lease-expired (now well after notAfter)", () => {
    const r = verifyCaEndorsements(
      [mkCa(alice, { caPubkey: HOT_CA })],
      caTrack(),
      caPolicy.approvalRule,
      new Date("2026-04-01T00:00:00Z"),
    );
    expect(r.rejections[0]?.reason).toBe("lease-expired");
  });

  it("rejects a malformed lease window (notAfter <= notBefore)", () => {
    const r = verifyCaEndorsements(
      [
        mkCa(alice, {
          caPubkey: HOT_CA,
          notBefore: "2026-03-08T00:00:00Z",
          notAfter: "2026-03-01T00:00:00Z",
        }),
      ],
      caTrack(),
      caPolicy.approvalRule,
      NOW_IN,
    );
    expect(r.rejections[0]?.reason).toBe("lease-window-malformed");
  });

  it("rejects an endorsement signed by a non-authority", () => {
    const r = verifyCaEndorsements(
      [mkCa(eve, { caPubkey: HOT_CA })],
      caTrack(),
      caPolicy.approvalRule,
      NOW_IN,
    );
    expect(r.rejections[0]?.reason).toBe("signer-not-authorized");
  });

  it("rejects a backdated endorsement once the ca-track holder has expired at now", () => {
    // Lease window straddles now, but the ca-track mandate expired
    // 2026-02-01; at now=2026-03-04 there is no ca authority, so even a
    // structurally perfect, in-window endorsement is rejected. This is
    // the core anti-backdating property.
    const r = verifyCaEndorsements(
      [mkCa(alice, { caPubkey: HOT_CA })],
      caTrack("2026-02-01T00:00:00Z"),
      caPolicy.approvalRule,
      NOW_IN,
    );
    expect(r.rejections[0]?.reason).toBe("no-ca-authority-at-now");
  });

  it("rejects a tampered endorsement (signature-invalid)", () => {
    const e = mkCa(alice, { caPubkey: HOT_CA });
    const tampered: CaEndorsement = { ...e, scope: "evil/scope" };
    const r = verifyCaEndorsements(
      [tampered],
      caTrack(),
      caPolicy.approvalRule,
      NOW_IN,
    );
    expect(r.rejections[0]?.reason).toBe("signature-invalid");
  });

  it("rotation: a newer in-window endorsement supersedes; both keys authorized during overlap", () => {
    const NEW_CA = "cd".repeat(32);
    const oldE = mkCa(alice, {
      caPubkey: HOT_CA,
      endorsementId: "old",
      issuedAt: "2026-03-01T00:00:00Z",
      notBefore: "2026-03-01T00:00:00Z",
      notAfter: "2026-03-10T00:00:00Z",
    });
    const newE = mkCa(alice, {
      caPubkey: NEW_CA,
      endorsementId: "new",
      issuedAt: "2026-03-05T00:00:00Z",
      notBefore: "2026-03-05T00:00:00Z",
      notAfter: "2026-03-14T00:00:00Z",
    });
    const at = new Date("2026-03-06T00:00:00Z"); // both windows overlap
    const r = verifyCaEndorsements(
      [oldE, newE],
      caTrack(),
      caPolicy.approvalRule,
      at,
    );
    expect(r.validEndorsements).toHaveLength(2);
    expect(r.currentCaPubkey).toBe(NEW_CA); // max issuedAt wins
    expect(
      authorizedCaKeys([oldE, newE], caTrack(), caPolicy.approvalRule, at),
    ).toEqual([HOT_CA, NEW_CA]);
  });

  it("honors the ±5 min window-edge skew tolerance", () => {
    const e = mkCa(alice, { caPubkey: HOT_CA }); // window 03-01 .. 03-08
    // 4 minutes before notBefore — inside default skew ⇒ accepted.
    const justBefore = new Date(Date.parse("2026-03-01T00:00:00Z") - 4 * 60_000);
    expect(
      verifyCaEndorsements([e], caTrack(), caPolicy.approvalRule, justBefore)
        .validEndorsements,
    ).toHaveLength(1);
    // 6 minutes before — outside default skew ⇒ lease-not-yet.
    const tooEarly = new Date(Date.parse("2026-03-01T00:00:00Z") - 6 * 60_000);
    expect(
      verifyCaEndorsements([e], caTrack(), caPolicy.approvalRule, tooEarly)
        .rejections[0]?.reason,
    ).toBe("lease-not-yet");
    // Skew is overridable (0 ⇒ strict).
    expect(
      verifyCaEndorsements([e], caTrack(), caPolicy.approvalRule, justBefore, {
        clockSkewMs: 0,
      }).rejections[0]?.reason,
    ).toBe("lease-not-yet");
    expect(DEFAULT_CLOCK_SKEW_MS).toBe(5 * 60 * 1000);
  });

  it("enforces an M-of-N specific-signer approval rule", () => {
    const b = keypair(2); // named successor / co-signer
    const mPolicy: TrackPolicy = {
      track: "ca",
      defaultMandateDuration: "180d",
      approvalRule: {
        kind: "threshold",
        threshold: 2,
        of: [alice.pubKey, b.pubKey],
      },
    };
    const genesis: Mandate = signMandate(
      {
        kind: "Mandate",
        version: 1,
        mandateId: "ca-m1",
        track: "ca",
        holder: alice.pubKey,
        issuedAt: "2026-01-01T00:00:00Z",
        expiresAt: "2026-06-01T00:00:00Z",
        successors: [b.pubKey],
        signedBy: alice.pubKey,
      },
      [{ privKey: alice.privKey }, { privKey: b.privKey }],
    );
    const track = verifyTrack("ca", mPolicy, [genesis]);

    const oneSig = mkCa(alice, { caPubkey: HOT_CA });
    expect(
      verifyCaEndorsements([oneSig], track, mPolicy.approvalRule, NOW_IN)
        .rejections[0]?.reason,
    ).toBe("approval-rule-unsatisfied");

    const twoSig = signCaEndorsement(
      {
        kind: "CaEndorsement",
        version: 1,
        endorsementId: "ca-e2",
        track: "ca",
        caPubkey: HOT_CA,
        scope: "flagship/directory-attestation",
        notBefore: "2026-03-01T00:00:00Z",
        notAfter: "2026-03-08T00:00:00Z",
        issuedAt: "2026-03-01T00:00:00Z",
        signedBy: alice.pubKey,
      },
      [{ privKey: alice.privKey }, { privKey: b.privKey }],
    );
    expect(
      verifyCaEndorsements([twoSig], track, mPolicy.approvalRule, NOW_IN)
        .validEndorsements,
    ).toHaveLength(1);
  });
});
