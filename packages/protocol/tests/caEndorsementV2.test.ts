/**
 * CaEndorsement v2 verification tests. A CaEndorsement is a present-tense
 * lease judged against the v2 ca-track authority at the verifier's clock
 * (NOW), no predecessor chain. These pin the §5.1 deviation under the v2
 * holder-signs model + the fail-closed authorizedCaKeysV2 set.
 */
import { describe, expect, it } from "vitest";
import { generateKeypair } from "../src/crypto.js";
import { signMandateV2, signCaEndorsement } from "../src/signing.js";
import { mandatePinHash } from "../src/canonical.js";
import { verifyMandateChainFromPin } from "../src/verifierV2.js";
import {
  verifyCaEndorsementsV2,
  authorizedCaKeysV2,
} from "../src/caEndorsementV2.js";
import { DEFAULT_CLOCK_SKEW_MS } from "../src/caEndorsement.js";
import type { CaEndorsement, MandateV2 } from "../src/types.js";

function kp(seedByte: number): { privKey: string; pubKey: string } {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

const alice = kp(1); // ca-track maintainer (cold key) = holder
const backup = kp(2);
const eve = kp(99);
const DAY = 86400;

/** v2 ca-track root mandate; expires at `expiresAt`. */
function caChain(expiresAt = "2026-06-01T00:00:00Z") {
  const m: Omit<MandateV2, "signatures"> = {
    kind: "Mandate",
    version: 2,
    mandateId: "ca-root",
    track: "ca",
    holder: alice.pubKey,
    issuedAt: "2026-01-01T00:00:00Z",
    expiresAt,
    successors: [backup.pubKey],
    approvalRule: { kind: "threshold", threshold: 1 },
    minSuccessors: 1,
    maxDurationSeconds: 365 * DAY,
    defaultDurationSeconds: 180 * DAY,
  };
  const signed = signMandateV2({ ...m, signedBy: alice.pubKey }, [
    { privKey: alice.privKey },
  ]);
  return verifyMandateChainFromPin(mandatePinHash(signed), [signed]);
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

const HOT_CA = "ab".repeat(32);
const NOW_IN = new Date("2026-03-04T00:00:00Z");

describe("verifyCaEndorsementsV2", () => {
  it("accepts an in-window endorsement signed by the v2 ca authority at now", () => {
    const r = verifyCaEndorsementsV2([mkCa(alice, { caPubkey: HOT_CA })], caChain(), NOW_IN);
    expect(r.validEndorsements).toHaveLength(1);
    expect(r.rejections).toHaveLength(0);
    expect(r.currentCaPubkey).toBe(HOT_CA);
  });

  it("authorizedCaKeysV2 returns the in-window key; empty input is fail-closed", () => {
    expect(
      authorizedCaKeysV2([mkCa(alice, { caPubkey: HOT_CA })], caChain(), NOW_IN),
    ).toEqual([HOT_CA]);
    expect(authorizedCaKeysV2([], caChain(), NOW_IN)).toEqual([]);
  });

  it("rejects lease-not-yet (now well before notBefore)", () => {
    const r = verifyCaEndorsementsV2(
      [mkCa(alice, { caPubkey: HOT_CA })],
      caChain(),
      new Date("2026-02-01T00:00:00Z"),
    );
    expect(r.rejections[0]?.reason).toBe("lease-not-yet");
    expect(r.currentCaPubkey).toBeNull();
  });

  it("rejects lease-expired (now well after notAfter)", () => {
    const r = verifyCaEndorsementsV2(
      [mkCa(alice, { caPubkey: HOT_CA })],
      caChain(),
      new Date("2026-04-01T00:00:00Z"),
    );
    expect(r.rejections[0]?.reason).toBe("lease-expired");
  });

  it("rejects a malformed lease window (notAfter <= notBefore)", () => {
    const r = verifyCaEndorsementsV2(
      [
        mkCa(alice, {
          caPubkey: HOT_CA,
          notBefore: "2026-03-08T00:00:00Z",
          notAfter: "2026-03-01T00:00:00Z",
        }),
      ],
      caChain(),
      NOW_IN,
    );
    expect(r.rejections[0]?.reason).toBe("lease-window-malformed");
  });

  it("rejects an endorsement signed by a non-authority", () => {
    const r = verifyCaEndorsementsV2([mkCa(eve, { caPubkey: HOT_CA })], caChain(), NOW_IN);
    expect(r.rejections[0]?.reason).toBe("signer-not-authorized");
  });

  it("rejects when the v2 ca-track holder has expired at now (anti-backdating)", () => {
    // Lease straddles now, but the ca-track mandate expired 2026-02-01;
    // at now=2026-03-04 there is no v2 ca authority ⇒ rejected.
    const r = verifyCaEndorsementsV2(
      [mkCa(alice, { caPubkey: HOT_CA })],
      caChain("2026-02-01T00:00:00Z"),
      NOW_IN,
    );
    expect(r.rejections[0]?.reason).toBe("no-ca-authority-at-now");
  });

  it("rejects a tampered endorsement (signature-invalid)", () => {
    const e = mkCa(alice, { caPubkey: HOT_CA });
    const tampered: CaEndorsement = { ...e, scope: "evil/scope" };
    const r = verifyCaEndorsementsV2([tampered], caChain(), NOW_IN);
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
    const at = new Date("2026-03-06T00:00:00Z");
    const r = verifyCaEndorsementsV2([oldE, newE], caChain(), at);
    expect(r.validEndorsements).toHaveLength(2);
    expect(r.currentCaPubkey).toBe(NEW_CA);
    expect(authorizedCaKeysV2([oldE, newE], caChain(), at)).toEqual([HOT_CA, NEW_CA]);
  });

  it("honors the ±5 min window-edge skew tolerance and the override", () => {
    const e = mkCa(alice, { caPubkey: HOT_CA }); // window 03-01 .. 03-08
    const justBefore = new Date(Date.parse("2026-03-01T00:00:00Z") - 4 * 60_000);
    expect(
      verifyCaEndorsementsV2([e], caChain(), justBefore).validEndorsements,
    ).toHaveLength(1);
    const tooEarly = new Date(Date.parse("2026-03-01T00:00:00Z") - 6 * 60_000);
    expect(
      verifyCaEndorsementsV2([e], caChain(), tooEarly).rejections[0]?.reason,
    ).toBe("lease-not-yet");
    expect(
      verifyCaEndorsementsV2([e], caChain(), justBefore, { clockSkewMs: 0 })
        .rejections[0]?.reason,
    ).toBe("lease-not-yet");
    expect(DEFAULT_CLOCK_SKEW_MS).toBe(5 * 60 * 1000);
  });

  it("FAIL-CLOSED: a chain anchored at an absent/forked pin ⇒ no-ca-authority-at-now", () => {
    const e = mkCa(alice, { caPubkey: HOT_CA });
    const forked = verifyMandateChainFromPin("de".repeat(32), []);
    expect(verifyCaEndorsementsV2([e], forked, NOW_IN).rejections[0]?.reason).toBe(
      "no-ca-authority-at-now",
    );
    expect(authorizedCaKeysV2([e], forked, NOW_IN)).toEqual([]);
    const noPin = verifyMandateChainFromPin("", []);
    expect(verifyCaEndorsementsV2([e], noPin, NOW_IN).rejections[0]?.reason).toBe(
      "no-ca-authority-at-now",
    );
  });
});
