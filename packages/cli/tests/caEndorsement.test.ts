/**
 * `ca-endorsement` command — the weekly CA lease (LOCKED Phase-2 v2).
 *
 * The emitted envelope is still a v1 `CaEndorsement` (that type is
 * unchanged by the v2 model — only the Mandate/policy authority path
 * moved). We cross-check end to end against the **v2** verifier: a
 * ca-track from-scratch (root) `Mandate` → `verifyMandateChainFromPin`
 * → `verifyCaEndorsements` / `authorizedCaKeys`. The CLI must emit a
 * lease the §9 link-3 chokepoint accepts at the verifier's clock and
 * that authorizes exactly the hot CA pubkey. The YubiKey-PIV path must
 * be byte-identical to the hex path (§11.1).
 */

import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  authorizedCaKeys,
  canonicalCaEndorsement,
  generateKeypair,
  mandatePinHash,
  sign,
  signCaEndorsement,
  signMandate,
  verify,
  verifyCaEndorsements,
  verifyMandateChainFromPin,
  type Mandate,
} from "@ibisllc/maintainers";
import { buildCaEndorsement } from "../src/commands/caEndorsement.js";
import { dispatch, type CliEnv } from "../src/index.js";
import { parseArgs } from "../src/lib/args.js";
import { writeMandate } from "../src/lib/store.js";
import type { PivTransport } from "../src/lib/keysource.js";

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

const NOW = new Date("2026-05-17T12:00:00Z");

/** A ca-track from-scratch (root) v2 mandate self-signed by `maintainer`
 *  as the cold authority — long-lived so it is the live authority at NOW. */
function caRootMandate(maintainer: { pubKey: string; privKey: string }): Mandate {
  const unsigned: Omit<Mandate, "signatures"> = {
    kind: "Mandate",
    version: 1,
    mandateId: "ca-root-0000-4000-8000-000000000000",
    track: "ca",
    holder: maintainer.pubKey,
    issuedAt: "2026-01-01T00:00:00.000Z",
    expiresAt: "2027-01-01T00:00:00.000Z",
    successors: [maintainer.pubKey],
    approvalRule: { kind: "threshold", threshold: 1 },
    minSuccessors: 1,
    maxDurationSeconds: 365 * 86_400,
    defaultDurationSeconds: 365 * 86_400,
    project: { name: "flagship", contact: "harry@flagship.services", tracks: ["ca"] },
    signedBy: maintainer.pubKey,
  };
  return signMandate(unsigned, [{ privKey: maintainer.privKey }]);
}

/** The verified v2 ca chain anchored at the root's own pin. */
function caChainOf(maintainer: { pubKey: string; privKey: string }) {
  const root = caRootMandate(maintainer);
  return verifyMandateChainFromPin(mandatePinHash(root), [root]);
}

describe("buildCaEndorsement", () => {
  it("emits a lease the v2 verifier accepts and that authorizes the hot CA key", async () => {
    const maintainer = keypair(1);
    const hotCa = keypair(9);
    const e = await buildCaEndorsement({
      caPubkey: hotCa.pubKey,
      scope: "flagship/directory-attestation",
      duration: "7d",
      track: "ca",
      signingKeySource: "file:./m.priv",
      now: () => NOW,
      io: fakeFs({ "./m.priv": maintainer.privKey }),
      uuid: () => "ca-e1-0000-0000-0000-000000000000",
    });

    expect(e.kind).toBe("CaEndorsement");
    expect(e.signedBy).toBe(maintainer.pubKey);
    expect(e.caPubkey).toBe(hotCa.pubKey);
    expect(e.notBefore).toBe("2026-05-17T12:00:00.000Z");
    expect(e.notAfter).toBe("2026-05-24T12:00:00.000Z");
    // Byte-identical to the in-process signCaEndorsement path.
    const { signatures, ...unsigned } = e;
    void signatures;
    expect(e).toEqual(signCaEndorsement(unsigned, [{ privKey: maintainer.privKey }]));
    expect(verify(e.signatures[0]!.sig, canonicalCaEndorsement(e), maintainer.pubKey)).toBe(true);

    const caChain = caChainOf(maintainer);
    const result = verifyCaEndorsements([e], caChain, NOW);
    expect(result.validEndorsements).toHaveLength(1);
    expect(result.rejections).toHaveLength(0);
    expect(result.currentCaPubkey).toBe(hotCa.pubKey);
    expect(authorizedCaKeys([e], caChain, NOW)).toEqual([hotCa.pubKey]);
  });

  it("a lapsed lease is rejected at the verifier's clock (fail-closed)", async () => {
    const maintainer = keypair(2);
    const hotCa = keypair(8);
    const e = await buildCaEndorsement({
      caPubkey: hotCa.pubKey,
      scope: "flagship/directory-attestation",
      duration: "7d",
      track: "ca",
      signingKeySource: "file:./m.priv",
      now: () => NOW,
      io: fakeFs({ "./m.priv": maintainer.privKey }),
      uuid: () => "ca-e2-0000-0000-0000-000000000000",
    });
    const caChain = caChainOf(maintainer);
    const later = new Date("2026-06-30T00:00:00Z"); // well past notAfter
    expect(authorizedCaKeys([e], caChain, later)).toEqual([]);
  });

  it("an empty/absent pin ⇒ no-pin ⇒ fail-closed (no CA key is authorized)", async () => {
    const maintainer = keypair(13);
    const hotCa = keypair(14);
    const e = await buildCaEndorsement({
      caPubkey: hotCa.pubKey,
      scope: "flagship/directory-attestation",
      duration: "7d",
      track: "ca",
      signingKeySource: "file:./m.priv",
      now: () => NOW,
      io: fakeFs({ "./m.priv": maintainer.privKey }),
      uuid: () => "ca-e-empty-0000-0000-000000000000",
    });
    const root = caRootMandate(maintainer);
    // empty baked pin ⇒ rootError "no-pin" ⇒ empty chain ⇒ reject all.
    const noPin = verifyMandateChainFromPin("", [root]);
    expect(noPin.rootError).toBe("no-pin");
    expect(authorizedCaKeys([e], noPin, NOW)).toEqual([]);
  });

  it("YubiKey-PIV (injected token) is byte-identical to the file: path", async () => {
    const maintainer = keypair(3);
    const hotCa = keypair(7);
    const token: PivTransport = {
      async getPublicKey() {
        return maintainer.pubKey;
      },
      async signEd25519(_slot, _pin, message) {
        return sign(message, maintainer.privKey);
      },
      async generateEd25519() {
        return maintainer.pubKey;
      },
    };
    const common = {
      caPubkey: hotCa.pubKey,
      scope: "flagship/directory-attestation",
      duration: "7d",
      track: "ca",
      now: () => NOW,
      uuid: () => "ca-e3-0000-0000-0000-000000000000",
    };
    const viaFile = await buildCaEndorsement({
      ...common,
      signingKeySource: "file:./m.priv",
      io: fakeFs({ "./m.priv": maintainer.privKey }),
    });
    const viaPiv = await buildCaEndorsement({
      ...common,
      signingKeySource: "yubikey-piv:slot=9c",
      io: fakeFs({}),
      pivTransport: token,
      pivPin: async () => "424242",
    });
    expect(viaPiv).toEqual(viaFile);
  });

  it("rejects a malformed --ca-pubkey", async () => {
    const maintainer = keypair(4);
    await expect(
      buildCaEndorsement({
        caPubkey: "not-hex",
        scope: "s",
        duration: "7d",
        track: "ca",
        signingKeySource: "file:./m.priv",
        now: () => NOW,
        io: fakeFs({ "./m.priv": maintainer.privKey }),
        uuid: () => "x",
      }),
    ).rejects.toThrow(/--ca-pubkey must be exactly 64 hex/);
  });
});

describe("ca-endorsement dispatch (e2e)", () => {
  function mkEnv(lines: string[]): CliEnv {
    return {
      now: () => NOW,
      io: { readFileSync: (p: string) => fs.readFileSync(p, "utf8") },
      uuid: () => "ca-disp-0000-0000-0000-000000000000",
      println: (l) => lines.push(l),
      printerr: (l) => lines.push(`ERR ${l}`),
    };
  }

  it("writes a CaEndorsement under .maintainers/ca-endorsements and exits 0", async () => {
    const maintainer = keypair(5);
    const hotCa = keypair(6);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "maintainers-ca-disp-"));
    const root = path.join(tmp, ".maintainers");
    const keyFile = path.join(tmp, "m.priv");
    fs.writeFileSync(keyFile, maintainer.privKey);
    // A real ca-track v2 root mandate on disk so the signer IS the
    // on-disk authority (the advisory must NOT fire).
    writeMandate(root, caRootMandate(maintainer));

    const lines: string[] = [];
    const code = await dispatch(
      parseArgs([
        "ca-endorsement",
        "--ca-pubkey",
        hotCa.pubKey,
        "--signing-key",
        `file:${keyFile}`,
        "--path",
        root,
        "--yes",
      ]),
      mkEnv(lines),
    );
    expect(code).toBe(0);
    const dir = path.join(root, "ca-endorsements");
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
    expect(files).toHaveLength(1);
    const e = JSON.parse(fs.readFileSync(path.join(dir, files[0]!), "utf8"));
    expect(e.kind).toBe("CaEndorsement");
    expect(e.caPubkey).toBe(hotCa.pubKey);
    expect(e.signedBy).toBe(maintainer.pubKey);
    expect(lines.join("\n")).toContain("wrote CA lease");
    // The on-disk-authority ADVISORY must not fire (root is present +
    // the signer is the authority). Scoped to the advisory's wording so
    // it doesn't collide with the always-on preview's "note:" line.
    expect(lines.join("\n")).not.toMatch(/^note: (no |signer )/m);

    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("emits an advisory when no ca-track mandate exists on disk", async () => {
    const maintainer = keypair(11);
    const hotCa = keypair(12);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "maintainers-ca-noauth-"));
    const root = path.join(tmp, ".maintainers");
    const keyFile = path.join(tmp, "m.priv");
    fs.writeFileSync(keyFile, maintainer.privKey);

    const lines: string[] = [];
    const code = await dispatch(
      parseArgs([
        "ca-endorsement",
        "--ca-pubkey",
        hotCa.pubKey,
        "--signing-key",
        `file:${keyFile}`,
        "--path",
        root,
        "--yes",
      ]),
      mkEnv(lines),
    );
    expect(code).toBe(0);
    expect(lines.join("\n")).toMatch(/note: no "ca"-track mandates found/);
    fs.rmSync(tmp, { recursive: true, force: true });
  });
});
