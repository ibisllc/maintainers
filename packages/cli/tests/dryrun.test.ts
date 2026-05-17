/**
 * `--dry-run` for the four maintainer-key ceremonies (#28).
 *
 * The security contract proven here:
 *   1. dry-run prints the EXACT canonical bytes a real run would sign
 *      (hex == Buffer.from(assemble().canonical)), plus the unsigned
 *      `.maintainers` diff;
 *   2. dry-run signs NOTHING and writes NOTHING — proven by a token
 *      whose sign/PIN paths throw if touched, yet dry-run still exits 0;
 *   3. the SAME assembled unsigned, signed via the real path, verifies
 *      and is byte-identical to the legacy `build*` (fidelity);
 *   4. `signAssembled` fail-closes if the resolved signer ≠ the
 *      assembled `signedBy` (wrong/swapped YubiKey).
 */

import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  canonicalMandate,
  canonicalCaEndorsement,
  generateKeypair,
  sign,
  verify,
  signMandateWith,
  type Mandate,
} from "@maintainers/protocol";
import {
  assembleGenesis,
  buildGenesis,
} from "../src/commands/genesis.js";
import { assembleRenewal } from "../src/commands/mandate.js";
import { assembleTakeover } from "../src/commands/takeover.js";
import {
  assembleCaEndorsement,
  buildCaEndorsement,
} from "../src/commands/caEndorsement.js";
import { signAssembled } from "../src/lib/ceremony.js";
import { dispatch, type CliEnv } from "../src/index.js";
import { parseArgs } from "../src/lib/args.js";
import { writeMandate, writeTrackPolicyIfMissing } from "../src/lib/store.js";
import type { PivTransport } from "../src/lib/keysource.js";

function keypair(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

const NOW = new Date("2026-05-17T12:00:00Z");
const UUID = "dryrun00-0000-0000-0000-000000000000";

function hex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/** A token that refuses every PRIVATE operation. Public read is fine
 *  (no PIN). If dry-run ever signs or asks for a PIN, the test fails. */
function readOnlyToken(pub: string): PivTransport {
  return {
    async getPublicKey() {
      return pub;
    },
    async signEd25519() {
      throw new Error("BUG: dry-run must never sign");
    },
    async generateEd25519() {
      throw new Error("BUG: dry-run must never generate");
    },
  };
}
const forbidPin = async (): Promise<string> => {
  throw new Error("BUG: dry-run must never ask for a PIN");
};

function tmpRoot(prefix: string): { tmp: string; root: string } {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return { tmp, root: path.join(tmp, ".maintainers") };
}

function mkEnv(
  lines: string[],
  transport: PivTransport,
  pin: () => Promise<string>,
): CliEnv {
  return {
    now: () => NOW,
    io: { readFileSync: (p: string) => fs.readFileSync(p, "utf8") },
    uuid: () => UUID,
    println: (l) => lines.push(l),
    printerr: (l) => lines.push(`ERR ${l}`),
    pivTransport: transport,
    pivPin: pin,
  };
}

describe("ca-endorsement --dry-run", () => {
  it("prints exact canonical bytes + diff, signs/writes nothing, no PIN/tap", async () => {
    const maintainer = keypair(1);
    const hotCa = keypair(9);
    const { tmp, root } = tmpRoot("dry-ca-");
    try {
      const lines: string[] = [];
      const code = await dispatch(
        parseArgs([
          "ca-endorsement",
          "--ca-pubkey",
          hotCa.pubKey,
          "--signing-key",
          "yubikey-piv:slot=9c",
          "--path",
          root,
          "--dry-run",
        ]),
        mkEnv(lines, readOnlyToken(maintainer.pubKey), forbidPin),
      );
      expect(code).toBe(0);

      // Nothing written.
      expect(fs.existsSync(path.join(root, "ca-endorsements"))).toBe(false);

      // The printed hex is EXACTLY assemble()'s canonical bytes.
      const a = await assembleCaEndorsement({
        caPubkey: hotCa.pubKey,
        scope: "flagship/directory-attestation",
        duration: "7d",
        track: "ca",
        signingKeySource: "yubikey-piv:slot=9c",
        rootDir: root,
        now: () => NOW,
        io: { readFileSync: () => "" },
        uuid: () => UUID,
        pivTransport: readOnlyToken(maintainer.pubKey),
        pivPin: forbidPin,
      });
      const out = lines.join("\n");
      expect(out).toContain("DRY RUN — ca-endorsement");
      expect(out).toContain(hex(a.canonical));
      expect(out).toContain(hex(canonicalCaEndorsement(a.unsigned)));
      expect(out).toContain('"kind": "CaEndorsement"');
      expect(out).not.toContain('"signatures"');
      expect(out).not.toMatch(/^ERR /m);

      // Fidelity: the SAME assembled unsigned, signed for real, verifies
      // and is byte-identical to the legacy build path.
      const real = await buildCaEndorsement({
        caPubkey: hotCa.pubKey,
        scope: "flagship/directory-attestation",
        duration: "7d",
        track: "ca",
        signingKeySource: "file:m",
        now: () => NOW,
        io: { readFileSync: () => maintainer.privKey },
        uuid: () => UUID,
      });
      expect(real.signedBy).toBe(maintainer.pubKey);
      expect(verify(real.signatures[0]!.sig, a.canonical, maintainer.pubKey)).toBe(true);
      const { signatures, ...realUnsigned } = real;
      void signatures;
      expect(realUnsigned).toEqual(a.unsigned);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("genesis/mandate/takeover --dry-run", () => {
  it("genesis dry-run: no policy.json, no mandate, exact bytes", async () => {
    const maintainer = keypair(2);
    const { tmp, root } = tmpRoot("dry-g-");
    const pub = path.join(tmp, "m.pub");
    fs.writeFileSync(pub, maintainer.pubKey);
    try {
      const lines: string[] = [];
      const code = await dispatch(
        parseArgs([
          "genesis",
          "--track",
          "ca",
          "--duration",
          "365d",
          "--holder-key",
          `file:${pub}`,
          "--signing-key",
          "yubikey-piv:slot=9c",
          "--output",
          root,
          "--dry-run",
        ]),
        mkEnv(lines, readOnlyToken(maintainer.pubKey), forbidPin),
      );
      expect(code).toBe(0);
      expect(fs.existsSync(path.join(root, "tracks"))).toBe(false);
      const a = await assembleGenesis({
        track: "ca",
        duration: "365d",
        holderKeySource: `file:${pub}`,
        signingKeySource: "yubikey-piv:slot=9c",
        successorsSource: undefined,
        outputDir: root,
        now: () => NOW,
        io: { readFileSync: (p: string) => fs.readFileSync(p, "utf8") },
        uuid: () => UUID,
        pivTransport: readOnlyToken(maintainer.pubKey),
        pivPin: forbidPin,
      });
      const out = lines.join("\n");
      expect(out).toContain("DRY RUN — genesis");
      expect(out).toContain(hex(a.canonical));
      expect(out).toContain("if missing");
      expect(out).toContain("tracks/ca/policy.json");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("mandate + takeover dry-run over an on-disk genesis write nothing", async () => {
    const maintainer = keypair(3);
    const succ = keypair(4);
    const { tmp, root } = tmpRoot("dry-mt-");
    const succPub = path.join(tmp, "s.pub");
    fs.writeFileSync(succPub, succ.pubKey);
    try {
      // Seed a real ca-track genesis on disk (holder=maintainer,
      // successors=[succ]) so mandate/takeover have a predecessor.
      writeTrackPolicyIfMissing(root, {
        track: "ca",
        defaultMandateDuration: "365d",
        approvalRule: { kind: "threshold", threshold: 1, of: "anyAuthorizedSigner" },
      });
      const genesis = await buildGenesis({
        track: "ca",
        duration: "30d",
        holderKeySource: "file:hpub",
        signingKeySource: "file:hpriv",
        successorsSource: "file:spub",
        outputDir: undefined,
        now: () => new Date("2026-01-01T00:00:00Z"),
        io: {
          readFileSync: (p: string) =>
            p === "hpub"
              ? maintainer.pubKey
              : p === "hpriv"
                ? maintainer.privKey
                : succ.pubKey,
        },
        uuid: () => "genesis0-0000-0000-0000-000000000000",
      });
      writeMandate(root, genesis);
      const before = fs.readdirSync(path.join(root, "tracks/ca/mandates")).length;

      // mandate dry-run (signer = current holder = maintainer)
      const ml: string[] = [];
      const mc = await dispatch(
        parseArgs([
          "mandate",
          "--track",
          "ca",
          "--duration",
          "30d",
          "--signing-key",
          "yubikey-piv:slot=9c",
          "--path",
          root,
          "--dry-run",
        ]),
        mkEnv(ml, readOnlyToken(maintainer.pubKey), forbidPin),
      );
      expect(mc).toBe(0);
      expect(ml.join("\n")).toContain("DRY RUN — mandate");

      // takeover dry-run (now past genesis expiry; signer = successor)
      const tl: string[] = [];
      const tc = await dispatch(
        parseArgs([
          "takeover",
          "--track",
          "ca",
          "--successor-key",
          "yubikey-piv:slot=9c",
          "--new-holder",
          `file:${succPub}`,
          "--path",
          root,
          "--dry-run",
        ]),
        {
          ...mkEnv(tl, readOnlyToken(succ.pubKey), forbidPin),
          now: () => new Date("2026-03-01T00:00:00Z"),
        },
      );
      expect(tc).toBe(0);
      expect(tl.join("\n")).toContain("DRY RUN — takeover");

      // Not a single new file from either dry-run.
      const after = fs.readdirSync(path.join(root, "tracks/ca/mandates")).length;
      expect(after).toBe(before);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("signAssembled fail-closed guard", () => {
  it("refuses when the resolved signer ≠ the assembled signedBy", async () => {
    const a = keypair(5);
    const b = keypair(6);
    const unsigned: Omit<Mandate, "signatures"> = {
      kind: "Mandate",
      version: 1,
      mandateId: "m-guard",
      track: "ca",
      holder: a.pubKey,
      issuedAt: "2026-05-17T12:00:00.000Z",
      expiresAt: "2026-06-17T12:00:00.000Z",
      successors: [a.pubKey],
      signedBy: a.pubKey,
    };
    await expect(
      signAssembled(
        {
          ceremony: "mandate",
          unsigned,
          canonical: canonicalMandate(unsigned),
          signingKeySource: "yubikey-piv:slot=9c",
          signedBy: a.pubKey,
          rootDir: ".maintainers",
          targetRelative: "tracks/ca/mandates/x.json",
        },
        signMandateWith,
        {
          pivTransport: {
            async getPublicKey() {
              return b.pubKey; // a DIFFERENT (swapped) token
            },
            async signEd25519(_s, _p, m) {
              return sign(m, b.privKey);
            },
            async generateEd25519() {
              return b.pubKey;
            },
          },
          pivPin: async () => "0",
        },
      ),
    ).rejects.toThrow(/refusing to sign/);
  });
});
