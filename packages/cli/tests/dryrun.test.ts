/**
 * `--dry-run` for the maintainer-key ceremonies (#28), LOCKED Phase-2
 * v2. genesis/mandate/takeover collapsed into the ONE `upsert-mandate`
 * verb, so the dry-run surface is upsert-mandate + ca-endorsement.
 *
 * The security contract proven here:
 *   1. dry-run prints the EXACT canonical bytes a real run would sign
 *      (hex == the assembled `canonical`), plus the unsigned
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
  canonicalCaEndorsement,
  canonicalMandate,
  generateKeypair,
  sign,
  signMandateWith,
  verify,
  type Mandate,
} from "@ibisllc/maintainers";
import {
  assembleCaEndorsement,
  buildCaEndorsement,
} from "../src/commands/caEndorsement.js";
import {
  assembleUpsertMandate,
  buildUpsertMandate,
} from "../src/commands/upsertMandate.js";
import { signAssembled } from "../src/lib/ceremony.js";
import { dispatch, type CliEnv } from "../src/index.js";
import { parseArgs } from "../src/lib/args.js";
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

describe("upsert-mandate --dry-run", () => {
  it("from-scratch dry-run: no mandate written, exact canonicalMandate bytes, no PIN/tap", async () => {
    const maintainer = keypair(2);
    const { tmp, root } = tmpRoot("dry-um-");
    try {
      const lines: string[] = [];
      const code = await dispatch(
        parseArgs([
          "upsert-mandate",
          "--track",
          "ca",
          "--duration",
          "365d",
          "--signing-key",
          "yubikey-piv:slot=9c",
          "--project-name",
          "flagship",
          "--path",
          root,
          "--dry-run",
        ]),
        mkEnv(lines, readOnlyToken(maintainer.pubKey), forbidPin),
      );
      expect(code).toBe(0);
      expect(fs.existsSync(path.join(root, "tracks"))).toBe(false);
      const a = await assembleUpsertMandate({
        track: "ca",
        signingKeySource: "yubikey-piv:slot=9c",
        holderSource: undefined,
        successorsSource: undefined,
        duration: "365d",
        threshold: undefined,
        minSuccessors: undefined,
        maxDuration: undefined,
        defaultDuration: undefined,
        project: { name: "flagship" },
        rootDir: root,
        now: () => NOW,
        io: { readFileSync: () => "" },
        uuid: () => UUID,
        pivTransport: readOnlyToken(maintainer.pubKey),
        pivPin: forbidPin,
      });
      const out = lines.join("\n");
      expect(out).toContain("DRY RUN — upsert-mandate");
      expect(out).toContain("FROM-SCRATCH ORIGIN");
      expect(out).toContain(hex(a.canonical));
      expect(out).toContain(hex(canonicalMandate(a.unsigned)));
      expect(out).not.toContain('"signatures"');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("byte-fidelity: from-scratch genesis dry-run preview bytes EQUAL canonicalMandate of the envelope a real signed run produces (uuid/timestamps pinned)", async () => {
    // The security contract: the bytes a `--dry-run` previews for a
    // from-scratch genesis upsert-mandate are EXACTLY the bytes a real
    // signed run would sign. uuid + timestamps differ across invocations,
    // so they are held FIXED (injected `now`/`uuid`) — the dryrun.test.ts
    // pattern — and we assert canonical-bytes equality + the real
    // signature verifies over precisely the previewed bytes.
    const founder = keypair(2);
    const backup = keypair(3);
    const { tmp, root } = tmpRoot("dry-um-fid-");
    try {
      const bpub = path.join(tmp, "backup.pub");
      fs.writeFileSync(bpub, backup.pubKey);

      const common = {
        track: "ca",
        holderSource: undefined,
        successorsSource: `file:${bpub}`,
        duration: "3650d",
        threshold: undefined,
        minSuccessors: undefined,
        maxDuration: undefined,
        defaultDuration: undefined,
        project: { name: "flagship", contact: "harry@flagship.services" },
        rootDir: root,
        now: () => NOW, // PINNED
        uuid: () => UUID, // PINNED
      } as const;

      // The dry-run preview's assembled bytes (PIV public read, no PIN).
      const preview = await assembleUpsertMandate({
        ...common,
        signingKeySource: "yubikey-piv:slot=9c",
        io: { readFileSync: (p: string) => fs.readFileSync(p, "utf8") },
        pivTransport: readOnlyToken(founder.pubKey),
        pivPin: forbidPin,
      });

      // The SAME assembled envelope, signed for real (file: hex path so
      // the test needs no token to produce a genuine signature).
      const fpriv = path.join(tmp, "f.priv");
      fs.writeFileSync(fpriv, founder.privKey);
      const real = await buildUpsertMandate({
        ...common,
        signingKeySource: `file:${fpriv}`,
        io: { readFileSync: (p: string) => fs.readFileSync(p, "utf8") },
      });

      // 1. The previewed canonical bytes EQUAL canonicalMandate of the
      //    real signed envelope's unsigned projection — byte-for-byte.
      const { signatures, ...realUnsigned } = real;
      expect(realUnsigned).toEqual(preview.unsigned);
      expect(hex(preview.canonical)).toBe(hex(canonicalMandate(realUnsigned)));
      // 2. The real signature verifies over PRECISELY the previewed bytes.
      expect(real.signedBy).toBe(founder.pubKey);
      expect(real.holder).toBe(founder.pubKey); // genesis is self-signed
      expect(real.successors).toEqual([backup.pubKey]);
      expect(real.project).toEqual({
        name: "flagship",
        contact: "harry@flagship.services",
      });
      expect(verify(signatures[0]!.sig, preview.canonical, founder.pubKey)).toBe(
        true,
      );
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
      approvalRule: { kind: "threshold", threshold: 1 },
      minSuccessors: 1,
      maxDurationSeconds: 365 * 86_400,
      defaultDurationSeconds: 60 * 86_400,
      signedBy: a.pubKey,
    };
    await expect(
      signAssembled(
        {
          ceremony: "upsert-mandate",
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
