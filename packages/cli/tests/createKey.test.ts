/**
 * `maintainers create-key` (LOCKED Phase-2 v2 — self-registration).
 *
 * Same #28 contract as the mandate ceremonies, on the ONE ceremony
 * path: (1) --dry-run prints the EXACT canonical bytes a real run
 * would sign + the unsigned diff, signs/writes NOTHING (proven by a
 * token whose sign/PIN throw if touched), (2) the real path produces a
 * valid SELF-signature over canonicalKeyFile (the c1 signKeyFileWith
 * seam — signer pubkey == envelope pubkey), (3) append-only
 * (refuse-overwrite), (4) never logs the private key.
 */
import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  canonicalKeyFile,
  generateKeypair,
  verify,
} from "@maintainers/protocol";
import { assembleCreateKey, buildCreateKey } from "../src/commands/createKey.js";
import { dispatch, type CliEnv } from "../src/index.js";
import { parseArgs } from "../src/lib/args.js";
import type { PivTransport } from "../src/lib/keysource.js";

function keypair(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

const NOW = new Date("2026-05-17T12:00:00Z");

function hex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

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
  io: (p: string) => string,
  transport?: PivTransport,
  pin?: () => Promise<string>,
): CliEnv {
  return {
    now: () => NOW,
    io: { readFileSync: io },
    uuid: () => "unused-for-keyfile",
    println: (l) => lines.push(l),
    printerr: (l) => lines.push(`ERR ${l}`),
    pivTransport: transport,
    pivPin: pin,
  };
}

describe("create-key --dry-run", () => {
  it("prints exact canonical bytes + diff, signs/writes nothing, no PIN/tap", async () => {
    const me = keypair(7);
    const { tmp, root } = tmpRoot("ck-dry-");
    try {
      const lines: string[] = [];
      const code = await dispatch(
        parseArgs([
          "create-key",
          "--signing-key",
          "yubikey-piv:slot=9c",
          "--display-name",
          "Harry Winner",
          "--email",
          "harry@flagship.services",
          "--path",
          root,
          "--dry-run",
        ]),
        mkEnv(lines, () => "", readOnlyToken(me.pubKey), forbidPin),
      );
      expect(code).toBe(0);
      expect(fs.existsSync(path.join(root, "keys"))).toBe(false);

      const a = await assembleCreateKey({
        signingKeySource: "yubikey-piv:slot=9c",
        displayName: "Harry Winner",
        email: "harry@flagship.services",
        introductionMandate: undefined,
        photo: undefined,
        github: undefined,
        role: undefined,
        rootDir: root,
        now: () => NOW,
        io: { readFileSync: () => "" },
        pivTransport: readOnlyToken(me.pubKey),
        pivPin: forbidPin,
      });
      const out = lines.join("\n");
      expect(out).toContain("DRY RUN — create-key");
      expect(out).toContain("REGISTER KEY"); // honest low-stakes banner
      expect(out).toContain(hex(a.canonical));
      expect(out).toContain(hex(canonicalKeyFile(a.unsigned)));
      expect(out).toContain('"kind": "KeyFile"');
      expect(out).not.toContain('"signature"'); // unsigned diff
      expect(out).not.toMatch(/^ERR /m);
      expect(a.signedBy).toBe(me.pubKey); // self-signed
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("create-key real self-sign", () => {
  it("produces a valid self-signature over canonicalKeyFile; nil intro UUID by default", async () => {
    const me = keypair(8);
    const k = await buildCreateKey({
      signingKeySource: "file:k",
      displayName: "Harry Winner",
      email: "harry@flagship.services",
      introductionMandate: undefined,
      photo: undefined,
      github: "harrywinner",
      role: undefined,
      rootDir: ".maintainers",
      now: () => NOW,
      io: { readFileSync: () => me.privKey },
    });
    expect(k.pubkey).toBe(me.pubKey);
    expect(k.introductionMandate).toBe("00000000-0000-0000-0000-000000000000");
    expect(k.currentEmail).toBe("harry@flagship.services");
    expect(k.emailHistory).toEqual([
      { email: "harry@flagship.services", from: NOW.toISOString(), to: null },
    ]);
    expect(k.metadata.github).toBe("harrywinner");
    expect(k.metadata.photo).toBeNull();
    const { signature, ...unsigned } = k;
    expect(verify(signature, canonicalKeyFile(unsigned), me.pubKey)).toBe(true);
    // tampered bytes must NOT verify under the same signature
    expect(
      verify(signature, canonicalKeyFile({ ...unsigned, displayName: "Mallory" }), me.pubKey),
    ).toBe(false);
  });

  it("writes keys/<email>.json then refuses to overwrite (append-only)", async () => {
    const me = keypair(9);
    const { tmp, root } = tmpRoot("ck-w-");
    try {
      const lines: string[] = [];
      const argv = [
        "create-key",
        "--signing-key",
        "file:k",
        "--display-name",
        "Harry Winner",
        "--email",
        "harry@flagship.services",
        "--path",
        root,
        "--yes",
      ];
      const code1 = await dispatch(
        parseArgs(argv),
        mkEnv(lines, () => me.privKey),
      );
      expect(code1).toBe(0);
      const written = path.join(root, "keys", "harry@flagship.services.json");
      expect(fs.existsSync(written)).toBe(true);
      const parsed = JSON.parse(fs.readFileSync(written, "utf8"));
      expect(parsed.kind).toBe("KeyFile");
      expect(parsed.pubkey).toBe(me.pubKey);

      // second run → refuse-overwrite (CliError → exit 1)
      const lines2: string[] = [];
      const code2 = await dispatch(
        parseArgs(argv),
        mkEnv(lines2, () => me.privKey),
      );
      expect(code2).toBe(1);
      expect(lines2.join("\n")).toMatch(/refusing to overwrite existing key file/);

      // never logs the private key
      const all = lines.join("\n") + "\n" + lines2.join("\n");
      expect(all).not.toContain(me.privKey);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
