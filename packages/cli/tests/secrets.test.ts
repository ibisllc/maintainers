/**
 * Never-log-secrets regression (#28, §10.1/§11). Across the ENTIRE
 * command surface of the maintainer-key ceremonies (LOCKED Phase-2 v2:
 * upsert-mandate / ca-endorsement) — banner, byte/diff preview, confirm,
 * advisory, success lines, dry-run, and the sign-failure error path —
 * neither the YubiKey PIN nor a `file:` private key hex may ever appear
 * in ANY emitted line.
 */

import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { generateKeypair, sign } from "@ibisllc/maintainers";
import { dispatch, type CliEnv } from "../src/index.js";
import { parseArgs } from "../src/lib/args.js";
import { CliError } from "../src/lib/args.js";
import type { PivTransport } from "../src/lib/keysource.js";

function keypair(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

const PIN = "super-secret-pin-0918273645";

function token(pub: string, priv: string): PivTransport {
  return {
    async getPublicKey() {
      return pub;
    },
    async signEd25519(_s, _p, m) {
      return sign(m, priv);
    },
    async generateEd25519() {
      return pub;
    },
  };
}

describe("no ceremony ever logs a secret", () => {
  it("PIN + file: privkey never appear across the full ceremony surface", async () => {
    const maintainer = keypair(1);
    const succ = keypair(2);
    const hotCa = keypair(3);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sec-"));
    const root = path.join(tmp, ".maintainers");
    const mPub = path.join(tmp, "m.pub");
    const mPriv = path.join(tmp, "m.priv");
    const sPub = path.join(tmp, "s.pub");
    const sPriv = path.join(tmp, "s.priv");
    fs.writeFileSync(mPub, maintainer.pubKey);
    fs.writeFileSync(mPriv, maintainer.privKey);
    fs.writeFileSync(sPub, succ.pubKey);
    fs.writeFileSync(sPriv, succ.privKey);

    const all: string[] = [];
    let uuidN = 0;
    const mkEnv = (now: string, t?: PivTransport): CliEnv => ({
      now: () => new Date(now),
      io: { readFileSync: (p: string) => fs.readFileSync(p, "utf8") },
      uuid: () => `sec0${(uuidN++).toString().padStart(3, "0")}-0000-4000-8000-000000000000`,
      println: (l) => all.push(l),
      printerr: (l) => all.push(`ERR ${l}`),
      pivTransport: t,
      pivPin: async () => PIN,
    });

    try {
      // 1. from-scratch ORIGIN (ca track) — file: privkey is the secret.
      //    self-signed; successors=[maintainer,succ] so a later takeover
      //    by `succ` is a named successor of the origin.
      expect(
        await dispatch(
          parseArgs([
            "upsert-mandate", "--track", "ca", "--duration", "365d",
            "--signing-key", `file:${mPriv}`,
            "--successors", `file:${mPub},file:${sPub}`,
            "--max-duration", "365d",
            "--project-name", "flagship",
            "--path", root, "--yes",
          ]),
          mkEnv("2026-01-01T00:00:00Z"),
        ),
      ).toBe(0);

      // 2. ca-endorsement via YubiKey-PIV — PIN is the secret here
      expect(
        await dispatch(
          parseArgs([
            "ca-endorsement", "--ca-pubkey", hotCa.pubKey,
            "--signing-key", "yubikey-piv:slot=9c",
            "--path", root, "--yes",
          ]),
          mkEnv("2026-01-10T00:00:00Z", token(maintainer.pubKey, maintainer.privKey)),
        ),
      ).toBe(0);

      // 3. succession (renewal) via YubiKey-PIV — maintainer is a named
      //    successor of the origin, so this is accepted forward.
      expect(
        await dispatch(
          parseArgs([
            "upsert-mandate", "--track", "ca", "--duration", "60d",
            "--signing-key", "yubikey-piv:slot=9c",
            "--successors", `file:${mPub},file:${sPub}`,
            "--path", root, "--yes",
          ]),
          mkEnv("2026-01-15T00:00:00Z", token(maintainer.pubKey, maintainer.privKey)),
        ),
      ).toBe(0);

      // 4. succession (takeover) by the successor — `succ` is a named
      //    successor; the holder changes.
      expect(
        await dispatch(
          parseArgs([
            "upsert-mandate", "--track", "ca", "--duration", "60d",
            "--signing-key", "yubikey-piv:slot=9c",
            "--holder", `file:${sPub}`,
            "--successors", `file:${sPub}`,
            "--path", root, "--yes",
          ]),
          mkEnv("2026-03-01T00:00:00Z", token(succ.pubKey, succ.privKey)),
        ),
      ).toBe(0);

      // 5. dry-run upsert-mandate + dry-run ca-endorsement (preview path)
      await dispatch(
        parseArgs([
          "upsert-mandate", "--track", "release", "--duration", "30d",
          "--signing-key", `file:${mPriv}`,
          "--project-name", "flagship",
          "--path", root, "--dry-run",
        ]),
        mkEnv("2026-01-01T00:00:00Z"),
      );
      await dispatch(
        parseArgs([
          "ca-endorsement", "--ca-pubkey", hotCa.pubKey,
          "--signing-key", "yubikey-piv:slot=9c",
          "--path", root, "--dry-run",
        ]),
        mkEnv("2026-01-10T00:00:00Z", token(maintainer.pubKey, maintainer.privKey)),
      );

      // 6. sign-failure path: the token errors mid-sign
      const failTok: PivTransport = {
        async getPublicKey() {
          return maintainer.pubKey;
        },
        async signEd25519() {
          throw new CliError("token refused: touch timeout");
        },
        async generateEd25519() {
          return maintainer.pubKey;
        },
      };
      const failCode = await dispatch(
        parseArgs([
          "ca-endorsement", "--ca-pubkey", hotCa.pubKey,
          "--signing-key", "yubikey-piv:slot=9c",
          "--path", root, "--yes",
        ]),
        mkEnv("2026-01-12T00:00:00Z", failTok),
      );
      expect(failCode).toBe(1);

      // The surface really ran (not a vacuous pass), and leaked nothing.
      const out = all.join("\n");
      expect(out).toContain("wrote from-scratch (root) mandate");
      expect(out).toContain("wrote CA lease");
      expect(out).toContain("wrote succession mandate");
      expect(out).toContain("holder is unchanged (a renewal)");
      expect(out).toContain("holder CHANGES");
      expect(out).toContain("DRY RUN — upsert-mandate");
      expect(out).toMatch(/touch timeout/); // the failure WAS surfaced
      expect(out).not.toContain(PIN);
      expect(out).not.toContain(maintainer.privKey);
      expect(out).not.toContain(succ.privKey);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
