/**
 * `maintainers upsert-mandate` — the ONE mandate verb (LOCKED Phase-2
 * v2). Security-critical surface: this pins the from-scratch ORIGIN
 * path, the succession (renew/takeover) path, the round-trip against
 * the c2 verifier, AND every fail-closed PRE-FLIGHT — each proven to
 * refuse BEFORE any token touch (a token whose sign/PIN throw is used
 * so a single stray tap fails the test).
 */
import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  canonicalMandate,
  mandatePinHash,
  verifyMandateChainFromPin,
  currentAuthority,
  generateKeypair,
} from "@maintainers/protocol";
import {
  assembleUpsertMandate,
  buildUpsertMandate,
} from "../src/commands/upsertMandate.js";
import { readMandates, writeMandate } from "../src/lib/store.js";
import { dispatch, type CliEnv } from "../src/index.js";
import { parseArgs } from "../src/lib/args.js";
import type { PivTransport } from "../src/lib/keysource.js";

function keypair(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}
const founder = keypair(1);
const backup = keypair(2);
const eve = keypair(9);

const T0 = new Date("2026-01-01T00:00:00Z");
const T1 = new Date("2026-02-01T00:00:00Z");

function hex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

const keyMap: Record<string, string> = {
  fpriv: founder.privKey,
  fpub: founder.pubKey,
  bpriv: backup.privKey,
  bpub: backup.pubKey,
  epriv: eve.privKey,
  epub: eve.pubKey,
};
const io = (p: string): string => keyMap[p] ?? "";

function readOnlyToken(pub: string): PivTransport {
  return {
    async getPublicKey() {
      return pub;
    },
    async signEd25519() {
      throw new Error("BUG: must never sign here");
    },
    async generateEd25519() {
      throw new Error("BUG: must never generate");
    },
  };
}
const forbidPin = async (): Promise<string> => {
  throw new Error("BUG: must never ask for a PIN here");
};

function tmpRoot(prefix: string): { tmp: string; root: string } {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return { tmp, root: path.join(tmp, ".maintainers") };
}

function mkEnv(
  lines: string[],
  now: Date,
  uuid: string,
  transport?: PivTransport,
  pin?: () => Promise<string>,
): CliEnv {
  return {
    now: () => now,
    io: { readFileSync: io },
    uuid: () => uuid,
    println: (l) => lines.push(l),
    printerr: (l) => lines.push(`ERR ${l}`),
    pivTransport: transport,
    pivPin: pin,
  };
}

/** Seed a from-scratch root on disk (founder self-signs, successors as given). */
async function seedRoot(
  root: string,
  opts: {
    successors?: string;
    threshold?: number;
    minSuccessors?: number;
    maxDuration?: string;
    duration?: string;
  } = {},
) {
  const m = await buildUpsertMandate({
    track: "release",
    signingKeySource: "file:fpriv",
    holderSource: undefined,
    successorsSource: opts.successors,
    duration: opts.duration ?? "60d",
    threshold: opts.threshold,
    minSuccessors: opts.minSuccessors,
    maxDuration: opts.maxDuration,
    defaultDuration: undefined,
    project: { name: "flagship", contact: "harry@flagship.services", tracks: ["release"] },
    rootDir: root,
    now: () => T0,
    io: { readFileSync: io },
    uuid: () => "root0000-0000-4000-8000-000000000000",
  });
  writeMandate(root, m);
  return m;
}

describe("upsert-mandate — from-scratch ORIGIN", () => {
  it("self-signs, carries inline policy + project, and verifies from its own PIN", async () => {
    const { tmp, root } = tmpRoot("um-fs-");
    try {
      const lines: string[] = [];
      const code = await dispatch(
        parseArgs([
          "upsert-mandate",
          "--track", "release",
          "--signing-key", "file:fpriv",
          "--duration", "60d",
          "--successors", "file:fpub,file:bpub",
          "--threshold", "1",
          "--min-successors", "1",
          "--max-duration", "365d",
          "--project-name", "flagship",
          "--project-contact", "harry@flagship.services",
          "--project-tracks", "release,ca",
          "--path", root,
          "--yes",
        ]),
        mkEnv(lines, T0, "root0000-0000-4000-8000-000000000000"),
      );
      expect(code).toBe(0);
      const out = lines.join("\n");
      expect(out).toContain("FROM-SCRATCH ORIGIN");
      expect(out).toContain("PIN (canonical hash):");
      expect(out).toContain("RECORD the PIN");
      expect(out).not.toContain(founder.privKey); // never logs secrets

      const onDisk = readMandates(root, "release");
      expect(onDisk.length).toBe(1);
      const m = onDisk[0]!;
      expect(m.version).toBe(1);
      expect(m.signedBy).toBe(founder.pubKey);
      expect(m.holder).toBe(founder.pubKey); // self-signed
      expect(m.successors).toEqual([founder.pubKey, backup.pubKey]);
      expect(m.approvalRule).toEqual({ kind: "threshold", threshold: 1 });
      expect(m.project).toEqual({
        name: "flagship",
        contact: "harry@flagship.services",
        tracks: ["release", "ca"],
      });

      // verifies FORWARD from its own baked PIN
      const chain = verifyMandateChainFromPin(mandatePinHash(m), onDisk);
      expect(chain.rootError).toBeUndefined();
      expect(chain.validMandates.map((x) => x.mandateId)).toEqual([m.mandateId]);
      // the printed PIN equals mandatePinHash(m)
      expect(out).toContain(mandatePinHash(m));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("--dry-run prints exact canonicalMandate bytes + the PIN, signs/writes nothing", async () => {
    const { tmp, root } = tmpRoot("um-dry-");
    try {
      const lines: string[] = [];
      const code = await dispatch(
        parseArgs([
          "upsert-mandate",
          "--track", "release",
          "--signing-key", "yubikey-piv:slot=9c",
          "--duration", "60d",
          "--project-name", "flagship",
          "--path", root,
          "--dry-run",
        ]),
        mkEnv(lines, T0, "root0000-0000-4000-8000-000000000000",
          readOnlyToken(founder.pubKey), forbidPin),
      );
      expect(code).toBe(0);
      expect(fs.existsSync(path.join(root, "tracks"))).toBe(false);
      const a = await assembleUpsertMandate({
        track: "release",
        signingKeySource: "yubikey-piv:slot=9c",
        holderSource: undefined,
        successorsSource: undefined,
        duration: "60d",
        threshold: undefined,
        minSuccessors: undefined,
        maxDuration: undefined,
        defaultDuration: undefined,
        project: { name: "flagship" },
        rootDir: root,
        now: () => T0,
        io: { readFileSync: io },
        uuid: () => "root0000-0000-4000-8000-000000000000",
        pivTransport: readOnlyToken(founder.pubKey),
        pivPin: forbidPin,
      });
      const out = lines.join("\n");
      expect(out).toContain("DRY RUN — upsert-mandate");
      expect(out).toContain(hex(a.canonical));
      expect(out).toContain(hex(canonicalMandate(a.unsigned)));
      expect(out).not.toContain('"signatures"');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("rejects --holder ≠ signer; rejects missing --project-name; rejects threshold > successors", async () => {
    const { tmp, root } = tmpRoot("um-fsbad-");
    try {
      const l1: string[] = [];
      expect(
        await dispatch(
          parseArgs([
            "upsert-mandate", "--track", "release",
            "--signing-key", "file:fpriv", "--holder", "file:bpub",
            "--duration", "60d", "--project-name", "x", "--path", root, "--yes",
          ]),
          mkEnv(l1, T0, "id1"),
        ),
      ).toBe(1);
      expect(l1.join("\n")).toMatch(/must be self-signed by its holder/);

      const l2: string[] = [];
      expect(
        await dispatch(
          parseArgs([
            "upsert-mandate", "--track", "release",
            "--signing-key", "file:fpriv", "--duration", "60d",
            "--path", root, "--yes",
          ]),
          mkEnv(l2, T0, "id2"),
        ),
      ).toBe(1);
      expect(l2.join("\n")).toMatch(/requires --project-name/);

      const l3: string[] = [];
      expect(
        await dispatch(
          parseArgs([
            "upsert-mandate", "--track", "release",
            "--signing-key", "file:fpriv", "--duration", "60d",
            "--threshold", "2", "--project-name", "x", "--path", root, "--yes",
          ]),
          mkEnv(l3, T0, "id3"),
        ),
      ).toBe(1);
      expect(l3.join("\n")).toMatch(/threshold 2 exceeds the successor count 1/);
      expect(fs.existsSync(path.join(root, "tracks"))).toBe(false);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("upsert-mandate — succession (the ONE mechanism)", () => {
  it("solo-founder renewal: chain verifies; currentAuthority tracks the window", async () => {
    const { tmp, root } = tmpRoot("um-renew-");
    try {
      const r = await seedRoot(root, { successors: "file:fpub", threshold: 1 });
      const lines: string[] = [];
      const code = await dispatch(
        parseArgs([
          "upsert-mandate", "--track", "release",
          "--signing-key", "file:fpriv", "--duration", "30d",
          "--path", root, "--yes",
        ]),
        mkEnv(lines, T1, "next0000-0000-4000-8000-000000000001"),
      );
      expect(code).toBe(0);
      expect(lines.join("\n")).toContain("holder is unchanged (a renewal)");

      const log = readMandates(root, "release");
      expect(log.map((m) => m.mandateId)).toEqual([r.mandateId, log[1]!.mandateId]);
      const chain = verifyMandateChainFromPin(mandatePinHash(r), log);
      expect(chain.validMandates.length).toBe(2);
      // at a time inside the renewal window → the renewal's holder
      const auth = currentAuthority(chain, new Date("2026-02-15T00:00:00Z"));
      expect(auth?.mandate.mandateId).toBe(log[1]!.mandateId);
      expect(auth?.holder).toBe(founder.pubKey);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("takeover: a named successor signs, the holder changes, the chain verifies", async () => {
    const { tmp, root } = tmpRoot("um-take-");
    try {
      const r = await seedRoot(root, { successors: "file:bpub", threshold: 1 });
      const lines: string[] = [];
      const code = await dispatch(
        parseArgs([
          "upsert-mandate", "--track", "release",
          "--signing-key", "file:bpriv", "--holder", "file:bpub",
          "--successors", "file:bpub", "--duration", "30d",
          "--path", root, "--yes",
        ]),
        mkEnv(lines, T1, "take0000-0000-4000-8000-000000000001"),
      );
      expect(code).toBe(0);
      expect(lines.join("\n")).toContain("holder CHANGES");
      const log = readMandates(root, "release");
      const chain = verifyMandateChainFromPin(mandatePinHash(r), log);
      expect(chain.validMandates.length).toBe(2);
      expect(chain.validMandates[1]!.holder).toBe(backup.pubKey);
      expect(chain.validMandates[1]!.signedBy).toBe(backup.pubKey);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("upsert-mandate — fail-closed PRE-FLIGHT (refuses BEFORE any tap)", () => {
  // The signing source is a YubiKey whose sign/PIN throw — if assemble
  // ever reached the token, the test would error rather than exit 1.
  it("signer not in predecessor.successors ⇒ refuse, nothing written", async () => {
    const { tmp, root } = tmpRoot("um-pf1-");
    try {
      await seedRoot(root, { successors: "file:fpub", threshold: 1 });
      const before = fs.readdirSync(path.join(root, "tracks/release/mandates")).length;
      const lines: string[] = [];
      const code = await dispatch(
        parseArgs([
          "upsert-mandate", "--track", "release",
          "--signing-key", "yubikey-piv:slot=9c", "--duration", "30d",
          "--path", root, "--yes",
        ]),
        mkEnv(lines, T1, "x", readOnlyToken(eve.pubKey), forbidPin),
      );
      expect(code).toBe(1);
      expect(lines.join("\n")).toMatch(/is not a named successor of the current mandate/);
      expect(fs.readdirSync(path.join(root, "tracks/release/mandates")).length).toBe(before);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("predecessor needs a quorum (threshold>1) ⇒ refuse (single-signer scoped boundary)", async () => {
    const { tmp, root } = tmpRoot("um-pf2-");
    try {
      await seedRoot(root, { successors: "file:fpub,file:bpub", threshold: 2 });
      const lines: string[] = [];
      const code = await dispatch(
        parseArgs([
          "upsert-mandate", "--track", "release",
          "--signing-key", "yubikey-piv:slot=9c", "--duration", "30d",
          "--path", root, "--yes",
        ]),
        mkEnv(lines, T1, "x", readOnlyToken(founder.pubKey), forbidPin),
      );
      expect(code).toBe(1);
      expect(lines.join("\n")).toMatch(/quorum;.*SINGLE signature/s);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("window exceeds predecessor.maxDuration ⇒ refuse", async () => {
    const { tmp, root } = tmpRoot("um-pf3-");
    try {
      await seedRoot(root, { successors: "file:fpub", threshold: 1, maxDuration: "30d" });
      const lines: string[] = [];
      const code = await dispatch(
        parseArgs([
          "upsert-mandate", "--track", "release",
          "--signing-key", "yubikey-piv:slot=9c", "--duration", "60d",
          "--path", root, "--yes",
        ]),
        mkEnv(lines, T1, "x", readOnlyToken(founder.pubKey), forbidPin),
      );
      expect(code).toBe(1);
      expect(lines.join("\n")).toMatch(/exceeds the predecessor's maxDuration/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("successors below predecessor.minSuccessors ⇒ refuse", async () => {
    const { tmp, root } = tmpRoot("um-pf4-");
    try {
      await seedRoot(root, {
        successors: "file:fpub,file:bpub",
        threshold: 1,
        minSuccessors: 2,
      });
      const lines: string[] = [];
      const code = await dispatch(
        parseArgs([
          "upsert-mandate", "--track", "release",
          "--signing-key", "yubikey-piv:slot=9c", "--successors", "file:fpub",
          "--duration", "30d", "--path", root, "--yes",
        ]),
        mkEnv(lines, T1, "x", readOnlyToken(founder.pubKey), forbidPin),
      );
      expect(code).toBe(1);
      expect(lines.join("\n")).toMatch(/below minSuccessors/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
