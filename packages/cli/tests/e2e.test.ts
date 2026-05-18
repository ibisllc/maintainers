/**
 * End-to-end exercise of the CLI (LOCKED Phase-2 v2 model):
 *   - upsert-mandate (from-scratch ORIGIN) → writes a self-signed root
 *     mandate with inline policy + project (no policy.json)
 *   - upsert-mandate (succession/renewal)  → writes the holder-signed
 *     next mandate, governed by the predecessor's inline rule
 *   - verify   → reads everything back, anchors at the first on-repo
 *     mandate's pin, and verifies the chain FORWARD
 *   - status   → identical read path but does not exit on failure
 *
 * Plus the mandated v2 fail-closed negatives on the verify read path:
 *   - empty store ⇒ no tracks, verify trivially OK (nothing to anchor)
 *   - a tampered first mandate ⇒ root-signature-invalid ⇒ verify FAILs
 *     (the pure pin-not-in-log / forked-pin / unauthorised-successor
 *      negatives are proven at the protocol layer in envelopes.test.ts)
 *
 * Goes through `dispatch()` so we cover the argv → command-dispatch →
 * write path the bin shim actually uses.
 */

import { afterEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { generateKeypair } from "@ibisllc/maintainers";
import { dispatch, type CliEnv } from "../src/index.js";
import { parseArgs } from "../src/lib/args.js";

function keypair(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

const cleanup: string[] = [];
afterEach(() => {
  for (const d of cleanup) {
    try {
      fs.rmSync(d, { recursive: true, force: true });
    } catch {}
  }
  cleanup.length = 0;
});

function setupTmp(): { root: string; cliRoot: string; keys: Record<string, string> } {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "maintainers-cli-e2e-"));
  cleanup.push(tmp);
  const keysDir = path.join(tmp, "keys");
  fs.mkdirSync(keysDir);
  const alice = keypair(1);
  const bob = keypair(2);
  fs.writeFileSync(path.join(keysDir, "alice.pub"), alice.pubKey);
  fs.writeFileSync(path.join(keysDir, "alice.priv"), alice.privKey);
  fs.writeFileSync(path.join(keysDir, "bob.pub"), bob.pubKey);
  fs.writeFileSync(path.join(keysDir, "bob.priv"), bob.privKey);
  return {
    root: tmp,
    cliRoot: path.join(tmp, ".maintainers"),
    keys: {
      "alice.pub": path.join(keysDir, "alice.pub"),
      "alice.priv": path.join(keysDir, "alice.priv"),
      "bob.pub": path.join(keysDir, "bob.pub"),
      "bob.priv": path.join(keysDir, "bob.priv"),
    },
  };
}

function makeUuidFactory(): () => string {
  let counter = 0;
  return () => `00000000-0000-0000-0000-${(counter++).toString(16).padStart(12, "0")}`;
}

function mkEnv(now: Date, lines: string[], errs: string[], uuid: () => string): CliEnv {
  return {
    now: () => now,
    io: { readFileSync: (p: string) => fs.readFileSync(p, "utf8") },
    uuid,
    println: (line: string) => lines.push(line),
    printerr: (line: string) => errs.push(line),
  };
}

describe("end-to-end CLI dispatch", () => {
  it("upsert-mandate (origin) → upsert-mandate (renewal) → verify exits 0", async () => {
    const fx = setupTmp();
    const lines: string[] = [];
    const errs: string[] = [];
    const uuid = makeUuidFactory();

    // from-scratch ORIGIN — self-signed; successors=[alice,bob]; the
    // project metadata rides the inline `project` field (no policy.json).
    const env1 = mkEnv(new Date("2026-01-01T00:00:00Z"), lines, errs, uuid);
    const code1 = await dispatch(parseArgs([
      "upsert-mandate",
      "--track", "release",
      "--duration", "60d",
      "--signing-key", `file:${fx.keys["alice.priv"]}`,
      "--successors", `file:${fx.keys["alice.pub"]},file:${fx.keys["bob.pub"]}`,
      "--threshold", "1",
      "--max-duration", "365d",
      "--project-name", "flagship",
      "--path", fx.cliRoot,
      "--yes",
    ]), env1);
    expect(code1).toBe(0);
    // v2: NO policy.json — the rule is inline in the mandate file.
    expect(fs.existsSync(path.join(fx.cliRoot, "tracks/release/policy.json"))).toBe(false);
    expect(
      fs.readdirSync(path.join(fx.cliRoot, "tracks/release/mandates")).length,
    ).toBe(1);

    // succession (renewal) — alice is a named successor of the origin.
    const env2 = mkEnv(new Date("2026-02-15T00:00:00Z"), lines, errs, uuid);
    const code2 = await dispatch(parseArgs([
      "upsert-mandate",
      "--track", "release",
      "--duration", "60d",
      "--signing-key", `file:${fx.keys["alice.priv"]}`,
      "--path", fx.cliRoot,
      "--yes",
    ]), env2);
    expect(code2).toBe(0);

    const env3 = mkEnv(new Date("2026-02-20T00:00:00Z"), lines, errs, uuid);
    const code3 = await dispatch(parseArgs([
      "verify",
      "--path", fx.cliRoot,
    ]), env3);
    expect(code3).toBe(0);
    const out = lines.join("\n");
    expect(out).toContain("verify: OK");
    expect(out).toContain("anchored:         yes");
  });

  it("status reports an un-anchored track without exiting non-zero", async () => {
    const fx = setupTmp();
    const lines: string[] = [];
    const errs: string[] = [];
    const uuid = makeUuidFactory();

    const env1 = mkEnv(new Date("2026-01-01T00:00:00Z"), lines, errs, uuid);
    await dispatch(parseArgs([
      "upsert-mandate",
      "--track", "release",
      "--duration", "60d",
      "--signing-key", `file:${fx.keys["alice.priv"]}`,
      "--project-name", "flagship",
      "--path", fx.cliRoot,
      "--yes",
    ]), env1);

    // Tamper the only (root) mandate: the preview anchor recomputes the
    // pin over the on-disk bytes (so it still "matches"), but the
    // signature no longer verifies over the mutated canonical bytes ⇒
    // root-signature-invalid ⇒ the track does not anchor (fail-closed).
    const mdir = path.join(fx.cliRoot, "tracks/release/mandates");
    const f = path.join(mdir, fs.readdirSync(mdir)[0]!);
    const m = JSON.parse(fs.readFileSync(f, "utf8"));
    m.holder = "ff".repeat(32); // mutate a signed field
    fs.writeFileSync(f, JSON.stringify(m, null, 2) + "\n");

    const env2 = mkEnv(new Date("2026-01-15T00:00:00Z"), lines, errs, uuid);
    const code = await dispatch(parseArgs([
      "status",
      "--path", fx.cliRoot,
    ]), env2);
    expect(code).toBe(0); // status never exits non-zero
    expect(lines.join("\n")).toMatch(/anchored:\s+NO/);
  });

  it("verify returns 1 when a track cannot anchor (tampered root ⇒ fail-closed)", async () => {
    const fx = setupTmp();
    const lines: string[] = [];
    const errs: string[] = [];
    const uuid = makeUuidFactory();

    const env1 = mkEnv(new Date("2026-01-01T00:00:00Z"), lines, errs, uuid);
    await dispatch(parseArgs([
      "upsert-mandate",
      "--track", "release",
      "--duration", "60d",
      "--signing-key", `file:${fx.keys["alice.priv"]}`,
      "--project-name", "flagship",
      "--path", fx.cliRoot,
      "--yes",
    ]), env1);
    const mdir = path.join(fx.cliRoot, "tracks/release/mandates");
    const f = path.join(mdir, fs.readdirSync(mdir)[0]!);
    const m = JSON.parse(fs.readFileSync(f, "utf8"));
    m.expiresAt = "2099-01-01T00:00:00.000Z"; // tamper a signed field
    fs.writeFileSync(f, JSON.stringify(m, null, 2) + "\n");

    const env2 = mkEnv(new Date("2026-01-15T00:00:00Z"), lines, errs, uuid);
    const code = await dispatch(parseArgs([
      "verify",
      "--path", fx.cliRoot,
    ]), env2);
    expect(code).toBe(1);
    // The preview anchor recomputes mandatePinHash over the on-disk
    // bytes, so a tampered root still matches its own (recomputed) pin —
    // but its signature no longer verifies over the mutated canonical
    // bytes ⇒ root-signature-invalid ⇒ fail-closed (verify FAILs). The
    // pure pin-not-in-log / forked-pin negatives are proven at the
    // protocol layer in envelopes.test.ts.
    expect(lines.join("\n")).toMatch(
      /did not anchor a forward chain.*root-signature-invalid/s,
    );
  });

  it("verify on an empty/absent store exits 0 (no tracks to anchor)", async () => {
    const fx = setupTmp();
    const lines: string[] = [];
    const errs: string[] = [];
    const env = mkEnv(new Date("2026-01-01T00:00:00Z"), lines, errs, makeUuidFactory());
    const code = await dispatch(parseArgs(["verify", "--path", fx.cliRoot]), env);
    expect(code).toBe(0);
    expect(lines.join("\n")).toContain("no tracks discovered");
  });

  it("unknown command exits 2 with usage on stderr", async () => {
    const lines: string[] = [];
    const errs: string[] = [];
    const env = mkEnv(new Date("2026-01-01T00:00:00Z"), lines, errs, makeUuidFactory());
    const code = await dispatch(parseArgs(["banana"]), env);
    expect(code).toBe(2);
    expect(errs.join("\n")).toContain("unknown command");
  });

  it("help prints usage and exits 0", async () => {
    const lines: string[] = [];
    const errs: string[] = [];
    const env = mkEnv(new Date("2026-01-01T00:00:00Z"), lines, errs, makeUuidFactory());
    const code = await dispatch(parseArgs(["help"]), env);
    expect(code).toBe(0);
    expect(lines.join("\n")).toContain("authority-management CLI");
  });

  it("CliError from a command translates to exit 1 with an error: prefix", async () => {
    const fx = setupTmp();
    const lines: string[] = [];
    const errs: string[] = [];
    const env = mkEnv(new Date("2026-01-01T00:00:00Z"), lines, errs, makeUuidFactory());
    // upsert-mandate succession with no prior mandate AND no project-name
    // ⇒ treated as from-scratch but missing the required --project-name.
    const code = await dispatch(parseArgs([
      "upsert-mandate",
      "--track", "release",
      "--duration", "60d",
      "--signing-key", `file:${fx.keys["alice.priv"]}`,
      "--path", fx.cliRoot,
    ]), env);
    expect(code).toBe(1);
    expect(errs.join("\n")).toMatch(/requires --project-name/);
  });
});
