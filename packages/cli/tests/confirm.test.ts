/**
 * The typed-confirm gate (#28): a real ceremony must not sign or write
 * until the operator has explicitly affirmed. `--yes` is the only
 * non-interactive bypass; with neither `--yes` nor an injected confirm
 * the gate fails CLOSED (never silently auto-proceeds). The banner +
 * byte/diff preview are always shown first.
 *
 * LOCKED Phase-2 v2: genesis/mandate/takeover collapsed into the ONE
 * `upsert-mandate` verb — the ceremony kinds exercised here are
 * `upsert-mandate` / `ca-endorsement` / `create-key`.
 */

import { describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { generateKeypair } from "@ibisllc/maintainers";
import {
  confirmGate,
  confirmPhrase,
  type ConfirmFn,
} from "../src/lib/ceremony.js";
import { dispatch, type CliEnv } from "../src/index.js";
import { parseArgs } from "../src/lib/args.js";

function keypair(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

describe("confirmPhrase", () => {
  it("forces a ceremony-specific word", () => {
    expect(confirmPhrase("upsert-mandate")).toBe("UPSERT-MANDATE");
    expect(confirmPhrase("create-key")).toBe("CREATE-KEY");
    expect(confirmPhrase("ca-endorsement")).toBe("CA-LEASE");
  });
});

describe("confirmGate", () => {
  it("--yes skips the prompt (and says so)", async () => {
    const lines: string[] = [];
    const confirm = vi.fn<ConfirmFn>();
    await confirmGate("upsert-mandate", true, confirm, (l) => lines.push(l));
    expect(confirm).not.toHaveBeenCalled();
    expect(lines.join("\n")).toMatch(/--yes.*skipping/);
  });

  it("no --yes and no confirm provider → fail closed", async () => {
    await expect(
      confirmGate("ca-endorsement", false, undefined, () => {}),
    ).rejects.toThrow(/needs interactive confirmation/);
  });

  it("confirm returning false aborts (nothing proceeds)", async () => {
    await expect(
      confirmGate("upsert-mandate", false, async () => false, () => {}),
    ).rejects.toThrow(/aborted at the confirmation/);
  });

  it("confirm gets the right phrase and true proceeds", async () => {
    let seen: string | undefined;
    await confirmGate(
      "upsert-mandate",
      false,
      async ({ phrase }) => {
        seen = phrase;
        return true;
      },
      () => {},
    );
    expect(seen).toBe("UPSERT-MANDATE");
  });
});

describe("the gate is wired into the real command path", () => {
  function mkEnv(lines: string[], confirm?: ConfirmFn): CliEnv {
    return {
      now: () => new Date("2026-05-17T12:00:00Z"),
      io: { readFileSync: (p: string) => fs.readFileSync(p, "utf8") },
      uuid: () => "cfm00000-0000-0000-0000-000000000000",
      println: (l) => lines.push(l),
      printerr: (l) => lines.push(`ERR ${l}`),
      confirm,
    };
  }

  function fromScratchArgs(root: string, priv: string, extra: string[]) {
    // from-scratch upsert-mandate: signer self-signs (holder defaults to
    // the signing key); --project-name is required for an origin mandate.
    return parseArgs([
      "upsert-mandate",
      "--track", "ca",
      "--duration", "365d",
      "--signing-key", `file:${priv}`,
      "--project-name", "flagship",
      "--path", root,
      ...extra,
    ]);
  }

  it("no confirm + no --yes ⇒ exit 1, banner+preview shown, nothing written", async () => {
    const m = keypair(7);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cfm-fc-"));
    try {
      const priv = path.join(tmp, "m.priv");
      fs.writeFileSync(priv, m.privKey);
      const lines: string[] = [];
      // env.confirm undefined ⇒ fail-closed (the bin shim's defaultEnv
      // would supply ttyConfirm; here we model a non-TTY/no-confirm env)
      const code = await dispatch(
        fromScratchArgs(path.join(tmp, ".maintainers"), priv, []),
        mkEnv(lines),
      );
      expect(code).toBe(1);
      const out = lines.join("\n");
      expect(out).toContain("FROM-SCRATCH ORIGIN"); // the loud origin warning
      expect(out).toContain("REVIEW — upsert-mandate"); // preview was shown
      expect(out).toMatch(/ERR error:.*needs interactive confirmation/);
      expect(fs.existsSync(path.join(tmp, ".maintainers", "tracks"))).toBe(false);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("confirm returning false ⇒ exit 1, nothing written", async () => {
    const m = keypair(8);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cfm-no-"));
    try {
      const priv = path.join(tmp, "m.priv");
      fs.writeFileSync(priv, m.privKey);
      const lines: string[] = [];
      const code = await dispatch(
        fromScratchArgs(path.join(tmp, ".maintainers"), priv, []),
        mkEnv(lines, async () => false),
      );
      expect(code).toBe(1);
      expect(lines.join("\n")).toMatch(/aborted at the confirmation/);
      expect(fs.existsSync(path.join(tmp, ".maintainers", "tracks"))).toBe(false);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("confirm returning true ⇒ writes and exits 0 (banner+REVIEW shown)", async () => {
    const m = keypair(9);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cfm-ok-"));
    try {
      const priv = path.join(tmp, "m.priv");
      fs.writeFileSync(priv, m.privKey);
      const lines: string[] = [];
      let askedPhrase = "";
      const code = await dispatch(
        fromScratchArgs(path.join(tmp, ".maintainers"), priv, []),
        mkEnv(lines, async ({ phrase }) => {
          askedPhrase = phrase;
          return true;
        }),
      );
      expect(code).toBe(0);
      expect(askedPhrase).toBe("UPSERT-MANDATE");
      const out = lines.join("\n");
      expect(out).toContain("REVIEW — upsert-mandate");
      expect(out).toContain("wrote from-scratch (root) mandate");
      expect(out).toContain("RECORD the PIN"); // bake-per-surface guidance
      expect(
        fs.existsSync(path.join(tmp, ".maintainers", "tracks/ca/mandates")),
      ).toBe(true);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
