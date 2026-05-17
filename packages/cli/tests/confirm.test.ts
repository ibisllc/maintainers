/**
 * The typed-confirm gate (#28): a real ceremony must not sign or write
 * until the operator has explicitly affirmed. `--yes` is the only
 * non-interactive bypass; with neither `--yes` nor an injected confirm
 * the gate fails CLOSED (never silently auto-proceeds). The banner +
 * byte/diff preview are always shown first.
 */

import { describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { generateKeypair } from "@maintainers/protocol";
import {
  confirmGate,
  confirmPhrase,
  type ConfirmFn,
} from "../src/lib/ceremony.js";
import { CliError } from "../src/lib/args.js";
import { dispatch, type CliEnv } from "../src/index.js";
import { parseArgs } from "../src/lib/args.js";

function keypair(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

describe("confirmPhrase", () => {
  it("forces a ceremony-specific word", () => {
    expect(confirmPhrase("genesis")).toBe("GENESIS");
    expect(confirmPhrase("mandate")).toBe("MANDATE");
    expect(confirmPhrase("takeover")).toBe("TAKEOVER");
    expect(confirmPhrase("ca-endorsement")).toBe("CA-LEASE");
  });
});

describe("confirmGate", () => {
  it("--yes skips the prompt (and says so)", async () => {
    const lines: string[] = [];
    const confirm = vi.fn<ConfirmFn>();
    await confirmGate("genesis", true, confirm, (l) => lines.push(l));
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
      confirmGate("takeover", false, async () => false, () => {}),
    ).rejects.toThrow(/aborted at the confirmation/);
  });

  it("confirm gets the right phrase and true proceeds", async () => {
    let seen: string | undefined;
    await confirmGate(
      "mandate",
      false,
      async ({ phrase }) => {
        seen = phrase;
        return true;
      },
      () => {},
    );
    expect(seen).toBe("MANDATE");
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

  function genesisArgs(root: string, pub: string, priv: string, extra: string[]) {
    return parseArgs([
      "genesis",
      "--track", "ca",
      "--duration", "365d",
      "--holder-key", `file:${pub}`,
      "--signing-key", `file:${priv}`,
      "--output", root,
      ...extra,
    ]);
  }

  it("no confirm + no --yes ⇒ exit 1, banner+preview shown, nothing written", async () => {
    const m = keypair(7);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cfm-fc-"));
    try {
      const pub = path.join(tmp, "m.pub");
      const priv = path.join(tmp, "m.priv");
      fs.writeFileSync(pub, m.pubKey);
      fs.writeFileSync(priv, m.privKey);
      const lines: string[] = [];
      // env.confirm undefined ⇒ fail-closed (the bin shim's defaultEnv
      // would supply ttyConfirm; here we model a non-TTY/no-confirm env)
      const code = await dispatch(
        genesisArgs(path.join(tmp, ".maintainers"), pub, priv, []),
        mkEnv(lines),
      );
      expect(code).toBe(1);
      const out = lines.join("\n");
      expect(out).toContain("GENESIS — you are creating the ROOT OF TRUST");
      expect(out).toContain("REVIEW — genesis"); // preview was shown
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
      const pub = path.join(tmp, "m.pub");
      const priv = path.join(tmp, "m.priv");
      fs.writeFileSync(pub, m.pubKey);
      fs.writeFileSync(priv, m.privKey);
      const lines: string[] = [];
      const code = await dispatch(
        genesisArgs(path.join(tmp, ".maintainers"), pub, priv, []),
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
      const pub = path.join(tmp, "m.pub");
      const priv = path.join(tmp, "m.priv");
      fs.writeFileSync(pub, m.pubKey);
      fs.writeFileSync(priv, m.privKey);
      const lines: string[] = [];
      let askedPhrase = "";
      const code = await dispatch(
        genesisArgs(path.join(tmp, ".maintainers"), pub, priv, []),
        mkEnv(lines, async ({ phrase }) => {
          askedPhrase = phrase;
          return true;
        }),
      );
      expect(code).toBe(0);
      expect(askedPhrase).toBe("GENESIS");
      const out = lines.join("\n");
      expect(out).toContain("REVIEW — genesis");
      expect(out).toContain("wrote genesis mandate");
      expect(out).toContain("ONLY recovery"); // successor guidance
      expect(
        fs.existsSync(path.join(tmp, ".maintainers", "tracks/ca/mandates")),
      ).toBe(true);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
