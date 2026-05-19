/**
 * The guided menu wizard is a THIN front-end: it ONLY gathers inputs via
 * the injected prompt seam, then builds the SAME ParsedArgs the flag
 * path produces and re-dispatches through the EXISTING handlers — so the
 * canonical-byte preview, the typed-confirm, the PIN read and the tap
 * are the unchanged existing code path. These tests are hermetic: no
 * real TTY/token/PIN. A scripted `prompt`, captured `println`/`printerr`,
 * a fake `confirm`/`pivPin`, and a temp `.maintainers` store stand in
 * for everything.
 *
 * Proven:
 *  1. the menu renders the 5 actions + quit; an invalid choice
 *     re-prompts; `q` quits cleanly (exit 0)
 *  2. each action gathers inputs and invokes the SAME handler with a
 *     ParsedArgs byte-equal to the equivalent flag invocation, and does
 *     NOT pass --yes / skip-confirm (the typed phrase confirm still runs)
 *  3. defaults: empty input takes the [default]
 *  4. non-interactive with no subcommand ⇒ existing printUsage + exit 0,
 *     prompt-free, the wizard does NOT engage and does NOT hang
 *  5. a handler CliError is surfaced cleanly (menu returns to the menu /
 *     `menu` exits non-zero) — no unhandled crash
 */

import { describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { generateKeypair } from "@ibisllc/maintainers";
import { dispatch, type CliEnv } from "../src/index.js";
import { runWizard } from "../src/lib/wizard.js";
import { parseArgs, type ParsedArgs, CliError } from "../src/lib/args.js";
import type { ConfirmFn } from "../src/lib/ceremony.js";

function keypair(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

/** A scripted prompt: returns the next queued answer for each call,
 *  recording every question asked. Throws if the script underruns (so a
 *  hang/extra-prompt is a loud test failure, never a real wait). */
function scripted(answers: string[]) {
  const asked: string[] = [];
  let i = 0;
  const prompt = async (q: string): Promise<string> => {
    asked.push(q);
    if (i >= answers.length) {
      throw new Error(`prompt script underran at question: ${q}`);
    }
    return answers[i++]!;
  };
  return { prompt, asked: () => asked, used: () => i };
}

function mkEnv(opts: {
  out: string[];
  err: string[];
  prompt?: (q: string) => Promise<string>;
  interactive?: boolean;
  confirm?: ConfirmFn;
  now?: Date;
}): CliEnv {
  return {
    now: () => opts.now ?? new Date("2026-05-17T12:00:00Z"),
    io: { readFileSync: (p: string) => fs.readFileSync(p, "utf8") },
    uuid: () => "wiz00000-0000-0000-0000-000000000000",
    println: (l) => opts.out.push(l),
    printerr: (l) => opts.err.push(l),
    prompt: opts.prompt,
    interactive: opts.interactive,
    confirm: opts.confirm,
  };
}

describe("wizard — menu render, invalid choice re-prompts, q quits", () => {
  it("renders the 5 actions + quit, re-prompts an invalid choice, q exits 0", async () => {
    const out: string[] = [];
    const err: string[] = [];
    // first answer is an invalid choice, then q
    const s = scripted(["bogus", "q"]);
    const code = await runWizard(
      { println: (l) => out.push(l), printerr: (l) => err.push(l), prompt: s.prompt, interactive: true },
      async () => 0,
    );
    expect(code).toBe(0);
    const text = out.join("\n");
    expect(text).toContain("Flagship maintainers — what do you want to do?");
    expect(text).toContain("1) Show status (tracks, mandates, expiry)");
    expect(text).toContain("2) Register a key (KeyFile)");
    expect(text).toContain("3) Issue / renew a mandate");
    expect(text).toContain("4) CA endorsement (lease the hot key)");
    expect(text).toContain("5) Verify the store");
    expect(text).toContain("q) Quit");
    // invalid choice produced an error line and the menu rendered twice
    expect(err.join("\n")).toMatch(/not a choice: "bogus"/);
    const menuCount = out.filter((l) =>
      l.includes("what do you want to do?"),
    ).length;
    expect(menuCount).toBe(2);
  });
});

describe("wizard — each action maps to the SAME ParsedArgs as the flag path", () => {
  it("status: byte-equal to `status --path P --as-of now`", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const seen: ParsedArgs[] = [];
    const s = scripted([
      "1", // choose status
      "/tmp/some-store", // path
      "now", // as-of
      "q", // quit
    ]);
    await runWizard(
      { println: (l) => out.push(l), printerr: (l) => err.push(l), prompt: s.prompt, interactive: true },
      async (a) => {
        seen.push(a);
        return 0;
      },
    );
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual(
      parseArgs(["status", "--path", "/tmp/some-store", "--as-of", "now"]),
    );
  });

  it("issue/renew mandate: byte-equal to the flag invocation; NO --yes", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const seen: ParsedArgs[] = [];
    const s = scripted([
      "3", // choose issue/renew mandate
      "ca", // track
      "100d", // duration
      "yubikey-piv:slot=9c", // signing key
      "", // holder (blank)
      "", // successors (blank)
      "flagship", // project name
      ".maintainers", // path
      "N", // dry run
      "q", // quit
    ]);
    await runWizard(
      { println: (l) => out.push(l), printerr: (l) => err.push(l), prompt: s.prompt, interactive: true },
      async (a) => {
        seen.push(a);
        return 0;
      },
    );
    expect(seen).toHaveLength(1);
    const expected = parseArgs([
      "upsert-mandate",
      "--track",
      "ca",
      "--duration",
      "100d",
      "--signing-key",
      "yubikey-piv:slot=9c",
      "--project-name",
      "flagship",
      "--path",
      ".maintainers",
    ]);
    expect(seen[0]).toEqual(expected);
    // The wizard NEVER injects --yes / a skip-confirm for an
    // irreversible verb: the typed phrase confirm + PIN + tap stay
    // mandatory and run inside the unchanged handler.
    expect(seen[0]!.flags.yes).toBeUndefined();
    expect(seen[0]!.flags["dry-run"]).toBeUndefined();
  });

  it("dry-run answer threads through as --dry-run (the flag path's dry-run)", async () => {
    const seen: ParsedArgs[] = [];
    const s = scripted([
      "4", // ca-endorsement
      "ab".repeat(32), // ca pubkey
      "flagship/directory-attestation", // scope
      "7d", // duration
      "ca", // track
      "yubikey-piv:slot=9c", // signing key
      ".maintainers", // path
      "y", // dry run = yes
      "q",
    ]);
    await runWizard(
      { println: () => {}, printerr: () => {}, prompt: s.prompt, interactive: true },
      async (a) => {
        seen.push(a);
        return 0;
      },
    );
    const expected = parseArgs([
      "ca-endorsement",
      "--ca-pubkey",
      "ab".repeat(32),
      "--scope",
      "flagship/directory-attestation",
      "--duration",
      "7d",
      "--track",
      "ca",
      "--signing-key",
      "yubikey-piv:slot=9c",
      "--path",
      ".maintainers",
      "--dry-run",
    ]);
    expect(seen[0]).toEqual(expected);
    expect(seen[0]!.flags.yes).toBeUndefined();
  });
});

describe("wizard — empty input takes the [default]", () => {
  it("blank answers fall back to the shown defaults", async () => {
    const seen: ParsedArgs[] = [];
    const s = scripted([
      "1", // status
      "", // path → default .maintainers
      "", // as-of → default now
      "q",
    ]);
    await runWizard(
      { println: () => {}, printerr: () => {}, prompt: s.prompt, interactive: true },
      async (a) => {
        seen.push(a);
        return 0;
      },
    );
    expect(seen[0]).toEqual(
      parseArgs(["status", "--path", ".maintainers", "--as-of", "now"]),
    );
  });
});

describe("wizard — drives the REAL handler path (preview + typed-confirm + PIN unchanged)", () => {
  it("issue/renew mandate dry-run: existing handler shows DRY RUN canonical bytes, no confirm, no PIN, nothing written", async () => {
    const m = keypair(21);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wiz-dry-"));
    try {
      const priv = path.join(tmp, "m.priv");
      fs.writeFileSync(priv, m.privKey);
      const root = path.join(tmp, ".maintainers");
      const out: string[] = [];
      const err: string[] = [];
      const confirm = vi.fn<ConfirmFn>(async () => true);
      const pivPin = vi.fn(async () => "unused");
      const env: CliEnv = {
        ...mkEnv({ out, err, interactive: true, confirm }),
        pivPin,
      };
      const s = scripted([
        "3",
        "ca", // track
        "365d", // duration
        `file:${priv}`, // signing key (hex fallback, no token)
        "", // holder
        "", // successors
        "flagship", // project name (required for from-scratch)
        root, // path
        "y", // dry run
        "q",
      ]);
      const code = await runWizard(
        {
          println: (l) => out.push(l),
          printerr: (l) => err.push(l),
          prompt: s.prompt,
          interactive: true,
        },
        (a) => dispatch(a, env),
      );
      expect(code).toBe(0);
      const text = out.join("\n");
      // The EXISTING ceremony preview ran (not reimplemented here).
      expect(text).toContain("DRY RUN — upsert-mandate");
      expect(text).toContain("canonical bytes (hex");
      expect(text).toContain("FROM-SCRATCH ORIGIN");
      // dry-run: never touches the confirm or the PIN, writes nothing.
      expect(confirm).not.toHaveBeenCalled();
      expect(pivPin).not.toHaveBeenCalled();
      expect(fs.existsSync(path.join(root, "tracks"))).toBe(false);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("real (non-dry) mandate via the wizard goes through the EXISTING typed-confirm (confirm true ⇒ writes; never auto --yes)", async () => {
    const m = keypair(22);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wiz-real-"));
    try {
      const priv = path.join(tmp, "m.priv");
      fs.writeFileSync(priv, m.privKey);
      const root = path.join(tmp, ".maintainers");
      const out: string[] = [];
      const err: string[] = [];
      let askedPhrase = "";
      const confirm: ConfirmFn = async ({ phrase }) => {
        askedPhrase = phrase;
        return true;
      };
      const env = mkEnv({ out, err, interactive: true, confirm });
      const s = scripted([
        "3",
        "ca",
        "365d",
        `file:${priv}`,
        "",
        "",
        "flagship",
        root,
        "N", // NOT a dry run — must hit the real typed-confirm
        "q",
      ]);
      const code = await runWizard(
        {
          println: (l) => out.push(l),
          printerr: (l) => err.push(l),
          prompt: s.prompt,
          interactive: true,
        },
        (a) => dispatch(a, env),
      );
      expect(code).toBe(0);
      // The EXISTING confirmGate ran with the EXISTING phrase — proof
      // the wizard did NOT pass --yes / bypass the typed-confirm.
      expect(askedPhrase).toBe("UPSERT-MANDATE");
      const text = out.join("\n");
      expect(text).toContain("REVIEW — upsert-mandate");
      expect(text).toContain("wrote from-scratch (root) mandate");
      expect(fs.existsSync(path.join(root, "tracks/ca/mandates"))).toBe(true);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("confirm returning false aborts via the EXISTING gate; the menu surfaces it and continues (no crash)", async () => {
    const m = keypair(23);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wiz-abort-"));
    try {
      const priv = path.join(tmp, "m.priv");
      fs.writeFileSync(priv, m.privKey);
      const root = path.join(tmp, ".maintainers");
      const out: string[] = [];
      const err: string[] = [];
      const env = mkEnv({ out, err, interactive: true, confirm: async () => false });
      const s = scripted([
        "3",
        "ca",
        "365d",
        `file:${priv}`,
        "",
        "",
        "flagship",
        root,
        "N",
        "q", // after the aborted action the loop returns to the menu
      ]);
      const code = await runWizard(
        {
          println: (l) => out.push(l),
          printerr: (l) => err.push(l),
          prompt: s.prompt,
          interactive: true,
        },
        (a) => dispatch(a, env),
      );
      // q after the aborted action ⇒ clean exit 0; nothing written.
      expect(code).toBe(0);
      const all = out.concat(err).join("\n");
      expect(all).toMatch(/aborted at the confirmation/);
      expect(all).toMatch(/returning to the menu/);
      expect(fs.existsSync(path.join(root, "tracks"))).toBe(false);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("wizard — non-interactive determinism (mirror the piv-pin/ttyConfirm taxonomy)", () => {
  it("bare `maintainers` non-interactive ⇒ printUsage + exit 0, prompt-free, wizard does NOT engage and does NOT hang", async () => {
    const out: string[] = [];
    const err: string[] = [];
    let promptCalled = false;
    const env = mkEnv({
      out,
      err,
      interactive: false, // piped/CI/no-TTY
      prompt: async () => {
        promptCalled = true;
        return "";
      },
    });
    const code = await dispatch(parseArgs([]), env);
    expect(code).toBe(0);
    expect(promptCalled).toBe(false); // never engaged the menu
    const text = out.join("\n");
    expect(text).toContain("maintainers — authority-management CLI");
    expect(text).toContain("commands:");
    // No menu render leaked into a non-interactive run.
    expect(text).not.toContain("what do you want to do?");
  });

  it("explicit `menu` non-interactive ⇒ deterministic fail-closed CliError (exit 1), never opens the prompt, never hangs", async () => {
    const out: string[] = [];
    const err: string[] = [];
    let promptCalled = false;
    const env = mkEnv({
      out,
      err,
      interactive: false,
      prompt: async () => {
        promptCalled = true;
        return "";
      },
    });
    const code = await dispatch(parseArgs(["menu"]), env);
    expect(code).toBe(1);
    expect(promptCalled).toBe(false);
    expect(err.join("\n")).toMatch(
      /guided menu needs an interactive terminal|non-interactive context/,
    );
  });

  it("runWizard with no prompt seam ⇒ deterministic fail-closed CliError (never hangs)", async () => {
    await expect(
      runWizard(
        { println: () => {}, printerr: () => {}, interactive: true },
        async () => 0,
      ),
    ).rejects.toBeInstanceOf(CliError);
  });
});

describe("wizard — a handler CliError is surfaced cleanly (no unhandled crash)", () => {
  it("`menu` then a handler that throws CliError: the menu surfaces it and returns to the menu", async () => {
    const out: string[] = [];
    const err: string[] = [];
    // status with a bad --as-of makes runStatus throw a CliError (parsed
    // by the EXISTING handler — the wizard does NOT pre-validate).
    const s = scripted([
      "1", // status
      ".maintainers", // path
      "not-a-date", // as-of → handler throws CliError
      "q", // proves the loop survived and returned to the menu
    ]);
    const realEnv = mkEnv({ out, err, interactive: true });
    const code = await runWizard(
      {
        println: (l) => out.push(l),
        printerr: (l) => err.push(l),
        prompt: s.prompt,
        interactive: true,
      },
      (a) => dispatch(a, realEnv),
    );
    // The loop did NOT crash; q after the failed action ⇒ exit 0.
    expect(code).toBe(0);
    const all = out.concat(err).join("\n");
    expect(all).toMatch(/invalid --as-of/);
    expect(all).toMatch(/returning to the menu/);
    // The menu rendered again after the error (loop survived).
    const menuCount = out.filter((l) =>
      l.includes("what do you want to do?"),
    ).length;
    expect(menuCount).toBe(2);
  });
});
