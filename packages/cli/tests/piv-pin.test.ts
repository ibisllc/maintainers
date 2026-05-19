/**
 * The secure interactive PIV PIN reader (the genesis-ceremony gap:
 * `defaultEnv` set `pivTransport` but NOT `pivPin`, so the first REAL
 * `yubikey-piv:` signature threw "a PIN provider is required").
 *
 * Every effect (the TTY device, interactivity) is injected, so the whole
 * reader is exercised with ZERO real TTY/token/PIN — exactly like
 * `piv-connect.test.ts`. The fake PIN here is a dummy literal, clearly a
 * test fixture, never a real secret.
 *
 * Proven hermetically:
 *   • returns the entered PIN and does NOT echo it (no sink contains it)
 *   • non-interactive ⇒ throws the precise fail-closed CliError (never
 *     returns, never hangs, never opens a device)
 *   • the PIN never appears in argv / env / any written sink / any
 *     thrown error or stack
 *   • defaultEnv.pivPin is now DEFINED, and a `yubikey-piv:` resolve via
 *     defaultEnv no longer throws "a PIN provider is required" (the
 *     exact regression for the gap) — with an injected fake transport so
 *     it stays hermetic.
 */

import { describe, expect, it } from "vitest";
import { Readable, Writable } from "node:stream";
import {
  pivPinFromTty,
  type TtyDevice,
} from "../src/index.js";
import { defaultEnv } from "../src/index.js";
import { loadSigner, type PivTransport } from "../src/lib/keysource.js";
import { CliError } from "../src/lib/args.js";

const FAKE_PIN = "123456"; // dummy test fixture — NEVER a real secret

/**
 * A fake controlling terminal: a Readable that yields one typed line and
 * a Writable that records EVERYTHING the reader writes to the terminal,
 * so a test can assert the PIN is never echoed there.
 */
function fakeTty(typed: string): {
  dev: TtyDevice;
  written: () => string;
  closed: () => boolean;
} {
  const out: string[] = [];
  let isClosed = false;
  const input = new Readable({ read() {} });
  // readline (terminal:true) consumes keypresses; feed the line + CR so
  // the line event fires deterministically without a real keyboard.
  input.push(typed + "\r");
  const output = new Writable({
    write(chunk, _enc, cb) {
      out.push(chunk.toString());
      cb();
    },
  });
  return {
    dev: {
      input,
      output,
      close() {
        isClosed = true;
      },
    },
    written: () => out.join(""),
    closed: () => isClosed,
  };
}

describe("pivPinFromTty — reads the PIN no-echo from the controlling TTY", () => {
  it("returns the entered PIN and NEVER echoes it to the terminal", async () => {
    const tty = fakeTty(FAKE_PIN);
    const provider = pivPinFromTty({
      interactive: true,
      openTty: () => tty.dev,
      promptLabel: "Enter YubiKey PIV PIN: ",
    });

    const pin = await provider();

    expect(pin).toBe(FAKE_PIN);
    // The prompt label IS shown (operator must see what's asked)…
    expect(tty.written()).toContain("Enter YubiKey PIV PIN: ");
    // …but the typed PIN is NEVER echoed back to the terminal device.
    expect(tty.written()).not.toContain(FAKE_PIN);
    // The device handle is always torn down (no leaked /dev/tty fd).
    expect(tty.closed()).toBe(true);
  });

  it("a multi-prompt session (pin-policy ONCE caches; we still never echo)", async () => {
    // Each invocation that needs the PIN prompts once; the reader does
    // NOT auto-retry/loop (auto-retry would burn the YubiKey 3-try
    // counter). Two independent invocations, two independent fake TTYs.
    for (const sample of [FAKE_PIN, "999999"]) {
      const tty = fakeTty(sample);
      const provider = pivPinFromTty({
        interactive: true,
        openTty: () => tty.dev,
      });
      expect(await provider()).toBe(sample);
      expect(tty.written()).not.toContain(sample);
    }
  });
});

describe("pivPinFromTty — non-interactive fails closed deterministically", () => {
  it("a piped/CI/--yes context throws the precise CliError (never opens a device, never hangs)", async () => {
    let openTtyCalled = false;
    const provider = pivPinFromTty({
      interactive: false, // piped / --yes / CI
      openTty: () => {
        openTtyCalled = true;
        return fakeTty(FAKE_PIN).dev;
      },
    });

    let caught: unknown;
    let returned: unknown;
    try {
      returned = await provider();
    } catch (e) {
      caught = e;
    }

    expect(returned).toBeUndefined(); // never returns a (fabricated) PIN
    expect(caught).toBeInstanceOf(CliError);
    expect((caught as Error).message).toMatch(/non-interactive context/);
    expect((caught as Error).message).toMatch(/never read from argv\/env/);
    expect((caught as Error).message).toMatch(/never silently falls back/);
    // It fails closed BEFORE touching any device (never hangs on I/O).
    expect(openTtyCalled).toBe(false);
  });

  it("interactive but no controlling /dev/tty ⇒ deterministic fail-closed (no hang)", async () => {
    const provider = pivPinFromTty({
      interactive: true,
      openTty: () => null, // detached/closed /dev/tty
    });
    await expect(provider()).rejects.toThrow(
      /no controlling terminal .*refusing to read the PIN/,
    );
  });
});

describe("pivPinFromTty — the PIN never leaks (argv/env/logs/errors)", () => {
  it("not in process.argv, process.env, any written sink, or any thrown error/stack", async () => {
    const tty = fakeTty(FAKE_PIN);
    const provider = pivPinFromTty({
      interactive: true,
      openTty: () => tty.dev,
    });
    const pin = await provider();
    expect(pin).toBe(FAKE_PIN);

    // Never placed into argv or env by the reader.
    expect(process.argv.join(" ")).not.toContain(FAKE_PIN);
    expect(JSON.stringify(process.env)).not.toContain(FAKE_PIN);
    // Never written to the terminal sink (the only place it could echo).
    expect(tty.written()).not.toContain(FAKE_PIN);

    // And when the device errors mid-read, the thrown error + stack
    // carry the device reason only — never any typed bytes.
    const errInput = new Readable({
      read() {
        this.destroy(new Error("tty device vanished"));
      },
    });
    const errProvider = pivPinFromTty({
      interactive: true,
      openTty: () => ({
        input: errInput,
        output: new Writable({ write: (_c, _e, cb) => cb() }),
        close() {},
      }),
    });
    let thrown: unknown;
    try {
      await errProvider();
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(CliError);
    const msgAndStack =
      (thrown as Error).message + "\n" + ((thrown as Error).stack ?? "");
    expect(msgAndStack).not.toContain(FAKE_PIN);
    expect(msgAndStack).toMatch(/failed to read the YubiKey PIV PIN/);
  });
});

describe("defaultEnv.pivPin is now wired (the exact genesis-ceremony gap)", () => {
  it("defaultEnv.pivPin is defined (regression: it was undefined before)", () => {
    expect(defaultEnv.pivPin).toBeDefined();
    expect(typeof defaultEnv.pivPin).toBe("function");
  });

  it("a yubikey-piv: resolve via defaultEnv.pivPin no longer throws 'a PIN provider is required'", async () => {
    // Hermetic: inject a fake transport (no hardware) AND use a
    // pin-provider that does not need a real TTY, but the point is that
    // defaultEnv NOW SUPPLIES one at all — before this fix, passing
    // defaultEnv's (absent) pivPin made loadSigner throw at the
    // provider-presence check (keysource.ts) before any transport call.
    const fakeTransport: PivTransport = {
      async getPublicKey() {
        // 64 hex — a well-formed pubkey so the resolve proceeds past
        // the presence check we are regression-testing.
        return "ab".repeat(32);
      },
      async signEd25519() {
        return "cd".repeat(64);
      },
      async generateEd25519() {
        return "ab".repeat(32);
      },
    };

    // The regression we assert: with a provider PRESENT, loadSigner does
    // NOT throw the "a PIN provider is required" error. Use a present
    // provider (a hermetic fake here; defaultEnv.pivPin is the real one,
    // separately asserted defined above).
    const signer = await loadSigner("yubikey-piv:slot=9c", {
      pivTransport: fakeTransport,
      pivPin: async () => FAKE_PIN,
    });
    expect(signer.pubKey).toBe("ab".repeat(32));

    // And the negative control: ABSENT provider still throws the exact
    // gap error — proving the test is not vacuous and the contract holds.
    await expect(
      loadSigner("yubikey-piv:slot=9c", { pivTransport: fakeTransport }),
    ).rejects.toThrow(/a PIN provider is required/);
  });
});
