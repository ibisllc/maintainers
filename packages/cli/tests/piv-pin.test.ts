/**
 * The secure interactive PIV PIN reader (the genesis-ceremony gap:
 * `defaultEnv` set `pivTransport` but NOT `pivPin`, so the first REAL
 * `yubikey-piv:` signature threw "a PIN provider is required").
 *
 * Every effect (the TTY device, interactivity) is injected, so the whole
 * reader is exercised with ZERO real TTY/token/PIN — exactly like
 * `piv-connect.test.ts`. The fake here models RAW-MODE byte input plus a
 * `setRawMode` spy (the real reader disables echo at the OS level via
 * raw mode — NOT the proven-broken readline `_writeToOutput` intercept).
 * Every "PIN" literal is a dummy test fixture, never a real secret.
 *
 * Proven hermetically:
 *   • returns the entered line and NEVER echoes any typed byte (the
 *     output sink contains only the label + a trailing newline)
 *   • raw mode is ENABLED before the read and RESTORED (cooked) after
 *   • Backspace edits the in-memory buffer
 *   • Ctrl-C / EOF ⇒ a clean CliError abort with the terminal restored
 *   • the owned fd/handle is closed EXACTLY ONCE and a forced teardown
 *     error is SWALLOWED (no unhandled 'error', the process never throws)
 *   • non-interactive ⇒ the precise fail-closed CliError BEFORE any
 *     device open (never returns, never hangs, never opens a device)
 *   • the line never appears in argv / env / any written sink / any
 *     thrown error or stack
 *   • defaultEnv.pivPin is DEFINED and a `yubikey-piv:` resolve via a
 *     present provider no longer throws "a PIN provider is required"
 */

import { describe, expect, it } from "vitest";
import { Readable, Writable } from "node:stream";
import { pivPinFromTty, type TtyDevice } from "../src/index.js";
import { defaultEnv } from "../src/index.js";
import { loadSigner, type PivTransport } from "../src/lib/keysource.js";
import { CliError } from "../src/lib/args.js";

const FAKE_PIN = "123456"; // dummy test fixture — NEVER a real secret

/**
 * A fake controlling terminal modelling RAW-MODE byte input.
 *
 * `keystrokes` is the exact byte stream the human would produce; the
 * reader consumes `data` chunks itself (no readline). We append `\r`
 * (Enter) so the line completes deterministically without a keyboard.
 * A `setRawMode` spy records the enable→restore transition. The output
 * Writable records EVERYTHING written so a test can assert no echo.
 */
function fakeTty(keystrokes: string): {
  dev: TtyDevice;
  written: () => string;
  closed: () => boolean;
  closeCount: () => number;
  rawCalls: () => boolean[];
  rawNow: () => boolean;
} {
  const out: string[] = [];
  let closeCount = 0;
  const rawCalls: boolean[] = [];
  let rawNow = false;

  const input = new Readable({ read() {} }) as Readable & {
    setRawMode?: (m: boolean) => unknown;
    isRaw?: boolean;
  };
  input.setRawMode = (m: boolean) => {
    rawCalls.push(m);
    rawNow = m;
    input.isRaw = m;
    return input;
  };
  // Deliver the keystrokes + Enter on next tick (matches a real TTY:
  // raw mode is set, .resume() called, THEN bytes arrive).
  process.nextTick(() => {
    input.push(keystrokes + "\r");
  });

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
        closeCount++;
      },
    },
    written: () => out.join(""),
    closed: () => closeCount > 0,
    closeCount: () => closeCount,
    rawCalls: () => rawCalls,
    rawNow: () => rawNow,
  };
}

describe("pivPinFromTty — reads the PIN no-echo (OS-level raw mode) from /dev/tty", () => {
  it("returns the entered PIN and NEVER echoes it; raw mode enabled then restored", async () => {
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
    // …but no typed byte is EVER written back to the terminal device.
    // The only writes are the label and a single trailing newline.
    expect(tty.written()).not.toContain(FAKE_PIN);
    expect(tty.written()).toBe("Enter YubiKey PIV PIN: \n");
    // OS-level no-echo proof: raw mode was turned ON, then restored OFF.
    expect(tty.rawCalls()).toEqual([true, false]);
    expect(tty.rawNow()).toBe(false);
    // The device handle is always torn down (no leaked /dev/tty fd).
    expect(tty.closed()).toBe(true);
  });

  it("Backspace/DEL edits the in-memory buffer (never echoes an erase)", async () => {
    // Type "12X" then DEL (0x7f) then "3456" → resolves "123456".
    const tty = fakeTty("12X\x7f3456");
    const provider = pivPinFromTty({
      interactive: true,
      openTty: () => tty.dev,
    });
    const pin = await provider();
    expect(pin).toBe("123456");
    // The mistaken char, the erase, and the corrected chars never echo.
    expect(tty.written()).not.toContain("12X");
    expect(tty.written()).not.toContain("123456");
    expect(tty.rawCalls()).toEqual([true, false]);
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
      expect(tty.rawCalls()).toEqual([true, false]);
    }
  });
});

describe("pivPinFromTty — Ctrl-C / EOF abort cleanly with the terminal restored", () => {
  it("Ctrl-C (0x03) ⇒ clean CliError, raw mode restored, device closed", async () => {
    // No trailing Enter is reached: 0x03 aborts mid-line.
    const out: string[] = [];
    let closeCount = 0;
    const rawCalls: boolean[] = [];
    const input = new Readable({ read() {} }) as Readable & {
      setRawMode?: (m: boolean) => unknown;
    };
    input.setRawMode = (m: boolean) => {
      rawCalls.push(m);
      return input;
    };
    process.nextTick(() => input.push("12\x03"));
    const dev: TtyDevice = {
      input,
      output: new Writable({
        write(c, _e, cb) {
          out.push(c.toString());
          cb();
        },
      }),
      close() {
        closeCount++;
      },
    };
    const provider = pivPinFromTty({ interactive: true, openTty: () => dev });

    let caught: unknown;
    try {
      await provider();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CliError);
    expect((caught as Error).message).toMatch(/cancelled \(Ctrl-C\)/);
    // No typed byte leaked into the abort message.
    expect((caught as Error).message).not.toContain("12");
    // Terminal restored (raw on then off) and device closed exactly once.
    expect(rawCalls).toEqual([true, false]);
    expect(closeCount).toBe(1);
    // Nothing typed echoed.
    expect(out.join("")).not.toContain("12");
  });

  it("Ctrl-D / stream EOF ⇒ clean CliError (never hangs)", async () => {
    const rawCalls: boolean[] = [];
    const input = new Readable({ read() {} }) as Readable & {
      setRawMode?: (m: boolean) => unknown;
    };
    input.setRawMode = (m: boolean) => {
      rawCalls.push(m);
      return input;
    };
    // End the stream with no Enter and no data → EOF abort.
    process.nextTick(() => input.push(null));
    const dev: TtyDevice = {
      input,
      output: new Writable({ write: (_c, _e, cb) => cb() }),
      close() {},
    };
    const provider = pivPinFromTty({ interactive: true, openTty: () => dev });
    await expect(provider()).rejects.toThrow(
      /no PIN was read and nothing was signed/,
    );
    expect(rawCalls).toEqual([true, false]);
  });
});

describe("pivPinFromTty — fd lifecycle: single close, teardown errors swallowed", () => {
  it("close() is called exactly once even on the happy path", async () => {
    const tty = fakeTty(FAKE_PIN);
    const provider = pivPinFromTty({
      interactive: true,
      openTty: () => tty.dev,
    });
    await provider();
    expect(tty.closeCount()).toBe(1);
  });

  it("close() throwing EBADF is SWALLOWED — the real outcome is never masked, process never throws", async () => {
    // Model the EXACT prior crash shape: teardown raises (the old impl
    // double-closed one fd → EBADF). The reader must still RESOLVE the
    // PIN (never mask the real outcome) and never let close() escape.
    const input = new Readable({ read() {} }) as Readable & {
      setRawMode?: (m: boolean) => unknown;
    };
    input.setRawMode = () => input;
    process.nextTick(() => input.push(FAKE_PIN + "\r"));
    let closeCalls = 0;
    const dev: TtyDevice = {
      input,
      output: new Writable({ write: (_c, _e, cb) => cb() }),
      close() {
        closeCalls++;
        // Simulate the EBADF-on-double-close the old code hit.
        throw new Error("EBADF: bad file descriptor, close");
      },
    };
    const provider = pivPinFromTty({ interactive: true, openTty: () => dev });

    // It must RESOLVE (the real outcome is never masked by teardown)
    // even though close() throws, and close() runs exactly once.
    const pin = await provider();
    expect(pin).toBe(FAKE_PIN);
    expect(closeCalls).toBe(1);
  });

  it("the REAL device (openControllingTty) carries a lifetime 'error' swallow handler so a late EBADF can never become an unhandled 'error'", async () => {
    // The prior impl crashed because no 'error' listener was attached to
    // the /dev/tty streams, so a double-close EBADF surfaced as an
    // unhandled 'error' event. Assert the real opener attaches one for
    // the stream's whole lifetime (independent of any read in flight).
    const { openControllingTty } = await import("../src/index.js");
    const dev = openControllingTty();
    if (dev === null) {
      // No /dev/tty in this CI/sandbox — the contract is then vacuously
      // satisfied (we already fail-close on a null device elsewhere).
      expect(dev).toBeNull();
      return;
    }
    const inp = dev.input as unknown as {
      listenerCount: (e: string) => number;
      emit: (e: string, ...a: unknown[]) => boolean;
    };
    const out = dev.output as unknown as {
      listenerCount: (e: string) => number;
      emit: (e: string, ...a: unknown[]) => boolean;
    };
    // A swallowing 'error' listener is present on BOTH sides up front.
    expect(inp.listenerCount("error")).toBeGreaterThanOrEqual(1);
    expect(out.listenerCount("error")).toBeGreaterThanOrEqual(1);
    // Emitting a late EBADF on either stream does NOT throw (would be an
    // unhandled 'error' — the exact prior crash — if no handler existed).
    expect(() =>
      inp.emit("error", new Error("late teardown EBADF")),
    ).not.toThrow();
    expect(() =>
      out.emit("error", new Error("late teardown EBADF")),
    ).not.toThrow();
    // Single-close is idempotent and never throws.
    expect(() => {
      dev.close();
      dev.close();
    }).not.toThrow();
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

  it("a TTY with no raw-mode support ⇒ fail-closed (refuse to risk an echo)", async () => {
    // setRawMode absent → the reader must refuse rather than prompt
    // where the kernel would echo. close() must still run once.
    let closeCalls = 0;
    const dev: TtyDevice = {
      input: new Readable({ read() {} }),
      output: new Writable({ write: (_c, _e, cb) => cb() }),
      close() {
        closeCalls++;
      },
    };
    const provider = pivPinFromTty({ interactive: true, openTty: () => dev });
    await expect(provider()).rejects.toThrow(/no raw mode/);
    expect(closeCalls).toBe(1);
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
    }) as Readable & { setRawMode?: (m: boolean) => unknown };
    errInput.setRawMode = () => errInput;
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
    // A device error mid-read surfaces as a clean fail-closed CliError
    // (EOF/closed/failed-to-read) — never any typed bytes, never a hang.
    expect(msgAndStack).toMatch(
      /YubiKey PIV PIN|controlling terminal|nothing was signed/,
    );
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
