/**
 * The no-hardware UX state machine (Phase-A ceremony hardening,
 * [[feedback-no-hardware-assumptions]]). `connectPcscChannelWithPrompt`
 * wraps the injected channel factory and the typed transport-error
 * taxonomy:
 *
 *   • not-ready × N → ready → succeeds   (recoverable: prompt+wait+poll)
 *   • security-failure → hard-abort, NEVER a software/in-process fallback
 *   • build-not-wired → fail-closed, NOT retried (a missing binding is
 *     not a missing reader), precise message preserved
 *   • non-interactive → fail-closed DETERMINISTICALLY (never hangs)
 *   • bounded: a token that never appears fails closed at the deadline,
 *     never an infinite wait; the inter-attempt wait is cooperative
 *
 * Every effect is injected (factory, prompt, sleep, clock) so the whole
 * machine is exercised with ZERO hardware. The security path is asserted
 * to NEVER return a channel.
 */

import { describe, expect, it, vi } from "vitest";
import {
  connectPcscChannelWithPrompt,
  PcscNotReadyError,
  PcscSecurityError,
  PcscBuildError,
  isRecoverableNotReady,
} from "../src/index.js";
import { CliError } from "../src/lib/args.js";
import type { PcscChannel } from "../src/lib/piv-pcsc.js";

const fakeChannel: PcscChannel = {
  async transmit() {
    return new Uint8Array([0x90, 0x00]);
  },
};

/** A sleeper that never wall-clock waits but advances an injected clock,
 *  so "bounded by the overall deadline" is testable instantly. */
function fakeClock(startMs = 0) {
  let t = startMs;
  return {
    now: () => t,
    sleep: async (ms: number) => {
      t += ms;
    },
    advance: (ms: number) => {
      t += ms;
    },
  };
}

describe("connectPcscChannelWithPrompt — recoverable not-ready", () => {
  it("not-ready ×3 → ready → returns the channel (prompts + polls + retries)", async () => {
    const clk = fakeClock();
    let calls = 0;
    const connect = vi.fn(async () => {
      calls++;
      if (calls <= 3) {
        throw new PcscNotReadyError("no token in the reader yet");
      }
      return fakeChannel;
    });
    const prompts: string[] = [];

    const ch = await connectPcscChannelWithPrompt({
      connect,
      prompt: (l) => prompts.push(l),
      interactive: true,
      sleep: clk.sleep,
      now: clk.now,
    });

    expect(ch).toBe(fakeChannel);
    expect(connect).toHaveBeenCalledTimes(4); // 3 not-ready + 1 success
    // It prompted the human (friendly, with the recoverable reason) and
    // kept a quieter "still waiting" poll line — NOT a fatal error.
    const out = prompts.join("\n");
    expect(out).toMatch(/Waiting for your YubiKey: no token in the reader yet/);
    expect(out).toMatch(/Insert the YubiKey/);
    expect(out).toMatch(/still waiting for the YubiKey \(attempt 3\)/);
  });

  it("succeeds on the FIRST try without prompting at all", async () => {
    const prompts: string[] = [];
    const ch = await connectPcscChannelWithPrompt({
      connect: async () => fakeChannel,
      prompt: (l) => prompts.push(l),
      interactive: true,
    });
    expect(ch).toBe(fakeChannel);
    expect(prompts).toEqual([]); // no prompt when hardware is already ready
  });
});

describe("connectPcscChannelWithPrompt — security failure is FATAL, no fallback", () => {
  it("re-throws PcscSecurityError immediately and NEVER returns a channel", async () => {
    const connect = vi.fn(async () => {
      throw new PcscSecurityError(
        "slot 9c pubkey does not match the expected signer (wrong YubiKey)",
      );
    });
    let caught: unknown;
    let returned: unknown;
    try {
      returned = await connectPcscChannelWithPrompt({
        connect,
        prompt: () => {},
        interactive: true,
      });
    } catch (e) {
      caught = e;
    }
    expect(returned).toBeUndefined(); // NEVER a software/in-process key
    expect(caught).toBeInstanceOf(PcscSecurityError);
    expect((caught as Error).message).toMatch(/wrong YubiKey/);
    expect(connect).toHaveBeenCalledTimes(1); // not retried — hard abort
  });

  it("a security failure AFTER not-ready retries still hard-aborts (no fallback)", async () => {
    const clk = fakeClock();
    let calls = 0;
    const connect = async () => {
      calls++;
      if (calls <= 2) throw new PcscNotReadyError("reader empty");
      throw new PcscSecurityError("VERIFY PIN blocked — token locked");
    };
    let caught: unknown;
    let returned: unknown;
    try {
      returned = await connectPcscChannelWithPrompt({
        connect,
        prompt: () => {},
        interactive: true,
        sleep: clk.sleep,
        now: clk.now,
      });
    } catch (e) {
      caught = e;
    }
    expect(returned).toBeUndefined();
    expect(caught).toBeInstanceOf(PcscSecurityError);
    expect((caught as Error).message).toMatch(/token locked/);
    expect(calls).toBe(3); // 2 recoverable waits, then the fatal one
  });
});

describe("connectPcscChannelWithPrompt — build-not-wired is fail-closed, not retried", () => {
  it("re-throws PcscBuildError immediately with its precise message", async () => {
    let calls = 0;
    const connect = async () => {
      calls++;
      throw new PcscBuildError(
        "the native PIV/PC/SC transport is not wired in this build: the " +
          "optional 'pcsclite' binding is not installed. … It never " +
          "silently falls back.",
      );
    };
    let caught: unknown;
    try {
      await connectPcscChannelWithPrompt({
        connect,
        prompt: () => {},
        interactive: true,
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(PcscBuildError);
    expect((caught as Error).message).toMatch(
      /native PIV\/PC\/SC transport is not wired in this build/,
    );
    expect((caught as Error).message).toMatch(/never silently falls back/);
    expect(calls).toBe(1); // a missing binding is NOT a missing reader
  });
});

describe("connectPcscChannelWithPrompt — non-interactive fails closed deterministically", () => {
  it("first not-ready in a piped/CI context aborts immediately (never hangs)", async () => {
    let calls = 0;
    const connect = async () => {
      calls++;
      throw new PcscNotReadyError("no reader connected");
    };
    const sleep = vi.fn(async () => {});
    let caught: unknown;
    try {
      await connectPcscChannelWithPrompt({
        connect,
        prompt: () => {},
        interactive: false, // piped / --yes / CI
        sleep,
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CliError);
    expect((caught as Error).message).toMatch(/non-interactive context/);
    expect((caught as Error).message).toMatch(/never silently falls back/);
    expect(calls).toBe(1); // did NOT loop
    expect(sleep).not.toHaveBeenCalled(); // did NOT wait for a human
  });
});

describe("connectPcscChannelWithPrompt — bounded (never an infinite wait)", () => {
  it("a token that never appears fails closed at the overall deadline", async () => {
    const clk = fakeClock();
    let calls = 0;
    const connect = async () => {
      calls++;
      throw new PcscNotReadyError("still no token");
    };
    let caught: unknown;
    try {
      await connectPcscChannelWithPrompt({
        connect,
        prompt: () => {},
        interactive: true,
        sleep: clk.sleep, // advances the injected clock by the poll interval
        now: clk.now,
        overallTimeoutMs: 10_000,
        pollIntervalMs: 1_000,
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CliError);
    expect((caught as Error).message).toMatch(/within 10s/);
    expect((caught as Error).message).toMatch(/never silently falls back/);
    // bounded: ~10 polls of 1s, NOT infinite.
    expect(calls).toBeGreaterThanOrEqual(10);
    expect(calls).toBeLessThanOrEqual(12);
  });

  it("the inter-attempt wait never overshoots the remaining budget", async () => {
    const clk = fakeClock();
    const slept: number[] = [];
    let calls = 0;
    const connect = async () => {
      calls++;
      throw new PcscNotReadyError("nope");
    };
    try {
      await connectPcscChannelWithPrompt({
        connect,
        prompt: () => {},
        interactive: true,
        sleep: async (ms) => {
          slept.push(ms);
          clk.advance(ms);
        },
        now: clk.now,
        overallTimeoutMs: 2_500,
        pollIntervalMs: 1_000,
      });
    } catch {
      /* expected */
    }
    // last sleep is clamped to the remaining budget (≤ pollInterval).
    for (const s of slept) expect(s).toBeLessThanOrEqual(1_000);
    expect(slept[slept.length - 1]).toBeLessThanOrEqual(1_000);
  });
});

describe("isRecoverableNotReady discriminator", () => {
  it("is true ONLY for PcscNotReadyError; false for security/build/plain", () => {
    expect(isRecoverableNotReady(new PcscNotReadyError("x"))).toBe(true);
    expect(isRecoverableNotReady(new PcscSecurityError("x"))).toBe(false);
    expect(isRecoverableNotReady(new PcscBuildError("x"))).toBe(false);
    expect(isRecoverableNotReady(new CliError("x"))).toBe(false);
    expect(isRecoverableNotReady(new Error("x"))).toBe(false);
    expect(isRecoverableNotReady("not even an error")).toBe(false);
  });

  it("all three typed errors are still CliError (existing dispatch unchanged)", () => {
    expect(new PcscNotReadyError("x")).toBeInstanceOf(CliError);
    expect(new PcscSecurityError("x")).toBeInstanceOf(CliError);
    expect(new PcscBuildError("x")).toBeInstanceOf(CliError);
  });
});

describe("unexpected (non-taxonomy) errors are fatal, never downgraded", () => {
  it("a plain Error from connect is re-thrown, not treated as not-ready", async () => {
    const connect = async () => {
      throw new Error("totally unexpected binding fault");
    };
    let caught: unknown;
    try {
      await connectPcscChannelWithPrompt({
        connect,
        prompt: () => {},
        interactive: true,
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toMatch(/unexpected binding fault/);
    expect(caught).not.toBeInstanceOf(PcscNotReadyError);
  });
});
