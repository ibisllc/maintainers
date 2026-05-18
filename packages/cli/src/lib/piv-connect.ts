/**
 * The no-hardware UX state machine — a prompt + wait + poll + retry loop
 * wrapping {@link connectPcscChannel}.
 *
 * [[feedback-no-hardware-assumptions]] (HARD user requirement): the
 * transport must NEVER assume the key/reader is present. *Absent reader
 * / absent token / not-tapped-yet* are NORMAL, RECOVERABLE states — the
 * loop prompts ("Insert your YubiKey…"), waits, polls, and retries them.
 * They are NOT failures and NEVER a fatal error.
 *
 * Fail-closed is a SECURITY property ONLY. A real security failure
 * (wrong key, signature/PIN failure, tamper — {@link PcscSecurityError})
 * MUST hard-abort and MUST NEVER silently fall back to a weaker/
 * in-process key. The build-not-wired condition ({@link PcscBuildError})
 * is a non-recoverable BUILD state — it stays fail-closed with its
 * precise message and is NOT retried forever (a missing binding cannot
 * be fixed by waiting). These are DISTINCT in the type system, never
 * conflated; this loop branches on that taxonomy and only ever retries
 * the one recoverable {@link PcscNotReadyError} case.
 *
 * Non-interactive-safe: a piped / `--yes` / CI context (no TTY, or no
 * injected prompt) fails CLOSED deterministically and immediately — it
 * never hangs waiting for a human who isn't there. Bounded: a sane
 * overall deadline caps the total wait; the inter-attempt wait is
 * cooperative (a sleeper, not a busy-loop).
 *
 * Pure & fully unit-testable: every effect (the channel factory, the
 * prompt, the sleeper, the clock, TTY-ness) is injected, so tests
 * substitute fakes that yield not-ready N times → then ready → then a
 * security failure, with zero hardware.
 */

import { CliError } from "./args.js";
import {
  connectPcscChannel,
  isRecoverableNotReady,
  type PcscChannel,
} from "./piv-pcsc.js";

/**
 * A factory that performs ONE connect attempt. Resolves a live channel,
 * or rejects: a recoverable {@link PcscNotReadyError} → the loop
 * prompts + waits + retries; anything else (security failure, build-
 * not-wired, unexpected) → the loop hard-aborts. Injected so tests drive
 * the not-ready→ready→security sequence with no hardware.
 */
export type ChannelFactory = () => Promise<PcscChannel>;

/** Cooperative sleeper (injected so tests don't wall-clock wait). */
export type Sleeper = (ms: number) => Promise<void>;

/** Human prompt sink for the recoverable wait UX. Never receives a PIN
 *  or any secret — only the "insert/tap your YubiKey" guidance. */
export type Prompter = (line: string) => void;

export interface ConnectWithPromptOptions {
  /** ONE connect attempt (default: the real {@link connectPcscChannel}). */
  connect?: ChannelFactory;
  /** Where the friendly wait/retry guidance goes (e.g. env.println). */
  prompt: Prompter;
  /** True iff attached to an interactive terminal. Non-interactive ⇒
   *  fail closed immediately on the first not-ready (never hang). */
  interactive: boolean;
  /** Cooperative sleeper (default: real setTimeout). */
  sleep?: Sleeper;
  /** Monotonic-ish clock in ms (default: Date.now). Injected for tests. */
  now?: () => number;
  /** Overall deadline budget in ms (default 120_000). The loop refuses
   *  to wait past this; a token that never appears fails closed rather
   *  than hang forever. */
  overallTimeoutMs?: number;
  /** Wait between poll attempts in ms (default 1_500). Cooperative. */
  pollIntervalMs?: number;
}

const DEFAULT_OVERALL_TIMEOUT_MS = 120_000;
const DEFAULT_POLL_INTERVAL_MS = 1_500;

const realSleep: Sleeper = (ms) =>
  new Promise((r) => setTimeout(r, ms));

/**
 * Connect to the PC/SC channel, treating absent hardware as a normal
 * recoverable wait (prompt + poll + retry) and a security/build failure
 * as a hard, no-fallback abort.
 *
 * Contract:
 *   • {@link PcscNotReadyError} (recoverable) — interactive: prompt the
 *     human, wait `pollIntervalMs`, retry, until a channel opens or the
 *     overall deadline elapses (then fail closed, never hang).
 *     Non-interactive: fail closed IMMEDIATELY (deterministic — never
 *     wait for a human who cannot answer).
 *   • {@link PcscSecurityError} — re-thrown unchanged, immediately. The
 *     caller MUST hard-abort; this function NEVER returns a fallback.
 *   • {@link PcscBuildError} / any other error — re-thrown unchanged,
 *     immediately (a missing binding is NOT a missing reader; do not
 *     retry it). NEVER a software fallback.
 *
 * It returns ONLY a real channel or throws — there is no third
 * "degraded" return, by design.
 */
export async function connectPcscChannelWithPrompt(
  opts: ConnectWithPromptOptions,
): Promise<PcscChannel> {
  const connect = opts.connect ?? connectPcscChannel;
  const sleep = opts.sleep ?? realSleep;
  const now = opts.now ?? Date.now;
  const overall = opts.overallTimeoutMs ?? DEFAULT_OVERALL_TIMEOUT_MS;
  const poll = opts.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;

  const deadline = now() + overall;
  let prompted = false;
  let attempts = 0;

  for (;;) {
    attempts++;
    try {
      return await connect();
    } catch (e) {
      // ONLY the recoverable absent-hardware state is ever retried.
      // A security failure or the build-not-wired condition (or anything
      // unexpected) is fatal and re-thrown unchanged — NEVER a fallback.
      if (!isRecoverableNotReady(e)) {
        throw e;
      }

      // Non-interactive ⇒ fail closed deterministically on the FIRST
      // not-ready. Never hang waiting for a human who isn't there;
      // never silently downgrade. The caller must deliberately attach a
      // terminal (or use the documented file: lower-assurance path).
      if (!opts.interactive) {
        throw new CliError(
          "no YubiKey/PC/SC reader is ready and this is a " +
            "non-interactive context (piped/--yes/CI) — refusing to wait " +
            "for hardware that cannot be inserted here. Re-run attached " +
            "to a terminal, or use the documented file: lower-assurance " +
            "air-gapped/successor path. It never silently falls back.",
        );
      }

      // Bounded: never wait past the overall deadline. A token that
      // never appears fails closed rather than hang forever.
      if (now() >= deadline) {
        throw new CliError(
          `no YubiKey/PC/SC reader became ready within ` +
            `${Math.round(overall / 1000)}s (${attempts} attempts). ` +
            `Aborting rather than waiting indefinitely — re-run when the ` +
            `reader + token are connected. It never silently falls back.`,
        );
      }

      // Recoverable: prompt (once, then a quieter poll line) and wait
      // cooperatively before retrying. The message reflects the precise
      // recoverable reason the transport reported.
      if (!prompted) {
        opts.prompt(
          "Waiting for your YubiKey: " + e.message,
        );
        opts.prompt(
          "Insert the YubiKey into the reader (and tap it when it " +
            "lights, if prompted). Polling…",
        );
        prompted = true;
      } else {
        opts.prompt(`…still waiting for the YubiKey (attempt ${attempts}).`);
      }
      // Don't overshoot the deadline with the final sleep.
      const remaining = deadline - now();
      await sleep(Math.max(0, Math.min(poll, remaining)));
    }
  }
}
