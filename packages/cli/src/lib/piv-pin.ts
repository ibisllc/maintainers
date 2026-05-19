/**
 * The secure interactive PIV PIN reader — the concrete
 * {@link PivPinProvider} the CLI's `defaultEnv` wires into every real
 * `yubikey-piv:` signing path (`keysource.ts` `loadSigner` calls it once
 * per on-token signature for the VERIFY-PIN APDU).
 *
 * Security contract (the error message in `loadSigner` states it; this
 * module is the implementation that honors it EXACTLY):
 *
 *   • The PIN is read INTERACTIVELY from the controlling terminal with
 *     echo DISABLED (getpass-style). It is NEVER read from argv, env
 *     vars, or any file; NEVER logged / echoed / written to any sink;
 *     NEVER placed in an error message or stack. It exists only
 *     transiently, is handed to the VERIFY-PIN path, then best-effort
 *     dropped (the binding holds no reference).
 *
 *   • Non-interactive ⇒ DETERMINISTIC fail-closed. A piped / CI /
 *     `--yes` / no-`/dev/tty` context throws a precise {@link CliError}
 *     (same taxonomy/voice as {@link connectPcscChannelWithPrompt}'s
 *     non-interactive abort) — it does NOT hang waiting for a human who
 *     isn't there and does NOT fabricate a PIN. (`--yes` only ever
 *     skipped the typed *confirm*; the PIN is ALWAYS required for an
 *     on-token signature — that is unchanged here.)
 *
 *   • A wrong PIN is surfaced by the transport as a {@link
 *     PcscSecurityError} (fatal, never a fallback). This reader does NOT
 *     loop-retry on its own — auto-retrying would silently burn the
 *     YubiKey's 3-try PIN counter. One prompt per invocation that needs
 *     it; a bad PIN fails closed clearly. With `--pin-policy ONCE` the
 *     PIV session caches the PIN, so a single ceremony typically prompts
 *     once even across multiple signatures.
 *
 * Every effect (the TTY device, the prompt sink, interactivity) is
 * injected so the whole reader is exercised hermetically with ZERO real
 * TTY/token/PIN — exactly like `piv-connect.ts`. Production callers use
 * {@link pivPinFromTty} with no overrides.
 */

import * as fs from "node:fs";
import * as readline from "node:readline";
import { CliError } from "./args.js";

/**
 * A minimal, readable+writable terminal device handle. Production opens
 * `/dev/tty` (the real controlling terminal — NOT stdin, which may be a
 * pipe). Tests inject a fake duplex so no real TTY is touched.
 */
export interface TtyDevice {
  /** Readable side: lines the human types (echo is suppressed by us). */
  input: NodeJS.ReadableStream;
  /** Writable side: where the no-echo prompt itself is written. */
  output: NodeJS.WritableStream;
  /** Best-effort close of the underlying device handle. */
  close(): void;
}

/**
 * Open the real controlling terminal for a no-echo prompt. Uses
 * `/dev/tty` deliberately: it is the operator's terminal even when
 * stdin/stdout are redirected, and its absence is precisely the
 * non-interactive condition we must fail closed on (never hang). Returns
 * `null` (not throw) when there is no controlling terminal — the caller
 * turns that into the deterministic fail-closed CliError.
 */
export function openControllingTty(): TtyDevice | null {
  let fd: number;
  try {
    fd = fs.openSync("/dev/tty", "r+");
  } catch {
    return null;
  }
  let closed = false;
  const input = fs.createReadStream("", { fd, autoClose: false });
  const output = fs.createWriteStream("", { fd, autoClose: false });
  return {
    input,
    output,
    close() {
      if (closed) return;
      closed = true;
      // Best-effort: never mask the real outcome on teardown.
      try {
        input.destroy();
      } catch {
        /* ignore */
      }
      try {
        output.destroy();
      } catch {
        /* ignore */
      }
      try {
        fs.closeSync(fd);
      } catch {
        /* ignore */
      }
    },
  };
}

export interface PivPinPromptOptions {
  /** True iff attached to an interactive terminal. Non-interactive ⇒
   *  fail closed immediately (deterministic — never hang, never
   *  fabricate). Default: derived from `process.stdin.isTTY`, mirroring
   *  `defaultEnv`'s `pivTransport` interactivity. */
  interactive?: boolean;
  /** Opens the controlling terminal (default: {@link openControllingTty}).
   *  Injected so the reader is unit-testable without a real TTY. */
  openTty?: () => TtyDevice | null;
  /** The prompt label written (no-echo) to the terminal. NEVER contains
   *  a secret — it is only the "Enter … PIN:" guidance. */
  promptLabel?: string;
}

const DEFAULT_PROMPT_LABEL = "Enter YubiKey PIV PIN: ";

/**
 * Build a concrete {@link PivPinProvider}: a function that, each time the
 * signing path needs the PIN, prompts the controlling terminal with echo
 * disabled, reads ONE line, and resolves it. Throws a precise
 * fail-closed {@link CliError} in any non-interactive context BEFORE
 * touching a device (never hangs, never fabricates). The returned PIN is
 * not retained by this module after it is returned to the caller; the
 * transient line buffer is best-effort cleared.
 */
export function pivPinFromTty(
  opts: PivPinPromptOptions = {},
): () => Promise<string> {
  const interactive = opts.interactive ?? Boolean(process.stdin.isTTY);
  const openTty = opts.openTty ?? openControllingTty;
  const label = opts.promptLabel ?? DEFAULT_PROMPT_LABEL;

  return async function readPivPin(): Promise<string> {
    // Non-interactive ⇒ deterministic fail-closed, BEFORE opening any
    // device. Same voice/taxonomy as connectPcscChannelWithPrompt's
    // non-interactive abort: never wait for a human who cannot answer,
    // never silently downgrade. The PIN is ALWAYS required for an
    // on-token signature (--yes never skipped it; it only ever skipped
    // the typed confirm — unchanged).
    if (!interactive) {
      throw new CliError(
        "the YubiKey PIV PIN must be entered interactively but this is a " +
          "non-interactive context (piped/--yes/CI/no controlling " +
          "terminal) — refusing to read a PIN from anywhere other than a " +
          "no-echo terminal prompt (it is never read from argv/env/a file " +
          "and never logged). Re-run attached to a real terminal. It " +
          "never silently falls back.",
      );
    }

    const tty = openTty();
    if (!tty) {
      // No controlling terminal even though stdin claimed TTY-ness
      // (rare: detached/closed /dev/tty). Same deterministic
      // fail-closed — never hang, never fabricate.
      throw new CliError(
        "no controlling terminal (/dev/tty) is available to securely " +
          "prompt for the YubiKey PIV PIN — refusing to read the PIN from " +
          "argv/env/a file or to proceed without it. Re-run attached to a " +
          "real terminal. It never silently falls back.",
      );
    }

    try {
      return await new Promise<string>((resolve, reject) => {
        const rl = readline.createInterface({
          input: tty.input,
          output: tty.output,
          terminal: true,
        });

        // No-echo: intercept the readline interface's own write so each
        // keystroke the human types is NOT echoed back to the terminal.
        // The prompt label itself is written once, directly, so the
        // operator still sees what is being asked. This is the
        // getpass-style mask: input hidden, prompt visible.
        const rlMutable = rl as unknown as {
          _writeToOutput?: (chunk: string) => void;
        };
        let labelWritten = false;
        rlMutable._writeToOutput = (chunk: string) => {
          // Write ONLY the prompt label (once); swallow every echo of
          // typed characters. Never write the typed PIN anywhere.
          if (!labelWritten && chunk.includes(label)) {
            tty.output.write(label);
            labelWritten = true;
          }
        };

        let settled = false;
        const finish = (fn: () => void) => {
          if (settled) return;
          settled = true;
          rl.close();
          // Terminate the masked line on the terminal so the next
          // output starts cleanly (the newline the human's Enter would
          // normally have echoed, which we suppressed).
          try {
            tty.output.write("\n");
          } catch {
            /* ignore */
          }
          fn();
        };

        rl.question(label, (answer: string) => {
          // Hand the PIN straight back to the caller; do NOT log it,
          // store it, or include it in any message. Best-effort clear
          // the transient local reference (JS strings are immutable, so
          // this only drops our handle — the binding keeps no copy).
          const pin = answer;
          answer = "";
          finish(() => resolve(pin));
        });

        rl.on("error", (err: unknown) => {
          // Never include any typed bytes in the error — only the
          // device-level failure reason.
          finish(() =>
            reject(
              err instanceof CliError
                ? err
                : new CliError(
                    "failed to read the YubiKey PIV PIN from the " +
                      "controlling terminal: " +
                      (err instanceof Error ? err.message : String(err)),
                  ),
            ),
          );
        });
      });
    } finally {
      tty.close();
    }
  };
}
