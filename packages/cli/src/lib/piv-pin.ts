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
 *     echo DISABLED at the OS level (getpass-style). It is NEVER read
 *     from argv, env vars, or any file; NEVER logged / echoed / written
 *     to any sink; NEVER placed in an error message or stack. It exists
 *     only transiently, is handed to the VERIFY-PIN path, then
 *     best-effort dropped (the binding holds no reference).
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
 * How no-echo is actually achieved (this is the part the prior
 * implementation got WRONG): terminal echo is an OS-level TTY
 * line-discipline property (termios `ECHO`), NOT something `readline`'s
 * output writes control. We therefore put the controlling terminal into
 * RAW mode (`input.setRawMode(true)`) so the kernel does not echo
 * keystrokes, read bytes ourselves, accumulate the line until Enter,
 * handle Backspace/Ctrl-C/EOF explicitly, write NOTHING for typed
 * characters, and ALWAYS restore cooked mode in a `finally`. A single
 * file descriptor is owned and closed exactly once (idempotent,
 * exception-safe); every stream gets an `'error'` handler so a teardown
 * failure can never surface as an unhandled `'error'` event or crash the
 * process or mask the real signing outcome.
 *
 * Every effect (the TTY device, the prompt sink, interactivity) is
 * injected so the whole reader is exercised hermetically with ZERO real
 * TTY/token/PIN — exactly like `piv-connect.ts`. Production callers use
 * {@link pivPinFromTty} with no overrides.
 */

import * as fs from "node:fs";
import * as tty from "node:tty";
import { CliError } from "./args.js";

/**
 * A raw-capable, readable+writable controlling-terminal handle.
 * Production opens `/dev/tty` (the real controlling terminal — NOT
 * stdin, which may be a pipe) and constructs a {@link tty.ReadStream}
 * for it so OS-level raw mode (and thus echo suppression) is genuinely
 * available. Tests inject a fake that models raw-mode byte input plus a
 * `setRawMode` spy so no real TTY is touched.
 */
export interface TtyDevice {
  /**
   * Readable side: raw bytes the human types. In raw mode the kernel
   * does NOT echo these and delivers them unbuffered — we read and
   * accumulate them ourselves.
   */
  input: NodeJS.ReadableStream & {
    setRawMode?: (mode: boolean) => unknown;
    isRaw?: boolean;
  };
  /** Writable side: where the (no-secret) prompt label is written. */
  output: NodeJS.WritableStream;
  /**
   * Best-effort, idempotent, exception-safe teardown of the underlying
   * device handle. Restoring cooked mode is the reader's job (it owns
   * the raw-mode transition); this only releases the fd. Calling it more
   * than once, or after a partial failure, must never throw.
   */
  close(): void;
}

/**
 * Open the real controlling terminal for a no-echo prompt. Uses
 * `/dev/tty` deliberately: it is the operator's terminal even when
 * stdin/stdout are redirected, and its absence is precisely the
 * non-interactive condition we must fail closed on (never hang). Returns
 * `null` (not throw) when there is no controlling terminal — the caller
 * turns that into the deterministic fail-closed CliError.
 *
 * A SINGLE fd is opened and a {@link tty.ReadStream} / {@link
 * tty.WriteStream} pair is constructed over it with `autoClose:false` so
 * destroying the streams does NOT touch the fd. The fd is closed exactly
 * once, guarded by a `closed` flag, with every error swallowed. Every
 * stream also gets a no-op `'error'` listener so a destroy/EBADF error
 * on teardown can never become an unhandled `'error'` event.
 */
export function openControllingTty(): TtyDevice | null {
  let fd: number;
  try {
    fd = fs.openSync("/dev/tty", "r+");
  } catch {
    return null;
  }

  let input: tty.ReadStream;
  let output: tty.WriteStream;
  try {
    input = new tty.ReadStream(fd);
    output = new tty.WriteStream(fd);
  } catch {
    // Constructing the tty streams failed (e.g. fd is not a real TTY).
    // Release the fd and present as "no controlling terminal".
    try {
      fs.closeSync(fd);
    } catch {
      /* ignore */
    }
    return null;
  }

  // CRITICAL: a teardown/EBADF/destroy error must NEVER surface as an
  // unhandled 'error' event (that crashed the process in the prior
  // impl). Attach a swallowing handler to BOTH streams up front.
  input.on("error", () => {
    /* swallow: teardown/EBADF must never crash or mask the outcome */
  });
  output.on("error", () => {
    /* swallow */
  });

  let closed = false;
  return {
    input,
    output,
    close() {
      if (closed) return;
      closed = true;
      // Best-effort: never mask the real signing outcome on teardown,
      // never let any of these throw. The fd is the single owned
      // resource — close it exactly once (the `closed` guard above) and
      // swallow EBADF/anything. Destroying the streams must not autoClose
      // the fd (autoClose:false is the tty.*Stream default for an
      // explicit fd; we still guard the single closeSync).
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
        /* ignore — fd may already be gone; closing twice is not fatal */
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
 * Read ONE line of raw bytes from a raw-mode terminal with NO echo.
 *
 * The terminal is put into raw mode by the caller; here we consume
 * `data` chunks and build the line ourselves:
 *
 *   • `\r` or `\n`  → line complete (resolve the accumulated string).
 *   • 0x7f / 0x08    → Backspace/DEL: drop the last char (no visible
 *                      erase — we never wrote anything to erase).
 *   • 0x03           → Ctrl-C: abort with a clean CliError.
 *   • 0x04           → Ctrl-D / EOF on an empty line: abort cleanly.
 *   • 'end'/'close'  → stream EOF: abort (never hang).
 *
 * NOTHING typed is ever written back to `output` — in raw mode WE own
 * all output and we deliberately emit nothing for keystrokes (not even
 * `*`), so the PIN cannot be reconstructed from the terminal sink.
 */
function readLineNoEcho(
  input: NodeJS.ReadableStream,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    let buf = "";
    let settled = false;

    const cleanup = () => {
      input.removeListener("data", onData);
      input.removeListener("end", onEnd);
      input.removeListener("close", onEnd);
      input.removeListener("error", onError);
    };
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      cleanup();
      fn();
    };

    const onData = (chunk: Buffer | string) => {
      const s =
        typeof chunk === "string" ? chunk : chunk.toString("utf8");
      for (let i = 0; i < s.length; i++) {
        const ch = s[i]!;
        const code = ch.charCodeAt(0);
        if (ch === "\r" || ch === "\n") {
          const line = buf;
          // Drop our transient handle to the bytes (JS strings are
          // immutable; this only releases our reference).
          buf = "";
          done(() => resolve(line));
          return;
        }
        if (code === 0x7f || code === 0x08) {
          // Backspace / DEL — edit the in-memory buffer only.
          if (buf.length > 0) buf = buf.slice(0, -1);
          continue;
        }
        if (code === 0x03) {
          // Ctrl-C — clean abort. Never include any typed bytes.
          buf = "";
          done(() =>
            reject(
              new CliError(
                "YubiKey PIV PIN entry was cancelled (Ctrl-C) — no PIN " +
                  "was read and nothing was signed. Re-run when ready.",
              ),
            ),
          );
          return;
        }
        if (code === 0x04) {
          // Ctrl-D / EOF — clean abort (never hang, never fabricate).
          buf = "";
          done(() =>
            reject(
              new CliError(
                "end-of-input while reading the YubiKey PIV PIN (Ctrl-D/" +
                  "EOF) — no PIN was read and nothing was signed. Re-run " +
                  "attached to a real terminal.",
              ),
            ),
          );
          return;
        }
        // Any other byte is part of the PIN. Accumulate; echo NOTHING.
        buf += ch;
      }
    };

    const onEnd = () => {
      // Stream closed before Enter — treat as EOF, fail closed.
      buf = "";
      done(() =>
        reject(
          new CliError(
            "the controlling terminal closed while reading the YubiKey " +
              "PIV PIN — no PIN was read and nothing was signed. Re-run " +
              "attached to a real terminal.",
          ),
        ),
      );
    };

    const onError = (err: unknown) => {
      // The device died mid-read (vanished/destroyed/EBADF). Settle the
      // read with a CLEAN fail-closed CliError carrying ONLY the
      // device-level reason — never any typed bytes, and never let this
      // become an unhandled 'error' (which crashed the prior impl). This
      // also guarantees the read never hangs if the TTY disappears.
      buf = "";
      done(() =>
        reject(
          new CliError(
            "failed to read the YubiKey PIV PIN from the controlling " +
              "terminal: " +
              (err instanceof Error ? err.message : String(err)),
          ),
        ),
      );
    };

    input.on("data", onData);
    input.once("end", onEnd);
    input.once("close", onEnd);
    input.on("error", onError);
  });
}

/**
 * Build a concrete {@link PivPinProvider}: a function that, each time the
 * signing path needs the PIN, prompts the controlling terminal with echo
 * disabled AT THE OS LEVEL (raw mode), reads ONE line, and resolves it.
 * Throws a precise fail-closed {@link CliError} in any non-interactive
 * context BEFORE touching a device (never hangs, never fabricates). The
 * returned PIN is not retained by this module after it is returned to
 * the caller; the transient line buffer is best-effort cleared.
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

    const ttyDev = openTty();
    if (!ttyDev) {
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

    const input = ttyDev.input;
    let rawEnabled = false;

    // Restore cooked mode + release the device. Best-effort and
    // exception-safe: a teardown failure must NEVER crash the process or
    // mask the real signing outcome. Idempotent on close() via the
    // device's own `closed` guard.
    const restoreAndClose = () => {
      if (rawEnabled && typeof input.setRawMode === "function") {
        try {
          input.setRawMode(false);
        } catch {
          /* ignore — best-effort restore of cooked mode */
        }
        rawEnabled = false;
      }
      try {
        ttyDev.close();
      } catch {
        /* ignore — single-close is guarded inside close() */
      }
    };

    try {
      // Write ONLY the no-secret prompt label. (Done before raw mode so
      // it cannot interleave with our byte reads; nothing typed is ever
      // written, so there is no need to write anything after this.)
      try {
        ttyDev.output.write(label);
      } catch {
        /* a prompt-write failure still proceeds to the read; the read's
           own fail-closed path will surface a clean device error */
      }

      // OS-LEVEL no-echo: put the terminal into raw mode so the kernel
      // does not echo keystrokes. This is the actual fix — readline's
      // _writeToOutput could never disable termios ECHO.
      if (typeof input.setRawMode !== "function") {
        throw new CliError(
          "the controlling terminal does not support disabling echo " +
            "(no raw mode) — refusing to prompt for the YubiKey PIV PIN " +
            "where it could be echoed. Re-run attached to a real " +
            "terminal. It never silently falls back.",
        );
      }
      input.setRawMode(true);
      rawEnabled = true;
      if (typeof (input as { resume?: () => void }).resume === "function") {
        (input as { resume: () => void }).resume();
      }

      const pin = await readLineNoEcho(input);

      // Terminate the (suppressed) input line on the terminal so the
      // next output starts on a fresh line — this writes only a newline,
      // never any typed byte.
      try {
        ttyDev.output.write("\n");
      } catch {
        /* ignore */
      }

      // Hand the PIN straight back to the caller; do NOT log it, store
      // it, or include it in any message. The local `pin` ref is the
      // only handle and it is returned immediately (the binding keeps no
      // copy).
      return pin;
    } catch (err) {
      // Never include any typed bytes in the error — only the
      // device-level / control reason. CliError (Ctrl-C, EOF, no-raw,
      // non-interactive) passes through verbatim.
      if (err instanceof CliError) throw err;
      throw new CliError(
        "failed to read the YubiKey PIV PIN from the controlling " +
          "terminal: " +
          (err instanceof Error ? err.message : String(err)),
      );
    } finally {
      restoreAndClose();
    }
  };
}

/**
 * Hidden, NON-SECRET self-test of the exact no-echo PIN-read path, so a
 * human can re-trust the IO in a REAL terminal WITHOUT ever typing a
 * real PIN. It drives {@link pivPinFromTty} (same code path), then
 * prints ONLY a verdict + the entered byte length + a SHA-256 hex of the
 * entered bytes — NEVER the value itself.
 *
 * Exposed via the hidden `selftest-pin` command (see `index.ts`). It is
 * never wired into any signing path and the hermetic test suite never
 * triggers a real prompt (it injects a fake TTY).
 */
export async function runPivPinSelfTest(
  println: (s: string) => void,
  printerr: (s: string) => void,
  opts: PivPinPromptOptions = {},
): Promise<number> {
  println(
    "PIV PIN reader self-test — type a DUMMY value, NOT your real PIN.",
  );
  println(
    "(e.g. type:  test123  then press Enter. Nothing you type should " +
      "appear on screen.)",
  );

  let entered: string;
  try {
    const provider = pivPinFromTty(opts);
    entered = await provider();
  } catch (err) {
    printerr(
      "SELFTEST FAIL: the reader aborted before completing: " +
        (err instanceof CliError
          ? err.message
          : err instanceof Error
            ? err.message
            : String(err)),
    );
    return 1;
  }

  const { createHash } = await import("node:crypto");
  const len = Buffer.byteLength(entered, "utf8");
  const sha = createHash("sha256").update(entered, "utf8").digest("hex");
  // Drop the local handle to the dummy bytes immediately.
  entered = "";

  if (len === 0) {
    printerr(
      "SELFTEST FAIL: empty input — nothing was read. (Did you press " +
        "Enter without typing the dummy?)",
    );
    return 1;
  }

  println("");
  println("SELFTEST PASS:");
  println(`  • the prompt was shown and input was read with NO echo`);
  println(`  • the process did NOT crash on teardown (clean exit)`);
  println(`  • entered byte length : ${len}`);
  println(`  • entered sha256      : ${sha}`);
  println(
    "  (the dummy itself is never printed; verify nothing you typed " +
      "appeared above)",
  );
  return 0;
}
