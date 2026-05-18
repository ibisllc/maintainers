/**
 * PC/SC channel seam + the PIV transport built on the pure APDU codec.
 *
 * `PcscChannel` is the ONLY hardware-touching boundary: a single
 * `transmit(commandApdu) → responseApdu`. `pcscPivTransport` composes
 * the pure `piv-apdu` encoders/parsers with a channel into a
 * {@link PivTransport} (SELECT → VERIFY PIN → GENERAL AUTHENTICATE /
 * GENERATE), so the whole flow is unit-testable against a fake channel.
 *
 * `connectPcscChannel` opens a real channel via an OPTIONAL native
 * binding (`pcsclite`) loaded by dynamic import — NOT a mandatory
 * dependency (no package.json/lockfile entry; "bring the binding in the
 * ceremony build"). If the binding or a reader/token is absent it
 * fail-closes with a precise, human-readable reason and NEVER returns a
 * non-hardware fallback. The libpcsclite round-trip is verified only at
 * the YubiKey human gate.
 */

import { CliError } from "./args.js";
import type { PivTransport, PivKeyPolicy } from "./keysource.js";

// ---- Typed transport error taxonomy ------------------------------------
//
// [[feedback-no-hardware-assumptions]]: a check whose precondition you
// did NOT set up must not be treated as a conclusion. Three DISTINCT
// conditions, never conflated in one generic CliError:
//
//   1. PcscNotReadyError  — RECOVERABLE. No reader plugged in yet / no
//      token in the reader / not tapped yet. The caller's connect loop
//      MUST prompt + wait + poll + retry. This is the everyday
//      absent-hardware UX, NOT a failure.
//   2. PcscSecurityError  — FATAL. A real security failure: wrong key,
//      signature/PIN failure, tamper, a token that answered but is the
//      wrong identity. The caller MUST hard-abort and MUST NEVER fall
//      back to a weaker/in-process key. Fail-closed is a SECURITY
//      property only.
//   3. PcscBuildError     — FATAL (non-recoverable build condition). The
//      optional `pcsclite` binding is not installed / not wired in this
//      build. This is NOT "reader not plugged in yet" — retrying forever
//      cannot fix a missing binding. It stays fail-closed with its
//      precise message + the `file:`-lower-assurance pointer; the loop
//      MUST NOT retry it.
//
// All three extend CliError so existing `catch (e instanceof CliError)`
// dispatch + the exit-1 path keep working unchanged; the subclass is the
// machine-readable discriminator the connect loop branches on.

export class PcscNotReadyError extends CliError {
  /** Discriminant — a recoverable absent-hardware state (prompt+wait). */
  readonly recoverable = true as const;
  constructor(message: string) {
    super(message);
    this.name = "PcscNotReadyError";
  }
}

export class PcscSecurityError extends CliError {
  /** Discriminant — a real security failure: hard-abort, NEVER fall back. */
  readonly recoverable = false as const;
  readonly security = true as const;
  constructor(message: string) {
    super(message);
    this.name = "PcscSecurityError";
  }
}

export class PcscBuildError extends CliError {
  /** Discriminant — the optional binding is absent: non-recoverable,
   *  must NOT be retried (a missing binding is not a missing reader). */
  readonly recoverable = false as const;
  constructor(message: string) {
    super(message);
    this.name = "PcscBuildError";
  }
}

/** True iff `e` is the recoverable absent-hardware state — the ONLY
 *  condition the connect loop may prompt+wait+retry on. Everything else
 *  (security failure, build-not-wired, anything unexpected) is fatal. */
export function isRecoverableNotReady(e: unknown): e is PcscNotReadyError {
  return e instanceof PcscNotReadyError && e.recoverable === true;
}
import {
  commandApdu,
  encodeSelectPiv,
  encodeVerifyPin,
  encodeGeneralAuthenticateEd25519,
  encodeGenerateEd25519,
  encodeGetResponse,
  parseResponseApdu,
  isSuccess,
  statusWordReason,
  extractEd25519Signature,
  extractEd25519PublicKey,
  extractMetadataPublicKey,
} from "./piv-apdu.js";

/** The raw transport: send a command APDU, get the response APDU
 *  (data ‖ SW1 SW2). No PIV awareness — just bytes in / bytes out. */
export interface PcscChannel {
  transmit(commandApdu: Uint8Array): Promise<Uint8Array>;
}

// ---- Minimal structural typing for the OPTIONAL `pcsclite` binding -----
//
// `pcsclite` is NOT a declared dependency (no package.json/lockfile entry
// — it is brought in transiently for the ceremony build), so its types
// are not in scope at compile time. We narrow only the slice of its
// EventEmitter surface this binding drives (per the GATE-(A) plan
// doc-comment below). Everything is treated as untrusted/late-bound.

interface PcscReaderLike {
  name: string;
  state: number;
  readonly SCARD_STATE_PRESENT: number;
  readonly SCARD_STATE_EMPTY: number;
  readonly SCARD_SHARE_SHARED: number;
  on(event: "error", cb: (err: unknown) => void): void;
  on(event: "end", cb: () => void): void;
  on(event: "status", cb: (status: { state: number }) => void): void;
  connect(
    options: { share_mode: number },
    cb: (err: unknown, protocol: number) => void,
  ): void;
  disconnect(cb: (err: unknown) => void): void;
  transmit(
    data: Uint8Array,
    resLen: number,
    protocol: number,
    cb: (err: unknown, response: Uint8Array) => void,
  ): void;
  close(): void;
}

interface PcscLiteLike {
  on(event: "error", cb: (err: unknown) => void): void;
  on(event: "reader", cb: (reader: PcscReaderLike) => void): void;
  close(): void;
}

/**
 * Load the optional native binding. Injectable ONLY so the hermetic unit
 * suite can deterministically exercise the build-not-wired path (a forced
 * import failure) WITHOUT depending on whether `pcsclite` is physically
 * installed in the test environment — the gate must stay
 * hardware-independent and CI-safe. Production callers never pass this:
 * the default performs the real, indirect dynamic `import("pcsclite")`.
 */
export type PcscliteImporter = () => Promise<unknown>;

const realPcscliteImporter: PcscliteImporter = async () => {
  // Indirect specifier so bundlers/tsc don't hard-require the optional
  // module; absence is an expected, fail-closed BUILD condition.
  const moduleName = "pcsclite";
  return import(/* @vite-ignore */ moduleName);
};

/** A PC/SC error whose `.message` mentions a card/reader absence we treat
 *  as the recoverable not-ready state (the connect loop owns the retry). */
function looksLikeAbsentHardware(err: unknown): boolean {
  const msg =
    err instanceof Error
      ? err.message
      : typeof err === "string"
        ? err
        : err && typeof err === "object" && "message" in err
          ? String((err as { message: unknown }).message)
          : "";
  return /no.?smart.?card|removed.?card|SCARD_E_NO_SMARTCARD|SCARD_W_REMOVED_CARD|SCARD_E_NO_READERS|SCARD_E_READER_UNAVAILABLE|SCARD_E_NOT_READY|empty|not present|no reader/i.test(
    msg,
  );
}

function slotByte(slot: string): number {
  const n = parseInt(slot, 16);
  if (!/^[0-9a-fA-F]{2}$/.test(slot) || Number.isNaN(n)) {
    throw new CliError(`invalid PIV slot "${slot}" (expected 2 hex, e.g. 9c)`);
  }
  return n;
}

/**
 * Transmit, transparently following SW=61xx (GET RESPONSE) and SW=6Cxx
 * (re-issue with corrected Le) chaining, returning the assembled data
 * and final status word. Throws (PIN-free) on a non-success status.
 */
async function send(
  channel: PcscChannel,
  apdu: Uint8Array,
  what: string,
): Promise<Uint8Array> {
  let resp = parseResponseApdu(await channel.transmit(apdu));
  const acc: number[] = [...resp.data];
  // 6Cxx: wrong Le — the card tells us the exact length; re-issue.
  if (resp.sw1 === 0x6c) {
    const fixed = new Uint8Array(apdu);
    fixed[fixed.length - 1] = resp.sw2;
    resp = parseResponseApdu(await channel.transmit(fixed));
    acc.length = 0;
    acc.push(...resp.data);
  }
  // 61xx: more data — GET RESPONSE until 9000.
  while (resp.sw1 === 0x61) {
    resp = parseResponseApdu(
      await channel.transmit(encodeGetResponse(resp.sw2)),
    );
    acc.push(...resp.data);
  }
  if (!isSuccess(resp.sw)) {
    throw new CliError(`${what} failed: ${statusWordReason(resp.sw)}`);
  }
  return new Uint8Array(acc);
}

async function selectPiv(channel: PcscChannel): Promise<void> {
  await send(channel, encodeSelectPiv(), "SELECT PIV");
}

/** Build a {@link PivTransport} over a raw PC/SC channel. Pure
 *  composition of the tested APDU codec — no hidden I/O. */
export function pcscPivTransport(channel: PcscChannel): PivTransport {
  return {
    async getPublicKey(slot: string): Promise<string> {
      await selectPiv(channel);
      // Public read: ask the card for slot metadata (Yubico GET
      // METADATA, INS 0xF7) — no PIN, no touch. The response is a FLAT
      // top-level TLV sequence; the public key is under top-level tag
      // 0x04 → inner 0x86 (32 bytes for Ed25519). This is NOT the 7F49
      // GENERATE template — it has no 7F49 at all — so it MUST be parsed
      // with the dedicated metadata parser (verified byte-for-byte
      // against a real YubiKey 5.7.4 Ed25519 slot 9c).
      const data = await send(
        channel,
        commandApdu(0x00, 0xf7, 0x00, slotByte(slot), [], "max"),
        "read PIV public key",
      );
      return extractMetadataPublicKey(data);
    },

    async signEd25519(
      slot: string,
      pin: string,
      message: Uint8Array,
    ): Promise<string> {
      await selectPiv(channel);
      await send(channel, encodeVerifyPin(pin), "VERIFY PIN");
      const data = await send(
        channel,
        encodeGeneralAuthenticateEd25519(slotByte(slot), message),
        "GENERAL AUTHENTICATE (sign)",
      );
      return extractEd25519Signature(data);
    },

    async generateEd25519(
      slot: string,
      policy: PivKeyPolicy,
    ): Promise<string> {
      await selectPiv(channel);
      const data = await send(
        channel,
        encodeGenerateEd25519(slotByte(slot), {
          touch: policy.touch,
          pin: policy.pin,
        }),
        "GENERATE Ed25519",
      );
      return extractEd25519PublicKey(data);
    },
  };
}

/**
 * Open a real PC/SC channel via the OPTIONAL `pcsclite` binding. The
 * binding is loaded by dynamic import and is NOT declared as a
 * dependency: a build that wants hardware signing installs it (the
 * genesis-ceremony build). Absent binding ⇒ a precise {@link
 * PcscBuildError}. NEVER returns a software fallback (the `file:` hex
 * key is the only — explicitly lower-assurance — alternative, chosen by
 * the operator, never silently).
 *
 * --------------------------------------------------------------------
 * GATE-(A) NATIVE-BINDING IMPLEMENTATION PLAN — DO NOT WRITE THIS BLIND.
 * --------------------------------------------------------------------
 * The libpcsclite reader-enumeration → connect → APDU-transmit wiring is
 * the explicit hardware/human-gate increment. It is SECURITY-CRITICAL
 * native transport for the root of trust; per the program it is NEVER
 * written without the real reader + token present, and lands upstream
 * via a governed `maintainers` PR + re-pin (PR #1/#2 precedent). This
 * comment is the exact, reviewable API contract the (A) step implements
 * against so that step is mechanical, not invented under time pressure.
 *
 * `pcsclite` (npm `pcsclite`, libpcsclite-backed) API surface to use:
 *
 *   const pcsc = pcsclite();                  // EventEmitter
 *   pcsc.on('error', err => …)                // binding/daemon error
 *   pcsc.on('reader', reader => {             // a reader appeared
 *     reader.on('error', err => …)
 *     reader.on('status', status => {
 *       const changes = reader.state ^ status.state;
 *       if (changes & reader.SCARD_STATE_PRESENT
 *           && status.state & reader.SCARD_STATE_PRESENT) {
 *         // a card/token is now present in THIS reader
 *         reader.connect(
 *           { share_mode: reader.SCARD_SHARE_SHARED },
 *           (err, protocol) => {
 *             if (err) …                       // → classify (below)
 *             // protocol is T=0/T=1; pass straight to transmit
 *           });
 *       }
 *     });
 *   });
 *
 *   // The ONE hardware operation behind PcscChannel.transmit():
 *   reader.transmit(
 *     Buffer.from(commandApdu),   // Uint8Array → Buffer (no copy semantics change)
 *     264,                        // resLen: max R-APDU (256 data + 2 SW + slack)
 *     protocol,                   // from connect()'s callback
 *     (err, responseBuffer) => {
 *       if (err) …                // → classify (below)
 *       resolve(new Uint8Array(responseBuffer)); // Buffer → Uint8Array
 *     });
 *
 * Marshalling: command APDUs come from the PURE, already-tested
 * `piv-apdu` codec as `Uint8Array`; wrap with `Buffer.from(apdu)` on the
 * way out and `new Uint8Array(buf)` on the way back. The
 * SELECT/VERIFY/GENERAL-AUTHENTICATE/GENERATE/GET-RESPONSE sequencing,
 * 61xx/6Cxx chaining and all status-word interpretation already live in
 * `send()`/`pcscPivTransport()` above — the binding ONLY supplies the
 * raw `transmit`. SELECT the PIV applet with AID prefix
 * `A0 00 00 03 08` (`PIV_AID` in piv-apdu.ts) via `encodeSelectPiv()`;
 * the PUBLIC-KEY READ (GET METADATA, no PIN) is exercised FIRST as the
 * non-destructive round-trip proof before any VERIFY-PIN / GENERAL
 * AUTHENTICATE sign / GENERATE.
 *
 * Error classification the (A) wiring MUST apply (this is the whole
 * point of the typed taxonomy above — do not collapse it):
 *   • no reader event within the poll window, reader removed, NO card in
 *     the reader (SCARD_STATE_EMPTY), card removed mid-prompt, a
 *     "no smart card" / SCARD_E_NO_SMARTCARD / SCARD_W_REMOVED_CARD
 *     style transmit/connect error → throw {@link PcscNotReadyError}
 *     (RECOVERABLE — the connect loop prompts + waits + retries).
 *   • the token answered but the slot pubkey ≠ the expected signer, a
 *     VERIFY-PIN hard-fail / blocked PIN, a tamper/auth status word, any
 *     signature that fails to verify → throw {@link PcscSecurityError}
 *     (FATAL — hard-abort, NEVER fall back to a weaker/in-process key).
 *   • genuinely unexpected binding faults are NOT silently downgraded to
 *     "not ready": default to fatal (re-throw) unless positively
 *     identified as an absent-hardware condition.
 * The non-destructive public-key read is performed and verified FIRST.
 * Until that (A) increment lands WITH hardware, the path below stays
 * fail-closed and is NEVER bolted in unverified.
 */
export async function connectPcscChannel(
  importPcsclite: PcscliteImporter = realPcscliteImporter,
): Promise<PcscChannel> {
  // 1. Load the OPTIONAL binding. A failed import is a non-recoverable
  //    BUILD condition (NOT a recoverable "reader not plugged in yet" —
  //    a missing binding cannot be fixed by waiting, so the connect loop
  //    must NOT retry it). The importer is injectable ONLY so the
  //    hermetic unit suite drives this path deterministically without
  //    depending on physical absence of the binding.
  let mod: unknown;
  try {
    mod = await importPcsclite();
  } catch {
    throw new PcscBuildError(
      "the native PIV/PC/SC transport is not wired in this build: the " +
        "optional 'pcsclite' binding is not installed. Use the genesis-" +
        "ceremony build (which bundles it) and a connected reader, or " +
        "fall back to a file: hex key (lower assurance, air-gapped/" +
        "successor only — docs/ca-operations.md). It never silently " +
        "falls back.",
    );
  }
  // ESM-vs-CJS interop: `pcsclite` is a CJS module exporting a factory
  // function; under dynamic import it may surface as the function itself
  // or on `.default`. A binding that is present but not a callable
  // factory is also a non-recoverable BUILD condition.
  const factory: unknown =
    typeof mod === "function"
      ? mod
      : mod && typeof mod === "object" && "default" in mod
        ? (mod as { default: unknown }).default
        : undefined;
  if (typeof factory !== "function") {
    throw new PcscBuildError(
      "the native PIV/PC/SC transport is not wired in this build: the " +
        "'pcsclite' binding loaded but did not expose a callable factory. " +
        "Use the genesis-ceremony build and a connected reader, or a " +
        "file: hex key (lower assurance). It never silently falls back.",
    );
  }

  // 2. Open the PCSC context (EventEmitter). A binding/daemon-level
  //    error before any reader is enumerated is treated as recoverable
  //    only when it positively looks like an absent-hardware condition;
  //    otherwise it is fatal (we never downgrade an unexpected fault).
  let pcsc: PcscLiteLike;
  try {
    pcsc = (factory as () => PcscLiteLike)();
  } catch (err) {
    if (looksLikeAbsentHardware(err)) {
      throw new PcscNotReadyError(
        "no PC/SC reader is available yet (the PC/SC subsystem reported " +
          "no reader). Insert the YubiKey/reader and it will be retried.",
      );
    }
    throw err;
  }

  // 3. ONE attempt: enumerate readers, wait (bounded, cooperative — NOT
  //    a busy loop) for a reader with a card PRESENT, connect SHARED,
  //    and resolve a PcscChannel. ANY absent/empty/removed condition →
  //    PcscNotReadyError (the connectPcscChannelWithPrompt loop OWNS the
  //    prompt + wait + retry — we do NOT duplicate it here, just make
  //    ONE bounded attempt and surface the recoverable state). The
  //    handle is always torn down on every path; a card handle is never
  //    leaked.
  const ATTEMPT_BUDGET_MS = 8_000;

  return await new Promise<PcscChannel>((resolve, reject) => {
    let settled = false;
    let activeReader: PcscReaderLike | null = null;
    let connectedReader: PcscReaderLike | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const teardownContext = () => {
      try {
        pcsc.close();
      } catch {
        /* best-effort: never mask the original outcome */
      }
    };

    const disconnectReader = (r: PcscReaderLike, done: () => void) => {
      try {
        r.disconnect((_err: unknown) => {
          try {
            r.close();
          } catch {
            /* ignore */
          }
          done();
        });
      } catch {
        try {
          r.close();
        } catch {
          /* ignore */
        }
        done();
      }
    };

    const finishOk = (channel: PcscChannel) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(channel);
    };

    const finishErr = (e: unknown) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      // Clean teardown on EVERY error path: never leak a connected card
      // handle. Disconnect the connected reader (if any), then close the
      // PCSC context, then reject with the (classified) error.
      const after = () => {
        teardownContext();
        reject(e);
      };
      if (connectedReader) {
        disconnectReader(connectedReader, after);
      } else {
        after();
      }
    };

    // Bounded: this is ONE attempt. If no reader+card becomes PRESENT
    // within the budget, surface the RECOVERABLE not-ready state so the
    // caller's loop prompts + waits + retries (it is NOT a failure).
    timer = setTimeout(() => {
      finishErr(
        new PcscNotReadyError(
          "no YubiKey/PC/SC reader with a card became present yet. " +
            "Insert the YubiKey into the reader; it will be retried.",
        ),
      );
    }, ATTEMPT_BUDGET_MS);
    if (typeof (timer as { unref?: () => void }).unref === "function") {
      (timer as { unref: () => void }).unref();
    }

    pcsc.on("error", (err: unknown) => {
      // A context-level error: recoverable only if it positively looks
      // like absent hardware; otherwise fatal (never downgraded).
      if (looksLikeAbsentHardware(err)) {
        finishErr(
          new PcscNotReadyError(
            "the PC/SC subsystem reported no reader/card yet — insert the " +
              "YubiKey; it will be retried.",
          ),
        );
      } else {
        finishErr(
          err instanceof Error ? err : new Error(String(err)),
        );
      }
    });

    pcsc.on("reader", (reader: PcscReaderLike) => {
      // First usable reader wins; ignore any extra readers for this
      // single attempt (a single physical token services one read).
      if (activeReader || settled) return;
      activeReader = reader;

      reader.on("error", (err: unknown) => {
        if (looksLikeAbsentHardware(err)) {
          finishErr(
            new PcscNotReadyError(
              "the reader reported no card yet — insert the YubiKey; it " +
                "will be retried.",
            ),
          );
        } else {
          finishErr(err instanceof Error ? err : new Error(String(err)));
        }
      });

      reader.on("end", () => {
        // Reader was removed mid-attempt → recoverable not-ready.
        finishErr(
          new PcscNotReadyError(
            "the PC/SC reader was removed — re-insert it; it will be " +
              "retried.",
          ),
        );
      });

      const onPresent = () => {
        reader.connect(
          { share_mode: reader.SCARD_SHARE_SHARED },
          (err: unknown, protocol: number) => {
            if (settled) return;
            if (err) {
              // connect failed: classify. An absent/removed card here is
              // recoverable; anything else is fatal.
              if (looksLikeAbsentHardware(err)) {
                finishErr(
                  new PcscNotReadyError(
                    "the card was not ready for connect (likely removed) " +
                      "— re-insert the YubiKey; it will be retried.",
                  ),
                );
              } else {
                finishErr(
                  err instanceof Error ? err : new Error(String(err)),
                );
              }
              return;
            }
            connectedReader = reader;
            // The single hardware operation behind PcscChannel.transmit:
            // marshal Uint8Array → Buffer out, Buffer → Uint8Array back.
            // The SELECT/VERIFY/GA/GENERATE sequencing + 61xx/6Cxx
            // chaining + status-word interpretation all live in
            // send()/pcscPivTransport — the binding ONLY moves bytes.
            const channel: PcscChannel = {
              transmit(commandBytes: Uint8Array): Promise<Uint8Array> {
                return new Promise<Uint8Array>((res, rej) => {
                  if (settled && !connectedReader) {
                    rej(
                      new PcscNotReadyError(
                        "the PC/SC channel was already torn down.",
                      ),
                    );
                    return;
                  }
                  try {
                    reader.transmit(
                      // copy into a fresh Buffer-compatible Uint8Array;
                      // never hand the codec's buffer to native code.
                      Uint8Array.from(commandBytes),
                      // max R-APDU: 256 data + 2 SW + slack.
                      264,
                      protocol,
                      (txErr: unknown, response: unknown) => {
                        if (txErr) {
                          // A card removed mid-op is recoverable; any
                          // other transmit fault is fatal (never
                          // silently downgraded).
                          rej(
                            looksLikeAbsentHardware(txErr)
                              ? new PcscNotReadyError(
                                  "the card was removed during a PC/SC " +
                                    "exchange — re-insert it; it will be " +
                                    "retried.",
                                )
                              : txErr instanceof Error
                                ? txErr
                                : new Error(String(txErr)),
                          );
                          return;
                        }
                        if (
                          !response ||
                          typeof (response as { length?: unknown })
                            .length !== "number"
                        ) {
                          rej(
                            new PcscSecurityError(
                              "the PC/SC reader returned an empty/invalid " +
                                "response APDU — refusing to proceed on " +
                                "the root-of-trust path.",
                            ),
                          );
                          return;
                        }
                        res(
                          Uint8Array.from(response as ArrayLike<number>),
                        );
                      },
                    );
                  } catch (syncErr) {
                    rej(
                      syncErr instanceof Error
                        ? syncErr
                        : new Error(String(syncErr)),
                    );
                  }
                });
              },
            };
            finishOk(channel);
          },
        );
      };

      reader.on("status", (status: { state: number }) => {
        if (settled || connectedReader) return;
        const changes = reader.state ^ status.state;
        reader.state = status.state;
        if (
          changes & reader.SCARD_STATE_PRESENT &&
          status.state & reader.SCARD_STATE_PRESENT
        ) {
          onPresent();
        }
      });
    });
  });
}
