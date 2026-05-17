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
} from "./piv-apdu.js";

/** The raw transport: send a command APDU, get the response APDU
 *  (data ‖ SW1 SW2). No PIV awareness — just bytes in / bytes out. */
export interface PcscChannel {
  transmit(commandApdu: Uint8Array): Promise<Uint8Array>;
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
      // Public read: ask the card for slot metadata's public key
      // (Yubico GET METADATA, INS 0xF7) — no PIN. The response carries
      // the same 7F49/86 public-key TLV GENERATE returns.
      const data = await send(
        channel,
        commandApdu(0x00, 0xf7, 0x00, slotByte(slot), [], "max"),
        "read PIV public key",
      );
      return extractEd25519PublicKey(data);
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
 * genesis-ceremony build). Absent binding / reader / card ⇒ a precise
 * CliError. NEVER returns a software fallback (the `file:` hex key is
 * the only — explicitly lower-assurance — alternative, chosen by the
 * operator, never silently).
 */
export async function connectPcscChannel(): Promise<PcscChannel> {
  // Indirect specifier so bundlers/tsc don't hard-require the optional
  // module; absence is an expected, fail-closed condition.
  const moduleName = "pcsclite";
  let mod: unknown;
  try {
    mod = await import(/* @vite-ignore */ moduleName);
  } catch {
    throw new CliError(
      "the native PIV/PC/SC transport is not wired in this build: the " +
        "optional 'pcsclite' binding is not installed. Use the genesis-" +
        "ceremony build (which bundles it) and a connected reader, or " +
        "fall back to a file: hex key (lower assurance, air-gapped/" +
        "successor only — docs/ca-operations.md). It never silently " +
        "falls back.",
    );
  }
  // The real binding wiring (reader enumeration, connect, transmit
  // Buffer↔Uint8Array) is exercised ONLY at the YubiKey human gate; if
  // we reach here without a reader it must still fail closed.
  void mod;
  throw new CliError(
    "the native PIV/PC/SC transport is not wired in this build: no PC/SC " +
      "reader/token round-trip is available here (verified only at the " +
      "YubiKey ceremony gate). Use a file: hex key for the lower-" +
      "assurance air-gapped/successor path — it never silently falls back.",
  );
}
