/**
 * PIV APDU codec — PURE functions, fully unit-testable WITHOUT hardware.
 *
 * Encodes the four APDUs the maintainer ceremonies need and parses the
 * responses, per NIST SP 800-73-4 + the Yubico PIV Ed25519 extension
 * (YubiKey 5, fw ≥ 5.7 — §11.1):
 *
 *   • SELECT PIV application   (AID prefix A0 00 00 03 08)
 *   • VERIFY PIN               (key ref 0x80, 8-byte 0xFF-padded)
 *   • GENERAL AUTHENTICATE     (Ed25519 sign over the raw message —
 *                               pure RFC-8032, byte-identical to
 *                               ed25519.sign; NO caller pre-hash)
 *   • GENERATE asymmetric key  (Ed25519 on-token, genesis)
 *
 * A PIV-Ed25519 signature over the canonical bytes is byte-identical to
 * the in-process path — ZERO protocol/wire/spec delta. This module does
 * NO I/O; the PC/SC round-trip is layered on top (`piv-pcsc.ts`) and is
 * the only thing the YubiKey human gate exercises. Fail-closed: malformed
 * responses throw, never guess.
 */

import { CliError } from "./args.js";

/** PIV application AID prefix. A partial-AID SELECT (P1=0x04) on this
 *  RID/PIX prefix selects the PIV applet on a YubiKey. */
export const PIV_AID = [0xa0, 0x00, 0x00, 0x03, 0x08] as const;

/** Key reference 0x80 = the PIV PIN (SP 800-73-4 §3.2.1). */
export const PIV_PIN_REF = 0x80;

/** Algorithm reference for Ed25519 (Yubico PIV Ed25519 extension). */
export const ALG_ED25519 = 0xe0;

/** Yubico key-policy byte values (PIN policy tag 0xAA / touch 0xAB). */
const PIN_POLICY: Record<string, number> = { never: 0x01, once: 0x02, always: 0x03 };
const TOUCH_POLICY: Record<string, number> = { never: 0x01, always: 0x02, cached: 0x03 };

function u8(parts: number[]): Uint8Array {
  const a = new Uint8Array(parts.length);
  for (let i = 0; i < parts.length; i++) {
    const v = parts[i]!;
    if (!Number.isInteger(v) || v < 0 || v > 0xff) {
      throw new CliError(`APDU byte out of range at ${i}: ${v}`);
    }
    a[i] = v;
  }
  return a;
}

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** BER definite-length encoding (short form, or long form 0x81/0x82). */
export function encodeBerLen(n: number): number[] {
  if (n < 0) throw new CliError("negative TLV length");
  if (n < 0x80) return [n];
  if (n < 0x100) return [0x81, n];
  if (n < 0x10000) return [0x82, (n >> 8) & 0xff, n & 0xff];
  throw new CliError("TLV length exceeds 65535");
}

function tlv(tag: number[], value: number[]): number[] {
  return [...tag, ...encodeBerLen(value.length), ...value];
}

/**
 * Assemble a command APDU. Short form when data ≤ 255; otherwise an
 * extended-length APDU (leading 0x00, 2-byte Lc/Le). `le === "max"`
 * requests the maximum response.
 */
export function commandApdu(
  cla: number,
  ins: number,
  p1: number,
  p2: number,
  data: number[] = [],
  le?: number | "max",
): Uint8Array {
  const header = [cla, ins, p1, p2];
  if (data.length === 0 && le === undefined) return u8(header);
  if (data.length <= 255 && data.length > 0 && (le === undefined || le === "max")) {
    const tail = le === undefined ? [] : [0x00]; // short Le 0x00 = up to 256
    return u8([...header, data.length, ...data, ...tail]);
  }
  if (data.length === 0 && le !== undefined) {
    return u8([...header, le === "max" ? 0x00 : (le as number)]);
  }
  // Extended-length APDU.
  const lc = [0x00, (data.length >> 8) & 0xff, data.length & 0xff];
  const leBytes =
    le === undefined ? [] : le === "max" ? [0x00, 0x00] : [(le >> 8) & 0xff, le & 0xff];
  return u8([...header, ...lc, ...data, ...leBytes]);
}

export function encodeSelectPiv(): Uint8Array {
  // 00 A4 04 00 Lc <AID prefix> — case 3 (no Le); SW 9000 = selected.
  return commandApdu(0x00, 0xa4, 0x04, 0x00, [...PIV_AID]);
}

export function encodeVerifyPin(pin: string): Uint8Array {
  if (!/^[0-9]{1,8}$/.test(pin)) {
    // Note: the message intentionally does NOT echo the PIN.
    throw new CliError("PIV PIN must be 1–8 ASCII digits");
  }
  const body = new Array(8).fill(0xff);
  for (let i = 0; i < pin.length; i++) body[i] = pin.charCodeAt(i);
  return commandApdu(0x00, 0x20, 0x00, PIV_PIN_REF, body);
}

/**
 * GENERAL AUTHENTICATE for an Ed25519 signature over `message`.
 * Dynamic-auth template `7C { 82 00 (response, empty) , 81 LL <message> }`.
 * P1 = algorithm (Ed25519), P2 = slot. The card returns the signature
 * inside `7C { 82 LL <sig> }`.
 */
export function encodeGeneralAuthenticateEd25519(
  slot: number,
  message: Uint8Array,
): Uint8Array {
  const inner = [...tlv([0x82], []), ...tlv([0x81], [...message])];
  const data = tlv([0x7c], inner);
  return commandApdu(0x00, 0x87, ALG_ED25519, slot, data, "max");
}

export function encodeGetResponse(le: number): Uint8Array {
  return commandApdu(0x00, 0xc0, 0x00, 0x00, [], le === 0 ? "max" : le);
}

export interface PivKeyPolicyBytes {
  touch: "always" | "cached" | "never";
  pin: "once" | "always" | "never";
}

/**
 * GENERATE an Ed25519 key on the token (genesis — the cold maintainer
 * key, never leaves the token). Control-reference template
 * `AC { 80 01 E0 , AA 01 <pinPolicy> , AB 01 <touchPolicy> }`.
 */
export function encodeGenerateEd25519(
  slot: number,
  policy: PivKeyPolicyBytes,
): Uint8Array {
  const pin = PIN_POLICY[policy.pin];
  const touch = TOUCH_POLICY[policy.touch];
  if (pin === undefined || touch === undefined) {
    throw new CliError(`unsupported PIV key policy ${JSON.stringify(policy)}`);
  }
  const crt = [
    ...tlv([0x80], [ALG_ED25519]),
    ...tlv([0xaa], [pin]),
    ...tlv([0xab], [touch]),
  ];
  const data = tlv([0xac], crt);
  return commandApdu(0x00, 0x47, 0x00, slot, data, "max");
}

export interface ResponseApdu {
  data: Uint8Array;
  sw1: number;
  sw2: number;
  /** (sw1 << 8) | sw2 — e.g. 0x9000. */
  sw: number;
}

export function parseResponseApdu(resp: Uint8Array): ResponseApdu {
  if (resp.length < 2) {
    throw new CliError(`truncated response APDU (${resp.length} bytes)`);
  }
  const sw1 = resp[resp.length - 2]!;
  const sw2 = resp[resp.length - 1]!;
  return { data: resp.slice(0, resp.length - 2), sw1, sw2, sw: (sw1 << 8) | sw2 };
}

export function isSuccess(sw: number): boolean {
  return sw === 0x9000;
}

/** Retries left when SW = 0x63CX (VERIFY failed); else null. */
export function verifyRetriesLeft(sw: number): number | null {
  return (sw & 0xfff0) === 0x63c0 ? sw & 0x000f : null;
}

/** Human-readable, PIN-free explanation of a status word. */
export function statusWordReason(sw: number): string {
  if (sw === 0x9000) return "OK";
  if ((sw & 0xff00) === 0x6100) return `more data available (${sw & 0xff} bytes)`;
  const retries = verifyRetriesLeft(sw);
  if (retries !== null) return `wrong PIN, ${retries} retries left`;
  switch (sw) {
    case 0x6982:
      return "security status not satisfied (PIN not verified / touch missing)";
    case 0x6983:
      return "authentication method blocked (PIN locked — use PUK or the successor key)";
    case 0x6a80:
      return "incorrect parameters in the command data";
    case 0x6a82:
      return "file/application not found (is this a PIV-capable YubiKey ≥ fw 5.7?)";
    case 0x6a86:
      return "incorrect P1/P2 (unsupported slot or algorithm)";
    case 0x6d00:
      return "instruction not supported (PIV Ed25519 needs YubiKey fw ≥ 5.7)";
    default:
      return `card error 0x${sw.toString(16).padStart(4, "0")}`;
  }
}

interface Tlv {
  tag: number;
  value: Uint8Array;
  /** Offset just past this TLV in the parent buffer. */
  end: number;
}

/** Read ONE TLV at `off`. Supports 1- or 2-byte tags and definite
 *  short/long (0x81/0x82) lengths — the shapes PIV uses. */
function readTlv(b: Uint8Array, off: number): Tlv {
  if (off >= b.length) throw new CliError("TLV: unexpected end of data");
  let tag = b[off]!;
  let i = off + 1;
  if ((tag & 0x1f) === 0x1f) {
    // multi-byte tag (e.g. 0x7F49): subsequent bytes until MSB clear.
    let more = true;
    while (more) {
      if (i >= b.length) throw new CliError("TLV: truncated multi-byte tag");
      const next = b[i]!;
      tag = (tag << 8) | next;
      i++;
      more = (next & 0x80) !== 0;
    }
  }
  if (i >= b.length) throw new CliError("TLV: missing length");
  let len = b[i]!;
  i++;
  if (len === 0x81) {
    if (i >= b.length) throw new CliError("TLV: truncated long length");
    len = b[i]!;
    i++;
  } else if (len === 0x82) {
    if (i + 1 >= b.length) throw new CliError("TLV: truncated long length");
    len = (b[i]! << 8) | b[i + 1]!;
    i += 2;
  } else if (len > 0x82) {
    throw new CliError(`TLV: unsupported length form 0x${len.toString(16)}`);
  }
  if (i + len > b.length) {
    throw new CliError(`TLV: value (${len}) overruns buffer`);
  }
  return { tag, value: b.slice(i, i + len), end: i + len };
}

/** Find the first TLV with `tag` at the top level of `b`. */
export function findTlvValue(b: Uint8Array, tag: number): Uint8Array | null {
  let off = 0;
  while (off < b.length) {
    const t = readTlv(b, off);
    if (t.tag === tag) return t.value;
    off = t.end;
  }
  return null;
}

/**
 * Extract the 64-byte Ed25519 signature (→128-hex) from a GENERAL
 * AUTHENTICATE response: `7C { 82 <sig> }`. Fail-closed on any other
 * shape — never returns a guessed/short signature.
 */
export function extractEd25519Signature(responseData: Uint8Array): string {
  const dyn = findTlvValue(responseData, 0x7c);
  if (!dyn) throw new CliError("GENERAL AUTHENTICATE: missing 7C template");
  const sig = findTlvValue(dyn, 0x82);
  if (!sig) throw new CliError("GENERAL AUTHENTICATE: missing 82 response value");
  if (sig.length !== 64) {
    throw new CliError(
      `GENERAL AUTHENTICATE: signature is ${sig.length} bytes, expected 64 (Ed25519)`,
    );
  }
  return toHex(sig);
}

/**
 * Extract the 32-byte Ed25519 public key (→64-hex) from a GENERATE
 * asymmetric-key response: `7F49 { 86 <pubkey> }` (NIST SP 800-73-4 §3.3.2
 * / Yubico PIV Ed25519). Fail-closed on any other shape — never returns a
 * guessed/short key. This is the GENERATE wire shape ONLY; a Yubico GET
 * METADATA response is a DIFFERENT, flat TLV sequence — use
 * {@link extractMetadataPublicKey} for that (the no-PIN public read path).
 */
export function extractEd25519PublicKey(responseData: Uint8Array): string {
  const inner = findTlvValue(responseData, 0x7f49);
  if (!inner) throw new CliError("GENERATE: missing 7F49 public-key template");
  const pt = findTlvValue(inner, 0x86);
  if (!pt) throw new CliError("GENERATE: missing 86 public-point value");
  if (pt.length !== 32) {
    throw new CliError(
      `GENERATE: Ed25519 public key is ${pt.length} bytes, expected 32`,
    );
  }
  return toHex(pt);
}

/**
 * Extract the 32-byte Ed25519 public key (→64-hex) from a Yubico PIV
 * **GET METADATA** response (INS 0xF7 — the no-PIN public read).
 *
 * A real GET METADATA response is a FLAT sequence of top-level TLVs (NOT
 * the `7F49` GENERATE template). Captured byte-for-byte from a YubiKey
 * 5.7.4 Ed25519 slot 9c:
 *
 *   01 01 E0            Algorithm   (E0 = Ed25519)
 *   02 02 <pin> <touch> Policy
 *   03 01 <origin>      Origin
 *   04 22 86 20 <32B>   Public      (top-level 04 → inner 86 → 32-byte key)
 *
 * Fail-closed (root-of-trust path): the Algorithm tag, when present, must
 * be Ed25519 (0xE0) — a non-Ed25519 slot is rejected, never coerced; the
 * Public TLV (top-level `0x04`) and its inner `0x86` must be present and
 * exactly 32 bytes. Anything off throws — a wrong/short/absent key on the
 * signer-binding path MUST never be returned as a guess.
 */
export function extractMetadataPublicKey(responseData: Uint8Array): string {
  // Algorithm sanity (cheap, fail-closed): tag 0x01 carries the algorithm
  // id; if present it MUST be Ed25519 (0xE0). A different/short value
  // means this is not the Ed25519 signer slot we will bind — reject.
  const alg = findTlvValue(responseData, 0x01);
  if (alg && !(alg.length === 1 && alg[0] === ALG_ED25519)) {
    throw new CliError(
      `GET METADATA: slot algorithm is not Ed25519 (got 0x${
        alg.length === 1 ? alg[0]!.toString(16) : toHex(alg)
      }, expected 0xe0)`,
    );
  }
  const pub = findTlvValue(responseData, 0x04);
  if (!pub) throw new CliError("GET METADATA: missing 04 public-key TLV");
  const pt = findTlvValue(pub, 0x86);
  if (!pt) throw new CliError("GET METADATA: missing 86 public-point value");
  if (pt.length !== 32) {
    throw new CliError(
      `GET METADATA: Ed25519 public key is ${pt.length} bytes, expected 32`,
    );
  }
  return toHex(pt);
}
