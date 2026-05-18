/**
 * Pure PIV APDU codec (#28) — no hardware. Exact byte layouts per
 * NIST SP 800-73-4 + the Yubico PIV Ed25519 extension, and fail-closed
 * response parsing.
 */

import { describe, expect, it } from "vitest";
import {
  encodeSelectPiv,
  encodeVerifyPin,
  encodeBerLen,
  commandApdu,
  encodeGeneralAuthenticateEd25519,
  encodeGenerateEd25519,
  parseResponseApdu,
  isSuccess,
  verifyRetriesLeft,
  statusWordReason,
  findTlvValue,
  extractEd25519Signature,
  extractEd25519PublicKey,
  extractMetadataPublicKey,
  toHex,
} from "../src/lib/piv-apdu.js";
import { CliError } from "../src/lib/args.js";

const h = (b: Uint8Array) => toHex(b);

describe("APDU encoders", () => {
  it("SELECT PIV is 00 A4 04 00 05 A0 00 00 03 08", () => {
    expect(h(encodeSelectPiv())).toBe("00a4040005a000000308");
  });

  it("VERIFY PIN pads to 8 bytes with 0xFF and never echoes the PIN", () => {
    expect(h(encodeVerifyPin("123456"))).toBe("0020008008313233343536ffff");
    for (const bad of ["", "123456789", "12 45", "abcd"]) {
      try {
        encodeVerifyPin(bad);
        throw new Error(`expected reject for ${JSON.stringify(bad)}`);
      } catch (e) {
        expect(e).toBeInstanceOf(CliError);
        // Never echo the supplied PIN material (vacuous for "").
        if (bad.length > 0) expect((e as Error).message).not.toContain(bad);
      }
    }
  });

  it("BER length: short / 0x81 / 0x82, reject > 0xFFFF", () => {
    expect(encodeBerLen(0)).toEqual([0]);
    expect(encodeBerLen(0x7f)).toEqual([0x7f]);
    expect(encodeBerLen(0x80)).toEqual([0x81, 0x80]);
    expect(encodeBerLen(0xff)).toEqual([0x81, 0xff]);
    expect(encodeBerLen(0x100)).toEqual([0x82, 0x01, 0x00]);
    expect(encodeBerLen(0xabcd)).toEqual([0x82, 0xab, 0xcd]);
    expect(() => encodeBerLen(0x10000)).toThrow(CliError);
  });

  it("commandApdu: case-3 (no Le), case-4 short, extended-length", () => {
    expect(h(commandApdu(0, 0xa4, 4, 0, [1, 2]))).toBe("00a40400020102");
    expect(h(commandApdu(0, 0x87, 0xe0, 0x9c, [9], "max"))).toBe("0087e09c010900");
    const big = new Array(300).fill(0x41);
    const ext = commandApdu(0, 0x87, 0xe0, 0x9c, big, "max");
    expect([ext[4], ext[5], ext[6]]).toEqual([0x00, 0x01, 0x2c]); // ext Lc=300
    expect(ext.length).toBe(4 + 3 + 300 + 2);
  });

  it("GENERAL AUTHENTICATE wraps 7C { 82 00 , 81 <msg> }", () => {
    const msg = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const a = encodeGeneralAuthenticateEd25519(0x9c, msg);
    expect([a[0], a[1], a[2], a[3]]).toEqual([0x00, 0x87, 0xe0, 0x9c]);
    const data = a.slice(5, a.length - 1); // strip header+Lc and trailing Le
    const dyn = findTlvValue(data, 0x7c)!;
    expect(findTlvValue(dyn, 0x82)!.length).toBe(0);
    expect(h(findTlvValue(dyn, 0x81)!)).toBe("deadbeef");
  });

  it("GENERATE Ed25519 carries 80 01 E0 + AA/AB policy bytes", () => {
    const a = encodeGenerateEd25519(0x9a, { touch: "always", pin: "once" });
    expect([a[0], a[1], a[2], a[3]]).toEqual([0x00, 0x47, 0x00, 0x9a]);
    const data = a.slice(5, a.length - 1);
    const crt = findTlvValue(data, 0xac)!;
    expect(h(findTlvValue(crt, 0x80)!)).toBe("e0");
    expect(h(findTlvValue(crt, 0xaa)!)).toBe("02"); // pin=once
    expect(h(findTlvValue(crt, 0xab)!)).toBe("02"); // touch=always
  });
});

describe("response parsing", () => {
  it("splits data + SW; flags success/retries; explains common SWs", () => {
    const r = parseResponseApdu(new Uint8Array([0xaa, 0xbb, 0x90, 0x00]));
    expect(h(r.data)).toBe("aabb");
    expect(r.sw).toBe(0x9000);
    expect(isSuccess(r.sw)).toBe(true);
    expect(() => parseResponseApdu(new Uint8Array([0x90]))).toThrow(CliError);
    expect(verifyRetriesLeft(0x63c2)).toBe(2);
    expect(verifyRetriesLeft(0x9000)).toBeNull();
    expect(statusWordReason(0x9000)).toBe("OK");
    expect(statusWordReason(0x63c1)).toMatch(/1 retries left/);
    expect(statusWordReason(0x6983)).toMatch(/blocked/);
    expect(statusWordReason(0x6a82)).toMatch(/not found/);
    expect(statusWordReason(0x6d00)).toMatch(/fw ≥ 5\.7/);
    expect(statusWordReason(0x6fff)).toMatch(/0x6fff/);
  });

  it("extracts an Ed25519 signature from 7C{82<64>}", () => {
    const sig = new Uint8Array(64).fill(0xab);
    const resp = new Uint8Array([0x7c, 0x42, 0x82, 0x40, ...sig]);
    expect(extractEd25519Signature(resp)).toBe("ab".repeat(64));
    expect(() =>
      extractEd25519Signature(new Uint8Array([0x7c, 0x02, 0x82, 0x00])),
    ).toThrow(/64 \(Ed25519\)/);
    expect(() => extractEd25519Signature(new Uint8Array([0x99, 0x00]))).toThrow(
      /missing 7C/,
    );
  });

  it("extracts an Ed25519 pubkey from a GENERATE 7F49{86<32>} (2-byte tag)", () => {
    const pk = new Uint8Array(32).fill(0xcd);
    const resp = new Uint8Array([0x7f, 0x49, 0x22, 0x86, 0x20, ...pk]);
    expect(extractEd25519PublicKey(resp)).toBe("cd".repeat(32));
    const bad = new Uint8Array([0x7f, 0x49, 0x03, 0x86, 0x01, 0x00]);
    expect(() => extractEd25519PublicKey(bad)).toThrow(/expected 32/);
  });

  // GET METADATA (INS 0xF7, no-PIN public read) is a FLAT top-level TLV
  // sequence — NOT the 7F49 GENERATE template. These bytes were captured
  // BYTE-FOR-BYTE from a real YubiKey 5.7.4 Ed25519 slot 9c (the
  // root-of-trust signer-pubkey path the genesis ceremony depends on).
  // Regression lock for the Gate-B hardware-surfaced parse bug.
  const REAL_METADATA_9C_HEX =
    "0101e002020202030101042286202137e739f00550b0e6a33a75366ebaf16f66f3492f733d0a8010ba91ab5e71d7";
  const REAL_PUB_9C_HEX =
    "2137e739f00550b0e6a33a75366ebaf16f66f3492f733d0a8010ba91ab5e71d7";
  const fromHex = (s: string): Uint8Array =>
    new Uint8Array(s.match(/../g)!.map((x) => parseInt(x, 16)));

  it("extracts the pubkey from a REAL YubiKey GET METADATA (flat 04→86)", () => {
    expect(extractMetadataPublicKey(fromHex(REAL_METADATA_9C_HEX))).toBe(
      REAL_PUB_9C_HEX,
    );
  });

  it("GET METADATA parser is fail-closed (no silent/garbled return)", () => {
    // Missing the top-level 0x04 Public TLV → throw, never guess.
    expect(() =>
      extractMetadataPublicKey(fromHex("0101e0020202020301 01".replace(/ /g, ""))),
    ).toThrow(/missing 04 public-key TLV/);
    // 0x04 present and well-formed but carries no inner 0x86.
    expect(() =>
      extractMetadataPublicKey(fromHex("0101e0040301 01ff".replace(/ /g, ""))),
    ).toThrow(/missing 86 public-point/);
    // Inner 0x86 present but wrong length (31 bytes, not 32).
    const short = new Uint8Array([
      0x01, 0x01, 0xe0, 0x04, 0x21, 0x86, 0x1f, ...new Uint8Array(31).fill(0xaa),
    ]);
    expect(() => extractMetadataPublicKey(short)).toThrow(/expected 32/);
    // Non-Ed25519 algorithm (e.g. 0x11 = ECCP256) → reject, never coerce.
    const wrongAlg = new Uint8Array([
      0x01, 0x01, 0x11, 0x04, 0x22, 0x86, 0x20, ...new Uint8Array(32).fill(0xbb),
    ]);
    expect(() => extractMetadataPublicKey(wrongAlg)).toThrow(/not Ed25519/);
    // The GENERATE 7F49 shape is NOT a valid GET METADATA response.
    expect(() =>
      extractMetadataPublicKey(
        new Uint8Array([0x7f, 0x49, 0x22, 0x86, 0x20, ...new Uint8Array(32)]),
      ),
    ).toThrow(/missing 04 public-key TLV/);
  });
});
