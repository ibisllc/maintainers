/**
 * PC/SC composition (#28). `pcscPivTransport` is exercised end-to-end
 * against a FAKE channel (no hardware): correct APDU ordering, SW
 * failure surfacing, 61xx chaining; and `connectPcscChannel`
 * fail-closes precisely when the optional native binding is absent —
 * NEVER a silent software fallback.
 */

import { describe, expect, it } from "vitest";
import {
  pcscPivTransport,
  connectPcscChannel,
  PcscBuildError,
  isRecoverableNotReady,
  type PcscChannel,
} from "../src/lib/piv-pcsc.js";
import { CliError } from "../src/lib/args.js";

function tlv(tag: number | number[], value: number[]): number[] {
  const t = Array.isArray(tag) ? tag : [tag];
  const n = value.length;
  const lb =
    n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, (n >> 8) & 0xff, n & 0xff];
  return [...t, ...lb, ...value];
}
const OK = [0x90, 0x00];
const SIG = new Array(64).fill(0xab);
const PUB = new Array(32).fill(0xcd);
const gaResp = [...tlv(0x7c, tlv(0x82, SIG)), ...OK];
const pkResp = [...tlv([0x7f, 0x49], tlv(0x86, PUB)), ...OK];

/** Scripted channel keyed by INS; records the INS order. */
function chan(
  script: Record<number, number[]>,
  order: number[] = [],
): PcscChannel {
  return {
    async transmit(apdu) {
      const ins = apdu[1]!;
      order.push(ins);
      const r = script[ins];
      if (!r) throw new Error(`unscripted INS 0x${ins.toString(16)}`);
      return new Uint8Array(r);
    },
  };
}

describe("pcscPivTransport", () => {
  it("getPublicKey: SELECT then GET METADATA → 64-hex pubkey", async () => {
    const order: number[] = [];
    const t = pcscPivTransport(
      chan({ 0xa4: OK, 0xf7: pkResp }, order),
    );
    expect(await t.getPublicKey("9c")).toBe("cd".repeat(32));
    expect(order).toEqual([0xa4, 0xf7]); // SELECT before the read
  });

  it("signEd25519: SELECT → VERIFY → GENERAL AUTHENTICATE, 128-hex sig", async () => {
    const order: number[] = [];
    const t = pcscPivTransport(
      chan({ 0xa4: OK, 0x20: OK, 0x87: gaResp }, order),
    );
    const sig = await t.signEd25519("9c", "123456", new Uint8Array([1, 2, 3]));
    expect(sig).toBe("ab".repeat(64));
    expect(order).toEqual([0xa4, 0x20, 0x87]); // VERIFY strictly before sign
  });

  it("generateEd25519: SELECT → GENERATE → 64-hex pubkey", async () => {
    const t = pcscPivTransport(chan({ 0xa4: OK, 0x47: pkResp }));
    expect(await t.generateEd25519("9a", { touch: "always", pin: "once" })).toBe(
      "cd".repeat(32),
    );
  });

  it("surfaces a PIN-failure status word (no PIN echoed)", async () => {
    const t = pcscPivTransport(
      chan({ 0xa4: OK, 0x20: [0x63, 0xc2], 0x87: gaResp }),
    );
    await expect(
      t.signEd25519("9c", "999999", new Uint8Array([1])),
    ).rejects.toThrow(/VERIFY PIN failed: wrong PIN, 2 retries left/);
  });

  it("surfaces applet-not-found on SELECT", async () => {
    const t = pcscPivTransport(chan({ 0xa4: [0x6a, 0x82] }));
    await expect(t.getPublicKey("9c")).rejects.toThrow(/not found/);
  });

  it("follows 61xx GET RESPONSE chaining", async () => {
    let gaCalls = 0;
    const channel: PcscChannel = {
      async transmit(apdu) {
        const ins = apdu[1]!;
        if (ins === 0xa4 || ins === 0x20) return new Uint8Array(OK);
        if (ins === 0x87) {
          gaCalls++;
          return new Uint8Array([0x61, 0x44]); // 0x44 bytes more
        }
        if (ins === 0xc0) return new Uint8Array(gaResp); // GET RESPONSE
        throw new Error(`unexpected INS 0x${ins.toString(16)}`);
      },
    };
    const sig = await pcscPivTransport(channel).signEd25519(
      "9c",
      "123456",
      new Uint8Array([7]),
    );
    expect(sig).toBe("ab".repeat(64));
    expect(gaCalls).toBe(1);
  });

  it("rejects a malformed slot", async () => {
    const t = pcscPivTransport(chan({ 0xa4: OK }));
    await expect(t.getPublicKey("zz")).rejects.toThrow(/invalid PIV slot/);
  });
});

describe("connectPcscChannel — fail-closed, no silent fallback", () => {
  it("throws a precise PcscBuildError (NOT recoverable) when the binding is absent", async () => {
    let err: unknown;
    try {
      await connectPcscChannel();
    } catch (e) {
      err = e;
    }
    // Still a CliError (existing dispatch/exit-1 path unchanged) AND the
    // typed build discriminator so the connect loop does NOT retry it
    // (a missing binding is not a missing reader).
    expect(err).toBeInstanceOf(CliError);
    expect(err).toBeInstanceOf(PcscBuildError);
    expect(isRecoverableNotReady(err)).toBe(false);
    const m = (err as Error).message;
    expect(m).toMatch(/native PIV\/PC\/SC transport is not wired in this build/);
    expect(m).toMatch(/never silently falls back/);
  });
});
