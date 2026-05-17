import { describe, expect, it } from "vitest";
import {
  generateKeypair,
  sign,
  verify,
  signCaEndorsement,
  signCaEndorsementWith,
  signMandate,
  signMandateWith,
  canonicalCaEndorsement,
} from "@maintainers/protocol";
import { CliError } from "../src/lib/args.js";
import {
  loadPrivKey,
  loadPubKey,
  loadPubKeyList,
  loadSigner,
  loadSignerPubKey,
  realPivTransport,
  DEFAULT_PIV_SLOT,
  type PivTransport,
} from "../src/lib/keysource.js";

function keypair(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

function fakeFs(files: Record<string, string>) {
  return {
    readFileSync(path: string): string {
      const v = files[path];
      if (v === undefined) {
        const err = new Error(`ENOENT: no such file or directory, open '${path}'`);
        throw err;
      }
      return v;
    },
  };
}

describe("loadPubKey", () => {
  it("loads a pubkey from file: source", () => {
    const a = keypair(1);
    const io = fakeFs({ "./alice.pub": a.pubKey });
    const loaded = loadPubKey("file:./alice.pub", io);
    expect(loaded.pubKey).toBe(a.pubKey);
  });

  it("tolerates 0x prefix and surrounding whitespace", () => {
    const a = keypair(2);
    const io = fakeFs({ "/k": `  0x${a.pubKey}\n` });
    expect(loadPubKey("file:/k", io).pubKey).toBe(a.pubKey);
  });

  it("rejects non-hex content", () => {
    const io = fakeFs({ "/k": "not-a-key" });
    expect(() => loadPubKey("file:/k", io)).toThrow(CliError);
  });

  it("yubikey: source raises a clear staging error", () => {
    const io = fakeFs({});
    expect(() => loadPubKey("yubikey:slot=9c", io)).toThrow(/yubikey/);
  });

  it("rejects unsupported scheme", () => {
    const io = fakeFs({});
    expect(() => loadPubKey("http://example.com/key", io)).toThrow(CliError);
  });
});

describe("loadPrivKey", () => {
  it("loads a privkey and derives its pubkey", () => {
    const a = keypair(3);
    const io = fakeFs({ "/p": a.privKey });
    const loaded = loadPrivKey("file:/p", io);
    expect(loaded.privKey).toBe(a.privKey);
    expect(loaded.pubKey).toBe(a.pubKey);
  });

  it("yubikey: privkey is staged-not-implemented", () => {
    const io = fakeFs({});
    expect(() => loadPrivKey("yubikey:slot=9a", io)).toThrow(/yubikey/);
  });
});

describe("loadPubKeyList", () => {
  it("parses comma-separated file: sources", () => {
    const a = keypair(1);
    const b = keypair(2);
    const io = fakeFs({ "/a": a.pubKey, "/b": b.pubKey });
    const list = loadPubKeyList("file:/a,file:/b", io);
    expect(list.map((k) => k.pubKey)).toEqual([a.pubKey, b.pubKey]);
  });

  it("empty input -> empty list", () => {
    const io = fakeFs({});
    expect(loadPubKeyList("", io)).toEqual([]);
  });
});

describe("loadSigner / PivTransport seam (#28)", () => {
  // A fake token: holds the key out-of-process, does standard Ed25519.
  function fakeToken(
    priv: string,
    pub: string,
    onPin?: (pin: string) => void,
  ): PivTransport {
    return {
      async getPublicKey() {
        return pub;
      },
      async signEd25519(_slot, pin, message) {
        onPin?.(pin);
        return sign(message, priv);
      },
      async generateEd25519() {
        return pub;
      },
    };
  }

  const caUnsigned = (signedBy: string) => ({
    kind: "CaEndorsement" as const,
    version: 1 as const,
    endorsementId: "ca-e1",
    track: "ca",
    caPubkey: "ab".repeat(32),
    scope: "flagship/directory-attestation",
    notBefore: "2026-03-01T00:00:00Z",
    notAfter: "2026-03-08T00:00:00Z",
    issuedAt: "2026-03-01T00:00:00Z",
    signedBy,
  });
  const mandateUnsigned = (holder: string) => ({
    kind: "Mandate" as const,
    version: 1 as const,
    mandateId: "m1",
    track: "ca",
    holder,
    issuedAt: "2026-03-01T00:00:00Z",
    expiresAt: "2026-09-01T00:00:00Z",
    successors: [holder],
    signedBy: holder,
  });

  it("file: source resolves to a signer byte-identical to the hex path", async () => {
    const a = keypair(1);
    const io = fakeFs({ "/k": a.privKey });
    const signer = await loadSigner("file:/k", { io });
    expect(signer.pubKey).toBe(a.pubKey);
    const viaSigner = await signCaEndorsementWith(caUnsigned(a.pubKey), [signer]);
    expect(viaSigner).toEqual(
      signCaEndorsement(caUnsigned(a.pubKey), [{ privKey: a.privKey }]),
    );
  });

  it("yubikey-piv: source signs through the token, byte-identical to file:", async () => {
    const a = keypair(2);
    const signer = await loadSigner("yubikey-piv:slot=9c", {
      pivTransport: fakeToken(a.privKey, a.pubKey),
      pivPin: async () => "123456",
    });
    expect(signer.pubKey).toBe(a.pubKey);
    const m = await signMandateWith(mandateUnsigned(a.pubKey), [signer]);
    expect(m).toEqual(
      signMandate(mandateUnsigned(a.pubKey), [{ privKey: a.privKey }]),
    );
    expect(
      verify(
        m.signatures[0]!.sig,
        canonicalCaEndorsement(caUnsigned(a.pubKey)) /* wrong-bytes guard */,
        a.pubKey,
      ),
    ).toBe(false);
  });

  it("defaults to PIV slot 9c when no slot given", async () => {
    const a = keypair(3);
    let usedSlot = "";
    const transport: PivTransport = {
      async getPublicKey(slot) {
        usedSlot = slot;
        return a.pubKey;
      },
      async signEd25519(slot, _pin, msg) {
        usedSlot = slot;
        return sign(msg, a.privKey);
      },
      async generateEd25519() {
        return a.pubKey;
      },
    };
    const signer = await loadSigner("yubikey-piv:", {
      pivTransport: transport,
      pivPin: async () => "x",
    });
    await signer.sign(new Uint8Array([1, 2, 3]));
    expect(usedSlot).toBe(DEFAULT_PIV_SLOT);
  });

  it("the default real transport fail-closes (no silent hex fallback)", async () => {
    await expect(
      loadSigner("yubikey-piv:slot=9c", { pivPin: async () => "x" }),
    ).rejects.toThrow(/native PIV\/PC\/SC transport is not wired/);
    await expect(realPivTransport.signEd25519("9c", "x", new Uint8Array())).rejects.toThrow(
      CliError,
    );
  });

  it("PIV requires a PIN provider", async () => {
    const a = keypair(4);
    await expect(
      loadSigner("yubikey-piv:slot=9c", {
        pivTransport: fakeToken(a.privKey, a.pubKey),
      }),
    ).rejects.toThrow(/PIN provider is required/);
  });

  it("rejects a malformed slot and unknown options", async () => {
    const pin = async () => "x";
    // slot/option parse happens before the PIN check, so opts is moot.
    await expect(loadSigner("yubikey-piv:slot=zz", {})).rejects.toThrow(
      /2-hex PIV slot/,
    );
    await expect(
      loadSigner("yubikey-piv:bogus=1", { pivPin: pin }),
    ).rejects.toThrow(/unknown option "bogus"/);
  });

  it("never leaks the PIN into errors", async () => {
    const a = keypair(5);
    const SECRET = "super-secret-pin-987654";
    const transport: PivTransport = {
      async getPublicKey() {
        return a.pubKey;
      },
      async signEd25519() {
        throw new CliError("token refused: touch timeout");
      },
      async generateEd25519() {
        return a.pubKey;
      },
    };
    const signer = await loadSigner("yubikey-piv:slot=9c", {
      pivTransport: transport,
      pivPin: async () => SECRET,
    });
    let msg = "";
    try {
      await signer.sign(new Uint8Array([9]));
    } catch (e) {
      msg = e instanceof Error ? `${e.message}\n${e.stack ?? ""}` : String(e);
    }
    expect(msg).not.toContain(SECRET);
    expect(msg).toMatch(/touch timeout/);
  });

  it("loadSignerPubKey reads pubkey from file: and yubikey-piv: (no PIN)", async () => {
    const a = keypair(6);
    const io = fakeFs({ "/p": a.pubKey });
    expect(await loadSignerPubKey("file:/p", { io })).toBe(a.pubKey);
    let pinAsked = false;
    const transport: PivTransport = {
      async getPublicKey() {
        return a.pubKey;
      },
      async signEd25519() {
        return "";
      },
      async generateEd25519() {
        return a.pubKey;
      },
    };
    const pub = await loadSignerPubKey("yubikey-piv:slot=9a", {
      pivTransport: transport,
      pivPin: async () => {
        pinAsked = true;
        return "x";
      },
    });
    expect(pub).toBe(a.pubKey);
    expect(pinAsked).toBe(false);
  });
});
