/**
 * Key-source resolution.
 *
 * Two forms supported on the CLI surface:
 *   file:<path>            local hex-encoded key (pubkey or privkey)
 *   yubikey-piv:slot=9c    YubiKey PIV-resident Ed25519 (the maintainer
 *                          root path — key never leaves the token)
 *
 * `loadPubKey`/`loadPrivKey` are the legacy hex-only entry points and
 * still reject `yubikey:` by design (a privkey can never be extracted
 * from a token). The signer-aware entry points are `loadSigner` /
 * `loadSignerPubKey` (below): they resolve EITHER form into an
 * `Ed25519Signer` / public key, so one signature path serves both.
 *
 * A PIV-Ed25519 signature over the canonical bytes is byte-identical
 * to RFC-8032 `ed25519.sign` — NO protocol/spec change is needed
 * (the §11.1 linchpin; the old "needs ES256" note was wrong). The
 * `file:` path is the lower-assurance air-gapped/successor fallback.
 *
 * File contents:
 *   - Whitespace and a leading "0x" are tolerated.
 *   - 32 raw bytes  -> 64 hex chars  -> private key.
 *   - Ed25519 pubkeys are 32 raw bytes / 64 hex chars too. Disambiguation
 *     happens at the call site: callers ask for either a privKey or a pubKey
 *     and we return that part. (When loading a privKey we derive the pubKey
 *     and return both.)
 */

import * as fs from "node:fs";
import {
  pubKeyFromPriv,
  privKeySigner,
  type Ed25519Signer,
} from "@ibisllc/maintainers";
import { CliError } from "./args.js";

export interface LoadedPubKey {
  kind: "pub";
  pubKey: string;
  source: string;
}

export interface LoadedPrivKey {
  kind: "priv";
  privKey: string;
  pubKey: string;
  source: string;
}

export type LoadedKey = LoadedPubKey | LoadedPrivKey;

export interface KeySourceFs {
  readFileSync(path: string): string;
}

export const realFs: KeySourceFs = {
  readFileSync(path: string): string {
    return fs.readFileSync(path, "utf8");
  },
};

function normalizeHex(raw: string): string {
  const trimmed = raw.trim();
  const stripped = trimmed.startsWith("0x") || trimmed.startsWith("0X")
    ? trimmed.slice(2)
    : trimmed;
  return stripped.toLowerCase();
}

function isHex64(s: string): boolean {
  if (s.length !== 64) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const ok = (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66);
    if (!ok) return false;
  }
  return true;
}

/**
 * Resolve a key source string into a public key. Accepts file: pointers
 * that contain either a privkey or a pubkey (we derive the pubkey when given
 * a privkey).
 */
export function loadPubKey(source: string, io: KeySourceFs = realFs): LoadedPubKey {
  if (source.startsWith("yubikey:")) {
    // TODO: implement PIV-backed signing. ES256 will need protocol-side support.
    throw new CliError(
      `yubikey: key sources are not yet implemented; use file: keys for now (got "${source}")`,
    );
  }
  if (!source.startsWith("file:")) {
    throw new CliError(
      `key source must start with "file:" or "yubikey:" (got "${source}")`,
    );
  }
  const path = source.slice("file:".length);
  if (path.length === 0) throw new CliError("file: key source has empty path");
  let raw: string;
  try {
    raw = io.readFileSync(path);
  } catch (err) {
    throw new CliError(
      `failed to read key file "${path}": ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const hex = normalizeHex(raw);
  if (!isHex64(hex)) {
    throw new CliError(
      `key file "${path}" does not contain 64 hex characters of key material`,
    );
  }
  // The 32-byte hex could be either a privkey or a pubkey — we can't tell from
  // hex alone. We treat it as a pubkey when the caller wants a pubkey; when
  // the caller wants to sign with it, they call loadPrivKey instead and we
  // re-validate by deriving the corresponding pubkey.
  return { kind: "pub", pubKey: hex, source };
}

/**
 * Resolve a key source string into a private key. Yubikey is stubbed.
 */
export function loadPrivKey(source: string, io: KeySourceFs = realFs): LoadedPrivKey {
  if (source.startsWith("yubikey:")) {
    throw new CliError(
      `yubikey: signing is not yet implemented; provide an Ed25519 key via file: (got "${source}")`,
    );
  }
  if (!source.startsWith("file:")) {
    throw new CliError(
      `signing key source must start with "file:" (got "${source}")`,
    );
  }
  const path = source.slice("file:".length);
  if (path.length === 0) throw new CliError("file: signing key source has empty path");
  let raw: string;
  try {
    raw = io.readFileSync(path);
  } catch (err) {
    throw new CliError(
      `failed to read signing key file "${path}": ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const hex = normalizeHex(raw);
  if (!isHex64(hex)) {
    throw new CliError(
      `signing key file "${path}" does not contain 64 hex characters`,
    );
  }
  const pub = pubKeyFromPriv(hex);
  return { kind: "priv", privKey: hex, pubKey: pub, source };
}

export function loadPubKeyList(csv: string, io: KeySourceFs = realFs): LoadedPubKey[] {
  if (csv.length === 0) return [];
  const parts = csv.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  return parts.map((p) => loadPubKey(p, io));
}

// ---- YubiKey-PIV signer seam (#28) --------------------------------------
//
// The maintainer root key is the root of the whole CA chain (§10.1). A
// `file:` hex key is the lower-assurance air-gapped/successor fallback;
// the supported path is a YubiKey 5 (fw >= 5.7) PIV-resident Ed25519 key
// — the private half NEVER leaves the token. A PIV-Ed25519 signature over
// the canonical bytes is byte-identical to the in-process path and
// verifies unchanged (the §11.1 linchpin: NO protocol/wire/spec delta).
//
// The actual PC/SC + APDU round-trip is a native concern that can only
// be verified with a real token, so it is injected behind `PivTransport`.
// Unit tests use a fake; the default real transport fail-closes with a
// precise message until the native implementation is wired (the
// human-gate increment) — it NEVER silently falls back to a hex key.

/** PIV slot used for the maintainer Ed25519 key. 9c = "digital
 *  signature" (PIN gating on every signature) — §11.4 default. */
export const DEFAULT_PIV_SLOT = "9c";

export interface PivKeyPolicy {
  /** "always" => every signature needs a physical tap (§11.1). */
  touch: "always" | "cached" | "never";
  /** "once" => PIN once per session; "always" => PIN per signature. */
  pin: "once" | "always";
}

export const GENESIS_PIV_POLICY: PivKeyPolicy = { touch: "always", pin: "once" };

/**
 * The narrow contract the CLI needs from a YubiKey PIV applet. All
 * methods are async (PC/SC/NFC round-trips). Injected so the
 * signature-collection path is fully unit-testable without hardware.
 */
export interface PivTransport {
  /** Read the Ed25519 public key resident in `slot` (no PIN — public
   *  read). 64-hex. Used to bind a signer and to read a successor's
   *  backup-key pubkey during genesis. */
  getPublicKey(slot: string): Promise<string>;
  /** PIV GENERAL AUTHENTICATE: Ed25519 over `message` after VERIFY
   *  PIN; the touch policy is satisfied by the physical tap. 128-hex
   *  signature, byte-identical to RFC-8032 `ed25519.sign`. */
  signEd25519(slot: string, pin: string, message: Uint8Array): Promise<string>;
  /** PIV GENERATE: create a fresh Ed25519 key in `slot` ON the token
   *  (genesis — the cold maintainer key, never leaves the token).
   *  Returns the new 64-hex public key. */
  generateEd25519(slot: string, policy: PivKeyPolicy): Promise<string>;
}

/** Secure PIN provider — injected by the command so the PIN is read
 *  from a no-echo prompt, never argv/env-by-default, never logged. */
export type PivPinProvider = () => Promise<string>;

/**
 * The default real transport: the pure APDU codec composed over a real
 * PC/SC channel (`piv-pcsc.ts`). The channel binding is OPTIONAL and
 * loaded lazily; if it (or a reader/token) is absent, `connectPcscChannel`
 * fail-closes with a precise, human-readable reason whose message still
 * contains "the native PIV/PC/SC transport is not wired in this build".
 * It MUST NOT fall back to any in-process key — the only alternative is
 * the explicitly lower-assurance `file:` hex key, chosen by the operator.
 * The libpcsclite round-trip is verified only at the YubiKey human gate.
 */
async function realChannelTransport(): Promise<PivTransport> {
  // Dynamic import: defers the optional-binding probe to call time and
  // sidesteps any module-init cycle (piv-pcsc only type-imports here).
  const { connectPcscChannel, pcscPivTransport } = await import("./piv-pcsc.js");
  return pcscPivTransport(await connectPcscChannel());
}

export const realPivTransport: PivTransport = {
  async getPublicKey(slot) {
    return (await realChannelTransport()).getPublicKey(slot);
  },
  async signEd25519(slot, pin, message) {
    return (await realChannelTransport()).signEd25519(slot, pin, message);
  },
  async generateEd25519(slot, policy) {
    return (await realChannelTransport()).generateEd25519(slot, policy);
  },
};

/**
 * Build a {@link PivTransport} whose channel is obtained through the
 * no-hardware UX state machine ({@link connectPcscChannelWithPrompt}):
 * *absent reader / token / not-tapped-yet* are prompted + waited + polled
 * + retried (a normal recoverable state, NOT a fatal error), while a
 * security failure or the build-not-wired condition still fail-closed
 * with NO weaker-key fallback. Non-interactive contexts fail closed
 * deterministically (never hang). This is the production wrapper used by
 * the CLI's `defaultEnv`; tests inject their own fake `PivTransport`
 * directly and never touch this. The connect factory is injectable so
 * the wrapper itself stays unit-testable without hardware.
 */
export function pivTransportWithPrompt(promptOpts: {
  prompt: (line: string) => void;
  interactive: boolean;
  connect?: () => Promise<import("./piv-pcsc.js").PcscChannel>;
}): PivTransport {
  const channel = async () => {
    const { connectPcscChannelWithPrompt } = await import("./piv-connect.js");
    const { pcscPivTransport } = await import("./piv-pcsc.js");
    return pcscPivTransport(
      await connectPcscChannelWithPrompt({
        prompt: promptOpts.prompt,
        interactive: promptOpts.interactive,
        ...(promptOpts.connect ? { connect: promptOpts.connect } : {}),
      }),
    );
  };
  return {
    async getPublicKey(slot) {
      return (await channel()).getPublicKey(slot);
    },
    async signEd25519(slot, pin, message) {
      return (await channel()).signEd25519(slot, pin, message);
    },
    async generateEd25519(slot, policy) {
      return (await channel()).generateEd25519(slot, policy);
    },
  };
}

export interface SignerOptions {
  io?: KeySourceFs;
  /** PIV transport for `yubikey-piv:` sources (default: realPivTransport). */
  pivTransport?: PivTransport;
  /** PIN provider for `yubikey-piv:` sources. Required for PIV. */
  pivPin?: PivPinProvider;
}

/** Parse `yubikey-piv:slot=9c` / `yubikey:slot=9c` → slot. */
function parsePivSource(source: string): { slot: string } {
  const rest = source.startsWith("yubikey-piv:")
    ? source.slice("yubikey-piv:".length)
    : source.slice("yubikey:".length);
  let slot = DEFAULT_PIV_SLOT;
  for (const kv of rest.split(",")) {
    const t = kv.trim();
    if (t.length === 0) continue;
    const eq = t.indexOf("=");
    const k = eq === -1 ? t : t.slice(0, eq);
    const v = eq === -1 ? "" : t.slice(eq + 1);
    if (k === "slot") {
      if (!/^[0-9a-fA-F]{2}$/.test(v)) {
        throw new CliError(
          `yubikey-piv: slot must be a 2-hex PIV slot id (e.g. slot=9c); got "${v}"`,
        );
      }
      slot = v.toLowerCase();
    } else {
      throw new CliError(`yubikey-piv: unknown option "${k}" in "${source}"`);
    }
  }
  return { slot };
}

function isPivSource(source: string): boolean {
  return source.startsWith("yubikey-piv:") || source.startsWith("yubikey:");
}

/**
 * Resolve a signing source into an {@link Ed25519Signer}. The single
 * entry point both the local-hex and YubiKey-PIV paths funnel through —
 * one signature-collection path (with `signMandateWith` et al.).
 *
 *   file:<path>            local hex key  -> privKeySigner (fallback)
 *   yubikey-piv:slot=9c    PIV-resident   -> token-backed signer
 */
export async function loadSigner(
  source: string,
  opts: SignerOptions = {},
): Promise<Ed25519Signer> {
  if (isPivSource(source)) {
    const { slot } = parsePivSource(source);
    const transport = opts.pivTransport ?? realPivTransport;
    const pin = opts.pivPin;
    if (!pin) {
      throw new CliError(
        "yubikey-piv: a PIN provider is required (the command must prompt; " +
          "the PIN is never read from argv and never logged)",
      );
    }
    const pubKey = await transport.getPublicKey(slot);
    if (!isHex64(normalizeHex(pubKey))) {
      throw new CliError(
        `yubikey-piv: token returned a malformed public key for slot ${slot}`,
      );
    }
    return {
      pubKey: normalizeHex(pubKey),
      async sign(message: Uint8Array): Promise<string> {
        // PIN obtained per call from the secure provider; the provider
        // is responsible for caching when policy is pin=once.
        return transport.signEd25519(slot, await pin(), message);
      },
    };
  }
  // file: (or anything else loadPrivKey accepts) — wrap the hex key.
  const loaded = loadPrivKey(source, opts.io ?? realFs);
  return privKeySigner(loaded.privKey);
}

/**
 * Read a *public* key from a signing-style source without needing the
 * private half — `file:` pubkey/privkey or a `yubikey-piv:` public read
 * (no PIN). Used by genesis to read the named successor/backup key.
 */
export async function loadSignerPubKey(
  source: string,
  opts: SignerOptions = {},
): Promise<string> {
  if (isPivSource(source)) {
    const { slot } = parsePivSource(source);
    const transport = opts.pivTransport ?? realPivTransport;
    const pub = normalizeHex(await transport.getPublicKey(slot));
    if (!isHex64(pub)) {
      throw new CliError(
        `yubikey-piv: token returned a malformed public key for slot ${slot}`,
      );
    }
    return pub;
  }
  return loadPubKey(source, opts.io ?? realFs).pubKey;
}

/**
 * The public key that {@link loadSigner}(source) would bind — resolved
 * WITHOUT a PIN and WITHOUT producing a signer (cannot sign).
 *
 *   yubikey-piv:slot=9c   PIV public read (no PIN, no tap, no sign)
 *   file:<path>           derive the pubkey from the local hex priv
 *                         (the lower-assurance air-gapped/successor
 *                         fallback — the key is already a plaintext
 *                         local file the operator chose; we derive but
 *                         never sign and never log it)
 *
 * This differs from {@link loadSignerPubKey}, which treats a `file:`
 * source as a *public* key (correct for `--holder-key`/`--new-holder`/
 * successors). A *signing* `file:` source is a private key, so its bound
 * pubkey must be DERIVED to match what `loadSigner` produces. Used by
 * the `--dry-run` preview so the previewed canonical bytes are exactly
 * what the real run would sign — without touching the token's private
 * operation or writing anything.
 */
export async function loadSignerBoundPubKey(
  source: string,
  opts: SignerOptions = {},
): Promise<string> {
  if (isPivSource(source)) {
    const { slot } = parsePivSource(source);
    const transport = opts.pivTransport ?? realPivTransport;
    const pub = normalizeHex(await transport.getPublicKey(slot));
    if (!isHex64(pub)) {
      throw new CliError(
        `yubikey-piv: token returned a malformed public key for slot ${slot}`,
      );
    }
    return pub;
  }
  // file: (or anything loadPrivKey accepts) — derive, same as loadSigner.
  return loadPrivKey(source, opts.io ?? realFs).pubKey;
}

/**
 * Resolve a comma-separated list of signing-style sources into public
 * keys. Each element may be `file:` or `yubikey-piv:` (the latter is a
 * no-PIN public read — used for the named successor / second-YubiKey
 * during genesis, §11.2). Resolved sequentially: a single physical
 * token can only service one read at a time.
 */
export async function loadSignerPubKeyList(
  csv: string,
  opts: SignerOptions = {},
): Promise<string[]> {
  if (csv.length === 0) return [];
  const parts = csv.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  const out: string[] = [];
  for (const p of parts) out.push(await loadSignerPubKey(p, opts));
  return out;
}
