/**
 * Helpers for producing signed envelopes from unsigned object shapes.
 *
 * Each `sign*` function takes the envelope's pre-signature fields,
 * derives canonical bytes, signs with the provided private key, and
 * returns the fully-formed envelope.
 *
 * Each `signWith*Keys` variant accepts multiple private keys (one per
 * required signer) and is used for M-of-N tracks.
 */

import {
  canonicalMandateV2,
  canonicalKeyFile,
  canonicalKeyRedirect,
  canonicalEmailRotation,
  canonicalKeyIntroductionRequest,
  canonicalReleaseEndorsement,
  canonicalCaEndorsement,
} from "./canonical.js";
import { sign, pubKeyFromPriv } from "./crypto.js";
import type {
  MandateV2,
  KeyFile,
  KeyRedirect,
  EmailRotation,
  KeyIntroductionRequest,
  ReleaseEndorsement,
  CaEndorsement,
} from "./types.js";

/**
 * Sign a v2 mandate (LOCKED Phase-2 v2). One or more signers; the
 * verify-forward walk later checks they satisfy the *predecessor's*
 * embedded approvalRule over its successors set. A from-scratch (root)
 * mandate is self-signed by its holder and trusted purely via the pin.
 * Byte-identical RFC-8032 Ed25519 over {@link canonicalMandateV2}.
 */
export function signMandateV2(
  unsigned: Omit<MandateV2, "signatures">,
  signers: { privKey: string }[],
): MandateV2 {
  const bytes = canonicalMandateV2(unsigned);
  const signatures = signers.map(({ privKey }) => ({
    pubkey: pubKeyFromPriv(privKey),
    sig: sign(bytes, privKey),
  }));
  return { ...unsigned, signatures };
}

export function signKeyFile(
  unsigned: Omit<KeyFile, "signature">,
  privKey: string,
): KeyFile {
  const bytes = canonicalKeyFile(unsigned);
  const signature = sign(bytes, privKey);
  if (pubKeyFromPriv(privKey) !== unsigned.pubkey) {
    throw new Error(
      "signKeyFile: private key does not correspond to the KeyFile's pubkey field",
    );
  }
  return { ...unsigned, signature };
}

export function signKeyRedirect(
  unsigned: Omit<KeyRedirect, "signature">,
  privKey: string,
): KeyRedirect {
  const bytes = canonicalKeyRedirect(unsigned);
  const signature = sign(bytes, privKey);
  if (pubKeyFromPriv(privKey) !== unsigned.pubkey) {
    throw new Error(
      "signKeyRedirect: private key does not correspond to the redirect's pubkey field",
    );
  }
  return { ...unsigned, signature };
}

export function signEmailRotation(
  unsigned: Omit<EmailRotation, "signature">,
  privKey: string,
): EmailRotation {
  const bytes = canonicalEmailRotation(unsigned);
  const signature = sign(bytes, privKey);
  if (pubKeyFromPriv(privKey) !== unsigned.pubkey) {
    throw new Error(
      "signEmailRotation: private key does not correspond to the rotation's pubkey field",
    );
  }
  return { ...unsigned, signature };
}

export function signKeyIntroductionRequest(
  unsigned: Omit<KeyIntroductionRequest, "signature">,
  privKey: string,
): KeyIntroductionRequest {
  const bytes = canonicalKeyIntroductionRequest(unsigned);
  const signature = sign(bytes, privKey);
  if (pubKeyFromPriv(privKey) !== unsigned.pubkey) {
    throw new Error(
      "signKeyIntroductionRequest: private key does not correspond to the request's pubkey field",
    );
  }
  return { ...unsigned, signature };
}

export function signReleaseEndorsement(
  unsigned: Omit<ReleaseEndorsement, "signatures">,
  signers: { privKey: string }[],
): ReleaseEndorsement {
  const bytes = canonicalReleaseEndorsement(unsigned);
  const signatures = signers.map(({ privKey }) => ({
    pubkey: pubKeyFromPriv(privKey),
    sig: sign(bytes, privKey),
  }));
  return { ...unsigned, signatures };
}

export function signCaEndorsement(
  unsigned: Omit<CaEndorsement, "signatures">,
  signers: { privKey: string }[],
): CaEndorsement {
  const bytes = canonicalCaEndorsement(unsigned);
  const signatures = signers.map(({ privKey }) => ({
    pubkey: pubKeyFromPriv(privKey),
    sig: sign(bytes, privKey),
  }));
  return { ...unsigned, signatures };
}

/**
 * An external Ed25519 signer: the private key lives somewhere this
 * process cannot read (a YubiKey PIV slot, an HSM, a remote signer).
 * `sign` receives the EXACT canonical bytes and returns a 128-hex
 * RFC-8032 Ed25519 signature over them — byte-identical to the
 * in-process path, so the wire format, canonical bytes, verifier and
 * spec are all unchanged. This is purely an additive signing-API
 * surface (the §11.1 linchpin: PIV-Ed25519 == standard Ed25519 over
 * the same bytes ⇒ NO protocol delta).
 *
 * `sign` may be sync (the `privKeySigner` wrapper) or async (hardware
 * transports are inherently async); the `*With` helpers `await` it
 * uniformly so there is exactly ONE signature-collection path used by
 * both the local-hex-file and the YubiKey sources.
 */
export interface Ed25519Signer {
  /** 64-hex Ed25519 public key whose private half this signer holds. */
  readonly pubKey: string;
  /** 128-hex Ed25519 signature over the presented canonical bytes. */
  sign(message: Uint8Array): string | Promise<string>;
}

/**
 * Adapt a local hex private key to the {@link Ed25519Signer} interface.
 * Produces byte-identical output to the sync `sign*` functions — the
 * lower-assurance air-gapped/successor fallback documented in
 * `docs/ca-operations.md`.
 */
export function privKeySigner(privKey: string): Ed25519Signer {
  const pub = pubKeyFromPriv(privKey);
  return {
    pubKey: pub,
    sign: (message: Uint8Array) => sign(message, privKey),
  };
}

async function collectSignatures(
  bytes: Uint8Array,
  signers: Ed25519Signer[],
): Promise<{ pubkey: string; sig: string }[]> {
  const out: { pubkey: string; sig: string }[] = [];
  // Sequential, not Promise.all: a single physical token can only
  // service one tap/PIN at a time, and ordering is deterministic.
  for (const s of signers) {
    out.push({ pubkey: s.pubKey, sig: await s.sign(bytes) });
  }
  return out;
}

/** {@link signMandateV2} with external (e.g. YubiKey-PIV) signers. */
export async function signMandateV2With(
  unsigned: Omit<MandateV2, "signatures">,
  signers: Ed25519Signer[],
): Promise<MandateV2> {
  const bytes = canonicalMandateV2(unsigned);
  return { ...unsigned, signatures: await collectSignatures(bytes, signers) };
}

/** {@link signReleaseEndorsement} with external signers. */
export async function signReleaseEndorsementWith(
  unsigned: Omit<ReleaseEndorsement, "signatures">,
  signers: Ed25519Signer[],
): Promise<ReleaseEndorsement> {
  const bytes = canonicalReleaseEndorsement(unsigned);
  return { ...unsigned, signatures: await collectSignatures(bytes, signers) };
}

/** {@link signCaEndorsement} with external signers (the weekly lease). */
export async function signCaEndorsementWith(
  unsigned: Omit<CaEndorsement, "signatures">,
  signers: Ed25519Signer[],
): Promise<CaEndorsement> {
  const bytes = canonicalCaEndorsement(unsigned);
  return { ...unsigned, signatures: await collectSignatures(bytes, signers) };
}

/**
 * The identity envelopes (KeyFile, KeyRedirect, EmailRotation) carry a
 * SINGLE self-signature: each is signed by the very key it describes,
 * so the external signer's `pubKey` MUST equal the envelope's `pubkey`
 * field (mirrors the sync `sign*` invariant for the YubiKey-PIV path
 * so a key can self-register from a token). Byte-identical RFC-8032
 * Ed25519 — ZERO canonical/verifier/wire/spec change (the §11.1
 * linchpin). Exactly one signer (these are never M-of-N).
 */
async function selfSignature(
  label: string,
  bytes: Uint8Array,
  pubkey: string,
  signers: Ed25519Signer[],
): Promise<string> {
  if (signers.length !== 1) {
    throw new Error(`${label}: exactly one self-signer is required`);
  }
  const signer = signers[0]!;
  if (signer.pubKey !== pubkey) {
    throw new Error(
      `${label}: signer does not correspond to the envelope's pubkey field`,
    );
  }
  return signer.sign(bytes);
}

/** {@link signKeyFile} with an external (e.g. YubiKey-PIV) self-signer. */
export async function signKeyFileWith(
  unsigned: Omit<KeyFile, "signature">,
  signers: Ed25519Signer[],
): Promise<KeyFile> {
  const bytes = canonicalKeyFile(unsigned);
  const signature = await selfSignature(
    "signKeyFileWith",
    bytes,
    unsigned.pubkey,
    signers,
  );
  return { ...unsigned, signature };
}

/** {@link signKeyRedirect} with an external self-signer. */
export async function signKeyRedirectWith(
  unsigned: Omit<KeyRedirect, "signature">,
  signers: Ed25519Signer[],
): Promise<KeyRedirect> {
  const bytes = canonicalKeyRedirect(unsigned);
  const signature = await selfSignature(
    "signKeyRedirectWith",
    bytes,
    unsigned.pubkey,
    signers,
  );
  return { ...unsigned, signature };
}

/** {@link signEmailRotation} with an external self-signer. */
export async function signEmailRotationWith(
  unsigned: Omit<EmailRotation, "signature">,
  signers: Ed25519Signer[],
): Promise<EmailRotation> {
  const bytes = canonicalEmailRotation(unsigned);
  const signature = await selfSignature(
    "signEmailRotationWith",
    bytes,
    unsigned.pubkey,
    signers,
  );
  return { ...unsigned, signature };
}
