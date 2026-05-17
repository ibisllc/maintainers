/**
 * `maintainers ca-endorsement` — issue / renew a CA lease.
 *
 * A `CaEndorsement` is a present-tense, liveness-sensitive lease that
 * authorizes a hot operational CA pubkey until `notAfter`, evaluated at
 * the *verifier's* clock against the ca-track authority (spec §5.1). A
 * lapsed lease invalidates the CA globally with no revocation list;
 * overlapping leases make renewal gap-free. This is the recurring
 * weekly chore — `docs/ca-operations.md` Operation 1, Path B (the CLI
 * path that document referenced before this command existed).
 *
 * Signed by the cold maintainer key resolved through {@link loadSigner}:
 * the supported path is a YubiKey PIV-resident Ed25519
 * (`yubikey-piv:slot=9c`) whose private half never leaves the token;
 * `file:` hex is the lower-assurance air-gapped/successor fallback. A
 * PIV-Ed25519 signature over the canonical bytes is byte-identical
 * RFC-8032 Ed25519 — ZERO protocol/wire/spec delta (§11.1).
 *
 * It deliberately does NOT hard-fail when the signing key is not the
 * current on-disk ca-track authority: authority is judged at the
 * VERIFIER's clock, overlapping leases are intentional, and a fresh
 * takeover legitimately signs before its mandate is the "last" seen
 * here. It emits a clear human-readable advisory instead, so a
 * non-expert successor is warned without being falsely blocked.
 */

import { signCaEndorsementWith, type CaEndorsement } from "@maintainers/protocol";
import { parseDurationMs, isoFromMsSince } from "../lib/duration.js";
import { CliError, type ParsedArgs, requireFlag, optionalFlag } from "../lib/args.js";
import {
  loadSigner,
  type KeySourceFs,
  type PivTransport,
  type PivPinProvider,
  type SignerOptions,
} from "../lib/keysource.js";
import { readStore, writeCaEndorsement } from "../lib/store.js";

export const DEFAULT_CA_SCOPE = "flagship/directory-attestation";
export const DEFAULT_CA_TRACK = "ca";
export const DEFAULT_LEASE_DURATION = "7d";

export interface CaEndorsementOptions {
  caPubkey: string;
  scope: string;
  duration: string;
  track: string;
  signingKeySource: string;
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
}

/** Normalize + validate a 64-hex Ed25519 public key (tolerates 0x and
 *  surrounding whitespace; lower-cases). */
function expectCaPubkey(raw: string): string {
  const trimmed = raw.trim();
  const stripped =
    trimmed.startsWith("0x") || trimmed.startsWith("0X")
      ? trimmed.slice(2)
      : trimmed;
  const hex = stripped.toLowerCase();
  if (hex.length !== 64) {
    throw new CliError(
      `--ca-pubkey must be exactly 64 hex characters (an Ed25519 public key); got ${hex.length}`,
    );
  }
  for (let i = 0; i < hex.length; i++) {
    const c = hex.charCodeAt(i);
    const ok = (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66);
    if (!ok) {
      throw new CliError(`--ca-pubkey contains a non-hex character at index ${i}`);
    }
  }
  return hex;
}

export async function buildCaEndorsement(
  opts: CaEndorsementOptions,
): Promise<CaEndorsement> {
  const sopts: SignerOptions = {
    io: opts.io,
    pivTransport: opts.pivTransport,
    pivPin: opts.pivPin,
  };
  const caPubkey = expectCaPubkey(opts.caPubkey);
  const signer = await loadSigner(opts.signingKeySource, sopts);

  const issuedAtMs = opts.now().getTime();
  const issuedAt = new Date(issuedAtMs).toISOString();
  const notAfter = isoFromMsSince(issuedAtMs, parseDurationMs(opts.duration));

  return signCaEndorsementWith(
    {
      kind: "CaEndorsement",
      version: 1,
      endorsementId: opts.uuid(),
      track: opts.track,
      caPubkey,
      scope: opts.scope,
      notBefore: issuedAt,
      notAfter,
      issuedAt,
      signedBy: signer.pubKey,
    },
    [signer],
  );
}

export interface CaEndorsementCmdEnv {
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  println: (line: string) => void;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
}

/**
 * The set of pubkeys that are ca-track holders or named successors on
 * disk (a loose, fs-only view — the cryptographic authority decision is
 * the verifier's, at its own clock; this is only for the advisory).
 */
function onDiskCaAuthority(rootDir: string, track: string): Set<string> {
  const out = new Set<string>();
  const store = readStore(rootDir);
  for (const m of store.mandatesByTrack.get(track) ?? []) {
    if (typeof m.holder === "string") out.add(m.holder);
    for (const s of m.successors ?? []) out.add(s);
  }
  return out;
}

export async function runCaEndorsement(
  args: ParsedArgs,
  env: CaEndorsementCmdEnv,
): Promise<number> {
  const caPubkey = requireFlag(args, "ca-pubkey");
  const scope = optionalFlag(args, "scope") ?? DEFAULT_CA_SCOPE;
  const duration = optionalFlag(args, "duration") ?? DEFAULT_LEASE_DURATION;
  const track = optionalFlag(args, "track") ?? DEFAULT_CA_TRACK;
  const signingKey = requireFlag(args, "signing-key");
  const rootDir = optionalFlag(args, "path") ?? ".maintainers";

  const e = await buildCaEndorsement({
    caPubkey,
    scope,
    duration,
    track,
    signingKeySource: signingKey,
    now: env.now,
    io: env.io,
    uuid: env.uuid,
    pivTransport: env.pivTransport,
    pivPin: env.pivPin,
  });

  const authority = onDiskCaAuthority(rootDir, track);
  if (authority.size === 0) {
    env.println(
      `note: no "${track}"-track mandates found under ${rootDir}; cannot ` +
        `locally confirm this signer is the ${track} authority (genesis ` +
        `may not be present yet). Verifiers decide authority at their own ` +
        `clock — issue it, but check with "rotate-ca status".`,
    );
  } else if (!authority.has(e.signedBy)) {
    env.println(
      `note: signer ${e.signedBy.slice(0, 8)}… is not a current ${track}-` +
        `track holder/successor on disk here. This can be legitimate (a ` +
        `fresh takeover, or an out-of-date local clone) — authority is ` +
        `judged at the verifier's clock — but DOUBLE-CHECK before relying ` +
        `on this lease ("rotate-ca status").`,
    );
  }

  const written = writeCaEndorsement(rootDir, e);
  env.println(`wrote CA lease for track "${track}" → ${written.relative}`);
  env.println(`  endorsementId: ${e.endorsementId}`);
  env.println(`  caPubkey:      ${e.caPubkey}`);
  env.println(`  scope:         ${e.scope}`);
  env.println(`  notBefore:     ${e.notBefore}`);
  env.println(`  notAfter:      ${e.notAfter}`);
  env.println(`  signedBy:      ${e.signedBy}`);
  env.println(
    `commit ${written.relative} (append-only) and publish it; ` +
      `.com serves the live lease automatically — no deploy.`,
  );
  return 0;
}
