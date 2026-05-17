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
 * Signed by the cold maintainer key resolved through
 * {@link loadSignerBoundPubKey} (preview, no PIN) then {@link loadSigner}
 * (the real sign): the supported path is a YubiKey PIV-resident Ed25519
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

import {
  signCaEndorsementWith,
  canonicalCaEndorsement,
  type CaEndorsement,
} from "@maintainers/protocol";
import * as path from "node:path";
import { parseDurationMs, isoFromMsSince } from "../lib/duration.js";
import {
  CliError,
  type ParsedArgs,
  requireFlag,
  optionalFlag,
  boolFlag,
} from "../lib/args.js";
import {
  loadSignerBoundPubKey,
  type KeySourceFs,
  type PivTransport,
  type PivPinProvider,
  type SignerOptions,
} from "../lib/keysource.js";
import {
  type Assembled,
  type ConfirmFn,
  previewConfirmSign,
  signAssembled,
} from "../lib/ceremony.js";
import { readStore, writeCaEndorsement, caEndorsementFilename } from "../lib/store.js";

export const DEFAULT_CA_SCOPE = "flagship/directory-attestation";
export const DEFAULT_CA_TRACK = "ca";
export const DEFAULT_LEASE_DURATION = "7d";

export interface CaEndorsementOptions {
  caPubkey: string;
  scope: string;
  duration: string;
  track: string;
  signingKeySource: string;
  /** Store root (for the would-write path + the on-disk advisory).
   *  Defaults to ".maintainers"; not needed to produce the envelope. */
  rootDir?: string;
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

type UnsignedCaEndorsement = Omit<CaEndorsement, "signatures">;

/**
 * Phase 1 — pure: validate `--ca-pubkey`, read the signer's PUBLIC key
 * (no PIN/tap/sign/write), build the unsigned lease + canonical bytes +
 * target path.
 */
export async function assembleCaEndorsement(
  opts: CaEndorsementOptions,
): Promise<Assembled<UnsignedCaEndorsement>> {
  const sopts: SignerOptions = {
    io: opts.io,
    pivTransport: opts.pivTransport,
    pivPin: opts.pivPin,
  };
  const caPubkey = expectCaPubkey(opts.caPubkey);
  const signerPub = await loadSignerBoundPubKey(opts.signingKeySource, sopts);

  const issuedAtMs = opts.now().getTime();
  const issuedAt = new Date(issuedAtMs).toISOString();
  const unsigned: UnsignedCaEndorsement = {
    kind: "CaEndorsement",
    version: 1,
    endorsementId: opts.uuid(),
    track: opts.track,
    caPubkey,
    scope: opts.scope,
    notBefore: issuedAt,
    notAfter: isoFromMsSince(issuedAtMs, parseDurationMs(opts.duration)),
    issuedAt,
    signedBy: signerPub,
  };
  const rootDir = opts.rootDir ?? ".maintainers";
  return {
    ceremony: "ca-endorsement",
    unsigned,
    canonical: canonicalCaEndorsement(unsigned),
    signingKeySource: opts.signingKeySource,
    signedBy: signerPub,
    rootDir,
    targetRelative: path.join("ca-endorsements", caEndorsementFilename(unsigned)),
  };
}

export async function buildCaEndorsement(
  opts: CaEndorsementOptions,
): Promise<CaEndorsement> {
  const a = await assembleCaEndorsement(opts);
  const sopts: SignerOptions = {
    io: opts.io,
    pivTransport: opts.pivTransport,
    pivPin: opts.pivPin,
  };
  return signAssembled(a, signCaEndorsementWith, sopts);
}

export interface CaEndorsementCmdEnv {
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  println: (line: string) => void;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
  confirm?: ConfirmFn;
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
  const dryRun = boolFlag(args, "dry-run");
  const yes = boolFlag(args, "yes");

  const a = await assembleCaEndorsement({
    caPubkey,
    scope,
    duration,
    track,
    signingKeySource: signingKey,
    rootDir,
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
  } else if (!authority.has(a.signedBy)) {
    env.println(
      `note: signer ${a.signedBy.slice(0, 8)}… is not a current ${track}-` +
        `track holder/successor on disk here. This can be legitimate (a ` +
        `fresh takeover, or an out-of-date local clone) — authority is ` +
        `judged at the verifier's clock — but DOUBLE-CHECK before relying ` +
        `on this lease ("rotate-ca status").`,
    );
  }

  const e = await previewConfirmSign(a, signCaEndorsementWith, {
    dryRun,
    yes,
    env: {
      println: env.println,
      io: env.io,
      pivTransport: env.pivTransport,
      pivPin: env.pivPin,
      confirm: env.confirm,
    },
  });
  if (!e) return 0; // dry-run

  const written = writeCaEndorsement(a.rootDir, e);
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
