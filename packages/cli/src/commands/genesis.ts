/**
 * `maintainers genesis` — emit a self-signed genesis mandate for a track.
 *
 * A genesis mandate is the bootstrap: the holder signs it themselves; trust
 * is rooted in the user's choice to clone this repo at all (spec §4).
 *
 * The signing/holder key is resolved through {@link loadSignerPubKey} /
 * {@link loadSignerBoundPubKey} / {@link loadSigner}, so the maintainer-root
 * path is a YubiKey PIV-resident Ed25519 (`yubikey-piv:slot=9c`) whose
 * private half never leaves the token; `file:` hex is the lower-assurance
 * air-gapped / successor fallback. A PIV-Ed25519 signature over the
 * canonical bytes is byte-identical to the in-process path — ZERO
 * protocol/wire/spec delta (the §11.1 linchpin).
 *
 * Split into `assembleGenesis` (pure: unsigned envelope + canonical bytes
 * + target path, no PIN/tap/sign/write) and the signing step, so
 * `--dry-run` previews EXACTLY the bytes a real run would sign.
 */

import { signMandateWith, canonicalMandate, type Mandate } from "@maintainers/protocol";
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
  loadSigner,
  loadSignerPubKey,
  loadSignerBoundPubKey,
  loadSignerPubKeyList,
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
import { newUuid } from "../lib/uuid.js";
import { writeMandate, writeTrackPolicyIfMissing, mandateFilename } from "../lib/store.js";

export interface GenesisOptions {
  track: string;
  duration: string;
  holderKeySource: string;
  signingKeySource: string;
  successorsSource: string | undefined;
  outputDir: string | undefined;
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  /** PIV transport for `yubikey-piv:` sources (default: realPivTransport). */
  pivTransport?: PivTransport;
  /** Secure no-echo PIN provider for `yubikey-piv:` sources. */
  pivPin?: PivPinProvider;
}

function signerOpts(opts: GenesisOptions): SignerOptions {
  return { io: opts.io, pivTransport: opts.pivTransport, pivPin: opts.pivPin };
}

type UnsignedMandate = Omit<Mandate, "signatures">;

/**
 * Phase 1 — pure: validate + read PUBLIC keys only, build the unsigned
 * genesis mandate, its canonical bytes, and the path that would be
 * written. No PIN, no tap, no signature, no write.
 */
export async function assembleGenesis(
  opts: GenesisOptions,
): Promise<Assembled<UnsignedMandate>> {
  const sopts = signerOpts(opts);
  const holderPub = await loadSignerPubKey(opts.holderKeySource, sopts);
  const signerPub = await loadSignerBoundPubKey(opts.signingKeySource, sopts);
  if (signerPub !== holderPub) {
    throw new CliError(
      "genesis: signing key does not match --holder-key (genesis must be self-signed)",
    );
  }
  const successors = opts.successorsSource
    ? await loadSignerPubKeyList(opts.successorsSource, sopts)
    : [holderPub];

  const issuedAtMs = opts.now().getTime();
  const durMs = parseDurationMs(opts.duration);
  const unsigned: UnsignedMandate = {
    kind: "Mandate",
    version: 1,
    mandateId: opts.uuid(),
    track: opts.track,
    holder: holderPub,
    issuedAt: new Date(issuedAtMs).toISOString(),
    expiresAt: isoFromMsSince(issuedAtMs, durMs),
    successors,
    signedBy: holderPub,
  };
  const rootDir = resolveRootDir(
    opts.outputDir ?? `.maintainers/tracks/${opts.track}/mandates/`,
  );
  return {
    ceremony: "genesis",
    unsigned,
    canonical: canonicalMandate(unsigned),
    signingKeySource: opts.signingKeySource,
    signedBy: holderPub,
    rootDir,
    targetRelative: path.join(
      "tracks",
      opts.track,
      "mandates",
      mandateFilename(unsigned),
    ),
    alsoIfMissing: [
      { relative: path.join("tracks", opts.track, "policy.json") },
    ],
  };
}

export async function buildGenesis(opts: GenesisOptions): Promise<Mandate> {
  const a = await assembleGenesis(opts);
  return signAssembled(a, signMandateWith, signerOpts(opts));
}

export async function runGenesis(args: ParsedArgs, env: GenesisCmdEnv): Promise<number> {
  const track = requireFlag(args, "track");
  const duration = requireFlag(args, "duration");
  const holderKey = requireFlag(args, "holder-key");
  const signingKey = optionalFlag(args, "signing-key") ?? holderKey;
  const successorsCsv = optionalFlag(args, "successors");
  const output = optionalFlag(args, "output");
  const dryRun = boolFlag(args, "dry-run");
  const yes = boolFlag(args, "yes");

  const a = await assembleGenesis({
    track,
    duration,
    holderKeySource: holderKey,
    signingKeySource: signingKey,
    successorsSource: successorsCsv,
    outputDir: output,
    now: env.now,
    io: env.io,
    uuid: env.uuid,
    pivTransport: env.pivTransport,
    pivPin: env.pivPin,
  });

  const mandate = await previewConfirmSign(a, signMandateWith, {
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
  if (!mandate) return 0; // dry-run

  writeTrackPolicyIfMissing(a.rootDir, {
    track,
    defaultMandateDuration: duration,
    approvalRule: { kind: "threshold", threshold: 1, of: "anyAuthorizedSigner" },
  });
  const written = writeMandate(a.rootDir, mandate);
  env.println(`wrote genesis mandate for track "${track}" → ${written.relative}`);
  env.println(`  holder:    ${mandate.holder}`);
  env.println(`  issuedAt:  ${mandate.issuedAt}`);
  env.println(`  expiresAt: ${mandate.expiresAt}`);
  env.println(`  mandateId: ${mandate.mandateId}`);
  env.println(`  successors: ${mandate.successors.join(", ")}`);
  env.println(
    "RECORD the holder pubkey above — bake it into @flagship/protocol " +
      "MAINTAINER_GENESIS_PUBKEYS (re-bake per surface: protocol-const, " +
      "webapp via it, iOS, Android).",
  );
  env.println(
    "Your named successor key is the ONLY recovery if this primary is " +
      "lost/bricked — store it safely and offline (no key escrow exists).",
  );
  return 0;
}

export interface GenesisCmdEnv {
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  println: (line: string) => void;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
  confirm?: ConfirmFn;
}

/**
 * `--output ./.maintainers/tracks/release/mandates/` → root is `./.maintainers`.
 * The writer takes the root and appends `tracks/<track>/mandates/`.
 */
function resolveRootDir(output: string): string {
  // Trim trailing slashes.
  let s = output.replace(/\/+$/, "");
  // Strip mandate-leaf paths the user might supply for convenience.
  s = s.replace(/\/tracks\/[^/]+\/mandates$/, "");
  if (s.endsWith("/mandates")) s = s.slice(0, -"/mandates".length);
  if (s.includes("/tracks/")) s = s.slice(0, s.indexOf("/tracks/"));
  return s.length > 0 ? s : ".maintainers";
}

export const _internal = { resolveRootDir };

export function newUuidWithGuard(): string {
  return newUuid();
}
