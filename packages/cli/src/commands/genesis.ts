/**
 * `maintainers genesis` — emit a self-signed genesis mandate for a track.
 *
 * A genesis mandate is the bootstrap: the holder signs it themselves; trust
 * is rooted in the user's choice to clone this repo at all (spec §4).
 *
 * The signing/holder key is resolved through {@link loadSigner} /
 * {@link loadSignerPubKey}, so the maintainer-root path is a YubiKey
 * PIV-resident Ed25519 (`yubikey-piv:slot=9c`) whose private half never
 * leaves the token; `file:` hex is the lower-assurance air-gapped /
 * successor fallback. A PIV-Ed25519 signature over the canonical bytes
 * is byte-identical to the in-process path — ZERO protocol/wire/spec
 * delta (the §11.1 linchpin).
 */

import { signMandateWith, type Mandate } from "@maintainers/protocol";
import { parseDurationMs, isoFromMsSince } from "../lib/duration.js";
import { CliError, type ParsedArgs, requireFlag, optionalFlag } from "../lib/args.js";
import {
  loadSigner,
  loadSignerPubKey,
  loadSignerPubKeyList,
  type KeySourceFs,
  type PivTransport,
  type PivPinProvider,
  type SignerOptions,
} from "../lib/keysource.js";
import { newUuid } from "../lib/uuid.js";
import { writeMandate, writeTrackPolicyIfMissing } from "../lib/store.js";

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

export async function buildGenesis(opts: GenesisOptions): Promise<Mandate> {
  const sopts = signerOpts(opts);
  const holderPub = await loadSignerPubKey(opts.holderKeySource, sopts);
  const signer = await loadSigner(opts.signingKeySource, sopts);
  if (signer.pubKey !== holderPub) {
    throw new CliError(
      "genesis: signing key does not match --holder-key (genesis must be self-signed)",
    );
  }
  const successors = opts.successorsSource
    ? await loadSignerPubKeyList(opts.successorsSource, sopts)
    : [holderPub];

  const issuedAtMs = opts.now().getTime();
  const durMs = parseDurationMs(opts.duration);
  const issuedAt = new Date(issuedAtMs).toISOString();
  const expiresAt = isoFromMsSince(issuedAtMs, durMs);

  return signMandateWith(
    {
      kind: "Mandate",
      version: 1,
      mandateId: opts.uuid(),
      track: opts.track,
      holder: holderPub,
      issuedAt,
      expiresAt,
      successors,
      signedBy: holderPub,
    },
    [signer],
  );
}

export async function runGenesis(args: ParsedArgs, env: GenesisCmdEnv): Promise<number> {
  const track = requireFlag(args, "track");
  const duration = requireFlag(args, "duration");
  const holderKey = requireFlag(args, "holder-key");
  const signingKey = optionalFlag(args, "signing-key") ?? holderKey;
  const successorsCsv = optionalFlag(args, "successors");
  const output = optionalFlag(args, "output") ?? `.maintainers/tracks/${track}/mandates/`;
  const rootDir = resolveRootDir(output);

  const mandate = await buildGenesis({
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

  writeTrackPolicyIfMissing(rootDir, {
    track,
    defaultMandateDuration: duration,
    approvalRule: { kind: "threshold", threshold: 1, of: "anyAuthorizedSigner" },
  });
  const written = writeMandate(rootDir, mandate);
  env.println(`wrote genesis mandate for track "${track}" → ${written.relative}`);
  env.println(`  holder:    ${mandate.holder}`);
  env.println(`  issuedAt:  ${mandate.issuedAt}`);
  env.println(`  expiresAt: ${mandate.expiresAt}`);
  env.println(`  mandateId: ${mandate.mandateId}`);
  return 0;
}

export interface GenesisCmdEnv {
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  println: (line: string) => void;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
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
