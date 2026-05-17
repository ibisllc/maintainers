/**
 * `maintainers mandate` — renew authority on a track. The signing key MUST
 * be the current holder of the track (in-mandate renewal). The new mandate
 * is signed by the current holder; --successors lets the holder rotate the
 * named successor set.
 *
 * Note: the verifier checks holder-signed-renew vs successor-takeover by
 * comparing issuedAt to the predecessor's expiresAt window. This command
 * always issues "now" — if the predecessor has already expired, the user
 * should run `takeover` instead (which uses the successor's key).
 *
 * The signing key is resolved via {@link loadSignerBoundPubKey} (preview,
 * no PIN) then {@link loadSigner} (the real sign): the supported path is a
 * YubiKey PIV-resident Ed25519 (`yubikey-piv:slot=9c`); `file:` hex is the
 * lower-assurance air-gapped/successor fallback. ZERO wire delta.
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
  loadSignerBoundPubKey,
  loadSignerPubKeyList,
  type KeySourceFs,
  type PivTransport,
  type PivPinProvider,
  type SignerOptions,
} from "../lib/keysource.js";
import {
  type Assembled,
  renderDryRun,
  signAssembled,
} from "../lib/ceremony.js";
import { readStore, writeMandate, mandateFilename } from "../lib/store.js";

export interface MandateOptions {
  track: string;
  duration: string;
  signingKeySource: string;
  successorsSource: string | undefined;
  rootDir: string;
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
}

function signerOpts(opts: MandateOptions): SignerOptions {
  return { io: opts.io, pivTransport: opts.pivTransport, pivPin: opts.pivPin };
}

type UnsignedMandate = Omit<Mandate, "signatures">;

/**
 * Phase 1 — pure: read the store + the signer's PUBLIC key (no PIN/tap/
 * sign/write), build the unsigned renewal mandate + canonical bytes +
 * target path.
 */
export async function assembleRenewal(
  opts: MandateOptions,
): Promise<Assembled<UnsignedMandate>> {
  const store = readStore(opts.rootDir);
  const prior = store.mandatesByTrack.get(opts.track) ?? [];
  if (prior.length === 0) {
    throw new CliError(
      `no prior mandates on track "${opts.track}"; use "genesis" to bootstrap`,
    );
  }
  const last = prior[prior.length - 1]!;
  const sopts = signerOpts(opts);
  const signerPub = await loadSignerBoundPubKey(opts.signingKeySource, sopts);
  if (signerPub !== last.holder) {
    throw new CliError(
      `signing key ${signerPub.slice(0, 8)}… is not the current holder ${last.holder.slice(0, 8)}…; use "takeover" if the mandate has expired`,
    );
  }

  const issuedAtMs = opts.now().getTime();
  const successors = opts.successorsSource
    ? await loadSignerPubKeyList(opts.successorsSource, sopts)
    : last.successors;
  const unsigned: UnsignedMandate = {
    kind: "Mandate",
    version: 1,
    mandateId: opts.uuid(),
    track: opts.track,
    holder: signerPub,
    issuedAt: new Date(issuedAtMs).toISOString(),
    expiresAt: isoFromMsSince(issuedAtMs, parseDurationMs(opts.duration)),
    successors,
    signedBy: signerPub,
  };
  return {
    ceremony: "mandate",
    unsigned,
    canonical: canonicalMandate(unsigned),
    signingKeySource: opts.signingKeySource,
    signedBy: signerPub,
    rootDir: opts.rootDir,
    targetRelative: path.join(
      "tracks",
      opts.track,
      "mandates",
      mandateFilename(unsigned),
    ),
  };
}

export async function buildRenewal(opts: MandateOptions): Promise<Mandate> {
  const a = await assembleRenewal(opts);
  return signAssembled(a, signMandateWith, signerOpts(opts));
}

export interface MandateCmdEnv {
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  println: (line: string) => void;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
}

export async function runMandate(args: ParsedArgs, env: MandateCmdEnv): Promise<number> {
  const track = requireFlag(args, "track");
  const duration = requireFlag(args, "duration");
  const signingKey = optionalFlag(args, "signing-key") ?? requireFlag(args, "holder-key");
  const successorsCsv = optionalFlag(args, "successors");
  const rootDir = optionalFlag(args, "path") ?? ".maintainers";
  const dryRun = boolFlag(args, "dry-run");

  const a = await assembleRenewal({
    track,
    duration,
    signingKeySource: signingKey,
    successorsSource: successorsCsv,
    rootDir,
    now: env.now,
    io: env.io,
    uuid: env.uuid,
    pivTransport: env.pivTransport,
    pivPin: env.pivPin,
  });

  if (dryRun) {
    renderDryRun(a, env.println);
    return 0;
  }

  const sopts: SignerOptions = {
    io: env.io,
    pivTransport: env.pivTransport,
    pivPin: env.pivPin,
  };
  const m = await signAssembled(a, signMandateWith, sopts);
  const written = writeMandate(a.rootDir, m);
  env.println(`wrote renewal mandate for track "${track}" → ${written.relative}`);
  env.println(`  holder:    ${m.holder}`);
  env.println(`  issuedAt:  ${m.issuedAt}`);
  env.println(`  expiresAt: ${m.expiresAt}`);
  env.println(`  mandateId: ${m.mandateId}`);
  return 0;
}
