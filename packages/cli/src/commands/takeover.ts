/**
 * `maintainers takeover` — a named successor unilaterally issues a new
 * mandate after the predecessor expired. Per spec §4: first successor to
 * land wins (canonical-log ordering resolves races).
 *
 * The successor signs the new mandate using their own key; the new holder
 * can be the same person or a delegate. The takeover mandate's signedBy
 * MUST appear in the predecessor's successors[] list.
 *
 * Keys resolve via {@link loadSignerBoundPubKey} (preview, no PIN) /
 * {@link loadSignerPubKey} / {@link loadSigner} (the real sign): the
 * successor key is normally a YubiKey PIV-resident Ed25519
 * (`yubikey-piv:slot=9c`, the second key named in the genesis
 * `successors`); `file:` hex is the lower-assurance fallback. ZERO wire
 * delta — a PIV-Ed25519 signature is byte-identical (§11.1).
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
  renderDryRun,
  signAssembled,
} from "../lib/ceremony.js";
import { readStore, writeMandate, mandateFilename } from "../lib/store.js";

export interface TakeoverOptions {
  track: string;
  duration: string;
  successorKeySource: string;
  newHolderSource: string;
  successorsSource: string | undefined;
  rootDir: string;
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
}

function signerOpts(opts: TakeoverOptions): SignerOptions {
  return { io: opts.io, pivTransport: opts.pivTransport, pivPin: opts.pivPin };
}

type UnsignedMandate = Omit<Mandate, "signatures">;

/**
 * Phase 1 — pure: read the store + PUBLIC keys (successor key resolved
 * with NO PIN, NO tap, NO sign), enforce the successor-membership +
 * predecessor-expiry rules, build the unsigned takeover mandate.
 */
export async function assembleTakeover(
  opts: TakeoverOptions,
): Promise<Assembled<UnsignedMandate>> {
  const store = readStore(opts.rootDir);
  const prior = store.mandatesByTrack.get(opts.track) ?? [];
  if (prior.length === 0) {
    throw new CliError(`no prior mandates on track "${opts.track}"; nothing to take over`);
  }
  const last = prior[prior.length - 1]!;
  const sopts = signerOpts(opts);
  const successorPub = await loadSignerBoundPubKey(opts.successorKeySource, sopts);
  if (!last.successors.includes(successorPub)) {
    throw new CliError(
      `signer ${successorPub.slice(0, 8)}… is not a named successor on the last mandate; valid successors: ${last.successors.map((s) => s.slice(0, 8) + "…").join(", ")}`,
    );
  }
  const newHolderPub = await loadSignerPubKey(opts.newHolderSource, sopts);

  const issuedAtMs = opts.now().getTime();
  const predExpiresMs = Date.parse(last.expiresAt);
  if (Number.isFinite(predExpiresMs) && issuedAtMs < predExpiresMs) {
    throw new CliError(
      `predecessor mandate has not yet expired (expiresAt=${last.expiresAt}); takeover is only valid at or after expiry`,
    );
  }

  const successors = opts.successorsSource
    ? await loadSignerPubKeyList(opts.successorsSource, sopts)
    : [newHolderPub];
  const unsigned: UnsignedMandate = {
    kind: "Mandate",
    version: 1,
    mandateId: opts.uuid(),
    track: opts.track,
    holder: newHolderPub,
    issuedAt: new Date(issuedAtMs).toISOString(),
    expiresAt: isoFromMsSince(issuedAtMs, parseDurationMs(opts.duration)),
    successors,
    signedBy: successorPub,
  };
  return {
    ceremony: "takeover",
    unsigned,
    canonical: canonicalMandate(unsigned),
    signingKeySource: opts.successorKeySource,
    signedBy: successorPub,
    rootDir: opts.rootDir,
    targetRelative: path.join(
      "tracks",
      opts.track,
      "mandates",
      mandateFilename(unsigned),
    ),
  };
}

export async function buildTakeover(opts: TakeoverOptions): Promise<Mandate> {
  const a = await assembleTakeover(opts);
  return signAssembled(a, signMandateWith, signerOpts(opts));
}

export interface TakeoverCmdEnv {
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  println: (line: string) => void;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
}

export async function runTakeover(args: ParsedArgs, env: TakeoverCmdEnv): Promise<number> {
  const track = requireFlag(args, "track");
  const duration = optionalFlag(args, "duration") ?? "60d";
  const successorKey = requireFlag(args, "successor-key");
  const newHolder = requireFlag(args, "new-holder");
  const successorsCsv = optionalFlag(args, "successors");
  const rootDir = optionalFlag(args, "path") ?? ".maintainers";
  const dryRun = boolFlag(args, "dry-run");

  const a = await assembleTakeover({
    track,
    duration,
    successorKeySource: successorKey,
    newHolderSource: newHolder,
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
  env.println(`wrote takeover mandate for track "${track}" → ${written.relative}`);
  env.println(`  new holder: ${m.holder}`);
  env.println(`  signed by:  ${m.signedBy}`);
  env.println(`  issuedAt:   ${m.issuedAt}`);
  env.println(`  expiresAt:  ${m.expiresAt}`);
  env.println(`  mandateId:  ${m.mandateId}`);
  return 0;
}
