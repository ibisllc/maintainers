/**
 * `maintainers upsert-mandate` — the ONE mandate verb (LOCKED Phase-2
 * v2). genesis / mandate / takeover collapse into this:
 *
 *   - NO prior mandate on the track  → FROM-SCRATCH (root). Sets the
 *     succession policy freely; self-signed by its holder; trusted
 *     purely via its baked canonical-hash PIN (#30 generalised). This
 *     is the genesis-equivalent — its shape is frozen forever once
 *     pinned (the Gate-B artifact).
 *   - prior mandate exists           → SUCCESSION. Verified FORWARD
 *     against the *predecessor's* embedded rule: every signer ∈
 *     pred.successors, distinct count ≥ pred.approvalRule.threshold,
 *     successors ≥ pred.minSuccessors, window ≤ pred.maxDuration.
 *     Renewal = rotation = takeover = repolicy = this ONE mechanism;
 *     there is NO privileged self-renewal.
 *
 * Fail-closed PRE-FLIGHT: every predecessor-rule check that can be made
 * from PUBLIC reads is done in `assemble` (no PIN/tap) and raises a
 * precise CliError BEFORE the operator is ever asked to touch the
 * token — you never tap a YubiKey for a mandate the verifier would
 * reject. Same #28 ceremony discipline as the other verbs
 * (assemble/sign split, `--dry-run` exact bytes + diff, banner, typed
 * confirm, never-log-secrets).
 *
 * SCOPED BOUNDARY (honest, fail-closed — NOT a silent under-build): the
 * shared ceremony orchestrator collects a SINGLE signature. A
 * predecessor whose `approvalRule.threshold > 1` therefore cannot be
 * succeeded by this CLI yet — assemble refuses rather than emit a
 * mandate that cannot satisfy the threshold. Multi-signer quorum
 * collection (N sequential taps) is a scoped follow-up to the shared
 * `previewConfirmSign`/`signAssembled` path; the c2 verifier already
 * enforces the threshold regardless.
 */

import {
  signMandateWith,
  canonicalMandate,
  mandatePinHash,
  type Mandate,
} from "@ibisllc/maintainers";
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
  loadSignerPubKey,
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
import { readMandates, writeMandate, mandateFilename } from "../lib/store.js";

export interface UpsertMandateOptions {
  track: string;
  signingKeySource: string;
  holderSource: string | undefined;
  successorsSource: string | undefined;
  duration: string;
  threshold: number | undefined;
  minSuccessors: number | undefined;
  maxDuration: string | undefined;
  defaultDuration: string | undefined;
  project:
    | { name: string; contact?: string; homepage?: string; tracks?: string[] }
    | undefined;
  rootDir: string;
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
}

function signerOpts(opts: UpsertMandateOptions): SignerOptions {
  return { io: opts.io, pivTransport: opts.pivTransport, pivPin: opts.pivPin };
}

type UnsignedMandate = Omit<Mandate, "signatures">;

const RULE = "────────────────────────────────────────────────────────────";

function durSeconds(s: string): number {
  // parseDurationMs already rejects non-positive / malformed.
  return Math.floor(parseDurationMs(s) / 1000);
}

/**
 * Phase 1 — pure: read the v2 log + PUBLIC keys only (no PIN/tap/sign/
 * write), run every predecessor-rule check that can be made publicly,
 * and build the unsigned v2 mandate + canonical bytes + target path.
 * Fail-closed BEFORE any token touch.
 */
export async function assembleUpsertMandate(
  opts: UpsertMandateOptions,
): Promise<Assembled<UnsignedMandate>> {
  const sopts = signerOpts(opts);
  const prior = readMandates(opts.rootDir, opts.track);
  const signerPub = await loadSignerBoundPubKey(opts.signingKeySource, sopts);
  const holderPub = opts.holderSource
    ? await loadSignerPubKey(opts.holderSource, sopts)
    : signerPub;

  const nowMs = opts.now().getTime();
  const durMs = parseDurationMs(opts.duration);
  const windowSec = Math.floor(durMs / 1000);
  const issuedAt = new Date(nowMs).toISOString();
  const expiresAt = isoFromMsSince(nowMs, durMs);

  const isFromScratch = prior.length === 0;
  let successors: string[];
  let threshold: number;
  let minSuccessors: number;
  let maxDurationSeconds: number;
  let defaultDurationSeconds: number;
  let signedBy: string;
  let project: Mandate["project"] | undefined;
  let bannerExtra: string[];

  if (isFromScratch) {
    if (signerPub !== holderPub) {
      throw new CliError(
        "from-scratch mandate must be self-signed by its holder: the " +
          "--signing-key pubkey must equal --holder (omit --holder to use " +
          "the signing key as holder).",
      );
    }
    successors = opts.successorsSource
      ? await loadSignerPubKeyList(opts.successorsSource, sopts)
      : [holderPub];
    threshold = opts.threshold ?? 1;
    minSuccessors = opts.minSuccessors ?? 1;
    // Conservative default: the next mandate cannot outlast THIS one
    // unless the founder widens it explicitly.
    maxDurationSeconds = opts.maxDuration ? durSeconds(opts.maxDuration) : windowSec;
    defaultDurationSeconds = opts.defaultDuration
      ? durSeconds(opts.defaultDuration)
      : windowSec;
    if (!opts.project || opts.project.name.length === 0) {
      throw new CliError(
        "from-scratch mandate requires --project-name (the project-level " +
          "contact/track-list lives on the origin mandate).",
      );
    }
    project = opts.project;
    signedBy = holderPub;
    bannerExtra = [
      RULE,
      "⚠  FROM-SCRATCH ORIGIN — this mandate has NO predecessor. Its",
      "   trust comes ENTIRELY from its canonical-hash PIN being baked",
      "   into the signed build (#30 generalised). RECORD the PIN printed",
      "   below and bake it per surface (protocol-const, webapp, iOS,",
      "   Android — same value). This CANNOT be undone; a later, more-",
      "   cosigned mandate is the only way forward.",
      "   • Use your PRIMARY key; name your BACKUP in --successors —",
      "     a named successor is the ONLY recovery (no key escrow).",
    ];
  } else {
    const pred = prior[prior.length - 1]!;
    // ---- fail-closed pre-flight (PUBLIC reads only, before any tap) ----
    if (!pred.successors.includes(signerPub)) {
      throw new CliError(
        `signing key ${signerPub.slice(0, 8)}… is not a named successor of ` +
          `the current mandate ${pred.mandateId} on track "${opts.track}" — ` +
          `only the predecessor's successors may sign the next mandate ` +
          `(there is no self-renewal). Refusing.`,
      );
    }
    if (pred.approvalRule.kind !== "threshold" || pred.approvalRule.threshold > 1) {
      const t =
        pred.approvalRule.kind === "threshold" ? pred.approvalRule.threshold : "?";
      throw new CliError(
        `the predecessor requires a ${t}-of-${pred.successors.length} quorum; ` +
          `this CLI collects a SINGLE signature (multi-signer quorum ` +
          `collection is a scoped follow-up). Refusing to assemble a mandate ` +
          `that cannot satisfy the predecessor's threshold.`,
      );
    }
    if (windowSec > pred.maxDurationSeconds) {
      throw new CliError(
        `this mandate's window (${windowSec}s) exceeds the predecessor's ` +
          `maxDuration (${pred.maxDurationSeconds}s) — refusing.`,
      );
    }
    if (nowMs < Date.parse(pred.issuedAt)) {
      throw new CliError(
        "clock skew: 'now' precedes the predecessor's issuedAt — refusing " +
          "to issue a mandate that would be rejected as issued-before-predecessor.",
      );
    }
    successors = opts.successorsSource
      ? await loadSignerPubKeyList(opts.successorsSource, sopts)
      : pred.successors;
    minSuccessors = opts.minSuccessors ?? pred.minSuccessors;
    threshold = opts.threshold ?? pred.approvalRule.threshold;
    maxDurationSeconds = opts.maxDuration
      ? durSeconds(opts.maxDuration)
      : pred.maxDurationSeconds;
    defaultDurationSeconds = opts.defaultDuration
      ? durSeconds(opts.defaultDuration)
      : pred.defaultDurationSeconds;
    signedBy = signerPub;
    const holderChanges = holderPub !== pred.holder;
    bannerExtra = [
      RULE,
      `SUCCESSION on track "${opts.track}" — signed as a named successor`,
      `of mandate ${pred.mandateId}.`,
      holderChanges
        ? `   The holder CHANGES ${pred.holder.slice(0, 8)}… → ` +
          `${holderPub.slice(0, 8)}… (a takeover; visible to every consumer).`
        : "   The holder is unchanged (a renewal).",
    ];
  }

  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new CliError(`--threshold must be a positive integer; got ${threshold}`);
  }
  if (!Number.isInteger(minSuccessors) || minSuccessors < 0) {
    throw new CliError(
      `--min-successors must be a non-negative integer; got ${minSuccessors}`,
    );
  }
  if (threshold > successors.length) {
    throw new CliError(
      `approvalRule threshold ${threshold} exceeds the successor count ` +
        `${successors.length}: the next mandate could never satisfy it ` +
        `(the chain would be unrenewable). Refusing.`,
    );
  }
  if (successors.length < minSuccessors) {
    throw new CliError(
      `successors (${successors.length}) is below minSuccessors ` +
        `(${minSuccessors}) — refusing.`,
    );
  }

  const unsigned: UnsignedMandate = {
    kind: "Mandate",
    version: 1,
    mandateId: opts.uuid(),
    track: opts.track,
    holder: holderPub,
    issuedAt,
    expiresAt,
    successors,
    approvalRule: { kind: "threshold", threshold },
    minSuccessors,
    maxDurationSeconds,
    defaultDurationSeconds,
    ...(project ? { project } : {}),
    signedBy,
  };

  return {
    ceremony: "upsert-mandate",
    unsigned,
    canonical: canonicalMandate(unsigned),
    signingKeySource: opts.signingKeySource,
    signedBy,
    rootDir: opts.rootDir,
    targetRelative: path.join(
      "tracks",
      opts.track,
      "mandates",
      mandateFilename(unsigned),
    ),
    bannerExtra,
  };
}

export async function buildUpsertMandate(
  opts: UpsertMandateOptions,
): Promise<Mandate> {
  const a = await assembleUpsertMandate(opts);
  return signAssembled(a, signMandateWith, signerOpts(opts));
}

export interface UpsertMandateCmdEnv {
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  println: (line: string) => void;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
  confirm?: ConfirmFn;
}

function parseProject(args: ParsedArgs):
  | { name: string; contact?: string; homepage?: string; tracks?: string[] }
  | undefined {
  const name = optionalFlag(args, "project-name");
  if (!name) return undefined;
  const contact = optionalFlag(args, "project-contact");
  const homepage = optionalFlag(args, "project-homepage");
  const tracksCsv = optionalFlag(args, "project-tracks");
  const tracks = tracksCsv
    ? tracksCsv.split(",").map((s) => s.trim()).filter((s) => s.length > 0)
    : undefined;
  return {
    name,
    ...(contact ? { contact } : {}),
    ...(homepage ? { homepage } : {}),
    ...(tracks && tracks.length > 0 ? { tracks } : {}),
  };
}

function optInt(args: ParsedArgs, name: string): number | undefined {
  const v = optionalFlag(args, name);
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) {
    throw new CliError(`--${name} must be a non-negative integer; got "${v}"`);
  }
  return n;
}

export async function runUpsertMandate(
  args: ParsedArgs,
  env: UpsertMandateCmdEnv,
): Promise<number> {
  const track = requireFlag(args, "track");
  const signingKey = requireFlag(args, "signing-key");
  const duration = requireFlag(args, "duration");
  const holderSource = optionalFlag(args, "holder");
  const successorsSource = optionalFlag(args, "successors");
  const threshold = optInt(args, "threshold");
  const minSuccessors = optInt(args, "min-successors");
  const maxDuration = optionalFlag(args, "max-duration");
  const defaultDuration = optionalFlag(args, "default-duration");
  const project = parseProject(args);
  const rootDir = optionalFlag(args, "path") ?? ".maintainers";
  const dryRun = boolFlag(args, "dry-run");
  const yes = boolFlag(args, "yes");

  const a = await assembleUpsertMandate({
    track,
    signingKeySource: signingKey,
    holderSource,
    successorsSource,
    duration,
    threshold,
    minSuccessors,
    maxDuration,
    defaultDuration,
    project,
    rootDir,
    now: env.now,
    io: env.io,
    uuid: env.uuid,
    pivTransport: env.pivTransport,
    pivPin: env.pivPin,
  });

  const m = await previewConfirmSign(a, signMandateWith, {
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
  if (!m) return 0; // dry-run

  const written = writeMandate(a.rootDir, m);
  const pin = mandatePinHash(m);
  const isFromScratch = m.project !== undefined;
  env.println(`wrote ${isFromScratch ? "from-scratch (root)" : "succession"} ` +
    `mandate for track "${track}" → ${written.relative}`);
  env.println(`  holder:     ${m.holder}`);
  env.println(`  issuedAt:   ${m.issuedAt}`);
  env.println(`  expiresAt:  ${m.expiresAt}`);
  env.println(`  mandateId:  ${m.mandateId}`);
  env.println(`  successors: ${m.successors.join(", ")}`);
  env.println(`  rule:       ${m.approvalRule.threshold}-of-${m.successors.length}` +
    `, minSuccessors=${m.minSuccessors}, maxDuration=${m.maxDurationSeconds}s`);
  env.println(`  PIN (canonical hash): ${pin}`);
  if (isFromScratch) {
    env.println(
      "RECORD the PIN above — it is the #30-generalised baked anchor. " +
        "Bake it per surface (protocol-const → daemon + webapp; iOS; " +
        "Android — the SAME value). It cannot be undone.",
    );
  }
  return 0;
}
