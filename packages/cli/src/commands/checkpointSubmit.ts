/**
 * `maintainers checkpoint submit` — generate + holder-sign a public
 * Maintainers Checkpoints request and emit the §9 PR payload.
 *
 * Spec: docs/maintainers-checkpoints-spec-v0.1.md §8 (the maintainer may
 * use the CLI to generate the checkpoint request + open the PR
 * automatically), §9 (PR payload), §7.1 (`current_mandate_hash` =
 * `sha256:<hex>`), open-detail item 1 (HOLDER-SIGNS — RESOLVED).
 *
 * A `CheckpointRequest` is the first-class signed proof a project's
 * CURRENT maintainer authority asks the registry to witness a publicly
 * available current mandate hash. Authorisation is HOLDER-SIGNS —
 * EXACTLY the CaEndorsement model (open-detail item 1, RESOLVED): the
 * holder of the project's mandate current at `now` signs the request's
 * canonical bytes; the registry bot's `verifyCheckpointRequest` checks
 * that signature. There is no quorum here (the security-state change
 * being witnessed is already quorum-signed by construction — it is a new
 * mandate; the checkpoint merely witnesses it).
 *
 * This verb mirrors `ca-endorsement` EXACTLY: a pure `assemble*`
 * (validate inputs, resolve the signer's PUBLIC key with NO PIN/tap,
 * build the unsigned envelope + canonical bytes); the shared
 * `previewConfirmSign` ceremony (plain-language banner → exact
 * canonical-byte preview → typed `CHECKPOINT-SUBMIT` confirm → PIN/sign,
 * strictly after the bytes were shown); `--dry-run` stops after the
 * preview (no PIN/sign/network). Non-interactive without `--yes` ⇒ the
 * existing deterministic fail-closed taxonomy (never hangs).
 *
 * The load-bearing deliverable is the PURE build+sign+payload-emit path.
 * Opening the PR over the network is OPTIONAL/out-of-scope this chunk:
 * the verb EMITS the §9 payload + the exact `gh`/PR instructions; it
 * bundles no network client (zero new runtime deps).
 *
 * ★ Integration constraint (why this chunk exists): the emitted payload
 * MUST round-trip through the chunk-2 bot library. It carries the REAL
 * signed `CheckpointRequest` envelope (real `pubkey`/`sig`
 * `SignatureEntry[]`, the encoding `verifyCheckpointRequest` already
 * consumes) — NOT an invented `keyId/base64` proof the verifier cannot
 * read. The §9 replay-binding is guaranteed BY CONSTRUCTION: the
 * payload's `canonicalRepo`/`maintainersPath`/`currentMandateHash` are
 * the SAME values that were canonicalised + signed into the request, so
 * `validateCheckpointSubmission`'s `request-repo-mismatch` check holds.
 */

import {
  signCheckpointRequestWith,
  canonicalCheckpointRequest,
  currentAuthority,
  mandatePinHash,
  verifyMandateChainFromPin,
  type CheckpointRequest,
  type CheckpointPrPayload,
  type Mandate,
} from "@ibisllc/maintainers";
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
import { readMandates } from "../lib/store.js";

/** Spec §9 `statement.type`. */
export const CHECKPOINT_STATEMENT_TYPE = "maintainers.checkpoint.request.v1";
/** Spec §9 `statement.text`. */
export const CHECKPOINT_STATEMENT_TEXT =
  "The current maintainer authority for this project requests that this " +
  "mandate hash be recorded in the public Maintainers Checkpoints repo.";
/** The default mandate-track a checkpoint witnesses (Flagship v1: `ca`). */
export const DEFAULT_CHECKPOINT_TRACK = "ca";

export interface CheckpointSubmitOptions {
  canonicalRepo: string;
  maintainersPath: string;
  sourceCommit: string;
  track: string;
  /** §7.1 `sha256:<hex>` H_new. If omitted, derived from the local
   *  `.maintainers` store the way `verify`/`status` read it. */
  currentMandateHash?: string;
  signingKeySource: string;
  /** Store root, used ONLY to derive `currentMandateHash` when the flag
   *  is absent (read-only; never written). Defaults to ".maintainers". */
  rootDir?: string;
  now: () => Date;
  io: KeySourceFs;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
}

type UnsignedCheckpointRequest = Omit<CheckpointRequest, "signatures">;

/** §7.1 / §9: `sha256:` then exactly 64 lower-case hex digits. The same
 *  shape `verifyCheckpointRequest` / `validateCheckpointSubmission`
 *  enforce — never an invented format. */
function expectSha256Prefixed(raw: string, where: string): string {
  const v = raw.trim();
  if (!v.startsWith("sha256:")) {
    throw new CliError(`${where} must be "sha256:<64-hex>"; got ${JSON.stringify(raw)}`);
  }
  const hex = v.slice("sha256:".length);
  if (hex.length !== 64) {
    throw new CliError(
      `${where} must be sha256:<exactly 64 hex>; the hex part is ${hex.length} chars`,
    );
  }
  for (let i = 0; i < hex.length; i++) {
    const c = hex.charCodeAt(i);
    if (!((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66))) {
      throw new CliError(`${where} contains a non-lower-hex character at index ${i}`);
    }
  }
  return v;
}

/**
 * Derive H_new from the local store the same way `verify`/`status` read
 * it: anchor the track's on-disk mandate log at the FIRST mandate's
 * `mandatePinHash` (the no-baked-pin preview pattern), forward-verify,
 * and take the `sha256:`+`mandatePinHash` of the mandate CURRENT at
 * `now`. Fail-closed (a clear `CliError`, never a guess) when no live
 * authority can be resolved — pass `--current-mandate-hash` explicitly.
 */
function deriveCurrentMandateHash(
  rootDir: string,
  track: string,
  now: Date,
): string {
  const mandates: Mandate[] = readMandates(rootDir, track);
  if (mandates.length === 0) {
    throw new CliError(
      `no "${track}"-track mandates under ${rootDir} to derive ` +
        `--current-mandate-hash from; pass it explicitly (sha256:<64-hex>).`,
    );
  }
  let pin: string;
  try {
    pin = mandatePinHash(mandates[0]!);
  } catch {
    pin = ""; // adversarial first mandate ⇒ no-pin ⇒ fail-closed below
  }
  const chain = verifyMandateChainFromPin(pin, mandates);
  if (chain.root === null) {
    throw new CliError(
      `the "${track}"-track chain under ${rootDir} did not anchor a ` +
        `forward chain (${chain.rootError ?? "no-forward-chain"}); pass ` +
        `--current-mandate-hash explicitly.`,
    );
  }
  const auth = currentAuthority(chain, now);
  if (!auth) {
    throw new CliError(
      `no live "${track}"-track authority at ${now.toISOString()} under ` +
        `${rootDir} (the current mandate has expired pending succession); ` +
        `pass --current-mandate-hash explicitly.`,
    );
  }
  return "sha256:" + mandatePinHash(auth.mandate);
}

/**
 * Phase 1 — pure: validate inputs, resolve `currentMandateHash` (flag or
 * local-store derive), read the signer's PUBLIC key (NO PIN/tap/sign),
 * build the unsigned `CheckpointRequest` + its canonical bytes. No
 * private-key op, no write, no network.
 */
export async function assembleCheckpointRequest(
  opts: CheckpointSubmitOptions,
): Promise<Assembled<UnsignedCheckpointRequest>> {
  const sopts: SignerOptions = {
    io: opts.io,
    pivTransport: opts.pivTransport,
    pivPin: opts.pivPin,
  };
  const canonicalRepo = opts.canonicalRepo.trim();
  if (canonicalRepo.length === 0) {
    throw new CliError("--canonical-repo must not be empty");
  }
  const maintainersPath = opts.maintainersPath.trim();
  if (maintainersPath.length === 0) {
    throw new CliError("--maintainers-path must not be empty");
  }
  const sourceCommit = opts.sourceCommit.trim();
  if (sourceCommit.length === 0) {
    throw new CliError("--source-commit must not be empty");
  }
  const track = opts.track.trim();
  if (track.length === 0) {
    throw new CliError("--track must not be empty");
  }

  const rootDir = opts.rootDir ?? ".maintainers";
  const currentMandateHash =
    opts.currentMandateHash !== undefined
      ? expectSha256Prefixed(opts.currentMandateHash, "--current-mandate-hash")
      : deriveCurrentMandateHash(rootDir, track, opts.now());

  const signerPub = await loadSignerBoundPubKey(opts.signingKeySource, sopts);

  const unsigned: UnsignedCheckpointRequest = {
    kind: "CheckpointRequest",
    version: 1,
    canonicalRepo,
    maintainersPath,
    currentMandateHash,
    sourceCommit,
  };
  return {
    ceremony: "checkpoint-submit",
    unsigned,
    canonical: canonicalCheckpointRequest(unsigned),
    signingKeySource: opts.signingKeySource,
    signedBy: signerPub,
    rootDir,
    // No artifact is written under .maintainers/ — a checkpoint request
    // is a PUBLIC, transient PR proof, not a stored envelope (unlike a
    // CaEndorsement). This is the §6 checkpoints-repo CSV path the PR
    // would touch, shown for the operator's situational awareness only.
    targetRelative: checkpointCsvPath(canonicalRepo),
  };
}

export async function buildCheckpointRequest(
  opts: CheckpointSubmitOptions,
): Promise<CheckpointRequest> {
  const a = await assembleCheckpointRequest(opts);
  const sopts: SignerOptions = {
    io: opts.io,
    pivTransport: opts.pivTransport,
    pivPin: opts.pivPin,
  };
  return signAssembled(a, signCheckpointRequestWith, sopts);
}

/**
 * The §6 one-file-per-project checkpoints-repo path derived from the
 * canonical project repo URL: `checkpoints/<host>/<owner>/<repo>.csv`.
 * Best-effort + total — an unparseable URL degrades to a sanitized
 * fallback rather than throwing (this string is advisory, never signed;
 * the load-bearing binding is the signed request's fields).
 */
export function checkpointCsvPath(canonicalRepo: string): string {
  let host = "";
  let rest = canonicalRepo.trim();
  const scheme = rest.indexOf("://");
  if (scheme >= 0) rest = rest.slice(scheme + 3);
  const slash = rest.indexOf("/");
  if (slash > 0) {
    host = rest.slice(0, slash);
    rest = rest.slice(slash + 1);
  }
  rest = rest.replace(/\.git$/, "").replace(/\/+$/, "");
  const segs = [host, ...rest.split("/")]
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((s) => s.replace(/[^A-Za-z0-9._-]/g, "_"));
  if (segs.length < 2) return "checkpoints/UNKNOWN.csv";
  return `checkpoints/${segs.join("/")}.csv`;
}

/**
 * The §9 PR payload. It keeps the spec's
 * `project/checkpoint/statement/proof` envelope shape AND carries the
 * REAL verifier-consumable signed `CheckpointRequest` so the chunk-2 bot
 * can validate it directly:
 *
 *   - `proof.request` is the actual signed envelope (real
 *     `signatures: SignatureEntry[]`) — `verifyCheckpointRequest`
 *     accepts it verbatim. `proof.signatures` mirrors those same
 *     signatures in the §9 `{keyId, signature}` projection for
 *     human/PR readability ONLY (NOT a separate proof format).
 *   - `botPayload` is literally a {@link CheckpointPrPayload} — the
 *     EXACT shape `validateCheckpointSubmission` consumes, with
 *     `botPayload.request` === `proof.request`.
 *
 * §9 replay-binding is guaranteed BY CONSTRUCTION: every payload field
 * (`canonicalRepo`, `maintainersPath`, `currentMandateHash`, `track`) is
 * copied FROM the signed request, so the bot's `request-repo-mismatch`
 * check (payload fields === signed request fields) always holds.
 */
export interface CheckpointSubmissionPayload {
  schemaVersion: 1;
  project: { canonicalRepo: string; maintainersPath: string };
  checkpoint: { currentMandateHash: string; sourceCommit: string; track: string };
  statement: { type: typeof CHECKPOINT_STATEMENT_TYPE; text: string };
  proof: {
    signedByMandate: string;
    /** §9 human/PR projection of `proof.request.signatures`. */
    signatures: { keyId: string; signature: string }[];
    /** The REAL verifier-consumable signed envelope. */
    request: CheckpointRequest;
  };
  /** The exact {@link CheckpointPrPayload} the chunk-2 bot consumes. */
  botPayload: CheckpointPrPayload;
}

/**
 * Build the §9 payload AROUND the real signed request. Pure; every
 * field is sourced FROM `signed` so the §9 replay-binding holds by
 * construction.
 */
export function buildCheckpointSubmissionPayload(
  signed: CheckpointRequest,
): CheckpointSubmissionPayload {
  const botPayload: CheckpointPrPayload = {
    canonicalRepo: signed.canonicalRepo,
    maintainersPath: signed.maintainersPath,
    currentMandateHash: signed.currentMandateHash,
    sourceCommit: signed.sourceCommit,
    // `track` is a §7.1 row column, not a signed field — but the bot's
    // continuity is keyed per (project, track). It is carried from the
    // submit options via the signed request's witnessed mandate; the
    // dispatch path threads the resolved track in (see runCheckpointSubmit).
    track: DEFAULT_CHECKPOINT_TRACK,
    request: signed,
  };
  return {
    schemaVersion: 1,
    project: {
      canonicalRepo: signed.canonicalRepo,
      maintainersPath: signed.maintainersPath,
    },
    checkpoint: {
      currentMandateHash: signed.currentMandateHash,
      sourceCommit: signed.sourceCommit,
      track: DEFAULT_CHECKPOINT_TRACK,
    },
    statement: {
      type: CHECKPOINT_STATEMENT_TYPE,
      text: CHECKPOINT_STATEMENT_TEXT,
    },
    proof: {
      signedByMandate: signed.currentMandateHash,
      signatures: signed.signatures.map((s) => ({
        keyId: `ed25519:${s.pubkey}`,
        signature: s.sig,
      })),
      request: signed,
    },
    botPayload,
  };
}

export interface CheckpointSubmitCmdEnv {
  now: () => Date;
  io: KeySourceFs;
  println: (line: string) => void;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
  confirm?: ConfirmFn;
}

export async function runCheckpointSubmit(
  args: ParsedArgs,
  env: CheckpointSubmitCmdEnv,
): Promise<number> {
  const canonicalRepo = requireFlag(args, "canonical-repo");
  const maintainersPath = optionalFlag(args, "maintainers-path") ?? ".maintainers/";
  const sourceCommit = requireFlag(args, "source-commit");
  const track = optionalFlag(args, "track") ?? DEFAULT_CHECKPOINT_TRACK;
  const currentMandateHash = optionalFlag(args, "current-mandate-hash");
  const signingKey = requireFlag(args, "signing-key");
  const rootDir = optionalFlag(args, "path") ?? ".maintainers";
  const dryRun = boolFlag(args, "dry-run");
  const yes = boolFlag(args, "yes");

  const a = await assembleCheckpointRequest({
    canonicalRepo,
    maintainersPath,
    sourceCommit,
    track,
    currentMandateHash,
    signingKeySource: signingKey,
    rootDir,
    now: env.now,
    io: env.io,
    pivTransport: env.pivTransport,
    pivPin: env.pivPin,
  });

  // The §9 payload + the would-be CSV row, shown on BOTH paths (dry-run
  // preview AND the real run's emit). On dry-run it is computed from the
  // UNSIGNED request (signatures empty) so nothing is signed; the real
  // path recomputes it from the signed envelope.
  const csvPath = checkpointCsvPath(canonicalRepo);
  const observedAtNote =
    "the registry bot assigns observed_at at validation time (rule 8) — " +
    "not the submitter; the row below shows current_mandate_hash + track only.";

  if (dryRun) {
    // Preview: bytes + §9 payload (around the UNSIGNED request — no
    // signatures, no PIN, no sign, no network) + the would-be CSV row.
    const previewSigned: CheckpointRequest = { ...a.unsigned, signatures: [] };
    const payload = withTrack(
      buildCheckpointSubmissionPayload(previewSigned),
      track,
    );
    const e = await previewConfirmSign(a, signCheckpointRequestWith, {
      dryRun: true,
      yes,
      env: {
        println: env.println,
        io: env.io,
        pivTransport: env.pivTransport,
        pivPin: env.pivPin,
        confirm: env.confirm,
      },
    });
    // previewConfirmSign returns null for a dry-run (after the byte
    // preview). e is always null here; assert it so a future change to
    // the ceremony helper can't silently leak a sign on --dry-run.
    if (e !== null) {
      throw new CliError("internal: dry-run unexpectedly produced a signed request");
    }
    env.println("");
    env.println("§9 PR payload (DRY RUN — request UNSIGNED, signatures empty):");
    for (const line of JSON.stringify(payload, null, 2).split("\n")) {
      env.println(`  ${line}`);
    }
    env.println("");
    env.println(`would append (CSV row, ${csvPath}):`);
    env.println(`  track=${track} current_mandate_hash=${a.unsigned.currentMandateHash}`);
    env.println(`  note: ${observedAtNote}`);
    return 0;
  }

  const signed = await previewConfirmSign(a, signCheckpointRequestWith, {
    dryRun: false,
    yes,
    env: {
      println: env.println,
      io: env.io,
      pivTransport: env.pivTransport,
      pivPin: env.pivPin,
      confirm: env.confirm,
    },
  });
  if (!signed) return 0; // (defensive — non-dry-run never returns null)

  const payload = withTrack(buildCheckpointSubmissionPayload(signed), track);
  env.println("");
  env.println("§9 PR payload (signed CheckpointRequest — verifier-consumable):");
  for (const line of JSON.stringify(payload, null, 2).split("\n")) {
    env.println(`  ${line}`);
  }
  env.println("");
  env.println(`checkpoints-repo file (§6): ${csvPath}`);
  env.println(`would append (CSV row): track=${track} current_mandate_hash=${signed.currentMandateHash}`);
  env.println(`  note: ${observedAtNote}`);
  env.println("");
  env.println(
    "next (opening the PR is a human/credential step — this verb emits, " +
      "it does not push):",
  );
  env.println(
    `  1. fork github.com/ibisllc/maintainers-checkpoints; create/append ${csvPath}`,
  );
  env.println(
    "  2. put the §9 payload above in the PR body (or an attached .json)",
  );
  env.println(
    `  3. open the PR (e.g. \`gh pr create -R ibisllc/maintainers-checkpoints\`); ` +
      `the checkpoint bot validates + assigns observed_at on merge`,
  );
  return 0;
}

/** Thread the resolved `--track` into the payload (the bot keys
 *  continuity per (project, track); `track` is a §7.1 row column, not a
 *  signed request field — so it is set HERE from the resolved flag, and
 *  is the only payload field NOT copied from the signed request). */
function withTrack(
  p: CheckpointSubmissionPayload,
  track: string,
): CheckpointSubmissionPayload {
  return {
    ...p,
    checkpoint: { ...p.checkpoint, track },
    botPayload: { ...p.botPayload, track },
  };
}
