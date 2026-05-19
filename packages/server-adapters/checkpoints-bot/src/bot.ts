/**
 * Checkpoint-bot I/O adapter — the PURE core.
 *
 * **LOCKED Phase-H v0.1 model** (spec
 * docs/maintainers-checkpoints-spec-v0.1.md §21 "A GitHub Action or bot
 * that validates …"; the rules it enforces are §10/§11/§7/§12/§13).
 *
 * This file is the analogue of the Cloudflare Worker's `policy.ts`: it
 * holds the PURE decision/effect plumbing. Every byte of real I/O —
 * reading the PR payload, fetching the project's `.maintainers/` chain,
 * reading/appending the checkpoints CSV, posting the PR decision — lives
 * in the thin `action.ts` entrypoint (the analogue of `worker.ts`) and is
 * supplied here via the injected {@link CheckpointBotDeps}.
 *
 * The rules themselves are NOT re-implemented: this module marshals the
 * injected I/O into a {@link CheckpointSubmissionInput} and calls the
 * landed, conformance-tested {@link validateCheckpointSubmission} verbatim
 * (exactly as `policy.ts` reuses `verifyMandateChainFromPin` /
 * `currentAuthority`). It then turns the {@link CheckpointDecision} into a
 * structured {@link BotOutcome}: the EFFECTS as DATA — on accept, the
 * single 4-column CSV line to append (§7 append-only — a line to append,
 * never a rewrite) plus (iff rule-11 over-cap) the maintainer-ping
 * descriptor; on reject, the human-readable PR decision to post.
 *
 * Effects are returned as data AND, when sinks are injected, applied
 * through them ({@link CheckpointBotDeps.appendCsvLine} /
 * {@link CheckpointBotDeps.postPrDecision}) so the core stays pure and the
 * sinks are the only thing that touches the world. With no sinks the
 * function is a pure decision→effect-data mapper (the form the hermetic
 * tests exercise).
 *
 * Imports are restricted to the protocol package — there is deliberately
 * NO node:fs / node:net / node:child_process here (that is `action.ts`).
 */

import {
  validateCheckpointSubmission,
  type CheckpointDecision,
  type CheckpointPrPayload,
  type CheckpointRow,
  type CheckpointAction,
  type CheckpointRejectReason,
  type CheckpointSubmissionInput,
  type ExistingCheckpointRow,
  type ProjectChainMaterial,
} from "@ibisllc/maintainers";

export type {
  CheckpointDecision,
  CheckpointPrPayload,
  CheckpointRow,
  CheckpointAction,
  CheckpointRejectReason,
  ExistingCheckpointRow,
  ProjectChainMaterial,
} from "@ibisllc/maintainers";

/**
 * The booleans `validateCheckpointSubmission` consumes for the inherently
 * I/O rules 1/2/9 — the ADAPTER does not decide these; the injected
 * fetcher (a `git`/HTTPS shell in `action.ts`) reports them, exactly as
 * the spec's "the Action performs them and passes the RESULTS in".
 */
export interface FetchedProjectChain {
  /** The fetched chain material for the payload's track (rule 3/4/§11). */
  chainMaterial: ProjectChainMaterial;
  /** rule 1: the canonical project repo was publicly reachable. */
  repoReachable: boolean;
  /** rule 2: the declared `.maintainers/` path exists in that repo. */
  maintainersPathExists: boolean;
  /** rule 9: the checkpoint file path matches the declared canonical repo. */
  pathMatchesCanonicalRepo: boolean;
}

/**
 * The maintainer-ping descriptor emitted (as DATA) on a rule-11 over-cap
 * accept. This is the spec §10-rule-11 manual-verification flow: the bot
 * "auto-sends the project maintainer an 'is everything OK …' email; an
 * opened ticket escalates to a human reviewer." The PURE core only
 * *describes* the ping; `action.ts` (or an injected sink) performs it.
 */
export interface MaintainerPing {
  kind: "manual-verification";
  reason: "rate-cap";
  detail: string;
  /** The (project, track) the over-cap volume was observed on. */
  canonicalRepo: string;
  track: string;
}

/**
 * The reject effect emitted (as DATA) when the submission fails any of
 * rules 1–10 / §11 continuity. The Action posts `label` + `reason` on the
 * PR and does NOT touch the CSV (no append on reject — rule 7).
 */
export interface PrDecision {
  state: "rejected";
  /** The closed reject taxonomy from the protocol verifier (1:1 §10). */
  reason: CheckpointRejectReason;
  /** Human-readable detail from the verifier, when present. */
  detail?: string;
  /** A short PR label the Action applies (e.g. `checkpoint:rejected`). */
  label: string;
}

/**
 * What the Action must DO, expressed purely as data. Exactly one of:
 *
 *  - `accept` — append `csvLine` (the §7 4-column line, the ONLY mutation,
 *    never a rewrite) and, iff `ping` is present (rule-11 fail-open),
 *    open the maintainer manual-verification flow. `decision` carries the
 *    full {@link CheckpointDecision} (incl. the structured `row`).
 *  - `reject` — post `pr` on the PR; make NO CSV mutation.
 */
export type BotOutcome =
  | {
      kind: "accept";
      decision: Extract<CheckpointDecision, { accept: true }>;
      /** The single §7 line to append: `observed_at,track,hash,flagged`. */
      csvLine: string;
      /** The parsed row behind `csvLine` (same data, structured). */
      row: CheckpointRow;
      /** rule-11 fail-open only: the maintainer-ping descriptor. */
      ping?: MaintainerPing;
    }
  | {
      kind: "reject";
      decision: Extract<CheckpointDecision, { accept: false }>;
      pr: PrDecision;
    };

/**
 * Injected I/O. The PURE core never touches the world itself: the Action
 * supplies a payload reader, a chain fetcher, an existing-rows reader, the
 * clock, and OPTIONAL effect sinks. Mirrors how the Worker entrypoint
 * supplies `policy.ts` its `RepoState` + `now`.
 */
export interface CheckpointBotDeps {
  /** Parse the submitted §9 `botPayload` (CLI-emitted) from the PR. */
  parsePayload: () => CheckpointPrPayload | Promise<CheckpointPrPayload>;
  /**
   * Fetch the project's `.maintainers/` chain for `track` and report the
   * inherently-I/O rule-1/2/9 booleans. The adapter does NOT decide them.
   */
  fetchProjectChain: (
    canonicalRepo: string,
    maintainersPath: string,
    sourceCommit: string,
    track: string,
  ) => FetchedProjectChain | Promise<FetchedProjectChain>;
  /** Currently-present CSV rows for this (project, track), in file order. */
  readExistingRows: (
    track: string,
  ) => ExistingCheckpointRow[] | Promise<ExistingCheckpointRow[]>;
  /** The bot's clock; `observed_at` is assigned from this (rule 8). */
  now: Date;
  /** rule-11 cap override; defaults to the spec's N=6 / 30 rolling days. */
  rateCap?: { maxPerWindow?: number; windowDays?: number };
  /**
   * OPTIONAL accept sink — append exactly one §7 line (never a rewrite).
   * When absent the line is returned in {@link BotOutcome} only.
   */
  appendCsvLine?: (
    track: string,
    line: string,
  ) => void | Promise<void>;
  /**
   * OPTIONAL effect sink for both branches: post the PR decision and/or
   * open the rule-11 maintainer-ping. When absent the effects are
   * returned in {@link BotOutcome} only.
   */
  postPrDecision?: (
    outcome: BotOutcome,
  ) => void | Promise<void>;
}

const PR_LABEL_BY_REASON: Record<CheckpointRejectReason, string> = {
  "repo-unreachable": "checkpoint:rejected:repo-unreachable",
  "maintainers-path-missing": "checkpoint:rejected:path-missing",
  "path-mismatch": "checkpoint:rejected:path-mismatch",
  "payload-malformed": "checkpoint:rejected:payload-malformed",
  "hash-format-invalid": "checkpoint:rejected:hash-format",
  "hash-not-in-history": "checkpoint:rejected:hash-not-in-history",
  "chain-invalid": "checkpoint:rejected:chain-invalid",
  "authority-invalid": "checkpoint:rejected:authority-invalid",
  "request-repo-mismatch": "checkpoint:rejected:request-repo-mismatch",
  "continuity-broken": "checkpoint:rejected:continuity-broken",
  "not-append-only": "checkpoint:rejected:not-append-only",
  "no-op": "checkpoint:rejected:no-op",
};

/**
 * The §7 CSV serialization of a {@link CheckpointRow}. The schema is
 * fixed (`observed_at,track,current_mandate_hash,flagged`, in this order)
 * and every field is constrained by the verifier to a CSV-safe token (an
 * ISO seconds timestamp, a lowercase track id, a `sha256:<hex>`, and
 * `""`|`"rate-cap"`), so no quoting/escaping is required — this is a
 * deliberately minimal append (spec §7). NOT a rewrite: the Action
 * appends this single line to the project's existing file.
 */
export function checkpointRowToCsvLine(row: CheckpointRow): string {
  return `${row.observed_at},${row.track},${row.current_mandate_hash},${row.flagged}`;
}

/**
 * Run the landed checkpoint-bot verifier on a submitted PR.
 *
 * PURE w.r.t. decision logic: it injects no I/O of its own — it pulls the
 * payload / chain / rows / clock from {@link CheckpointBotDeps}, calls
 * {@link validateCheckpointSubmission} VERBATIM (no rule re-implemented),
 * and maps the {@link CheckpointDecision} to a {@link BotOutcome} whose
 * effects are DATA. If accept/reject sinks are injected they are then
 * invoked (the only place the world is touched, and only via the caller's
 * own functions); with no sinks this is a total decision→effect-data map.
 */
export async function runCheckpointBotOnSubmission(
  deps: CheckpointBotDeps,
): Promise<BotOutcome> {
  const payload = await deps.parsePayload();
  const fetched = await deps.fetchProjectChain(
    payload.canonicalRepo,
    payload.maintainersPath,
    payload.sourceCommit,
    payload.track,
  );
  const existingRows = await deps.readExistingRows(payload.track);

  const input: CheckpointSubmissionInput = {
    payload,
    chainMaterial: fetched.chainMaterial,
    existingRows,
    now: deps.now,
    repoReachable: fetched.repoReachable,
    maintainersPathExists: fetched.maintainersPathExists,
    pathMatchesCanonicalRepo: fetched.pathMatchesCanonicalRepo,
    ...(deps.rateCap ? { rateCap: deps.rateCap } : {}),
  };

  // Reuse the conformance-tested verifier verbatim — no rule re-derived.
  const decision: CheckpointDecision = validateCheckpointSubmission(input);

  let outcome: BotOutcome;
  if (decision.accept) {
    const csvLine = checkpointRowToCsvLine(decision.row);
    outcome = {
      kind: "accept",
      decision,
      csvLine,
      row: decision.row,
      ...(decision.action
        ? {
            ping: pingFromAction(
              decision.action,
              payload.canonicalRepo,
              payload.track,
            ),
          }
        : {}),
    };
  } else {
    outcome = {
      kind: "reject",
      decision,
      pr: {
        state: "rejected",
        reason: decision.reason,
        ...(decision.detail !== undefined ? { detail: decision.detail } : {}),
        label: PR_LABEL_BY_REASON[decision.reason],
      },
    };
  }

  // Effect sinks (optional). The core decided; the caller's functions are
  // the ONLY thing that touches the world. Append happens ONLY on accept
  // and is a single-line append (rule 7 — never a rewrite); the PR
  // decision sink fires on both branches.
  if (outcome.kind === "accept" && deps.appendCsvLine) {
    await deps.appendCsvLine(outcome.row.track, outcome.csvLine);
  }
  if (deps.postPrDecision) {
    await deps.postPrDecision(outcome);
  }

  return outcome;
}

/** Map the verifier's {@link CheckpointAction} onto the ping descriptor. */
function pingFromAction(
  action: CheckpointAction,
  canonicalRepo: string,
  track: string,
): MaintainerPing {
  return {
    kind: action.kind,
    reason: action.reason,
    detail: action.detail,
    canonicalRepo,
    track,
  };
}
