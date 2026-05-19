/**
 * Checkpoint-registry bot validation rules — the PURE decision logic a
 * `maintainers-checkpoints` PR validator runs (spec
 * docs/maintainers-checkpoints-spec-v0.1.md §10 rules 1–11, §11
 * continuity, §12 first-checkpoint, §13 authority).
 *
 * This module is RUNTIME-AGNOSTIC and TOTAL exactly like the sibling
 * protocol verifiers ({@link verifyMandateChainFromPin},
 * {@link verifyCheckpointRequest}, {@link verifyCaEndorsements}): all I/O
 * is INJECTED — there is no network/git/fs/octokit here. The thin
 * GitHub-Action shell (a later Phase-H chunk) fetches the repo, reads the
 * CSV, checks path/reachability, then calls {@link
 * validateCheckpointSubmission} with already-parsed data.
 *
 *   - Rules 1, 2, 9 (repo reachable / path exists / path matches the
 *     canonical repo) are inherently I/O. The Action performs them and
 *     passes the RESULTS in as booleans/strings; the library only
 *     validates those results.
 *   - Rules 3, 4, 5, 6/§11, §12 (hash-in-history, chain validity,
 *     authority/holder-signs, continuity, first-checkpoint) are pure and
 *     run here, REUSING the landed protocol verifiers — never
 *     re-implemented:
 *       · rule 3   — the requested hash equals `sha256:` +
 *                    {@link mandatePinHash} of some mandate in the
 *                    project's fetched `.maintainers/` chain material.
 *       · rule 4   — {@link verifyMandateChainFromPin} anchors a valid
 *                    forward chain at the project pin.
 *       · rule 5   — {@link verifyCheckpointRequest}: HOLDER-SIGNS
 *                    (open-detail item 1, RESOLVED) — the request carries
 *                    a signature from the holder of the mandate current
 *                    at `now`; NOT the succession quorum.
 *       · §11      — H_old (the latest currently-present prior row for
 *                    this (project, track), flagged rows included) must
 *                    appear in the project's verified chain leading to
 *                    H_new — prunable-witness-aware (pruning only moves
 *                    the anchor earlier; never a false continuity-break).
 *       · §12      — first checkpoint: no H_old; rules 3/4/5/9 still
 *                    enforced.
 *   - Rule 7 (append-only) is validated from the injected pre-existing
 *     row set (the library emits the row to APPEND; it never rewrites).
 *   - Rule 8 (bot-assigned timestamp): `observed_at` is assigned from the
 *     injected `now`, NEVER trusted from the submitter.
 *   - Rule 10 (no-op): H_new equal to the most-recent witnessed hash for
 *     the same track ⇒ reject.
 *   - Rule 11 (rate cap) is the ONE deliberate FAIL-OPEN: an over-cap
 *     submission that passed rules 1–10 + §11 is still `accept:true`
 *     with `flagged:"rate-cap"` and a signalled manual-verification
 *     action — NEVER a reject (a witness that refuses mid-incident fails
 *     when needed most).
 *
 * Fail-closed everywhere else (mirrors the protocol verifiers): an
 * absent/forked pin or unverifiable chain ⇒ reject; a malformed field
 * that makes canonicalization throw is CAUGHT and recorded as a reason,
 * never an exception.
 */

import { mandatePinHash } from "./canonical.js";
import {
  verifyCheckpointRequest,
  type CheckpointRequestFailReason,
} from "./checkpointRequest.js";
import { currentAuthority, verifyMandateChainFromPin } from "./verifier.js";
import type { CheckpointRequest, Mandate } from "./types.js";

/** The §7 4-column CSV row this library emits for the Action to append. */
export interface CheckpointRow {
  /** §7.1: UTC `YYYY-MM-DDTHH:MM:SSZ`, BOT-ASSIGNED from `now` (rule 8). */
  observed_at: string;
  /** §7.1: the per-(project,track) lineage key; never blank. */
  track: string;
  /** §7.1: `sha256:<hex>` — the witnessed current mandate hash. */
  current_mandate_hash: string;
  /** §7.1: "" normally, or "rate-cap" when rule 11's cap was exceeded. */
  flagged: "" | "rate-cap";
}

/**
 * An already-parsed pre-existing CSV row for the target (project, track).
 * The caller parses the §7 CSV; the library treats this list as the
 * source of H_old (§11) and the rule-7 append-only / rule-10 no-op /
 * rule-11 rate-window inputs. Rows are the project's CURRENTLY-PRESENT
 * rows only (a pruned/sparse history is expected and MUST NOT yield a
 * false continuity-break — §11 prunable-witness).
 */
export interface ExistingCheckpointRow {
  observed_at: string;
  track: string;
  current_mandate_hash: string;
  flagged: string;
}

/**
 * The closed reject taxonomy — one reason per spec rule, mirroring the
 * sibling verifiers' `*FailReason` unions. `authority-invalid` carries
 * the exact {@link CheckpointRequestFailReason} sub-reason (rule 5 / §13
 * holder-signs) so the caller keeps the precise protocol diagnosis.
 */
export type CheckpointRejectReason =
  | "repo-unreachable" // rule 1 (I/O result, supplied by the caller)
  | "maintainers-path-missing" // rule 2 (I/O result, supplied by the caller)
  | "path-mismatch" // rule 9 (I/O result, supplied by the caller)
  | "payload-malformed" // §9 payload shape / track not a non-empty string
  | "hash-format-invalid" // §7.1 / §9: H_new not a `sha256:<hex>` string
  | "hash-not-in-history" // rule 3
  | "chain-invalid" // rule 4
  | "authority-invalid" // rule 5 / §13 (holder-signs via verifyCheckpointRequest)
  | "request-repo-mismatch" // §9: the signed request must bind the declared repo/path/hash
  | "continuity-broken" // §11 (rollback / fork / history rewrite)
  | "not-append-only" // rule 7
  | "no-op"; // rule 10 (equals the most-recent witnessed hash for the track)

/**
 * A non-blocking action the bot SIGNALS to the (out-of-scope) Action
 * shell. v0.1: only the rule-11 manual-verification ping (maintainer
 * email → optional human ticket). Pure: the library decides, the shell
 * performs.
 */
export interface CheckpointAction {
  kind: "manual-verification";
  /** Why the human-review flow was opened (v0.1: the §10 rule-11 cap). */
  reason: "rate-cap";
  detail: string;
}

export type CheckpointDecision =
  | {
      accept: true;
      /** The §7 row the Action should append (rule 7 — never rewrite). */
      row: CheckpointRow;
      /**
       * Present iff `row.flagged === "rate-cap"` (rule 11 fail-OPEN):
       * the signalled manual-verification action. Absent on a normal
       * accept.
       */
      action?: CheckpointAction;
    }
  | { accept: false; reason: CheckpointRejectReason; detail?: string };

/**
 * The §9 PR payload, ALREADY parsed by the (out-of-scope) Action. Only
 * the fields the pure bot logic consumes are modelled; the rich proof is
 * the {@link CheckpointRequest} envelope itself (verified holder-signs).
 */
export interface CheckpointPrPayload {
  /** §9: canonical public project repo URL. */
  canonicalRepo: string;
  /** §9: path to `.maintainers/` within that repo. */
  maintainersPath: string;
  /** §9: claimed current mandate hash, `sha256:<hex>` (§7.1). */
  currentMandateHash: string;
  /** §9: source commit / ref where the chain is publicly available. */
  sourceCommit: string;
  /** The §7.1 mandate-track this row witnesses (item-5 multi-track). */
  track: string;
  /** §9 proof: the first-class signed CheckpointRequest envelope. */
  request: CheckpointRequest;
}

/**
 * The project's fetched `.maintainers/` chain material for `track`,
 * ALREADY fetched/parsed by the Action: the baked/registry pin the chain
 * is anchored at + the track's mandate log (oldest-first). The library
 * runs {@link verifyMandateChainFromPin} over this — it does NOT fetch.
 */
export interface ProjectChainMaterial {
  /** the pin {@link verifyMandateChainFromPin} anchors at (§11 anchor). */
  pin: string;
  /** the track's mandate log in canonical (oldest-first) order. */
  mandates: Mandate[];
}

export interface CheckpointSubmissionInput {
  payload: CheckpointPrPayload;
  /** The fetched chain material for the payload's track (rule 3/4/§11). */
  chainMaterial: ProjectChainMaterial;
  /**
   * Pre-existing CURRENTLY-PRESENT CSV rows for the SAME (project,track)
   * — already parsed, in file order. Empty ⇒ §12 first checkpoint.
   * Prunable-witness-aware: a sparse list is fine (§11).
   */
  existingRows: ExistingCheckpointRow[];
  /** The bot's clock. `observed_at` is assigned from this (rule 8). */
  now: Date;
  /** rule 1 result, supplied by the caller (inherently I/O). */
  repoReachable: boolean;
  /** rule 2 result, supplied by the caller (inherently I/O). */
  maintainersPathExists: boolean;
  /** rule 9 result, supplied by the caller (path↔canonical-repo, I/O). */
  pathMatchesCanonicalRepo: boolean;
  /**
   * rule 11 rolling rate cap per (project,track): at most `N`
   * checkpoints within `windowDays`. Spec default N=6 / 30 days.
   */
  rateCap?: { maxPerWindow?: number; windowDays?: number };
}

/** §10 rule 11 published defaults (spec §10: N=6 over a rolling 30 days). */
export const DEFAULT_RATE_CAP_MAX = 6;
export const DEFAULT_RATE_CAP_WINDOW_DAYS = 30;

const SHA256_PREFIX = "sha256:";

/** §7.1 / §9: a `sha256:` + exactly 64 lower-case hex string. */
function isSha256Prefixed(v: unknown): v is string {
  if (typeof v !== "string" || !v.startsWith(SHA256_PREFIX)) return false;
  const hex = v.slice(SHA256_PREFIX.length);
  if (hex.length !== 64) return false;
  for (let i = 0; i < hex.length; i++) {
    const c = hex.charCodeAt(i);
    if (!((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66))) return false;
  }
  return true;
}

/** rule 8: bot-assigned UTC `YYYY-MM-DDTHH:MM:SSZ` from the bot clock. */
function isoSeconds(now: Date): string {
  // toISOString is millisecond `...000Z`; the §7.1 format is seconds.
  return now.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * The canonical hash of a mandate in the §7.1 `sha256:<hex>` form. The
 * pin/hash format is NOT re-invented: it is exactly {@link
 * mandatePinHash} (the bytes the consumer pins) with the spec's
 * `sha256:` prefix. Never throws — an adversarial mandate that fails
 * canonicalization is simply skipped (returns null).
 */
function prefixedPinHashOrNull(m: Mandate): string | null {
  try {
    return SHA256_PREFIX + mandatePinHash(m);
  } catch {
    return null;
  }
}

/**
 * Validate a checkpoint PR submission. PURE + TOTAL: never throws on
 * adversarial input (canonicalization throws are caught and mapped to a
 * reason). The order mirrors spec §10 rules 1→11 then §11; the ONLY
 * fail-open is rule 11 (over-cap ⇒ accept + `flagged:"rate-cap"` + a
 * manual-verification action), per spec §10.
 */
export function validateCheckpointSubmission(
  input: CheckpointSubmissionInput,
): CheckpointDecision {
  const {
    payload,
    chainMaterial,
    existingRows,
    now,
    repoReachable,
    maintainersPathExists,
    pathMatchesCanonicalRepo,
  } = input;

  // --- §9 payload shape (defensive; the Action parses, we never trust) ---
  if (
    payload === null ||
    typeof payload !== "object" ||
    typeof payload.track !== "string" ||
    payload.track.length === 0 ||
    typeof payload.canonicalRepo !== "string" ||
    typeof payload.maintainersPath !== "string" ||
    typeof payload.sourceCommit !== "string" ||
    payload.request === null ||
    typeof payload.request !== "object"
  ) {
    return { accept: false, reason: "payload-malformed" };
  }
  const track = payload.track;

  // --- Rule 1 / 2 / 9: inherently-I/O results supplied by the caller ----
  if (!repoReachable) return { accept: false, reason: "repo-unreachable" };
  if (!maintainersPathExists) {
    return { accept: false, reason: "maintainers-path-missing" };
  }
  if (!pathMatchesCanonicalRepo) {
    return { accept: false, reason: "path-mismatch" };
  }

  // --- §7.1 / §9: H_new must be a well-formed `sha256:<hex>` string -----
  const hNew = payload.currentMandateHash;
  if (!isSha256Prefixed(hNew)) {
    return { accept: false, reason: "hash-format-invalid" };
  }

  // --- §9: the signed request must BIND the declared repo/path/hash. ----
  // The witness proof is only meaningful if the holder signed over the
  // SAME (canonicalRepo, maintainersPath, currentMandateHash) the PR
  // declares — otherwise a valid signature over an unrelated request
  // could be replayed. (sourceCommit is advisory provenance, not a
  // continuity input, so it is not bound here.)
  const req = payload.request;
  if (
    req.canonicalRepo !== payload.canonicalRepo ||
    req.maintainersPath !== payload.maintainersPath ||
    req.currentMandateHash !== hNew
  ) {
    return {
      accept: false,
      reason: "request-repo-mismatch",
      detail:
        "the signed CheckpointRequest does not bind the PR's declared canonicalRepo/maintainersPath/currentMandateHash",
    };
  }

  // --- Rule 4: the project's chain verifies (verifyMandateChainFromPin).
  const chain = verifyMandateChainFromPin(
    chainMaterial.pin,
    chainMaterial.mandates,
  );
  if (chain.root === null || chain.validMandates.length === 0) {
    return {
      accept: false,
      reason: "chain-invalid",
      detail: chain.rootError ?? "no-valid-mandates",
    };
  }

  // --- Rule 3: H_new exists in the public verified chain. ---------------
  // Anchored to the VALIDATED chain (not the raw served log) so a
  // rejected/forked mandate can never satisfy "publicly available".
  const validHashes = new Set<string>();
  for (const m of chain.validMandates) {
    const h = prefixedPinHashOrNull(m);
    if (h !== null) validHashes.add(h);
  }
  if (!validHashes.has(hNew)) {
    return { accept: false, reason: "hash-not-in-history" };
  }

  // --- Rule 5 / §13: HOLDER-SIGNS (NOT the succession quorum). ----------
  // Reuse the landed envelope verifier verbatim (open-detail item 1).
  const authResult = verifyCheckpointRequest(req, chain, now);
  if (!authResult.ok) {
    const sub: CheckpointRequestFailReason = authResult.reason;
    return {
      accept: false,
      reason: "authority-invalid",
      detail: authResult.detail ? `${sub}: ${authResult.detail}` : sub,
    };
  }
  // Defensive: holder-signs already proved a live authority at `now`;
  // assert it so a future verifier change can't silently weaken this.
  if (!currentAuthority(chain, now)) {
    return {
      accept: false,
      reason: "authority-invalid",
      detail: "no-authority-at-now",
    };
  }

  // --- §11 H_old: the latest CURRENTLY-PRESENT prior row for THIS -------
  // (project, track). Flagged rows count while present. A pruned/sparse
  // CSV is expected: H_old is whatever is still present (anchor only
  // moves earlier — never a false continuity-break).
  const trackRows = existingRows.filter((r) => r.track === track);
  const hOld =
    trackRows.length > 0
      ? trackRows[trackRows.length - 1]!.current_mandate_hash
      : null;

  if (hOld === null) {
    // --- §12 first checkpoint: no H_old. Rules 3/4/5/9 already done; ----
    // no continuity / no-op to check. Append.
    return acceptRow(input, track, hNew, "first-checkpoint");
  }

  // --- Rule 10 (no-op): H_new equals the MOST-RECENT witnessed hash ----
  // for the same track ⇒ reject (the registry records only *changes*).
  if (hNew === hOld) {
    return {
      accept: false,
      reason: "no-op",
      detail: "current_mandate_hash equals the most recent witnessed hash for this track",
    };
  }

  // --- §11 continuity: the verified chain leading to H_new MUST -------
  // contain H_old. `validHashes` IS the project's own gap-free verified
  // chain (re-verified forward from the pin every submission), so a
  // rollback/fork/history-rewrite that drops the previously-witnessed
  // mandate is rejected. Prunable-witness: if the registry pruned to an
  // older still-present row, H_old is merely an EARLIER real witnessed
  // hash — still a real mandate the chain must contain, a strictly
  // weaker (never bypassed) anchor.
  if (!validHashes.has(hOld)) {
    return {
      accept: false,
      reason: "continuity-broken",
      detail:
        "the previously-witnessed current_mandate_hash is absent from the project's verified chain leading to the new hash (possible rollback, fork, or history rewrite)",
    };
  }

  // --- Rule 7 (append-only): the library NEVER rewrites — it returns ---
  // ONLY the single row to append. Defensive: a prior row whose
  // observed_at is in the future relative to the bot clock means the
  // existing file was tampered (rule 8 forbids submitter timestamps);
  // refuse rather than append onto a forged tail.
  const nowMs = now.getTime();
  for (const r of trackRows) {
    const t = Date.parse(r.observed_at);
    if (Number.isFinite(t) && t > nowMs) {
      return {
        accept: false,
        reason: "not-append-only",
        detail: "an existing row carries a future observed_at (file tampering; rule 8)",
      };
    }
  }

  // Rules 1–10 + §11 all passed. Rule 11 (rate cap) decides the flag
  // ONLY — it never rejects (fail-OPEN).
  return acceptRow(input, track, hNew, "continuation");
}

/**
 * Build the accept decision, applying rule 11 (the ONE fail-open). Over
 * the rolling window the row is STILL accepted — appended like any other
 * — with `flagged:"rate-cap"` and a manual-verification action signalled
 * to the (out-of-scope) Action shell. The cap counts the
 * already-present rows for this track whose `observed_at` is within the
 * window ending at `now`, PLUS this submission (so the Nth+1 trips it).
 */
function acceptRow(
  input: CheckpointSubmissionInput,
  track: string,
  hNew: string,
  context: "first-checkpoint" | "continuation",
): CheckpointDecision {
  const { now } = input;
  const maxPerWindow =
    input.rateCap?.maxPerWindow ?? DEFAULT_RATE_CAP_MAX;
  const windowDays = input.rateCap?.windowDays ?? DEFAULT_RATE_CAP_WINDOW_DAYS;
  const windowMs = windowDays * 24 * 60 * 60 * 1000;
  const nowMs = now.getTime();

  let inWindow = 1; // this submission
  for (const r of input.existingRows) {
    if (r.track !== track) continue;
    const t = Date.parse(r.observed_at);
    if (Number.isFinite(t) && t > nowMs - windowMs && t <= nowMs) inWindow++;
  }

  const observed_at = isoSeconds(now);
  if (inWindow > maxPerWindow) {
    // Rule 11 FAIL-OPEN: recorded anyway, flagged + reviewed. NEVER a
    // reject — a witness that refuses mid-incident fails when needed
    // most (spec §10 rule 11).
    return {
      accept: true,
      row: { observed_at, track, current_mandate_hash: hNew, flagged: "rate-cap" },
      action: {
        kind: "manual-verification",
        reason: "rate-cap",
        detail: `checkpoint volume for this (project, track) exceeded the published cap of ${maxPerWindow} per ${windowDays} rolling days (${inWindow} including this ${context}); recorded and flagged for maintainer review (never refused)`,
      },
    };
  }
  return {
    accept: true,
    row: { observed_at, track, current_mandate_hash: hNew, flagged: "" },
  };
}
