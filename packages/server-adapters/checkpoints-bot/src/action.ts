/**
 * GitHub Action entrypoint — maintainers-checkpoints PR validator.
 *
 * This is the analogue of the Cloudflare Worker's `worker.ts`: the THIN
 * runtime layer that wires REAL I/O into {@link CheckpointBotDeps} and
 * calls the pure {@link runCheckpointBotOnSubmission}. There is NO
 * decision logic here — every rule lives in `bot.ts` (which in turn
 * reuses the landed `validateCheckpointSubmission` verbatim). This file
 * only marshals the GitHub-Actions environment into the injected deps and
 * performs the effects the pure core decided.
 *
 * ───────────────────────────────────────────────────────────────────────
 * NOT EXECUTED / NOT EXERCISED IN THIS REPO. This entrypoint runs inside
 * a GitHub Action in the (human-gated, not-yet-created)
 * `github.com/ibisllc/maintainers-checkpoints` repository, on a real
 * checkpoint-submission PR. Creating that repo is an explicit human gate
 * within the Phase-H build (spec §21 open-detail item 4). It is authored
 * + typechecked here but there is no `GITHUB_EVENT_PATH`, no real PR, and
 * no project `.maintainers/` chain to fetch in this clone, so it cannot
 * be — and is deliberately NOT — run by the hermetic test suite. The
 * tests cover the PURE core (`bot.ts`) fully; this wiring is verified by
 * `tsc` only. Its only logic-bearing helpers (CSV parse/serialize,
 * payload extraction) are pure and unit-tested in `tests/bot.test.ts`.
 * ───────────────────────────────────────────────────────────────────────
 *
 * No new runtime dependency: GitHub Actions exposes everything via env
 * vars + files + the pre-installed `git`/`gh`. We use only `node:fs` /
 * `node:child_process` (no `@actions/*`, no octokit — none are in this
 * monorepo and none are added).
 */

import { readFileSync, appendFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import {
  runCheckpointBotOnSubmission,
  type BotOutcome,
  type CheckpointBotDeps,
  type CheckpointPrPayload,
  type ExistingCheckpointRow,
  type FetchedProjectChain,
  type ProjectChainMaterial,
} from "./bot.js";
import type { Mandate } from "@ibisllc/maintainers";

// ── Pure helpers (logic-bearing, unit-tested in tests/bot.test.ts) ───────

/**
 * Parse the §7 checkpoints CSV (header + 4-column rows) into the
 * already-parsed {@link ExistingCheckpointRow}[] the pure core consumes,
 * filtered to `track`. Pure: string → rows. The §7 format is quote-free
 * by construction (the bot only ever appends CSV-safe tokens), so a plain
 * comma split is exact.
 */
export function parseCheckpointCsv(
  csv: string,
  track: string,
): ExistingCheckpointRow[] {
  const out: ExistingCheckpointRow[] = [];
  const lines = csv.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    // Skip the required §7 header row.
    if (i === 0 && trimmed.startsWith("observed_at,")) continue;
    const parts = trimmed.split(",");
    if (parts.length < 3) continue;
    const row: ExistingCheckpointRow = {
      observed_at: parts[0] ?? "",
      track: parts[1] ?? "",
      current_mandate_hash: parts[2] ?? "",
      flagged: parts[3] ?? "",
    };
    if (row.track === track) out.push(row);
  }
  return out;
}

/**
 * Extract the §9 machine-readable `botPayload` from the
 * GitHub-Actions-provided event/workspace file content. Pure: the raw
 * file string → the typed payload (the same shape the CLI verb emits).
 * Throws on malformed JSON; the entrypoint maps that to a PR rejection.
 */
export function parseBotPayloadFile(raw: string): CheckpointPrPayload {
  return JSON.parse(raw) as CheckpointPrPayload;
}

/**
 * Derive the on-repo checkpoints CSV path from the canonical repo URL,
 * per spec §6 (`checkpoints/<host>/<owner>/<repo>.csv`). Pure.
 */
export function checkpointCsvPathFor(canonicalRepo: string): string {
  let s = canonicalRepo.trim();
  if (s.startsWith("https://")) s = s.slice("https://".length);
  if (s.startsWith("http://")) s = s.slice("http://".length);
  if (s.endsWith("/")) s = s.slice(0, -1);
  if (s.endsWith(".git")) s = s.slice(0, -4);
  return `checkpoints/${s}.csv`;
}

// ── Real-I/O wiring (NOT executed here — see file header) ────────────────

/* istanbul ignore next — wiring-only; runs only inside the Action repo. */
function realDeps(env: NodeJS.ProcessEnv): CheckpointBotDeps {
  const eventPath = env["GITHUB_EVENT_PATH"];
  const workspace = env["GITHUB_WORKSPACE"] ?? process.cwd();
  const payloadFile = env["CHECKPOINT_PAYLOAD_FILE"];

  return {
    now: new Date(),

    parsePayload(): CheckpointPrPayload {
      // The CLI verb (`maintainers checkpoint submit`) writes the §9
      // botPayload into the PR; the Action surfaces it as a workspace
      // file (CHECKPOINT_PAYLOAD_FILE) or, failing that, the PR event
      // body. We read whichever the workflow provided.
      if (payloadFile && existsSync(payloadFile)) {
        return parseBotPayloadFile(readFileSync(payloadFile, "utf8"));
      }
      if (eventPath && existsSync(eventPath)) {
        const ev = JSON.parse(readFileSync(eventPath, "utf8")) as {
          pull_request?: { body?: string };
        };
        const body = ev.pull_request?.body ?? "";
        const m = body.match(/```json\s*([\s\S]*?)```/);
        return parseBotPayloadFile(m && m[1] ? m[1] : body);
      }
      throw new Error("no checkpoint payload available in the Action env");
    },

    fetchProjectChain(
      canonicalRepo: string,
      maintainersPath: string,
      sourceCommit: string,
      track: string,
    ): FetchedProjectChain {
      // Shell out to the pre-installed `git` (no bundled HTTP client).
      // Sparse-checkout just the declared .maintainers/ path at the
      // submitted source commit into a temp dir, read the track's
      // mandate log, and report the rule-1/2/9 booleans. The pure core
      // does NOT decide these — we report observed facts.
      const dir = spawnSync("mktemp", ["-d"], { encoding: "utf8" })
        .stdout.trim();
      const clone = spawnSync(
        "git",
        ["clone", "--no-checkout", "--filter=blob:none", canonicalRepo, dir],
        { encoding: "utf8" },
      );
      const repoReachable = clone.status === 0;
      let maintainersPathExists = false;
      let pathMatchesCanonicalRepo = true; // file-path↔repo is checked by the workflow path filter
      let mandates: Mandate[] = [];
      let pin = "";
      if (repoReachable) {
        spawnSync("git", ["-C", dir, "checkout", sourceCommit], {
          encoding: "utf8",
        });
        const trackDir = `${dir}/${maintainersPath}tracks/${track}/mandates`;
        maintainersPathExists = existsSync(`${dir}/${maintainersPath}`);
        if (existsSync(trackDir)) {
          const ls = spawnSync("ls", ["-1", trackDir], { encoding: "utf8" });
          const files = ls.stdout
            .split("\n")
            .filter((f) => f.endsWith(".json"));
          const parsed: Mandate[] = [];
          for (const f of files) {
            try {
              const m = JSON.parse(
                readFileSync(`${trackDir}/${f}`, "utf8"),
              ) as Mandate;
              if (m && m.kind === "Mandate") parsed.push(m);
            } catch {
              /* skip malformed; the verifier fails-closed on a short chain */
            }
          }
          parsed.sort(
            (a, b) => Date.parse(a.issuedAt) - Date.parse(b.issuedAt),
          );
          mandates = parsed;
          // The registry pin is the project's own first on-repo mandate
          // hash (same anchor convention as the Worker). The workflow
          // supplies the expected pin out-of-band; absence ⇒ chain-invalid.
          pin = env["CHECKPOINT_PROJECT_PIN"] ?? "";
        }
      }
      const chainMaterial: ProjectChainMaterial = { pin, mandates };
      return {
        chainMaterial,
        repoReachable,
        maintainersPathExists,
        pathMatchesCanonicalRepo,
      };
    },

    readExistingRows(track: string): ExistingCheckpointRow[] {
      const payloadFileForRepo = env["CHECKPOINT_CANONICAL_REPO"] ?? "";
      const csvPath = `${workspace}/${checkpointCsvPathFor(
        payloadFileForRepo,
      )}`;
      if (!existsSync(csvPath)) return [];
      return parseCheckpointCsv(readFileSync(csvPath, "utf8"), track);
    },

    appendCsvLine(_track: string, line: string): void {
      const csvPath = `${workspace}/${checkpointCsvPathFor(
        env["CHECKPOINT_CANONICAL_REPO"] ?? "",
      )}`;
      // Rule 7: a single-line APPEND. Never a rewrite of prior rows.
      appendFileSync(csvPath, line + "\n", "utf8");
    },

    postPrDecision(outcome: BotOutcome): void {
      // Emit the PR decision via the Actions-provided mechanism. We use
      // the pre-installed `gh` CLI (auth comes from the workflow's
      // GITHUB_TOKEN); no octokit. On accept we also emit the GITHUB_OUTPUT
      // marker so a downstream merge step can gate on it.
      const out = env["GITHUB_OUTPUT"];
      if (out) {
        appendFileSync(
          out,
          `decision=${outcome.kind}\n` +
            (outcome.kind === "reject"
              ? `reject_reason=${outcome.pr.reason}\n`
              : `flagged=${outcome.row.flagged}\n`),
          "utf8",
        );
      }
      const pr = env["PR_NUMBER"];
      if (!pr) return;
      if (outcome.kind === "reject") {
        spawnSync(
          "gh",
          [
            "pr",
            "comment",
            pr,
            "--body",
            `Checkpoint rejected: \`${outcome.pr.reason}\`` +
              (outcome.pr.detail ? ` — ${outcome.pr.detail}` : ""),
          ],
          { encoding: "utf8" },
        );
        spawnSync("gh", ["pr", "edit", pr, "--add-label", outcome.pr.label], {
          encoding: "utf8",
        });
      } else if (outcome.ping) {
        // Rule-11 fail-open: the row was recorded; open the maintainer
        // manual-verification flow (email/ticket) — never a refusal.
        spawnSync(
          "gh",
          [
            "pr",
            "comment",
            pr,
            "--body",
            `Checkpoint recorded but FLAGGED (rate-cap): ${outcome.ping.detail}`,
          ],
          { encoding: "utf8" },
        );
      }
    },
  };
}

/* istanbul ignore next — wiring-only; runs only inside the Action repo. */
export async function main(): Promise<void> {
  const outcome = await runCheckpointBotOnSubmission(realDeps(process.env));
  if (outcome.kind === "reject") {
    process.exitCode = 1;
  }
}

// Executed only inside the GitHub Action runtime (never imported by tests).
/* istanbul ignore next */
if (process.env["CHECKPOINT_BOT_ENTRYPOINT"] === "1") {
  void main();
}
