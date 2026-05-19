/**
 * maintainers CLI entrypoint.
 *
 * Usage:
 *   maintainers upsert-mandate --track <name> --signing-key <key> --duration <60d> [--holder <key>] [--successors a,b] [--threshold N] [--min-successors N] [--max-duration 365d] [--default-duration 60d] [--project-name P ...] [--dry-run]
 *   maintainers endorsement    --commit <40hex> --tag <semver> [--previous-id <uuid> --previous-commit <40hex>] [--intermediates auto|file:X|csv] --signing-key <key>
 *   maintainers ca-endorsement --ca-pubkey <64hex> [--scope S] [--duration 7d] [--track ca] --signing-key <key> [--dry-run]
 *   maintainers create-key     --signing-key <key> --display-name NAME --email ADDR [--dry-run]
 *
 *   --dry-run: print the EXACT canonical bytes a real run would sign + the
 *   would-write .maintainers diff; sign nothing, write nothing, no PIN/tap
 *   (pubkeys resolved via the no-PIN public read only).
 *   maintainers verify         [--path ./.maintainers/] [--as-of <RFC3339|now>]
 *   maintainers status         [--path ./.maintainers/] [--as-of <RFC3339|now>]
 *
 * Key sources (`<key>`):
 *   file:<path>          local 32-byte hex Ed25519 key (priv or pub) — the
 *                        lower-assurance air-gapped / successor fallback.
 *   yubikey-piv:slot=9c  YubiKey PIV-resident Ed25519 — the supported
 *                        maintainer-root path; the private half never leaves
 *                        the token. A PIV-Ed25519 signature over the canonical
 *                        bytes is byte-identical RFC-8032 Ed25519, so there is
 *                        ZERO protocol/wire/spec delta (§11.1). The native
 *                        PC/SC transport is verified only at the YubiKey gate;
 *                        until then it fail-closes — it NEVER silently falls
 *                        back to a hex key.
 */

import { CliError, parseArgs, type ParsedArgs } from "./lib/args.js";
import {
  realFs,
  pivTransportWithPrompt,
  type KeySourceFs,
  type PivTransport,
  type PivPinProvider,
} from "./lib/keysource.js";
import { ttyConfirm, type ConfirmFn } from "./lib/ceremony.js";
import { pivPinFromTty, runPivPinSelfTest } from "./lib/piv-pin.js";
import { runWizard, defaultPrompt, type PromptFn } from "./lib/wizard.js";
import { newUuid } from "./lib/uuid.js";
import { runEndorsement } from "./commands/endorsement.js";
import { runCaEndorsement } from "./commands/caEndorsement.js";
import { runCreateKey } from "./commands/createKey.js";
import { runUpsertMandate } from "./commands/upsertMandate.js";
import { runCheckpointSubmit } from "./commands/checkpointSubmit.js";
import { runStatus, runVerify } from "./commands/verify.js";

export interface CliEnv {
  now: () => Date;
  io: KeySourceFs;
  uuid: () => string;
  println: (line: string) => void;
  printerr: (line: string) => void;
  /** PIV transport for `yubikey-piv:` key sources (default:
   *  realPivTransport, which fail-closes until the native PC/SC
   *  transport is wired — it NEVER silently falls back to a hex key). */
  pivTransport?: PivTransport;
  /** Secure no-echo PIN provider for `yubikey-piv:` sources. The PIN is
   *  never read from argv/env-by-default and never logged. */
  pivPin?: PivPinProvider;
  /** Typed-confirm provider for the four maintainer-key ceremonies.
   *  Default: {@link ttyConfirm} (real TTY; fail-closed when piped).
   *  `--yes` skips the prompt; tests inject a fake. */
  confirm?: ConfirmFn;
  /** Line prompt for the guided menu wizard. Default:
   *  {@link defaultPrompt} (a `node:readline/promises` reader over the
   *  real TTY). Tests inject a scripted fake. Never used for the PIN —
   *  the PIN is read only inside the existing signing path via
   *  {@link CliEnv.pivPin}, no-echo. */
  prompt?: PromptFn;
  /** True iff attached to an interactive terminal. The bare-invocation
   *  guided menu engages ONLY when this is true; a non-interactive bare
   *  invocation stays `printUsage` (unchanged). Default: derived from
   *  `process.stdin.isTTY`, matching `pivTransport`/`pivPin`. */
  interactive?: boolean;
}

export const defaultEnv: CliEnv = {
  now: () => new Date(),
  io: realFs,
  uuid: newUuid,
  println: (line: string) => process.stdout.write(line + "\n"),
  printerr: (line: string) => process.stderr.write(line + "\n"),
  confirm: ttyConfirm,
  // The production PIV transport routes through the no-hardware UX state
  // machine: absent reader/token/not-tapped-yet are prompted+polled+
  // retried (recoverable, never fatal); a security failure or the
  // build-not-wired condition still fail-closed with NO weaker-key
  // fallback; a non-interactive context fails closed deterministically.
  // The wait/retry guidance goes to stderr so it never contaminates the
  // signed-bytes stdout preview.
  pivTransport: pivTransportWithPrompt({
    prompt: (line: string) => process.stderr.write(line + "\n"),
    interactive: Boolean(process.stdin.isTTY),
  }),
  // The missing seam (the genesis-ceremony gap): the concrete secure PIN
  // reader. Prompts the controlling terminal (/dev/tty) with echo
  // DISABLED; the PIN is never read from argv/env/a file and never
  // logged. A non-interactive context fails closed deterministically
  // (never hangs, never fabricates) — matching the pivTransport
  // interactivity above so both seams agree on what "interactive" means.
  pivPin: pivPinFromTty({ interactive: Boolean(process.stdin.isTTY) }),
  prompt: defaultPrompt,
  interactive: Boolean(process.stdin.isTTY),
};

export async function dispatch(args: ParsedArgs, env: CliEnv): Promise<number> {
  try {
    switch (args.command) {
      case "endorsement":
        return await runEndorsement(args, env);
      case "ca-endorsement":
        return await runCaEndorsement(args, env);
      case "create-key":
        return await runCreateKey(args, env);
      case "upsert-mandate":
        return await runUpsertMandate(args, env);
      case "checkpoint": {
        // `maintainers checkpoint submit …` — sub-action dispatch (the
        // only verb in this namespace at v0.1). An unknown/absent
        // sub-action fails closed with a clear message, never silently.
        const sub = args.positionals[0];
        if (sub === "submit") return await runCheckpointSubmit(args, env);
        env.printerr(
          `unknown checkpoint sub-action: ${sub ?? "(none)"} — expected ` +
            `\`maintainers checkpoint submit …\``,
        );
        return 2;
      }
      case "verify":
        return await runVerify(args, env);
      case "status":
        return await runStatus(args, env);
      case "selftest-pin":
        // Hidden, NON-SECRET acceptance check of the no-echo PIN-read
        // path. Drives the SAME reader; the human types a throwaway
        // dummy (NOT a real PIN); prints only verdict + length + SHA.
        // Not listed in `printUsage` (operator-facing surface stays the
        // four ceremony verbs); never wired into any signing path.
        return await runPivPinSelfTest(env.println, env.printerr);
      case "menu":
        // Explicit opt-in. Non-interactive ⇒ runWizard fails closed with
        // a clear CliError (caught below → exit 1); never hangs.
        return await runWizard(
          {
            println: env.println,
            printerr: env.printerr,
            prompt: env.prompt,
            interactive: env.interactive,
          },
          (a) => dispatch(a, env),
        );
      case undefined:
        // Bare `maintainers`: the guided menu ONLY when interactive.
        // Non-interactive (piped/CI/no-TTY) stays EXACTLY as before —
        // printUsage + exit 0, prompt-free, never engages the wizard.
        if (env.interactive) {
          return await runWizard(
            {
              println: env.println,
              printerr: env.printerr,
              prompt: env.prompt,
              interactive: env.interactive,
            },
            (a) => dispatch(a, env),
          );
        }
        printUsage(env.println);
        return 0;
      case "help":
      case "--help":
      case "-h":
        printUsage(env.println);
        return 0;
      case "version":
      case "--version":
      case "-v":
        env.println("maintainers 0.1.0");
        return 0;
      default:
        env.printerr(`unknown command: ${args.command}`);
        printUsage(env.printerr);
        return 2;
    }
  } catch (err) {
    if (err instanceof CliError) {
      env.printerr(`error: ${err.message}`);
      return 1;
    }
    env.printerr(`unexpected: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
    return 1;
  }
}

export async function run(argv: string[], env: CliEnv = defaultEnv): Promise<number> {
  const parsed = parseArgs(argv);
  const code = await dispatch(parsed, env);
  // run() returns; the bin shim calls process.exit. We avoid calling
  // process.exit here so the function is easy to unit-test.
  return code;
}

function printUsage(println: (s: string) => void): void {
  println("maintainers — authority-management CLI");
  println("");
  println("run `maintainers` (no subcommand) in a terminal for a guided");
  println("menu; `maintainers menu` forces it. The flag-driven commands");
  println("below are unchanged (the scripting path).");
  println("");
  println("commands:");
  println("  upsert-mandate  --track NAME --signing-key KEY --duration 60d [--holder KEY] [--successors A,B] [--threshold N] [--min-successors N] [--max-duration 365d] [--default-duration 60d] [--project-name P --project-contact C --project-homepage H --project-tracks a,b] [--path .maintainers] [--dry-run]");
  println("                  (the ONE mandate verb — genesis/renew/takeover/repolicy all collapse into this; the predecessor's inline rule governs each step, there is NO self-renewal)");
  println("  endorsement     --commit 40HEX --tag SEMVER --signing-key KEY [--previous-id UUID --previous-commit 40HEX] [--intermediates auto|file:X|csv] [--track release] [--path .maintainers]");
  println("  ca-endorsement  --ca-pubkey 64HEX --signing-key KEY [--scope S] [--duration 7d] [--track ca] [--path .maintainers] [--dry-run]");
  println("  create-key      --signing-key KEY --display-name NAME --email ADDR [--introduction-mandate UUID] [--photo URL] [--github H] [--role R] [--path .maintainers] [--dry-run]");
  println("  checkpoint submit --canonical-repo URL --source-commit REF --signing-key KEY [--maintainers-path .maintainers/] [--track ca] [--current-mandate-hash sha256:HEX] [--path .maintainers] [--dry-run]");
  println("                  (holder-sign a PUBLIC Maintainers-Checkpoints request + emit the §9 PR payload; H_new derived from the local store unless --current-mandate-hash is given; the verb EMITS — opening the PR is a separate human/gh step)");
  println("  verify          [--path .maintainers] [--as-of RFC3339|now]");
  println("  status          [--path .maintainers] [--as-of RFC3339|now]");
  println("");
  println("key sources (KEY):");
  println("  file:<path>           local 32-byte hex Ed25519 key (priv or pub) — air-gapped/successor fallback");
  println("  yubikey-piv:slot=9c   YubiKey PIV-resident Ed25519 — the supported maintainer-root path");
  println("");
  println("  --dry-run  print the EXACT canonical bytes + the .maintainers diff that");
  println("             WOULD be written; sign nothing, write nothing, no PIN/tap.");
}

// Re-exports so tests and embedders can drive the CLI without spawning a process.
export { parseArgs } from "./lib/args.js";
export { buildEndorsement } from "./commands/endorsement.js";
export { buildCaEndorsement, assembleCaEndorsement } from "./commands/caEndorsement.js";
export { buildCreateKey, assembleCreateKey } from "./commands/createKey.js";
export { buildUpsertMandate, assembleUpsertMandate } from "./commands/upsertMandate.js";
export {
  buildCheckpointRequest,
  assembleCheckpointRequest,
  buildCheckpointSubmissionPayload,
  checkpointCsvPath,
  type CheckpointSubmissionPayload,
} from "./commands/checkpointSubmit.js";
export { buildReport } from "./commands/verify.js";
export {
  renderPreview,
  previewConfirmSign,
  ceremonyBanner,
  confirmPhrase,
  confirmGate,
  signAssembled,
  type Assembled,
  type ConfirmFn,
} from "./lib/ceremony.js";
export {
  PcscNotReadyError,
  PcscSecurityError,
  PcscBuildError,
  isRecoverableNotReady,
} from "./lib/piv-pcsc.js";
export {
  connectPcscChannelWithPrompt,
  type ConnectWithPromptOptions,
  type ChannelFactory,
} from "./lib/piv-connect.js";
export {
  pivPinFromTty,
  openControllingTty,
  runPivPinSelfTest,
  type TtyDevice,
  type PivPinPromptOptions,
} from "./lib/piv-pin.js";
export { runWizard, defaultPrompt, type PromptFn } from "./lib/wizard.js";
