/**
 * The guided menu wizard — a THIN front-end over the existing flag-driven
 * command path. Running `maintainers` with NO subcommand in an
 * interactive terminal (or the explicit `menu` subcommand) shows a
 * numbered menu; the operator picks an action and is walked through
 * prompts with sensible defaults. The wizard ONLY gathers inputs and
 * then constructs the SAME {@link ParsedArgs} the equivalent flag
 * invocation would produce and re-dispatches through the EXISTING
 * handlers — so the canonical-byte preview, the typed-confirm, the PIN
 * read and the YubiKey tap are the unchanged existing code path.
 *
 * It NEVER reimplements canonical bytes, signing, the REVIEW/DRY-RUN
 * banner, the typed confirm, the PIN reader, or verify/status logic. It
 * NEVER passes `--yes` / a skip-confirm for the irreversible verbs: the
 * hand-typed phrase confirm + PIN + tap stay mandatory and run via the
 * existing handler path. It NEVER prompts for the PIN (the PIN is read
 * only inside the existing signing path via `env.pivPin`, no-echo).
 *
 * Non-interactive determinism: the menu must NEVER engage
 * non-interactively and must NEVER hang waiting for input. `dispatch`
 * only routes a bare invocation here when `env.interactive` is true;
 * the explicit `menu` subcommand in a non-interactive context (or any
 * entry without a usable prompt seam) fails closed deterministically
 * with a clear {@link CliError} — same voice as `ttyConfirm`'s piped
 * abort — never hangs, never fabricates.
 */

import { CliError, parseArgs, type ParsedArgs } from "./args.js";

/**
 * Injectable line prompt. The default ({@link defaultPrompt}) is a
 * `node:readline/promises` reader over the real TTY; tests inject a
 * scripted fake. Returns the raw line (untrimmed); the wizard applies
 * defaults/trimming.
 */
export type PromptFn = (question: string) => Promise<string>;

/** The minimal env the wizard needs. A superset-compatible subset of
 *  {@link CliEnv} so `dispatch` can pass its own `env` straight through
 *  to the re-dispatched handler (the real signing path). */
export interface WizardEnv {
  println: (line: string) => void;
  printerr: (line: string) => void;
  prompt?: PromptFn;
  interactive?: boolean;
}

/**
 * The default real prompt: read ONE line from stdin/stdout via
 * `node:readline/promises`. Used only when `env.interactive` is true (so
 * a TTY is present); the non-interactive guard in {@link runWizard}
 * fails closed before this is ever reached in a piped/CI context.
 */
export const defaultPrompt: PromptFn = async (question: string) => {
  const readline = await import("node:readline/promises");
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  try {
    return await rl.question(question);
  } finally {
    rl.close();
  }
};

interface MenuAction {
  key: string;
  label: string;
  /** Build the flag argv this action maps to (sans the leading shim
   *  args). The wizard parses it with the SAME {@link parseArgs} the
   *  flag path uses, then re-dispatches — byte-equivalent to the
   *  operator having typed those flags. */
  gather: (ask: Ask) => Promise<string[]>;
}

/** A defaulting prompt helper bound to one wizard run. */
type Ask = (question: string, fallback?: string) => Promise<string>;

function makeAsk(prompt: PromptFn): Ask {
  return async (question, fallback) => {
    const suffix = fallback !== undefined ? ` [${fallback}]` : "";
    const raw = await prompt(`  ${question}${suffix}: `);
    const trimmed = raw.trim();
    if (trimmed.length === 0 && fallback !== undefined) return fallback;
    return trimmed;
  };
}

const DEFAULT_SIGNING_KEY = "yubikey-piv:slot=9c";
const DEFAULT_PATH = ".maintainers";

/** Append `--flag value` only when `value` is non-empty (mirrors how the
 *  flag path treats an omitted optional). */
function pushOpt(out: string[], flag: string, value: string): void {
  if (value.length > 0) out.push(`--${flag}`, value);
}

const ACTIONS: MenuAction[] = [
  {
    key: "1",
    label: "Show status (tracks, mandates, expiry)",
    async gather(ask) {
      const path = await ask("Store path", DEFAULT_PATH);
      const asOf = await ask("As of (RFC3339 or 'now')", "now");
      const argv = ["status"];
      pushOpt(argv, "path", path);
      pushOpt(argv, "as-of", asOf);
      return argv;
    },
  },
  {
    key: "2",
    label: "Register a key (KeyFile)",
    async gather(ask) {
      const signingKey = await ask("Signing key", DEFAULT_SIGNING_KEY);
      const displayName = await ask("Display name");
      const email = await ask("Email");
      const path = await ask("Store path", DEFAULT_PATH);
      const dryRun = await ask("Dry run only? (y/N)", "N");
      const argv = ["create-key"];
      pushOpt(argv, "signing-key", signingKey);
      pushOpt(argv, "display-name", displayName);
      pushOpt(argv, "email", email);
      pushOpt(argv, "path", path);
      if (isYes(dryRun)) argv.push("--dry-run");
      return argv;
    },
  },
  {
    key: "3",
    label: "Issue / renew a mandate",
    async gather(ask) {
      const track = await ask("Track", "ca");
      const duration = await ask("Duration", "100d");
      const signingKey = await ask("Signing key", DEFAULT_SIGNING_KEY);
      const holder = await ask("Holder key (blank = signing key)", "");
      const successors = await ask("Successors (csv, blank = inherit)", "");
      const projectName = await ask(
        "Project name (required for a from-scratch origin)",
        "",
      );
      const path = await ask("Store path", DEFAULT_PATH);
      const dryRun = await ask("Dry run only? (y/N)", "N");
      const argv = ["upsert-mandate"];
      pushOpt(argv, "track", track);
      pushOpt(argv, "duration", duration);
      pushOpt(argv, "signing-key", signingKey);
      pushOpt(argv, "holder", holder);
      pushOpt(argv, "successors", successors);
      pushOpt(argv, "project-name", projectName);
      pushOpt(argv, "path", path);
      if (isYes(dryRun)) argv.push("--dry-run");
      return argv;
    },
  },
  {
    key: "4",
    label: "CA endorsement (lease the hot key)",
    async gather(ask) {
      const caPubkey = await ask("CA pubkey (64 hex)");
      const scope = await ask("Scope", "flagship/directory-attestation");
      const duration = await ask("Duration", "7d");
      const track = await ask("Track", "ca");
      const signingKey = await ask("Signing key", DEFAULT_SIGNING_KEY);
      const path = await ask("Store path", DEFAULT_PATH);
      const dryRun = await ask("Dry run only? (y/N)", "N");
      const argv = ["ca-endorsement"];
      pushOpt(argv, "ca-pubkey", caPubkey);
      pushOpt(argv, "scope", scope);
      pushOpt(argv, "duration", duration);
      pushOpt(argv, "track", track);
      pushOpt(argv, "signing-key", signingKey);
      pushOpt(argv, "path", path);
      if (isYes(dryRun)) argv.push("--dry-run");
      return argv;
    },
  },
  {
    key: "5",
    label: "Verify the store",
    async gather(ask) {
      const path = await ask("Store path", DEFAULT_PATH);
      const asOf = await ask("As of (RFC3339 or 'now')", "now");
      const argv = ["verify"];
      pushOpt(argv, "path", path);
      pushOpt(argv, "as-of", asOf);
      return argv;
    },
  },
];

function isYes(s: string): boolean {
  const v = s.trim().toLowerCase();
  return v === "y" || v === "yes";
}

function renderMenu(println: (l: string) => void): void {
  const rule = "────────────────────────────────────────";
  println(rule);
  println("  Flagship maintainers — what do you want to do?");
  println("");
  for (const a of ACTIONS) println(`   ${a.key}) ${a.label}`);
  println("   q) Quit");
  println("");
}

/**
 * Run the guided menu loop. `dispatchArgs` is the existing
 * {@link dispatch} (injected to avoid an import cycle and to keep the
 * wizard a pure front-end): the wizard hands it a {@link ParsedArgs}
 * built by {@link parseArgs} from the gathered flag argv plus the SAME
 * `env`, so the byte preview / typed-confirm / PIN / tap are the
 * unchanged existing path. A handler {@link CliError} is surfaced
 * cleanly and the loop returns to the menu (the process never crashes);
 * `q` quits with exit 0.
 */
export async function runWizard(
  env: WizardEnv,
  dispatchArgs: (args: ParsedArgs) => Promise<number>,
): Promise<number> {
  // Deterministic fail-closed: the menu must NEVER engage
  // non-interactively and NEVER hang waiting for prompt input. Same
  // taxonomy/voice as ttyConfirm's / pivPinFromTty's non-interactive
  // abort — refuse before reading anything.
  if (!env.interactive) {
    throw new CliError(
      "the guided menu needs an interactive terminal but this is a " +
        "non-interactive context (piped/CI/no TTY) — re-run attached to a " +
        "terminal, or invoke a subcommand directly with flags. It never " +
        "engages non-interactively and never hangs.",
    );
  }
  const prompt = env.prompt;
  if (!prompt) {
    throw new CliError(
      "the guided menu has no input source (no prompt seam) — refusing to " +
        "proceed without a way to read the operator's choice. Invoke a " +
        "subcommand directly with flags instead.",
    );
  }
  const ask = makeAsk(prompt);

  for (;;) {
    renderMenu(env.println);
    const choice = (await prompt("  > ")).trim().toLowerCase();
    if (choice === "q" || choice === "quit") {
      return 0;
    }
    const action = ACTIONS.find((a) => a.key === choice);
    if (!action) {
      env.printerr(`  not a choice: "${choice}" — pick 1-5 or q.`);
      continue;
    }
    let argv: string[];
    try {
      argv = await action.gather(ask);
    } catch (err) {
      if (err instanceof CliError) {
        env.printerr(`error: ${err.message}`);
        continue;
      }
      throw err;
    }
    // Build the SAME ParsedArgs the flag path produces and re-dispatch
    // through the EXISTING handler. NEVER inject --yes / skip-confirm:
    // the typed phrase confirm + PIN + tap stay mandatory and run inside
    // the unchanged handler path.
    const code = await dispatchArgs(parseArgs(argv));
    if (code !== 0) {
      env.printerr(
        `  (the "${action.label}" step exited ${code} — see the message ` +
          `above; returning to the menu)`,
      );
    }
  }
}
