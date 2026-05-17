/**
 * maintainers CLI entrypoint.
 *
 * Usage:
 *   maintainers genesis        --track <name> --duration <60d> --holder-key <key> [--signing-key <key>] [--dry-run]
 *   maintainers mandate        --track <name> --duration <60d> --signing-key <key> [--successors a,b] [--dry-run]
 *   maintainers endorsement    --commit <40hex> --tag <semver> [--previous-id <uuid> --previous-commit <40hex>] [--intermediates auto|file:X|csv] --signing-key <key>
 *   maintainers ca-endorsement --ca-pubkey <64hex> [--scope S] [--duration 7d] [--track ca] --signing-key <key> [--dry-run]
 *   maintainers takeover       --track <name> --successor-key <key> --new-holder <key> [--dry-run]
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
  type KeySourceFs,
  type PivTransport,
  type PivPinProvider,
} from "./lib/keysource.js";
import { ttyConfirm, type ConfirmFn } from "./lib/ceremony.js";
import { newUuid } from "./lib/uuid.js";
import { runGenesis } from "./commands/genesis.js";
import { runMandate } from "./commands/mandate.js";
import { runEndorsement } from "./commands/endorsement.js";
import { runCaEndorsement } from "./commands/caEndorsement.js";
import { runTakeover } from "./commands/takeover.js";
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
}

export const defaultEnv: CliEnv = {
  now: () => new Date(),
  io: realFs,
  uuid: newUuid,
  println: (line: string) => process.stdout.write(line + "\n"),
  printerr: (line: string) => process.stderr.write(line + "\n"),
  confirm: ttyConfirm,
};

export async function dispatch(args: ParsedArgs, env: CliEnv): Promise<number> {
  try {
    switch (args.command) {
      case "genesis":
        return await runGenesis(args, env);
      case "mandate":
        return await runMandate(args, env);
      case "endorsement":
        return await runEndorsement(args, env);
      case "ca-endorsement":
        return await runCaEndorsement(args, env);
      case "takeover":
        return await runTakeover(args, env);
      case "verify":
        return await runVerify(args, env);
      case "status":
        return await runStatus(args, env);
      case undefined:
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
  println("commands:");
  println("  genesis         --track NAME --duration 60d --holder-key KEY [--signing-key KEY] [--successors A,B] [--output DIR] [--dry-run]");
  println("  mandate         --track NAME --duration 60d --signing-key KEY [--successors A,B] [--path .maintainers] [--dry-run]");
  println("  endorsement     --commit 40HEX --tag SEMVER --signing-key KEY [--previous-id UUID --previous-commit 40HEX] [--intermediates auto|file:X|csv] [--track release] [--path .maintainers]");
  println("  ca-endorsement  --ca-pubkey 64HEX --signing-key KEY [--scope S] [--duration 7d] [--track ca] [--path .maintainers] [--dry-run]");
  println("  takeover        --track NAME --successor-key KEY --new-holder KEY [--successors A,B] [--duration 60d] [--path .maintainers] [--dry-run]");
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
export { buildGenesis, assembleGenesis } from "./commands/genesis.js";
export { buildRenewal, assembleRenewal } from "./commands/mandate.js";
export { buildEndorsement } from "./commands/endorsement.js";
export { buildCaEndorsement, assembleCaEndorsement } from "./commands/caEndorsement.js";
export { buildTakeover, assembleTakeover } from "./commands/takeover.js";
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
