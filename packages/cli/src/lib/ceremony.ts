/**
 * Shared ceremony scaffolding for the four maintainer-key commands
 * (genesis / mandate / takeover / ca-endorsement).
 *
 * The security-critical invariant: the bytes a `--dry-run` previews are
 * EXACTLY the bytes the real run signs. Every ceremony is two phases —
 *
 *   1. `assemble*`  — pure: validate inputs, read the store + PUBLIC
 *      keys only (PIV public read = no PIN/tap; `file:` priv = derived,
 *      never signed, never logged), build the *unsigned* envelope, its
 *      canonical bytes, and the path that WOULD be written. No private
 *      key op, no write.
 *   2. sign         — `signAssembled` loads the real signer (the only
 *      step that touches the token/PIN), re-checks the resolved pubkey
 *      against `signedBy` (fail-closed on a swap), and signs.
 *
 * `previewConfirmSign` is the run-path orchestrator: plain-language
 * banner → byte/diff preview → (real path only) typed explicit confirm
 * BEFORE any token touch or write → sign. `--dry-run` stops after the
 * preview; `--yes` skips only the interactive prompt (never the banner).
 * Secrets (PIN, key material) are never printed by any of this.
 */

import type { Ed25519Signer } from "@maintainers/protocol";
import {
  loadSigner,
  type SignerOptions,
  type KeySourceFs,
  type PivTransport,
  type PivPinProvider,
} from "./keysource.js";
import { CliError } from "./args.js";

export type CeremonyKind =
  | "genesis"
  | "mandate"
  | "takeover"
  | "ca-endorsement"
  | "create-key";

/**
 * The output of an `assemble*` call: everything needed to either preview
 * (dry-run) or sign+write, with NO signing yet performed.
 */
export interface Assembled<U> {
  ceremony: CeremonyKind;
  /** The unsigned envelope (no `signatures` field). */
  unsigned: U;
  /** Canonical bytes of `unsigned` — exactly what would be signed. */
  canonical: Uint8Array;
  /** Source string to feed {@link loadSigner} in the real (sign) path. */
  signingKeySource: string;
  /** Pubkey the signature MUST come from (the envelope's `signedBy`). */
  signedBy: string;
  /** Store root the artifact would be written under. */
  rootDir: string;
  /** Path, relative to `rootDir`, that WOULD be written. */
  targetRelative: string;
  /** Extra append-only writes a real run would also make if missing
   *  (e.g. a track `policy.json` on genesis) — informational only. */
  alsoIfMissing?: { relative: string }[];
  /** Ceremony-specific extra banner lines (e.g. the loud FROM-SCRATCH
   *  ORIGIN warning for an `upsert-mandate` with no predecessor). The
   *  assemble step decides these — it knows the sub-case the static
   *  `ceremonyBanner` switch cannot see. Appended inside the banner so
   *  it still precedes the byte preview + the typed confirm. */
  bannerExtra?: string[];
}

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/**
 * Plain-language banner so a non-expert successor knows EXACTLY what
 * they are about to do and what is irreversible/visible (§11.2). Pure;
 * no secrets — only the public envelope shape.
 */
export function ceremonyBanner<U>(a: Assembled<U>): string[] {
  const head = "────────────────────────────────────────────────────────────";
  const lines = bannerBody(a, head);
  if (a.bannerExtra && a.bannerExtra.length > 0) {
    // splice the extra lines just inside the closing rule
    return [...lines.slice(0, -1), ...a.bannerExtra, head];
  }
  return lines;
}

function bannerBody<U>(a: Assembled<U>, head: string): string[] {
  switch (a.ceremony) {
    case "genesis":
      return [
        head,
        "⚠  GENESIS — you are creating the ROOT OF TRUST for this project.",
        "   This CANNOT be undone or revoked. Every future CA lease and",
        "   release ultimately chains to the key you are signing with now.",
        "   • Use your PRIMARY YubiKey.",
        "   • Your BACKUP / successor key MUST be named in --successors —",
        "     that named successor is your ONLY recovery if the primary is",
        "     lost or bricked (there is no key escrow).",
        "   • RECORD the holder pubkey printed at the end: it is baked into",
        "     the build as MAINTAINER_GENESIS_PUBKEYS.",
        head,
      ];
    case "takeover":
      return [
        head,
        "⚠  TAKEOVER — you are claiming a track as a NAMED SUCCESSOR because",
        "   the predecessor mandate has expired. This is VISIBLE to every",
        "   consumer (a TakeoverAlarm) — expected and good. Proceed only if",
        "   you are the legitimate successor.",
        head,
      ];
    case "mandate":
      return [
        head,
        "RENEW — extend authority on this track. Signed by the CURRENT",
        "holder. The previous mandate stays valid until its own expiry",
        "(overlap is normal and gap-free).",
        head,
      ];
    case "ca-endorsement":
      return [
        head,
        "CA LEASE — authorize the hot operational CA pubkey until notAfter.",
        "A LAPSED lease fail-closes the CA globally (no revocation list) —",
        "renew before notAfter. Overlapping leases are fine.",
        head,
      ];
    case "create-key":
      return [
        head,
        "REGISTER KEY — a self-signed identity label (display name +",
        "email) for this pubkey. This is NOT a grant of authority: a key",
        "file is non-load-bearing (trust operates on the pubkey, never",
        "the email). Safe to redo — just remove/rename the old file.",
        head,
      ];
  }
}

type PreviewMode = "dry-run" | "review";

/**
 * Render the byte/diff preview: the exact canonical bytes (hex + the
 * human-auditable utf-8 rendering — canonical bytes are a printable
 * tagged pipe-joined string by construction) and the unsigned
 * `.maintainers` diff. Identical bytes whether previewing a dry-run or
 * the about-to-sign review; only the header differs. Signs/writes
 * nothing; prints no secrets (pubkeys + timestamps only).
 */
export function renderPreview<U>(
  a: Assembled<U>,
  println: (line: string) => void,
  mode: PreviewMode,
): void {
  println("");
  if (mode === "dry-run") {
    println(`═══ DRY RUN — ${a.ceremony} — NOTHING was signed or written ═══`);
  } else {
    println(`═══ REVIEW — ${a.ceremony} — about to SIGN + WRITE the below ═══`);
  }
  println(`would write: ${a.rootDir}/${a.targetRelative}`);
  for (const w of a.alsoIfMissing ?? []) {
    println(`  (also, if missing: ${a.rootDir}/${w.relative})`);
  }
  println("");
  println("canonical bytes (hex — EXACTLY what a real run would sign):");
  println(`  ${toHex(a.canonical)}`);
  println("");
  println("canonical bytes (utf-8 — same bytes, human-auditable):");
  println(`  ${new TextDecoder().decode(a.canonical)}`);
  println("");
  println(".maintainers diff preview (unsigned — signatures NOT computed):");
  for (const line of JSON.stringify(a.unsigned, null, 2).split("\n")) {
    println(`  ${line}`);
  }
  println("");
  println(
    "note: a real run mints a fresh id + timestamps, so re-running " +
      "produces different (but structurally identical) bytes. This " +
      "preview is exact for THIS invocation only.",
  );
}

/** The exact phrase the operator must type to proceed (forces intent —
 *  you cannot blindly muscle-memory "yes"). */
export function confirmPhrase(ceremony: CeremonyKind): string {
  return ceremony === "ca-endorsement" ? "CA-LEASE" : ceremony.toUpperCase();
}

/** Injected interactive confirmation. Returns true iff the operator
 *  explicitly affirmed (e.g. typed the exact phrase). */
export type ConfirmFn = (req: {
  ceremony: CeremonyKind;
  phrase: string;
}) => Promise<boolean>;

/**
 * The default real confirmation: read ONE line from the TTY and require
 * it to equal the phrase exactly. Fail-closed when there is no TTY
 * (piped/automated) — the caller must pass `--yes` deliberately rather
 * than have a non-interactive run silently auto-proceed.
 */
export const ttyConfirm: ConfirmFn = async ({ ceremony, phrase }) => {
  if (!process.stdin.isTTY) {
    process.stderr.write(
      `\nrefusing to ${ceremony} non-interactively without confirmation: ` +
        `re-run attached to a terminal, or pass --yes deliberately.\n`,
    );
    return false;
  }
  process.stdout.write(
    `\nType ${phrase} (exactly) then Enter to proceed, anything else aborts: `,
  );
  const readline = await import("node:readline");
  const rl = readline.createInterface({ input: process.stdin });
  const line: string = await new Promise((resolve) => {
    rl.once("line", (l) => resolve(l));
  });
  rl.close();
  return line.trim() === phrase;
};

/**
 * Gate before any token touch / write. Prints nothing secret. With
 * `--yes` the interactive prompt (only) is skipped — the banner +
 * preview were already shown. Without `--yes` AND without an injected
 * confirm, fail closed (never silently auto-proceed).
 */
export async function confirmGate(
  ceremony: CeremonyKind,
  yes: boolean,
  confirm: ConfirmFn | undefined,
  println: (line: string) => void,
): Promise<void> {
  if (yes) {
    println(`(--yes) skipping the interactive confirmation prompt for ${ceremony}.`);
    return;
  }
  if (!confirm) {
    throw new CliError(
      `${ceremony} needs interactive confirmation: attach a terminal, or ` +
        `pass --yes for deliberate non-interactive/automated use — refusing.`,
    );
  }
  const ok = await confirm({ ceremony, phrase: confirmPhrase(ceremony) });
  if (!ok) {
    throw new CliError(
      `${ceremony} aborted at the confirmation prompt — nothing was signed or written.`,
    );
  }
}

export interface CeremonyRunEnv {
  println: (line: string) => void;
  io?: KeySourceFs;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
  confirm?: ConfirmFn;
}

/**
 * The run-path orchestrator. Banner → preview → (real path) confirm →
 * sign. Returns the signed envelope, or `null` for a dry-run (the
 * caller then returns exit 0 without writing). The confirm + the signer
 * load (the only token/PIN touch) happen strictly AFTER the operator
 * has seen the exact bytes.
 */
export async function previewConfirmSign<U, X>(
  a: Assembled<U>,
  signWith: (unsigned: U, signers: Ed25519Signer[]) => Promise<X>,
  opts: { dryRun: boolean; yes: boolean; env: CeremonyRunEnv },
): Promise<X | null> {
  for (const line of ceremonyBanner(a)) opts.env.println(line);
  renderPreview(a, opts.env.println, opts.dryRun ? "dry-run" : "review");
  if (opts.dryRun) return null;
  await confirmGate(a.ceremony, opts.yes, opts.env.confirm, opts.env.println);
  const sopts: SignerOptions = {
    io: opts.env.io,
    pivTransport: opts.env.pivTransport,
    pivPin: opts.env.pivPin,
  };
  return signAssembled(a, signWith, sopts);
}

/**
 * Phase 2: load the real signer (the only token/PIN touch), verify it
 * resolves to the pubkey the assembled bytes name, and sign. Fail-closed
 * if they differ — a signature over bytes whose `signedBy` is some other
 * key would never verify; refusing loudly here turns a silent
 * wrong-token mistake into a clear, ceremony-grade message.
 */
export async function signAssembled<U, X>(
  a: Assembled<U>,
  signWith: (unsigned: U, signers: Ed25519Signer[]) => Promise<X>,
  sopts: SignerOptions,
): Promise<X> {
  const signer = await loadSigner(a.signingKeySource, sopts);
  if (signer.pubKey !== a.signedBy) {
    throw new CliError(
      `the signing key resolved to ${signer.pubKey.slice(0, 8)}… but the ` +
        `${a.ceremony} bytes name ${a.signedBy.slice(0, 8)}… as the signer ` +
        `— refusing to sign (wrong/swapped YubiKey or key file?).`,
    );
  }
  return signWith(a.unsigned, [signer]);
}
