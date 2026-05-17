/**
 * Shared ceremony scaffolding for the four maintainer-key commands
 * (genesis / mandate / takeover / ca-endorsement).
 *
 * The security-critical invariant this module enforces: the bytes a
 * `--dry-run` previews are EXACTLY the bytes the real run signs. We get
 * that by splitting every ceremony into two phases —
 *
 *   1. `assemble*`  — pure: validate inputs, read the store + PUBLIC
 *      keys only (PIV public read = no PIN/tap; `file:` priv = derived,
 *      never signed, never logged), build the *unsigned* envelope and
 *      its canonical bytes + the path that WOULD be written. Touches no
 *      private key operation and writes nothing.
 *   2. sign         — `signAssembled` loads the real signer (the only
 *      step that touches the token/PIN), re-checks the resolved pubkey
 *      against the assembled `signedBy` (fail-closed if the token was
 *      swapped between phases), and produces the signed envelope.
 *
 * `--dry-run` runs phase 1 and prints; it never reaches phase 2.
 */

import type { Ed25519Signer } from "@maintainers/protocol";
import { loadSigner, type SignerOptions } from "./keysource.js";
import { CliError } from "./args.js";

export type CeremonyKind = "genesis" | "mandate" | "takeover" | "ca-endorsement";

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
}

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/**
 * Render a dry-run preview: the exact canonical bytes (hex + the
 * human-auditable utf-8 rendering — canonical bytes are a printable
 * tagged pipe-joined string by construction) and the unsigned
 * `.maintainers` diff. Signs nothing, writes nothing.
 */
export function renderDryRun<U>(
  a: Assembled<U>,
  println: (line: string) => void,
): void {
  println("");
  println(`═══ DRY RUN — ${a.ceremony} — NOTHING was signed or written ═══`);
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
