/**
 * `maintainers create-key` — self-register a KeyFile (LOCKED Phase-2 v2).
 *
 * Each key self-registers under a human-readable identity label
 * (display name + email). This is INDEPENDENT and non-load-bearing: the
 * protocol identifies holders by Ed25519 pubkey; emails are
 * "conventional but not load-bearing" (spec non-goal). A non-chained
 * KeyFile carries ZERO authority — so free self-registration is safe,
 * and there is deliberately no `--mandate-id`/`introductionMandate`
 * bootstrap (that v1-era sub-plan is OBSOLETE under the v2 lock; the
 * field stays an optional, non-cross-checked audit pointer that
 * defaults to the nil UUID = "self-registered, no introduction").
 *
 * The KeyFile carries a SINGLE self-signature: it is signed by the very
 * key it describes, so the signer's pubkey MUST equal the envelope's
 * `pubkey`. Signed via the c1 external-self-signer seam
 * (`signKeyFileWith`) so a YubiKey-PIV key can self-register from the
 * token; `file:` hex is the lower-assurance fallback. Same #28 ceremony
 * discipline as the mandate verbs (assemble/sign split, `--dry-run`
 * exact bytes + diff, banner, typed confirm, never-log-secrets,
 * fail-closed) — kept on the ONE ceremony path for uniformity, with a
 * banner that honestly states this is low-stakes.
 */

import { signKeyFileWith, canonicalKeyFile, type KeyFile } from "@ibisllc/maintainers";
import * as path from "node:path";
import {
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
import { writeKeyFile, keyFileFilename } from "../lib/store.js";

/** Sentinel for "self-registered, no introducing mandate" (v2 norm). */
const NIL_UUID = "00000000-0000-0000-0000-000000000000";

export interface CreateKeyOptions {
  signingKeySource: string;
  displayName: string;
  email: string;
  introductionMandate: string | undefined;
  photo: string | undefined;
  github: string | undefined;
  role: string | undefined;
  rootDir: string;
  now: () => Date;
  io: KeySourceFs;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
}

function signerOpts(opts: CreateKeyOptions): SignerOptions {
  return { io: opts.io, pivTransport: opts.pivTransport, pivPin: opts.pivPin };
}

type UnsignedKeyFile = Omit<KeyFile, "signature">;

/**
 * Phase 1 — pure: read the signer's PUBLIC key only (no PIN/tap/sign/
 * write), build the unsigned self-signed KeyFile + canonical bytes +
 * the path that WOULD be written.
 */
export async function assembleCreateKey(
  opts: CreateKeyOptions,
): Promise<Assembled<UnsignedKeyFile>> {
  const pubkey = await loadSignerBoundPubKey(opts.signingKeySource, signerOpts(opts));
  const nowIso = opts.now().toISOString();
  const unsigned: UnsignedKeyFile = {
    kind: "KeyFile",
    version: 1,
    pubkey,
    displayName: opts.displayName,
    currentEmail: opts.email,
    emailHistory: [{ email: opts.email, from: nowIso, to: null }],
    metadata: {
      photo: opts.photo ?? null,
      github: opts.github ?? null,
      role: opts.role ?? null,
    },
    introductionMandate: opts.introductionMandate ?? NIL_UUID,
  };
  return {
    ceremony: "create-key",
    unsigned,
    canonical: canonicalKeyFile(unsigned),
    signingKeySource: opts.signingKeySource,
    signedBy: pubkey, // self-signed: the signer MUST be this very key
    rootDir: opts.rootDir,
    targetRelative: path.join("keys", keyFileFilename(opts.email)),
  };
}

export async function buildCreateKey(opts: CreateKeyOptions): Promise<KeyFile> {
  const a = await assembleCreateKey(opts);
  return signAssembled(a, signKeyFileWith, signerOpts(opts));
}

export interface CreateKeyCmdEnv {
  now: () => Date;
  io: KeySourceFs;
  println: (line: string) => void;
  pivTransport?: PivTransport;
  pivPin?: PivPinProvider;
  confirm?: ConfirmFn;
}

export async function runCreateKey(args: ParsedArgs, env: CreateKeyCmdEnv): Promise<number> {
  const signingKey = requireFlag(args, "signing-key");
  const displayName = requireFlag(args, "display-name");
  const email = requireFlag(args, "email");
  const introductionMandate = optionalFlag(args, "introduction-mandate");
  const photo = optionalFlag(args, "photo");
  const github = optionalFlag(args, "github");
  const role = optionalFlag(args, "role");
  const rootDir = optionalFlag(args, "path") ?? ".maintainers";
  const dryRun = boolFlag(args, "dry-run");
  const yes = boolFlag(args, "yes");

  const a = await assembleCreateKey({
    signingKeySource: signingKey,
    displayName,
    email,
    introductionMandate,
    photo,
    github,
    role,
    rootDir,
    now: env.now,
    io: env.io,
    pivTransport: env.pivTransport,
    pivPin: env.pivPin,
  });

  const keyFile = await previewConfirmSign(a, signKeyFileWith, {
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
  if (!keyFile) return 0; // dry-run

  if (keyFile.introductionMandate === NIL_UUID) {
    // not an error — the v2 norm; surface it so it isn't mistaken for a bug
    env.println(
      "note: no --introduction-mandate given → recorded as self-registered " +
        "(the nil UUID). A key file is non-load-bearing; this is expected.",
    );
  }
  const written = writeKeyFile(a.rootDir, keyFile);
  env.println(`wrote key file → ${written.relative}`);
  env.println(`  pubkey:      ${keyFile.pubkey}`);
  env.println(`  displayName: ${keyFile.displayName}`);
  env.println(`  email:       ${keyFile.currentEmail}`);
  return 0;
}
