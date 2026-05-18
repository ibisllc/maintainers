/**
 * On-disk .maintainers/ folder I/O (LOCKED Phase-2 v2 model).
 *
 *   .maintainers/
 *   ├── keys/<email>.json
 *   ├── tracks/<track>/mandates/<iso>-<id>.json   (v2 Mandate only)
 *   ├── endorsements/<semver-tag>.json
 *   └── ca-endorsements/<iso>-<short-id>.json      (the weekly CA lease)
 *
 * There is **no `policy.json`** (root or per-track) in v2: the
 * succession rule (approvalRule + successors + minSuccessors +
 * maxDurationSeconds) lives INLINE in each `Mandate`, and the
 * project-level contact/track-list rides the from-scratch (root)
 * mandate's inline `project` field (L2). A v1 `Mandate` file
 * (`version: 1`) is malformed for this store and is silently ignored,
 * never parsed.
 *
 * The reader returns parsed v2 envelopes; the writer canonicalizes
 * filenames and refuses to overwrite. Both sides are pure-fs and have no
 * git awareness — git is the canonical-log layer above us.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type {
  CaEndorsement,
  KeyFile,
  Mandate,
  ReleaseEndorsement,
} from "@ibisllc/maintainers";
import { CliError } from "./args.js";

export interface MaintainersStore {
  rootDir: string;
  mandatesByTrack: Map<string, Mandate[]>;
  endorsements: ReleaseEndorsement[];
}

export function readStore(rootDir: string): MaintainersStore {
  const out: MaintainersStore = {
    rootDir,
    mandatesByTrack: new Map(),
    endorsements: [],
  };

  const tracksDir = path.join(rootDir, "tracks");
  if (fs.existsSync(tracksDir) && fs.statSync(tracksDir).isDirectory()) {
    for (const name of fs.readdirSync(tracksDir).sort()) {
      const trackDir = path.join(tracksDir, name);
      if (!fs.statSync(trackDir).isDirectory()) continue;
      out.mandatesByTrack.set(name, readMandates(rootDir, name));
    }
  }

  const endorsementsDir = path.join(rootDir, "endorsements");
  if (fs.existsSync(endorsementsDir) && fs.statSync(endorsementsDir).isDirectory()) {
    const files = fs.readdirSync(endorsementsDir)
      .filter((f) => f.endsWith(".json"))
      .sort();
    for (const f of files) {
      const parsed = readJson(path.join(endorsementsDir, f));
      if (isReleaseEndorsement(parsed)) out.endorsements.push(parsed);
    }
    // Order by issuedAt as a stable canonical-log substitute (real adapters
    // get this from git commit order, but the on-disk view used by verify/
    // status only sees timestamps).
    out.endorsements.sort((a, b) => Date.parse(a.issuedAt) - Date.parse(b.issuedAt));
  }

  return out;
}

export interface WrittenPath {
  absolute: string;
  relative: string;
}

/**
 * Read a track's v2 mandate log (LOCKED Phase-2 v2). On-disk directory
 * convention `tracks/<track>/mandates/*.json`, filename-sorted as the
 * canonical-log substitute (real adapters get order from git), filtered
 * to `version === 1`. There is NO `policy.json`: the succession policy
 * is folded INTO each mandate. The published static-fetch layout
 * (`tracks/<t>/log.json`) is a later (c5) distribution artifact; the
 * CLI's authoring store stays file-per-mandate.
 */
export function readMandates(rootDir: string, track: string): Mandate[] {
  const dir = path.join(rootDir, "tracks", track, "mandates");
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) return [];
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
  const out: Mandate[] = [];
  for (const f of files) {
    const parsed = readJson(path.join(dir, f));
    if (isMandate(parsed)) out.push(parsed);
  }
  return out;
}

/**
 * Write a v2 mandate under `tracks/<track>/mandates/<compact-iso>-<id>.json`.
 * Append-only (refuse-overwrite); the from-scratch (root) mandate and
 * every successor are distinct files, by design.
 */
export function writeMandate(rootDir: string, m: Mandate): WrittenPath {
  const dir = path.join(rootDir, "tracks", m.track, "mandates");
  fs.mkdirSync(dir, { recursive: true });
  const abs = path.join(dir, mandateFilename(m));
  if (fs.existsSync(abs)) {
    throw new CliError(`refusing to overwrite existing mandate file: ${abs}`);
  }
  fs.writeFileSync(abs, JSON.stringify(m, null, 2) + "\n", "utf8");
  return { absolute: abs, relative: path.relative(rootDir, abs) };
}

function isMandate(x: unknown): x is Mandate {
  if (typeof x !== "object" || x === null) return false;
  const o = x as Record<string, unknown>;
  return (
    o.kind === "Mandate" &&
    o.version === 1 &&
    typeof o.mandateId === "string" &&
    typeof o.track === "string" &&
    typeof o.holder === "string" &&
    typeof o.issuedAt === "string" &&
    typeof o.expiresAt === "string" &&
    Array.isArray(o.successors) &&
    typeof o.approvalRule === "object" &&
    o.approvalRule !== null &&
    typeof o.minSuccessors === "number" &&
    typeof o.maxDurationSeconds === "number" &&
    typeof o.signedBy === "string" &&
    Array.isArray(o.signatures)
  );
}

export function writeEndorsement(rootDir: string, e: ReleaseEndorsement): WrittenPath {
  const dir = path.join(rootDir, "endorsements");
  fs.mkdirSync(dir, { recursive: true });
  const safeTag = e.semverTag.replace(/[^A-Za-z0-9.\-_+]/g, "_");
  const file = `${safeTag}.json`;
  const abs = path.join(dir, file);
  if (fs.existsSync(abs)) {
    throw new CliError(`refusing to overwrite existing endorsement file: ${abs}`);
  }
  fs.writeFileSync(abs, JSON.stringify(e, null, 2) + "\n", "utf8");
  return { absolute: abs, relative: path.relative(rootDir, abs) };
}

/**
 * Write a CaEndorsement (the weekly CA lease) under
 * `<rootDir>/ca-endorsements/`. This directory + filename convention is
 * the on-disk store contract for CA leases — `scripts/rotate-ca.mjs`
 * `readCaEndorsements()` reads exactly `<rootDir>/ca-endorsements/*.json`
 * and accepts any file whose JSON `kind === "CaEndorsement"`. The
 * compact-`notBefore` prefix keeps directory listings chronologically
 * sortable; the short id disambiguates leases issued in the same second.
 * Append-only: refuses to overwrite (overlapping leases are distinct
 * files, by design — §5.1).
 */
export function writeCaEndorsement(
  rootDir: string,
  e: CaEndorsement,
): WrittenPath {
  const dir = path.join(rootDir, "ca-endorsements");
  fs.mkdirSync(dir, { recursive: true });
  const abs = path.join(dir, caEndorsementFilename(e));
  if (fs.existsSync(abs)) {
    throw new CliError(`refusing to overwrite existing CA lease file: ${abs}`);
  }
  fs.writeFileSync(abs, JSON.stringify(e, null, 2) + "\n", "utf8");
  return { absolute: abs, relative: path.relative(rootDir, abs) };
}

/**
 * Filesystem-safe name for a key file: `keys/<sanitized-email>.json`.
 * Email is a human label, not a credential (spec non-goal — identity
 * for trust is the pubkey), so a lossy sanitization is fine for the
 * on-disk name; the authoritative `currentEmail` lives inside the
 * signed envelope.
 */
export function keyFileFilename(currentEmail: string): string {
  const safe = currentEmail.replace(/[^A-Za-z0-9.@_+-]/g, "_");
  return `${safe}.json`;
}

/**
 * Write a self-signed KeyFile under `<rootDir>/keys/<email>.json`
 * (spec §2.4 / §7). A KeyFile is a non-load-bearing identity label —
 * verification operates on the pubkey, never the email — so this is
 * deliberately low-stakes; still append-only (refuses to overwrite, so
 * a re-registration is an explicit delete/rename, never a silent
 * clobber of a record someone may be rendering).
 */
export function writeKeyFile(rootDir: string, k: KeyFile): WrittenPath {
  const dir = path.join(rootDir, "keys");
  fs.mkdirSync(dir, { recursive: true });
  const abs = path.join(dir, keyFileFilename(k.currentEmail));
  if (fs.existsSync(abs)) {
    throw new CliError(
      `refusing to overwrite existing key file: ${abs} ` +
        `(a re-registration must explicitly remove/rename the old file)`,
    );
  }
  fs.writeFileSync(abs, JSON.stringify(k, null, 2) + "\n", "utf8");
  return { absolute: abs, relative: path.relative(rootDir, abs) };
}

/**
 * Build a mandate filename: `<iso-zulu-compact>-<short-id>.json`. The compact
 * timestamp keeps directory listings sortable; the short id disambiguates
 * mandates issued in the same second. Accepts the unsigned shape too so the
 * `--dry-run` preview can show the exact path that WOULD be written.
 */
export function mandateFilename(
  m: Pick<Mandate, "issuedAt" | "mandateId">,
): string {
  const compact = m.issuedAt.replace(/[:\-]/g, "").replace(/\..*Z$/, "Z").replace(/Z$/, "");
  const safeCompact = compact.replace(/[^0-9T]/g, "");
  const shortId = m.mandateId.slice(0, 8);
  return `${safeCompact}-${shortId}.json`;
}

/**
 * Build a CA-lease filename: `<compact-notBefore>-<short-id>.json`. The
 * single source of truth for the `ca-endorsements/` filename convention
 * (used by {@link writeCaEndorsement} and the `--dry-run` preview);
 * `scripts/rotate-ca.mjs` reads any `*.json` here regardless of name, so
 * this only governs sortability/uniqueness, not discovery.
 */
export function caEndorsementFilename(
  e: Pick<CaEndorsement, "notBefore" | "endorsementId">,
): string {
  const compact = e.notBefore
    .replace(/[:\-]/g, "")
    .replace(/\..*Z$/, "Z")
    .replace(/Z$/, "")
    .replace(/[^0-9T]/g, "");
  const shortId = e.endorsementId.replace(/[^A-Za-z0-9]/g, "").slice(0, 8);
  return `${compact}-${shortId}.json`;
}

function readJson(p: string): unknown {
  let raw: string;
  try {
    raw = fs.readFileSync(p, "utf8");
  } catch (err) {
    throw new CliError(`failed to read ${p}: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new CliError(`failed to parse JSON in ${p}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function isReleaseEndorsement(x: unknown): x is ReleaseEndorsement {
  if (typeof x !== "object" || x === null) return false;
  const obj = x as Record<string, unknown>;
  return obj.kind === "ReleaseEndorsement" && obj.version === 1
    && typeof obj.releaseId === "string"
    && typeof obj.commitHash === "string"
    && typeof obj.intermediateMerkleRoot === "string"
    && typeof obj.issuedAt === "string"
    && Array.isArray(obj.signatures)
    && Array.isArray(obj.intermediateCommits);
}
