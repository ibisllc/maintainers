/**
 * On-disk .maintainers/ folder I/O.
 *
 * Matches §7 of the spec:
 *   .maintainers/
 *   ├── policy.json
 *   ├── keys/<email>.json
 *   ├── tracks/<track>/policy.json
 *   ├── tracks/<track>/mandates/<iso>-<summary>.json
 *   ├── endorsements/<semver-tag>.json
 *   └── ca-endorsements/<iso>-<short-id>.json   (the weekly CA lease)
 *
 * The reader returns parsed envelopes; the writer canonicalizes filenames and
 * refuses to overwrite. Both sides are pure-fs and have no git awareness —
 * git is the canonical-log layer above us.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type {
  CaEndorsement,
  KeyFile,
  Mandate,
  MandateV2,
  ReleaseEndorsement,
  RootPolicy,
  TrackPolicy,
} from "@maintainers/protocol";
import { CliError } from "./args.js";

export interface MaintainersStore {
  rootDir: string;
  rootPolicy: RootPolicy | null;
  trackPolicies: Map<string, TrackPolicy>;
  mandatesByTrack: Map<string, Mandate[]>;
  endorsements: ReleaseEndorsement[];
}

export function readStore(rootDir: string): MaintainersStore {
  const out: MaintainersStore = {
    rootDir,
    rootPolicy: null,
    trackPolicies: new Map(),
    mandatesByTrack: new Map(),
    endorsements: [],
  };

  const rootPolicyPath = path.join(rootDir, "policy.json");
  if (fs.existsSync(rootPolicyPath)) {
    out.rootPolicy = readJson(rootPolicyPath) as RootPolicy;
  }

  const tracksDir = path.join(rootDir, "tracks");
  if (fs.existsSync(tracksDir) && fs.statSync(tracksDir).isDirectory()) {
    for (const name of fs.readdirSync(tracksDir).sort()) {
      const trackDir = path.join(tracksDir, name);
      if (!fs.statSync(trackDir).isDirectory()) continue;
      const policyPath = path.join(trackDir, "policy.json");
      if (fs.existsSync(policyPath)) {
        out.trackPolicies.set(name, readJson(policyPath) as TrackPolicy);
      }
      const mandatesDir = path.join(trackDir, "mandates");
      if (fs.existsSync(mandatesDir) && fs.statSync(mandatesDir).isDirectory()) {
        const files = fs.readdirSync(mandatesDir)
          .filter((f) => f.endsWith(".json"))
          .sort();
        const arr: Mandate[] = [];
        for (const f of files) {
          const parsed = readJson(path.join(mandatesDir, f));
          if (isMandate(parsed)) arr.push(parsed);
        }
        out.mandatesByTrack.set(name, arr);
      } else {
        out.mandatesByTrack.set(name, []);
      }
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

export function writeMandate(rootDir: string, m: Mandate): WrittenPath {
  const dir = path.join(rootDir, "tracks", m.track, "mandates");
  fs.mkdirSync(dir, { recursive: true });
  const file = mandateFilename(m);
  const abs = path.join(dir, file);
  if (fs.existsSync(abs)) {
    throw new CliError(`refusing to overwrite existing mandate file: ${abs}`);
  }
  fs.writeFileSync(abs, JSON.stringify(m, null, 2) + "\n", "utf8");
  return { absolute: abs, relative: path.relative(rootDir, abs) };
}

/**
 * Read a track's v2 mandate log (LOCKED Phase-2 v2). Same on-disk
 * directory convention as v1 (`tracks/<track>/mandates/*.json`,
 * filename-sorted as the canonical-log substitute — real adapters get
 * order from git), but filtered to `version === 2`. There is NO
 * `policy.json` in v2: the succession policy is folded INTO each
 * mandate. The published static-fetch layout (`tracks/<t>/log.json`)
 * is a later (c5) distribution artifact; the CLI's authoring store
 * stays file-per-mandate.
 */
export function readMandatesV2(rootDir: string, track: string): MandateV2[] {
  const dir = path.join(rootDir, "tracks", track, "mandates");
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) return [];
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
  const out: MandateV2[] = [];
  for (const f of files) {
    const parsed = readJson(path.join(dir, f));
    if (isMandateV2(parsed)) out.push(parsed);
  }
  return out;
}

/**
 * Write a v2 mandate under `tracks/<track>/mandates/<compact-iso>-<id>.json`.
 * Append-only (refuse-overwrite); the from-scratch (root) mandate and
 * every successor are distinct files, by design.
 */
export function writeMandateV2(rootDir: string, m: MandateV2): WrittenPath {
  const dir = path.join(rootDir, "tracks", m.track, "mandates");
  fs.mkdirSync(dir, { recursive: true });
  const abs = path.join(dir, mandateFilename(m));
  if (fs.existsSync(abs)) {
    throw new CliError(`refusing to overwrite existing mandate file: ${abs}`);
  }
  fs.writeFileSync(abs, JSON.stringify(m, null, 2) + "\n", "utf8");
  return { absolute: abs, relative: path.relative(rootDir, abs) };
}

function isMandateV2(x: unknown): x is MandateV2 {
  if (typeof x !== "object" || x === null) return false;
  const o = x as Record<string, unknown>;
  return (
    o.kind === "Mandate" &&
    o.version === 2 &&
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

export function writeTrackPolicyIfMissing(
  rootDir: string,
  policy: TrackPolicy,
): WrittenPath | null {
  const dir = path.join(rootDir, "tracks", policy.track);
  fs.mkdirSync(dir, { recursive: true });
  const abs = path.join(dir, "policy.json");
  if (fs.existsSync(abs)) return null;
  fs.writeFileSync(abs, JSON.stringify(policy, null, 2) + "\n", "utf8");
  return { absolute: abs, relative: path.relative(rootDir, abs) };
}

export function writeRootPolicyIfMissing(
  rootDir: string,
  policy: RootPolicy,
): WrittenPath | null {
  fs.mkdirSync(rootDir, { recursive: true });
  const abs = path.join(rootDir, "policy.json");
  if (fs.existsSync(abs)) return null;
  fs.writeFileSync(abs, JSON.stringify(policy, null, 2) + "\n", "utf8");
  return { absolute: abs, relative: path.relative(rootDir, abs) };
}

/**
 * Build a mandate filename: `<iso-zulu-compact>-<short-id>.json`. The compact
 * timestamp keeps directory listings sortable; the short id disambiguates
 * mandates issued in the same second. Accepts the unsigned shape too so the
 * `--dry-run` preview can show the exact path that WOULD be written.
 */
export function mandateFilename(m: Pick<Mandate, "issuedAt" | "mandateId">): string {
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

function isMandate(x: unknown): x is Mandate {
  if (typeof x !== "object" || x === null) return false;
  const obj = x as Record<string, unknown>;
  return obj.kind === "Mandate" && obj.version === 1
    && typeof obj.mandateId === "string"
    && typeof obj.track === "string"
    && typeof obj.holder === "string"
    && typeof obj.issuedAt === "string"
    && typeof obj.expiresAt === "string"
    && Array.isArray(obj.successors)
    && typeof obj.signedBy === "string"
    && Array.isArray(obj.signatures);
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
