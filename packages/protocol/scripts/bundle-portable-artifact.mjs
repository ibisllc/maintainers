/**
 * prepack step — stage the portable artifact INTO the package dir so npm
 * can include it in the tarball (npm `files` cannot reach outside the
 * package directory).
 *
 * Copies, deterministically:
 *   <repo>/conformance/        -> packages/protocol/conformance/
 *   <repo>/docs/spec/v1.md     -> packages/protocol/SPEC.md
 *
 * Both copy targets are gitignored pack artifacts: never committed,
 * always regenerated fresh from the canonical source on `npm pack` /
 * `npm publish`. The conformance set + spec are the protocol's primary
 * portable artifact (#35) — a non-TS adopter installing the npm package
 * gets the full conformance vectors and the normative spec, not just
 * the compiled TypeScript.
 *
 * Deterministic: a plain recursive file copy, no timestamps embedded in
 * content, sorted directory walk. Re-running yields byte-identical
 * targets.
 */
import {
  cpSync,
  copyFileSync,
  rmSync,
  existsSync,
  mkdirSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pkgDir = join(here, "..");
const repoRoot = join(pkgDir, "..", "..");

const srcConformance = join(repoRoot, "conformance");
const dstConformance = join(pkgDir, "conformance");
const srcSpec = join(repoRoot, "docs", "spec", "v1.md");
const dstSpec = join(pkgDir, "SPEC.md");

if (!existsSync(srcConformance)) {
  throw new Error(`portable-artifact: missing ${srcConformance}`);
}
if (!existsSync(srcSpec)) {
  throw new Error(`portable-artifact: missing ${srcSpec}`);
}

// Idempotent: clear any prior staged copy so a removed vector cannot
// linger in the tarball.
rmSync(dstConformance, { recursive: true, force: true });
rmSync(dstSpec, { force: true });

mkdirSync(dstConformance, { recursive: true });
cpSync(srcConformance, dstConformance, { recursive: true });
copyFileSync(srcSpec, dstSpec);

console.log(
  `portable-artifact: staged conformance/ + SPEC.md into ${pkgDir}`,
);
