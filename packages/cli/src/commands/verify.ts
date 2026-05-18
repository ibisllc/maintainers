/**
 * `maintainers verify` — read .maintainers/ and verify everything.
 * `maintainers status` — read .maintainers/ and print a summary (no exit on partial failure).
 *
 * Both walk the same code path; the difference is verify exits non-zero on
 * any failure, while status reports the same data without failing.
 *
 * **LOCKED Phase-2 v2 model.** Each track is verified FORWARD from a
 * pinned mandate (`verifyMandateChainFromPin`); succession policy is
 * INLINE in each `Mandate` (no `policy.json`); endorsements verify
 * holder-signs against the v2 release chain. There is no
 * holder-in-window vs after-expiry split — "expired" is simply
 * `currentAuthority === null`.
 *
 * **No baked pin (the c4.5a/b/c preview pattern).** The CLI verifies an
 * arbitrary on-disk `.maintainers/` folder with NO compiled-in
 * `MAINTAINER_PINNED_MANDATE_HASH`, so it anchors each track at the
 * FIRST on-repo mandate's `mandatePinHash` (`safePinHash`). This is
 * read-only inspection — the v2 security boundary is UNCHANGED: real
 * trust is the pin a downstream consumer BAKES into its signed build
 * and walks forward from. An empty mandate list ⇒
 * `verifyMandateChainFromPin("", …)` ⇒ `rootError:"no-pin"` ⇒
 * fail-closed (the #30 invariant, generalised).
 */

import {
  currentAuthority,
  mandatePinHash,
  verifyChainOfEndorsements,
  verifyMandateChainFromPin,
  type Mandate,
  type VerifiedChain,
  type VerifiedEndorsements,
} from "@maintainers/protocol";
import { CliError, type ParsedArgs, optionalFlag } from "../lib/args.js";
import { readStore } from "../lib/store.js";

export interface VerifyReport {
  rootDir: string;
  tracks: TrackReport[];
  endorsementsTotal: number;
  endorsementsValid: number;
  endorsementsRejected: number;
  endorsementErrors: { detail?: string; reason: string; releaseId: string }[];
}

export interface TrackReport {
  track: string;
  /** Did this track anchor a forward chain (root resolved)? */
  anchored: boolean;
  /** Why the anchor failed (the L1 fail-closed cases), if it did. */
  rootError: string | null;
  totalMandates: number;
  validMandates: number;
  rejections: { mandateId: string; reason: string; detail?: string }[];
  currentHolder: string | null;
  currentMandateExpiresAt: string | null;
  msUntilExpiry: number | null;
  successors: string[];
  /**
   * v2 has no holder-in-window-vs-after-expiry split. When there is no
   * live authority, this is the most-recent valid mandate's holder (its
   * window has elapsed); its `successors` are who may continue the
   * track. Informational only.
   */
  lastExpiredHolder: string | null;
}

/**
 * Forward-verify a track anchored at its first on-repo mandate. An
 * empty log ⇒ empty pin ⇒ `rootError:"no-pin"` ⇒ fail-closed.
 */
function verifyTrackChain(mandates: Mandate[]): VerifiedChain {
  const pin = mandates.length > 0 ? safePinHash(mandates[0]!) : "";
  return verifyMandateChainFromPin(pin, mandates);
}

function safePinHash(m: Mandate): string {
  try {
    return mandatePinHash(m);
  } catch {
    // An adversarial first mandate that won't canonicalize ⇒ no anchor
    // ⇒ pin-not-in-log ⇒ fail-closed.
    return "";
  }
}

export function buildReport(rootDir: string, now: Date): VerifyReport {
  const store = readStore(rootDir);
  const tracks: TrackReport[] = [];
  let endorsementsTotal = 0;
  let endorsementsValid = 0;
  let endorsementsRejected = 0;
  const endorsementErrors: VerifyReport["endorsementErrors"] = [];

  const verifiedTracks = new Map<string, VerifiedChain>();

  for (const [name, mandates] of store.mandatesByTrack.entries()) {
    const chain = verifyTrackChain(mandates);
    verifiedTracks.set(name, chain);

    if (chain.root === null) {
      tracks.push({
        track: name,
        anchored: false,
        rootError: chain.rootError ?? "no-forward-chain",
        totalMandates: mandates.length,
        validMandates: 0,
        rejections: chain.rejections.map((r) => ({
          mandateId: r.mandate.mandateId,
          reason: r.reason,
          detail: r.detail,
        })),
        currentHolder: null,
        currentMandateExpiresAt: null,
        msUntilExpiry: null,
        successors: [],
        lastExpiredHolder: null,
      });
      continue;
    }

    const auth = currentAuthority(chain, now);
    const last: Mandate | null =
      chain.validMandates[chain.validMandates.length - 1] ?? null;
    const expired = !auth ? last : null;
    tracks.push({
      track: name,
      anchored: true,
      rootError: null,
      totalMandates: mandates.length,
      validMandates: chain.validMandates.length,
      rejections: chain.rejections.map((r) => ({
        mandateId: r.mandate.mandateId,
        reason: r.reason,
        detail: r.detail,
      })),
      currentHolder: auth ? auth.holder : null,
      currentMandateExpiresAt: auth ? auth.mandate.expiresAt : null,
      msUntilExpiry: auth ? Date.parse(auth.mandate.expiresAt) - now.getTime() : null,
      successors: auth ? auth.successors : (expired ? expired.successors : []),
      lastExpiredHolder: expired ? expired.holder : null,
    });
  }

  // Endorsements verify holder-signs against the v2 release chain.
  if (store.endorsements.length > 0) {
    const releaseChain = verifiedTracks.get("release");
    if (!releaseChain || releaseChain.root === null) {
      endorsementsTotal = store.endorsements.length;
      endorsementsRejected = store.endorsements.length;
      for (const e of store.endorsements) {
        endorsementErrors.push({
          releaseId: e.releaseId,
          reason: "no-release-chain",
          detail: "endorsements present but the release track did not anchor a forward chain",
        });
      }
    } else {
      const result: VerifiedEndorsements = verifyChainOfEndorsements(
        store.endorsements,
        releaseChain,
      );
      endorsementsTotal = result.endorsements.length;
      endorsementsValid = result.validEndorsements.length;
      endorsementsRejected = result.rejections.length;
      for (const r of result.rejections) {
        endorsementErrors.push({
          releaseId: r.endorsement.releaseId,
          reason: r.reason,
          detail: r.detail,
        });
      }
    }
  }

  return {
    rootDir,
    tracks,
    endorsementsTotal,
    endorsementsValid,
    endorsementsRejected,
    endorsementErrors,
  };
}

export interface VerifyCmdEnv {
  now: () => Date;
  println: (line: string) => void;
}

export function runVerify(args: ParsedArgs, env: VerifyCmdEnv): number {
  const rootDir = optionalFlag(args, "path") ?? ".maintainers";
  const asOfFlag = optionalFlag(args, "as-of");
  const now = parseAsOf(asOfFlag, env.now());
  const report = buildReport(rootDir, now);
  printReport(report, env.println);
  let ok = true;
  for (const t of report.tracks) {
    if (!t.anchored) {
      env.println(
        `error: track "${t.track}" did not anchor a forward chain` +
          `${t.rootError ? ` (${t.rootError})` : ""}`,
      );
      ok = false;
    }
    if (t.rejections.length > 0) ok = false;
  }
  if (report.endorsementsRejected > 0) ok = false;
  if (!ok) {
    env.println("verify: FAIL");
    return 1;
  }
  env.println("verify: OK");
  return 0;
}

export function runStatus(args: ParsedArgs, env: VerifyCmdEnv): number {
  const rootDir = optionalFlag(args, "path") ?? ".maintainers";
  const asOfFlag = optionalFlag(args, "as-of");
  const now = parseAsOf(asOfFlag, env.now());
  const report = buildReport(rootDir, now);
  printReport(report, env.println);
  return 0;
}

function printReport(r: VerifyReport, println: (l: string) => void): void {
  println(`maintainers store at ${r.rootDir}`);
  if (r.tracks.length === 0) {
    println("  no tracks discovered");
  }
  for (const t of r.tracks) {
    println("");
    println(`  track: ${t.track}`);
    println(
      `    anchored:         ${t.anchored ? "yes" : `NO (${t.rootError ?? "no-forward-chain"})`}`,
    );
    println(`    mandates (total): ${t.totalMandates}`);
    println(`    mandates (valid): ${t.validMandates}`);
    if (t.rejections.length > 0) {
      println(`    rejections:`);
      for (const rej of t.rejections) {
        println(`      - ${rej.mandateId.slice(0, 8)}… ${rej.reason}${rej.detail ? ` (${rej.detail})` : ""}`);
      }
    }
    if (t.currentHolder) {
      println(`    current holder:   ${t.currentHolder}`);
      println(`    expires at:       ${t.currentMandateExpiresAt}`);
      if (t.msUntilExpiry !== null) {
        const days = Math.floor(t.msUntilExpiry / (24 * 60 * 60 * 1000));
        const hours = Math.floor((t.msUntilExpiry % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));
        println(`    time remaining:   ${days}d ${hours}h`);
      }
      println(`    successors:       ${t.successors.length === 0 ? "(none)" : t.successors.map((s) => s.slice(0, 16) + "…").join(", ")}`);
    } else {
      println(`    current holder:   (none — track expired pending succession)`);
      if (t.lastExpiredHolder) {
        println(`    last holder:      ${t.lastExpiredHolder}`);
        println(`    successors:       ${t.successors.length === 0 ? "(none)" : t.successors.map((s) => s.slice(0, 16) + "…").join(", ")}`);
      }
    }
  }
  println("");
  println(`  endorsements: ${r.endorsementsValid}/${r.endorsementsTotal} valid`);
  if (r.endorsementsRejected > 0) {
    println(`  endorsement errors:`);
    for (const e of r.endorsementErrors) {
      println(`    - ${e.releaseId.slice(0, 8)}… ${e.reason}${e.detail ? ` (${e.detail})` : ""}`);
    }
  }
}

function parseAsOf(spec: string | undefined, fallback: Date): Date {
  if (!spec || spec === "now") return fallback;
  const t = Date.parse(spec);
  if (!Number.isFinite(t)) {
    throw new CliError(`invalid --as-of "${spec}"; expected RFC3339 or "now"`);
  }
  return new Date(t);
}

export const _internal = { parseAsOf, printReport, verifyTrackChain };
