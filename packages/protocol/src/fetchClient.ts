/**
 * Reference `fetch()` client — the canonical example a non-TS port
 * (#9 webapp, #10 iOS/Android) mirrors.
 *
 * It is the HTTP/raw-content form of the §7 Git-adapter layout: a
 * project commits ONE enumerable index at `.maintainers/index.json`
 * (the SAME convention `packages/extension/src/fetcher.ts` implements —
 * there is exactly ONE published layout), alongside content-addressed
 * mandate/key/endorsement files. Shared index.json contract (verbatim
 * from the extension fetcher):
 *
 *   {
 *     "version": 1,
 *     "tracks":  { "<track>": ["<rel-path>", ...] },
 *     "keys":    ["<rel-path>", ...],
 *     "endorsements": ["<rel-path>", ...]
 *   }
 *
 * Every path is repo-root-relative and MUST start with `.maintainers/`
 * (and contain no `..` / `\`); anything else is rejected to foreclose a
 * malicious index redirecting the client off-tree. There is NO
 * `policy.json` at any level — the succession rule is signed inline in
 * each Mandate (L2).
 *
 * The client:
 *   - takes a base URL, a baked pin (or pin set, one per track), and the
 *     consumer's OWN `now` (injectable; default `Date.now()`),
 *   - uses ONLY the global `fetch` — zero new dependency, no node-only
 *     API — to GET `<base>/.maintainers/index.json`, validate it, then
 *     GET the listed mandate/key/endorsement files,
 *   - runs the protocol verifier exactly as a real consumer must:
 *       verifyMandateChainFromPin(pin, mandates[track])
 *         -> currentAuthority(chain, now)
 *         -> verifyChainOfEndorsements(endorsements, releaseChain)
 *         -> verifyCaEndorsements / authorizedCaKeys (lease judged at
 *            the caller's OWN `now`),
 *   - returns a structured per-track verdict and is TOTAL: it never
 *     throws on adversarial input (mirrors the verifier's totality),
 *   - is fail-closed: no/empty pin ⇒ reject; missing / oversized /
 *     path-escaping index ⇒ reject; pin-not-in-log ⇒ reject.
 *
 * This is the published layout shared by the extension, this reference
 * client, #9 (webapp) and #10 (mobile). It does NOT fork the format.
 */

import { mandatePinHash } from "./canonical.js";
import {
  currentAuthority,
  verifyMandateChainFromPin,
  type V2RootFailReason,
  type VerifiedChain,
} from "./verifier.js";
import {
  verifyChainOfEndorsements,
  type VerifiedEndorsements,
} from "./endorsement.js";
import {
  authorizedCaKeys,
  verifyCaEndorsements,
  type VerifiedCaEndorsements,
} from "./caEndorsement.js";
import type {
  CaEndorsement,
  KeyFile,
  Mandate,
  Pubkey,
  ReleaseEndorsement,
} from "./types.js";

/**
 * Minimal structural fetch type — DELIBERATELY not the DOM/undici
 * `RequestInit` (the protocol package is lib-agnostic: it must compile
 * under `lib: ["ES2022"]` with no DOM, and a Swift/Kotlin port mirrors
 * only this shape). Any global `fetch` (browser, Node ≥18, Workers,
 * Deno, Bun) is assignable to it.
 */
export type FetchLike = (
  url: string,
  init?: { method?: string; redirect?: "follow" | "error" | "manual" },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

/** Max bytes for any single fetched document (mirrors the extension fetcher). */
const MAX_DOC_BYTES = 1_000_000;

/** The enumerable index a project commits (verbatim extension contract). */
export interface MaintainersIndex {
  version: 1;
  tracks: Record<string, string[]>;
  keys: string[];
  endorsements: string[];
}

export interface FetchClientOptions {
  /**
   * The baked pin. Either ONE pin (applied to whichever track the
   * caller verifies) or a per-track map `{ "<track>": "<pinHash>" }`.
   * An absent / empty pin for a track ⇒ that track fails closed
   * (`no-pin`) — the #30 invariant, generalised.
   */
  pin: string | Record<string, string>;
  /** The consumer's OWN clock. Injectable; defaults to `Date.now()`. */
  now?: Date;
  /** Override the global fetch (tests inject a fake). Defaults to `globalThis.fetch`. */
  fetch?: FetchLike;
  /**
   * Which track carries CA leases (D3 freshness). Defaults to `"ca"`.
   * Its newest valid CaEndorsement lease MUST contain the caller's own
   * `now` or every CA artifact is rejected.
   */
  caTrack?: string;
  /**
   * Which track carries ReleaseEndorsements. Defaults to `"release"`.
   */
  releaseTrack?: string;
  /** CaEndorsement window-edge skew (spec §7 default ±5 min). */
  clockSkewMs?: number;
}

/** Why the whole fetch step failed before any track could be verified. */
export type FetchClientError =
  | "index-fetch-failed" // index.json missing / HTTP error / unparseable
  | "index-too-large" // index.json exceeded MAX_DOC_BYTES
  | "index-shape-invalid"; // not `{version:1,...}`

export interface TrackVerdict {
  track: string;
  /** The pin used for this track (echoed). */
  pin: string;
  /** True iff a live authority holder exists at the caller's `now`. */
  accepted: boolean;
  /**
   * The exact landed fail-closed reason on rejection, or null on accept.
   * For a track with no live authority this is the chain's L1
   * `rootError` (`no-pin` / `pin-not-in-log` / `root-*`) when the chain
   * never anchored, else `no-authority-at-now` when it anchored but no
   * mandate's window contains `now`.
   */
  rejectReason: V2RootFailReason | "no-authority-at-now" | null;
  /** The holder pubkey live at `now`, or null. */
  holder: Pubkey | null;
  /** Forward-verified chain (root + accepted suffix + rejections). */
  chain: VerifiedChain;
}

export interface FetchClientVerdict {
  /** Set iff the index could not be fetched/validated — total fail-closed. */
  error?: FetchClientError;
  /** Per-track verdicts, keyed by track name. Empty on `error`. */
  tracks: Record<string, TrackVerdict>;
  /** ReleaseEndorsement verification over the release track, if present. */
  releaseEndorsements: VerifiedEndorsements | null;
  /** CaEndorsement verification over the ca track at the caller's `now`. */
  caEndorsements: VerifiedCaEndorsements | null;
  /**
   * The deduped operational keys a consumer may currently accept
   * CA-signed artifacts under (§9 link-3). `[]` ⇒ fail closed.
   */
  authorizedCaKeys: Pubkey[];
  /** Raw materialized inputs (post path-sanitization), for diagnostics. */
  fetched: {
    mandatesByTrack: Record<string, Mandate[]>;
    keys: KeyFile[];
    releaseEndorsements: ReleaseEndorsement[];
    caEndorsements: CaEndorsement[];
    /** Per-path fetch/sanitize errors (never fatal on their own). */
    errors: { path: string; error: string }[];
  };
}

function pinForTrack(
  pin: FetchClientOptions["pin"],
  track: string,
): string {
  if (typeof pin === "string") return pin;
  if (pin && typeof pin === "object") {
    const v = pin[track];
    return typeof v === "string" ? v : "";
  }
  return "";
}

function isSafePath(p: unknown): p is string {
  return (
    typeof p === "string" &&
    p.startsWith(".maintainers/") &&
    !p.includes("..") &&
    !p.includes("\\")
  );
}

/** Total: never throws. Returns null on any error/oversize/parse failure. */
async function getJson(
  base: string,
  relPath: string,
  doFetch: FetchLike,
): Promise<{ ok: true; value: unknown } | { ok: false; error: string }> {
  let url: string;
  try {
    url = joinUrl(base, relPath);
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
  try {
    const res = await doFetch(url, { method: "GET", redirect: "follow" });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const text = await res.text();
    if (text.length > MAX_DOC_BYTES) return { ok: false, error: "response too large" };
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

function joinUrl(base: string, relPath: string): string {
  const b = base.endsWith("/") ? base.slice(0, -1) : base;
  const p = relPath.replace(/^\/+/, "");
  return `${b}/${p}`;
}

function sanitizeIndex(
  raw: unknown,
  errors: { path: string; error: string }[],
): MaintainersIndex | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  if (r.version !== 1) return null;
  const safe: MaintainersIndex = { version: 1, tracks: {}, keys: [], endorsements: [] };
  if (r.tracks && typeof r.tracks === "object") {
    for (const [track, paths] of Object.entries(r.tracks as Record<string, unknown>)) {
      if (!Array.isArray(paths)) continue;
      const safePaths: string[] = [];
      for (const p of paths) {
        if (isSafePath(p)) safePaths.push(p);
        else errors.push({ path: String(p), error: "rejected: unsafe path in index.json" });
      }
      safe.tracks[track] = safePaths;
    }
  }
  if (Array.isArray(r.keys)) {
    for (const p of r.keys) {
      if (isSafePath(p)) safe.keys.push(p);
      else errors.push({ path: String(p), error: "rejected: unsafe key path in index.json" });
    }
  }
  if (Array.isArray(r.endorsements)) {
    for (const p of r.endorsements) {
      if (isSafePath(p)) safe.endorsements.push(p);
      else errors.push({ path: String(p), error: "rejected: unsafe endorsement path in index.json" });
    }
  }
  return safe;
}

function isMandateV1(v: unknown): v is Mandate {
  return (
    typeof v === "object" &&
    v !== null &&
    (v as { kind?: unknown }).kind === "Mandate" &&
    (v as { version?: unknown }).version === 1
  );
}

/**
 * Fetch a project's `.maintainers/` tree from `base` and run the full
 * protocol verifier against a baked pin at the caller's own `now`.
 *
 * TOTAL: never throws — every adversarial input (missing index,
 * oversized doc, path-escape, malformed envelope, absent/forked pin) is
 * a fail-closed return value, never an exception. This is the contract
 * a non-TS port reproduces, proven against the published conformance
 * vectors.
 */
export async function verifyFromFetch(
  base: string,
  opts: FetchClientOptions,
): Promise<FetchClientVerdict> {
  const now = opts.now ?? new Date();
  const doFetch: FetchLike =
    opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const caTrack = opts.caTrack ?? "ca";
  const releaseTrack = opts.releaseTrack ?? "release";
  const errors: { path: string; error: string }[] = [];

  const empty: FetchClientVerdict = {
    tracks: {},
    releaseEndorsements: null,
    caEndorsements: null,
    authorizedCaKeys: [],
    fetched: {
      mandatesByTrack: {},
      keys: [],
      releaseEndorsements: [],
      caEndorsements: [],
      errors,
    },
  };

  if (typeof doFetch !== "function") {
    return { ...empty, error: "index-fetch-failed" };
  }

  const idxResult = await getJson(base, ".maintainers/index.json", doFetch);
  if (!idxResult.ok) {
    return {
      ...empty,
      error: idxResult.error === "response too large" ? "index-too-large" : "index-fetch-failed",
    };
  }
  const index = sanitizeIndex(idxResult.value, errors);
  if (!index) {
    return { ...empty, error: "index-shape-invalid" };
  }

  // Materialize mandates per track (version-1-only; sorted issuedAt asc,
  // matching the extension fetcher's canonical-log ordering).
  const mandatesByTrack: Record<string, Mandate[]> = {};
  for (const [track, paths] of Object.entries(index.tracks)) {
    const list: Mandate[] = [];
    for (const p of paths) {
      const r = await getJson(base, p, doFetch);
      if (!r.ok) {
        errors.push({ path: p, error: r.error });
        continue;
      }
      if (isMandateV1(r.value)) list.push(r.value);
      else errors.push({ path: p, error: "not a version-1 Mandate" });
    }
    list.sort((x, y) => Date.parse(x.issuedAt) - Date.parse(y.issuedAt));
    mandatesByTrack[track] = list;
  }

  const keys: KeyFile[] = [];
  for (const p of index.keys) {
    const r = await getJson(base, p, doFetch);
    if (r.ok && (r.value as { kind?: unknown }).kind === "KeyFile") {
      keys.push(r.value as KeyFile);
    } else if (!r.ok) {
      errors.push({ path: p, error: r.error });
    }
  }

  const releaseEndorsements: ReleaseEndorsement[] = [];
  const caEndorsements: CaEndorsement[] = [];
  for (const p of index.endorsements) {
    const r = await getJson(base, p, doFetch);
    if (!r.ok) {
      errors.push({ path: p, error: r.error });
      continue;
    }
    const kind = (r.value as { kind?: unknown }).kind;
    if (kind === "ReleaseEndorsement") releaseEndorsements.push(r.value as ReleaseEndorsement);
    else if (kind === "CaEndorsement") caEndorsements.push(r.value as CaEndorsement);
    else errors.push({ path: p, error: "unrecognized endorsement kind" });
  }

  // Per-track forward verification anchored at the baked pin.
  const tracks: Record<string, TrackVerdict> = {};
  for (const track of Object.keys(mandatesByTrack)) {
    const trackPin = pinForTrack(opts.pin, track);
    const list = mandatesByTrack[track] ?? [];
    let chain: VerifiedChain;
    try {
      chain = verifyMandateChainFromPin(trackPin, list);
    } catch {
      // Defensive: the verifier is total, but never let a surprise
      // escape the client either.
      chain = { pin: trackPin, root: null, validMandates: [], rejections: [], rootError: "pin-not-in-log" };
    }
    const auth = currentAuthority(chain, now);
    let rejectReason: TrackVerdict["rejectReason"] = null;
    if (!auth) {
      rejectReason = chain.root === null ? (chain.rootError ?? "pin-not-in-log") : "no-authority-at-now";
    }
    tracks[track] = {
      track,
      pin: trackPin,
      accepted: auth !== null,
      rejectReason,
      holder: auth ? auth.holder : null,
      chain,
    };
  }

  // ReleaseEndorsement chain over the release track's verified chain.
  let releaseResult: VerifiedEndorsements | null = null;
  if (releaseEndorsements.length > 0) {
    const releaseChain =
      tracks[releaseTrack]?.chain ??
      verifyMandateChainFromPin(pinForTrack(opts.pin, releaseTrack), mandatesByTrack[releaseTrack] ?? []);
    try {
      releaseResult = verifyChainOfEndorsements(releaseEndorsements, releaseChain);
    } catch {
      releaseResult = { endorsements: releaseEndorsements, validEndorsements: [], rejections: [] };
    }
  }

  // CaEndorsement leases judged at the caller's OWN `now` (D3).
  let caResult: VerifiedCaEndorsements | null = null;
  let caKeys: Pubkey[] = [];
  if (caEndorsements.length > 0) {
    const caChain =
      tracks[caTrack]?.chain ??
      verifyMandateChainFromPin(pinForTrack(opts.pin, caTrack), mandatesByTrack[caTrack] ?? []);
    const skewOpt = opts.clockSkewMs === undefined ? {} : { clockSkewMs: opts.clockSkewMs };
    try {
      caResult = verifyCaEndorsements(caEndorsements, caChain, now, skewOpt);
      caKeys = authorizedCaKeys(caEndorsements, caChain, now, skewOpt);
    } catch {
      caResult = { endorsements: caEndorsements, validEndorsements: [], rejections: [], currentCaPubkey: null };
      caKeys = [];
    }
  }

  return {
    tracks,
    releaseEndorsements: releaseResult,
    caEndorsements: caResult,
    authorizedCaKeys: caKeys,
    fetched: {
      mandatesByTrack,
      keys,
      releaseEndorsements,
      caEndorsements,
      errors,
    },
  };
}

/**
 * Convenience: the canonical pin of a mandate (re-exported helper a port
 * uses to derive the value it bakes). Identical to {@link mandatePinHash}.
 */
export function pinOf(m: Omit<Mandate, "signatures">): string {
  return mandatePinHash(m);
}
