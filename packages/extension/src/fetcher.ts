/**
 * Fetcher: pulls the `.maintainers/` tree from a raw-content URL with
 * a 30-second extension-storage cache. Layered on injectable
 * KV-storage and fetch interfaces for testability.
 *
 * **LOCKED Phase-2 v2 model.** There is NO `policy.json` (root or
 * per-track): the succession rule is folded INTO each mandate
 * (`approvalRule` / `successors` / `minSuccessors` /
 * `maxDurationSeconds`), and project metadata rides the inline
 * `project` field of a from-scratch (root) mandate. A track is just
 * `.maintainers/tracks/<track>/mandates/*.json`, each a version-2
 * Mandate; a v1 Mandate file is treated as malformed and ignored
 * (never parsed onto the v2 path).
 *
 * NOTE: Repo providers (github, codeberg, gitea, gitlab) do not expose
 * a uniform "list files in a directory" API on raw content. We
 * therefore rely on a small index file at `.maintainers/index.json`
 * that the adopting project commits with each change. Without it the
 * mandate log can't be enumerated by name (mandate filenames are
 * content-derived), so the overlay degrades to "no .maintainers/ data
 * available" rather than crashing.
 *
 * The index file format (versioned for forward-compat):
 *   {
 *     "version": 1,
 *     "tracks": { "<track>": ["<rel-path>", ...] },
 *     "keys":   ["<rel-path>", ...],
 *     "endorsements": ["<rel-path>", ...]
 *   }
 *
 * Paths are relative to the repo root and MUST start with
 * `.maintainers/`. We reject anything else to prevent a malicious index
 * from redirecting us off-tree.
 */
import type {
  KeyFile,
  MandateV2,
  ReleaseEndorsement,
} from "@maintainers/protocol";
import type { RepoLocation } from "./repo-detect.js";

export interface KVStore {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
}

export interface FetcherDeps {
  fetch: typeof fetch;
  storage: KVStore;
  now(): number;
}

export interface MaintainersData {
  /** v2 mandates per track, version-2-filtered, sorted by issuedAt ascending. */
  mandates: Record<string, MandateV2[]>;
  keys: KeyFile[];
  endorsements: ReleaseEndorsement[];
  /** Branch we successfully fetched index.json from. */
  branch: string | null;
  /** Errors encountered per path (for diagnostics). */
  errors: { path: string; error: string }[];
  /** ms since epoch when this snapshot was materialized. */
  fetchedAt: number;
}

export interface MaintainersIndexFile {
  version: 1;
  tracks: Record<string, string[]>;
  keys: string[];
  endorsements: string[];
}

const CACHE_TTL_MS = 30_000;

function cacheKey(repo: RepoLocation): string {
  return `maintainers:cache:${repo.host}/${repo.owner}/${repo.repo}`;
}

export async function fetchMaintainers(
  repo: RepoLocation,
  deps: FetcherDeps,
): Promise<MaintainersData> {
  const cached = await readCache(repo, deps);
  if (cached) return cached;

  const data = await fetchFresh(repo, deps);
  await writeCache(repo, data, deps);
  return data;
}

async function readCache(
  repo: RepoLocation,
  deps: FetcherDeps,
): Promise<MaintainersData | null> {
  const raw = await deps.storage.get(cacheKey(repo));
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as MaintainersData;
    if (deps.now() - parsed.fetchedAt > CACHE_TTL_MS) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function writeCache(
  repo: RepoLocation,
  data: MaintainersData,
  deps: FetcherDeps,
): Promise<void> {
  await deps.storage.set(cacheKey(repo), JSON.stringify(data));
}

/** Public for tests; treats no cache as a forced refresh. */
export async function fetchFresh(
  repo: RepoLocation,
  deps: FetcherDeps,
): Promise<MaintainersData> {
  const errors: MaintainersData["errors"] = [];

  // v2 has no policy.json. The index is the only enumerable anchor; the
  // first branch that has one wins.
  let index: MaintainersIndexFile | null = null;
  let usedBranch: string | null = null;
  for (const branch of repo.branches) {
    const result = await fetchJson<MaintainersIndexFile>(
      repo.rawUrl(".maintainers/index.json", branch),
      deps,
    );
    if (result.ok) {
      index = sanitizeIndex(result.value, errors);
      usedBranch = branch;
      break;
    }
  }
  if (!index || !usedBranch) {
    return {
      mandates: {},
      keys: [],
      endorsements: [],
      branch: null,
      errors: [
        {
          path: ".maintainers/index.json",
          error: "not found on any candidate branch",
        },
      ],
      fetchedAt: deps.now(),
    };
  }

  // Mandates per track. v2-only: a Mandate file MUST be a well-formed
  // version-2 Mandate; a v1 Mandate (or any other shape) is recorded as
  // an error and dropped — it never reaches the v2 verifier.
  const mandates: Record<string, MandateV2[]> = {};
  for (const [track, mandatePaths] of Object.entries(index.tracks)) {
    const trackMandates: MandateV2[] = [];
    for (const p of mandatePaths) {
      const r = await fetchJson<unknown>(repo.rawUrl(p, usedBranch), deps);
      if (!r.ok) {
        errors.push({ path: p, error: r.error });
        continue;
      }
      const v = r.value as { kind?: unknown; version?: unknown };
      if (v && typeof v === "object" && v.kind === "Mandate" && v.version === 2) {
        trackMandates.push(r.value as MandateV2);
      } else {
        errors.push({ path: p, error: "not a version-2 Mandate" });
      }
    }
    // Canonical log order: issuedAt ascending. issuedAt is in the
    // signed canonical bytes — an attacker can't backdate without
    // breaking signatures or the forward verifier's
    // `issued-before-predecessor` check.
    mandates[track] = trackMandates.sort(
      (a, b) => Date.parse(a.issuedAt) - Date.parse(b.issuedAt),
    );
  }

  // Keys + endorsements (still v1 envelopes — only the Mandate/policy
  // path moved to v2; KeyFile/ReleaseEndorsement are unchanged).
  const keys: KeyFile[] = [];
  for (const p of index.keys) {
    const r = await fetchJson<KeyFile>(repo.rawUrl(p, usedBranch), deps);
    if (r.ok && r.value.kind === "KeyFile") keys.push(r.value);
    else if (!r.ok) errors.push({ path: p, error: r.error });
  }

  const endorsements: ReleaseEndorsement[] = [];
  for (const p of index.endorsements) {
    const r = await fetchJson<ReleaseEndorsement>(repo.rawUrl(p, usedBranch), deps);
    if (r.ok) endorsements.push(r.value);
    else errors.push({ path: p, error: r.error });
  }

  return {
    mandates,
    keys,
    endorsements,
    branch: usedBranch,
    errors,
    fetchedAt: deps.now(),
  };
}

function sanitizeIndex(
  raw: MaintainersIndexFile,
  errors: MaintainersData["errors"],
): MaintainersIndexFile {
  const safe: MaintainersIndexFile = { version: 1, tracks: {}, keys: [], endorsements: [] };
  if (typeof raw !== "object" || raw === null) return safe;
  if (raw.version !== 1) return safe;

  const isSafePath = (p: unknown): p is string =>
    typeof p === "string" &&
    p.startsWith(".maintainers/") &&
    !p.includes("..") &&
    !p.includes("\\");

  if (raw.tracks && typeof raw.tracks === "object") {
    for (const [track, paths] of Object.entries(raw.tracks)) {
      if (!Array.isArray(paths)) continue;
      const safePaths: string[] = [];
      for (const p of paths) {
        if (isSafePath(p)) safePaths.push(p);
        else errors.push({ path: String(p), error: "rejected: unsafe path in index.json" });
      }
      safe.tracks[track] = safePaths;
    }
  }
  if (Array.isArray(raw.keys)) {
    for (const p of raw.keys) {
      if (isSafePath(p)) safe.keys.push(p);
      else errors.push({ path: String(p), error: "rejected: unsafe key path in index.json" });
    }
  }
  if (Array.isArray(raw.endorsements)) {
    for (const p of raw.endorsements) {
      if (isSafePath(p)) safe.endorsements.push(p);
      else errors.push({ path: String(p), error: "rejected: unsafe endorsement path in index.json" });
    }
  }
  return safe;
}

type FetchJsonResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

async function fetchJson<T>(url: string, deps: FetcherDeps): Promise<FetchJsonResult<T>> {
  try {
    const res = await deps.fetch(url, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "follow",
    });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const text = await res.text();
    if (text.length > 1_000_000) return { ok: false, error: "response too large" };
    return { ok: true, value: JSON.parse(text) as T };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
