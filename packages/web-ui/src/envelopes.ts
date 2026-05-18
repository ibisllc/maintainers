/**
 * Serialization + path helpers tuned to the UI's needs.
 *
 * **#31 — web-ui is STATUS / PREVIEW ONLY; it is NEVER a signing
 * surface.** The mandate/policy *builders* that used to live here
 * (buildGenesis/Renewal/TakeoverMandate, makeGenesisPolicy/TrackPolicy,
 * PATH_ROOT_POLICY, pathForTrackPolicy, the KeyFile/IntroductionRequest
 * signers) all belonged to the deleted signing views. Under the LOCKED
 * Phase-2 v2 model there is no policy.json / RootPolicy / TrackPolicy at
 * all, and signing happens on the YubiKey-driven CLI, not the browser.
 *
 * What remains are pure, v1-symbol-free helpers the read-only path (and
 * its test fixtures) still need: deterministic on-disk paths under the
 * v2 convention and a JSON serializer.
 */

/**
 * Serialize an envelope as the JSON bytes that will be written to disk.
 * Pretty-printed (2-space indent) so a casual viewer on github.com sees
 * something legible; the verifier doesn't care about whitespace.
 */
export function serializeEnvelope(env: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(env, null, 2) + "\n");
}

export function serializeJson(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value, null, 2) + "\n");
}

/**
 * Path conventions per the v2 on-disk layout: mandates live at
 * `tracks/<track>/mandates/*.json` (there is NO policy.json in v2 — the
 * succession rule is folded into each mandate).
 */
export function pathForMandate(track: string, issuedAt: string, summary: string): string {
  const tsSlug = issuedAt.replace(/[:.]/g, "-").replace(/Z$/, "");
  const slug = summary.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-|-$/g, "");
  return `tracks/${track}/mandates/${tsSlug}-${slug}.json`;
}

export function pathForKeyFile(email: string): string {
  return `keys/${email}.json`;
}

/**
 * Generate a UUID v4 using the platform CSPRNG. Falls back to a
 * Math.random()-seeded variant only when crypto isn't available
 * (and warns via console; we never want that path in production).
 */
export function randomUuid(): string {
  if (typeof globalThis.crypto !== "undefined" && typeof globalThis.crypto.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  const b = new Uint8Array(16);
  if (typeof globalThis.crypto !== "undefined" && typeof globalThis.crypto.getRandomValues === "function") {
    globalThis.crypto.getRandomValues(b);
  } else {
    for (let i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
  }
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
