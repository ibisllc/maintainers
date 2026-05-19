/**
 * Conformance test — the guard for #9 (webapp) and #10 (iOS/Android).
 *
 * This is the proven flagship "generator + test asserts the byte
 * output" pattern (scripts/bootstrap-flagship-maintainers.test.ts),
 * applied to the c5 conformance vectors:
 *
 *   1. Regenerate the vector set and WRITE it to the committed portable
 *      dir `maintainers/conformance/` (so the orchestrator commits a
 *      fresh, in-sync artifact — never a hand-edited one).
 *   2. Determinism: build the vectors TWICE; the serialized bytes MUST
 *      be byte-identical (fixed seeds / timestamps / UUIDs).
 *   3. For EVERY vector, replay `input` through the LANDED verifier
 *      exactly as `verifyFromFetch` does (same functions, same order)
 *      and assert it yields the vector's `expect` — `accepted` AND the
 *      exact `rejectReason`. The suite FAILS if any expected reject
 *      silently turns into an accept (the whole point).
 *   4. Sanity: all 10 mandatory fail-closed negatives + >=1 happy path
 *      are present, and the on-disk files match a fresh build.
 */
import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  buildConformanceVectors,
  writeConformanceVectors,
  CONFORMANCE_DIR,
  buildCheckpointRequestVectors,
  writeCheckpointRequestVectors,
  CHECKPOINT_CONFORMANCE_DIR,
  type ConformanceVector,
  type CheckpointRequestVector,
} from "../scripts/gen-conformance.js";
import {
  currentAuthority,
  verifyMandateChainFromPin,
} from "../src/verifier.js";
import { verifyChainOfEndorsements } from "../src/endorsement.js";
import { verifyCaEndorsements } from "../src/caEndorsement.js";
import { verifyCheckpointRequest } from "../src/checkpointRequest.js";

/**
 * Replay one vector through the LANDED verifier, returning the verdict
 * for the vector's `subject`. This mirrors `verifyFromFetch`'s
 * verification step (post-materialization): same functions, same order,
 * the consumer's own `now`. Totality: never throws.
 */
function replay(vec: ConformanceVector): {
  accepted: boolean;
  rejectReason: string | null;
} {
  const { pin, now, track, mandatesByTrack, endorsements, caEndorsements } =
    vec.input;
  const nowDate = new Date(now);
  const list = mandatesByTrack[track] ?? [];
  const chain = verifyMandateChainFromPin(pin, list);

  if (vec.expect.subject === "mandate-chain") {
    const auth = currentAuthority(chain, nowDate);
    if (auth) return { accepted: true, rejectReason: null };
    const reason =
      chain.root === null
        ? (chain.rootError ?? "pin-not-in-log")
        : (chain.rejections[0]?.reason ?? "no-authority-at-now");
    return { accepted: false, rejectReason: reason };
  }

  if (vec.expect.subject === "release-endorsement") {
    const r = verifyChainOfEndorsements(endorsements, chain);
    if (r.rejections.length === 0 && r.validEndorsements.length > 0) {
      return { accepted: true, rejectReason: null };
    }
    return {
      accepted: false,
      rejectReason: r.rejections[0]?.reason ?? "no-authority-at-issuance",
    };
  }

  // ca-endorsement
  const r = verifyCaEndorsements(caEndorsements, chain, nowDate);
  if (r.rejections.length === 0 && r.validEndorsements.length > 0) {
    return { accepted: true, rejectReason: null };
  }
  return {
    accepted: false,
    rejectReason: r.rejections[0]?.reason ?? "no-ca-authority-at-now",
  };
}

/**
 * Replay one checkpoint-request vector through the LANDED
 * `verifyCheckpointRequest` (holder-signs over a verify-forward-from-pin
 * chain). Totality: never throws.
 */
function replayCheckpoint(vec: CheckpointRequestVector): {
  accepted: boolean;
  rejectReason: string | null;
} {
  const { pin, now, track, mandatesByTrack, checkpointRequest } = vec.input;
  const nowDate = new Date(now);
  const list = mandatesByTrack[track] ?? [];
  const chain = verifyMandateChainFromPin(pin, list);
  const r = verifyCheckpointRequest(checkpointRequest, chain, nowDate);
  if (r.ok) return { accepted: true, rejectReason: null };
  return { accepted: false, rejectReason: r.reason };
}

describe("conformance vectors — schema + presence", () => {
  it("contains >=1 happy path and ALL 10 mandatory fail-closed negatives", () => {
    const vs = buildConformanceVectors();
    const names = new Set(vs.map((v) => v.name));

    expect(vs.some((v) => v.expect.accepted)).toBe(true);

    // The 10 mandatory negatives (the v1-launch-program c5 list).
    const mandatory = [
      "neg-1-absent-pin",
      "neg-2-forked-unknown-pin",
      "neg-3-pin-not-in-log-tampered-bytes",
      "neg-4-self-renewal-attempt",
      "neg-5-sub-threshold-signers",
      "neg-6-under-min-successors",
      "neg-7-over-max-duration",
      "neg-8-endorsement-gap",
      "neg-9-lapsed-lease-at-now",
      "neg-10a-rolled-back-dropped-intermediate",
    ];
    for (const m of mandatory) expect(names.has(m)).toBe(true);
    // The tampered-history half of negative #10 is also present.
    expect(names.has("neg-10b-tampered-root-signature")).toBe(true);

    // Every negative asserts a concrete reject reason (never just
    // "didn't crash").
    for (const v of vs) {
      if (!v.expect.accepted) {
        expect(typeof v.expect.rejectReason).toBe("string");
        expect((v.expect.rejectReason ?? "").length).toBeGreaterThan(0);
      } else {
        expect(v.expect.rejectReason).toBeNull();
      }
    }
  });
});

describe("conformance vectors — the landed verifier produces every expected verdict", () => {
  for (const vec of buildConformanceVectors()) {
    it(`${vec.name}: ${vec.description.slice(0, 80)}`, () => {
      let verdict: { accepted: boolean; rejectReason: string | null };
      // Totality: replay MUST NOT throw on any (incl. adversarial) vector.
      expect(() => {
        verdict = replay(vec);
      }).not.toThrow();
      verdict = replay(vec);
      expect(verdict.accepted).toBe(vec.expect.accepted);
      expect(verdict.rejectReason).toBe(vec.expect.rejectReason);
    });
  }
});

describe("conformance vectors — deterministic generation + committed artifact", () => {
  it("two independent builds serialize byte-identically", () => {
    const a = JSON.stringify(buildConformanceVectors());
    const b = JSON.stringify(buildConformanceVectors());
    expect(a).toBe(b);
  });

  it("regenerates the committed maintainers/conformance/ dir (byte-stable)", () => {
    // Write once, capture bytes; write again, compare. Mirrors the
    // flagship bootstrap idempotency contract.
    const first = writeConformanceVectors();
    const snap1 = snapshotDir(CONFORMANCE_DIR);
    const second = writeConformanceVectors();
    const snap2 = snapshotDir(CONFORMANCE_DIR);
    expect(second).toEqual(first);
    expect(snap2).toEqual(snap1);

    // The manifest + every vector file exists on disk and round-trips.
    const manifest = JSON.parse(
      fs.readFileSync(path.join(CONFORMANCE_DIR, "manifest.json"), "utf8"),
    ) as { count: number; vectors: { name: string; file: string }[] };
    const vs = buildConformanceVectors();
    expect(manifest.count).toBe(vs.length);
    for (const entry of manifest.vectors) {
      const onDisk = JSON.parse(
        fs.readFileSync(path.join(CONFORMANCE_DIR, entry.file), "utf8"),
      ) as ConformanceVector;
      expect(onDisk.name).toBe(entry.name);
      // The on-disk vector replays to its own stated verdict.
      const verdict = replay(onDisk);
      expect(verdict.accepted).toBe(onDisk.expect.accepted);
      expect(verdict.rejectReason).toBe(onDisk.expect.rejectReason);
    }
  });
});

describe("checkpoint-request conformance — additive set (Phase-H foundation)", () => {
  it("has >=1 happy path + the mandatory holder-signs fail-closed negatives", () => {
    const vs = buildCheckpointRequestVectors();
    const names = new Set(vs.map((v) => v.name));

    expect(vs.some((v) => v.expect.accepted)).toBe(true);

    const mandatory = [
      "cr-happy-holder-signed",
      "cr-neg-signed-by-not-the-holder",
      "cr-neg-tampered-canonical-bytes",
      "cr-neg-separator-in-field",
      "cr-neg-empty-required-field",
      "cr-neg-signature-invalid",
      "cr-neg-no-authority-at-now",
    ];
    for (const m of mandatory) expect(names.has(m)).toBe(true);

    for (const v of vs) {
      expect(v.expect.subject).toBe("checkpoint-request");
      if (!v.expect.accepted) {
        expect(typeof v.expect.rejectReason).toBe("string");
        expect((v.expect.rejectReason ?? "").length).toBeGreaterThan(0);
      } else {
        expect(v.expect.rejectReason).toBeNull();
      }
    }
  });

  for (const vec of buildCheckpointRequestVectors()) {
    it(`${vec.name}: ${vec.description.slice(0, 80)}`, () => {
      let verdict: { accepted: boolean; rejectReason: string | null };
      expect(() => {
        verdict = replayCheckpoint(vec);
      }).not.toThrow();
      verdict = replayCheckpoint(vec);
      expect(verdict.accepted).toBe(vec.expect.accepted);
      expect(verdict.rejectReason).toBe(vec.expect.rejectReason);
    });
  }

  it("two independent builds serialize byte-identically", () => {
    const a = JSON.stringify(buildCheckpointRequestVectors());
    const b = JSON.stringify(buildCheckpointRequestVectors());
    expect(a).toBe(b);
  });

  it("regenerates its OWN conformance/checkpoint-request/ dir (byte-stable); shared 17-set untouched", () => {
    const first = writeCheckpointRequestVectors();
    const snap1 = snapshotDir(CHECKPOINT_CONFORMANCE_DIR);
    const second = writeCheckpointRequestVectors();
    const snap2 = snapshotDir(CHECKPOINT_CONFORMANCE_DIR);
    expect(second).toEqual(first);
    expect(snap2).toEqual(snap1);

    // The additive dir is strictly nested under, but disjoint from, the
    // shared 17-vector dir's own files (manifest.json / vectors/*.json).
    expect(CHECKPOINT_CONFORMANCE_DIR.startsWith(CONFORMANCE_DIR)).toBe(true);
    expect(CHECKPOINT_CONFORMANCE_DIR).not.toBe(CONFORMANCE_DIR);

    const manifest = JSON.parse(
      fs.readFileSync(
        path.join(CHECKPOINT_CONFORMANCE_DIR, "manifest.json"),
        "utf8",
      ),
    ) as { count: number; vectors: { name: string; file: string }[] };
    const vs = buildCheckpointRequestVectors();
    expect(manifest.count).toBe(vs.length);
    for (const entry of manifest.vectors) {
      const onDisk = JSON.parse(
        fs.readFileSync(
          path.join(CHECKPOINT_CONFORMANCE_DIR, entry.file),
          "utf8",
        ),
      ) as CheckpointRequestVector;
      expect(onDisk.name).toBe(entry.name);
      const verdict = replayCheckpoint(onDisk);
      expect(verdict.accepted).toBe(onDisk.expect.accepted);
      expect(verdict.rejectReason).toBe(onDisk.expect.rejectReason);
    }
  });
});

function snapshotDir(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  function walk(dir: string): void {
    for (const e of fs
      .readdirSync(dir, { withFileTypes: true })
      .sort((x, y) => x.name.localeCompare(y.name))) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile()) out[path.relative(root, full)] = fs.readFileSync(full, "utf8");
    }
  }
  walk(root);
  return out;
}
