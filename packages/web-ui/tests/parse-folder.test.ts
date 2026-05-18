/**
 * parse-folder tests — LOCKED Phase-2 v2 model.
 *
 * v2 has NO policy.json (root or track): a track is just
 * `tracks/<track>/mandates/*.json`, each a version-2 Mandate. We
 * verify the parser only accepts version-2 mandates, surfaces
 * malformed/v1 files without throwing, sorts by issuedAt, and resolves
 * the roster.
 */

import { describe, expect, it } from "vitest";
import { lookupHolder, parseMaintainersFolder } from "../src/parse-folder.js";
import { pathForKeyFile, pathForMandate, serializeEnvelope } from "../src/envelopes.js";
import { kp, mkKeyFile, mkV2 } from "./v2-fixtures.js";

function makeRawFolder(): Map<string, Uint8Array> {
  const alice = kp(1);
  const mandate = mkV2({
    id: "abc-123-0000-0000-0000-000000000001",
    holder: alice.pubKey,
    issuedAt: "2026-05-11T00:00:00Z",
    expiresAt: "2026-07-10T00:00:00Z",
    successors: [alice.pubKey],
    project: { name: "demo", tracks: ["release"] },
    signedBy: alice.pubKey,
    signWith: [alice.privKey],
  });
  const keyfile = mkKeyFile({
    pub: alice.pubKey,
    priv: alice.privKey,
    displayName: "Alice",
    email: "alice@example.com",
  });
  const files = new Map<string, Uint8Array>();
  files.set(pathForMandate("release", mandate.issuedAt, "genesis"), serializeEnvelope(mandate));
  files.set(pathForKeyFile("alice@example.com"), serializeEnvelope(keyfile));
  return files;
}

describe("parseMaintainersFolder (v2)", () => {
  it("parses a well-formed v2 folder (no policy.json)", () => {
    const folder = parseMaintainersFolder({ files: makeRawFolder() });
    expect(folder.tracks).toHaveLength(1);
    const t = folder.tracks[0]!;
    expect(t.name).toBe("release");
    expect(t.mandates).toHaveLength(1);
    expect(t.mandates[0]!.version).toBe(2);
    expect(t.mandates[0]!.project?.name).toBe("demo");
    expect(folder.keys).toHaveLength(1);
    expect(folder.keys[0]!.keyfile?.displayName).toBe("Alice");
  });

  it("surfaces malformed mandate files but keeps going", () => {
    const files = makeRawFolder();
    files.set("tracks/release/mandates/garbage.json", new TextEncoder().encode("{not json"));
    const folder = parseMaintainersFolder({ files });
    expect(folder.tracks[0]!.malformedMandates).toHaveLength(1);
    expect(folder.tracks[0]!.mandates).toHaveLength(1);
  });

  it("rejects a v1 Mandate as malformed (v2 is THE Mandate version)", () => {
    const files = makeRawFolder();
    files.set(
      "tracks/release/mandates/v1.json",
      new TextEncoder().encode(JSON.stringify({ kind: "Mandate", version: 1, mandateId: "old" })),
    );
    const folder = parseMaintainersFolder({ files });
    const mm = folder.tracks[0]!.malformedMandates;
    expect(mm).toHaveLength(1);
    expect(mm[0]!.reason).toBe("not a version-2 Mandate");
    expect(folder.tracks[0]!.mandates).toHaveLength(1);
  });

  it("sorts mandates by issuedAt", () => {
    const alice = kp(1);
    const m1 = mkV2({
      id: "m1-0000-0000-0000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-02-01T00:00:00Z",
      expiresAt: "2026-04-01T00:00:00Z",
      successors: [alice.pubKey],
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const m2 = mkV2({
      id: "m2-0000-0000-0000-000000000002",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-03-01T00:00:00Z",
      successors: [alice.pubKey],
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const files = new Map<string, Uint8Array>();
    // Insert in reverse order to test the sort.
    files.set("tracks/release/mandates/zz.json", serializeEnvelope(m1));
    files.set("tracks/release/mandates/aa.json", serializeEnvelope(m2));
    const folder = parseMaintainersFolder({ files });
    expect(folder.tracks[0]!.mandates.map((m) => m.mandateId)).toEqual([
      "m2-0000-0000-0000-000000000002",
      "m1-0000-0000-0000-000000000001",
    ]);
  });

  it("lookupHolder returns null for an unknown pubkey", () => {
    const folder = parseMaintainersFolder({ files: makeRawFolder() });
    expect(lookupHolder(folder, "0".repeat(64))).toBeNull();
  });

  it("lookupHolder returns name+email for a known pubkey", () => {
    const folder = parseMaintainersFolder({ files: makeRawFolder() });
    const known = folder.keys[0]!.keyfile!;
    const h = lookupHolder(folder, known.pubkey);
    expect(h?.displayName).toBe("Alice");
    expect(h?.email).toBe("alice@example.com");
  });

  it("collects unknown files instead of throwing", () => {
    const files = makeRawFolder();
    files.set("weird-thing.txt", new TextEncoder().encode("hi"));
    const folder = parseMaintainersFolder({ files });
    expect(folder.unknownFiles).toContain("weird-thing.txt");
  });
});
