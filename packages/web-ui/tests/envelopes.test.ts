/**
 * Serialization + path-helper tests.
 *
 * **#31 — web-ui is STATUS / PREVIEW ONLY (LOCKED Phase-2 v2 model).**
 * The mandate/policy *builders* were deleted with the signing views;
 * there is no policy.json in v2. What remains here is pure, v1-free:
 * deterministic on-disk paths under the v2 convention + a JSON
 * serializer + a UUID generator. We verify shape, not crypto.
 */

import { describe, expect, it } from "vitest";
import {
  pathForKeyFile,
  pathForMandate,
  randomUuid,
  serializeEnvelope,
  serializeJson,
} from "../src/envelopes.js";

describe("envelopes (status/preview helpers)", () => {
  it("pathForMandate produces a deterministic, sortable v2 path", () => {
    const p = pathForMandate("release", "2026-05-11T12:34:56Z", "Genesis");
    expect(p).toBe("tracks/release/mandates/2026-05-11T12-34-56-genesis.json");
  });

  it("pathForMandate never emits a policy.json path", () => {
    const p = pathForMandate("ca", "2026-01-01T00:00:00Z", "root");
    expect(p).not.toContain("policy.json");
    expect(p.startsWith("tracks/ca/mandates/")).toBe(true);
  });

  it("pathForKeyFile uses email verbatim", () => {
    expect(pathForKeyFile("alice@example.com")).toBe("keys/alice@example.com.json");
  });

  it("serializeEnvelope round-trips through JSON.parse", () => {
    const bytes = serializeEnvelope({ kind: "Mandate", version: 1, mandateId: "m1" });
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    expect(parsed.kind).toBe("Mandate");
    expect(parsed.version).toBe(1);
    // pretty-printed + trailing newline
    expect(new TextDecoder().decode(bytes).endsWith("}\n")).toBe(true);
  });

  it("serializeJson pretty-prints with a trailing newline", () => {
    const bytes = serializeJson({ a: 1 });
    expect(new TextDecoder().decode(bytes)).toBe('{\n  "a": 1\n}\n');
  });

  it("randomUuid produces a v4-shaped UUID", () => {
    const u = randomUuid();
    expect(u).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(randomUuid()).not.toBe(u);
  });
});
