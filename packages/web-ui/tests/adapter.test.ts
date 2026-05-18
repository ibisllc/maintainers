/**
 * Adapter contract tests — LOCKED Phase-2 v2 model.
 *
 * We stub `fetch` so the static adapter behaves deterministically and
 * verify the read/write flows. The GitHub OAuth path is exercised by
 * counting the PUT calls and inspecting their bodies. The ZIP fallback
 * is checked by snapshotting the magic bytes of the returned Blob.
 *
 * v2: there is NO policy.json — folders are version-2 mandates under
 * `tracks/<track>/mandates/*.json` + keyfiles under `keys/`.
 *
 * No real network. No real WebAuthn. No DOM.
 */

import { describe, expect, it } from "vitest";
import {
  serverAdapter,
  staticAdapter,
  type AdapterClient,
  type UiEnvelope,
} from "../src/adapter.js";
import { pathForKeyFile, pathForMandate, serializeEnvelope } from "../src/envelopes.js";
import { kp, mkKeyFile, mkV2 } from "./v2-fixtures.js";

function rootBundle(): { path: string; envelope: UiEnvelope; bytes: Uint8Array }[] {
  const alice = kp(1);
  const mandate = mkV2({
    id: "root-0000-0000-0000-000000000001",
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
  return [
    {
      path: pathForMandate("release", mandate.issuedAt, "genesis"),
      envelope: mandate,
      bytes: serializeEnvelope(mandate),
    },
    {
      path: pathForKeyFile("alice@example.com"),
      envelope: keyfile,
      bytes: serializeEnvelope(keyfile),
    },
  ];
}

describe("staticAdapter loadProject (v2)", () => {
  it("fetches raw mandate URLs from the github provider", async () => {
    const alice = kp(1);
    const mandate = mkV2({
      id: "g-0000-0000-0000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-05-11T00:00:00Z",
      expiresAt: "2026-07-10T00:00:00Z",
      successors: [alice.pubKey],
      project: { name: "demo", tracks: ["release"] },
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const rel = pathForMandate("release", mandate.issuedAt, "genesis");
    const seen: string[] = [];
    const fakeFetch = (async (url: string | Request | URL): Promise<Response> => {
      const u = url.toString();
      seen.push(u);
      if (u.endsWith(`/.maintainers/${rel}`)) {
        return new Response(new TextDecoder().decode(serializeEnvelope(mandate)), { status: 200 });
      }
      return new Response("", { status: 404 });
    }) as unknown as typeof fetch;
    const adapter = staticAdapter({ fetchImpl: fakeFetch, knownPaths: [rel] });
    const result = await adapter.loadProject("github.com/foo/bar");
    expect(result.ref.canonical).toBe("github.com/foo/bar");
    expect(result.folder.tracks[0]!.mandates[0]!.project?.name).toBe("demo");
    expect(
      seen.some((u) => u.includes(`raw.githubusercontent.com/foo/bar/main/.maintainers/${rel}`)),
    ).toBe(true);
  });

  it("uses knownPaths if provided to avoid the tree API", async () => {
    let called = 0;
    const fakeFetch = (async (url: string | Request | URL): Promise<Response> => {
      called++;
      const u = url.toString();
      if (u.includes("api.github.com")) {
        throw new Error("tree API should not have been called");
      }
      return new Response("", { status: 404 });
    }) as unknown as typeof fetch;
    const adapter = staticAdapter({ fetchImpl: fakeFetch, knownPaths: ["README.md"] });
    await adapter.loadProject("github.com/a/b");
    expect(called).toBeGreaterThan(0);
  });

  it("reports exists=false when the folder is empty", async () => {
    const fakeFetch = (async () => new Response("", { status: 404 })) as unknown as typeof fetch;
    const adapter = staticAdapter({ fetchImpl: fakeFetch, knownPaths: ["README.md"] });
    const result = await adapter.loadProject("github.com/empty/repo");
    expect(result.exists).toBe(false);
  });
});

describe("staticAdapter submit (ZIP fallback)", () => {
  it("returns a Blob with the ZIP signature when no OAuth token is set", async () => {
    const fakeFetch = (async () => new Response("", { status: 404 })) as unknown as typeof fetch;
    const adapter = staticAdapter({ fetchImpl: fakeFetch });
    const result = await adapter.submitBundle({
      repoUrl: "github.com/foo/bar",
      entries: rootBundle(),
    });
    expect(result.kind).toBe("downloadable");
    if (result.kind !== "downloadable") return;
    const ab = await result.blob.arrayBuffer();
    const bytes = new Uint8Array(ab);
    // ZIP local file header signature: 50 4b 03 04
    expect(bytes[0]).toBe(0x50);
    expect(bytes[1]).toBe(0x4b);
    expect(bytes[2]).toBe(0x03);
    expect(bytes[3]).toBe(0x04);
    expect(result.filename).toMatch(/foo-bar/);
  });
});

describe("staticAdapter submit (OAuth)", () => {
  it("PUTs each entry through the GitHub contents API", async () => {
    const calls: { url: string; method: string; body: string }[] = [];
    const fakeFetch = (async (url: string | Request | URL, init?: RequestInit): Promise<Response> => {
      const u = url.toString();
      calls.push({
        url: u,
        method: init?.method ?? "GET",
        body: typeof init?.body === "string" ? init.body : "",
      });
      return new Response(JSON.stringify({ content: { sha: "abc123" } }), { status: 200 });
    }) as unknown as typeof fetch;
    const adapter = staticAdapter({ fetchImpl: fakeFetch, oauthToken: "tok" });
    const entries = rootBundle();
    const result = await adapter.submitBundle({
      repoUrl: "github.com/foo/bar",
      entries,
    });
    expect(result.kind).toBe("committed");
    if (result.kind !== "committed") return;
    expect(result.sha).toBe("abc123");
    expect(calls).toHaveLength(entries.length);
    expect(calls.every((c) => c.method === "PUT")).toBe(true);
    expect(calls.every((c) => c.url.includes("api.github.com"))).toBe(true);
    expect(calls.every((c) => c.url.includes(".maintainers/"))).toBe(true);
  });

  it("submitEnvelope derives a v2 default commit message", async () => {
    const calls: { body: string }[] = [];
    const fakeFetch = (async (_url: string | Request | URL, init?: RequestInit): Promise<Response> => {
      calls.push({ body: typeof init?.body === "string" ? init.body : "" });
      return new Response(JSON.stringify({ content: { sha: "z" } }), { status: 200 });
    }) as unknown as typeof fetch;
    const adapter = staticAdapter({ fetchImpl: fakeFetch, oauthToken: "tok" });
    const [entry] = rootBundle();
    await adapter.submitEnvelope({
      repoUrl: "github.com/foo/bar",
      path: entry!.path,
      envelope: entry!.envelope,
      bytes: entry!.bytes,
    });
    expect(calls[0]!.body).toContain("maintainers: release mandate");
  });
});

describe("serverAdapter contract (v2)", () => {
  it("posts the bundle to /submitBundle", async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const fakeFetch = (async (url: string | Request | URL, init?: RequestInit): Promise<Response> => {
      const u = url.toString();
      calls.push({ url: u, init });
      if (u.endsWith("/submitBundle")) {
        return new Response(JSON.stringify({ kind: "committed", sha: "deadbeef" }), { status: 200 });
      }
      throw new Error("unexpected URL: " + u);
    }) as unknown as typeof fetch;
    const adapter: AdapterClient = serverAdapter({
      baseUrl: "https://example.test",
      fetchImpl: fakeFetch,
      bearer: "tok",
    });
    const result = await adapter.submitBundle({
      repoUrl: "github.com/foo/bar",
      entries: rootBundle(),
    });
    expect(result.kind).toBe("committed");
    if (result.kind === "committed") expect(result.sha).toBe("deadbeef");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.init?.method).toBe("POST");
    const headers = calls[0]!.init?.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer tok");
  });

  it("loadProject calls the right endpoint and decodes base64 v2 mandate files", async () => {
    const alice = kp(2);
    const mandate = mkV2({
      id: "srv-0000-0000-0000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-03-01T00:00:00Z",
      successors: [alice.pubKey],
      project: { name: "from-server", tracks: ["release"] },
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const fileBytes = serializeEnvelope(mandate);
    const b64 = btoa(String.fromCharCode(...fileBytes));
    const rel = pathForMandate("release", mandate.issuedAt, "genesis");
    const fakeFetch = (async (url: string | Request | URL): Promise<Response> => {
      const u = url.toString();
      if (u.includes("/loadProject")) {
        return new Response(
          JSON.stringify({
            ref: {
              provider: "github.com",
              owner: "foo",
              repo: "bar",
              ref: "main",
              canonical: "github.com/foo/bar",
            },
            files: { [rel]: b64 },
            exists: true,
          }),
          { status: 200 },
        );
      }
      throw new Error("unexpected URL: " + u);
    }) as unknown as typeof fetch;
    const adapter = serverAdapter({ baseUrl: "https://example.test", fetchImpl: fakeFetch });
    const result = await adapter.loadProject("github.com/foo/bar");
    expect(result.folder.tracks[0]!.mandates[0]!.project?.name).toBe("from-server");
    expect(result.exists).toBe(true);
  });
});
