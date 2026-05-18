/**
 * Reference `fetch()` client tests — injected fake fetch + deterministic
 * fixtures. Pins the happy path AND the fail-closed paths the client
 * promises (no/empty pin, missing index, oversized index, path-escaping
 * index, pin-not-in-log) and totality (never throws on adversarial
 * input). The fixture mirrors the extension fetcher's `.maintainers/
 * index.json` convention verbatim — there is exactly ONE published
 * layout.
 */
import { describe, expect, it } from "vitest";
import { generateKeypair, intermediateMerkleRoot } from "../src/crypto.js";
import {
  signCaEndorsement,
  signKeyFile,
  signMandate,
  signReleaseEndorsement,
} from "../src/signing.js";
import { mandatePinHash } from "../src/canonical.js";
import { verifyFromFetch } from "../src/fetchClient.js";
import type { CaEndorsement, Mandate } from "../src/types.js";

function kp(seedByte: number): { privKey: string; pubKey: string } {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

const founder = kp(1);
const caHolder = kp(7);
const DAY = 86_400;
const BASE = "https://raw.example.test/owner/repo/main";

function mkMandate(o: {
  id: string;
  track: string;
  holder: string;
  issuedAt: string;
  expiresAt: string;
  successors: string[];
  signedBy: string;
  signWith: string[];
}): Mandate {
  return signMandate(
    {
      kind: "Mandate",
      version: 1,
      mandateId: o.id,
      track: o.track,
      holder: o.holder,
      issuedAt: o.issuedAt,
      expiresAt: o.expiresAt,
      successors: o.successors,
      approvalRule: { kind: "threshold", threshold: 1 },
      minSuccessors: 1,
      maxDurationSeconds: 365 * DAY,
      defaultDurationSeconds: 60 * DAY,
      signedBy: o.signedBy,
    },
    o.signWith.map((privKey) => ({ privKey })),
  );
}

function buildTree(): {
  files: Map<string, string>;
  releasePin: string;
  caPin: string;
} {
  const releaseRoot = mkMandate({
    id: "11111111-1111-4111-8111-111111111111",
    track: "release",
    holder: founder.pubKey,
    issuedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2027-01-01T00:00:00Z",
    successors: [founder.pubKey],
    signedBy: founder.pubKey,
    signWith: [founder.privKey],
  });
  const caRoot = mkMandate({
    id: "22222222-2222-4222-8222-222222222222",
    track: "ca",
    holder: caHolder.pubKey,
    issuedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2027-01-01T00:00:00Z",
    successors: [caHolder.pubKey],
    signedBy: caHolder.pubKey,
    signWith: [caHolder.privKey],
  });

  const founderKey = signKeyFile(
    {
      kind: "KeyFile",
      version: 1,
      pubkey: founder.pubKey,
      displayName: "Founder",
      currentEmail: "founder@example.com",
      emailHistory: [
        { email: "founder@example.com", from: "2025-01-01T00:00:00Z", to: null },
      ],
      metadata: { photo: null, github: null, role: "release" },
      introductionMandate: releaseRoot.mandateId,
      signature: "" as never,
    },
    founder.privKey,
  );

  const endorsement = signReleaseEndorsement(
    {
      kind: "ReleaseEndorsement",
      version: 1,
      releaseId: "rel-1",
      semverTag: "v1.0.0",
      commitHash: "ab".repeat(20),
      previousReleaseId: null,
      previousCommitHash: null,
      intermediateCommits: [],
      intermediateMerkleRoot: intermediateMerkleRoot([]),
      endorsedNotes: null,
      issuedAt: "2026-02-01T00:00:00Z",
      signedBy: founder.pubKey,
    },
    [{ privKey: founder.privKey }],
  );

  const ca: CaEndorsement = signCaEndorsement(
    {
      kind: "CaEndorsement",
      version: 1,
      endorsementId: "ca-1",
      track: "ca",
      caPubkey: "cd".repeat(32),
      scope: "example/scope",
      notBefore: "2026-03-01T00:00:00Z",
      notAfter: "2026-03-08T00:00:00Z",
      issuedAt: "2026-03-01T00:00:00Z",
      signedBy: caHolder.pubKey,
    },
    [{ privKey: caHolder.privKey }],
  );

  const relPath = ".maintainers/tracks/release/mandates/0001-genesis.json";
  const caPath = ".maintainers/tracks/ca/mandates/0001-genesis.json";
  const keyPath = ".maintainers/keys/founder@example.com.json";
  const endoPath = ".maintainers/endorsements/v1.0.0.json";
  const caEndoPath = ".maintainers/endorsements/ca-1.json";

  const index = {
    version: 1,
    tracks: { release: [relPath], ca: [caPath] },
    keys: [keyPath],
    endorsements: [endoPath, caEndoPath],
  };

  const files = new Map<string, string>();
  files.set(`${BASE}/.maintainers/index.json`, JSON.stringify(index));
  files.set(`${BASE}/${relPath}`, JSON.stringify(releaseRoot));
  files.set(`${BASE}/${caPath}`, JSON.stringify(caRoot));
  files.set(`${BASE}/${keyPath}`, JSON.stringify(founderKey));
  files.set(`${BASE}/${endoPath}`, JSON.stringify(endorsement));
  files.set(`${BASE}/${caEndoPath}`, JSON.stringify(ca));

  return {
    files,
    releasePin: mandatePinHash(releaseRoot),
    caPin: mandatePinHash(caRoot),
  };
}

function fakeFetch(files: Map<string, string>): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : (input as Request).url;
    const body = files.get(url);
    if (body === undefined) return new Response("", { status: 404 });
    return new Response(body, { status: 200 });
  }) as typeof fetch;
}

describe("verifyFromFetch — happy path", () => {
  it("accepts the release + ca tracks pinned at their roots; lease fresh at now", async () => {
    const { files, releasePin, caPin } = buildTree();
    const verdict = await verifyFromFetch(BASE, {
      pin: { release: releasePin, ca: caPin },
      now: new Date("2026-03-04T00:00:00Z"),
      fetch: fakeFetch(files),
    });
    expect(verdict.error).toBeUndefined();
    expect(verdict.tracks.release?.accepted).toBe(true);
    expect(verdict.tracks.release?.rejectReason).toBeNull();
    expect(verdict.tracks.release?.holder).toBe(founder.pubKey);
    expect(verdict.tracks.ca?.accepted).toBe(true);
    expect(verdict.releaseEndorsements?.validEndorsements).toHaveLength(1);
    expect(verdict.releaseEndorsements?.rejections).toHaveLength(0);
    expect(verdict.caEndorsements?.validEndorsements).toHaveLength(1);
    expect(verdict.authorizedCaKeys).toEqual(["cd".repeat(32)]);
  });
});

describe("verifyFromFetch — fail-closed", () => {
  it("no/empty pin ⇒ track rejected no-pin", async () => {
    const { files } = buildTree();
    const verdict = await verifyFromFetch(BASE, {
      pin: "",
      now: new Date("2026-03-04T00:00:00Z"),
      fetch: fakeFetch(files),
    });
    expect(verdict.tracks.release?.accepted).toBe(false);
    expect(verdict.tracks.release?.rejectReason).toBe("no-pin");
    // CA lease cannot be accepted without a ca authority either.
    expect(verdict.authorizedCaKeys).toEqual([]);
    expect(verdict.caEndorsements?.rejections[0]?.reason).toBe(
      "no-ca-authority-at-now",
    );
  });

  it("pin not in log ⇒ track rejected pin-not-in-log", async () => {
    const { files } = buildTree();
    const verdict = await verifyFromFetch(BASE, {
      pin: "de".repeat(32),
      now: new Date("2026-03-04T00:00:00Z"),
      fetch: fakeFetch(files),
    });
    expect(verdict.tracks.release?.rejectReason).toBe("pin-not-in-log");
  });

  it("missing index.json ⇒ total fail-closed (index-fetch-failed)", async () => {
    const verdict = await verifyFromFetch(BASE, {
      pin: "ab".repeat(32),
      fetch: fakeFetch(new Map()),
    });
    expect(verdict.error).toBe("index-fetch-failed");
    expect(verdict.tracks).toEqual({});
  });

  it("oversized index.json ⇒ index-too-large", async () => {
    const files = new Map<string, string>();
    files.set(
      `${BASE}/.maintainers/index.json`,
      JSON.stringify({ version: 1, pad: "x".repeat(1_000_001) }),
    );
    const verdict = await verifyFromFetch(BASE, {
      pin: "ab".repeat(32),
      fetch: fakeFetch(files),
    });
    expect(verdict.error).toBe("index-too-large");
  });

  it("path-escaping index entries are dropped (anti-redirect)", async () => {
    const { files } = buildTree();
    files.set(
      `${BASE}/.maintainers/index.json`,
      JSON.stringify({
        version: 1,
        tracks: { release: ["../../etc/passwd", ".maintainers/x.json"] },
        keys: ["/abs/evil"],
        endorsements: ["..\\win"],
      }),
    );
    const verdict = await verifyFromFetch(BASE, {
      pin: "ab".repeat(32),
      fetch: fakeFetch(files),
    });
    const errs = verdict.fetched.errors.map((e) => e.error);
    expect(errs).toContain("rejected: unsafe path in index.json");
    expect(errs).toContain("rejected: unsafe key path in index.json");
    expect(errs).toContain("rejected: unsafe endorsement path in index.json");
    // The one safe-but-missing path is attempted (and 404s), never the
    // escaping ones.
    expect(
      verdict.fetched.errors.some((e) => e.path === ".maintainers/x.json"),
    ).toBe(true);
  });

  it("index with wrong version ⇒ index-shape-invalid", async () => {
    const files = new Map<string, string>();
    files.set(
      `${BASE}/.maintainers/index.json`,
      JSON.stringify({ version: 2, tracks: {} }),
    );
    const verdict = await verifyFromFetch(BASE, {
      pin: "ab".repeat(32),
      fetch: fakeFetch(files),
    });
    expect(verdict.error).toBe("index-shape-invalid");
  });

  it("is total: an adversarial mandate body never throws, surfaces as rejected", async () => {
    const { files, releasePin } = buildTree();
    // Replace the release mandate with a structurally-valid but
    // signature-poisoned body (non-hex holder injected post-sign).
    const relPath = ".maintainers/tracks/release/mandates/0001-genesis.json";
    const good = JSON.parse(files.get(`${BASE}/${relPath}`)!) as Mandate;
    files.set(
      `${BASE}/${relPath}`,
      JSON.stringify({ ...good, holder: "zz" + "00".repeat(31) }),
    );
    let verdict!: Awaited<ReturnType<typeof verifyFromFetch>>;
    await expect(
      (async () => {
        verdict = await verifyFromFetch(BASE, {
          pin: releasePin,
          now: new Date("2026-06-01T00:00:00Z"),
          fetch: fakeFetch(files),
        });
      })(),
    ).resolves.toBeUndefined();
    // The poisoned mandate no longer hashes to the pin ⇒ pin-not-in-log.
    expect(verdict.tracks.release?.accepted).toBe(false);
    expect(verdict.tracks.release?.rejectReason).toBe("pin-not-in-log");
  });
});
