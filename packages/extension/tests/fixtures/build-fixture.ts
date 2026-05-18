/**
 * Programmatically build a `.maintainers/` fixture tree (LOCKED
 * Phase-2 v2 model), returning a URL → text map that mock-fetch can
 * read from. We sign every envelope with deterministic keypairs so
 * tests are reproducible.
 *
 * v2: there is NO policy.json (root or per-track). The succession rule
 * is inline in each Mandate; project metadata rides the inline
 * `project` field of the from-scratch (root) mandate. A track is just
 * `.maintainers/tracks/<track>/mandates/*.json`, enumerated via
 * `.maintainers/index.json`. Mirrors the c4.5b web-ui `mk` helper.
 */
import {
  generateKeypair,
  intermediateMerkleRoot,
  mandatePinHash,
  signKeyFile,
  signMandate,
  signReleaseEndorsement,
  type KeyFile,
  type Mandate,
  type ReleaseEndorsement,
} from "@ibisllc/maintainers";

const DAY = 86_400_000;

export interface Fixture {
  rawBase: (path: string) => string;
  files: Map<string, string>;
  alice: { privKey: string; pubKey: string };
  bob: { privKey: string; pubKey: string };
  carol: { privKey: string; pubKey: string };
  /** First (root) release mandate's pin — the preview anchor. */
  releaseRootPin: string;
  mandates: { release: Mandate[]; ca: Mandate[] };
  keys: KeyFile[];
  endorsements: ReleaseEndorsement[];
}

export interface FixtureOptions {
  /**
   * Inject a takeover by Bob after Alice's release-track mandate
   * expires. If false, Alice rotates to herself (continuous).
   */
  takeover?: boolean;
  /**
   * Mark Bob's key as recently rotated (yellow alarm trigger).
   */
  recentEmailRotation?: boolean;
  /**
   * Make Alice's current release mandate expire within `expiresInDays`.
   */
  expiresInDays?: number;
  /** A reproducible "now" used to compute issuedAt fields. */
  now: Date;
}

function kp(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

export interface Mk {
  id: string;
  track?: string;
  holder: string;
  issuedAt: string;
  expiresAt: string;
  successors: string[];
  threshold?: number;
  minSuccessors?: number;
  maxDurationSeconds?: number;
  project?: { name: string; homepage?: string; tracks?: string[] };
  signedBy: string;
  signWith: string[];
}

export function mk(o: Mk): Mandate {
  const unsigned: Omit<Mandate, "signatures"> = {
    kind: "Mandate",
    version: 1,
    mandateId: o.id,
    track: o.track ?? "release",
    holder: o.holder,
    issuedAt: o.issuedAt,
    expiresAt: o.expiresAt,
    successors: o.successors,
    approvalRule: { kind: "threshold", threshold: o.threshold ?? 1 },
    minSuccessors: o.minSuccessors ?? 0,
    maxDurationSeconds: o.maxDurationSeconds ?? 1000 * 86_400,
    defaultDurationSeconds: 60 * 86_400,
    ...(o.project ? { project: o.project } : {}),
    signedBy: o.signedBy,
  };
  return signMandate(unsigned, o.signWith.map((privKey) => ({ privKey })));
}

export function buildFixture(opts: FixtureOptions): Fixture {
  const alice = kp(11);
  const bob = kp(22);
  const carol = kp(33);

  const now = opts.now;

  // KeyFiles
  const aliceKey = signKeyFile(
    {
      kind: "KeyFile",
      version: 1,
      pubkey: alice.pubKey,
      displayName: "Alice",
      currentEmail: "alice@example.com",
      emailHistory: [
        { email: "alice@example.com", from: new Date(now.getTime() - 90 * DAY).toISOString(), to: null },
      ],
      metadata: { photo: null, github: "alice", role: "release engineer" },
      introductionMandate: "00000000-0000-0000-0000-000000000000",
      signature: "" as any,
    },
    alice.privKey,
  );
  let bobKey = signKeyFile(
    {
      kind: "KeyFile",
      version: 1,
      pubkey: bob.pubKey,
      displayName: "Bob",
      currentEmail: "bob-new@example.com",
      emailHistory: [
        { email: "bob-old@example.com", from: new Date(now.getTime() - 365 * DAY).toISOString(), to: new Date(now.getTime() - 5 * DAY).toISOString() },
        { email: "bob-new@example.com", from: opts.recentEmailRotation ? new Date(now.getTime() - 2 * DAY).toISOString() : new Date(now.getTime() - 60 * DAY).toISOString(), to: null },
      ],
      metadata: { photo: null, github: "bob", role: "successor" },
      introductionMandate: "00000000-0000-0000-0000-000000000001",
      signature: "" as any,
    },
    bob.privKey,
  );
  if (!opts.recentEmailRotation) {
    // Make Bob's "new" email old enough that no banner fires
    bobKey = signKeyFile(
      {
        kind: "KeyFile",
        version: 1,
        pubkey: bob.pubKey,
        displayName: "Bob",
        currentEmail: "bob@example.com",
        emailHistory: [
          { email: "bob@example.com", from: new Date(now.getTime() - 365 * DAY).toISOString(), to: null },
        ],
        metadata: { photo: null, github: "bob", role: "successor" },
        introductionMandate: "00000000-0000-0000-0000-000000000001",
        signature: "" as any,
      },
      bob.privKey,
    );
  }
  const carolKey = signKeyFile(
    {
      kind: "KeyFile",
      version: 1,
      pubkey: carol.pubKey,
      displayName: "Carol",
      currentEmail: "carol@example.com",
      emailHistory: [
        { email: "carol@example.com", from: new Date(now.getTime() - 200 * DAY).toISOString(), to: null },
      ],
      metadata: { photo: null, github: "carol", role: "second successor" },
      introductionMandate: "00000000-0000-0000-0000-000000000002",
      signature: "" as any,
    },
    carol.privKey,
  );

  // Release mandates. The root (genesis) is self-signed by Alice and
  // carries the project metadata + the succession rule for K+1.
  const releaseMandates: Mandate[] = [];
  const genesisIssuedAt = new Date(now.getTime() - 90 * DAY).toISOString();
  const genesisExpiresAt = new Date(now.getTime() - 30 * DAY).toISOString();
  const releaseRoot = mk({
    id: "11111111-1111-1111-1111-111111111111",
    track: "release",
    holder: alice.pubKey,
    issuedAt: genesisIssuedAt,
    expiresAt: genesisExpiresAt,
    successors: [alice.pubKey, bob.pubKey, carol.pubKey],
    project: { name: "fixture-project", homepage: "https://example.com", tracks: ["release", "ca"] },
    signedBy: alice.pubKey,
    signWith: [alice.privKey],
  });
  releaseMandates.push(releaseRoot);

  const expiresInDays = opts.expiresInDays ?? 30;
  if (opts.takeover) {
    // Bob succeeds Alice (signedBy != prior holder ⇒ takeover alarm).
    releaseMandates.push(
      mk({
        id: "22222222-2222-2222-2222-222222222222",
        track: "release",
        holder: bob.pubKey,
        issuedAt: new Date(now.getTime() - 29 * DAY).toISOString(),
        expiresAt: new Date(now.getTime() + expiresInDays * DAY).toISOString(),
        successors: [bob.pubKey, carol.pubKey],
        signedBy: bob.pubKey,
        signWith: [bob.privKey],
      }),
    );
  } else {
    // Alice rotates to herself (continuous; no takeover).
    releaseMandates.push(
      mk({
        id: "22222222-2222-2222-2222-222222222222",
        track: "release",
        holder: alice.pubKey,
        issuedAt: new Date(now.getTime() - 31 * DAY).toISOString(),
        expiresAt: new Date(now.getTime() + expiresInDays * DAY).toISOString(),
        successors: [alice.pubKey, bob.pubKey, carol.pubKey],
        signedBy: alice.pubKey,
        signWith: [alice.privKey],
      }),
    );
  }

  // CA mandates — just Alice (active root, currently in-window).
  const caMandates: Mandate[] = [
    mk({
      id: "33333333-3333-3333-3333-333333333333",
      track: "ca",
      holder: alice.pubKey,
      issuedAt: new Date(now.getTime() - 60 * DAY).toISOString(),
      expiresAt: new Date(now.getTime() + 60 * DAY).toISOString(),
      successors: [alice.pubKey, bob.pubKey],
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    }),
  ];

  // A release endorsement signed by the current release-track holder
  // (v2 holder-signs).
  const intermediate = ["a".repeat(40), "b".repeat(40)];
  const root = intermediateMerkleRoot(intermediate);
  const currentReleaseHolderPriv = opts.takeover ? bob.privKey : alice.privKey;
  const currentReleaseHolderPub = opts.takeover ? bob.pubKey : alice.pubKey;
  const endorsement = signReleaseEndorsement(
    {
      kind: "ReleaseEndorsement",
      version: 1,
      releaseId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      semverTag: "v0.1.0",
      commitHash: "c".repeat(40),
      previousReleaseId: null,
      previousCommitHash: null,
      intermediateCommits: intermediate,
      intermediateMerkleRoot: root,
      endorsedNotes: "first release",
      issuedAt: new Date(now.getTime() - 1 * DAY).toISOString(),
      signedBy: currentReleaseHolderPub,
    },
    [{ privKey: currentReleaseHolderPriv }],
  );

  // Build the index file (v2: no policy.json anywhere).
  const releasePath0 = ".maintainers/tracks/release/mandates/0001-genesis.json";
  const releasePath1 = ".maintainers/tracks/release/mandates/0002-rotate.json";
  const caPath0 = ".maintainers/tracks/ca/mandates/0001-genesis.json";
  const aliceKeyPath = ".maintainers/keys/alice@example.com.json";
  const bobKeyPath = ".maintainers/keys/bob@example.com.json";
  const carolKeyPath = ".maintainers/keys/carol@example.com.json";
  const endorsementPath = ".maintainers/endorsements/v0.1.0.json";

  const index = {
    version: 1,
    tracks: {
      release: [releasePath0, releasePath1],
      ca: [caPath0],
    },
    keys: [aliceKeyPath, bobKeyPath, carolKeyPath],
    endorsements: [endorsementPath],
  };

  const RAW_BASE = "https://raw.example.test/owner/repo/main/";
  const files = new Map<string, string>();
  files.set(RAW_BASE + ".maintainers/index.json", JSON.stringify(index));
  files.set(RAW_BASE + releasePath0, JSON.stringify(releaseMandates[0]));
  files.set(RAW_BASE + releasePath1, JSON.stringify(releaseMandates[1]));
  files.set(RAW_BASE + caPath0, JSON.stringify(caMandates[0]));
  files.set(RAW_BASE + aliceKeyPath, JSON.stringify(aliceKey));
  files.set(RAW_BASE + bobKeyPath, JSON.stringify(bobKey));
  files.set(RAW_BASE + carolKeyPath, JSON.stringify(carolKey));
  files.set(RAW_BASE + endorsementPath, JSON.stringify(endorsement));

  return {
    rawBase: (path: string) => RAW_BASE + path.replace(/^\/+/, ""),
    files,
    alice,
    bob,
    carol,
    releaseRootPin: mandatePinHash(releaseRoot),
    mandates: { release: releaseMandates, ca: caMandates },
    keys: [aliceKey, bobKey, carolKey],
    endorsements: [endorsement],
  };
}

/** A vitest-friendly fake `fetch` that serves from a Map. */
export function makeFakeFetch(files: Map<string, string>): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const body = files.get(url);
    if (body === undefined) {
      return new Response("", { status: 404 });
    }
    return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
}

/** Tiny in-memory KV store implementing the extension's KVStore. */
export function makeMemKv(): { get(k: string): Promise<string | undefined>; set(k: string, v: string): Promise<void>; map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    async get(k) { return map.get(k); },
    async set(k, v) { map.set(k, v); },
  };
}
