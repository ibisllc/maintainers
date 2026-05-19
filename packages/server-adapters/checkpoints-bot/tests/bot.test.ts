/**
 * Hermetic tests for the checkpoints-bot I/O adapter (the PURE core,
 * `src/bot.ts`). Mirrors the Cloudflare Worker `policy.test.ts` style:
 * synthetic deps are built in-process and fed through
 * `runCheckpointBotOnSubmission()`; NO network / fs / git / process — the
 * `action.ts` wiring is NOT exercised here (no `maintainers-checkpoints`
 * repo, no real PR; it is typechecked only — see its file header).
 *
 * Fixtures/builders are the SAME deterministic Ed25519-seed + fixed-ISO
 * pattern the protocol `checkpointBot.test.ts` uses, so these tests prove
 * the adapter's decision→outcome MAPPING, not the verifier internals
 * (those are covered by the 22 protocol checkpointBot tests + conformance).
 *
 * The pure logic-bearing helpers of the un-runnable `action.ts`
 * (CSV parse, payload parse, §6 path) ARE unit-tested below; the I/O
 * wiring around them is stated as wiring-only / typechecked-not-executed.
 */

import { describe, expect, it } from "vitest";
import {
  generateKeypair,
  signMandate,
  signCheckpointRequest,
  mandatePinHash,
  DEFAULT_RATE_CAP_MAX,
  type CheckpointRequest,
  type Mandate,
} from "@ibisllc/maintainers";
import {
  runCheckpointBotOnSubmission,
  checkpointRowToCsvLine,
  type BotOutcome,
  type CheckpointBotDeps,
  type CheckpointPrPayload,
  type ExistingCheckpointRow,
  type FetchedProjectChain,
} from "../src/bot.js";
import {
  parseCheckpointCsv,
  parseBotPayloadFile,
  checkpointCsvPathFor,
} from "../src/action.js";

// --- Deterministic key material (same kp(seed) as the protocol tests) ----
function kp(seedByte: number): { privKey: string; pubKey: string } {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}
const alice = kp(3); // the project's current (ca-track) mandate holder
const backup = kp(2); // a successor — NOT the holder
const DAY = 86_400;
const NOW = new Date("2026-03-04T00:00:00Z");
const REPO = "https://github.com/ibisllc/checkpoint-fixture";
const PATH = ".maintainers/";

function authorityRoot(): Mandate {
  return signMandate(
    {
      kind: "Mandate",
      version: 1,
      mandateId: "00000000-0000-4000-8000-0000000000d1",
      track: "ca",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-06-01T00:00:00Z",
      successors: [backup.pubKey],
      approvalRule: { kind: "threshold", threshold: 1 },
      minSuccessors: 1,
      maxDurationSeconds: 365 * DAY,
      defaultDurationSeconds: 180 * DAY,
      signedBy: alice.pubKey,
    },
    [{ privKey: alice.privKey }],
  );
}

function successorMandate(): Mandate {
  return signMandate(
    {
      kind: "Mandate",
      version: 1,
      mandateId: "00000000-0000-4000-8000-0000000000d2",
      track: "ca",
      holder: alice.pubKey,
      issuedAt: "2026-02-01T00:00:00Z",
      expiresAt: "2026-07-01T00:00:00Z",
      successors: [backup.pubKey],
      approvalRule: { kind: "threshold", threshold: 1 },
      minSuccessors: 1,
      maxDurationSeconds: 365 * DAY,
      defaultDurationSeconds: 180 * DAY,
      signedBy: backup.pubKey,
    },
    [{ privKey: backup.privKey }],
  );
}

function sha(m: Mandate): string {
  return `sha256:${mandatePinHash(m)}`;
}

function mkRequest(
  signerPriv: string,
  over: Partial<Omit<CheckpointRequest, "signatures">> = {},
): CheckpointRequest {
  return signCheckpointRequest(
    {
      kind: "CheckpointRequest",
      version: 1,
      canonicalRepo: REPO,
      maintainersPath: PATH,
      currentMandateHash: over.currentMandateHash ?? sha(authorityRoot()),
      sourceCommit: "0123456789abcdef0123456789abcdef01234567",
      ...over,
    },
    [{ privKey: signerPriv }],
  );
}

/** Build injected deps from a payload + fetched chain + existing rows. */
function deps(o: {
  payload: CheckpointPrPayload;
  fetched: FetchedProjectChain;
  existingRows?: ExistingCheckpointRow[];
  now?: Date;
  rateCap?: { maxPerWindow?: number; windowDays?: number };
  appendCsvLine?: CheckpointBotDeps["appendCsvLine"];
  postPrDecision?: CheckpointBotDeps["postPrDecision"];
}): CheckpointBotDeps {
  return {
    parsePayload: () => o.payload,
    fetchProjectChain: () => o.fetched,
    readExistingRows: () => o.existingRows ?? [],
    now: o.now ?? NOW,
    ...(o.rateCap ? { rateCap: o.rateCap } : {}),
    ...(o.appendCsvLine ? { appendCsvLine: o.appendCsvLine } : {}),
    ...(o.postPrDecision ? { postPrDecision: o.postPrDecision } : {}),
  };
}

/** A fetched-chain stub where rules 1/2/9 all pass. */
function okFetched(chainMandates: Mandate[], pinFrom: Mandate): FetchedProjectChain {
  return {
    chainMaterial: { pin: mandatePinHash(pinFrom), mandates: chainMandates },
    repoReachable: true,
    maintainersPathExists: true,
    pathMatchesCanonicalRepo: true,
  };
}

function happyPayload(over: Partial<CheckpointPrPayload> = {}): CheckpointPrPayload {
  const r = authorityRoot();
  return {
    canonicalRepo: REPO,
    maintainersPath: PATH,
    currentMandateHash: sha(r),
    sourceCommit: "0123456789abcdef0123456789abcdef01234567",
    track: "ca",
    request: mkRequest(alice.privKey, { currentMandateHash: sha(r) }),
    ...over,
  };
}

describe("runCheckpointBotOnSubmission — §12 first checkpoint (happy)", () => {
  it("accepts a first holder-signed checkpoint: ONE CSV line, flagged:'' , no ping, no reject PR", async () => {
    const r = authorityRoot();
    const out = await runCheckpointBotOnSubmission(
      deps({ payload: happyPayload(), fetched: okFetched([r], r) }),
    );
    expect(out.kind).toBe("accept");
    if (out.kind !== "accept") return;
    expect(out.row.observed_at).toBe("2026-03-04T00:00:00Z"); // rule 8: bot clock
    expect(out.row.track).toBe("ca");
    expect(out.row.flagged).toBe("");
    expect(out.ping).toBeUndefined();
    expect(out.csvLine).toBe(`2026-03-04T00:00:00Z,ca,${sha(r)},`);
  });
});

describe("runCheckpointBotOnSubmission — §11 continuation (happy)", () => {
  it("accepts a continuation whose verified chain still contains H_old", async () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    const prior: ExistingCheckpointRow = {
      observed_at: "2026-02-10T00:00:00Z",
      track: "ca",
      current_mandate_hash: sha(r),
      flagged: "",
    };
    const out = await runCheckpointBotOnSubmission(
      deps({
        payload: happyPayload({
          currentMandateHash: sha(k1),
          request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
        }),
        fetched: okFetched([r, k1], r),
        existingRows: [prior],
      }),
    );
    expect(out.kind).toBe("accept");
    if (out.kind === "accept") expect(out.row.current_mandate_hash).toBe(sha(k1));
  });
});

describe("runCheckpointBotOnSubmission — each reject reason ⇒ PR-decision data, no CSV write", () => {
  // One assertion per spec rule: the reject maps to the verifier reason,
  // a stable PR label, and the append sink is NEVER called on reject.
  const cases: { name: string; mut: () => CheckpointBotDeps; reason: string }[] = [
    {
      name: "rule 1: repo unreachable ⇒ repo-unreachable",
      reason: "repo-unreachable",
      mut: () =>
        deps({
          payload: happyPayload(),
          fetched: { ...okFetched([authorityRoot()], authorityRoot()), repoReachable: false },
        }),
    },
    {
      name: "rule 2: .maintainers/ missing ⇒ maintainers-path-missing",
      reason: "maintainers-path-missing",
      mut: () =>
        deps({
          payload: happyPayload(),
          fetched: { ...okFetched([authorityRoot()], authorityRoot()), maintainersPathExists: false },
        }),
    },
    {
      name: "rule 9: path↔repo mismatch ⇒ path-mismatch",
      reason: "path-mismatch",
      mut: () =>
        deps({
          payload: happyPayload(),
          fetched: { ...okFetched([authorityRoot()], authorityRoot()), pathMatchesCanonicalRepo: false },
        }),
    },
    {
      name: "§9: empty track ⇒ payload-malformed",
      reason: "payload-malformed",
      mut: () =>
        deps({
          payload: happyPayload({ track: "" }),
          fetched: okFetched([authorityRoot()], authorityRoot()),
        }),
    },
    {
      name: "§7.1: H_new not sha256:<hex> ⇒ hash-format-invalid",
      reason: "hash-format-invalid",
      mut: () =>
        deps({
          payload: happyPayload({ currentMandateHash: "notahash" }),
          fetched: okFetched([authorityRoot()], authorityRoot()),
        }),
    },
    {
      name: "§9: signed request does not bind the declared repo ⇒ request-repo-mismatch",
      reason: "request-repo-mismatch",
      mut: () =>
        deps({
          payload: happyPayload({
            request: mkRequest(alice.privKey, {
              canonicalRepo: "https://github.com/ibisllc/OTHER",
            }),
          }),
          fetched: okFetched([authorityRoot()], authorityRoot()),
        }),
    },
    {
      name: "rule 3: well-formed hash absent from the verified chain ⇒ hash-not-in-history",
      reason: "hash-not-in-history",
      mut: () => {
        const r = authorityRoot();
        const other = successorMandate();
        return deps({
          payload: happyPayload({
            currentMandateHash: sha(other),
            request: mkRequest(alice.privKey, { currentMandateHash: sha(other) }),
          }),
          fetched: okFetched([r], r),
        });
      },
    },
    {
      name: "rule 4: absent/forked pin ⇒ chain-invalid (fail-closed)",
      reason: "chain-invalid",
      mut: () => {
        const r = authorityRoot();
        return deps({
          payload: happyPayload(),
          fetched: { ...okFetched([r], r), chainMaterial: { pin: "", mandates: [r] } },
        });
      },
    },
    {
      name: "rule 5/§13: successor-but-not-holder signature ⇒ authority-invalid",
      reason: "authority-invalid",
      mut: () => {
        const r = authorityRoot();
        return deps({
          payload: happyPayload({
            request: mkRequest(backup.privKey, { currentMandateHash: sha(r) }),
          }),
          fetched: okFetched([r], r),
        });
      },
    },
  ];

  for (const c of cases) {
    it(`${c.name} — reject, labelled, no append`, async () => {
      let appended = 0;
      const d = c.mut();
      d.appendCsvLine = () => {
        appended++;
      };
      const out = await runCheckpointBotOnSubmission(d);
      expect(out.kind).toBe("reject");
      if (out.kind !== "reject") return;
      expect(out.pr.reason).toBe(c.reason);
      expect(out.pr.state).toBe("rejected");
      expect(out.pr.label).toBe(`checkpoint:rejected:` + out.pr.label.split(":")[2]);
      expect(out.pr.label.startsWith("checkpoint:rejected:")).toBe(true);
      expect(appended).toBe(0); // rule 7: no CSV mutation on reject
    });
  }
});

describe("runCheckpointBotOnSubmission — rule 10 (no-op) ⇒ reject", () => {
  it("H_new equals the most-recent witnessed hash for the track ⇒ no-op", async () => {
    const r = authorityRoot();
    const prior: ExistingCheckpointRow = {
      observed_at: "2026-02-25T00:00:00Z",
      track: "ca",
      current_mandate_hash: sha(r),
      flagged: "",
    };
    const out = await runCheckpointBotOnSubmission(
      deps({ payload: happyPayload(), fetched: okFetched([r], r), existingRows: [prior] }),
    );
    expect(out.kind).toBe("reject");
    if (out.kind === "reject") expect(out.pr.reason).toBe("no-op");
  });
});

describe("runCheckpointBotOnSubmission — §11 continuity-broken ⇒ reject", () => {
  it("previously-witnessed H_old absent from the chain leading to H_new ⇒ continuity-broken", async () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    const prior: ExistingCheckpointRow = {
      observed_at: "2026-02-20T00:00:00Z",
      track: "ca",
      current_mandate_hash: sha(k1), // registry witnessed k1; now only [r] served
      flagged: "",
    };
    const out = await runCheckpointBotOnSubmission(
      deps({
        payload: happyPayload(),
        fetched: okFetched([r], r),
        existingRows: [prior],
      }),
    );
    expect(out.kind).toBe("reject");
    if (out.kind === "reject") expect(out.pr.reason).toBe("continuity-broken");
  });
});

describe("runCheckpointBotOnSubmission — prunable-witness (sparse CSV) ⇒ accept", () => {
  it("genesis pruned, only an older row present: continuity anchors to the gap-free chain — NOT a false continuity-broken", async () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    const onlyOld: ExistingCheckpointRow = {
      observed_at: "2026-02-05T00:00:00Z",
      track: "ca",
      current_mandate_hash: sha(r),
      flagged: "",
    };
    const out = await runCheckpointBotOnSubmission(
      deps({
        payload: happyPayload({
          currentMandateHash: sha(k1),
          request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
        }),
        fetched: okFetched([r, k1], r),
        existingRows: [onlyOld],
      }),
    );
    expect(out.kind).toBe("accept");
    if (out.kind === "accept") expect(out.row.current_mandate_hash).toBe(sha(k1));
  });
});

describe("runCheckpointBotOnSubmission — rule 11 (rate cap: FAIL-OPEN ping, never reject)", () => {
  it("over the rolling cap ⇒ accept + flagged:'rate-cap' line + manual-verification ping (NOT a reject)", async () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    const rows: ExistingCheckpointRow[] = [];
    for (let i = 0; i < DEFAULT_RATE_CAP_MAX; i++) {
      rows.push({
        observed_at: `2026-02-${String(10 + i).padStart(2, "0")}T00:00:00Z`,
        track: "ca",
        current_mandate_hash: sha(r),
        flagged: "",
      });
    }
    let appendedLine = "";
    const out = await runCheckpointBotOnSubmission(
      deps({
        payload: happyPayload({
          currentMandateHash: sha(k1),
          request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
        }),
        fetched: okFetched([r, k1], r),
        existingRows: rows,
        appendCsvLine: (_t, line) => {
          appendedLine = line;
        },
      }),
    );
    expect(out.kind).toBe("accept"); // the ONE deliberate fail-open
    if (out.kind !== "accept") return;
    expect(out.row.flagged).toBe("rate-cap");
    expect(appendedLine).toBe(`2026-03-04T00:00:00Z,ca,${sha(k1)},rate-cap`);
    expect(out.ping).toEqual({
      kind: "manual-verification",
      reason: "rate-cap",
      detail: expect.stringContaining("exceeded the published cap"),
      canonicalRepo: REPO,
      track: "ca",
    });
  });

  it("exactly at the cap ⇒ accept with NO flag and NO ping", async () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    const rows: ExistingCheckpointRow[] = [];
    for (let i = 0; i < DEFAULT_RATE_CAP_MAX - 1; i++) {
      rows.push({
        observed_at: `2026-02-${String(10 + i).padStart(2, "0")}T00:00:00Z`,
        track: "ca",
        current_mandate_hash: sha(r),
        flagged: "",
      });
    }
    const out = await runCheckpointBotOnSubmission(
      deps({
        payload: happyPayload({
          currentMandateHash: sha(k1),
          request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
        }),
        fetched: okFetched([r, k1], r),
        existingRows: rows,
      }),
    );
    expect(out.kind).toBe("accept");
    if (out.kind !== "accept") return;
    expect(out.row.flagged).toBe("");
    expect(out.ping).toBeUndefined();
  });
});

describe("runCheckpointBotOnSubmission — append-only (rule 7): EXACTLY one appended line, never a rewrite", () => {
  it("the accept effect is a single appended line; the existing rows are never passed to a writer", async () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    const priorRows: ExistingCheckpointRow[] = [
      { observed_at: "2026-01-10T00:00:00Z", track: "ca", current_mandate_hash: sha(r), flagged: "" },
      { observed_at: "2026-02-01T00:00:00Z", track: "ca", current_mandate_hash: sha(r), flagged: "" },
    ];
    const appends: { track: string; line: string }[] = [];
    const out = await runCheckpointBotOnSubmission(
      deps({
        payload: happyPayload({
          currentMandateHash: sha(k1),
          request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
        }),
        fetched: okFetched([r, k1], r),
        existingRows: priorRows,
        appendCsvLine: (track, line) => appends.push({ track, line }),
      }),
    );
    expect(out.kind).toBe("accept");
    // Exactly ONE append, exactly the new row, nothing about prior rows.
    expect(appends).toHaveLength(1);
    expect(appends[0]?.track).toBe("ca");
    expect(appends[0]?.line.split("\n")).toHaveLength(1);
    expect(appends[0]?.line).not.toContain("2026-01-10T00:00:00Z");
    expect(appends[0]?.line).not.toContain("2026-02-01T00:00:00Z");
    if (out.kind === "accept") expect(appends[0]?.line).toBe(out.csvLine);
  });

  it("rule 7: an existing row with a future observed_at (forged tail) ⇒ reject not-append-only, no append", async () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    const tampered: ExistingCheckpointRow = {
      observed_at: "2099-01-01T00:00:00Z",
      track: "ca",
      current_mandate_hash: sha(r),
      flagged: "",
    };
    let appended = 0;
    const out = await runCheckpointBotOnSubmission(
      deps({
        payload: happyPayload({
          currentMandateHash: sha(k1),
          request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
        }),
        fetched: okFetched([r, k1], r),
        existingRows: [tampered],
        appendCsvLine: () => {
          appended++;
        },
      }),
    );
    expect(out.kind).toBe("reject");
    if (out.kind === "reject") expect(out.pr.reason).toBe("not-append-only");
    expect(appended).toBe(0);
  });
});

describe("runCheckpointBotOnSubmission — postPrDecision sink fires on both branches", () => {
  it("accept ⇒ sink receives the accept outcome (with the row)", async () => {
    const r = authorityRoot();
    let seen: BotOutcome | null = null;
    await runCheckpointBotOnSubmission(
      deps({
        payload: happyPayload(),
        fetched: okFetched([r], r),
        postPrDecision: (o) => {
          seen = o;
        },
      }),
    );
    expect(seen).not.toBeNull();
    expect(seen!.kind).toBe("accept");
  });

  it("reject ⇒ sink receives the reject outcome (with the PR decision)", async () => {
    const r = authorityRoot();
    let seen: BotOutcome | null = null;
    await runCheckpointBotOnSubmission(
      deps({
        payload: happyPayload(),
        fetched: { ...okFetched([r], r), repoReachable: false },
        postPrDecision: (o) => {
          seen = o;
        },
      }),
    );
    expect(seen).not.toBeNull();
    expect(seen!.kind).toBe("reject");
    if (seen!.kind === "reject") expect(seen!.pr.reason).toBe("repo-unreachable");
  });
});

describe("checkpointRowToCsvLine — §7 4-column serialization", () => {
  it("emits exactly observed_at,track,current_mandate_hash,flagged with no quoting", () => {
    expect(
      checkpointRowToCsvLine({
        observed_at: "2026-03-04T00:00:00Z",
        track: "ca",
        current_mandate_hash: "sha256:" + "ab".repeat(32),
        flagged: "",
      }),
    ).toBe(`2026-03-04T00:00:00Z,ca,sha256:${"ab".repeat(32)},`);
    expect(
      checkpointRowToCsvLine({
        observed_at: "2026-03-04T00:00:00Z",
        track: "ca",
        current_mandate_hash: "sha256:" + "cd".repeat(32),
        flagged: "rate-cap",
      }),
    ).toBe(`2026-03-04T00:00:00Z,ca,sha256:${"cd".repeat(32)},rate-cap`);
  });
});

// ── action.ts: PURE helpers only. The I/O wiring around these is
// wiring-only and typechecked-not-executed (no maintainers-checkpoints
// repo / no real PR in this clone — see src/action.ts header). ──────────
describe("action.ts pure helpers (the only logic-bearing parts of the un-runnable wiring)", () => {
  it("parseCheckpointCsv: skips the §7 header + blanks, filters to the track, parses 4 cols", () => {
    const csv =
      "observed_at,track,current_mandate_hash,flagged\n" +
      "2026-02-10T00:00:00Z,ca,sha256:aaa,\n" +
      "2026-02-12T00:00:00Z,release,sha256:bbb,\n" +
      "\n" +
      "2026-02-14T00:00:00Z,ca,sha256:ccc,rate-cap\n";
    const rows = parseCheckpointCsv(csv, "ca");
    expect(rows).toEqual([
      { observed_at: "2026-02-10T00:00:00Z", track: "ca", current_mandate_hash: "sha256:aaa", flagged: "" },
      { observed_at: "2026-02-14T00:00:00Z", track: "ca", current_mandate_hash: "sha256:ccc", flagged: "rate-cap" },
    ]);
  });

  it("parseCheckpointCsv: an empty/header-only file yields no rows (§12 first checkpoint)", () => {
    expect(parseCheckpointCsv("observed_at,track,current_mandate_hash,flagged\n", "ca")).toEqual([]);
    expect(parseCheckpointCsv("", "ca")).toEqual([]);
  });

  it("parseBotPayloadFile: round-trips the §9 botPayload JSON the CLI emits", () => {
    const p = happyPayload();
    expect(parseBotPayloadFile(JSON.stringify(p))).toEqual(p);
  });

  it("checkpointCsvPathFor: §6 path derivation strips scheme/.git/trailing slash", () => {
    expect(checkpointCsvPathFor("https://github.com/ibisllc/flagship")).toBe(
      "checkpoints/github.com/ibisllc/flagship.csv",
    );
    expect(checkpointCsvPathFor("https://github.com/ibisllc/flagship.git/")).toBe(
      "checkpoints/github.com/ibisllc/flagship.csv",
    );
  });
});
