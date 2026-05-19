/**
 * Hermetic tests for the checkpoint-bot validation library (spec
 * docs/maintainers-checkpoints-spec-v0.1.md §10 rules 1–11, §11, §12).
 *
 * NO real I/O: every chain / CSV row / payload / clock / rule-1,2,9
 * boolean is fabricated and injected, mirroring the protocol verifier
 * test style (deterministic Ed25519 seeds + fixed ISO timestamps). The
 * library is asserted to reuse the LANDED verifiers
 * (verifyMandateChainFromPin / currentAuthority / verifyCheckpointRequest)
 * — these tests prove the bot's decision, not the verifiers' internals.
 */
import { describe, expect, it } from "vitest";
import { generateKeypair } from "../src/crypto.js";
import { signMandate, signCheckpointRequest } from "../src/signing.js";
import { mandatePinHash } from "../src/canonical.js";
import {
  validateCheckpointSubmission,
  DEFAULT_RATE_CAP_MAX,
  type CheckpointSubmissionInput,
  type ExistingCheckpointRow,
} from "../src/checkpointBot.js";
import type { CheckpointRequest, Mandate } from "../src/types.js";

// --- Deterministic key material (same kp(seed) pattern as gen-conformance).
function kp(seedByte: number): { privKey: string; pubKey: string } {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}
const alice = kp(3); // the project's current (ca-track) mandate holder
const backup = kp(2); // a successor — NOT the holder
const DAY = 86_400;
const NOW = new Date("2026-03-04T00:00:00Z");

/** A ca-track mandate live at NOW whose holder is `alice`. */
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

/** A second, distinct ca-track mandate (a real successor of `root`). */
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
    [{ privKey: backup.privKey }], // signed by root.successors (backup) ⇒ valid step
  );
}

const REPO = "https://github.com/ibisllc/checkpoint-fixture";
const PATH = ".maintainers/";

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

/** A well-formed input where every rule passes (the happy baseline). */
function happyInput(
  over: Partial<CheckpointSubmissionInput> = {},
): CheckpointSubmissionInput {
  const r = authorityRoot();
  return {
    payload: {
      canonicalRepo: REPO,
      maintainersPath: PATH,
      currentMandateHash: sha(r),
      sourceCommit: "0123456789abcdef0123456789abcdef01234567",
      track: "ca",
      request: mkRequest(alice.privKey, { currentMandateHash: sha(r) }),
    },
    chainMaterial: { pin: mandatePinHash(r), mandates: [r] },
    existingRows: [],
    now: NOW,
    repoReachable: true,
    maintainersPathExists: true,
    pathMatchesCanonicalRepo: true,
    ...over,
  };
}

describe("checkpointBot — §12 first checkpoint (happy)", () => {
  it("accepts a first holder-signed checkpoint with a bot-assigned observed_at and empty flag", () => {
    const d = validateCheckpointSubmission(happyInput());
    expect(d.accept).toBe(true);
    if (!d.accept) return;
    // rule 8: observed_at is the BOT clock, seconds-precision, not the submitter's.
    expect(d.row.observed_at).toBe("2026-03-04T00:00:00Z");
    expect(d.row.track).toBe("ca");
    expect(d.row.flagged).toBe("");
    expect(d.action).toBeUndefined();
  });
});

describe("checkpointBot — §11 continuation (happy)", () => {
  it("accepts a continuation whose verified chain still contains the previously-witnessed H_old", () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    const prior: ExistingCheckpointRow = {
      observed_at: "2026-02-10T00:00:00Z",
      track: "ca",
      current_mandate_hash: sha(r), // H_old = the root, still in the chain
      flagged: "",
    };
    const d = validateCheckpointSubmission(
      happyInput({
        payload: {
          canonicalRepo: REPO,
          maintainersPath: PATH,
          currentMandateHash: sha(k1),
          sourceCommit: "0123456789abcdef0123456789abcdef01234567",
          track: "ca",
          request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
        },
        chainMaterial: { pin: mandatePinHash(r), mandates: [r, k1] },
        existingRows: [prior],
      }),
    );
    expect(d.accept).toBe(true);
    if (d.accept) expect(d.row.current_mandate_hash).toBe(sha(k1));
  });
});

describe("checkpointBot — §10 rules 1/2/9 (injected I/O results)", () => {
  it("rule 1: repo unreachable ⇒ repo-unreachable", () => {
    const d = validateCheckpointSubmission(happyInput({ repoReachable: false }));
    expect(d).toEqual({ accept: false, reason: "repo-unreachable" });
  });
  it("rule 2: .maintainers/ path missing ⇒ maintainers-path-missing", () => {
    const d = validateCheckpointSubmission(
      happyInput({ maintainersPathExists: false }),
    );
    expect(d).toEqual({ accept: false, reason: "maintainers-path-missing" });
  });
  it("rule 9: file path does not match the canonical repo ⇒ path-mismatch", () => {
    const d = validateCheckpointSubmission(
      happyInput({ pathMatchesCanonicalRepo: false }),
    );
    expect(d).toEqual({ accept: false, reason: "path-mismatch" });
  });
});

describe("checkpointBot — §9 payload + hash format", () => {
  it("a non-string/empty track ⇒ payload-malformed", () => {
    const inp = happyInput();
    (inp.payload as { track: unknown }).track = "";
    const d = validateCheckpointSubmission(inp);
    expect(d).toEqual({ accept: false, reason: "payload-malformed" });
  });
  it("H_new not a sha256:<hex> string ⇒ hash-format-invalid", () => {
    const inp = happyInput();
    inp.payload.currentMandateHash = "notahash";
    const d = validateCheckpointSubmission(inp);
    expect(d).toEqual({ accept: false, reason: "hash-format-invalid" });
  });
  it("the signed request does not bind the PR's declared repo/path/hash ⇒ request-repo-mismatch", () => {
    const inp = happyInput();
    inp.payload.request = mkRequest(alice.privKey, {
      canonicalRepo: "https://github.com/ibisllc/OTHER",
    });
    const d = validateCheckpointSubmission(inp);
    expect(d.accept).toBe(false);
    if (!d.accept) expect(d.reason).toBe("request-repo-mismatch");
  });
});

describe("checkpointBot — rule 3 (hash in history)", () => {
  it("H_new is a well-formed hash but not present in the verified chain ⇒ hash-not-in-history", () => {
    const r = authorityRoot();
    const other = successorMandate(); // valid-looking but NOT in the served chain
    const inp = happyInput({
      payload: {
        canonicalRepo: REPO,
        maintainersPath: PATH,
        currentMandateHash: sha(other),
        sourceCommit: "0123456789abcdef0123456789abcdef01234567",
        track: "ca",
        request: mkRequest(alice.privKey, { currentMandateHash: sha(other) }),
      },
      chainMaterial: { pin: mandatePinHash(r), mandates: [r] },
    });
    const d = validateCheckpointSubmission(inp);
    expect(d).toEqual({ accept: false, reason: "hash-not-in-history" });
  });
});

describe("checkpointBot — rule 4 (chain validity)", () => {
  it("an absent/forked pin ⇒ chain never anchors ⇒ chain-invalid (fail-closed, no fallback)", () => {
    const inp = happyInput();
    inp.chainMaterial = { pin: "", mandates: inp.chainMaterial.mandates };
    const d = validateCheckpointSubmission(inp);
    expect(d.accept).toBe(false);
    if (!d.accept) {
      expect(d.reason).toBe("chain-invalid");
      expect(d.detail).toBe("no-pin");
    }
  });
});

describe("checkpointBot — rule 5 / §13 (HOLDER-SIGNS, not the quorum)", () => {
  it("a successor-but-not-holder signature ⇒ authority-invalid (reuses verifyCheckpointRequest)", () => {
    const r = authorityRoot();
    const inp = happyInput({
      payload: {
        canonicalRepo: REPO,
        maintainersPath: PATH,
        currentMandateHash: sha(r),
        sourceCommit: "0123456789abcdef0123456789abcdef01234567",
        track: "ca",
        // signed by `backup` (a successor in root.successors) — NOT the
        // current-mandate holder `alice`.
        request: mkRequest(backup.privKey, { currentMandateHash: sha(r) }),
      },
    });
    const d = validateCheckpointSubmission(inp);
    expect(d.accept).toBe(false);
    if (!d.accept) {
      expect(d.reason).toBe("authority-invalid");
      expect(d.detail).toContain("signer-not-the-holder");
    }
  });

  it("a forged (all-zero) signature ⇒ authority-invalid: signature-invalid", () => {
    const inp = happyInput();
    inp.payload.request = {
      ...inp.payload.request,
      signatures: [{ pubkey: alice.pubKey, sig: "00".repeat(64) }],
    };
    const d = validateCheckpointSubmission(inp);
    expect(d.accept).toBe(false);
    if (!d.accept) {
      expect(d.reason).toBe("authority-invalid");
      expect(d.detail).toContain("signature-invalid");
    }
  });

  it("totality: a '|' separator injected into a request field is CAUGHT, not thrown ⇒ authority-invalid", () => {
    const r = authorityRoot();
    const inp = happyInput();
    // Sign clean, then poison maintainersPath so canonicalization throws
    // on re-derivation inside verifyCheckpointRequest.
    const signed = mkRequest(alice.privKey, { currentMandateHash: sha(r) });
    inp.payload.maintainersPath = ".maintainers/|x";
    inp.payload.request = { ...signed, maintainersPath: ".maintainers/|x" };
    let d!: ReturnType<typeof validateCheckpointSubmission>;
    expect(() => {
      d = validateCheckpointSubmission(inp);
    }).not.toThrow();
    expect(d.accept).toBe(false);
    if (!d.accept) expect(d.reason).toBe("authority-invalid");
  });
});

describe("checkpointBot — §11 continuity (rollback / fork / rewrite)", () => {
  it("the previously-witnessed H_old is absent from the chain leading to H_new ⇒ continuity-broken", () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    // The registry previously witnessed `k1`, but the project now serves
    // a chain ([r] only) that no longer contains k1 ⇒ rollback.
    const prior: ExistingCheckpointRow = {
      observed_at: "2026-02-20T00:00:00Z",
      track: "ca",
      current_mandate_hash: sha(k1),
      flagged: "",
    };
    const inp = happyInput({
      payload: {
        canonicalRepo: REPO,
        maintainersPath: PATH,
        currentMandateHash: sha(r),
        sourceCommit: "0123456789abcdef0123456789abcdef01234567",
        track: "ca",
        request: mkRequest(alice.privKey, { currentMandateHash: sha(r) }),
      },
      chainMaterial: { pin: mandatePinHash(r), mandates: [r] },
      existingRows: [prior],
    });
    const d = validateCheckpointSubmission(inp);
    expect(d.accept).toBe(false);
    if (!d.accept) expect(d.reason).toBe("continuity-broken");
  });

  it("prunable-witness: a sparse CSV (genesis pruned, only an older row present) still validates continuity — NOT a false continuity-broken", () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    // The registry pruned everything except an OLD row (H_old = root).
    // Continuity must anchor to the project's own gap-free chain: root
    // IS in chain([r,k1]) ⇒ accept, not a false break.
    const onlyOld: ExistingCheckpointRow = {
      observed_at: "2026-02-05T00:00:00Z",
      track: "ca",
      current_mandate_hash: sha(r),
      flagged: "",
    };
    const inp = happyInput({
      payload: {
        canonicalRepo: REPO,
        maintainersPath: PATH,
        currentMandateHash: sha(k1),
        sourceCommit: "0123456789abcdef0123456789abcdef01234567",
        track: "ca",
        request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
      },
      chainMaterial: { pin: mandatePinHash(r), mandates: [r, k1] },
      existingRows: [onlyOld],
    });
    const d = validateCheckpointSubmission(inp);
    expect(d.accept).toBe(true);
    if (d.accept) expect(d.row.current_mandate_hash).toBe(sha(k1));
  });

  it("a flagged (rate-cap) row still counts as H_old while present (§11)", () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    const flaggedOld: ExistingCheckpointRow = {
      observed_at: "2026-02-12T00:00:00Z",
      track: "ca",
      current_mandate_hash: sha(r),
      flagged: "rate-cap",
    };
    const inp = happyInput({
      payload: {
        canonicalRepo: REPO,
        maintainersPath: PATH,
        currentMandateHash: sha(k1),
        sourceCommit: "0123456789abcdef0123456789abcdef01234567",
        track: "ca",
        request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
      },
      chainMaterial: { pin: mandatePinHash(r), mandates: [r, k1] },
      existingRows: [flaggedOld],
    });
    const d = validateCheckpointSubmission(inp);
    expect(d.accept).toBe(true);
  });
});

describe("checkpointBot — rule 10 (no-op)", () => {
  it("H_new equal to the most-recent witnessed hash for the same track ⇒ no-op reject", () => {
    const r = authorityRoot();
    const prior: ExistingCheckpointRow = {
      observed_at: "2026-02-25T00:00:00Z",
      track: "ca",
      current_mandate_hash: sha(r),
      flagged: "",
    };
    const inp = happyInput({ existingRows: [prior] }); // H_new defaults to sha(r) == H_old
    const d = validateCheckpointSubmission(inp);
    expect(d.accept).toBe(false);
    if (!d.accept) expect(d.reason).toBe("no-op");
  });

  it("per-(project,track): a same-hash row on a DIFFERENT track does not make this a no-op", () => {
    const r = authorityRoot();
    const otherTrackRow: ExistingCheckpointRow = {
      observed_at: "2026-02-25T00:00:00Z",
      track: "release", // different track ⇒ not this track's H_old
      current_mandate_hash: sha(r),
      flagged: "",
    };
    const d = validateCheckpointSubmission(
      happyInput({ existingRows: [otherTrackRow] }),
    );
    expect(d.accept).toBe(true); // first checkpoint for `ca`, not a no-op
  });
});

describe("checkpointBot — rule 7 (append-only)", () => {
  it("an existing row with a future observed_at (forged tail) ⇒ not-append-only", () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    const tampered: ExistingCheckpointRow = {
      observed_at: "2099-01-01T00:00:00Z", // after the bot clock ⇒ forged
      track: "ca",
      current_mandate_hash: sha(r),
      flagged: "",
    };
    const inp = happyInput({
      payload: {
        canonicalRepo: REPO,
        maintainersPath: PATH,
        currentMandateHash: sha(k1),
        sourceCommit: "0123456789abcdef0123456789abcdef01234567",
        track: "ca",
        request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
      },
      chainMaterial: { pin: mandatePinHash(r), mandates: [r, k1] },
      existingRows: [tampered],
    });
    const d = validateCheckpointSubmission(inp);
    expect(d.accept).toBe(false);
    if (!d.accept) expect(d.reason).toBe("not-append-only");
  });
});

describe("checkpointBot — rule 11 (rate cap: FAIL-OPEN, never reject)", () => {
  it("over the rolling cap ⇒ accept:true with flagged:'rate-cap' + a manual-verification action (NOT a reject)", () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    // DEFAULT_RATE_CAP_MAX prior rows in-window for this track; this
    // submission is the (cap+1)th ⇒ trips the cap.
    const rows: ExistingCheckpointRow[] = [];
    for (let i = 0; i < DEFAULT_RATE_CAP_MAX; i++) {
      rows.push({
        observed_at: `2026-02-${String(10 + i).padStart(2, "0")}T00:00:00Z`,
        track: "ca",
        current_mandate_hash: sha(r), // H_old = root, in chain([r,k1])
        flagged: "",
      });
    }
    const inp = happyInput({
      payload: {
        canonicalRepo: REPO,
        maintainersPath: PATH,
        currentMandateHash: sha(k1),
        sourceCommit: "0123456789abcdef0123456789abcdef01234567",
        track: "ca",
        request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
      },
      chainMaterial: { pin: mandatePinHash(r), mandates: [r, k1] },
      existingRows: rows,
    });
    const d = validateCheckpointSubmission(inp);
    expect(d.accept).toBe(true); // the ONE deliberate fail-open
    if (!d.accept) return;
    expect(d.row.flagged).toBe("rate-cap");
    expect(d.action).toEqual({
      kind: "manual-verification",
      reason: "rate-cap",
      detail: expect.stringContaining("exceeded the published cap"),
    });
  });

  it("exactly at the cap (cap-1 prior + this) ⇒ accepted with NO flag and NO action", () => {
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
    const inp = happyInput({
      payload: {
        canonicalRepo: REPO,
        maintainersPath: PATH,
        currentMandateHash: sha(k1),
        sourceCommit: "0123456789abcdef0123456789abcdef01234567",
        track: "ca",
        request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
      },
      chainMaterial: { pin: mandatePinHash(r), mandates: [r, k1] },
      existingRows: rows,
    });
    const d = validateCheckpointSubmission(inp);
    expect(d.accept).toBe(true);
    if (!d.accept) return;
    expect(d.row.flagged).toBe("");
    expect(d.action).toBeUndefined();
  });

  it("rows OUTSIDE the rolling window do not count toward the cap", () => {
    const r = authorityRoot();
    const k1 = successorMandate();
    // DEFAULT_RATE_CAP_MAX rows but all >30d before NOW ⇒ not in window.
    const rows: ExistingCheckpointRow[] = [];
    for (let i = 0; i < DEFAULT_RATE_CAP_MAX; i++) {
      rows.push({
        observed_at: `2025-01-${String(10 + i).padStart(2, "0")}T00:00:00Z`,
        track: "ca",
        current_mandate_hash: sha(r),
        flagged: "",
      });
    }
    const inp = happyInput({
      payload: {
        canonicalRepo: REPO,
        maintainersPath: PATH,
        currentMandateHash: sha(k1),
        sourceCommit: "0123456789abcdef0123456789abcdef01234567",
        track: "ca",
        request: mkRequest(alice.privKey, { currentMandateHash: sha(k1) }),
      },
      chainMaterial: { pin: mandatePinHash(r), mandates: [r, k1] },
      existingRows: rows,
    });
    const d = validateCheckpointSubmission(inp);
    expect(d.accept).toBe(true);
    if (d.accept) expect(d.row.flagged).toBe("");
  });
});
