/**
 * `maintainers checkpoint submit` — hermetic tests (NO real
 * TTY/token/PIN/network: a fake `confirm`/`pivPin`/signer + a captured
 * `println`, mirroring caEndorsement.test.ts / createKey.test.ts).
 *
 * The load-bearing assertion is the chunk-3 ↔ chunk-2 ROUND-TRIP: a
 * request built+holder-signed via this verb's assemble/sign path, whose
 * emitted §9 `botPayload` is fed (with a fabricated matching verified
 * chain + clock) into the landed `validateCheckpointSubmission` and
 * accepted with the expected row — plus a tamper negative proving the
 * bot rejects a perturbed payload. That is the proof chunk 3 composes
 * with chunk 2.
 */

import { describe, expect, it } from "vitest";
import {
  generateKeypair,
  mandatePinHash,
  sign,
  signMandate,
  verify,
  verifyMandateChainFromPin,
  canonicalCheckpointRequest,
  verifyCheckpointRequest,
  validateCheckpointSubmission,
  type Mandate,
} from "@ibisllc/maintainers";
import {
  buildCheckpointRequest,
  assembleCheckpointRequest,
  buildCheckpointSubmissionPayload,
  checkpointCsvPath,
} from "../src/commands/checkpointSubmit.js";
import { dispatch, type CliEnv } from "../src/index.js";
import { parseArgs } from "../src/lib/args.js";
import type { PivTransport } from "../src/lib/keysource.js";

function keypair(seedByte: number) {
  const seed = new Uint8Array(32);
  seed[0] = seedByte;
  return generateKeypair(seed);
}

function fakeFs(files: Record<string, string>) {
  return {
    readFileSync(p: string): string {
      const v = files[p];
      if (v === undefined) throw new Error(`ENOENT: ${p}`);
      return v;
    },
  };
}

const NOW = new Date("2026-05-18T12:00:00Z");
const REPO = "https://github.com/ibisllc/flagship";
const PATH = ".maintainers/";
const COMMIT = "0123456789abcdef0123456789abcdef01234567";

/** A ca-track from-scratch root v2 mandate, live (the authority) at NOW. */
function caRoot(maintainer: { pubKey: string; privKey: string }): Mandate {
  return signMandate(
    {
      kind: "Mandate",
      version: 1,
      mandateId: "cpk-root-0000-4000-8000-000000000000",
      track: "ca",
      holder: maintainer.pubKey,
      issuedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2027-01-01T00:00:00.000Z",
      successors: [maintainer.pubKey],
      approvalRule: { kind: "threshold", threshold: 1 },
      minSuccessors: 1,
      maxDurationSeconds: 365 * 86_400,
      defaultDurationSeconds: 365 * 86_400,
      project: { name: "flagship", contact: "harry@flagship.services", tracks: ["ca"] },
      signedBy: maintainer.pubKey,
    },
    [{ privKey: maintainer.privKey }],
  );
}

describe("buildCheckpointRequest (assemble+sign)", () => {
  it("holder-signs a CheckpointRequest the protocol verifier accepts; bytes match the in-process path", async () => {
    const maintainer = keypair(1);
    const root = caRoot(maintainer);
    const hNew = `sha256:${mandatePinHash(root)}`;
    const req = await buildCheckpointRequest({
      canonicalRepo: REPO,
      maintainersPath: PATH,
      sourceCommit: COMMIT,
      track: "ca",
      currentMandateHash: hNew,
      signingKeySource: "file:./m.priv",
      now: () => NOW,
      io: fakeFs({ "./m.priv": maintainer.privKey }),
    });
    expect(req.kind).toBe("CheckpointRequest");
    expect(req.currentMandateHash).toBe(hNew);
    expect(req.signatures[0]!.pubkey).toBe(maintainer.pubKey);
    // Signature is over the canonical bytes (byte-identical to in-proc).
    expect(verify(req.signatures[0]!.sig, canonicalCheckpointRequest(req), maintainer.pubKey)).toBe(true);
    // The landed envelope verifier accepts it (holder-signs at NOW).
    const chain = verifyMandateChainFromPin(mandatePinHash(root), [root]);
    expect(verifyCheckpointRequest(req, chain, NOW)).toEqual({ ok: true });
  });

  it("derives currentMandateHash from the local store when the flag is absent (verify/status pattern)", async () => {
    const maintainer = keypair(2);
    const root = caRoot(maintainer);
    // assemble (no sign) — derive must match mandatePinHash of the live mandate.
    const a = await assembleCheckpointRequest({
      canonicalRepo: REPO,
      maintainersPath: PATH,
      sourceCommit: COMMIT,
      track: "ca",
      signingKeySource: "file:./m.priv",
      rootDir: "/nonexistent-store-xyz", // no store ⇒ must fail closed, not guess
      now: () => NOW,
      io: fakeFs({ "./m.priv": maintainer.privKey }),
    }).then(
      () => "DERIVED-OK-UNEXPECTED",
      (e: Error) => e.message,
    );
    expect(a).toMatch(/no "ca"-track mandates|did not anchor|pass --current-mandate-hash/);
    // (the on-disk-store derive happy path is exercised via dispatch below)
    void root;
  });

  it("YubiKey-PIV (injected token) is byte-identical to the file: path", async () => {
    const maintainer = keypair(3);
    const root = caRoot(maintainer);
    const hNew = `sha256:${mandatePinHash(root)}`;
    const token: PivTransport = {
      async getPublicKey() {
        return maintainer.pubKey;
      },
      async signEd25519(_slot, _pin, message) {
        return sign(message, maintainer.privKey);
      },
      async generateEd25519() {
        return maintainer.pubKey;
      },
    };
    const common = {
      canonicalRepo: REPO,
      maintainersPath: PATH,
      sourceCommit: COMMIT,
      track: "ca",
      currentMandateHash: hNew,
      now: () => NOW,
    };
    const viaFile = await buildCheckpointRequest({
      ...common,
      signingKeySource: "file:./m.priv",
      io: fakeFs({ "./m.priv": maintainer.privKey }),
    });
    const viaPiv = await buildCheckpointRequest({
      ...common,
      signingKeySource: "yubikey-piv:slot=9c",
      io: fakeFs({}),
      pivTransport: token,
      pivPin: async () => "424242",
    });
    expect(viaPiv).toEqual(viaFile);
  });

  it("rejects a malformed --current-mandate-hash (not sha256:<64-hex>)", async () => {
    const maintainer = keypair(4);
    await expect(
      buildCheckpointRequest({
        canonicalRepo: REPO,
        maintainersPath: PATH,
        sourceCommit: COMMIT,
        track: "ca",
        currentMandateHash: "deadbeef",
        signingKeySource: "file:./m.priv",
        now: () => NOW,
        io: fakeFs({ "./m.priv": maintainer.privKey }),
      }),
    ).rejects.toThrow(/sha256:<64-hex>/);
  });
});

describe("§9 payload — round-trip into the chunk-2 bot", () => {
  it("ROUND-TRIP: verb-emitted botPayload + a matching verified chain ⇒ validateCheckpointSubmission accept:true with the expected row", async () => {
    const maintainer = keypair(5);
    const root = caRoot(maintainer);
    const hNew = `sha256:${mandatePinHash(root)}`;
    const signed = await buildCheckpointRequest({
      canonicalRepo: REPO,
      maintainersPath: PATH,
      sourceCommit: COMMIT,
      track: "ca",
      currentMandateHash: hNew,
      signingKeySource: "file:./m.priv",
      now: () => NOW,
      io: fakeFs({ "./m.priv": maintainer.privKey }),
    });
    const payload = buildCheckpointSubmissionPayload(signed);
    // §9 replay-binding holds by construction: payload fields == signed request fields.
    expect(payload.botPayload.canonicalRepo).toBe(signed.canonicalRepo);
    expect(payload.botPayload.maintainersPath).toBe(signed.maintainersPath);
    expect(payload.botPayload.currentMandateHash).toBe(signed.currentMandateHash);
    expect(payload.proof.request).toBe(signed); // the REAL verifier-consumable envelope

    const decision = validateCheckpointSubmission({
      payload: payload.botPayload,
      chainMaterial: { pin: mandatePinHash(root), mandates: [root] },
      existingRows: [],
      now: NOW,
      repoReachable: true,
      maintainersPathExists: true,
      pathMatchesCanonicalRepo: true,
    });
    expect(decision.accept).toBe(true);
    if (!decision.accept) return;
    expect(decision.row.track).toBe("ca");
    expect(decision.row.current_mandate_hash).toBe(hNew);
    expect(decision.row.flagged).toBe(""); // first checkpoint, under the rate cap
    expect(decision.row.observed_at).toBe("2026-05-18T12:00:00Z"); // bot clock (rule 8)
  });

  it("TAMPER NEGATIVE: perturbing currentMandateHash in the emitted payload ⇒ the bot rejects (request-repo-mismatch)", async () => {
    const maintainer = keypair(6);
    const root = caRoot(maintainer);
    const hNew = `sha256:${mandatePinHash(root)}`;
    const signed = await buildCheckpointRequest({
      canonicalRepo: REPO,
      maintainersPath: PATH,
      sourceCommit: COMMIT,
      track: "ca",
      currentMandateHash: hNew,
      signingKeySource: "file:./m.priv",
      now: () => NOW,
      io: fakeFs({ "./m.priv": maintainer.privKey }),
    });
    const payload = buildCheckpointSubmissionPayload(signed);
    const tampered = {
      ...payload.botPayload,
      // a different but well-formed sha256 hash — the signed request
      // still binds the original, so the §9 replay-binding check fires.
      currentMandateHash: `sha256:${"a".repeat(64)}`,
    };
    const decision = validateCheckpointSubmission({
      payload: tampered,
      chainMaterial: { pin: mandatePinHash(root), mandates: [root] },
      existingRows: [],
      now: NOW,
      repoReachable: true,
      maintainersPathExists: true,
      pathMatchesCanonicalRepo: true,
    });
    expect(decision.accept).toBe(false);
    if (decision.accept) return;
    expect(decision.reason).toBe("request-repo-mismatch");
  });
});

describe("checkpoint submit dispatch (e2e — fake confirm/pin, captured println)", () => {
  function mkEnv(
    lines: string[],
    over: Partial<CliEnv> = {},
  ): CliEnv {
    return {
      now: () => NOW,
      io: fakeFs({}),
      uuid: () => "cpk-disp-0000-0000-0000-000000000000",
      println: (l) => lines.push(l),
      printerr: (l) => lines.push(`ERR ${l}`),
      ...over,
    };
  }

  it("--dry-run previews the canonical bytes + §9 payload + would-be CSV row, and NEVER signs or PINs", async () => {
    const maintainer = keypair(7);
    const root = caRoot(maintainer);
    const hNew = `sha256:${mandatePinHash(root)}`;
    const lines: string[] = [];
    let pinAsked = false;
    const code = await dispatch(
      parseArgs([
        "checkpoint",
        "submit",
        "--canonical-repo",
        REPO,
        "--source-commit",
        COMMIT,
        "--current-mandate-hash",
        hNew,
        "--signing-key",
        "file:./m.priv",
        "--dry-run",
      ]),
      mkEnv(lines, {
        io: fakeFs({ "./m.priv": maintainer.privKey }),
        pivPin: async () => {
          pinAsked = true;
          return "x";
        },
        confirm: async () => {
          throw new Error("confirm must NOT be called on --dry-run");
        },
      }),
    );
    expect(code).toBe(0);
    expect(pinAsked).toBe(false);
    const out = lines.join("\n");
    expect(out).toContain("DRY RUN");
    expect(out).toContain("canonical bytes (hex");
    expect(out).toContain("§9 PR payload (DRY RUN");
    expect(out).toContain("would append (CSV row");
    expect(out).toContain(hNew);
    // request must be UNSIGNED on dry-run (signatures empty array).
    expect(out).toContain('"signatures": []');
  });

  it("real path: shows the REVIEW banner, requires the typed CHECKPOINT-SUBMIT confirm, holder-signs, emits a payload", async () => {
    const maintainer = keypair(8);
    const root = caRoot(maintainer);
    const hNew = `sha256:${mandatePinHash(root)}`;
    const lines: string[] = [];
    const phrases: string[] = [];
    const code = await dispatch(
      parseArgs([
        "checkpoint",
        "submit",
        "--canonical-repo",
        REPO,
        "--source-commit",
        COMMIT,
        "--current-mandate-hash",
        hNew,
        "--signing-key",
        "file:./m.priv",
      ]),
      mkEnv(lines, {
        io: fakeFs({ "./m.priv": maintainer.privKey }),
        confirm: async ({ phrase }) => {
          phrases.push(phrase);
          return true;
        },
      }),
    );
    expect(code).toBe(0);
    expect(phrases).toEqual(["CHECKPOINT-SUBMIT"]); // exact typed-confirm phrase
    const out = lines.join("\n");
    expect(out).toContain("CHECKPOINT SUBMIT —");
    expect(out).toContain("REVIEW — checkpoint-submit — about to SIGN");
    expect(out).toContain("§9 PR payload (signed CheckpointRequest");
    expect(out).toContain(`checkpoints-repo file (§6): ${checkpointCsvPath(REPO)}`);
    expect(out).toContain("gh pr create -R ibisllc/maintainers-checkpoints");
    expect(out).not.toContain('"signatures": []'); // signed ⇒ non-empty
  });

  it("derives H_new from an on-disk .maintainers store when --current-mandate-hash is absent", async () => {
    const fs = await import("node:fs");
    const os = await import("node:os");
    const pathmod = await import("node:path");
    const maintainer = keypair(9);
    const root = caRoot(maintainer);
    const tmp = fs.mkdtempSync(pathmod.join(os.tmpdir(), "maintainers-cpk-"));
    const storeRoot = pathmod.join(tmp, ".maintainers");
    const mdir = pathmod.join(storeRoot, "tracks", "ca", "mandates");
    fs.mkdirSync(mdir, { recursive: true });
    fs.writeFileSync(pathmod.join(mdir, "m.json"), JSON.stringify(root));
    const keyFile = pathmod.join(tmp, "m.priv");
    fs.writeFileSync(keyFile, maintainer.privKey);

    const lines: string[] = [];
    const code = await dispatch(
      parseArgs([
        "checkpoint",
        "submit",
        "--canonical-repo",
        REPO,
        "--source-commit",
        COMMIT,
        "--signing-key",
        `file:${keyFile}`,
        "--path",
        storeRoot,
        "--yes",
      ]),
      {
        now: () => NOW,
        io: { readFileSync: (p: string) => fs.readFileSync(p, "utf8") },
        uuid: () => "cpk-store-0000-0000-0000-000000000000",
        println: (l) => lines.push(l),
        printerr: (l) => lines.push(`ERR ${l}`),
      },
    );
    expect(code).toBe(0);
    expect(lines.join("\n")).toContain(`sha256:${mandatePinHash(root)}`);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("non-interactive without --yes and no injected confirm ⇒ deterministic fail-closed (never hangs)", async () => {
    const maintainer = keypair(10);
    const root = caRoot(maintainer);
    const hNew = `sha256:${mandatePinHash(root)}`;
    const lines: string[] = [];
    const code = await dispatch(
      parseArgs([
        "checkpoint",
        "submit",
        "--canonical-repo",
        REPO,
        "--source-commit",
        COMMIT,
        "--current-mandate-hash",
        hNew,
        "--signing-key",
        "file:./m.priv",
      ]),
      mkEnv(lines, {
        io: fakeFs({ "./m.priv": maintainer.privKey }),
        confirm: undefined, // no TTY, no injected confirm, no --yes
      }),
    );
    expect(code).toBe(1); // CliError ⇒ exit 1, not a hang
    expect(lines.join("\n")).toMatch(/needs interactive confirmation|refusing/);
  });

  it("confirm=false aborts cleanly (nothing signed/emitted; clear abort message)", async () => {
    const maintainer = keypair(11);
    const root = caRoot(maintainer);
    const hNew = `sha256:${mandatePinHash(root)}`;
    const lines: string[] = [];
    const code = await dispatch(
      parseArgs([
        "checkpoint",
        "submit",
        "--canonical-repo",
        REPO,
        "--source-commit",
        COMMIT,
        "--current-mandate-hash",
        hNew,
        "--signing-key",
        "file:./m.priv",
      ]),
      mkEnv(lines, {
        io: fakeFs({ "./m.priv": maintainer.privKey }),
        confirm: async () => false,
      }),
    );
    expect(code).toBe(1);
    const out = lines.join("\n");
    expect(out).toContain("aborted at the confirmation prompt");
    expect(out).not.toContain("§9 PR payload (signed");
  });

  it("an unknown checkpoint sub-action fails closed (exit 2, clear message)", async () => {
    const lines: string[] = [];
    const code = await dispatch(parseArgs(["checkpoint", "bogus"]), mkEnv(lines));
    expect(code).toBe(2);
    expect(lines.join("\n")).toContain("unknown checkpoint sub-action: bogus");
  });
});
