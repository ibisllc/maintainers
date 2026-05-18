/**
 * Envelope-construction + verify-path tests (LOCKED Phase-2 v2).
 *
 * Mandate construction (genesis/renew/takeover collapsed into the ONE
 * `upsert-mandate` verb) is owned by `upsertMandate.test.ts`. This file
 * covers what remains here:
 *
 *   - `buildEndorsement`: still emits a v1 `ReleaseEndorsement` (that
 *     type is unchanged by the v2 model) over a v2 release-track root;
 *   - the mandated v2 verify-path fail-closed NEGATIVES:
 *       • empty/absent pin ⇒ `no-pin` ⇒ reject all
 *       • a forked/tampered pin ⇒ `pin-not-in-log` ⇒ reject all
 *       • an unauthorised successor ⇒ `signer-not-in-successor-set`
 *   - a happy-path forward verify (root → renewal) so the positive case
 *     is anchored alongside the negatives.
 */

import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  canonicalReleaseEndorsement,
  currentAuthority,
  generateKeypair,
  intermediateMerkleRoot,
  mandatePinHash,
  signMandate,
  verify,
  verifyMandateChainFromPin,
  type Mandate,
} from "@ibisllc/maintainers";
import { buildEndorsement } from "../src/commands/endorsement.js";
import { writeMandate } from "../src/lib/store.js";

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

function mkTmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

const alice = keypair(1);
const bob = keypair(2);
const eve = keypair(3);

/** A from-scratch (root) release `Mandate`, self-signed by `holder`. */
function root(
  holder: { pubKey: string; privKey: string },
  successors: string[],
  o: { id?: string; threshold?: number } = {},
): Mandate {
  const unsigned: Omit<Mandate, "signatures"> = {
    kind: "Mandate",
    version: 1,
    mandateId: o.id ?? "rel-root-0000-4000-8000-000000000000",
    track: "release",
    holder: holder.pubKey,
    issuedAt: "2026-01-01T00:00:00.000Z",
    expiresAt: "2026-12-01T00:00:00.000Z",
    successors,
    approvalRule: { kind: "threshold", threshold: o.threshold ?? 1 },
    minSuccessors: 1,
    maxDurationSeconds: 365 * 86_400,
    defaultDurationSeconds: 60 * 86_400,
    project: { name: "flagship", contact: "harry@flagship.services", tracks: ["release"] },
    signedBy: holder.pubKey,
  };
  return signMandate(unsigned, [{ privKey: holder.privKey }]);
}

/** A succession mandate signed by `signer` (must be a named successor of
 *  the predecessor for the forward step to be accepted). */
function next(
  signer: { pubKey: string; privKey: string },
  holder: { pubKey: string },
  successors: string[],
  o: { id?: string; issuedAt?: string } = {},
): Mandate {
  const unsigned: Omit<Mandate, "signatures"> = {
    kind: "Mandate",
    version: 1,
    mandateId: o.id ?? "rel-next-0000-4000-8000-000000000001",
    track: "release",
    holder: holder.pubKey,
    issuedAt: o.issuedAt ?? "2026-02-01T00:00:00.000Z",
    expiresAt: "2026-06-01T00:00:00.000Z",
    successors,
    approvalRule: { kind: "threshold", threshold: 1 },
    minSuccessors: 1,
    maxDurationSeconds: 365 * 86_400,
    defaultDurationSeconds: 60 * 86_400,
    signedBy: signer.pubKey,
  };
  return signMandate(unsigned, [{ privKey: signer.privKey }]);
}

describe("v2 forward verify — happy path", () => {
  it("root → renewal verifies forward from the root's own pin", () => {
    const r = root(alice, [alice.pubKey, bob.pubKey]);
    const renewal = next(alice, alice, [alice.pubKey, bob.pubKey]);
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, renewal]);
    expect(chain.rootError).toBeUndefined();
    expect(chain.validMandates.map((m) => m.mandateId)).toEqual([
      r.mandateId,
      renewal.mandateId,
    ]);
    const auth = currentAuthority(chain, new Date("2026-03-01T00:00:00Z"));
    expect(auth?.holder).toBe(alice.pubKey);
  });

  it("takeover by a named successor: holder changes, chain still verifies", () => {
    const r = root(alice, [bob.pubKey]);
    const takeover = next(bob, bob, [bob.pubKey]);
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, takeover]);
    expect(chain.validMandates).toHaveLength(2);
    expect(chain.validMandates[1]!.holder).toBe(bob.pubKey);
    expect(chain.validMandates[1]!.signedBy).toBe(bob.pubKey);
  });
});

describe("v2 verify-path fail-closed negatives (the mandated set)", () => {
  it("empty/absent pin ⇒ no-pin ⇒ reject all", () => {
    const r = root(alice, [alice.pubKey]);
    const chain = verifyMandateChainFromPin("", [r]);
    expect(chain.rootError).toBe("no-pin");
    expect(chain.validMandates).toHaveLength(0);
    expect(currentAuthority(chain, new Date("2026-03-01T00:00:00Z"))).toBeNull();
  });

  it("a forked/tampered pin ⇒ pin-not-in-log ⇒ reject all", () => {
    const r = root(alice, [alice.pubKey]);
    // a pin that matches NO mandate's canonical bytes (a fork)
    const forked = "f".repeat(64);
    const chain = verifyMandateChainFromPin(forked, [r]);
    expect(chain.rootError).toBe("pin-not-in-log");
    expect(chain.validMandates).toHaveLength(0);
  });

  it("an unauthorised successor ⇒ signer-not-in-successor-set (forward step rejected)", () => {
    const r = root(alice, [bob.pubKey]); // only bob may succeed
    const usurp = next(eve, eve, [eve.pubKey]); // eve is NOT a successor
    const chain = verifyMandateChainFromPin(mandatePinHash(r), [r, usurp]);
    expect(chain.root?.mandateId).toBe(r.mandateId);
    expect(chain.validMandates.map((m) => m.mandateId)).toEqual([r.mandateId]);
    expect(chain.rejections).toHaveLength(1);
    expect(chain.rejections[0]!.reason).toBe("signer-not-in-successor-set");
    // and no live authority after the (rejected) usurpation window
    expect(
      currentAuthority(chain, new Date("2027-01-01T00:00:00Z")),
    ).toBeNull();
  });
});

describe("buildEndorsement (still a v1 ReleaseEndorsement; v2 chain underneath)", () => {
  it("produces a genesis release endorsement with correct merkle root", async () => {
    const tmp = mkTmp("maintainers-cli-endorsement-");
    // a v2 release root on disk so the "bootstrap with upsert-mandate
    // first" guard is satisfied.
    writeMandate(tmp, root(alice, [alice.pubKey]));

    const commit = "a".repeat(40);
    const e = await buildEndorsement({
      commit,
      tag: "v0.1.0",
      previousId: null,
      previousCommit: null,
      intermediatesSpec: commit,
      signingKeySource: "file:./alice.priv",
      track: "release",
      rootDir: tmp,
      now: () => new Date("2026-01-15T00:00:00Z"),
      io: fakeFs({ "./alice.priv": alice.privKey }),
      uuid: () => "e1e1e1e1-e1e1-e1e1-e1e1-e1e1e1e1e1e1",
    });

    expect(e.semverTag).toBe("v0.1.0");
    expect(e.commitHash).toBe(commit);
    expect(e.previousReleaseId).toBeNull();
    expect(e.previousCommitHash).toBeNull();
    expect(e.intermediateCommits).toEqual([commit]);
    expect(e.intermediateMerkleRoot).toBe(intermediateMerkleRoot([commit]));
    const bytes = canonicalReleaseEndorsement(e);
    expect(verify(e.signatures[0]!.sig, bytes, alice.pubKey)).toBe(true);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("verifies inline csv intermediates produce a correct merkle root", async () => {
    const tmp = mkTmp("maintainers-cli-endorsement-csv-");
    writeMandate(tmp, root(alice, [alice.pubKey]));

    const c1 = "1".repeat(40);
    const c2 = "2".repeat(40);
    const c3 = "3".repeat(40);
    const e = await buildEndorsement({
      commit: c3,
      tag: "v0.2.0",
      previousId: "e1e1e1e1-e1e1-e1e1-e1e1-e1e1e1e1e1e1",
      previousCommit: c1,
      intermediatesSpec: `${c2},${c3}`,
      signingKeySource: "file:./alice.priv",
      track: "release",
      rootDir: tmp,
      now: () => new Date("2026-02-01T00:00:00Z"),
      io: fakeFs({ "./alice.priv": alice.privKey }),
      uuid: () => "e2",
    });
    expect(e.intermediateCommits).toEqual([c2, c3]);
    expect(e.intermediateMerkleRoot).toBe(intermediateMerkleRoot([c2, c3]));
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("rejects a non-hex commit hash", async () => {
    const tmp = mkTmp("maintainers-cli-endorsement-bad-");
    writeMandate(tmp, root(alice, [alice.pubKey]));

    await expect(
      buildEndorsement({
        commit: "zzz",
        tag: "v0.0.1",
        previousId: null,
        previousCommit: null,
        intermediatesSpec: "auto",
        signingKeySource: "file:./alice.priv",
        track: "release",
        rootDir: tmp,
        now: () => new Date("2026-01-15T00:00:00Z"),
        io: fakeFs({ "./alice.priv": alice.privKey }),
        uuid: () => "e",
      }),
    ).rejects.toThrow(/commit must be a 40-character commit hash/);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("refuses when the track has no v2 mandate (bootstrap with upsert-mandate)", async () => {
    const tmp = mkTmp("maintainers-cli-endorsement-empty-");
    await expect(
      buildEndorsement({
        commit: "a".repeat(40),
        tag: "v0.0.1",
        previousId: null,
        previousCommit: null,
        intermediatesSpec: "a".repeat(40),
        signingKeySource: "file:./alice.priv",
        track: "release",
        rootDir: tmp,
        now: () => new Date("2026-01-15T00:00:00Z"),
        io: fakeFs({ "./alice.priv": alice.privKey }),
        uuid: () => "e",
      }),
    ).rejects.toThrow(/no v2 mandates found.*upsert-mandate/s);
    fs.rmSync(tmp, { recursive: true, force: true });
  });
});
