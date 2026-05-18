/**
 * Project status/preview view tests — LOCKED Phase-2 v2 model.
 *
 * #31: this view is READ-ONLY. It verifies a track's mandate log
 * FORWARD from the first on-repo mandate (the read-only-preview anchor)
 * via verifyMandateChainFromPin + currentAuthority. These tests pin
 * the v2 path and its fail-closed negatives (empty pin ⇒ reject,
 * pin-not-in-log ⇒ reject) — mirroring the c4.5a policy.test.ts
 * rewrite.
 */

import { describe, expect, it } from "vitest";
import {
  currentAuthority,
  mandatePinHash,
  verifyMandateChainFromPin,
} from "@maintainers/protocol";
import { _verifyChainForTest } from "../src/views/project.js";
import { kp, mk } from "./fixtures.js";

const NOW = new Date("2026-02-01T00:00:00Z");

describe("project view — v2 forward-from-pin status", () => {
  it("anchors at the first on-repo mandate and reports the current authority", () => {
    const alice = kp(1);
    const root = mk({
      id: "r-0000-0000-0000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-12-01T00:00:00Z",
      successors: [alice.pubKey],
      project: { name: "demo" },
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const chain = _verifyChainForTest([root]);
    expect(chain.root?.mandateId).toBe(root.mandateId);
    expect(chain.validMandates).toHaveLength(1);
    const auth = currentAuthority(chain, NOW);
    expect(auth?.holder).toBe(alice.pubKey);
  });

  it("accepts a forward succession (the L3 one rule, holder-rotates)", () => {
    const alice = kp(1);
    const bob = kp(2);
    const root = mk({
      id: "r-0000-0000-0000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-06-01T00:00:00Z",
      successors: [bob.pubKey],
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const next = mk({
      id: "r-0000-0000-0000-000000000002",
      holder: bob.pubKey,
      issuedAt: "2026-02-01T00:00:00Z",
      expiresAt: "2026-07-01T00:00:00Z",
      successors: [bob.pubKey],
      signedBy: bob.pubKey,
      signWith: [bob.privKey],
    });
    const chain = _verifyChainForTest([root, next]);
    expect(chain.validMandates.map((m) => m.mandateId)).toEqual([
      root.mandateId,
      next.mandateId,
    ]);
    const auth = currentAuthority(chain, new Date("2026-03-01T00:00:00Z"));
    expect(auth?.holder).toBe(bob.pubKey);
  });

  it("FAIL-CLOSED: empty pin ⇒ no chain, no authority", () => {
    const alice = kp(1);
    const root = mk({
      id: "r-0000-0000-0000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-12-01T00:00:00Z",
      successors: [alice.pubKey],
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const chain = verifyMandateChainFromPin("", [root]);
    expect(chain.root).toBeNull();
    expect(chain.rootError).toBe("no-pin");
    expect(chain.validMandates).toHaveLength(0);
    expect(currentAuthority(chain, NOW)).toBeNull();
    // The view's own helper also fail-closes on an empty mandate list.
    expect(_verifyChainForTest([]).rootError).toBe("no-pin");
  });

  it("FAIL-CLOSED: pin-not-in-log (forked/tampered) ⇒ reject", () => {
    const alice = kp(1);
    const eve = kp(99);
    const real = mk({
      id: "r-0000-0000-0000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-12-01T00:00:00Z",
      successors: [alice.pubKey],
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const forged = mk({
      id: "r-0000-0000-0000-000000000099",
      holder: eve.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-12-01T00:00:00Z",
      successors: [eve.pubKey],
      signedBy: eve.pubKey,
      signWith: [eve.privKey],
    });
    // Anchor at the REAL mandate's pin but feed only the forged log.
    const chain = verifyMandateChainFromPin(mandatePinHash(real), [forged]);
    expect(chain.root).toBeNull();
    expect(chain.rootError).toBe("pin-not-in-log");
    expect(currentAuthority(chain, NOW)).toBeNull();
  });

  it("rejects an unauthorised successor (signer not in predecessor's successors)", () => {
    const alice = kp(1);
    const eve = kp(99);
    const root = mk({
      id: "r-0000-0000-0000-000000000001",
      holder: alice.pubKey,
      issuedAt: "2026-01-01T00:00:00Z",
      expiresAt: "2026-06-01T00:00:00Z",
      successors: [], // nobody is authorised to succeed
      signedBy: alice.pubKey,
      signWith: [alice.privKey],
    });
    const stolen = mk({
      id: "r-0000-0000-0000-000000000099",
      holder: eve.pubKey,
      issuedAt: "2026-02-01T00:00:00Z",
      expiresAt: "2026-07-01T00:00:00Z",
      successors: [eve.pubKey],
      signedBy: eve.pubKey,
      signWith: [eve.privKey],
    });
    const chain = _verifyChainForTest([root, stolen]);
    expect(chain.validMandates).toHaveLength(1);
    expect(chain.rejections).toHaveLength(1);
    expect(chain.rejections[0]!.reason).toBe("signer-not-in-successor-set");
  });
});
