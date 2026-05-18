/**
 * v2 test fixtures (LOCKED Phase-2 v2 model). Mirrors the
 * cloudflare-worker `mk` helper from c4.5a so web-ui tests exercise
 * the same forward-from-pin path. No policy.json — the succession rule
 * is inline in each mandate.
 */

import {
  generateKeypair,
  signKeyFile,
  signMandate,
  type KeyFile,
  type Mandate,
} from "@maintainers/protocol";

const DAY = 86400;

export function kp(seedByte: number): { privKey: string; pubKey: string } {
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
  project?: { name: string; tracks?: string[] };
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
    maxDurationSeconds: o.maxDurationSeconds ?? 1000 * DAY,
    defaultDurationSeconds: 60 * DAY,
    ...(o.project ? { project: o.project } : {}),
    signedBy: o.signedBy,
  };
  return signMandate(unsigned, o.signWith.map((privKey) => ({ privKey })));
}

export function mkKeyFile(p: {
  pub: string;
  priv: string;
  displayName: string;
  email: string;
}): KeyFile {
  return signKeyFile(
    {
      kind: "KeyFile",
      version: 1,
      pubkey: p.pub,
      displayName: p.displayName,
      currentEmail: p.email,
      emailHistory: [],
      metadata: { photo: null, github: null, role: null },
      introductionMandate: "",
    },
    p.priv,
  );
}
