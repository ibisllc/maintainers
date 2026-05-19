# @ibisllc/maintainers

A trust protocol for declaring, renewing, and transferring signing
authority over a versioned artifact (typically a git repository, but the
storage layer is content-addressed and adapter-driven). The model is
**pin-a-mandate, verify-forward**: a consumer bakes the canonical hash of
one chosen `Mandate` (the *pin*) into its own signed build, then accepts
a track's authority **only** by walking that track's mandate log
*forward* from the pinned mandate, applying each mandate's own embedded
succession rule to authorize the next. There is no separate policy file
and no privileged self-renewal — one uniform rule, signed into each
mandate, governs the next. **The bake is the ceremony**: trust is
established once, at compile time, by choosing what to pin; everything
after is mechanical forward verification against that anchor.

This package is the TypeScript reference implementation: canonical-bytes,
Ed25519 sign/verify, the mandate-chain / release-endorsement /
CA-endorsement verifiers, storage + encrypted-blob adapters, and a
zero-dependency `fetch()` client.

**Source / issues:** <https://github.com/ibisllc/maintainers> (this
package lives at `packages/protocol`). The spec is
[`docs/spec/v1.md`](https://github.com/ibisllc/maintainers/blob/main/docs/spec/v1.md).

## Install

```
npm i @ibisllc/maintainers
```

ESM only. Runtime deps: `@noble/curves`, `@noble/hashes`.

## Verify from a fetched repo

`verifyFromFetch` GETs a project's `.maintainers/index.json` tree from a
base URL and runs the full verifier against your baked pin, at *your
own* clock. It is **total** — every adversarial input (missing index,
oversized doc, path escape, malformed envelope, absent or forked pin) is
a fail-closed return value, never a thrown exception.

```ts
import { verifyFromFetch } from "@ibisllc/maintainers";

const verdict = await verifyFromFetch("https://example.org", {
  pin: "<the mandate pin hash you compiled into your build>",
  now: new Date(),
});

const release = verdict.tracks["release"];
if (release?.accepted) {
  // release.holder is the pubkey authorized to sign releases right now
} else {
  // release?.rejectReason is the exact landed fail-closed reason
}
```

## Verify a chain you already have

```ts
import {
  verifyMandateChainFromPin,
  currentAuthority,
  pinOf,
} from "@ibisllc/maintainers";

const chain = verifyMandateChainFromPin(pin, mandates); // never throws
const auth = currentAuthority(chain, new Date());        // holder or null
// pinOf(mandate) derives the canonical pin you bake into a build
```

## Conformance & spec (bundled)

This tarball ships the protocol's **primary portable artifact** so a
non-TypeScript adopter has everything needed to build an independent,
provably-conformant implementation:

- `SPEC.md` — the normative protocol specification (wire-version 1).
- `conformance/manifest.json` + `conformance/vectors/*.json` — 17
  language-agnostic, deterministically-generated test vectors. An
  implementation is **conformant if and only if** it produces the
  expected verdict for **every** vector, including **every fail-closed
  negative**. Accepting an input a negative vector expects rejected is
  *not* conformant — it has silently weakened fail-closed.

## Threat model (one line)

Fail-closed by construction: no pin, a pin not in the log, a forked or
tampered log, sub-threshold approvals, a lapsed CA lease at *your* clock
— every one rejects. There is no path that accepts on ambiguity.

## Status

**0.1.0 — first public release.** The spec is Draft, targeting
stabilization at v1.0 once the reference implementation and at least one
independent implementation interoperate against the bundled conformance
vectors.

## License

BUSL-1.1 (Business Source License 1.1), (c) 2026 Ibis LLC. Change Date
**2030-05-03**, after which the Change License is Apache License,
Version 2.0. See `LICENSE`.
