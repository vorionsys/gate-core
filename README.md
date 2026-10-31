# @vorionsys/gate-core

> The minimal deterministic BASIS gate engine — fail-closed checks in fixed order,
> every verdict signed into a hash-linked chain of canonical decision records.

**Status:** Published on npm as `@vorionsys/gate-core@0.6.0`. The fixed fail-closed pipeline (credential, circuit breaker, domain allowlist, capability grants, param allowlists, verification gates, chain-derived rate limits, degradation, then tier caps) signs hash-linked decision records that `@vorionsys/verify` checks.  
`npm test` on Node v22.23.4 (`tsx --test test/gate.test.ts`): 32 passed, 0 failed. Pluggable check stages and multi-signer are not implemented.  
Known issue: `@vorionsys/contracts@^1.6.0` (resolved to 1.6.1) depends on `zod@^3.24.1` (resolved to 3.25.76), below 4.6.6, in open high-severity advisory [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5).

![license](https://img.shields.io/badge/license-Apache--2.0-blue)

> **What this is:** an *implementation*, not a specification. gate-core emits signed
> decision records from [`@vorionsys/contracts`](https://github.com/vorionsys/contracts)
> (`@vorionsys/contracts/basis`), checked with
> [`@vorionsys/verify`](https://www.npmjs.com/package/@vorionsys/verify).
> These are not [RFC-0002](https://github.com/vorionsys/basis-spec/blob/main/rfcs/0002-proof-event-chain.md)
> `ProofEvent`s — that draft uses a different shape (`eventId`, `eventType`, `previousHash`, …).
> The standard lives in [`basis-spec`](https://github.com/vorionsys/basis-spec); the pipeline
> companion spec in [`basis-gate`](https://github.com/vorionsys/basis-gate).

## Use

```ts
import { GateChain, ed25519Signer } from "@vorionsys/gate-core";

const gate = new GateChain({ policy, signer: ed25519Signer(privateKey, "my-kid") });
const record = gate.evaluate(ctx, {
  domain: "finance.payments",
  capability: "payments.execute",
  params: { amountUsd: 250_000 },
});
// `policy`, `ctx`, and `privateKey` are caller-supplied.
// With a tier cap below amountUsd: decision "escalate", reason "TIER_CAP_EXCEEDED", linksTo null.
// `latencyMs` is measured for that call; it is not a constant.

gate.resolveEscalation(record.id, "deny", ctx); // HUMAN_DENIED, linksTo record.id, action copied
gate.toChainFile(); // { basisVerify: "1", records }
gate.keysFile();    // { [kid]: publicKeyBase64 }
// npx @vorionsys/verify chain.json --keys keys.json
```

`@vorionsys/verify` is declared as `^0.1.0` (a fresh install resolved 0.1.1).
Registry latest at the time of this note was 0.6.0, which `^0.1.0` does not match.
Both 0.1.1 and 0.6.0 require `--keys` for this chain format. `verifier.html` ships in that package.

## The pipeline (fixed order, fail-closed)

A hit returns immediately. A step that reads an optional policy field does nothing when that field is absent.

1. **credential** → deny `CREDENTIAL_REVOKED`, or deny `CREDENTIAL_EXPIRED` when status is `expired` or `none`, or when `expiresAt` is at or before the evaluation time
2. **circuit breaker** (only with a degradation policy) → deny `CIRCUIT_BREAKER_OPEN`
3. **domain allowlist** → deny `DOMAIN_NOT_ALLOWLISTED`
4. **capability grants** (only when `capabilityGrants` is set, at the effective tier) → deny `CAPABILITY_NOT_GRANTED`
5. **param allowlists** → deny `PARAM_NOT_ALLOWLISTED`
6. **proof-of-verification** → deny `VERIFICATION_REQUIRED`
7. **rate limits** (prior `allow` records of that capability inside the window) → deny `RATE_LIMIT_EXCEEDED`
8. **degradation force-escalate** → escalate `TIER_CAP_EXCEEDED`
9. **tier caps** (legacy `tierCaps` for `payments.execute`, then generic `caps`; a tier with no entry caps at 0) → escalate `TIER_CAP_EXCEEDED`
10. otherwise → allow `WITHIN_AUTHORITY`

The decision and reason do not call a model, the network, or the RNG. Record ids default to `Math.random`, and timestamps default to the clock. Pass `now` and `rng` into the constructor when a replay must keep the same ids and times. Each verdict stores `latencyMs` for that evaluation. The suite asserts `latencyMs < 50`. On one 50-call sample here the recorded values were 0 or 1; that sample is not a latency guarantee.

Raw action params never enter a record. The record stores `sha256:` plus the hex digest of `@vorionsys/verify`'s `canonicalBytes`. That package documents its canonicalizer as a minimal RFC 8785 (JCS) implementation. This repo does not ship a separate RFC 8785 conformance suite.

`resolveEscalation` copies the escalated action onto each new record and sets `verdict.linksTo` to the escalation id. A denial is `deny` / `HUMAN_DENIED`. With no quorum rule, one approval is `allow` / `HUMAN_APPROVED`. Under a quorum, earlier approvals stay `escalate` / `HUMAN_APPROVED` until the required count. On the approving vote that would close the escalation, the gate re-checks the credential, the circuit breaker, and any approval ceiling. A conflict appends the signed `HUMAN_APPROVED` vote and a linked denial (`APPROVAL_CEILING_EXCEEDED`, `CREDENTIAL_EXPIRED`, `CREDENTIAL_REVOKED`, or `CIRCUIT_BREAKER_OPEN`).

## One crypto implementation, zero drift

This package imports `canonicalBytes` and `hashRecord` **from
[`@vorionsys/verify`](https://github.com/vorionsys/basis-verify)** rather than
implementing its own. Signing uses `@noble/ed25519` in this package. The shared
canonicalizer is what keeps the signer and the verifier on the same bytes.

## Where this sits in BASIS

```
basis-spec (standard)
   └── basis-gate (Gate v1 spec + layered reference runtime)
         ├── contracts (record schema — @vorionsys/contracts/basis)
         ├── THIS REPO ◄ (minimal embeddable gate core)
         └── basis-verify (offline proof-chain verification)
```

[`@vorionsys/basis-gate-runtime`](https://www.npmjs.com/package/@vorionsys/basis-gate-runtime)
is the published layered runtime (npm `0.2.0` when this note was written; its package description says postures and block/inline/deferred execution, and a two-stage proof chain). **This package is the minimal core** and emits `@vorionsys/contracts/basis` decision records. Those two proof shapes are not the same format today. Closing that gap is open as [basis-gate#8](https://github.com/vorionsys/basis-gate/issues/8).

[`basis-demo`](https://github.com/vorionsys/basis-demo) depends on `@vorionsys/gate-core@^0.6.0` and imports `GateChain` from it (`lib/server-gate.ts`).
Standard: [`basis-spec`](https://github.com/vorionsys/basis-spec) · [vorion.org](https://vorion.org)

## Not built

Pluggable check stages and multi-signer are not implemented. The constructor takes one `Signer`. Rate limits and the degradation strike score are implemented; both are derived from the chain, with no separate counter store.

## Development

```bash
git clone https://github.com/vorionsys/gate-core && cd gate-core
npm install && npm run build && npm test
```

There is no lockfile in this repo. `npm install` resolves the ranges in `package.json`. Node `>=18` is the declared `engines` range. [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs install, build, and `npm test` on Node 22. The test file is `test/gate.test.ts` (32 `node:test` cases: reason codes, order, quorum and approval ceiling, degradation, verification gates, resume, and strict `verifyChain`). PRs: small, tested, one concern.

## License

Apache-2.0. Copyright 2026 Vorion LLC. See [LICENSE](LICENSE).
