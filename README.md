# @vorionsys/gate-core

> Reference implementation of the BASIS Gate v1 pipeline — deterministic, fail-closed,
> and every verdict is signed into a hash-linked proof chain.

![license](https://img.shields.io/badge/license-Apache--2.0-blue)

## Use

```ts
import { GateChain, ed25519Signer } from "@vorionsys/gate-core";

const gate = new GateChain({ policy, signer: ed25519Signer(privateKey, "my-kid") });
const record = gate.evaluate(ctx, {
  domain: "finance.payments",
  capability: "payments.execute",
  params: { amountUsd: 250_000 },
});
// record.verdict → { decision: "escalate", reason: "TIER_CAP_EXCEEDED", latencyMs: 0, linksTo: null }

gate.resolveEscalation(record.id, "deny", ctx); // signed HUMAN_DENIED, linksTo record.id
gate.toChainFile(); // → verify with `npx @vorionsys/verify` or verifier.html
```

## The pipeline (fixed order, fail-closed by construction)

1. **credential check** → deny `CREDENTIAL_REVOKED` / `CREDENTIAL_EXPIRED` (expired, `none`, or past `expiresAt`)
2. **domain allowlist** → deny `DOMAIN_NOT_ALLOWLISTED`
3. **tier cap** → escalate `TIER_CAP_EXCEEDED`
4. otherwise → allow `WITHIN_AUTHORITY`

No model, no randomness, no I/O in the decision path — decisions land in
single-digit milliseconds and the latency is recorded in every verdict.
Raw action params never enter a record; only their RFC 8785 hash does.

Human resolutions (`resolveEscalation`) emit a record that copies the escalated
action verbatim and sets `verdict.linksTo` — accountability is structural.

## One crypto implementation, zero drift

This package imports `canonicalBytes` and `hashRecord` **from
[`@vorionsys/verify`](https://github.com/vorionsys/basis-verify)** rather than
implementing its own. That direction is deliberate: the thing that signs cannot
disagree with the thing that verifies.

## Where this sits in BASIS

```
basis-spec (standard)
   └── basis-gate (BASIS Gate v1 — the specification this implements)
         ├── contracts (record schema — @vorionsys/contracts/basis)
         ├── THIS REPO ◄ (reference gate engine)
         └── basis-verify (offline proof-chain verification)
```

See it run at [`basis-demo`](https://github.com/vorionsys/basis-demo) — the demo
imports this exact package; that is the credibility mechanism.
Standard: [`basis-spec`](https://github.com/vorionsys/basis-spec) · [vorion.org](https://vorion.org)

## Status & versioning

`v0.1.0` — minimal pipeline matching the demo policy surface (payment caps,
domain allowlist, credential state). npm publish lands once
`@vorionsys/contracts@1.2.0` (vorionsys/contracts PR: `feat/basis-decision-record`)
is merged and released. Roadmap, not built: pluggable check stages, rate/risk
accumulators, multi-signer.

## Development

```bash
git clone https://github.com/vorionsys/gate-core && cd gate-core
npm install && npm run build && npm test   # one test per reason code + chain round-trip
```

Node ≥ 18. PRs: small, tested, one concern.

## License

Apache-2.0 © Vorion LLC
