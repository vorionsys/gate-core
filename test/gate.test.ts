/**
 * One test per reason code (SPEC-basis-demo §6, days 3–5), plus pipeline-order
 * and chain-integrity checks. Run: npm test (tsx --test).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyChain } from "@vorionsys/verify";
import { GateChain, ed25519Signer, type GateContext, type PolicyDoc } from "../src/index.js";
import * as ed from "@noble/ed25519";

const policy: PolicyDoc = {
  id: "pol_test",
  version: "1.0.0",
  domainAllowlist: ["finance.ledger", "finance.payments"],
  tierCaps: { 2: { paymentUsdMax: 10_000 } },
};

const FUTURE = "2999-01-01T00:00:00.000Z";
const activeCtx: GateContext = {
  agent: { id: "agt_test", tier: 2 },
  credential: { id: "cred_test", status: "active", expiresAt: FUTURE },
};

const newGate = () => new GateChain({ policy, signer: ed25519Signer(ed.utils.randomPrivateKey(), "test-kid") });

const read = { domain: "finance.ledger", capability: "ledger.read", params: { period: "Q1" } };
const bigPayment = { domain: "finance.payments", capability: "payments.execute", params: { amountUsd: 50_000 } };

test("WITHIN_AUTHORITY — allow", () => {
  const r = newGate().evaluate(activeCtx, read);
  assert.equal(r.verdict.decision, "allow");
  assert.equal(r.verdict.reason, "WITHIN_AUTHORITY");
});

test("TIER_CAP_EXCEEDED — escalate above the tier payment cap", () => {
  const r = newGate().evaluate(activeCtx, bigPayment);
  assert.equal(r.verdict.decision, "escalate");
  assert.equal(r.verdict.reason, "TIER_CAP_EXCEEDED");
});

test("payments at or under the cap are allowed", () => {
  const r = newGate().evaluate(activeCtx, { ...bigPayment, params: { amountUsd: 10_000 } });
  assert.equal(r.verdict.reason, "WITHIN_AUTHORITY");
});

test("DOMAIN_NOT_ALLOWLISTED — deny", () => {
  const r = newGate().evaluate(activeCtx, { domain: "vendor.api", capability: "vendor.api.call", params: {} });
  assert.equal(r.verdict.decision, "deny");
  assert.equal(r.verdict.reason, "DOMAIN_NOT_ALLOWLISTED");
});

test("CREDENTIAL_EXPIRED — deny on status=expired, status=none, and past expiresAt", () => {
  for (const credential of [
    { ...activeCtx.credential, status: "expired" as const },
    { ...activeCtx.credential, status: "none" as const, expiresAt: null },
    { ...activeCtx.credential, expiresAt: "2000-01-01T00:00:00.000Z" },
  ]) {
    const r = newGate().evaluate({ ...activeCtx, credential }, read);
    assert.equal(r.verdict.decision, "deny");
    assert.equal(r.verdict.reason, "CREDENTIAL_EXPIRED");
  }
});

test("CREDENTIAL_REVOKED — deny", () => {
  const r = newGate().evaluate({ ...activeCtx, credential: { ...activeCtx.credential, status: "revoked" } }, read);
  assert.equal(r.verdict.decision, "deny");
  assert.equal(r.verdict.reason, "CREDENTIAL_REVOKED");
});

test("fail-closed ordering — credential check precedes domain check", () => {
  const r = newGate().evaluate(
    { ...activeCtx, credential: { ...activeCtx.credential, status: "revoked" } },
    { domain: "not.allowlisted", capability: "x.y", params: {} },
  );
  assert.equal(r.verdict.reason, "CREDENTIAL_REVOKED");
});

test("HUMAN_APPROVED / HUMAN_DENIED — resolution links to the escalation and copies its action", () => {
  for (const [resolution, decision, reason] of [
    ["approve", "allow", "HUMAN_APPROVED"],
    ["deny", "deny", "HUMAN_DENIED"],
  ] as const) {
    const gate = newGate();
    const esc = gate.evaluate(activeCtx, bigPayment);
    const res = gate.resolveEscalation(esc.id, resolution, activeCtx);
    assert.equal(res.verdict.decision, decision);
    assert.equal(res.verdict.reason, reason);
    assert.equal(res.verdict.linksTo, esc.id);
    assert.deepEqual(res.action, esc.action); // paramsHash carried verbatim
  }
});

test("resolveEscalation rejects unknown ids and non-escalations", () => {
  const gate = newGate();
  const allow = gate.evaluate(activeCtx, read);
  assert.throws(() => gate.resolveEscalation("01AAAAAAAAAAAAAAAAAAAAAAAA", "deny", activeCtx), /no escalation record/);
  assert.throws(() => gate.resolveEscalation(allow.id, "deny", activeCtx), /not an escalation/);
});

test("emitted chains verify with @vorionsys/verify (strict)", () => {
  const gate = newGate();
  gate.evaluate(activeCtx, read);
  const esc = gate.evaluate(activeCtx, bigPayment);
  gate.resolveEscalation(esc.id, "deny", activeCtx);
  gate.evaluate({ ...activeCtx, credential: { ...activeCtx.credential, status: "expired" } }, read);
  const result = verifyChain(gate.toChainFile(), gate.keysFile(), { strict: true });
  assert.equal(result.valid, true, JSON.stringify(result.firstFailure));
  assert.equal(result.records.length, 4);
});

test("generic cap rules — escalate over the tier max, allow at it, fail closed on unknown tier", () => {
  const capPolicy: PolicyDoc = {
    id: "pol_caps",
    version: "1.0.0",
    domainAllowlist: ["sec.endpoint"],
    caps: [{ capability: "endpoint.isolate", param: "hostCount", maxByTier: { 2: 10 } }],
  };
  const gate = () => new GateChain({ policy: capPolicy, signer: ed25519Signer(ed.utils.randomPrivateKey(), "k") });
  const isolate = (hostCount: number) => ({ domain: "sec.endpoint", capability: "endpoint.isolate", params: { hostCount } });

  assert.equal(gate().evaluate(activeCtx, isolate(250)).verdict.reason, "TIER_CAP_EXCEEDED");
  assert.equal(gate().evaluate(activeCtx, isolate(10)).verdict.reason, "WITHIN_AUTHORITY");
  // tier 0 has no entry in maxByTier → cap 0 → any positive value escalates
  const t0 = { ...activeCtx, agent: { ...activeCtx.agent, tier: 0 } };
  assert.equal(gate().evaluate(t0, isolate(1)).verdict.reason, "TIER_CAP_EXCEEDED");
  // unrelated capability ignores the rule
  assert.equal(
    gate().evaluate(activeCtx, { domain: "sec.endpoint", capability: "endpoint.scan", params: { hostCount: 9999 } }).verdict.reason,
    "WITHIN_AUTHORITY",
  );
});

test("CAPABILITY_NOT_GRANTED — deny when grants are declared and the capability is missing", () => {
  const p: PolicyDoc = {
    id: "pol_g", version: "1.0.0",
    domainAllowlist: ["gov.contracts"],
    capabilityGrants: { 3: ["contracts.read", "contracts.award"] },
  };
  const gate = new GateChain({ policy: p, signer: ed25519Signer(ed.utils.randomPrivateKey(), "k") });
  const t3 = { ...activeCtx, agent: { ...activeCtx.agent, tier: 3 } };
  assert.equal(gate.evaluate(t3, { domain: "gov.contracts", capability: "contracts.read", params: {} }).verdict.reason, "WITHIN_AUTHORITY");
  assert.equal(gate.evaluate(t3, { domain: "gov.contracts", capability: "contracts.novate", params: {} }).verdict.reason, "CAPABILITY_NOT_GRANTED");
  // tier with no grants entry gets nothing — fail closed
  assert.equal(gate.evaluate(activeCtx, { domain: "gov.contracts", capability: "contracts.read", params: {} }).verdict.reason, "CAPABILITY_NOT_GRANTED");
});

test("PARAM_NOT_ALLOWLISTED — deny a prohibited param value, allow listed ones", () => {
  const p: PolicyDoc = {
    id: "pol_p", version: "1.0.0",
    domainAllowlist: ["lending.decisions"],
    paramAllowlists: [{ capability: "decisions.record", param: "basis", allowed: ["dti", "ltv", "fico"] }],
  };
  const gate = new GateChain({ policy: p, signer: ed25519Signer(ed.utils.randomPrivateKey(), "k") });
  const rec = (basis: string) => ({ domain: "lending.decisions", capability: "decisions.record", params: { basis } });
  assert.equal(gate.evaluate(activeCtx, rec("dti")).verdict.reason, "WITHIN_AUTHORITY");
  assert.equal(gate.evaluate(activeCtx, rec("zip-code")).verdict.reason, "PARAM_NOT_ALLOWLISTED");
});

test("RATE_LIMIT_EXCEEDED — velocity derived from the chain; denies don't count", () => {
  const p: PolicyDoc = {
    id: "pol_r", version: "1.0.0",
    domainAllowlist: ["lending.decisions"],
    paramAllowlists: [{ capability: "decisions.record", param: "basis", allowed: ["dti", "ltv", "fico"] }],
    rateLimits: [{ capability: "decisions.record", maxPerWindow: 3, windowMs: 60_000 }],
  };
  const gate = new GateChain({ policy: p, signer: ed25519Signer(ed.utils.randomPrivateKey(), "k") });
  const rec = (basis: string) => ({ domain: "lending.decisions", capability: "decisions.record", params: { basis } });
  assert.equal(gate.evaluate(activeCtx, rec("dti")).verdict.reason, "WITHIN_AUTHORITY");
  assert.equal(gate.evaluate(activeCtx, rec("zip-code")).verdict.reason, "PARAM_NOT_ALLOWLISTED"); // deny — must not count
  assert.equal(gate.evaluate(activeCtx, rec("ltv")).verdict.reason, "WITHIN_AUTHORITY");
  assert.equal(gate.evaluate(activeCtx, rec("fico")).verdict.reason, "WITHIN_AUTHORITY");
  assert.equal(gate.evaluate(activeCtx, rec("dti")).verdict.reason, "RATE_LIMIT_EXCEEDED"); // 4th allow attempt in window
});

test("quorum — non-final approval stays escalate/HUMAN_APPROVED, final flips to allow, closed throws", () => {
  const p: PolicyDoc = {
    id: "pol_q", version: "1.0.0",
    domainAllowlist: ["gov.contracts"],
    caps: [{ capability: "contracts.award", param: "amountUsd", maxByTier: { 2: 250_000 } }],
    quorums: [{ capability: "contracts.award", approvalsRequired: 2 }],
  };
  const gate = new GateChain({ policy: p, signer: ed25519Signer(ed.utils.randomPrivateKey(), "k") });
  const esc = gate.evaluate(activeCtx, { domain: "gov.contracts", capability: "contracts.award", params: { amountUsd: 1_800_000 } });
  assert.equal(esc.verdict.decision, "escalate");

  const first = gate.resolveEscalation(esc.id, "approve", activeCtx);
  assert.equal(first.verdict.decision, "escalate"); // 1 of 2 — still pending
  assert.equal(first.verdict.reason, "HUMAN_APPROVED");
  assert.equal(first.verdict.linksTo, esc.id);

  const second = gate.resolveEscalation(esc.id, "approve", activeCtx);
  assert.equal(second.verdict.decision, "allow"); // 2 of 2 — quorate
  assert.equal(second.verdict.reason, "HUMAN_APPROVED");

  assert.throws(() => gate.resolveEscalation(esc.id, "approve", activeCtx), /already closed/);
  const result = verifyChain(gate.toChainFile(), gate.keysFile(), { strict: true });
  assert.equal(result.valid, true, JSON.stringify(result.firstFailure));
});

test("quorum — a denial closes the escalation immediately", () => {
  const p: PolicyDoc = {
    id: "pol_q2", version: "1.0.0",
    domainAllowlist: ["gov.contracts"],
    caps: [{ capability: "contracts.award", param: "amountUsd", maxByTier: { 2: 250_000 } }],
    quorums: [{ capability: "contracts.award", approvalsRequired: 2 }],
  };
  const gate = new GateChain({ policy: p, signer: ed25519Signer(ed.utils.randomPrivateKey(), "k") });
  const esc = gate.evaluate(activeCtx, { domain: "gov.contracts", capability: "contracts.award", params: { amountUsd: 1_800_000 } });
  gate.resolveEscalation(esc.id, "approve", activeCtx); // 1 of 2
  const denial = gate.resolveEscalation(esc.id, "deny", activeCtx);
  assert.equal(denial.verdict.decision, "deny");
  assert.throws(() => gate.resolveEscalation(esc.id, "approve", activeCtx), /already closed/);
});

/* ── approval-conflict (0.5.0): approval is not authority ───────────────── */

const ceilingPolicy: PolicyDoc = {
  id: "pol_ceiling",
  version: "1.0.0",
  domainAllowlist: ["gov.contracts"],
  caps: [{ capability: "contracts.award", param: "amountUsd", maxByTier: { 2: 250_000 } }],
  quorums: [{ capability: "contracts.award", approvalsRequired: 2, ceilingParam: "amountUsd", ceilingMax: 1_000_000 }],
};
const awardParams = { solicitation: "W91-TEST", amountUsd: 1_800_000 };
const award = { domain: "gov.contracts", capability: "contracts.award", params: awardParams };

test("approval ceiling — quorate approval still denies above the ceiling, as a linked triple", () => {
  const gate = new GateChain({ policy: ceilingPolicy, signer: ed25519Signer(ed.utils.randomPrivateKey(), "k") });
  const esc = gate.evaluate(activeCtx, award);
  assert.equal(esc.verdict.reason, "TIER_CAP_EXCEEDED");

  const vote1 = gate.resolveEscalation(esc.id, "approve", activeCtx, { params: awardParams });
  assert.equal(vote1.verdict.decision, "escalate"); // 1 of 2

  const final = gate.resolveEscalation(esc.id, "approve", activeCtx, { params: awardParams });
  assert.equal(final.verdict.decision, "deny");
  assert.equal(final.verdict.reason, "APPROVAL_CEILING_EXCEEDED");
  assert.equal(final.verdict.linksTo, esc.id);

  // the chain carries BOTH the second signed vote and the denial
  const linked = gate.records.filter((r) => r.verdict.linksTo === esc.id);
  assert.equal(linked.length, 3); // vote1, vote2, ceiling-deny
  assert.equal(linked[1].verdict.reason, "HUMAN_APPROVED");
  assert.throws(() => gate.resolveEscalation(esc.id, "approve", activeCtx, { params: awardParams }), /already closed/);
  assert.equal(verifyChain(gate.toChainFile(), gate.keysFile(), { strict: true }).valid, true);
});

test("approval ceiling — approvals at or under the ceiling still allow", () => {
  const okParams = { solicitation: "W91-TEST", amountUsd: 900_000 };
  const gate = new GateChain({ policy: ceilingPolicy, signer: ed25519Signer(ed.utils.randomPrivateKey(), "k") });
  const esc = gate.evaluate(activeCtx, { ...award, params: okParams });
  gate.resolveEscalation(esc.id, "approve", activeCtx, { params: okParams });
  const final = gate.resolveEscalation(esc.id, "approve", activeCtx, { params: okParams });
  assert.equal(final.verdict.decision, "allow");
  assert.equal(final.verdict.reason, "HUMAN_APPROVED");
});

test("approval ceiling — params are hash-verified; missing or forged params throw", () => {
  const gate = new GateChain({ policy: ceilingPolicy, signer: ed25519Signer(ed.utils.randomPrivateKey(), "k") });
  const esc = gate.evaluate(activeCtx, award);
  gate.resolveEscalation(esc.id, "approve", activeCtx, { params: awardParams });
  assert.throws(() => gate.resolveEscalation(esc.id, "approve", activeCtx), /needs the escalated action's raw params/);
  assert.throws(
    () => gate.resolveEscalation(esc.id, "approve", activeCtx, { params: { ...awardParams, amountUsd: 900_000 } }),
    /do not match the escalated action's paramsHash/,
  );
});

test("conditions changed — credential expired while the human decided: vote recorded, then denied", () => {
  const gate = newGate(); // plain policy, quorum 1 default
  const esc = gate.evaluate(activeCtx, bigPayment);
  const lapsed = { ...activeCtx, credential: { ...activeCtx.credential, status: "expired" as const } };
  const final = gate.resolveEscalation(esc.id, "approve", lapsed);
  assert.equal(final.verdict.decision, "deny");
  assert.equal(final.verdict.reason, "CREDENTIAL_EXPIRED");
  const linked = gate.records.filter((r) => r.verdict.linksTo === esc.id);
  assert.equal(linked.length, 2); // the signed approval vote + the denial
  assert.equal(linked[0].verdict.reason, "HUMAN_APPROVED");
  assert.equal(linked[0].verdict.decision, "escalate");
  assert.equal(verifyChain(gate.toChainFile(), gate.keysFile(), { strict: true }).valid, true);
});

/* ── degradation (0.4.0) ────────────────────────────────────────────────── */

const DEG: PolicyDoc["degradation"] = {
  window: 12,
  strikeWeights: { read: 1, write: 2, execute: 3 },
  classify: [
    { suffix: ".read", class: "read" },
    { suffix: ".write", class: "write" },
    { suffix: ".execute", class: "execute" },
  ],
  levels: [
    { minScore: 0, name: "NOMINAL", tierDelta: 0 },
    { minScore: 2, name: "WATCH", tierDelta: -1 },
    { minScore: 4, name: "RESTRICTED", tierDelta: -2, forceEscalate: ["execute"] },
    { minScore: 6, name: "PROBATION", tierDelta: -2, forceEscalate: ["write"], breakerFor: ["execute"] },
    { minScore: 8, name: "BREAKER", tierDelta: -2, breakerFor: ["write", "execute"] },
  ],
  earnBack: { decayPerAllow: 1, halvedAfterLevel: "PROBATION" },
};

const degPolicy: PolicyDoc = {
  id: "pol_deg",
  version: "1.0.0",
  domainAllowlist: ["ops.ledger"],
  caps: [{ capability: "ops.execute", param: "amountUsd", maxByTier: { 2: 10_000, 1: 2_500, 0: 0 } }],
  degradation: DEG,
};

const degGate = () => new GateChain({ policy: degPolicy, signer: ed25519Signer(ed.utils.randomPrivateKey(), "k") });
const readReq = { domain: "ops.ledger", capability: "ops.read", params: {} };
const offDomainWrite = { domain: "not.allowed", capability: "ops.write", params: {} };

test("degradation — strikes accrue by class and demote the effective tier stamped in records", () => {
  const gate = degGate();
  assert.equal(gate.evaluate(activeCtx, readReq).agent.tier, 2); // NOMINAL
  gate.evaluate(activeCtx, offDomainWrite); // deny, +2 → WATCH
  const r = gate.evaluate(activeCtx, readReq);
  assert.equal(r.agent.tier, 1); // effective tier stamped, not base
  assert.equal(gate.degradationState(2)!.level.name, "NOMINAL"); // the allow decayed 2→1
});

test("degradation — forced escalation at RESTRICTED for execute-class under any amount", () => {
  const gate = degGate();
  gate.evaluate(activeCtx, offDomainWrite); // +2
  gate.evaluate(activeCtx, offDomainWrite); // +2 → score 4 RESTRICTED
  const r = gate.evaluate(activeCtx, { domain: "ops.ledger", capability: "ops.execute", params: { amountUsd: 5 } });
  assert.equal(r.verdict.decision, "escalate");
  assert.equal(r.verdict.reason, "TIER_CAP_EXCEEDED");
  assert.equal(r.agent.tier, 0); // tier 2 − 2
});

test("degradation — breaker denies CIRCUIT_BREAKER_OPEN before other policy; reads still pass", () => {
  const gate = degGate();
  for (let i = 0; i < 4; i++) gate.evaluate(activeCtx, offDomainWrite); // +8 → BREAKER
  assert.equal(gate.degradationState(2)!.level.name, "BREAKER");
  const w = gate.evaluate(activeCtx, offDomainWrite); // write-class → breaker beats domain check
  assert.equal(w.verdict.reason, "CIRCUIT_BREAKER_OPEN");
  const r = gate.evaluate(activeCtx, readReq);
  assert.equal(r.verdict.decision, "allow"); // read-class exempt
});

test("degradation — breaker denials accrue nothing; earn-back is halved after touching PROBATION", () => {
  const gate = degGate();
  for (let i = 0; i < 4; i++) gate.evaluate(activeCtx, offDomainWrite); // score 8, touched PROBATION+
  gate.evaluate(activeCtx, offDomainWrite); // CIRCUIT_BREAKER_OPEN — must NOT add strikes
  assert.equal(gate.degradationState(2)!.score, 8);
  gate.evaluate(activeCtx, readReq); // allow: halved decay 0.5 → 7.5
  const s = gate.degradationState(2)!;
  assert.equal(s.score, 7.5);
  assert.equal(s.earnBackHalved, true);
  assert.equal(s.level.name, "PROBATION"); // recovered below 8
});

test("degradation — chains under degradation verify strictly end-to-end", () => {
  const gate = degGate();
  gate.evaluate(activeCtx, offDomainWrite);
  gate.evaluate(activeCtx, offDomainWrite);
  const esc = gate.evaluate(activeCtx, { domain: "ops.ledger", capability: "ops.execute", params: { amountUsd: 5 } });
  gate.resolveEscalation(esc.id, "deny", activeCtx);
  gate.evaluate(activeCtx, readReq);
  const result = verifyChain(gate.toChainFile(), gate.keysFile(), { strict: true });
  assert.equal(result.valid, true, JSON.stringify(result.firstFailure));
});

test("resume continues an existing chain with intact links and verification", () => {
  const signer = ed25519Signer(ed.utils.randomPrivateKey(), "test-kid");
  const first = new GateChain({ policy, signer });
  first.evaluate(activeCtx, read);
  const esc = first.evaluate(activeCtx, bigPayment);

  const second = new GateChain({ policy, signer, resume: [...first.records] });
  second.resolveEscalation(esc.id, "deny", activeCtx); // escalation found in resumed records
  second.evaluate(activeCtx, read);

  const result = verifyChain(second.toChainFile(), second.keysFile(), { strict: true });
  assert.equal(result.valid, true, JSON.stringify(result.firstFailure));
  assert.equal(second.records.length, 4);
});

test("every verdict is single-digit-fast (deterministic-gate claim, generous bound)", () => {
  const gate = newGate();
  for (let i = 0; i < 20; i++) gate.evaluate(activeCtx, read);
  assert.ok(Math.max(...gate.records.map((r) => r.verdict.latencyMs)) < 50);
});
