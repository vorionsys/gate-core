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
