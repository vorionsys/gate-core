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

test("every verdict is single-digit-fast (deterministic-gate claim, generous bound)", () => {
  const gate = newGate();
  for (let i = 0; i < 20; i++) gate.evaluate(activeCtx, read);
  assert.ok(Math.max(...gate.records.map((r) => r.verdict.latencyMs)) < 50);
});
