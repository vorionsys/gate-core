/**
 * @vorionsys/gate-core — src/degradation.ts
 * Multi-level aggressive graceful degradation (DESIGN-gauntlet.md §2).
 *
 * The strike score is derived ENTIRELY from the trailing window of the chain —
 * no counters, no store; the proof is the state. Denied records accrue strikes
 * weighted by capability risk class; allowed records decay the score (halved
 * for the rest of the window once the run has touched the configured level —
 * "first failure is data, repeat failure is a pattern"). Escalations accrue
 * nothing: asking permission is the desired behavior. Credential and breaker
 * denials accrue nothing (credential state is its own authority axis; the
 * breaker is already the punishment — no death spirals).
 *
 * This profiles the canonical accumulator / circuit-breaker lane (fast,
 * zero-cooldown, pattern-catching) — NOT the long-horizon trust-score model.
 */
import type { DecisionRecord } from "@vorionsys/contracts/basis";

export type CapabilityClass = "read" | "write" | "execute";

export interface DegradationLevel {
  /** Score at or above which this level applies (levels sorted ascending). */
  minScore: number;
  name: string;
  /** Added to the base tier (negative). Effective tier floors at 0. */
  tierDelta: number;
  /** Capability classes forced to escalate at this level regardless of caps. */
  forceEscalate?: readonly CapabilityClass[];
  /** Capability classes denied outright with CIRCUIT_BREAKER_OPEN. */
  breakerFor?: readonly CapabilityClass[];
}

export interface DegradationPolicy {
  /** Trailing records considered (count-based — replays are time-independent). */
  window: number;
  strikeWeights: Record<CapabilityClass, number>;
  /** Suffix → class map. Unmatched capabilities classify as "execute" — fail closed. */
  classify: readonly { suffix: string; class: CapabilityClass }[];
  levels: readonly DegradationLevel[];
  earnBack: {
    decayPerAllow: number;
    /** Once the window has touched the level with this name, decay halves. */
    halvedAfterLevel: string;
  };
}

export interface DegradationState {
  score: number;
  level: DegradationLevel;
  effectiveTier: number;
  /** True once the halvedAfterLevel has been touched inside the window. */
  earnBackHalved: boolean;
}

export function classifyCapability(policy: DegradationPolicy, capability: string): CapabilityClass {
  for (const rule of policy.classify) {
    if (capability.endsWith(rule.suffix)) return rule.class;
  }
  return "execute"; // unknown = most restricted
}

function levelForScore(policy: DegradationPolicy, score: number): DegradationLevel {
  let current = policy.levels[0];
  for (const level of policy.levels) {
    if (score >= level.minScore) current = level;
  }
  return current;
}

/** Strikes a record accrues under this policy (0 for allows/escalations). */
function strikesFor(policy: DegradationPolicy, r: DecisionRecord): number {
  if (r.verdict.decision !== "deny") return 0;
  const reason = r.verdict.reason;
  if (reason === "CREDENTIAL_EXPIRED" || reason === "CREDENTIAL_REVOKED" || reason === "CIRCUIT_BREAKER_OPEN") return 0;
  return policy.strikeWeights[classifyCapability(policy, r.action.capability)];
}

/** Pure derivation of the degradation state from the chain — the ONLY
 *  implementation; the gate, the demo server, and the UI gauge all call this. */
export function effectiveState(
  records: readonly DecisionRecord[],
  policy: DegradationPolicy,
  baseTier: number,
): DegradationState {
  const window = policy.window > 0 ? records.slice(-policy.window) : records;
  let score = 0;
  let halved = false;

  for (const r of window) {
    const strikes = strikesFor(policy, r);
    if (strikes > 0) {
      score += strikes;
    } else if (r.verdict.decision === "allow") {
      score = Math.max(0, score - (halved ? policy.earnBack.decayPerAllow / 2 : policy.earnBack.decayPerAllow));
    }
    if (!halved && levelForScore(policy, score).name === policy.earnBack.halvedAfterLevel) halved = true;
    // touching any level ABOVE the halving threshold also halves
    if (!halved) {
      const idx = policy.levels.findIndex((l) => l.name === policy.earnBack.halvedAfterLevel);
      const cur = policy.levels.indexOf(levelForScore(policy, score));
      if (idx !== -1 && cur > idx) halved = true;
    }
  }

  const level = levelForScore(policy, score);
  return {
    score,
    level,
    effectiveTier: Math.max(0, baseTier + level.tierDelta),
    earnBackHalved: halved,
  };
}
