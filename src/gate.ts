/**
 * @vorionsys/gate-core — src/gate.ts
 * Minimal deterministic BASIS gate pipeline — the embeddable core that emits
 * canonical decision records. (The full layered Gate v1 runtime is
 * @vorionsys/basis-gate-runtime; convergence tracked on vorionsys/basis-gate.)
 *
 * Pipeline order (fail-closed by construction — all denies precede escalate):
 *   1. credential check     → deny CREDENTIAL_EXPIRED / CREDENTIAL_REVOKED
 *   2. domain allowlist     → deny DOMAIN_NOT_ALLOWLISTED
 *   3. capability grants    → deny CAPABILITY_NOT_GRANTED
 *   4. param allowlists     → deny PARAM_NOT_ALLOWLISTED
 *   5. rate limits (chain-derived) → deny RATE_LIMIT_EXCEEDED
 *   6. proof-of-verification → deny VERIFICATION_REQUIRED (attestations rot)
 *   7. tier cap check       → escalate TIER_CAP_EXCEEDED (quorum-aware resolution)
 *   8. otherwise            → allow WITHIN_AUTHORITY
 *
 * No model, no randomness, no I/O in the decision path. Signing uses
 * @noble/ed25519; canonicalization + hashing are IMPORTED FROM @vorionsys/verify
 * so the signer and the verifier can never drift.
 *
 * Escalation resolutions: resolveEscalation() emits a record whose `action` is a
 * copy of the escalated action (the human verdict is ABOUT that action) with
 * verdict.linksTo = the escalation record's id. This is why scenario.ts s3b has
 * action: null at the UI level but the chain still satisfies the schema.
 */
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 } from "@noble/hashes/sha256";
import { canonicalBytes, hashRecord } from "@vorionsys/verify";
import {
  toSignable,
  type ChainFile,
  type DecisionRecord,
  type ReasonCode,
} from "@vorionsys/contracts/basis";
import { classifyCapability, effectiveState, type DegradationPolicy, type DegradationState } from "./degradation.js";

ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

/* ── policy + inputs ────────────────────────────────────────────────────── */

/** Generic numeric tier cap: escalate when `params[param]` exceeds the agent
 *  tier's max. A tier absent from maxByTier caps at 0 — fail closed. */
export interface CapRule {
  capability: string;
  param: string;
  maxByTier: Record<number, number>;
}

/** Deny when a string param's value is not in the allowed set. */
export interface ParamAllowlist {
  capability: string;
  param: string;
  allowed: readonly string[];
}

/** Deny when more than maxPerWindow ALLOWED records of this capability already
 *  exist in the chain within the trailing window. Velocity state is derived
 *  from the proof chain itself — no counters, no store. */
export interface RateLimit {
  capability: string;
  maxPerWindow: number;
  windowMs: number;
}

/** Escalations of this capability need N human approvals to close. Non-final
 *  approvals are recorded as { decision: "escalate", reason: "HUMAN_APPROVED" }
 *  — signed, linked, and visibly still pending. Any denial closes it.
 *
 *  ceilingParam/ceilingMax (0.5+): human approval grants permission WITHIN
 *  policy, never beyond it. If the escalated action's param exceeds the
 *  ceiling, a quorate approval still ends in APPROVAL_CEILING_EXCEEDED —
 *  the chain records the signed vote AND the denial. */
export interface QuorumRule {
  capability: string;
  approvalsRequired: number;
  ceilingParam?: string;
  ceilingMax?: number;
}

export interface PolicyDoc {
  id: string;
  version: string; // semver
  domainAllowlist: readonly string[];
  /** Legacy payments-only cap (v0.1.x). Still enforced when present. */
  tierCaps?: Record<number, { paymentUsdMax: number }>;
  /** Generic per-capability numeric caps (v0.2+). */
  caps?: readonly CapRule[];
  /** Per-tier capability grants (v0.3+). When present, a capability missing
   *  from the agent tier's list denies CAPABILITY_NOT_GRANTED — fail closed. */
  capabilityGrants?: Record<number, readonly string[]>;
  /** Param-value allowlists (v0.3+) → deny PARAM_NOT_ALLOWLISTED. */
  paramAllowlists?: readonly ParamAllowlist[];
  /** Chain-derived velocity caps (v0.3+) → deny RATE_LIMIT_EXCEEDED. */
  rateLimits?: readonly RateLimit[];
  /** Multi-approval escalations (v0.3+). */
  quorums?: readonly QuorumRule[];
  /** Multi-level aggressive graceful degradation (v0.4+) — see degradation.ts.
   *  When present, records are stamped with the EFFECTIVE tier at decision time. */
  degradation?: DegradationPolicy;
  /** Proof-of-Verification (v0.6+): a gated capability denies
   *  VERIFICATION_REQUIRED unless the chain carries a fresh ALLOWED record of
   *  requiresCapability (the attestation) — human-validated when required.
   *  Freshness is count-based (withinRecords) so attestations rot and replays
   *  stay time-independent. Pair with capabilityGrants so the working
   *  principal can never attest its own work. */
  verificationGates?: readonly VerificationGate[];
}

export interface VerificationGate {
  capability: string;
  requiresCapability: string;
  /** Trailing-record freshness window; omitted = the whole chain. */
  withinRecords?: number;
  /** The attestation must have closed through a human approval
   *  (reason HUMAN_APPROVED), not a plain allow. */
  humanValidated?: boolean;
}

export interface GateContext {
  agent: { id: string; tier: number };
  credential: { id: string; status: "active" | "expired" | "revoked" | "none"; expiresAt: string | null };
}

export interface ActionRequest {
  domain: string;
  capability: string;
  params: Record<string, unknown>;
}

export interface Signer {
  kid: string;
  publicKeyBase64: string;
  sign(bytes: Uint8Array): Uint8Array;
}

export function ed25519Signer(privateKey: Uint8Array, kid: string): Signer {
  const publicKey = ed.getPublicKey(privateKey);
  const toB64 = (b: Uint8Array) =>
    typeof Buffer !== "undefined" ? Buffer.from(b).toString("base64") : btoa(String.fromCharCode(...b));
  return {
    kid,
    publicKeyBase64: toB64(publicKey),
    sign: (bytes) => ed.sign(bytes, privateKey),
  };
}

/* ── tiny ULID (Crockford base32, time + randomness) — no dependency ────── */

const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function ulid(now: number, rng: () => number): string {
  let t = now, time = "";
  for (let i = 0; i < 10; i++) { time = B32[t % 32] + time; t = Math.floor(t / 32); }
  let rand = "";
  for (let i = 0; i < 16; i++) rand += B32[Math.floor(rng() * 32)];
  return time + rand;
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const sha256Ref = (v: unknown) => "sha256:" + hex(sha256(canonicalBytes(v)));

/* ── the gate ───────────────────────────────────────────────────────────── */

export class GateChain {
  private readonly policy: PolicyDoc;
  private readonly policyHash: string;
  private readonly signer: Signer;
  private readonly now: () => Date;
  private readonly rng: () => number;
  private readonly chain: DecisionRecord[] = [];
  private prevHash = "GENESIS";

  constructor(opts: {
    policy: PolicyDoc;
    signer: Signer;
    now?: () => Date;
    rng?: () => number;
    /** Continue an existing chain (stateless servers: the client's chain IS the
     *  session). TRUSTS the caller — run @vorionsys/verify's verifyChain first
     *  whenever the records crossed a trust boundary. */
    resume?: readonly DecisionRecord[];
  }) {
    this.policy = opts.policy;
    this.policyHash = sha256Ref(opts.policy); // hash of the exact doc evaluated
    this.signer = opts.signer;
    this.now = opts.now ?? (() => new Date());
    this.rng = opts.rng ?? Math.random;
    if (opts.resume?.length) {
      this.chain.push(...opts.resume);
      this.prevHash = hashRecord(this.chain[this.chain.length - 1]);
    }
  }

  get records(): readonly DecisionRecord[] { return this.chain; }
  toChainFile(): ChainFile { return { basisVerify: "1", records: [...this.chain] }; }
  keysFile(): Record<string, string> { return { [this.signer.kid]: this.signer.publicKeyBase64 }; }

  /** Degradation state derived from the current chain (null without a policy). */
  degradationState(baseTier: number): DegradationState | null {
    return this.policy.degradation ? effectiveState(this.chain, this.policy.degradation, baseTier) : null;
  }

  /** Evaluate one action. Deterministic; returns the signed, appended record.
   *  Under a degradation policy, the record is stamped with the EFFECTIVE tier. */
  evaluate(ctx: GateContext, req: ActionRequest): DecisionRecord {
    const t0 = performance.now();
    const nowIso = this.now().toISOString();

    const state = this.degradationState(ctx.agent.tier);
    const tier = state ? state.effectiveTier : ctx.agent.tier;
    const capClass = this.policy.degradation ? classifyCapability(this.policy.degradation, req.capability) : null;

    let decision: "allow" | "deny" | "escalate";
    let reason: ReasonCode;

    // 1. fail-closed credential check
    const cred = ctx.credential;
    const expired =
      cred.status === "expired" ||
      cred.status === "none" ||
      (cred.expiresAt !== null && cred.expiresAt <= nowIso);
    if (cred.status === "revoked") {
      decision = "deny"; reason = "CREDENTIAL_REVOKED";
    } else if (expired) {
      decision = "deny"; reason = "CREDENTIAL_EXPIRED";
    }
    // 2. circuit breaker — a tripped agent is denied before any other policy runs
    else if (state && capClass && state.level.breakerFor?.includes(capClass)) {
      decision = "deny"; reason = "CIRCUIT_BREAKER_OPEN";
    }
    // 3. domain allowlist
    else if (!this.policy.domainAllowlist.includes(req.domain)) {
      decision = "deny"; reason = "DOMAIN_NOT_ALLOWLISTED";
    }
    // 4. per-tier capability grants (at the EFFECTIVE tier)
    else if (this.policy.capabilityGrants && !(this.policy.capabilityGrants[tier] ?? []).includes(req.capability)) {
      decision = "deny"; reason = "CAPABILITY_NOT_GRANTED";
    }
    // 5. param-value allowlists
    else if (this.violatesParamAllowlist(req)) {
      decision = "deny"; reason = "PARAM_NOT_ALLOWLISTED";
    }
    // 6. proof-of-verification — no agent has final say on its own work
    else if (this.missingVerification(req)) {
      decision = "deny"; reason = "VERIFICATION_REQUIRED";
    }
    // 7. chain-derived velocity caps
    else if (this.exceedsRateLimit(req, nowIso)) {
      decision = "deny"; reason = "RATE_LIMIT_EXCEEDED";
    }
    // 8. degradation-forced escalation — at this level the class needs a human
    else if (state && capClass && state.level.forceEscalate?.includes(capClass)) {
      decision = "escalate"; reason = "TIER_CAP_EXCEEDED";
    }
    // 9. tier caps at the effective tier — legacy payments field, then generic rules
    else if (this.exceedsTierCap(tier, req)) {
      decision = "escalate"; reason = "TIER_CAP_EXCEEDED";
    }
    // 10. within authority
    else {
      decision = "allow"; reason = "WITHIN_AUTHORITY";
    }

    const stamped: GateContext = state ? { ...ctx, agent: { ...ctx.agent, tier } } : ctx;
    return this.append(stamped, req, { decision, reason, linksTo: null }, nowIso, t0);
  }

  /** Human resolution of a prior escalation (see header comment).
   *
   *  Quorum semantics: when the policy declares a quorum for the escalated
   *  capability, an approval that has not yet reached approvalsRequired is
   *  recorded as { decision: "escalate", reason: "HUMAN_APPROVED" } — a signed
   *  approval vote that leaves the escalation visibly pending. The final
   *  approval flips to allow. Any denial closes the escalation immediately.
   *  An escalation is CLOSED once a linked record with decision allow or deny
   *  exists; resolving a closed escalation throws. */
  resolveEscalation(
    escalationId: string,
    resolution: "approve" | "deny",
    ctx: GateContext,
    opts: {
      /** Raw params of the escalated action — REQUIRED when the capability's
       *  quorum rule declares a ceiling. Verified against the escalation's
       *  paramsHash before use: the gate will not apply a ceiling to numbers
       *  that are not provably the escalated ones. */
      params?: Record<string, unknown>;
    } = {},
  ): DecisionRecord {
    const t0 = performance.now();
    const esc = this.chain.find((r) => r.id === escalationId);
    if (!esc) throw new Error(`no escalation record ${escalationId} in chain`);
    if (esc.verdict.decision !== "escalate") throw new Error(`record ${escalationId} is not an escalation`);
    const linked = this.chain.filter((r) => r.verdict.linksTo === esc.id);
    if (linked.some((r) => r.verdict.decision !== "escalate")) {
      throw new Error(`escalation ${escalationId} is already closed`);
    }

    const state = this.degradationState(ctx.agent.tier);
    const stamped: GateContext = state ? { ...ctx, agent: { ...ctx.agent, tier: state.effectiveTier } } : ctx;
    const nowIso = this.now().toISOString();

    if (resolution === "deny") {
      return this.appendRaw(stamped, { ...esc.action }, { decision: "deny", reason: "HUMAN_DENIED", linksTo: esc.id }, nowIso, t0);
    }

    const rule = this.policy.quorums?.find((q) => q.capability === esc.action.capability);
    const required = rule?.approvalsRequired ?? 1;
    const priorApprovals = linked.filter((r) => r.verdict.reason === "HUMAN_APPROVED").length;

    if (priorApprovals + 1 < required) {
      // non-final vote — signed, linked, visibly still pending
      return this.appendRaw(stamped, { ...esc.action }, { decision: "escalate", reason: "HUMAN_APPROVED", linksTo: esc.id }, nowIso, t0);
    }

    // Final approval: the gate re-checks at RESOLUTION time. Approval is not
    // authority — a hard constraint still denies, and the chain records both
    // the signed vote and the denial (a linked triple with the escalation).
    const conflict = this.resolutionConflict(esc, ctx, rule, opts.params, nowIso);
    if (conflict) {
      this.appendRaw(stamped, { ...esc.action }, { decision: "escalate", reason: "HUMAN_APPROVED", linksTo: esc.id }, nowIso, t0);
      const t1 = performance.now();
      return this.appendRaw(stamped, { ...esc.action }, { decision: "deny", reason: conflict, linksTo: esc.id }, this.now().toISOString(), t1);
    }

    return this.appendRaw(stamped, { ...esc.action }, { decision: "allow", reason: "HUMAN_APPROVED", linksTo: esc.id }, nowIso, t0);
  }

  /** Hard constraints that outrank human approval, checked when the final
   *  approval lands (conditions may have changed while the human decided). */
  private resolutionConflict(
    esc: DecisionRecord,
    ctx: GateContext,
    rule: QuorumRule | undefined,
    params: Record<string, unknown> | undefined,
    nowIso: string,
  ): ReasonCode | null {
    // 1. credential state at resolution time
    const cred = ctx.credential;
    if (cred.status === "revoked") return "CREDENTIAL_REVOKED";
    if (cred.status === "expired" || cred.status === "none" || (cred.expiresAt !== null && cred.expiresAt <= nowIso)) {
      return "CREDENTIAL_EXPIRED";
    }
    // 2. circuit breaker at resolution time
    const state = this.degradationState(ctx.agent.tier);
    if (state && this.policy.degradation) {
      const capClass = classifyCapability(this.policy.degradation, esc.action.capability);
      if (state.level.breakerFor?.includes(capClass)) return "CIRCUIT_BREAKER_OPEN";
    }
    // 3. approval ceiling — verified against the escalation's paramsHash
    if (rule?.ceilingParam !== undefined && rule.ceilingMax !== undefined) {
      if (!params) throw new Error("this capability's quorum rule has a ceiling — resolveEscalation needs the escalated action's raw params");
      if (sha256Ref(params) !== esc.action.paramsHash) {
        throw new Error("provided params do not match the escalated action's paramsHash");
      }
      const v = params[rule.ceilingParam];
      if (typeof v === "number" && v > rule.ceilingMax) return "APPROVAL_CEILING_EXCEEDED";
    }
    return null;
  }

  /* ── internals ── */

  /** True when a verification gate for this capability lacks a fresh, valid
   *  attestation in the chain. The attestation is itself a chain record —
   *  evidence-committed via its paramsHash, and (when humanValidated) closed
   *  through the escalation machinery as allow/HUMAN_APPROVED. */
  private missingVerification(req: ActionRequest): boolean {
    for (const rule of this.policy.verificationGates ?? []) {
      if (rule.capability !== req.capability) continue;
      const window = rule.withinRecords && rule.withinRecords > 0 ? this.chain.slice(-rule.withinRecords) : this.chain;
      const attested = window.some(
        (r) =>
          r.action.capability === rule.requiresCapability &&
          r.verdict.decision === "allow" &&
          (!rule.humanValidated || r.verdict.reason === "HUMAN_APPROVED"),
      );
      if (!attested) return true;
    }
    return false;
  }

  private violatesParamAllowlist(req: ActionRequest): boolean {
    for (const rule of this.policy.paramAllowlists ?? []) {
      if (rule.capability !== req.capability) continue;
      const value = req.params[rule.param];
      if (typeof value === "string" && !rule.allowed.includes(value)) return true;
    }
    return false;
  }

  /** Velocity derived from the chain: count ALLOWED records of this capability
   *  inside the trailing window. No counters, no store — the proof IS the state. */
  private exceedsRateLimit(req: ActionRequest, nowIso: string): boolean {
    const nowMs = Date.parse(nowIso);
    for (const rule of this.policy.rateLimits ?? []) {
      if (rule.capability !== req.capability) continue;
      const recent = this.chain.filter(
        (r) =>
          r.action.capability === rule.capability &&
          r.verdict.decision === "allow" &&
          nowMs - Date.parse(r.ts) <= rule.windowMs,
      ).length;
      if (recent >= rule.maxPerWindow) return true;
    }
    return false;
  }

  private exceedsTierCap(tier: number, req: ActionRequest): boolean {
    const legacy = this.policy.tierCaps;
    if (
      legacy &&
      req.capability === "payments.execute" &&
      typeof req.params.amountUsd === "number" &&
      req.params.amountUsd > (legacy[tier]?.paymentUsdMax ?? 0)
    ) {
      return true;
    }
    for (const rule of this.policy.caps ?? []) {
      if (rule.capability !== req.capability) continue;
      const value = req.params[rule.param];
      if (typeof value === "number" && value > (rule.maxByTier[tier] ?? 0)) return true;
    }
    return false;
  }

  private append(
    ctx: GateContext,
    req: ActionRequest,
    v: { decision: "allow" | "deny" | "escalate"; reason: ReasonCode; linksTo: string | null },
    tsIso: string,
    t0: number,
  ): DecisionRecord {
    return this.appendRaw(
      ctx,
      { domain: req.domain, capability: req.capability, paramsHash: sha256Ref(req.params) },
      v,
      tsIso,
      t0,
    );
  }

  private appendRaw(
    ctx: GateContext,
    action: DecisionRecord["action"],
    v: { decision: "allow" | "deny" | "escalate"; reason: ReasonCode; linksTo: string | null },
    tsIso: string,
    t0: number,
  ): DecisionRecord {
    const unsigned = {
      v: "1" as const,
      id: ulid(Date.parse(tsIso), this.rng),
      ts: tsIso,
      agent: {
        id: ctx.agent.id,
        tier: ctx.agent.tier,
        credential: {
          id: ctx.credential.id,
          status: ctx.credential.status,
          expiresAt: ctx.credential.status === "none" ? null : ctx.credential.expiresAt,
        },
      },
      action,
      policy: { id: this.policy.id, version: this.policy.version, hash: this.policyHash },
      verdict: { ...v, latencyMs: Math.max(0, Math.round(performance.now() - t0)) },
      prev: this.prevHash,
    };

    const sigBytes = this.signer.sign(canonicalBytes(unsigned));
    const toB64 = (b: Uint8Array) =>
      typeof Buffer !== "undefined" ? Buffer.from(b).toString("base64") : btoa(String.fromCharCode(...b));

    const record: DecisionRecord = {
      ...unsigned,
      sig: { alg: "ed25519", kid: this.signer.kid, value: toB64(sigBytes) },
    };
    // sanity: signable form must round-trip identically
    void toSignable(record);

    this.chain.push(record);
    this.prevHash = hashRecord(record);
    return record;
  }
}
