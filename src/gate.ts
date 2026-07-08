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
 *   6. tier cap check       → escalate TIER_CAP_EXCEEDED (quorum-aware resolution)
 *   7. otherwise            → allow WITHIN_AUTHORITY
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
 *  — signed, linked, and visibly still pending. Any denial closes it. */
export interface QuorumRule {
  capability: string;
  approvalsRequired: number;
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

  /** Evaluate one action. Deterministic; returns the signed, appended record. */
  evaluate(ctx: GateContext, req: ActionRequest): DecisionRecord {
    const t0 = performance.now();
    const nowIso = this.now().toISOString();

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
    // 2. domain allowlist
    else if (!this.policy.domainAllowlist.includes(req.domain)) {
      decision = "deny"; reason = "DOMAIN_NOT_ALLOWLISTED";
    }
    // 3. per-tier capability grants (only when the policy declares them)
    else if (this.policy.capabilityGrants && !(this.policy.capabilityGrants[ctx.agent.tier] ?? []).includes(req.capability)) {
      decision = "deny"; reason = "CAPABILITY_NOT_GRANTED";
    }
    // 4. param-value allowlists
    else if (this.violatesParamAllowlist(req)) {
      decision = "deny"; reason = "PARAM_NOT_ALLOWLISTED";
    }
    // 5. chain-derived velocity caps
    else if (this.exceedsRateLimit(req, nowIso)) {
      decision = "deny"; reason = "RATE_LIMIT_EXCEEDED";
    }
    // 6. tier caps — legacy payments field, then generic cap rules
    else if (this.exceedsTierCap(ctx.agent.tier, req)) {
      decision = "escalate"; reason = "TIER_CAP_EXCEEDED";
    }
    // 7. within authority
    else {
      decision = "allow"; reason = "WITHIN_AUTHORITY";
    }

    return this.append(ctx, req, { decision, reason, linksTo: null }, nowIso, t0);
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
  resolveEscalation(escalationId: string, resolution: "approve" | "deny", ctx: GateContext): DecisionRecord {
    const t0 = performance.now();
    const esc = this.chain.find((r) => r.id === escalationId);
    if (!esc) throw new Error(`no escalation record ${escalationId} in chain`);
    if (esc.verdict.decision !== "escalate") throw new Error(`record ${escalationId} is not an escalation`);
    const linked = this.chain.filter((r) => r.verdict.linksTo === esc.id);
    if (linked.some((r) => r.verdict.decision !== "escalate")) {
      throw new Error(`escalation ${escalationId} is already closed`);
    }

    let verdict: { decision: "allow" | "deny" | "escalate"; reason: ReasonCode; linksTo: string };
    if (resolution === "deny") {
      verdict = { decision: "deny", reason: "HUMAN_DENIED", linksTo: esc.id };
    } else {
      const required = this.policy.quorums?.find((q) => q.capability === esc.action.capability)?.approvalsRequired ?? 1;
      const priorApprovals = linked.filter((r) => r.verdict.reason === "HUMAN_APPROVED").length;
      verdict =
        priorApprovals + 1 >= required
          ? { decision: "allow", reason: "HUMAN_APPROVED", linksTo: esc.id }
          : { decision: "escalate", reason: "HUMAN_APPROVED", linksTo: esc.id };
    }

    // action is a copy of the escalated action; paramsHash carried verbatim.
    return this.appendRaw(ctx, { ...esc.action }, verdict, this.now().toISOString(), t0);
  }

  /* ── internals ── */

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
