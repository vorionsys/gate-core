/**
 * @vorionsys/gate-core — src/gate.ts
 * Minimal deterministic BASIS gate pipeline — the embeddable core that emits
 * canonical decision records. (The full layered Gate v1 runtime is
 * @vorionsys/basis-gate-runtime; convergence tracked on vorionsys/basis-gate.)
 *
 * Pipeline order (fail-closed by construction):
 *   1. credential check   → deny CREDENTIAL_EXPIRED / CREDENTIAL_REVOKED
 *   2. domain allowlist   → deny DOMAIN_NOT_ALLOWLISTED
 *   3. tier cap check     → escalate TIER_CAP_EXCEEDED
 *   4. otherwise          → allow WITHIN_AUTHORITY
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

export interface PolicyDoc {
  id: string;
  version: string; // semver
  domainAllowlist: readonly string[];
  /** Per-tier caps. Only payments cap needed for demo v0; extend later. */
  tierCaps: Record<number, { paymentUsdMax: number }>;
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
    // 3. tier cap (payments)
    else if (
      req.capability === "payments.execute" &&
      typeof req.params.amountUsd === "number" &&
      req.params.amountUsd > (this.policy.tierCaps[ctx.agent.tier]?.paymentUsdMax ?? 0)
    ) {
      decision = "escalate"; reason = "TIER_CAP_EXCEEDED";
    }
    // 4. within authority
    else {
      decision = "allow"; reason = "WITHIN_AUTHORITY";
    }

    return this.append(ctx, req, { decision, reason, linksTo: null }, nowIso, t0);
  }

  /** Human resolution of a prior escalation (see header comment). */
  resolveEscalation(escalationId: string, resolution: "approve" | "deny", ctx: GateContext): DecisionRecord {
    const t0 = performance.now();
    const esc = this.chain.find((r) => r.id === escalationId);
    if (!esc) throw new Error(`no escalation record ${escalationId} in chain`);
    if (esc.verdict.decision !== "escalate") throw new Error(`record ${escalationId} is not an escalation`);

    const verdict = resolution === "approve"
      ? { decision: "allow" as const, reason: "HUMAN_APPROVED" as const, linksTo: esc.id }
      : { decision: "deny" as const, reason: "HUMAN_DENIED" as const, linksTo: esc.id };

    // action is a copy of the escalated action; paramsHash carried verbatim.
    return this.appendRaw(ctx, { ...esc.action }, verdict, this.now().toISOString(), t0);
  }

  /* ── internals ── */

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
