import type { HandlerInventory } from '../analyzers/reasoning/inventory.js';
import type { RubricVerdict } from '../analyzers/reasoning/rubric.js';

/**
 * A single HTTP exchange the exploit made, recorded for the evidence trail.
 * Never contains a real credential — the sandbox is seeded with synthetic
 * accounts and an ephemeral signing key.
 */
export interface RequestRecord {
  actor: 'attacker' | 'victim' | 'setup';
  method: string;
  path: string;
  status: number | null;
  /** Response body, truncated. Synthetic data only. */
  responseSummary: string;
}

export type VerificationResult =
  | 'verified-exploitable'
  | 'not-exploitable'
  | 'inconclusive'
  | 'sandbox-unavailable';

export interface VerificationEvidence {
  result: VerificationResult;
  /** Human-readable account of what the repro demonstrated. */
  narrative: string;
  /** Every request the repro made, in order. */
  requests: RequestRecord[];
  /**
   * The before/after state assertion that decides the verdict. Populated when
   * the repro could observe victim state; null when it could not run that far.
   */
  stateAssertion: {
    description: string;
    before: unknown;
    after: unknown;
    changed: boolean;
  } | null;
  /** How the sandbox was provided. */
  sandbox: 'local-process' | 'docker' | 'none';
  /** Reference to the torn-down sandbox instance, for the audit log. */
  sandboxRef: string;
  durationMs: number;
}

export interface VerificationCandidate {
  handler: HandlerInventory;
  verdict: RubricVerdict;
}

/**
 * A sandbox stands up an ephemeral, isolated copy of the target with synthetic
 * multi-tenant seed data, and tears it down afterwards. The exploit runner
 * drives it over HTTP.
 */
export interface Sandbox {
  kind: 'local-process' | 'docker';
  /** Base URL the running instance is reachable at. */
  baseUrl: string;
  /** Opaque instance id, recorded in evidence. */
  ref: string;
  /** Stop the instance and delete its data. Idempotent. */
  teardown(): Promise<void>;
}

export interface SandboxProvisionResult {
  ok: boolean;
  sandbox: Sandbox | null;
  /** Why provisioning failed, when it did. */
  detail: string | null;
}
