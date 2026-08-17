import type { FindingStatus } from '../types.js';
import type { SourceFile } from '../core/walk.js';
import type { ReasoningFinding } from '../analyzers/reasoning/index.js';
import { inferPlan, mergeConfig } from '../exploit/infer.js';
import type { DynamicConfigShape } from '../exploit/infer.js';
import { provisionLocalSandbox } from './sandbox.js';
import { verifyAgainstSandbox } from './exploit.js';
import type { VerificationEvidence } from './types.js';

export interface VerifiedReasoningFinding extends ReasoningFinding {
  /** Verification outcome, or null when verification was not attempted. */
  evidence: VerificationEvidence | null;
  /** Final status after verification. */
  status: FindingStatus;
}

export interface VerificationSummary {
  findings: VerifiedReasoningFinding[];
  notes: string[];
  attempted: number;
  verified: number;
}

export interface VerifyOptions {
  timeoutMs: number;
  enabled: boolean;
  /** Source files, for inferring the exploit plan target-agnostically. */
  files: SourceFile[];
  /** Operator overrides for the inferred plan (the target's `dynamic` block). */
  dynamicConfig: DynamicConfigShape | null;
}

/**
 * Verify flagged reasoning findings against a sandboxed copy of the target.
 *
 * The exploit plan (auth flow, resource shapes, create fields) is inferred from
 * the target's own source and overlaid with any operator config — so this
 * verifies any Express app, not just the one it was first built against. One
 * sandbox is provisioned for the batch, the plan is exercised once, and each
 * flagged finding is matched to the evidence for its route.
 *
 * Status promotion is strict: a finding becomes `verified-exploitable` only when
 * the repro demonstrated a cross-user state change. Every other outcome —
 * sandbox unavailable, setup failure, or a genuine not-exploitable — leaves it
 * `unverified-flagged`, never silently upgraded and never silently dropped.
 */
export async function verifyFindings(
  sourceDir: string,
  reasoningFindings: ReasoningFinding[],
  options: VerifyOptions,
): Promise<VerificationSummary> {
  const notes: string[] = [];
  const flagged = reasoningFindings.filter((f) => f.verdict.flagged && !f.reasoner.includes('refused'));

  const unchanged = (): VerificationSummary => ({
    findings: reasoningFindings.map((f) => ({ ...f, evidence: null, status: f.status })),
    notes,
    attempted: 0,
    verified: 0,
  });

  if (!options.enabled) {
    notes.push('Verification was disabled (--no-verify); all reasoning findings remain unverified-flagged.');
    return unchanged();
  }
  if (flagged.length === 0) return unchanged();

  const provision = await provisionLocalSandbox(sourceDir, options.timeoutMs);
  if (!provision.ok || !provision.sandbox) {
    notes.push(
      `Could not provision a verification sandbox: ${provision.detail}. ${flagged.length} flagged finding(s) ` +
        `remain unverified-flagged — they were not proven exploitable and were not dismissed.`,
    );
    return unchanged();
  }

  const plan = mergeConfig(inferPlan(options.files), options.dynamicConfig);
  const sandbox = provision.sandbox;

  let evidenceByRoute: Map<string, VerificationEvidence>;
  try {
    const result = await verifyAgainstSandbox(sandbox, plan);
    if (result.setupError) {
      notes.push(
        `Verification could not establish test identities against the sandbox (${result.setupError}); ` +
          `${flagged.length} flagged finding(s) remain unverified-flagged.`,
      );
    }
    evidenceByRoute = result.evidenceByRoute;
  } finally {
    await sandbox.teardown();
  }

  let verified = 0;
  const byId = new Map<ReasoningFinding, VerificationEvidence>();
  for (const finding of flagged) {
    const key = `${finding.handler.method.toUpperCase()} ${finding.handler.path}`;
    const evidence = evidenceByRoute.get(key);
    if (!evidence) {
      notes.push(
        `No verification route matched ${key} (the exploit planner did not derive a resource for it); ` +
          `finding remains unverified-flagged.`,
      );
      continue;
    }
    byId.set(finding, evidence);
    if (evidence.result === 'verified-exploitable') verified++;
  }

  const findings: VerifiedReasoningFinding[] = reasoningFindings.map((f) => {
    const evidence = byId.get(f) ?? null;
    const status: FindingStatus =
      evidence?.result === 'verified-exploitable' ? 'verified-exploitable' : f.status;
    return { ...f, evidence, status };
  });

  return { findings, notes, attempted: flagged.length, verified };
}
