import { existsSync, statSync } from 'node:fs';
import type { Finding, FindingStatus } from '../types.js';
import type { SourceFile } from '../core/walk.js';
import { walkSource } from '../core/walk.js';
import { inferPlan, mergeConfig } from '../exploit/infer.js';
import type { DynamicConfigShape } from '../exploit/infer.js';
import { provisionLocalSandbox } from '../verify/sandbox.js';
import { verifyAgainstSandbox } from '../verify/exploit.js';

/**
 * Re-verification (Layer 4): re-run the exact exploit against a fix and require
 * it to fail.
 *
 * This closes the loop the spec asks for — "re-run the pipeline against the fix
 * PR; the original repro must now fail before merge." It reuses the same
 * agnostic engine that produced the finding, pointed at the fixed source: infer
 * the plan from the fix, stand it up in a sandbox, run the differential test,
 * and check each previously verified-exploitable finding's route.
 *
 * A finding flips to `fixed-verified` only when the repro no longer reproduces.
 * If it still reproduces, the fix is incomplete and the finding stays
 * verified-exploitable. If the fix couldn't be exercised (sandbox failed), the
 * finding is `fixed-unverified` — the code changed but the loop couldn't confirm
 * it, which is stated rather than assumed.
 */

export interface ReverifyOutcome {
  finding: Finding;
  previousStatus: FindingStatus;
  newStatus: FindingStatus;
  stillReproduces: boolean | null;
  detail: string;
}

export interface ReverifySummary {
  outcomes: ReverifyOutcome[];
  notes: string[];
  fixed: number;
  stillVulnerable: number;
}

export async function reverifyFindings(
  fixDir: string,
  priorFindings: Finding[],
  options: { timeoutMs: number; dynamicConfig: DynamicConfigShape | null },
): Promise<ReverifySummary> {
  const notes: string[] = [];
  const targets = priorFindings.filter((f) => f.status === 'verified-exploitable' && f.endpoint);

  if (targets.length === 0) {
    return { outcomes: [], notes: ['No verified-exploitable findings to re-verify.'], fixed: 0, stillVulnerable: 0 };
  }

  if (!existsSync(fixDir) || !statSync(fixDir).isDirectory()) {
    throw new Error(`--fix path is not an existing directory: ${fixDir}`);
  }

  const files: SourceFile[] = walkSource(fixDir).files;
  const plan = mergeConfig(inferPlan(files), options.dynamicConfig);

  const provision = await provisionLocalSandbox(fixDir, options.timeoutMs);
  if (!provision.ok || !provision.sandbox) {
    notes.push(
      `Could not provision a sandbox for the fix (${provision.detail}); the fix could not be re-verified. ` +
        `Findings are marked fixed-unverified — the code changed but the repro was not re-run.`,
    );
    return {
      outcomes: targets.map((f) => ({
        finding: f,
        previousStatus: f.status,
        newStatus: 'fixed-unverified' as FindingStatus,
        stillReproduces: null,
        detail: 'sandbox unavailable',
      })),
      notes,
      fixed: 0,
      stillVulnerable: 0,
    };
  }

  const sandbox = provision.sandbox;
  let evidenceByRoute: Map<string, { result: string }>;
  try {
    const result = await verifyAgainstSandbox(sandbox, plan);
    if (result.setupError) notes.push(`Re-verification setup issue: ${result.setupError}`);
    evidenceByRoute = result.evidenceByRoute as Map<string, { result: string }>;
  } finally {
    await sandbox.teardown();
  }

  let fixed = 0;
  let stillVulnerable = 0;
  const outcomes: ReverifyOutcome[] = targets.map((finding) => {
    const key = finding.endpoint!; // normalised as `METHOD /path/:id` on both sides
    const evidence = evidenceByRoute.get(key);

    if (!evidence) {
      // The route no longer exists in the fix, or the resource could not be
      // exercised. A vanished route is a plausible fix, but not a proven one.
      return {
        finding,
        previousStatus: finding.status,
        newStatus: 'fixed-unverified',
        stillReproduces: null,
        detail: `no matching route for ${key} in the fix (route removed or not exercised); not confirmed by repro`,
      };
    }

    if (evidence.result === 'verified-exploitable') {
      stillVulnerable++;
      return {
        finding,
        previousStatus: finding.status,
        newStatus: 'verified-exploitable',
        stillReproduces: true,
        detail: `the exploit STILL reproduces against the fix — ${key} remains vulnerable`,
      };
    }

    fixed++;
    return {
      finding,
      previousStatus: finding.status,
      newStatus: 'fixed-verified',
      stillReproduces: false,
      detail: `the exploit no longer reproduces against the fix — ${key} is closed`,
    };
  });

  return { outcomes, notes, fixed, stillVulnerable };
}
