import type { Finding, FindingStatus, RuleFinding } from '../../types.js';
import type { SourceFile } from '../../core/walk.js';
import { JS_LIKE_EXTENSIONS, parseFile } from '../builtin/parse.js';
import { buildMutationInventory } from './inventory.js';
import type { HandlerInventory } from './inventory.js';
import { ReasonerRefusedError, ReasonerUnavailableError, anthropicReasoner } from './anthropic.js';
import { heuristicReasoner } from './reasoner.js';
import type { Reasoner } from './reasoner.js';
import type { RubricVerdict } from './rubric.js';

export const REASONING_RULE_ID = 'proofscan.authorization-ordering';

export type ReasonerChoice = 'heuristic' | 'anthropic';

export interface ReasoningNote {
  message: string;
}

/** What the reasoning layer decided about one candidate, before verification. */
export interface ReasoningFinding {
  ruleFinding: RuleFinding;
  handler: HandlerInventory;
  verdict: RubricVerdict;
  reasoner: string;
  /**
   * Status the finding should carry. The reasoning layer never sets
   * verified-exploitable — only the verification layer can, after a repro. This
   * is unverified-flagged unless/until that happens.
   */
  status: FindingStatus;
}

export interface ReasoningResult {
  findings: ReasoningFinding[];
  /** Candidates the reasoner identified, for reporting even when not flagged. */
  candidatesConsidered: number;
  notes: string[];
  reasonerUsed: string;
  /** Token spend, when a model backend ran. */
  usage: { input_tokens: number; output_tokens: number; cache_read_input_tokens: number } | null;
}

function pickReasoner(choice: ReasonerChoice): Reasoner {
  return choice === 'anthropic' ? anthropicReasoner : heuristicReasoner;
}

function severityForVerdict(verdict: RubricVerdict): Finding['severity'] {
  // A confirmed authorisation bypass on a mutation is high by default; the
  // verification layer can raise nothing higher than the tool already rates it,
  // and only lowers confidence, never invents severity.
  return verdict.confidence === 'low' ? 'medium' : 'high';
}

function buildRuleFinding(candidate: HandlerInventory, verdict: RubricVerdict, reasoner: string): RuleFinding {
  const endpoint = `${candidate.method.toUpperCase()} ${candidate.path}`;
  return {
    rule_id: REASONING_RULE_ID,
    title: `Authorisation-ordering defect in ${endpoint}`,
    description:
      `${verdict.explanation}\n\n` +
      `Exploit outline: ${verdict.exploit_outline}\n` +
      `Expected impact: ${verdict.observable_impact}\n\n` +
      `Assessed by the ${reasoner} reasoner (confidence: ${verdict.confidence}). This is a candidate until an ` +
      `automated exploit has run against a sandboxed copy and demonstrated the impact — see the verification ` +
      `status on this finding.`,
    file_path: candidate.file_path,
    line: candidate.suspect_operation?.line ?? candidate.line,
    severity: severityForVerdict(verdict),
    exploitability_note: verdict.exploit_outline,
    code_excerpt: candidate.suspect_operation?.text ?? null,
    cwe: ['CWE-639', 'CWE-285', 'CWE-863'],
  };
}

/**
 * Run Layer 2 over the target's source.
 *
 * Mechanically inventories mutation handlers, asks the chosen reasoner the
 * scoped rubric for each candidate, and returns flagged findings — all still
 * unverified. Verification is a separate step (src/verify/), invoked by the
 * scan orchestrator, so this function stays pure and testable without a
 * sandbox.
 */
export async function runReasoningLayer(
  files: SourceFile[],
  options: { reasoner: ReasonerChoice },
): Promise<ReasoningResult> {
  const reasoner = pickReasoner(options.reasoner);
  const notes: string[] = [];

  const availability = await reasoner.available();
  if (!availability.ok) {
    // Fall back to the deterministic backend rather than producing nothing.
    notes.push(
      `Reasoner "${reasoner.name}" is unavailable (${availability.detail}); falling back to the heuristic reasoner.`,
    );
    return runReasoningLayer(files, { reasoner: 'heuristic' });
  }

  const candidates: HandlerInventory[] = [];
  for (const file of files) {
    if (!JS_LIKE_EXTENSIONS.has(file.ext)) continue;
    const parsed = parseFile(file);
    for (const handler of buildMutationInventory(parsed)) {
      if (handler.candidate) candidates.push(handler);
    }
  }

  const findings: ReasoningFinding[] = [];
  let inTokens = 0;
  let outTokens = 0;
  let cacheTokens = 0;
  let anyModelUsage = false;

  for (const candidate of candidates) {
    let verdict: RubricVerdict;
    try {
      const result = await reasoner.judge(candidate);
      verdict = result.verdict;
      if (result.usage.input_tokens !== null) {
        anyModelUsage = true;
        inTokens += result.usage.input_tokens;
        outTokens += result.usage.output_tokens ?? 0;
        cacheTokens += result.usage.cache_read_input_tokens ?? 0;
      }
    } catch (err) {
      if (err instanceof ReasonerRefusedError) {
        notes.push(err.message);
        // Preserve the static candidate as a low-confidence finding so a refusal
        // does not silently drop the very handlers most worth looking at.
        findings.push({
          ruleFinding: {
            rule_id: REASONING_RULE_ID,
            title: `Authorisation-ordering candidate in ${candidate.method.toUpperCase()} ${candidate.path} (not assessed)`,
            description:
              `Static analysis flagged this handler: ${candidate.candidate_reason} The reasoning model declined to ` +
              `assess it, so it has not been judged or verified. Review it by hand.`,
            file_path: candidate.file_path,
            line: candidate.suspect_operation?.line ?? candidate.line,
            severity: 'medium',
            exploitability_note: 'Not assessed by the reasoning layer; review manually.',
            code_excerpt: candidate.suspect_operation?.text ?? null,
            cwe: ['CWE-639', 'CWE-285'],
          },
          handler: candidate,
          verdict: {
            ownership_check_precedes_mutation: false,
            scoped_to_same_resource_identifier: false,
            flagged: true,
            confidence: 'low',
            explanation: candidate.candidate_reason,
            exploit_outline: '',
            observable_impact: '',
          },
          reasoner: `${reasoner.name} (refused)`,
          status: 'unverified-flagged',
        });
        continue;
      }
      if (err instanceof ReasonerUnavailableError) {
        notes.push(`Reasoner became unavailable mid-run: ${err.message}`);
        break;
      }
      notes.push(`Reasoner error on ${candidate.method.toUpperCase()} ${candidate.path}: ${(err as Error).message}`);
      continue;
    }

    if (!verdict.flagged) continue;

    findings.push({
      ruleFinding: buildRuleFinding(candidate, verdict, reasoner.name),
      handler: candidate,
      verdict,
      reasoner: reasoner.name,
      status: 'unverified-flagged',
    });
  }

  return {
    findings,
    candidatesConsidered: candidates.length,
    notes,
    reasonerUsed: reasoner.name,
    usage: anyModelUsage
      ? { input_tokens: inTokens, output_tokens: outTokens, cache_read_input_tokens: cacheTokens }
      : null,
  };
}
