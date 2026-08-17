import type { HandlerInventory } from './inventory.js';
import type { RubricVerdict } from './rubric.js';

/**
 * A reasoner answers the rubric for one candidate handler.
 *
 * Two backends implement it. That is not hedging — it reflects what the
 * verification layer does to a verdict. A reasoner is a *candidate generator*:
 * whatever it says, nothing is reported as real until a generated exploit has
 * run against a sandboxed copy of the target and demonstrated impact. So the
 * pipeline stays meaningful with a cheaper generator, and it stays runnable
 * where there is no API key at all — offline, in CI, in an air-gapped review.
 *
 * Which reasoner produced a verdict is recorded on the finding and in the audit
 * log, because "a model judged this" and "an ordering rule judged this" are
 * different claims and must not be conflated.
 */
export interface Reasoner {
  /** Identifier recorded on findings and in the audit log. */
  name: string;
  /** Human-readable description of what this backend actually does. */
  description: string;
  /** Can it run here? Checked before the layer starts, so failures are reported up front. */
  available(): Promise<{ ok: boolean; detail: string | null }>;
  /** Answer the rubric for one candidate. */
  judge(candidate: HandlerInventory): Promise<{ verdict: RubricVerdict; usage: ReasonerUsage }>;
}

export interface ReasonerUsage {
  /** Null for backends that do not call a model. */
  input_tokens: number | null;
  output_tokens: number | null;
  cache_read_input_tokens: number | null;
  model: string | null;
  duration_ms: number;
}

/**
 * Deterministic backend.
 *
 * Restates the mechanical ordering analysis as a rubric verdict. It calls no
 * model, costs nothing, and returns the same answer every time — which makes it
 * the right generator for CI and for reproducing a run months later.
 *
 * Its ceiling is real and it does not pretend otherwise: it can only see what
 * the inventory extracted, so it reports `medium` confidence and never `high`,
 * and it cannot reason about a check performed in a helper function it did not
 * follow. Where the model backend adds value is exactly there — judging whether
 * an unusual construct amounts to an ownership check. The verification layer is
 * what converts either one's guess into evidence.
 */
export const heuristicReasoner: Reasoner = {
  name: 'heuristic',
  description:
    'deterministic ordering analysis over the extracted operation list; no model call, no network, reproducible',

  async available() {
    return { ok: true, detail: null };
  },

  async judge(candidate: HandlerInventory) {
    const started = Date.now();
    const suspect = candidate.suspect_operation;

    if (!suspect) {
      return {
        verdict: {
          ownership_check_precedes_mutation: true,
          scoped_to_same_resource_identifier: true,
          flagged: false,
          confidence: 'medium' as const,
          explanation: candidate.candidate_reason,
          exploit_outline: '',
          observable_impact: '',
        },
        usage: {
          input_tokens: null,
          output_tokens: null,
          cache_read_input_tokens: null,
          model: null,
          duration_ms: Date.now() - started,
        },
      };
    }

    const priorChecks = candidate.operations.filter(
      (o) => o.kind === 'ownership-check' && o.pos < suspect.pos,
    );
    const table = suspect.table ?? 'the target table';
    const resource = candidate.path.replace(/:(\w+)/, '<id>');

    return {
      verdict: {
        ownership_check_precedes_mutation: priorChecks.length > 0,
        scoped_to_same_resource_identifier: false,
        flagged: true,
        confidence: 'medium' as const,
        explanation:
          `Operation ${suspect.verb} on ${table} at line ${suspect.line} runs with a filter that is not ` +
          `constrained to the authenticated caller, and its identifier comes from request input. ` +
          (priorChecks.length === 0
            ? 'No caller-scoped read executes before it, so nothing has established that the caller owns the resource.'
            : 'A caller-scoped read executes earlier in the handler, but its result does not short-circuit before this operation runs.') +
          ' Determined by deterministic ordering analysis, not by a model.',
        exploit_outline:
          `Authenticate as any user. Call ${candidate.method.toUpperCase()} ${resource} with the identifier of a ` +
          `resource belonging to a different user. The handler reaches the ${suspect.verb} on ${table} before any ` +
          `ownership check can stop it.`,
        observable_impact:
          `Rows in ${table} associated with the victim's resource are ${suspect.verb === 'DELETE' ? 'deleted' : 'modified'}. ` +
          `The attacker's own response status may still indicate failure, so impact must be confirmed by reading ` +
          `state back as the victim rather than by trusting the attacker's response code.`,
      },
      usage: {
        input_tokens: null,
        output_tokens: null,
        cache_read_input_tokens: null,
        model: null,
        duration_ms: Date.now() - started,
      },
    };
  },
};
