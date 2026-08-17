import type { HandlerInventory, Operation } from './inventory.js';

/**
 * The rubric.
 *
 * One question, asked once per candidate handler. The build spec is deliberate
 * about this: a narrow rubric outperforms an open-ended "find the bugs" prompt,
 * because an open prompt invites the model to invent plausible findings across
 * the whole file while a scoped one gives it a single decidable question about
 * code it has been handed.
 *
 * The question is also the thing the verification layer can test. "Does an
 * ownership check short-circuit before this mutation?" has an observable
 * consequence — another user's data changes — and that is exactly what the
 * sandboxed repro goes and checks.
 */
export const RUBRIC_QUESTION =
  'Does an authorisation/ownership check execute and short-circuit before this mutation runs, ' +
  'scoped to the same resource identifier the mutation touches? If not, flag it and explain what ' +
  'a caller would need to do to exploit it.';

export type Confidence = 'high' | 'medium' | 'low';

export interface RubricVerdict {
  /** Does a check run before the mutation at all? */
  ownership_check_precedes_mutation: boolean;
  /** Is that check scoped to the same resource identifier the mutation touches? */
  scoped_to_same_resource_identifier: boolean;
  /** The answer to the rubric: is this an authorisation defect? */
  flagged: boolean;
  confidence: Confidence;
  /** Why, in terms of the ordered operations. */
  explanation: string;
  /** What a caller would have to do. Empty when not flagged. */
  exploit_outline: string;
  /** What changes in the data if the exploit runs. Empty when not flagged. */
  observable_impact: string;
}

/**
 * JSON Schema for the model's answer.
 *
 * Passed via `output_config.format` so the response is constrained rather than
 * parsed hopefully out of prose. `additionalProperties: false` and a complete
 * `required` list are mandatory for schema enforcement.
 */
export const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    ownership_check_precedes_mutation: {
      type: 'boolean',
      description: 'True if any authorisation or ownership check executes before the mutation.',
    },
    scoped_to_same_resource_identifier: {
      type: 'boolean',
      description:
        'True if that check is scoped to the same resource identifier the mutation acts on. A check on a ' +
        'different resource, or one that does not short-circuit, is false.',
    },
    flagged: {
      type: 'boolean',
      description: 'True if this is an authorisation defect a caller could exploit.',
    },
    confidence: {
      type: 'string',
      enum: ['high', 'medium', 'low'],
      description: 'Confidence in the judgement. Use low when the handler depends on code you cannot see.',
    },
    explanation: {
      type: 'string',
      description: 'One paragraph, referring to the specific operations and their order.',
    },
    exploit_outline: {
      type: 'string',
      description:
        'Concrete steps a caller would take: which endpoint, which identifier, whose resource. Empty string if not flagged.',
    },
    observable_impact: {
      type: 'string',
      description:
        'What changes in stored data if the exploit runs, and how a victim could observe it. Empty string if not flagged.',
    },
  },
  required: [
    'ownership_check_precedes_mutation',
    'scoped_to_same_resource_identifier',
    'flagged',
    'confidence',
    'explanation',
    'exploit_outline',
    'observable_impact',
  ],
  additionalProperties: false,
} as const;

/**
 * System prompt.
 *
 * Held byte-stable across every candidate in a run so it can be cached: it is
 * the same for handler 1 and handler 40, and only the handler-specific content
 * varies. Nothing volatile (no timestamps, no run ids, no file paths) goes in
 * here — that would invalidate the cached prefix on every call.
 */
export const SYSTEM_PROMPT = [
  'You are reviewing one HTTP route handler for a single, specific class of authorisation defect:',
  'a database mutation that runs before the code has confirmed the caller owns the resource being mutated.',
  '',
  'You will be given the handler source and a mechanically extracted list of its database operations in',
  'execution order. Answer only the question asked. Do not report other defect classes, style problems,',
  'or missing validation — other layers cover those, and findings outside the question are noise.',
  '',
  'What counts as a genuine defect:',
  '- A mutation whose WHERE clause (or equivalent filter) is not constrained to the authenticated caller,',
  '  and which no preceding, short-circuiting ownership check protects.',
  '- Order is what matters. A check that runs after the mutation does not prevent the mutation. A check',
  '  whose result is never tested does not prevent it either.',
  '- A response status is not a control. A handler that mutates data and then returns 404 has still',
  '  mutated the data; the status only hides it.',
  '',
  'What does not count:',
  '- A mutation already constrained to the caller in its own filter.',
  '- An INSERT creating a new resource owned by the caller — there is no prior owner to check.',
  '- A mutation on a resource identifier the caller cannot influence.',
  '',
  'Be conservative. A finding here triggers an automated exploit attempt against a sandboxed copy of the',
  'application, and a wrong flag costs a sandbox run and a reviewer\'s attention. If the handler depends on',
  'code you were not shown and that code could plausibly perform the check, say so and set confidence to low.',
].join('\n');

function renderOperation(op: Operation, index: number): string {
  const parts = [`${index + 1}. line ${op.line} — ${op.kind}`];
  if (op.kind === 'mutation') {
    parts.push(
      `verb=${op.verb}`,
      `table=${op.table ?? 'undetermined'}`,
      `constrained_to_caller=${op.ownerScoped ? 'yes' : 'no'}`,
      `driven_by_request_input=${op.requestDriven ? 'yes' : 'no'}`,
      `creates_new_resource=${op.isCreate ? 'yes' : 'no'}`,
    );
  }
  return `${parts.join('  ')}\n     ${op.text}`;
}

/** The per-candidate user message. Everything volatile lives here, never in the system prompt. */
export function buildUserPrompt(candidate: HandlerInventory): string {
  return [
    `Route: ${candidate.method.toUpperCase()} ${candidate.path}`,
    `File: ${candidate.file_path}:${candidate.line}`,
    `Authentication: ${candidate.authenticated ? `present (${candidate.auth_source})` : 'none'}`,
    '',
    'Database operations in execution order:',
    candidate.operations.map(renderOperation).join('\n'),
    '',
    'Static analysis flagged this handler because:',
    candidate.candidate_reason,
    '',
    'Handler source:',
    '```javascript',
    candidate.source,
    '```',
    '',
    RUBRIC_QUESTION,
  ].join('\n');
}
