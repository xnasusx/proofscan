import type { HandlerInventory } from './inventory.js';
import type { Reasoner, ReasonerUsage } from './reasoner.js';
import type { RubricVerdict } from './rubric.js';
import { SYSTEM_PROMPT, VERDICT_SCHEMA, buildUserPrompt } from './rubric.js';

/**
 * Anthropic API backend.
 *
 * Guardrails, per the build spec's requirement that the reasoning agent be
 * scoped rather than trusted:
 *
 *  - No tools are exposed. This layer answers one question about text it was
 *    handed; it cannot read files, run commands, or reach the network. The
 *    sandbox is driven by our own code in src/verify/, never by the model.
 *  - No credentials from the target ever enter a prompt. What is sent is the
 *    handler source and the extracted operation list, nothing else.
 *  - The answer is schema-constrained, so a verdict is a typed record rather
 *    than prose to be parsed hopefully.
 *  - A flag is a *candidate*. Promotion to verified-exploitable happens only
 *    after an exploit runs in the sandbox and demonstrates impact.
 *
 * The SDK is an optional peer dependency: proofscan does not require an API key
 * to run, so `@anthropic-ai/sdk` is imported dynamically and its absence is
 * reported as an unavailable reasoner rather than crashing the scan.
 */

const MODEL = 'claude-opus-5';

/**
 * Anthropic's recommended fallback, applied server-side if a safety classifier
 * declines the request.
 *
 * This is not boilerplate for a security tool. Classifiers target cyber content,
 * and a prompt containing a real authorisation vulnerability plus a request to
 * describe how to exploit it sits close to that boundary. A refusal returns
 * HTTP 200 with `stop_reason: "refusal"` and empty content — so without this,
 * the layer would silently produce nothing on exactly the handlers that matter
 * most. `"default"` routes by refusal category rather than pinning a model we
 * would later have to migrate.
 */
const FALLBACK_BETA = 'server-side-fallback-2026-07-01';

interface AnthropicLike {
  beta: {
    messages: {
      create(body: Record<string, unknown>): Promise<AnthropicResponse>;
    };
  };
  messages: {
    create(body: Record<string, unknown>): Promise<AnthropicResponse>;
  };
}

interface AnthropicResponse {
  stop_reason?: string | null;
  stop_details?: { category?: string | null; explanation?: string | null } | null;
  model?: string;
  content?: Array<{ type: string; text?: string }>;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
    cache_read_input_tokens?: number;
  };
}

export class ReasonerUnavailableError extends Error {}
export class ReasonerRefusedError extends Error {
  constructor(
    message: string,
    readonly category: string | null,
  ) {
    super(message);
  }
}

let cachedClient: AnthropicLike | null = null;
let cachedLoadError: string | null = null;

async function loadClient(): Promise<AnthropicLike> {
  if (cachedClient) return cachedClient;
  if (cachedLoadError) throw new ReasonerUnavailableError(cachedLoadError);

  let module: { default: new (options?: Record<string, unknown>) => AnthropicLike };
  try {
    // Not a static import: the package is an optional peer dependency and the
    // scan must run without it. The specifier is held in a variable so the
    // TypeScript compiler does not try to resolve it at build time — it may not
    // be installed in the build environment at all.
    const specifier = '@anthropic-ai/sdk';
    module = (await import(specifier)) as never;
  } catch {
    cachedLoadError =
      '@anthropic-ai/sdk is not installed. Install it with `npm install @anthropic-ai/sdk` to enable the ' +
      'AI reasoning backend, or run with --reasoner heuristic.';
    throw new ReasonerUnavailableError(cachedLoadError);
  }

  // The SDK resolves ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, or an `ant auth
  // login` profile on its own — an unset API key does not mean no credentials,
  // so the constructor is left to do the resolution.
  cachedClient = new module.default();
  return cachedClient;
}

function extractJson(response: AnthropicResponse): string {
  const text = (response.content ?? [])
    .filter((block) => block.type === 'text' && typeof block.text === 'string')
    .map((block) => block.text!)
    .join('');
  return text.trim();
}

function validateVerdict(parsed: unknown): RubricVerdict {
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('model returned a non-object verdict');
  }
  const record = parsed as Record<string, unknown>;

  const booleanField = (key: string): boolean => {
    if (typeof record[key] !== 'boolean') throw new Error(`verdict field \`${key}\` is not a boolean`);
    return record[key] as boolean;
  };
  const stringField = (key: string): string => {
    if (typeof record[key] !== 'string') throw new Error(`verdict field \`${key}\` is not a string`);
    return record[key] as string;
  };

  const confidence = stringField('confidence');
  if (!['high', 'medium', 'low'].includes(confidence)) {
    throw new Error(`verdict field \`confidence\` is not one of high|medium|low (got "${confidence}")`);
  }

  return {
    ownership_check_precedes_mutation: booleanField('ownership_check_precedes_mutation'),
    scoped_to_same_resource_identifier: booleanField('scoped_to_same_resource_identifier'),
    flagged: booleanField('flagged'),
    confidence: confidence as RubricVerdict['confidence'],
    explanation: stringField('explanation'),
    exploit_outline: stringField('exploit_outline'),
    observable_impact: stringField('observable_impact'),
  };
}

export const anthropicReasoner: Reasoner = {
  name: 'anthropic',
  description: `${MODEL} answering the scoped rubric with a schema-constrained response; no tools exposed`,

  async available() {
    try {
      await loadClient();
    } catch (err) {
      return { ok: false, detail: (err as Error).message };
    }
    return { ok: true, detail: null };
  },

  async judge(candidate: HandlerInventory) {
    const started = Date.now();
    const client = await loadClient();

    const body: Record<string, unknown> = {
      model: MODEL,
      max_tokens: 4096,
      // The system prompt is byte-identical for every candidate in the run, so
      // caching it turns handler 2..N into cache reads. The volatile part (this
      // handler's source) is in the user turn, after the breakpoint.
      system: [{ type: 'text', text: SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } }],
      messages: [{ role: 'user', content: buildUserPrompt(candidate) }],
      // Constrain the answer to the rubric schema rather than parsing prose.
      output_config: { format: { type: 'json_schema', schema: VERDICT_SCHEMA }, effort: 'high' },
    };

    let response: AnthropicResponse;
    try {
      response = await client.beta.messages.create({
        ...body,
        betas: [FALLBACK_BETA],
        fallbacks: 'default',
      });
    } catch (err) {
      // Server-side fallbacks are beta and may not be enabled for every
      // account. Losing the whole layer over an unavailable convenience would
      // be the wrong trade, so degrade to a plain request and note it.
      const message = (err as Error).message ?? '';
      if (/fallback|beta/i.test(message)) {
        response = await client.messages.create(body);
      } else {
        throw err;
      }
    }

    // Check stop_reason before touching content: on a refusal the content array
    // is empty (pre-output) or partial (mid-stream), and indexing it blindly is
    // the classic way this breaks.
    if (response.stop_reason === 'refusal') {
      throw new ReasonerRefusedError(
        `the model declined to assess ${candidate.method.toUpperCase()} ${candidate.path}` +
          (response.stop_details?.category ? ` (category: ${response.stop_details.category})` : '') +
          '. The handler is still reported as a static candidate; it was not assessed by the reasoning layer.',
        response.stop_details?.category ?? null,
      );
    }

    const raw = extractJson(response);
    if (!raw) throw new Error('model returned no text content');

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`model response was not valid JSON: ${raw.slice(0, 200)}`);
    }

    const usage: ReasonerUsage = {
      input_tokens: response.usage?.input_tokens ?? null,
      output_tokens: response.usage?.output_tokens ?? null,
      cache_read_input_tokens: response.usage?.cache_read_input_tokens ?? null,
      model: response.model ?? MODEL,
      duration_ms: Date.now() - started,
    };

    return { verdict: validateVerdict(parsed), usage };
  },
};
