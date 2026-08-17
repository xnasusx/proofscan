import type { RuleFinding } from '../../types.js';
import type { SourceFile } from '../../core/walk.js';
import { JS_LIKE_EXTENSIONS, parseFile } from './parse.js';
import { buildRouteInventory } from './routes.js';
import * as corsCredentials from './rules/cors-credentials.js';
import * as hardcodedFallbackSecret from './rules/hardcoded-fallback-secret.js';
import * as missingInputValidation from './rules/missing-input-validation.js';
import * as missingRateLimit from './rules/missing-rate-limit.js';
import * as schemaDrift from './rules/schema-drift.js';
import * as unauthenticatedSecretExposure from './rules/unauthenticated-secret-exposure.js';

export const BUILTIN_ENGINE = 'builtin';

export const BUILTIN_RULE_IDS = [
  hardcodedFallbackSecret.RULE_ID,
  corsCredentials.RULE_ID,
  missingRateLimit.RULE_ID,
  missingInputValidation.RULE_ID,
  unauthenticatedSecretExposure.RULE_ID,
  schemaDrift.RULE_ID,
] as const;

export interface BuiltinResult {
  findings: RuleFinding[];
  /** Files analysed by the AST rules. */
  filesAnalysed: number;
  /** Files that did not parse cleanly, which may therefore be under-reported. */
  parseFailures: Array<{ relPath: string; errors: number }>;
}

/**
 * Run every built-in rule.
 *
 * The AST rules are JavaScript/TypeScript only. The schema-drift rule is
 * text-based and also covers .sql files. Any other language in the target is not
 * examined by this engine — the caller surfaces that as a coverage note rather
 * than letting a silent zero read as a clean result.
 */
export function runBuiltinRules(files: SourceFile[]): BuiltinResult {
  const findings: RuleFinding[] = [];
  const parseFailures: BuiltinResult['parseFailures'] = [];
  let filesAnalysed = 0;

  for (const file of files) {
    if (!JS_LIKE_EXTENSIONS.has(file.ext)) continue;

    const parsed = parseFile(file);
    filesAnalysed++;

    if (parsed.parseErrorCount > 0) {
      parseFailures.push({ relPath: file.relPath, errors: parsed.parseErrorCount });
    }

    const inventory = buildRouteInventory(parsed);

    findings.push(
      ...hardcodedFallbackSecret.run(parsed),
      ...corsCredentials.run(parsed),
      ...missingRateLimit.run(parsed, inventory),
      ...missingInputValidation.run(parsed, inventory),
      ...unauthenticatedSecretExposure.run(parsed, inventory),
    );
  }

  // Repo-wide: needs every file at once, not one at a time.
  findings.push(...schemaDrift.run(files));

  return { findings, filesAnalysed, parseFailures };
}
