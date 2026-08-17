import type { RuleFinding, Severity } from '../../../types.js';
import { lineText } from '../../../core/walk.js';
import type { ParsedFile } from '../parse.js';
import type { RouteInventory } from '../routes.js';

export const RULE_ID = 'proofscan.missing-input-validation-schema';

/**
 * Mutating routes with no declarative request schema.
 *
 * Applies to POST, PUT and PATCH. DELETE is excluded: it carries no body in
 * normal use, so "no body schema" is not a defect there.
 *
 * Severity is graded rather than flat. On a credential route, absent validation
 * means unbounded and unchecked email/password input reaches hashing and
 * storage, so it is rated medium. Elsewhere it is a robustness and consistency
 * gap and is rated low. Where the handler does hand-rolled presence or coercion
 * checks, the finding says so instead of implying the input is untouched — the
 * absence of a schema is the finding, not the absence of all checking.
 */
export function run(parsed: ParsedFile, inventory: RouteInventory): RuleFinding[] {
  const { source } = parsed;
  const findings: RuleFinding[] = [];

  for (const route of inventory.routes) {
    if (!route.is_mutating || route.has_validation_schema) continue;

    // Nothing to say about a handler we cannot see.
    if (!route.handler_resolvable) continue;

    const isCredentialRoute = route.is_auth_route || route.is_auth_issuance_path;
    const severity: Severity = isCredentialRoute ? 'medium' : 'low';

    const manualNote = route.has_manual_checks
      ? `The handler does perform hand-rolled checks (explicit coercion and/or a 4xx early return), so input is ` +
        `not entirely unchecked. What is missing is a declared schema: type, format, length bounds and rejection ` +
        `of unexpected fields in one place that is enforced consistently and can be reviewed.`
      : `No validation of any kind was found in the handler — neither a schema nor hand-rolled checks.`;

    findings.push({
      rule_id: RULE_ID,
      title: `No request validation schema on ${route.method.toUpperCase()} ${route.path}`,
      description:
        `\`${route.method.toUpperCase()} ${route.path}\` accepts a request body but no validation-library schema ` +
        `(Zod, Joi, Yup, Ajv, express-validator, celebrate or similar) is referenced by the route middleware or ` +
        `the handler. ${manualNote}` +
        (isCredentialRoute
          ? ` This is a credential route, so the unvalidated fields are the email and password themselves: ` +
            `there is no format check on the identifier and no length bound on the secret.`
          : ''),
      file_path: source.relPath,
      line: route.line,
      severity,
      exploitability_note: isCredentialRoute
        ? `Reachable pre-authentication. Directly enables malformed and oversized credential input, and account ` +
          `creation with addresses that were never checked for format. Not a memory-safety or injection issue on ` +
          `its own; rated medium because it removes the input boundary on the one route an anonymous caller can ` +
          `always reach.`
        : `Requires an authenticated session. Consequence is unexpected types or oversized values reaching ` +
          `application logic and storage rather than a direct compromise, which is why this is rated low.`,
      code_excerpt: lineText(source.text, route.line),
      cwe: ['CWE-20'],
    });
  }

  return findings;
}
