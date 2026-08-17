import type { RuleFinding } from '../../../types.js';
import { lineText } from '../../../core/walk.js';
import type { ParsedFile } from '../parse.js';
import type { RouteInventory } from '../routes.js';

export const RULE_ID = 'proofscan.missing-rate-limit-auth-route';

/**
 * Credential and account-recovery routes with no rate limiting in front of them.
 *
 * Scoped to auth routes on purpose. Every endpoint benefits from a limiter, but
 * flagging all of them produces a wall of low-value findings; absent throttling
 * on a login route is the case where the missing control directly enables an
 * attack (credential stuffing, password spraying, OTP brute force).
 */
export function run(parsed: ParsedFile, inventory: RouteInventory): RuleFinding[] {
  const { source } = parsed;
  const findings: RuleFinding[] = [];

  for (const route of inventory.routes) {
    if (!route.is_auth_route || route.rate_limited) continue;

    // A GET on an auth path is usually rendering a form, not accepting a guess.
    if (route.method === 'get' || route.method === 'head' || route.method === 'options') continue;

    const configuredElsewhere = inventory.importsRateLimitModule;

    findings.push({
      rule_id: RULE_ID,
      title: `No rate limiting on ${route.method.toUpperCase()} ${route.path}`,
      description:
        `\`${route.method.toUpperCase()} ${route.path}\` accepts credentials but no rate-limiting or ` +
        `brute-force middleware applies to it` +
        (configuredElsewhere
          ? `. A rate-limiting package is imported in this file, so a limiter exists but is not applied to this ` +
            `route — check the middleware chain and the mount order.`
          : `, and no rate-limiting package is imported in this file. Middleware registered in another module is ` +
            `not visible to this rule, so confirm against the composed app before treating this as conclusive.`) +
        ` Apply a limiter keyed on both source IP and submitted account identifier; keying on IP alone leaves ` +
        `distributed stuffing unthrottled, and keying on the account alone lets one IP enumerate many accounts.`,
      file_path: source.relPath,
      line: route.line,
      severity: 'medium',
      exploitability_note:
        `No authentication required — this is a pre-auth endpoint by definition. An attacker with a credential ` +
        `list can test it at whatever rate the server sustains. Impact is bounded by password quality rather ` +
        `than by the application, which is the point: the control that should bound it is absent. Rated medium ` +
        `rather than high because success still depends on a weak or reused credential.`,
      code_excerpt: lineText(source.text, route.line),
      cwe: ['CWE-307', 'CWE-799'],
    });
  }

  return findings;
}
