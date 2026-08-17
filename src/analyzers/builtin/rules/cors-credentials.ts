import ts from 'typescript';
import type { RuleFinding } from '../../../types.js';
import { dottedName, lineOf, propertyName, stringLiteralValue, visit } from '../parse.js';
import type { ParsedFile } from '../parse.js';

export const RULE_ID = 'proofscan.cors-credentials-reflected-origin';

/**
 * CORS configured to reflect an arbitrary origin while also allowing credentials.
 *
 * `origin: true` in the `cors` package does not mean "allow *". It means "echo
 * back whatever Origin the request carried", which combined with
 * `credentials: true` instructs the browser to attach cookies and send the
 * response to any site that asks. `Access-Control-Allow-Origin: *` is actually
 * safer here, because browsers refuse to combine the wildcard with credentials.
 */

interface OriginAssessment {
  reflects: boolean;
  how: string;
}

function assessOrigin(node: ts.Node, sourceFile: ts.SourceFile): OriginAssessment | null {
  if (node.kind === ts.SyntaxKind.TrueKeyword) {
    return { reflects: true, how: '`origin: true`, which echoes the request Origin header back' };
  }

  const literal = stringLiteralValue(node);
  if (literal === '*') {
    // Browsers reject '*' together with credentials, so this is a
    // misconfiguration but not an exploitable one. Reported at lower severity.
    return { reflects: false, how: "`origin: '*'`" };
  }
  if (literal !== null) return null;

  // A callback that answers cb(null, true) unconditionally reflects any origin.
  if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
    const body = node.body.getText(sourceFile);
    const callsBackTrue = /\(\s*(null|undefined)\s*,\s*true\s*\)/.test(body);
    const hasAllowlistCheck = /\b(includes|indexOf|test|has|some|===|==|match)\b/.test(body);
    if (callsBackTrue && !hasAllowlistCheck) {
      return {
        reflects: true,
        how: 'an origin callback that answers `cb(null, true)` for every origin without checking an allowlist',
      };
    }
    return null;
  }

  // `origin: req.headers.origin` and similar.
  const name = dottedName(node);
  if (name && /req(uest)?\.(headers|header|get)/i.test(name)) {
    return { reflects: true, how: `\`origin: ${name}\`, taken straight from the request` };
  }

  return null;
}

export function run(parsed: ParsedFile): RuleFinding[] {
  const { sourceFile, source } = parsed;
  const findings: RuleFinding[] = [];

  visit(sourceFile, (node) => {
    if (!ts.isCallExpression(node)) return;

    const callee = dottedName(node.expression);
    if (!callee || !/(^|\.)cors$/i.test(callee)) return;

    const config = node.arguments[0];
    if (!config || !ts.isObjectLiteralExpression(config)) return;

    let origin: OriginAssessment | null = null;
    let credentials = false;

    for (const prop of config.properties) {
      const key = propertyName(prop);
      if (!key || !ts.isPropertyAssignment(prop)) continue;

      if (key === 'origin') origin = assessOrigin(prop.initializer, sourceFile);
      if (key === 'credentials' && prop.initializer.kind === ts.SyntaxKind.TrueKeyword) {
        credentials = true;
      }
    }

    if (!origin || !credentials) return;

    const line = lineOf(sourceFile, node);

    findings.push({
      rule_id: RULE_ID,
      title: origin.reflects
        ? 'CORS reflects any origin while allowing credentials'
        : 'CORS wildcard origin combined with credentials',
      description: origin.reflects
        ? `CORS is configured with ${origin.how}, together with \`credentials: true\`. Any website a logged-in ` +
          `user visits can then make credentialed cross-origin requests to this API and read the responses, ` +
          `because the browser is told that site is an allowed origin. Replace the reflected origin with an ` +
          `explicit allowlist of the origins the application is actually served from.`
        : `CORS is configured with ${origin.how} together with \`credentials: true\`. Browsers refuse to honour ` +
          `the wildcard when credentials are requested, so credentialed cross-origin calls will fail rather ` +
          `than leak. This is a configuration error to correct, not an exposure.`,
      file_path: source.relPath,
      line,
      severity: origin.reflects ? 'high' : 'low',
      exploitability_note: origin.reflects
        ? `Requires a victim with a live session to visit a page the attacker controls. No credential theft and ` +
          `no network position needed: the attacker's page issues \`fetch(target, {credentials: 'include'})\` ` +
          `and reads the authenticated response. Cookie-based sessions are directly affected; a session held ` +
          `only in localStorage is not reachable this way, so confirm how sessions are carried before rating ` +
          `this in your own environment.`
        : `Not exploitable as written — the browser blocks the combination. Fix to remove the ambiguity.`,
      code_excerpt: node.getText(sourceFile).replace(/\s+/g, ' ').slice(0, 200),
      cwe: ['CWE-942', 'CWE-346'],
    });
  });

  return findings;
}
