import ts from 'typescript';
import type { RuleFinding } from '../../../types.js';
import { dottedName, lineOf, stringLiteralValue, visit } from '../parse.js';
import type { ParsedFile } from '../parse.js';

export const RULE_ID = 'proofscan.hardcoded-fallback-secret';

/**
 * `process.env.X || '<literal>'` where the name is secret-shaped.
 *
 * This is a different failure mode from the one Gitleaks and TruffleHog are
 * tuned for. They look for strings that match the shape of a real issued
 * credential (an AWS key id, a Stripe token, high-entropy blobs). A fallback
 * like 'demo-jwt-secret-change-me' has none of those properties and is skipped
 * by entropy and format rules alike — yet it is the value the application
 * actually signs tokens with whenever the environment variable is unset, and it
 * is public. Detecting it needs the pattern, not the value.
 */

const SECRET_NAME_PATTERN =
  /secret|token|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|salt|passphrase|client[_-]?secret|signing|encryption[_-]?key|\bkey\b|_key$|^key_/i;

/**
 * Names whose fallback yields authentication forgery rather than access to one
 * third-party service. A known token-signing key lets an attacker mint a token
 * for any user, so these are rated a step higher.
 */
const AUTH_CRITICAL_NAME_PATTERN =
  /jwt|session|signing|sign[_-]?key|auth|cookie[_-]?secret|refresh[_-]?secret|token[_-]?secret|csrf/i;

/** Literals that are placeholders rather than usable fallbacks. */
const PLACEHOLDER_PATTERN = /^(|undefined|null|none|false|true|0|1|\{\}|\[\]|changeme|xxx+|todo|tbd|\*+)$/i;

function isProcessEnvAccess(node: ts.Node): string | null {
  if (ts.isPropertyAccessExpression(node)) {
    if (dottedName(node.expression) === 'process.env') return node.name.text;
    return null;
  }
  if (ts.isElementAccessExpression(node)) {
    if (dottedName(node.expression) !== 'process.env') return null;
    return node.argumentExpression ? stringLiteralValue(node.argumentExpression) : null;
  }
  return null;
}

/** Nearest enclosing variable / property / parameter name, for naming context. */
function enclosingName(node: ts.Node): string | null {
  let current: ts.Node | undefined = node.parent;
  for (let depth = 0; current && depth < 4; depth++, current = current.parent) {
    if (ts.isVariableDeclaration(current) && ts.isIdentifier(current.name)) return current.name.text;
    if (ts.isPropertyAssignment(current) && ts.isIdentifier(current.name)) return current.name.text;
    if (ts.isPropertyDeclaration(current) && ts.isIdentifier(current.name)) return current.name.text;
    if (ts.isBinaryExpression(current) && current.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const left = dottedName(current.left);
      if (left) return left;
    }
  }
  return null;
}

/** Replace the literal with its length so reports never carry the credential. */
function redact(excerpt: string, literal: string): string {
  const masked = `'<redacted: ${literal.length} chars>'`;
  return excerpt.split(literal).join(masked.slice(1, -1));
}

export function run(parsed: ParsedFile): RuleFinding[] {
  const { sourceFile, source } = parsed;
  const findings: RuleFinding[] = [];

  visit(sourceFile, (node) => {
    if (!ts.isBinaryExpression(node)) return;

    const operator = node.operatorToken.kind;
    if (
      operator !== ts.SyntaxKind.BarBarToken &&
      operator !== ts.SyntaxKind.QuestionQuestionToken
    ) {
      return;
    }

    const envName = isProcessEnvAccess(node.left);
    if (!envName) return;

    const literal = stringLiteralValue(node.right);
    if (literal === null || PLACEHOLDER_PATTERN.test(literal.trim())) return;

    const assignedName = enclosingName(node);
    const candidates = [envName, assignedName ?? ''].join(' ');
    if (!SECRET_NAME_PATTERN.test(candidates)) return;

    const authCritical = AUTH_CRITICAL_NAME_PATTERN.test(candidates);
    const operatorText = operator === ts.SyntaxKind.BarBarToken ? '||' : '??';
    const line = lineOf(sourceFile, node);
    const excerpt = node.getText(sourceFile).replace(/\s+/g, ' ');

    findings.push({
      rule_id: RULE_ID,
      title: `Hardcoded fallback secret for ${envName}`,
      description:
        `\`process.env.${envName} ${operatorText} '<literal>'\` supplies a hardcoded secret whenever ` +
        `${envName} is unset in the environment` +
        (assignedName ? `, assigned to \`${assignedName}\`` : '') +
        `. The literal is committed to the repository, so it is known to anyone who can read the source. ` +
        `Secret scanners tuned for issued-credential formats and high entropy do not flag values like this, ` +
        `which is why it is checked as a pattern rather than by value.`,
      file_path: source.relPath,
      line,
      severity: authCritical ? 'critical' : 'high',
      exploitability_note: authCritical
        ? `Requires the deployment to be missing ${envName}. If it is, the signing key is public: an attacker ` +
          `mints a token for any user id and authenticates as them, with no credential needed. Verify which ` +
          `environments actually set ${envName} before downgrading this.`
        : `Requires the deployment to be missing ${envName}. If it is, every caller shares one publicly known ` +
          `value; impact depends on what that credential authorises.`,
      code_excerpt: redact(excerpt, literal),
      cwe: ['CWE-798', 'CWE-1188'],
    });
  });

  return findings;
}
