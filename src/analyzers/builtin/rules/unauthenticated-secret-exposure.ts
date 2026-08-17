import type { RuleFinding, Severity } from '../../../types.js';
import { lineText } from '../../../core/walk.js';
import type { ParsedFile } from '../parse.js';
import type { RouteInventory } from '../routes.js';

export const RULE_ID = 'proofscan.unauthenticated-secret-exposure';

/**
 * Response field names that suggest credential material.
 *
 * `key` is matched as a substring rather than a whole word on purpose. Field
 * names in the wild are camelCase compounds — `fakeAiKeyPreview`, `apiKeyHint`,
 * `signingKeyId` — and a word-boundary match misses every one of them.
 */
const SECRET_FIELD_PATTERN =
  /secret|token|password|passwd|pwd|apikey|accesskey|privatekey|credential|salt|signature|passphrase|sessionid|key/i;

/** Words that merely contain "key" and mean nothing of the sort. */
const BENIGN_KEY_WORD_PATTERN = /monkey|keyboard|keynote|keyword|donkey|hockey|jockey|whiskey|turkey|keeper|keystone/i;

/**
 * Field names an auth-issuance route is supposed to return.
 *
 * Without this exemption the rule fires on every login and register endpoint
 * that returns a session token — which is the entire purpose of those routes.
 * That would be a false positive on essentially every application, so the
 * exemption is scoped to token-family names on credential-issuing paths only. A
 * login route returning `apiKey` or `dbPassword` is still flagged.
 */
const ISSUED_TOKEN_FIELDS = new Set([
  'token',
  'accesstoken',
  'access_token',
  'refreshtoken',
  'refresh_token',
  'idtoken',
  'id_token',
  'jwt',
  'csrftoken',
  'csrf_token',
  'sessiontoken',
  'session_token',
  'authtoken',
  'auth_token',
]);

export function run(parsed: ParsedFile, inventory: RouteInventory): RuleFinding[] {
  const { source } = parsed;
  const findings: RuleFinding[] = [];

  for (const route of inventory.routes) {
    if (route.authenticated) continue;

    for (const response of route.responses) {
      for (const property of response.properties) {
        if (!SECRET_FIELD_PATTERN.test(property.name)) continue;
        if (BENIGN_KEY_WORD_PATTERN.test(property.name)) continue;

        const normalised = property.name.toLowerCase().replace(/[^a-z_]/g, '');
        if (route.is_auth_issuance_path && ISSUED_TOKEN_FIELDS.has(normalised)) continue;

        // A value narrowed by slice/substring exposes a prefix, not the whole
        // secret. That is a real difference in impact, so it changes severity
        // rather than being ignored or treated as equivalent.
        const severity: Severity = property.truncated ? 'medium' : 'high';

        findings.push({
          rule_id: RULE_ID,
          title: `Unauthenticated ${route.method.toUpperCase()} ${route.path} returns \`${property.name}\``,
          description:
            `\`${route.method.toUpperCase()} ${route.path}\` has no authentication or authorisation middleware ` +
            `and returns a field named \`${property.name}\`, whose name indicates credential material. ` +
            (property.truncated
              ? `The value is truncated before it is sent (\`${property.valueText.replace(/\s+/g, ' ').slice(0, 80)}\`), ` +
                `so what leaves the process is a prefix rather than the whole secret. A prefix still confirms the ` +
                `credential exists, narrows a brute-force search, and identifies which key is deployed — and the ` +
                `truncation length is a code detail that can change without anyone revisiting this endpoint.`
              : `The value appears to be sent in full.`) +
            ` Health and status endpoints should return liveness only; move anything key-derived behind ` +
            `authentication or remove it.`,
          file_path: source.relPath,
          line: property.line,
          severity,
          exploitability_note:
            `No authentication, no session, no user interaction: a single unauthenticated GET returns it. ` +
            (property.truncated
              ? `Rated medium rather than high because the exposed value is a prefix. Confirm what the full value ` +
                `authorises before accepting that rating.`
              : `Rated high: the field appears to be returned in full to any anonymous caller.`),
          code_excerpt: lineText(source.text, property.line),
          cwe: ['CWE-200', 'CWE-215'],
        });
      }
    }
  }

  return findings;
}
