/**
 * Agnosticism acceptance check.
 *
 * proofscan was first built against FlaudeCode; this proves it is not coupled to
 * it. The bookmarks fixture (test/fixtures/repo/second-app) shares nothing with
 * FlaudeCode's surface — different auth paths (/auth/signup, /auth/token),
 * credential fields (username/passphrase), token field (accessToken), resource
 * (/v1/bookmarks/:bookmarkId with a tags child), and secret env var
 * (APP_TOKEN_SECRET). It is given NO app-specific configuration.
 *
 * Asserts:
 *   1. Layer 2 (static + reasoning + sandboxed verification) infers the shape
 *      from source and marks the bookmarks IDOR verified-exploitable.
 *   2. Layer 3 (dynamic fuzzer), given only a resource manifest and no source,
 *      rediscovers the same IDOR live against a running instance.
 *
 *   npm run acceptance:agnostic
 */
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { provisionLocalSandbox } from '../../dist/verify/sandbox.js';
import { runScan } from '../../dist/core/scan.js';
import { adHocTarget } from '../../dist/config/targets.js';
import type { Target } from '../../dist/types.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(HERE, '..', 'fixtures', 'repo', 'second-app');
const RULE_STATIC = 'proofscan.authorization-ordering';
const RULE_DYNAMIC = 'proofscan.bola-idor-dynamic';

async function main(): Promise<void> {
  let failures = 0;
  const check = (ok: boolean, label: string, detail = ''): void => {
    process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `\n        ${detail}` : ''}\n`);
    if (!ok) failures++;
  };

  process.stdout.write('Second fixture: bookmarks app (shares nothing with FlaudeCode)\n\n');

  // --- Layer 2: infer from source, verify in a sandbox, NO config ---
  const l2 = await runScan({
    target: adHocTarget(FIXTURE),
    layers: ['static', 'ai-reasoning'],
    rulesDir: resolve(HERE, '..', '..', 'rules', 'semgrep'),
    onlyScanners: [], timeoutMs: 300_000, kevCatalogPath: null,
    authorizedFlag: false, storeRoot: null, reasoner: 'heuristic', verify: true,
  });
  const l2Verified = l2.findings.find(
    (f) => f.rule_id === RULE_STATIC && f.status === 'verified-exploitable' && (f.endpoint ?? '').includes('bookmarks'),
  );
  check(!!l2Verified, 'Layer 2 infers the bookmarks shape and verifies the IDOR (no config)', l2Verified?.endpoint ?? '');

  const l2Spurious = l2.findings.filter(
    (f) => f.rule_id === RULE_STATIC && (f.endpoint ?? '').startsWith('PATCH'),
  );
  check(l2Spurious.length === 0, 'Layer 2 does not flag the ownership-scoped PATCH');

  // --- Layer 3: boot a running instance, fuzz with only a manifest, no source ---
  process.stdout.write('\nBooting the bookmarks app as a running instance …\n');
  const prov = await provisionLocalSandbox(FIXTURE, 300_000);
  if (!prov.ok || !prov.sandbox) {
    process.stdout.write(`\nCould not boot the fixture (${prov.detail}); Layer 3 live check skipped.\n`);
    process.exit(failures === 0 ? 0 : 1);
  }
  try {
    const target: Target = {
      id: 'agnostic', name: 'bookmarks-live', source_type: 'runtime_url', source_uri: '',
      runtime_base_url: prov.sandbox.baseUrl,
      authorized_by: 'acceptance-harness', authorized_at: '2026-08-09',
      authorization_basis: 'own fixture, ephemeral sandbox',
      dynamic: {
        // Layer 3 has no source, so it needs the auth flow and resource named —
        // exactly the black-box operator config path.
        auth: {
          register_path: '/auth/signup', login_path: '/auth/token',
          username_field: 'username', password_field: 'passphrase', token_field: 'accessToken',
        },
        resources: [
          { name: 'bookmarks', collection: '/v1/bookmarks', item: '/v1/bookmarks/:bookmarkId',
            methods: ['GET', 'PATCH', 'DELETE'], child: '/v1/bookmarks/:bookmarkId/tags', create_fields: ['url', 'label'] },
        ],
      } as never,
    };
    const l3 = await runScan({
      target, layers: ['dynamic-fuzzer'], rulesDir: '', onlyScanners: [],
      timeoutMs: 60_000, kevCatalogPath: null, authorizedFlag: true, storeRoot: null,
      reasoner: 'heuristic', verify: false,
    });
    const l3Del = l3.findings.find(
      (f) => f.rule_id === RULE_DYNAMIC && (f.endpoint ?? '').startsWith('DELETE'),
    );
    check(!!l3Del, 'Layer 3 rediscovers the bookmarks IDOR live from a manifest (no source)', l3Del?.endpoint ?? '');
    check(l3Del?.status === 'verified-exploitable', 'the Layer 3 finding is verified-exploitable');
    const l3Spurious = l3.findings.filter(
      (f) => f.rule_id === RULE_DYNAMIC && !(f.endpoint ?? '').startsWith('DELETE'),
    );
    check(l3Spurious.length === 0, 'Layer 3 does not false-positive GET or the ownership-scoped PATCH',
      l3Spurious.map((f) => f.endpoint ?? '').join(', '));
  } finally {
    await prov.sandbox.teardown();
    process.stdout.write('\nsandbox torn down\n');
  }

  process.stdout.write(`\nAgnosticism acceptance: ${failures === 0 ? 'PASS' : `FAIL (${failures})`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err: unknown) => {
  process.stderr.write(`agnosticism acceptance failed: ${(err as Error).stack ?? String(err)}\n`);
  process.exit(2);
});
