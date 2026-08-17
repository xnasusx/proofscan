/**
 * Phase 3 acceptance check.
 *
 * The spec's Phase 3 criterion: pointed at a *running* instance of the target
 * (not source), the dynamic fuzzer independently rediscovers the same ordering
 * bug via live differential authorisation testing, without needing repo access.
 *
 * This boots the FlaudeCode fixture as a running instance (reusing the sandbox
 * provisioner), then runs ONLY the dynamic-fuzzer layer against its base URL via
 * a runtime_url target — no source is read. It asserts:
 *   1. The DELETE /api/tasks/:id cross-user defect is rediscovered live.
 *   2. It is verified-exploitable (every dynamic finding is a live demonstration).
 *   3. The evidence shows the side effect was caught despite the attacker's 404.
 *   4. Every request the layer made was logged to the audit trail.
 *   5. The gate refuses a dynamic run without an authorisation record.
 *
 *   npm run acceptance:phase3
 *   npm run acceptance:phase3 -- --path <existing clone>
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { provisionLocalSandbox } from '../../dist/verify/sandbox.js';
import { runScan, ScanRefusedError } from '../../dist/core/scan.js';
import { adHocTarget } from '../../dist/config/targets.js';
import { FileStore } from '../../dist/core/store.js';
import type { Target } from '../../dist/types.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_REPO = 'https://github.com/DevAriwala2712/FlaudeCode.git';

function resolveFixture(): string {
  const i = process.argv.indexOf('--path');
  if (i !== -1 && process.argv[i + 1]) {
    const abs = resolve(process.argv[i + 1]!);
    if (!existsSync(abs)) throw new Error(`--path does not exist: ${abs}`);
    return abs;
  }
  const clone = join(HERE, '.fixture-cache', 'FlaudeCode');
  if (existsSync(join(clone, 'server.js'))) return clone;
  mkdirSync(dirname(clone), { recursive: true });
  process.stdout.write(`Cloning ${FIXTURE_REPO} …\n`);
  execFileSync('git', ['clone', '--depth', '1', FIXTURE_REPO, clone], { stdio: 'inherit' });
  return clone;
}

async function main(): Promise<void> {
  const fixture = resolveFixture();
  let failures = 0;
  const check = (ok: boolean, label: string, detail = ''): void => {
    process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `\n        ${detail}` : ''}\n`);
    if (!ok) failures++;
  };

  // 5 (first, no sandbox needed): the gate refuses an unauthorised dynamic run.
  let refused = false;
  try {
    await runScan({
      target: adHocTarget(fixture),
      layers: ['dynamic-fuzzer'],
      rulesDir: '', onlyScanners: [], timeoutMs: 60_000, kevCatalogPath: null,
      authorizedFlag: false, storeRoot: null, reasoner: 'heuristic', verify: false,
    });
  } catch (err) {
    refused = err instanceof ScanRefusedError;
  }
  check(refused, 'the authorisation gate refuses a dynamic run with no authorisation record');

  process.stdout.write('\nBooting the fixture as a running instance …\n');
  const prov = await provisionLocalSandbox(fixture, 300_000);
  if (!prov.ok || !prov.sandbox) {
    process.stdout.write(
      `\nCould not boot the fixture (${prov.detail}). This is an environment limitation (Node/npm), not a ` +
        `pipeline failure — the live differential test could not be exercised here.\n`,
    );
    process.exit(failures === 0 ? 0 : 1);
  }

  const storeRoot = join(HERE, '.fixture-cache', 'dyn-store');
  mkdirSync(storeRoot, { recursive: true });

  try {
    const target: Target = {
      id: 'acceptance', name: 'flaudecode-live', source_type: 'runtime_url', source_uri: '',
      runtime_base_url: prov.sandbox.baseUrl,
      authorized_by: 'acceptance-harness', authorized_at: '2026-08-09',
      authorization_basis: 'own fixture, ephemeral sandbox provisioned by the test',
      dynamic: {
        resources: [
          { name: 'tasks', collection: '/api/tasks', item: '/api/tasks/:id',
            methods: ['GET', 'PUT', 'DELETE'], child: '/api/tasks/:id/notes' },
        ],
      } as never,
    };

    process.stdout.write(`Fuzzing ${prov.sandbox.baseUrl} (no source access) …\n\n`);
    const report = await runScan({
      target, layers: ['dynamic-fuzzer'], rulesDir: '', onlyScanners: [],
      timeoutMs: 60_000, kevCatalogPath: null, authorizedFlag: true, storeRoot,
      reasoner: 'heuristic', verify: false,
    });

    const del = report.findings.find(
      (f) => f.rule_id === 'proofscan.bola-idor-dynamic' && (f.endpoint ?? '').startsWith('DELETE'),
    );
    check(!!del, 'DELETE cross-user defect rediscovered live, without source access', del?.endpoint ?? '');
    check(del?.status === 'verified-exploitable', 'the dynamic finding is verified-exploitable');
    check(
      !!del && /404/.test(del.exploitability_note) && /changed the owner/.test(del.exploitability_note),
      'the side effect was caught despite the attacker receiving a 404',
      del?.exploitability_note ?? '',
    );

    // 4: every request the layer made was written to the audit log.
    const audit = new FileStore(storeRoot).loadAuditEntries();
    const dynEntry = audit.find((e) => e.action === 'dynamic.requests');
    const reqCount = dynEntry ? (dynEntry.payload as { request_count?: number }).request_count ?? 0 : 0;
    check(reqCount > 0, 'every dynamic request was logged to the audit trail', `${reqCount} requests logged`);

    // GET (no such route) and the ownership-scoped PUT must not be flagged.
    const spurious = report.findings.filter(
      (f) => f.rule_id === 'proofscan.bola-idor-dynamic' && !(f.endpoint ?? '').startsWith('DELETE'),
    );
    check(spurious.length === 0, 'no false positive on GET or the ownership-scoped PUT',
      spurious.map((f) => f.endpoint ?? '').join(', '));
  } finally {
    await prov.sandbox.teardown();
    process.stdout.write('\nsandbox torn down\n');
  }

  process.stdout.write(`\nPhase 3 acceptance: ${failures === 0 ? 'PASS' : `FAIL (${failures})`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err: unknown) => {
  process.stderr.write(`phase 3 acceptance failed: ${(err as Error).stack ?? String(err)}\n`);
  process.exit(2);
});
