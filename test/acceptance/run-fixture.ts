/**
 * Phase 1 acceptance check.
 *
 * Runs a real scan against the FlaudeCode validation fixture named in the build
 * spec and asserts that the findings that phase is supposed to catch are present
 * with the expected severity and location.
 *
 * Separate from the unit suite because it needs the network (to clone) and picks
 * up whichever external scanners happen to be installed. The unit suite covers
 * the same defects hermetically against test/fixtures/repo/.
 *
 *   npm run acceptance
 *   npm run acceptance -- --path <existing clone>
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
// Imports the built output on purpose: the acceptance check should exercise the
// artifact that actually ships, not the sources. Run `npm run build` first
// (`npm run acceptance` does).
import { runScan } from '../../dist/core/scan.js';
import { adHocTarget } from '../../dist/config/targets.js';
import type { Finding, Severity } from '../../dist/types.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const RULES_DIR = resolve(HERE, '..', '..', 'rules', 'semgrep');
const FIXTURE_REPO = 'https://github.com/DevAriwala2712/FlaudeCode.git';

interface Expectation {
  /** The finding number from the build spec's validation fixture list. */
  spec: string;
  label: string;
  rule: string;
  /** Expected locations as `file:line`. */
  locations: string[];
  severity: Severity;
}

/**
 * Severity rationale for each expectation is documented in docs/RULES.md. The
 * two fallback secrets are deliberately rated differently: a token-signing key
 * yields authentication forgery, a third-party API key does not.
 */
const EXPECTATIONS: Expectation[] = [
  {
    spec: '#2a',
    label: 'Hardcoded fallback JWT signing secret',
    rule: 'proofscan.hardcoded-fallback-secret',
    locations: ['server.js:13'],
    severity: 'critical',
  },
  {
    spec: '#2b',
    label: 'Hardcoded fallback third-party API key',
    rule: 'proofscan.hardcoded-fallback-secret',
    locations: ['server.js:14'],
    severity: 'high',
  },
  {
    spec: '#3',
    label: 'Partial secret leak via unauthenticated /api/health',
    rule: 'proofscan.unauthenticated-secret-exposure',
    locations: ['server.js:72'],
    severity: 'medium',
  },
  {
    spec: '#4',
    label: 'CORS reflects any origin with credentials',
    rule: 'proofscan.cors-credentials-reflected-origin',
    locations: ['server.js:18'],
    severity: 'high',
  },
  {
    spec: '#6',
    label: 'No rate limiting on /api/login and /api/register',
    rule: 'proofscan.missing-rate-limit-auth-route',
    locations: ['server.js:76', 'server.js:101'],
    severity: 'medium',
  },
  {
    spec: '#7',
    label: 'Schema drift between server.js and initDb.js',
    rule: 'proofscan.schema-drift',
    locations: ['initDb.js:10', 'initDb.js:17', 'initDb.js:27'],
    severity: 'medium',
  },
  {
    spec: '#8',
    label: 'No input validation on /api/register and /api/login',
    rule: 'proofscan.missing-input-validation-schema',
    locations: ['server.js:76', 'server.js:101'],
    severity: 'medium',
  },
];

/** Findings Phase 1 is NOT expected to catch. Asserted absent, so scope stays honest. */
const OUT_OF_SCOPE = [
  {
    spec: '#1',
    label: 'Notes-deletion authorisation-ordering bug in DELETE /api/tasks/:id',
    why: 'Requires the Layer 2 AI-reasoning pass plus sandboxed exploit verification (Phase 2).',
  },
  {
    spec: '#5',
    label: 'JWT stored in localStorage with no revocation',
    why: 'Not in the Phase 1 rule set defined by the build spec.',
  },
];

function locate(finding: Finding): string {
  return `${finding.file_path}:${finding.line}`;
}

function resolveFixture(): string {
  const pathFlagIndex = process.argv.indexOf('--path');
  if (pathFlagIndex !== -1 && process.argv[pathFlagIndex + 1]) {
    const provided = resolve(process.argv[pathFlagIndex + 1]!);
    if (!existsSync(provided)) throw new Error(`--path does not exist: ${provided}`);
    return provided;
  }

  const cacheDir = join(HERE, '.fixture-cache');
  const clone = join(cacheDir, 'FlaudeCode');
  if (existsSync(join(clone, 'server.js'))) return clone;

  mkdirSync(cacheDir, { recursive: true });
  process.stdout.write(`Cloning ${FIXTURE_REPO} …\n`);
  execFileSync('git', ['clone', '--depth', '1', FIXTURE_REPO, clone], { stdio: 'inherit' });
  return clone;
}

async function main(): Promise<void> {
  const fixture = resolveFixture();

  const report = await runScan({
    target: adHocTarget(fixture),
    layers: ['static'],
    rulesDir: RULES_DIR,
    onlyScanners: [],
    timeoutMs: 300_000,
    kevCatalogPath: null,
    authorizedFlag: false,
    // Do not litter the fixture clone with a store.
    storeRoot: null,
    reasoner: 'heuristic',
    verify: false,
  });

  process.stdout.write(`\nScanned ${fixture}\n`);
  process.stdout.write('Scanners: ');
  process.stdout.write(
    report.scan_run.scanners.map((s) => `${s.name}=${s.status}`).join(', ') + '\n\n',
  );

  let failures = 0;

  for (const expectation of EXPECTATIONS) {
    const matches = report.findings.filter((f) => f.rule_id === expectation.rule);
    const found = new Set(matches.map(locate));

    const missing = expectation.locations.filter((l) => !found.has(l));
    const wrongSeverity = matches
      .filter((f) => expectation.locations.includes(locate(f)) && f.severity !== expectation.severity)
      .map((f) => `${locate(f)} is ${f.severity}, expected ${expectation.severity}`);

    const ok = missing.length === 0 && wrongSeverity.length === 0;
    if (!ok) failures++;

    process.stdout.write(
      `${ok ? 'PASS' : 'FAIL'}  ${expectation.spec.padEnd(4)} ${expectation.label}\n` +
        `            rule: ${expectation.rule}\n` +
        `            expected ${expectation.severity} at ${expectation.locations.join(', ')}\n`,
    );
    if (missing.length > 0) process.stdout.write(`            MISSING: ${missing.join(', ')}\n`);
    for (const problem of wrongSeverity) process.stdout.write(`            SEVERITY: ${problem}\n`);
  }

  process.stdout.write('\nOut of scope for Phase 1 (asserted absent):\n');
  for (const item of OUT_OF_SCOPE) {
    // Nothing in Phase 1 may claim these. A finding here would mean the tool is
    // overstating what it verified.
    const claimed = report.findings.some((f) => f.status === 'verified-exploitable');
    process.stdout.write(`  ${item.spec}  ${item.label}\n        ${item.why}\n`);
    if (claimed) {
      process.stdout.write('        FAIL: a finding claims verified-exploitable, which Phase 1 cannot establish\n');
      failures++;
    }
  }

  const unverified = report.findings.every((f) => f.status === 'unverified-flagged');
  process.stdout.write(
    `\n${unverified ? 'PASS' : 'FAIL'}  every finding is status unverified-flagged (Phase 1 proves nothing by execution)\n`,
  );
  if (!unverified) failures++;

  process.stdout.write(`\nTotal findings: ${report.findings.length}\n`);
  process.stdout.write(failures === 0 ? '\nPhase 1 acceptance: PASS\n' : `\nPhase 1 acceptance: FAIL (${failures})\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err: unknown) => {
  process.stderr.write(`acceptance run failed: ${(err as Error).stack ?? String(err)}\n`);
  process.exit(2);
});
