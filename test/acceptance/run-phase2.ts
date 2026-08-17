/**
 * Phase 2 acceptance check.
 *
 * The spec's Phase 2 criterion: the same scan additionally surfaces the
 * notes-deletion ordering bug as `verified-exploitable`, with the auto-generated
 * repro attached as evidence.
 *
 * This runs the full static + ai-reasoning pipeline (with sandboxed
 * verification) against the FlaudeCode fixture and asserts:
 *   1. The authorisation-ordering defect in DELETE /api/tasks/:id is flagged.
 *   2. It is verified-exploitable — a repro ran and demonstrated impact.
 *   3. The evidence records a victim-side state change (not just a status code).
 *   4. No finding is verified-exploitable without an accompanying repro.
 *
 *   npm run acceptance:phase2
 *   npm run acceptance:phase2 -- --path <existing clone>
 *   npm run acceptance:phase2 -- --reasoner anthropic   (uses the model backend)
 *
 * Requires Node on PATH and the ability to `npm install` the target (the
 * verification sandbox stands up a real instance). If a sandbox cannot be
 * provisioned, the check reports that honestly rather than passing vacuously.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../dist/core/scan.js';
import { adHocTarget } from '../../dist/config/targets.js';
import type { ReasonerChoice } from '../../dist/analyzers/reasoning/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const RULES_DIR = resolve(HERE, '..', '..', 'rules', 'semgrep');
const FIXTURE_REPO = 'https://github.com/DevAriwala2712/FlaudeCode.git';
const RULE_ID = 'proofscan.authorization-ordering';

function flag(name: string, fallback: string): string {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1]! : fallback;
}

function resolveFixture(): string {
  const provided = flag('--path', '');
  if (provided) {
    const abs = resolve(provided);
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
  const reasoner = flag('--reasoner', 'heuristic') as ReasonerChoice;

  const report = await runScan({
    target: adHocTarget(fixture),
    layers: ['static', 'ai-reasoning'],
    rulesDir: RULES_DIR,
    onlyScanners: [],
    timeoutMs: 300_000,
    kevCatalogPath: null,
    authorizedFlag: false,
    storeRoot: null,
    reasoner,
    verify: true,
  });

  process.stdout.write(`\nScanned ${fixture} (reasoner: ${reasoner})\n\n`);

  const ordering = report.findings.filter((f) => f.rule_id === RULE_ID);
  const verified = ordering.filter((f) => f.status === 'verified-exploitable');
  const run = report.verification_runs.find((v) => verified.some((f) => f.id === v.finding_id));

  let failures = 0;
  const check = (ok: boolean, label: string, detail = ''): void => {
    process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `\n        ${detail}` : ''}\n`);
    if (!ok) failures++;
  };

  check(ordering.length >= 1, 'authorisation-ordering defect flagged in DELETE /api/tasks/:id',
    ordering.map((f) => f.endpoint ?? '').join(', '));
  check(verified.length >= 1, 'the ordering defect is verified-exploitable (a repro ran and demonstrated impact)');

  const evidence = run?.evidence as { narrative?: string; state_assertion?: { changed?: boolean } } | undefined;
  check(!!run, 'a verification_run is attached as evidence');
  check(evidence?.state_assertion?.changed === true,
    'evidence records a victim-side state change (not merely the attacker response code)',
    evidence?.narrative ?? '');

  // The core integrity guarantee: nothing is verified-exploitable without a repro.
  const verifiedWithoutRepro = report.findings.filter(
    (f) => f.status === 'verified-exploitable' && !report.verification_runs.some((v) => v.finding_id === f.id),
  );
  check(verifiedWithoutRepro.length === 0, 'no finding is verified-exploitable without an accompanying repro');

  const sandboxNote = report.notes.find((n) => n.toLowerCase().includes('could not provision'));
  if (sandboxNote && verified.length === 0) {
    process.stdout.write(
      `\nNote: the verification sandbox could not be provisioned in this environment:\n  ${sandboxNote}\n` +
        `This is an environment limitation (Node/npm availability), not a pipeline failure — the finding was ` +
        `flagged and correctly left unverified rather than silently promoted.\n`,
    );
  }

  process.stdout.write(`\nPhase 2 acceptance: ${failures === 0 ? 'PASS' : `FAIL (${failures})`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err: unknown) => {
  process.stderr.write(`phase 2 acceptance failed: ${(err as Error).stack ?? String(err)}\n`);
  process.exit(2);
});
