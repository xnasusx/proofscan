/**
 * Phase 4 acceptance check — the remediation loop.
 *
 * The spec's Phase 4 criterion: a verified-exploitable finding auto-opens a
 * ticket, a fix PR re-runs the pipeline, and the finding flips to fixed-verified
 * only when the repro fails post-fix.
 *
 * This:
 *   1. Scans FlaudeCode (Layer 2) into a store, producing the verified DELETE IDOR.
 *   2. Generates a remediation ticket + draft PR and asserts they carry the evidence.
 *   3. Re-verifies against the UNFIXED source — asserts the exploit STILL reproduces
 *      (so re-verification isn't just always-passing).
 *   4. Applies the recommended fix to a copy (ownership check before the cascade
 *      delete) and re-verifies — asserts the finding flips to fixed-verified.
 *
 *   npm run acceptance:phase4
 */
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../dist/core/scan.js';
import { adHocTarget } from '../../dist/config/targets.js';
import { FileStore } from '../../dist/core/store.js';
import { buildTicket, draftPullRequest } from '../../dist/remediate/ticket.js';
import { reverifyFindings } from '../../dist/remediate/reverify.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const RULES_DIR = resolve(HERE, '..', '..', 'rules', 'semgrep');
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

/** Apply the recommended fix: an ownership check that short-circuits before the cascade delete. */
function applyFix(dir: string): boolean {
  const serverPath = join(dir, 'server.js');
  const src = readFileSync(serverPath, 'utf8');
  const cascade = "db.prepare('DELETE FROM notes WHERE task_id = ?').run(taskId);";
  if (!src.includes(cascade)) return false;
  const guard =
    "const owned = db.prepare('SELECT id FROM tasks WHERE id = ? AND user_id = ?').get(taskId, req.user.id);\n" +
    "  if (!owned) return res.status(404).json({ message: 'Task not found' });\n  " +
    cascade;
  writeFileSync(serverPath, src.replace(cascade, guard), 'utf8');
  return true;
}

async function main(): Promise<void> {
  const fixture = resolveFixture();
  let failures = 0;
  const check = (ok: boolean, label: string, detail = ''): void => {
    process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `\n        ${detail}` : ''}\n`);
    if (!ok) failures++;
  };

  const work = mkdtempSync(join(tmpdir(), 'proofscan-phase4-'));
  const vulnDir = join(work, 'vuln');
  const fixedDir = join(work, 'fixed');
  cpSync(fixture, vulnDir, { recursive: true, filter: (s) => !/[\\/](node_modules|\.git|\.proofscan)([\\/]|$)/.test(s) });
  cpSync(vulnDir, fixedDir, { recursive: true });

  try {
    // 1. Scan into a store to produce the verified finding.
    process.stdout.write('Scanning (Layer 2) to produce a verified finding …\n');
    await runScan({
      target: adHocTarget(vulnDir),
      layers: ['static', 'ai-reasoning'],
      rulesDir: RULES_DIR, onlyScanners: [], timeoutMs: 300_000, kevCatalogPath: null,
      authorizedFlag: false, storeRoot: vulnDir, reasoner: 'heuristic', verify: true,
    });
    const store = new FileStore(vulnDir);
    const report = store.latestReport()!;
    const verified = report.findings.filter((f) => f.status === 'verified-exploitable');
    check(verified.length >= 1, 'a verified-exploitable finding exists to remediate', verified.map((f) => f.endpoint ?? '').join(', '));
    if (verified.length === 0) throw new Error('nothing verified; cannot continue');

    // 2. Ticket + draft PR carry the evidence.
    const ticket = buildTicket(verified[0]!, report);
    const pr = draftPullRequest(ticket);
    check(ticket.evidence !== null, 'the ticket carries reproduction evidence');
    check(/ownership/i.test(ticket.recommendation), 'the ticket has a concrete ownership-ordering recommendation');
    check(/reverify/.test(pr.body) && /Merge gate/.test(pr.body), 'the draft PR states the reverify merge gate');

    // 3. Re-verify against the UNFIXED source: the exploit must still reproduce.
    process.stdout.write('\nRe-verifying against the UNFIXED source (control) …\n');
    const beforeFix = await reverifyFindings(vulnDir, report.findings, { timeoutMs: 300_000, dynamicConfig: null });
    check(beforeFix.stillVulnerable >= 1, 'the exploit still reproduces before the fix (control)',
      beforeFix.outcomes.map((o) => `${o.finding.endpoint}: ${o.newStatus}`).join('; '));

    // 4. Apply the fix and re-verify: the finding must flip to fixed-verified.
    check(applyFix(fixedDir), 'applied the recommended ownership-check fix to a copy');
    process.stdout.write('Re-verifying against the FIXED source …\n');
    const afterFix = await reverifyFindings(fixedDir, report.findings, { timeoutMs: 300_000, dynamicConfig: null });
    const fixedOutcome = afterFix.outcomes.find((o) => (o.finding.endpoint ?? '').startsWith('DELETE'));
    check(fixedOutcome?.newStatus === 'fixed-verified', 'the finding flips to fixed-verified after the fix',
      fixedOutcome ? `${fixedOutcome.previousStatus} -> ${fixedOutcome.newStatus}` : 'no DELETE outcome');
    check(afterFix.stillVulnerable === 0, 'no exploit reproduces after the fix (merge gate would pass)');
  } finally {
    rmSync(work, { recursive: true, force: true });
  }

  process.stdout.write(`\nPhase 4 acceptance: ${failures === 0 ? 'PASS' : `FAIL (${failures})`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err: unknown) => {
  process.stderr.write(`phase 4 acceptance failed: ${(err as Error).stack ?? String(err)}\n`);
  process.exit(2);
});
