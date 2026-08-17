import { existsSync } from 'node:fs';
import type { RuleFinding, Severity } from '../../types.js';
import { detectVersion, exec } from '../../core/exec.js';
import { outcome } from './types.js';
import type { ExternalScanner, ScannerContext, ScannerResult } from './types.js';

interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    metadata?: Record<string, unknown>;
  };
}

interface SemgrepOutput {
  results?: SemgrepResult[];
  errors?: Array<{ message?: string; level?: string }>;
  paths?: { scanned?: string[] };
}

/** Semgrep's three levels are coarser than ours; the rule metadata overrides this. */
function mapSeverity(value: string | undefined): Severity {
  switch ((value ?? '').toUpperCase()) {
    case 'ERROR':
      return 'high';
    case 'WARNING':
      return 'medium';
    default:
      return 'low';
  }
}

function normalisePath(path: string, root: string): string {
  const normalised = path.replace(/\\/g, '/');
  const normalisedRoot = root.replace(/\\/g, '/').replace(/\/$/, '');
  if (normalised.startsWith(`${normalisedRoot}/`)) return normalised.slice(normalisedRoot.length + 1);
  return normalised.replace(/^\.\//, '');
}

export const semgrepScanner: ExternalScanner = {
  name: 'semgrep',
  binary: 'semgrep',

  async run(context: ScannerContext): Promise<ScannerResult> {
    const started = Date.now();
    const version = await detectVersion('semgrep', ['--version']);

    if (version === null) {
      return {
        outcome: outcome('semgrep', 'not_installed', {
          detail:
            'semgrep not found on PATH. The rules in rules/semgrep/ were not evaluated by semgrep; the ' +
            'equivalent built-in AST rules still ran. Install with `pipx install semgrep`.',
          duration_ms: Date.now() - started,
        }),
        findings: [],
        notes: [],
      };
    }

    if (!existsSync(context.rulesDir)) {
      return {
        outcome: outcome('semgrep', 'failed', {
          detail: `rules directory not found: ${context.rulesDir}`,
          version,
          duration_ms: Date.now() - started,
        }),
        findings: [],
        notes: [],
      };
    }

    const result = await exec(
      'semgrep',
      [
        'scan',
        '--config',
        context.rulesDir,
        '--json',
        '--quiet',
        // Scan what is on disk, not what git tracks: a committed-then-ignored
        // file is exactly the kind of thing worth finding.
        '--no-git-ignore',
        '--disable-version-check',
        '--metrics',
        'off',
        context.root,
      ],
      { timeoutMs: context.timeoutMs, cwd: context.root },
    );

    if (result.timedOut) {
      return {
        outcome: outcome('semgrep', 'failed', {
          detail: `timed out after ${context.timeoutMs} ms`,
          version,
          duration_ms: Date.now() - started,
        }),
        findings: [],
        notes: [],
      };
    }

    let parsed: SemgrepOutput;
    try {
      parsed = JSON.parse(result.stdout) as SemgrepOutput;
    } catch {
      return {
        outcome: outcome('semgrep', 'failed', {
          detail: `could not parse semgrep JSON output (exit ${result.code}): ${result.stderr.slice(0, 300)}`,
          version,
          duration_ms: Date.now() - started,
        }),
        findings: [],
        notes: [],
      };
    }

    const notes: string[] = [];
    for (const error of parsed.errors ?? []) {
      if (error.message) notes.push(`semgrep reported an error: ${error.message.slice(0, 300)}`);
    }

    const findings: RuleFinding[] = [];
    for (const item of parsed.results ?? []) {
      if (!item.check_id || !item.path) continue;

      const metadata = item.extra?.metadata ?? {};
      const declaredSeverity = metadata['proofscan_severity'];
      const severity: Severity =
        typeof declaredSeverity === 'string' && ['critical', 'high', 'medium', 'low'].includes(declaredSeverity)
          ? (declaredSeverity as Severity)
          : mapSeverity(item.extra?.severity);

      const cweRaw = metadata['cwe'];
      const cwe = Array.isArray(cweRaw)
        ? cweRaw.filter((c): c is string => typeof c === 'string')
        : typeof cweRaw === 'string'
          ? [cweRaw]
          : [];

      // Rule ids are declared as `proofscan.<name>` in the YAML. Semgrep may
      // prefix them with the config path, so the trailing segment is used to
      // line up with the built-in rule ids for deduplication.
      const ruleId = item.check_id.includes('proofscan.')
        ? `proofscan.${item.check_id.split('proofscan.').pop()}`
        : item.check_id;

      findings.push({
        rule_id: ruleId,
        title: typeof metadata['title'] === 'string' ? metadata['title'] : ruleId,
        description: item.extra?.message?.trim() ?? '',
        file_path: normalisePath(item.path, context.root),
        line: item.start?.line ?? 0,
        severity,
        exploitability_note:
          typeof metadata['exploitability'] === 'string'
            ? metadata['exploitability']
            : 'Reported by semgrep; exploitability not assessed by the rule.',
        code_excerpt: item.extra?.lines?.trim().slice(0, 200) ?? null,
        cwe,
      });
    }

    const filesScanned = Array.isArray(parsed.paths?.scanned) ? parsed.paths!.scanned!.length : null;

    return {
      outcome: outcome('semgrep', 'ran', {
        version,
        duration_ms: Date.now() - started,
        findings_count: findings.length,
        detail: filesScanned === null ? null : `${filesScanned} file(s) scanned`,
      }),
      findings,
      notes,
      filesScanned,
    };
  },
};
