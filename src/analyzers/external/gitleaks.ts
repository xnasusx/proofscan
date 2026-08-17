import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { RuleFinding, Severity } from '../../types.js';
import { detectVersion, exec } from '../../core/exec.js';
import { outcome } from './types.js';
import type { ExternalScanner, ScannerContext, ScannerResult } from './types.js';

/**
 * Gitleaks v8 JSON finding.
 *
 * Field names verified against gitleaks 8.30.1 output. Note there is no
 * severity field — v8 does not emit one, so severity is derived below from the
 * rule id and entropy rather than read from the report.
 */
interface GitleaksFinding {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  Secret?: string;
  Match?: string;
  Entropy?: number;
  Fingerprint?: string;
  Tags?: string[];
}

/** Rule families that indicate a live, directly usable credential. */
const CRITICAL_RULE_PATTERN =
  /aws|gcp|google|azure|private-key|privatekey|stripe.*live|sk_live|twilio|sendgrid|slack|npm|pypi|docker|database|connection.?string|ssh/i;

function mapSeverity(finding: GitleaksFinding): Severity {
  const id = finding.RuleID ?? '';
  if (CRITICAL_RULE_PATTERN.test(id)) return 'critical';
  // A generic match with low entropy is more likely a placeholder than a live key.
  if (/generic/i.test(id) && (finding.Entropy ?? 0) < 3.5) return 'medium';
  return 'high';
}

/**
 * Never write a detected credential into our report.
 *
 * Reports get committed, attached to tickets and pasted into chat. Echoing the
 * secret turns the finding into a second copy of the leak. The first four
 * characters plus the length are enough to locate it in the file, and gitleaks'
 * own fingerprint is carried for correlation.
 */
function maskSecret(secret: string | undefined): string {
  if (!secret) return '<not reported>';
  const prefix = secret.slice(0, 4);
  return `${prefix}… (${secret.length} chars, redacted by proofscan)`;
}

function normalisePath(path: string, root: string): string {
  const normalised = path.replace(/\\/g, '/');
  const normalisedRoot = root.replace(/\\/g, '/').replace(/\/$/, '');
  if (normalised.startsWith(`${normalisedRoot}/`)) return normalised.slice(normalisedRoot.length + 1);
  return normalised.replace(/^\.\//, '');
}

export function parseGitleaksReport(raw: string, root: string): RuleFinding[] {
  const trimmed = raw.trim();
  if (!trimmed) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];

  return (parsed as GitleaksFinding[])
    .filter((f) => f.File)
    .map((finding) => {
      const ruleId = finding.RuleID ?? 'unknown';
      const severity = mapSeverity(finding);
      return {
        rule_id: `gitleaks.${ruleId}`,
        title: `Secret detected: ${finding.Description ?? ruleId}`,
        description:
          `gitleaks matched rule \`${ruleId}\` against this line. Detected value: ${maskSecret(finding.Secret)}. ` +
          (finding.Entropy !== undefined ? `Shannon entropy ${finding.Entropy.toFixed(2)}. ` : '') +
          `Treat the credential as compromised: rotate it first, then remove it from the file. Removing it from ` +
          `the working tree is not sufficient — if it was ever committed and pushed, it stays retrievable from ` +
          `the object history, and on GitHub a force-push leaves the old commit fetchable by SHA. Rotation is ` +
          `the control that actually ends the exposure.` +
          (finding.Fingerprint ? ` gitleaks fingerprint: ${finding.Fingerprint}.` : ''),
        file_path: normalisePath(finding.File!, root),
        line: finding.StartLine ?? 0,
        severity,
        exploitability_note:
          severity === 'critical'
            ? `Rule family indicates a live, directly usable credential. Anyone who can read the repository can ` +
              `use it; no exploitation step is required beyond authenticating with it.`
            : `Depends on whether the matched value is a real issued credential or a placeholder. Confirm before ` +
              `rating: a generic pattern match is not proof the value is live.`,
        // The matched line is deliberately not carried through — it contains
        // the secret. The file and line locate it precisely enough.
        code_excerpt: null,
        cwe: ['CWE-798'],
      } satisfies RuleFinding;
    });
}

export const gitleaksScanner: ExternalScanner = {
  name: 'gitleaks',
  binary: 'gitleaks',

  async run(context: ScannerContext): Promise<ScannerResult> {
    const started = Date.now();
    const version = await detectVersion('gitleaks', ['version']);

    if (version === null) {
      return {
        outcome: outcome('gitleaks', 'not_installed', {
          detail:
            'gitleaks not found on PATH. No issued-credential scanning was performed. The built-in ' +
            'hardcoded-fallback-secret rule covers a different pattern and is not a substitute. ' +
            'Install from github.com/gitleaks/gitleaks.',
          duration_ms: Date.now() - started,
        }),
        findings: [],
        notes: [],
      };
    }

    const reportDir = mkdtempSync(join(tmpdir(), 'proofscan-gitleaks-'));
    const reportPath = join(reportDir, 'report.json');

    try {
      const result = await exec(
        'gitleaks',
        [
          // `dir` is the v8.19+ subcommand for scanning a filesystem path.
          // Scanning the working tree rather than git history keeps the run
          // bounded; history scanning is a separate, slower mode.
          'dir',
          context.root,
          '--report-format',
          'json',
          '--report-path',
          reportPath,
          '--no-banner',
          // Findings must not turn into a non-zero exit that reads as a crash.
          '--exit-code',
          '0',
        ],
        { timeoutMs: context.timeoutMs, cwd: context.root },
      );

      if (result.timedOut) {
        return {
          outcome: outcome('gitleaks', 'failed', {
            detail: `timed out after ${context.timeoutMs} ms`,
            version,
            duration_ms: Date.now() - started,
          }),
          findings: [],
          notes: [],
        };
      }

      let raw: string;
      try {
        raw = readFileSync(reportPath, 'utf8');
      } catch {
        return {
          outcome: outcome('gitleaks', 'failed', {
            detail: `gitleaks wrote no report (exit ${result.code}): ${result.stderr.slice(0, 300)}`,
            version,
            duration_ms: Date.now() - started,
          }),
          findings: [],
          notes: [],
        };
      }

      const findings = parseGitleaksReport(raw, context.root);

      return {
        outcome: outcome('gitleaks', 'ran', {
          version,
          duration_ms: Date.now() - started,
          findings_count: findings.length,
        }),
        findings,
        notes: [],
      };
    } finally {
      rmSync(reportDir, { recursive: true, force: true });
    }
  },
};
