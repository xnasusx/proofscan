import pc from 'picocolors';
import type { Finding, ScanReport, Severity } from '../types.js';
import { countBySeverity } from '../core/findings.js';

const SEVERITY_LABEL: Record<Severity, (text: string) => string> = {
  critical: (t) => pc.bold(pc.red(t)),
  high: (t) => pc.red(t),
  medium: (t) => pc.yellow(t),
  low: (t) => pc.dim(t),
};

function wrap(text: string, width: number, indent: string): string {
  const out: string[] = [];
  for (const paragraph of text.split('\n')) {
    let line = '';
    for (const word of paragraph.split(/\s+/).filter(Boolean)) {
      if (line && line.length + word.length + 1 > width) {
        out.push(indent + line);
        line = word;
      } else {
        line = line ? `${line} ${word}` : word;
      }
    }
    if (line) out.push(indent + line);
  }
  return out.join('\n');
}

function location(finding: Finding): string {
  if (finding.file_path && finding.line) return `${finding.file_path}:${finding.line}`;
  if (finding.file_path) return finding.file_path;
  if (finding.endpoint) return finding.endpoint;
  return '(no location)';
}

/**
 * Human-readable summary.
 *
 * The scanner-coverage block is printed before the findings, and deliberately
 * not collapsed into a count. A findings list is only meaningful alongside what
 * actually ran: "0 dependency findings" and "dependencies were never scanned"
 * look identical otherwise, and the second is the one that gets someone hurt.
 */
export function renderText(report: ScanReport, options: { width?: number } = {}): string {
  const width = options.width ?? 96;
  const lines: string[] = [];
  const counts = countBySeverity(report.findings);

  lines.push('');
  lines.push(pc.bold(`proofscan ${report.scan_run.tool_version} — ${report.target.name}`));
  lines.push(pc.dim(`target:  ${report.target.source_uri}`));
  lines.push(pc.dim(`run:     ${report.scan_run.id}`));
  lines.push(pc.dim(`started: ${report.scan_run.started_at}`));
  lines.push('');

  /* ---- coverage ---- */
  lines.push(pc.bold('Scanner coverage'));
  for (const scanner of report.scan_run.scanners) {
    const marker =
      scanner.status === 'ran'
        ? pc.green('ran')
        : scanner.status === 'not_installed'
          ? pc.yellow('NOT INSTALLED')
          : scanner.status === 'no_input'
            ? pc.yellow('NOTHING TO SCAN')
            : scanner.status === 'skipped'
              ? pc.dim('skipped')
              : pc.red('FAILED');

    const version = scanner.version ? pc.dim(` ${scanner.version.split(/\s+/).pop() ?? ''}`) : '';
    lines.push(
      `  ${scanner.name.padEnd(10)} ${marker}${version}` +
        (scanner.status === 'ran' ? pc.dim(`  ${scanner.findings_count} finding(s), ${scanner.duration_ms} ms`) : ''),
    );
    if (scanner.detail && scanner.status !== 'ran') {
      lines.push(wrap(scanner.detail, width - 6, '      '));
    }
  }
  lines.push('');

  /* ---- findings ---- */
  if (report.findings.length === 0) {
    lines.push(pc.bold('Findings: none'));
    lines.push(
      wrap(
        'No findings from the scanners that ran. Read the coverage block above before treating this as clean — ' +
          'a scanner that was not installed found nothing because it never looked.',
        width,
        '  ',
      ),
    );
  } else {
    const summary = (['critical', 'high', 'medium', 'low'] as Severity[])
      .filter((s) => counts[s] > 0)
      .map((s) => SEVERITY_LABEL[s](`${counts[s]} ${s}`))
      .join(pc.dim('  ·  '));
    lines.push(`${pc.bold(`Findings: ${report.findings.length}`)}   ${summary}`);
    lines.push('');

    const verificationByFinding = new Map(report.verification_runs.map((v) => [v.finding_id, v]));

    report.findings.forEach((finding, index) => {
      const tag = SEVERITY_LABEL[finding.severity](finding.severity.toUpperCase().padEnd(8));
      const verifiedBadge =
        finding.status === 'verified-exploitable' ? ` ${pc.bold(pc.green('[VERIFIED EXPLOITABLE]'))}` : '';
      lines.push(`${pc.dim(String(index + 1).padStart(3))}. ${tag} ${pc.bold(finding.title)}${verifiedBadge}`);
      lines.push(`      ${pc.cyan(location(finding))}${finding.rule_id ? pc.dim(`  [${finding.rule_id}]`) : ''}`);
      lines.push(wrap(finding.description, width - 6, '      '));
      if (finding.code_excerpt) {
        lines.push(`      ${pc.dim('code:')} ${finding.code_excerpt.slice(0, width - 12)}`);
      }
      lines.push(wrap(`${pc.dim('exploitability:')} ${finding.exploitability_note}`, width - 6, '      '));

      // When a repro ran, show what it demonstrated — the evidence is the point.
      const verification = verificationByFinding.get(finding.id);
      if (verification) {
        const narrative = (verification.evidence as { narrative?: string }).narrative ?? '';
        lines.push(wrap(`${pc.green('verified:')} ${narrative}`, width - 6, '      '));
      }

      const statusText =
        finding.status === 'verified-exploitable' ? pc.green(`status: ${finding.status}`) : `status: ${finding.status}`;
      const meta: string[] = [statusText, `detected by: ${finding.detected_by.join(' + ')}`];
      if (finding.cwe.length > 0) meta.push(finding.cwe.join(', '));
      lines.push(`      ${pc.dim(meta.join('  ·  '))}`);
      lines.push('');
    });
  }

  /* ---- coverage notes ---- */
  if (report.notes.length > 0) {
    lines.push(pc.bold(`Coverage notes (${report.notes.length})`));
    for (const note of report.notes) lines.push(wrap(`- ${note}`, width - 2, '  '));
    lines.push('');
  }

  const verified = report.findings.filter((f) => f.status === 'verified-exploitable');
  const verifiedCount = verified.length;
  const ranReasoning = report.scan_run.layers_run.includes('ai-reasoning');

  if (verifiedCount > 0) {
    // Layer 2 proves a finding against a sandboxed copy; Layer 3 against a live
    // running instance. Describe whichever actually produced the verified finding.
    const anyDynamic = verified.some((f) => f.layer === 'dynamic-fuzzer');
    const anySandbox = verified.some((f) => f.layer !== 'dynamic-fuzzer');
    const arena =
      anyDynamic && anySandbox
        ? 'a sandboxed copy or a live instance of the target'
        : anyDynamic
          ? 'a live instance of the target'
          : 'a sandboxed copy of the target';
    lines.push(
      pc.dim(
        `${verifiedCount} finding(s) are \`verified-exploitable\`: a generated exploit ran against ${arena} ` +
          'and demonstrated impact. Every other finding is `unverified-flagged` — a static or ' +
          'model signal that has not been proven by execution.',
      ),
    );
  } else if (ranReasoning) {
    lines.push(
      pc.dim(
        'No finding was verified by execution. Flagged authorisation candidates remain `unverified-flagged` — ' +
          'either the sandbox could not run or the repro did not demonstrate impact. Treat severities as triage input.',
      ),
    );
  } else {
    lines.push(
      pc.dim(
        'Every finding above is `unverified-flagged`: this run was static analysis only, so nothing here has been ' +
          'proven exploitable by executing it. Run with `--layers static,ai-reasoning` to verify authorisation defects.',
      ),
    );
  }
  lines.push('');

  return lines.join('\n');
}
