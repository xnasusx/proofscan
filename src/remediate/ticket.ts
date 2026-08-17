import type { Finding, ScanReport, VerificationRun } from '../types.js';

/**
 * Remediation ticket generation (Layer 4).
 *
 * For each verified-exploitable finding, produce a ticket carrying the evidence
 * that makes it actionable — the exploit, the observed impact, the request
 * trail — plus a concrete remediation recommendation. The output is
 * sink-agnostic: a structured object plus a Jira-API-shaped payload and a
 * human-readable Markdown rendering. A real Jira/GitHub integration is the same
 * object posted to a different endpoint; proofscan ships the filesystem sink
 * (write the ticket + a draft-PR description to disk) because that is the part
 * that can be demonstrated and shipped without embedding anyone's credentials.
 */

export interface RemediationTicket {
  /** Stable key derived from the finding fingerprint, so re-runs don't duplicate. */
  key: string;
  finding_id: string;
  title: string;
  severity: Finding['severity'];
  layer: Finding['layer'];
  endpoint: string | null;
  file_path: string | null;
  line: number | null;
  cwe: string[];
  summary: string;
  recommendation: string;
  /** Repro evidence, when the finding was verified by a run. */
  evidence: VerificationRun['evidence'] | null;
  markdown: string;
  /** Jira-issue-shaped payload (fields a POST /rest/api/3/issue would carry). */
  jira: Record<string, unknown>;
}

/** Rule-specific, concrete remediation guidance. */
function recommendationFor(finding: Finding): string {
  const rule = finding.rule_id ?? '';
  const where = finding.endpoint ? `\`${finding.endpoint}\`` : finding.file_path ? `\`${finding.file_path}\`` : 'the handler';

  if (rule === 'proofscan.authorization-ordering' || rule === 'proofscan.bola-idor-dynamic') {
    return [
      `Enforce ownership **before** any mutation in ${where}.`,
      '',
      'Concretely:',
      '1. As the first step in the handler, load the target resource scoped to the authenticated caller ' +
        '(e.g. `SELECT … WHERE id = ? AND <owner_column> = ?` bound to the caller identity).',
      '2. If that lookup returns nothing, short-circuit with a 403/404 and return **before** touching any row.',
      '3. Only then perform the mutation — and apply the same caller scoping to every statement, including ' +
        'cascade deletes of child records. The flaw is typically that a child delete (e.g. notes/tags) runs ' +
        'unconditionally before the owner-scoped delete of the parent, so a non-owner still destroys the ' +
        "child rows even though the parent delete affects zero rows and returns 404.",
      '',
      'Do not rely on the response status as the control: returning 404 while the child rows are already gone ' +
        'is exactly the defect. The fix is verified only when a second user can no longer change the first ' +
        "user's data — which `proofscan reverify --fix <branch>` checks by re-running this exact exploit.",
    ].join('\n');
  }

  // Fallback: surface the finding's own exploitability note as the starting point.
  return `Address ${where}. ${finding.exploitability_note}`;
}

function renderMarkdown(finding: Finding, evidence: VerificationRun['evidence'] | null, recommendation: string): string {
  const lines: string[] = [];
  lines.push(`# ${finding.title}`, '');
  lines.push(`- **Severity:** ${finding.severity}`);
  lines.push(`- **Status:** ${finding.status}`);
  if (finding.endpoint) lines.push(`- **Endpoint:** \`${finding.endpoint}\``);
  if (finding.file_path) lines.push(`- **Location:** \`${finding.file_path}${finding.line ? `:${finding.line}` : ''}\``);
  if (finding.cwe.length) lines.push(`- **CWE:** ${finding.cwe.join(', ')}`);
  lines.push(`- **Detected by:** ${finding.detected_by.join(', ')}`, '');

  lines.push('## What was found', '', finding.description, '');

  if (evidence) {
    lines.push('## Reproduction evidence', '');
    lines.push(`This was **proven by execution** — ${(evidence as { narrative?: string }).narrative ?? ''}`, '');
    const requests = (evidence as { requests?: Array<{ actor: string; method: string; path: string; status: number | null }> }).requests;
    if (requests?.length) {
      lines.push('Request trail:', '', '```');
      for (const r of requests) lines.push(`${r.actor.padEnd(9)} ${r.method} ${r.path} -> ${r.status ?? 'n/a'}`);
      lines.push('```', '');
    }
    const assertion = (evidence as { state_assertion?: unknown }).state_assertion;
    if (assertion) lines.push('State change (victim read-back):', '', '```json', JSON.stringify(assertion, null, 2), '```', '');
  }

  lines.push('## Recommended fix', '', recommendation, '');
  lines.push('## Verifying the fix', '');
  lines.push(
    'Re-run the exact exploit against the fix branch and require it to fail before merge:',
    '',
    '```bash',
    'proofscan reverify --store <scanned-target> --fix <path-to-fix-branch-checkout>',
    '```',
    '',
    'The finding flips to `fixed-verified` only when the repro no longer reproduces.',
  );
  return lines.join('\n');
}

export function buildTicket(finding: Finding, report: ScanReport): RemediationTicket {
  const evidence = report.verification_runs.find((v) => v.finding_id === finding.id)?.evidence ?? null;
  const recommendation = recommendationFor(finding);
  const markdown = renderMarkdown(finding, evidence, recommendation);

  return {
    key: `PROOFSCAN-${finding.fingerprint.slice(0, 10)}`,
    finding_id: finding.id,
    title: finding.title,
    severity: finding.severity,
    layer: finding.layer,
    endpoint: finding.endpoint,
    file_path: finding.file_path,
    line: finding.line,
    cwe: finding.cwe,
    summary: finding.description.split('\n')[0] ?? finding.title,
    recommendation,
    evidence,
    markdown,
    jira: {
      fields: {
        summary: `[proofscan] ${finding.title}`,
        description: markdown,
        issuetype: { name: 'Bug' },
        labels: ['proofscan', `severity-${finding.severity}`, ...finding.cwe.map((c) => c.toLowerCase())],
        // priority is a rough map; a real integration would use the project's scheme.
        priority: { name: finding.severity === 'critical' ? 'Highest' : finding.severity === 'high' ? 'High' : 'Medium' },
      },
    },
  };
}

/**
 * Draft pull-request description for a fix. Not a patch — proofscan does not
 * auto-apply source changes it cannot prove correct — but a ready-to-use PR body
 * carrying the evidence and the acceptance gate (the repro must fail).
 */
export function draftPullRequest(ticket: RemediationTicket): { title: string; body: string } {
  return {
    title: `Fix ${ticket.severity} authorisation defect: ${ticket.endpoint ?? ticket.title}`,
    body: [
      `Closes ${ticket.key}.`,
      '',
      ticket.markdown,
      '',
      '---',
      '**Merge gate:** do not merge until `proofscan reverify` reports this finding as `fixed-verified` ' +
        'against this branch — i.e. the cross-user exploit no longer reproduces.',
    ].join('\n'),
  };
}
