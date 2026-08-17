import { describe, expect, it } from 'vitest';
import { buildTicket, draftPullRequest } from '../src/remediate/ticket.js';
import { buildFinding } from '../src/core/findings.js';
import type { ScanReport, VerificationRun } from '../src/types.js';

function reportWith(finding: ReturnType<typeof buildFinding>, run: VerificationRun | null): ScanReport {
  return {
    scan_run: {
      id: 'r1', target_id: 't', started_at: '2026-08-09T00:00:00Z', completed_at: null,
      layers_run: ['ai-reasoning'], status: 'completed', scanners: [], tool_version: '0.4.0',
    },
    target: {
      id: 't', name: 'x', source_type: 'local_path', source_uri: '/x',
      runtime_base_url: null, authorized_by: null, authorized_at: null, authorization_basis: null, dynamic: null,
    },
    findings: [finding],
    verification_runs: run ? [run] : [],
    notes: [],
  };
}

const finding = buildFinding({
  scan_run_id: 'r1', layer: 'ai-reasoning', detected_by: 'reasoner:heuristic',
  endpoint: 'DELETE /api/tasks/:id', status: 'verified-exploitable', now: '2026-08-09T00:00:00Z',
  rule_id: 'proofscan.authorization-ordering', title: 'Authorisation-ordering defect in DELETE /api/tasks/:id',
  description: 'A mutation runs before the ownership check.', file_path: 'server.js', line: 221,
  severity: 'high', exploitability_note: 'B deletes A’s notes.', code_excerpt: "db.prepare('DELETE FROM notes...",
  cwe: ['CWE-639'],
});

const run: VerificationRun = {
  id: 'v1', finding_id: finding.id, executed_at: '2026-08-09T00:01:00Z', method: 'auto-repro', result: 'pass',
  evidence: {
    result: 'verified-exploitable',
    narrative: 'Identity B deleted A’s note despite a 404.',
    requests: [{ actor: 'attacker', method: 'DELETE', path: '/api/tasks/1', status: 404, responseSummary: 'status 404' }],
    state_assertion: { changed: true },
  },
  sandbox_ref: 'sbx-1',
};

describe('remediation ticket', () => {
  it('carries evidence, a concrete recommendation, and a Jira-shaped payload', () => {
    const ticket = buildTicket(finding, reportWith(finding, run));
    expect(ticket.key).toMatch(/^PROOFSCAN-/);
    expect(ticket.severity).toBe('high');
    expect(ticket.evidence).not.toBeNull();
    expect(ticket.recommendation).toMatch(/ownership/i);
    expect(ticket.recommendation).toMatch(/before/i);
    // Evidence and the reverify gate are in the human-readable body.
    expect(ticket.markdown).toMatch(/Reproduction evidence/);
    expect(ticket.markdown).toMatch(/reverify/);
    // Jira payload shape.
    expect((ticket.jira as { fields: { summary: string } }).fields.summary).toContain('proofscan');
    expect((ticket.jira as { fields: { labels: string[] } }).fields.labels).toContain('severity-high');
  });

  it('drafts a PR whose body states the reverify merge gate', () => {
    const pr = draftPullRequest(buildTicket(finding, reportWith(finding, run)));
    expect(pr.title).toMatch(/DELETE \/api\/tasks/);
    expect(pr.body).toMatch(/Merge gate/);
    expect(pr.body).toMatch(/fixed-verified/);
  });

  it('still produces a ticket when there is no repro evidence', () => {
    const ticket = buildTicket(finding, reportWith(finding, null));
    expect(ticket.evidence).toBeNull();
    expect(ticket.markdown).not.toMatch(/Reproduction evidence/);
    expect(ticket.recommendation.length).toBeGreaterThan(0);
  });
});
