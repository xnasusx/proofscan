import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuditLog, canonicalise, verifyChain } from '../src/core/audit.js';
import { applyHistory, buildFinding, dedupe, fingerprintOf, sortFindings } from '../src/core/findings.js';
import { authorizeLayers, adHocTarget, parseTargetsFile, TargetConfigError } from '../src/config/targets.js';
import { parseTrivyOutput } from '../src/analyzers/external/trivy.js';
import { parseGitleaksReport } from '../src/analyzers/external/gitleaks.js';
import type { Finding, Target } from '../src/types.js';

const HERE = dirname(fileURLToPath(import.meta.url));

function finding(overrides: Partial<Finding> = {}): Finding {
  return buildFinding({
    scan_run_id: 'run-1',
    layer: 'static',
    detected_by: 'builtin',
    now: '2026-01-01T00:00:00.000Z',
    rule_id: 'proofscan.test',
    title: 'Test finding',
    description: 'description',
    file_path: 'server.js',
    line: 10,
    severity: 'high',
    exploitability_note: 'note',
    code_excerpt: 'const a = 1;',
    ...overrides,
  });
}

describe('audit log', () => {
  it('canonicalises objects deterministically regardless of key order', () => {
    expect(canonicalise({ b: 1, a: 2 })).toBe(canonicalise({ a: 2, b: 1 }));
    expect(canonicalise({ a: [1, { d: 4, c: 3 }] })).toBe('{"a":[1,{"c":3,"d":4}]}');
  });

  it('chains entries and verifies a well-formed log', () => {
    const log = new AuditLog();
    log.append({ actor: 'system', action: 'scan.started', created_at: '2026-01-01T00:00:00.000Z' });
    log.append({ actor: 'system', action: 'finding.recorded', created_at: '2026-01-01T00:00:01.000Z' });
    log.append({ actor: 'system', action: 'scan.completed', created_at: '2026-01-01T00:00:02.000Z' });

    const entries = log.all();
    expect(entries).toHaveLength(3);
    expect(entries[0]!.prev_entry_hash).toBeNull();
    expect(entries[1]!.prev_entry_hash).toBe(entries[0]!.entry_hash);
    expect(verifyChain(entries).ok).toBe(true);
  });

  it('detects an edited entry', () => {
    const log = new AuditLog();
    log.append({ actor: 'system', action: 'scan.started', created_at: '2026-01-01T00:00:00.000Z' });
    log.append({ actor: 'system', action: 'finding.recorded', created_at: '2026-01-01T00:00:01.000Z' });

    const entries = log.all();
    entries[0]!.action = 'scan.tampered';

    const result = verifyChain(entries);
    expect(result.ok).toBe(false);
    expect(result.problems.some((p) => p.problem.includes('edited after it was written'))).toBe(true);
  });

  it('detects a removed entry', () => {
    const log = new AuditLog();
    log.append({ actor: 'system', action: 'a', created_at: '2026-01-01T00:00:00.000Z' });
    log.append({ actor: 'system', action: 'b', created_at: '2026-01-01T00:00:01.000Z' });
    log.append({ actor: 'system', action: 'c', created_at: '2026-01-01T00:00:02.000Z' });

    const entries = log.all();
    const truncated = [entries[0]!, entries[2]!];

    const result = verifyChain(truncated);
    expect(result.ok).toBe(false);
    expect(result.problems.some((p) => p.problem.includes('removed, reordered, or inserted'))).toBe(true);
  });

  it('resumes an existing chain without breaking it', () => {
    const first = new AuditLog();
    first.append({ actor: 'system', action: 'a', created_at: '2026-01-01T00:00:00.000Z' });
    const second = new AuditLog(first.all());
    second.append({ actor: 'system', action: 'b', created_at: '2026-01-01T00:00:01.000Z' });
    expect(verifyChain(second.all()).ok).toBe(true);
  });
});

describe('finding normalisation', () => {
  it('keeps one finding when two engines detect the same defect, and records both', () => {
    const fromBuiltin = finding({ detected_by: 'builtin' });
    const fromSemgrep = finding({ detected_by: 'semgrep' });
    const merged = dedupe([fromBuiltin, fromSemgrep]);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.detected_by).toEqual(['builtin', 'semgrep']);
  });

  it('lets the built-in engine decide severity when engines disagree', () => {
    // The built-in engine resolves detail semgrep cannot express (for instance
    // that an exposed value is truncated), so it must not be overridden by the
    // harsher of the two ratings.
    const builtinMedium = finding({ detected_by: 'builtin', severity: 'medium' });
    const semgrepHigh = finding({ detected_by: 'semgrep', severity: 'high' });

    expect(dedupe([builtinMedium, semgrepHigh])[0]!.severity).toBe('medium');
    // Order of arrival must not change the outcome.
    expect(dedupe([semgrepHigh, builtinMedium])[0]!.severity).toBe('medium');
  });

  it('fails safe on the higher severity when neither engine is authoritative', () => {
    const a = finding({ detected_by: 'gitleaks', severity: 'medium' });
    const b = finding({ detected_by: 'trivy', severity: 'critical' });
    expect(dedupe([a, b])[0]!.severity).toBe('critical');
  });

  it('keeps two genuine instances of one rule in one file distinct', () => {
    const first = finding({ line: 13 });
    const second = finding({ line: 14 });
    expect(dedupe([first, second])).toHaveLength(2);
  });

  it('produces a fingerprint stable across line movement', () => {
    const base = {
      rule_id: 'proofscan.test',
      layer: 'static' as const,
      file_path: 'server.js',
      endpoint: null,
      code_excerpt: 'const a = 1;',
      title: 'Test',
    };
    expect(fingerprintOf(base)).toBe(fingerprintOf({ ...base, code_excerpt: 'const  a  =  1;' }));
  });

  it('sorts by severity, then file, then line', () => {
    const sorted = sortFindings([
      finding({ severity: 'low', file_path: 'a.js', line: 1 }),
      finding({ severity: 'critical', file_path: 'z.js', line: 99 }),
      finding({ severity: 'medium', file_path: 'b.js', line: 5 }),
      finding({ severity: 'medium', file_path: 'a.js', line: 5 }),
    ]);
    expect(sorted.map((f) => `${f.severity}:${f.file_path}`)).toEqual([
      'critical:z.js',
      'medium:a.js',
      'medium:b.js',
      'low:a.js',
    ]);
  });

  it('carries first_seen_at forward for a finding that persists', () => {
    const previous = finding({ now: '2025-06-01T00:00:00.000Z' });
    const current = finding({ now: '2026-01-01T00:00:00.000Z' });
    const [carried] = applyHistory([current], [previous]);
    expect(carried!.first_seen_at).toBe('2025-06-01T00:00:00.000Z');
    expect(carried!.last_seen_at).toBe('2026-01-01T00:00:00.000Z');
  });

  it('marks every static finding unverified, never verified', () => {
    expect(finding().status).toBe('unverified-flagged');
  });
});

describe('authorisation gate', () => {
  const authorised: Target = {
    id: 'abc',
    name: 'staging',
    source_type: 'local_path',
    source_uri: '/srv/app',
    runtime_base_url: 'https://staging.example.com',
    authorized_by: 'rootcaws',
    authorized_at: '2026-08-01',
    authorization_basis: 'own application, staging environment',
  };

  it('allows static-only runs without any authorisation record', () => {
    const target = adHocTarget('/some/path');
    const decision = authorizeLayers(target, ['static'], { authorizedFlag: false });
    expect(decision.allowed).toBe(true);
  });

  it('refuses a dynamic layer when the target has no authorisation record', () => {
    const target = adHocTarget('/some/path');
    const decision = authorizeLayers(target, ['dynamic-fuzzer'], { authorizedFlag: true });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('authorized_by');
  });

  it('refuses a dynamic layer when the record exists but --authorized was not passed', () => {
    const decision = authorizeLayers(authorised, ['dynamic-fuzzer'], { authorizedFlag: false });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('--authorized');
  });

  it('allows a dynamic layer only with both a record and the flag', () => {
    const decision = authorizeLayers(authorised, ['dynamic-fuzzer'], { authorizedFlag: true });
    expect(decision.allowed).toBe(true);
    expect(decision.record).toContain('authorized_by=rootcaws');
  });

  it('refuses a dynamic layer with no runtime_base_url', () => {
    const decision = authorizeLayers({ ...authorised, runtime_base_url: null }, ['dynamic-fuzzer'], {
      authorizedFlag: true,
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('runtime_base_url');
  });

  it('refuses a partial authorisation record', () => {
    const partial = { ...authorised, authorization_basis: null };
    const decision = authorizeLayers(partial, ['dynamic-fuzzer'], { authorizedFlag: true });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('authorization_basis');
  });
});

describe('targets file', () => {
  it('parses a valid file', () => {
    const yaml = `
targets:
  - name: flaudecode
    source_type: local_path
    source_uri: ./fixtures/flaudecode
    authorized_by: rootcaws
    authorized_at: "2026-08-09"
    authorization_basis: own test fixture
`;
    const targets = parseTargetsFile(yaml, 'targets.yaml');
    expect(targets).toHaveLength(1);
    expect(targets[0]!.name).toBe('flaudecode');
    expect(targets[0]!.runtime_base_url).toBeNull();
  });

  it('gives a stable id for the same name and uri', () => {
    const yaml = `
targets:
  - name: a
    source_type: local_path
    source_uri: /x
`;
    expect(parseTargetsFile(yaml, 'f')[0]!.id).toBe(parseTargetsFile(yaml, 'f')[0]!.id);
  });

  it('rejects duplicate names, bad source_type and missing fields', () => {
    expect(() =>
      parseTargetsFile(
        `targets:\n  - name: a\n    source_type: local_path\n    source_uri: /x\n  - name: a\n    source_type: local_path\n    source_uri: /y\n`,
        'f',
      ),
    ).toThrow(TargetConfigError);

    expect(() => parseTargetsFile(`targets:\n  - name: a\n    source_type: ftp\n    source_uri: /x\n`, 'f')).toThrow(
      /source_type/,
    );

    expect(() => parseTargetsFile(`targets:\n  - source_type: local_path\n    source_uri: /x\n`, 'f')).toThrow(/name/);
    expect(() => parseTargetsFile(`nope: []\n`, 'f')).toThrow(/targets:/);
  });
});

describe('trivy adapter', () => {
  it('parses real trivy output captured from trivy 0.73.0', () => {
    const raw = readFileSync(join(HERE, 'fixtures', 'trivy', 'npm-vulnerable.json'), 'utf8');
    const { findings, analysedTargets } = parseTrivyOutput(raw);

    expect(analysedTargets.length).toBeGreaterThan(0);
    expect(findings.length).toBeGreaterThan(10);

    const first = findings[0]!;
    expect(first.rule_id).toMatch(/^CVE-/);
    expect(['critical', 'high', 'medium', 'low']).toContain(first.severity);
    // Absence of KEV data must be stated, never implied to be a clean signal.
    expect(first.exploitability_note).toContain('KEV status not checked');
    expect(first.exploitability_note).toContain('Reachability was not assessed');
  });

  it('applies KEV context when a catalog is supplied', () => {
    const raw = readFileSync(join(HERE, 'fixtures', 'trivy', 'npm-vulnerable.json'), 'utf8');
    const anyCve = parseTrivyOutput(raw).findings[0]!.rule_id!;
    const { findings } = parseTrivyOutput(raw, { kev: new Set([anyCve]) });
    const target = findings.find((f) => f.rule_id === anyCve)!;
    expect(target.exploitability_note).toContain('Known Exploited Vulnerabilities');
  });

  it('returns nothing for unparseable output rather than throwing', () => {
    expect(parseTrivyOutput('not json').findings).toEqual([]);
  });
});

describe('gitleaks adapter', () => {
  // Shape verified against gitleaks 8.30.1. Note v8 emits no Severity field,
  // so severity is derived rather than read.
  const report = JSON.stringify([
    {
      RuleID: 'aws-access-token',
      Description: 'AWS Access Token',
      File: 'config/creds.js',
      StartLine: 4,
      Secret: 'AKIA_FAKE_VALUE_FOR_TEST_ONLY',
      Match: 'awsKey = "AKIA_FAKE_VALUE_FOR_TEST_ONLY"',
      Entropy: 4.2,
      Fingerprint: 'config/creds.js:aws-access-token:4',
    },
    {
      RuleID: 'generic-api-key',
      Description: 'Generic API Key',
      File: 'config/creds.js',
      StartLine: 9,
      Secret: 'lowentropyplaceholder',
      Entropy: 2.9,
    },
  ]);

  it('never writes the detected secret into the finding', () => {
    const findings = parseGitleaksReport(report, '/repo');
    const serialised = JSON.stringify(findings);
    expect(serialised).not.toContain('AKIA_FAKE_VALUE_FOR_TEST_ONLY');
    expect(serialised).not.toContain('lowentropyplaceholder');
    expect(findings[0]!.description).toContain('redacted by proofscan');
    expect(findings[0]!.code_excerpt).toBeNull();
  });

  it('rates a live cloud credential critical and a low-entropy generic match medium', () => {
    const findings = parseGitleaksReport(report, '/repo');
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[1]!.severity).toBe('medium');
  });

  it('tells the reader that rotation, not deletion, ends the exposure', () => {
    const findings = parseGitleaksReport(report, '/repo');
    expect(findings[0]!.description).toContain('Rotation');
  });

  it('handles an empty report and malformed JSON', () => {
    expect(parseGitleaksReport('', '/repo')).toEqual([]);
    expect(parseGitleaksReport('[]', '/repo')).toEqual([]);
    expect(parseGitleaksReport('{oops', '/repo')).toEqual([]);
  });
});
