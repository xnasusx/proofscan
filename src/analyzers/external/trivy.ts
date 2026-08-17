import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { RuleFinding, Severity } from '../../types.js';
import { detectVersion, exec } from '../../core/exec.js';
import { outcome } from './types.js';
import type { ExternalScanner, ScannerContext, ScannerResult } from './types.js';

/** Trivy JSON shape, verified against trivy 0.73.0 output. */
interface TrivyVulnerability {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
  CweIDs?: string[];
  Status?: string;
  CVSS?: Record<string, { V3Score?: number; V3Vector?: string; V2Score?: number }>;
}

interface TrivyResult {
  Target?: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[] | null;
}

interface TrivyOutput {
  Results?: TrivyResult[];
}

/**
 * Manifests that declare dependencies, and the lockfiles that pin them.
 *
 * Trivy resolves versions from lockfiles. A project with a manifest but no
 * lockfile produces no Results section at all — indistinguishable from a clean
 * scan unless the difference is reported, which is what LOCKFILE_EXPECTATIONS
 * exists for.
 */
const LOCKFILE_EXPECTATIONS: Array<{ manifest: string; lockfiles: string[]; ecosystem: string }> = [
  {
    manifest: 'package.json',
    lockfiles: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json', 'bun.lockb'],
    ecosystem: 'npm',
  },
  {
    manifest: 'requirements.txt',
    lockfiles: ['requirements.txt', 'poetry.lock', 'Pipfile.lock', 'uv.lock'],
    ecosystem: 'pip',
  },
  { manifest: 'pyproject.toml', lockfiles: ['poetry.lock', 'uv.lock', 'pdm.lock'], ecosystem: 'python' },
  { manifest: 'Gemfile', lockfiles: ['Gemfile.lock'], ecosystem: 'bundler' },
  { manifest: 'go.mod', lockfiles: ['go.sum', 'go.mod'], ecosystem: 'gomod' },
  { manifest: 'composer.json', lockfiles: ['composer.lock'], ecosystem: 'composer' },
  { manifest: 'Cargo.toml', lockfiles: ['Cargo.lock'], ecosystem: 'cargo' },
  { manifest: 'pom.xml', lockfiles: ['pom.xml'], ecosystem: 'maven' },
];

function mapSeverity(value: string | undefined): Severity {
  switch ((value ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    default:
      return 'low';
  }
}

/** Best available CVSS v3 score across reporting sources. */
function bestCvss(vuln: TrivyVulnerability): { score: number; vector: string | null } | null {
  const sources = Object.values(vuln.CVSS ?? {});
  let best: { score: number; vector: string | null } | null = null;
  for (const source of sources) {
    if (typeof source?.V3Score === 'number') {
      if (!best || source.V3Score > best.score) {
        best = { score: source.V3Score, vector: source.V3Vector ?? null };
      }
    }
  }
  return best;
}

/**
 * Load a local CISA Known Exploited Vulnerabilities catalog.
 *
 * Deliberately offline: the operator supplies the file. A scanner that reaches
 * out to the internet mid-run behaves differently in an air-gapped environment
 * and in CI, and silently degrades when the fetch fails. Nothing is fabricated
 * when the catalog is absent — the field simply says it was not checked.
 */
export function loadKevCatalog(path: string): Set<string> | null {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as {
      vulnerabilities?: Array<{ cveID?: string }>;
    };
    const ids = (parsed.vulnerabilities ?? [])
      .map((v) => v.cveID)
      .filter((id): id is string => typeof id === 'string');
    return ids.length > 0 ? new Set(ids) : null;
  } catch {
    return null;
  }
}

export function parseTrivyOutput(
  raw: string,
  options: { kev: Set<string> | null } = { kev: null },
): { findings: RuleFinding[]; analysedTargets: string[] } {
  let parsed: TrivyOutput;
  try {
    parsed = JSON.parse(raw) as TrivyOutput;
  } catch {
    return { findings: [], analysedTargets: [] };
  }

  const findings: RuleFinding[] = [];
  const analysedTargets: string[] = [];

  for (const result of parsed.Results ?? []) {
    if (result.Target) analysedTargets.push(result.Target);

    for (const vuln of result.Vulnerabilities ?? []) {
      if (!vuln.VulnerabilityID || !vuln.PkgName) continue;

      const cvss = bestCvss(vuln);
      const inKev = options.kev ? options.kev.has(vuln.VulnerabilityID) : null;

      const exploitability: string[] = [];
      if (inKev === true) {
        exploitability.push(
          'Listed in the CISA Known Exploited Vulnerabilities catalog — exploitation has been observed in the wild.',
        );
      } else if (inKev === false) {
        exploitability.push('Not in the supplied CISA KEV catalog.');
      } else {
        exploitability.push(
          'KEV status not checked — no catalog was supplied (--kev-catalog). Absence of a KEV note is not evidence the flaw is unexploited.',
        );
      }
      if (cvss) {
        exploitability.push(`CVSS v3 ${cvss.score.toFixed(1)}${cvss.vector ? ` (${cvss.vector})` : ''}.`);
      }
      exploitability.push(
        vuln.FixedVersion
          ? `A fixed version exists (${vuln.FixedVersion}), so remediation is an upgrade rather than a mitigation.`
          : 'No fixed version is published yet; mitigation or removal is the only route.',
      );
      exploitability.push(
        'Reachability was not assessed: this reports that a vulnerable version is present, not that the ' +
          'affected code path is called by this application.',
      );

      findings.push({
        rule_id: vuln.VulnerabilityID,
        title: `${vuln.PkgName} ${vuln.InstalledVersion ?? ''} — ${vuln.VulnerabilityID}`.trim(),
        description:
          `${vuln.Title ?? vuln.Description?.slice(0, 300) ?? 'No description supplied by the advisory.'}\n` +
          `Package: ${vuln.PkgName} ${vuln.InstalledVersion ?? '(version unknown)'}` +
          (vuln.FixedVersion ? ` → fixed in ${vuln.FixedVersion}` : ' (no fix available)') +
          (result.Target ? `\nFound via: ${result.Target}` : '') +
          (vuln.PrimaryURL ? `\nAdvisory: ${vuln.PrimaryURL}` : ''),
        // Point at the lockfile that pinned the version, which is the file to edit.
        file_path: result.Target ?? null,
        line: 0,
        severity: mapSeverity(vuln.Severity),
        exploitability_note: exploitability.join(' '),
        code_excerpt: null,
        cwe: vuln.CweIDs ?? [],
      } as RuleFinding);
    }
  }

  return { findings, analysedTargets };
}

export const trivyScanner: ExternalScanner = {
  name: 'trivy',
  binary: 'trivy',

  async run(context: ScannerContext): Promise<ScannerResult> {
    const started = Date.now();
    const version = await detectVersion('trivy', ['--version']);

    if (version === null) {
      return {
        outcome: outcome('trivy', 'not_installed', {
          detail:
            'trivy not found on PATH. No dependency (SCA) scanning was performed — known-vulnerable ' +
            'dependencies in this target are unexamined, not absent.',
          duration_ms: Date.now() - started,
        }),
        findings: [],
        notes: [],
      };
    }

    const notes: string[] = [];

    // Establish what *should* be analysable before running, so a silent empty
    // result can be explained rather than presented as a clean bill of health.
    const missingLockfiles: string[] = [];
    for (const expectation of LOCKFILE_EXPECTATIONS) {
      if (!existsSync(join(context.root, expectation.manifest))) continue;
      const hasLock = expectation.lockfiles.some((lock) => existsSync(join(context.root, lock)));
      if (!hasLock) missingLockfiles.push(`${expectation.manifest} (${expectation.ecosystem})`);
    }

    const result = await exec(
      'trivy',
      ['fs', '--scanners', 'vuln', '--format', 'json', '--quiet', context.root],
      { timeoutMs: context.timeoutMs, cwd: context.root },
    );

    if (result.timedOut) {
      return {
        outcome: outcome('trivy', 'failed', {
          detail: `timed out after ${context.timeoutMs} ms`,
          version,
          duration_ms: Date.now() - started,
        }),
        findings: [],
        notes,
      };
    }

    const kev = context.kevCatalogPath ? loadKevCatalog(context.kevCatalogPath) : null;
    if (context.kevCatalogPath && kev === null) {
      notes.push(
        `KEV catalog at ${context.kevCatalogPath} could not be read or contained no entries; KEV status was not applied.`,
      );
    }

    const { findings, analysedTargets } = parseTrivyOutput(result.stdout, { kev });

    // No analysable target at all: report no_input rather than a clean run.
    if (analysedTargets.length === 0) {
      const detail =
        missingLockfiles.length > 0
          ? `trivy found nothing it could analyse. A dependency manifest is present but no lockfile: ` +
            `${missingLockfiles.join(', ')}. Trivy resolves versions from lockfiles, so dependencies were NOT ` +
            `scanned. Generate one (\`npm install --package-lock-only\`) and re-run.`
          : `trivy found no dependency manifest or lockfile in this target, so there was nothing to scan for ` +
            `known-vulnerable dependencies.`;
      notes.push(detail);
      return {
        outcome: outcome('trivy', 'no_input', {
          detail,
          version,
          duration_ms: Date.now() - started,
        }),
        findings: [],
        notes,
      };
    }

    if (missingLockfiles.length > 0) {
      notes.push(
        `Partial dependency coverage: ${missingLockfiles.join(', ')} has no lockfile, so those dependencies ` +
          `were not version-resolved and are unscanned.`,
      );
    }

    return {
      outcome: outcome('trivy', 'ran', {
        version,
        duration_ms: Date.now() - started,
        findings_count: findings.length,
        detail: `analysed: ${analysedTargets.join(', ')}`,
      }),
      findings,
      notes,
    };
  },
};
