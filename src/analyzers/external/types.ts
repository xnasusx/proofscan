import type { RuleFinding, ScannerOutcome } from '../../types.js';

export interface ScannerContext {
  /** Absolute path to the scan root. */
  root: string;
  /** Directory holding the shipped Semgrep rule files. */
  rulesDir: string;
  timeoutMs: number;
  /**
   * Optional local copy of the CISA Known Exploited Vulnerabilities catalog.
   * Supplied by the operator; never fetched at scan time.
   */
  kevCatalogPath: string | null;
}

export interface ScannerResult {
  outcome: ScannerOutcome;
  findings: RuleFinding[];
  /** Coverage observations, e.g. "manifest present but no lockfile". */
  notes: string[];
  /**
   * How many files this scanner actually examined, when it reports that.
   * Compared against the built-in engine's count so that a scanner quietly
   * skipping part of the tree becomes visible instead of looking like a clean
   * result. Null when the scanner does not say.
   */
  filesScanned?: number | null;
}

export interface ExternalScanner {
  name: string;
  /** Binary to look for on PATH. */
  binary: string;
  versionArgs?: string[];
  run(context: ScannerContext): Promise<ScannerResult>;
}

export function outcome(
  name: string,
  status: ScannerOutcome['status'],
  options: { detail?: string | null; version?: string | null; duration_ms?: number; findings_count?: number } = {},
): ScannerOutcome {
  return {
    name,
    status,
    detail: options.detail ?? null,
    version: options.version ?? null,
    duration_ms: options.duration_ms ?? 0,
    findings_count: options.findings_count ?? 0,
  };
}
