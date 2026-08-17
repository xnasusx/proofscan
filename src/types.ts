/**
 * Data model.
 *
 * Field names deliberately use snake_case to match the Postgres schema in the
 * build spec 1:1. Phase 1 persists to JSON files; when Phase 3 moves the store
 * to Postgres, the row shape and the JSON shape stay identical and no mapping
 * layer is needed.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type Layer = 'static' | 'ai-reasoning' | 'dynamic-fuzzer';

export type FindingStatus =
  | 'unverified-flagged'
  | 'verified-exploitable'
  | 'fixed-unverified'
  | 'fixed-verified'
  | 'wont-fix';

/**
 * `runtime_url` is for a target you can only reach as a running instance, with
 * no source on disk — the case Layer 3 (dynamic fuzzer) is built for. Such a
 * target carries `runtime_base_url` and no scannable source, and static layers
 * skip it rather than erroring.
 */
export type SourceType = 'local_path' | 'git_url' | 'runtime_url';

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export interface Target {
  id: string;
  name: string;
  source_type: SourceType;
  source_uri: string;
  /** Base URL of a running instance. Only used by the dynamic layer (Layer 3). */
  runtime_base_url: string | null;
  authorized_by: string | null;
  authorized_at: string | null;
  authorization_basis: string | null;
  /**
   * Configuration for the dynamic-fuzzer layer (auth flow, route manifest).
   * Opaque here to avoid a type cycle with src/dynamic; validated when the
   * dynamic layer runs. Null when the target has no dynamic config.
   */
  dynamic: Record<string, unknown> | null;
}

export interface Finding {
  id: string;
  scan_run_id: string;
  layer: Layer;
  /** Rule identifier for static findings; null for layers without rules. */
  rule_id: string | null;
  title: string;
  description: string;
  file_path: string | null;
  line: number | null;
  /** Endpoint under test. Populated by the dynamic layer (Phase 3). */
  endpoint: string | null;
  severity: Severity;
  /**
   * What an attacker would need, and what they would get. This is context, not
   * a score — it is never used to reorder the findings list.
   */
  exploitability_note: string;
  status: FindingStatus;
  first_seen_at: string;
  last_seen_at: string;

  /* ---- fields beyond the spec's core schema, additive ---- */

  /** Stable across runs; used to carry first_seen_at forward. See core/findings.ts. */
  fingerprint: string;
  /** Which engines independently produced this finding. Corroboration signal. */
  detected_by: string[];
  /** Verbatim source line, for report context. Never contains a secret value. */
  code_excerpt: string | null;
  /** CWE identifiers, where the rule maps cleanly to one. */
  cwe: string[];
}

/** A scanner that was asked to run, and what actually happened. */
export interface ScannerOutcome {
  name: string;
  /**
   * ran            - executed and produced results (possibly zero)
   * not_installed  - binary absent from PATH
   * no_input       - installed and executed, but the target had nothing it can analyse
   * failed         - executed and errored
   * skipped        - deselected by --scanners
   */
  status: 'ran' | 'not_installed' | 'no_input' | 'failed' | 'skipped';
  /** Human-readable reason. Required for every status except 'ran'. */
  detail: string | null;
  version: string | null;
  duration_ms: number;
  findings_count: number;
}

export interface ScanRun {
  id: string;
  target_id: string;
  started_at: string;
  completed_at: string | null;
  layers_run: Layer[];
  status: 'running' | 'completed' | 'failed';
  /** Per-scanner provenance. The report is not trustworthy without this. */
  scanners: ScannerOutcome[];
  tool_version: string;
}

export interface AuditLogEntry {
  id: string;
  entry_hash: string;
  prev_entry_hash: string | null;
  actor: string;
  action: string;
  target_id: string | null;
  finding_id: string | null;
  payload: Record<string, unknown>;
  created_at: string;
}

/**
 * A verification attempt against a finding. Mirrors the spec's verification_runs
 * table: an auto-generated repro run against a sandboxed copy of the target,
 * with the before/after evidence that decided the verdict.
 */
export interface VerificationRun {
  id: string;
  finding_id: string;
  executed_at: string;
  method: 'auto-repro' | 'manual';
  result: 'pass' | 'fail';
  /** Request/response pairs and before/after state. Synthetic data only. */
  evidence: Record<string, unknown>;
  /** Reference to the (torn-down) sandbox instance. */
  sandbox_ref: string;
}

export interface ScanReport {
  scan_run: ScanRun;
  target: Target;
  findings: Finding[];
  /** Verification attempts, keyed to findings by finding_id. */
  verification_runs: VerificationRun[];
  /** Non-finding observations: coverage gaps, degraded scanners, unsupported files. */
  notes: string[];
}

/** What a rule returns. The engine fills in the rest of the Finding. */
export interface RuleFinding {
  rule_id: string;
  title: string;
  description: string;
  /** Source location, or null for layers that work without repo access (dynamic). */
  file_path: string | null;
  line: number;
  severity: Severity;
  exploitability_note: string;
  code_excerpt?: string | null;
  cwe?: string[];
}
