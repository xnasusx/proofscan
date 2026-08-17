import { randomUUID } from 'node:crypto';
import { existsSync, statSync } from 'node:fs';
import type { Finding, Layer, ScanReport, ScanRun, ScannerOutcome, Target, VerificationRun } from '../types.js';
import { BUILTIN_ENGINE, runBuiltinRules } from '../analyzers/builtin/index.js';
import { gitleaksScanner } from '../analyzers/external/gitleaks.js';
import { semgrepScanner } from '../analyzers/external/semgrep.js';
import { trivyScanner } from '../analyzers/external/trivy.js';
import type { ExternalScanner, ScannerContext } from '../analyzers/external/types.js';
import { runReasoningLayer } from '../analyzers/reasoning/index.js';
import type { ReasonerChoice } from '../analyzers/reasoning/index.js';
import { verifyFindings } from '../verify/index.js';
import { runDynamicLayer } from '../dynamic/index.js';
import { authorizeLayers, isDynamicLayer } from '../config/targets.js';
import { applyHistory, buildFinding, dedupe, sortFindings } from './findings.js';
import { FileStore } from './store.js';
import { walkSource } from './walk.js';

export const TOOL_VERSION = '0.4.0';

export const ALL_EXTERNAL_SCANNERS: ExternalScanner[] = [semgrepScanner, gitleaksScanner, trivyScanner];

export interface ScanOptions {
  target: Target;
  layers: Layer[];
  rulesDir: string;
  /** Scanner names to run. Empty means all of them. */
  onlyScanners: string[];
  timeoutMs: number;
  kevCatalogPath: string | null;
  authorizedFlag: boolean;
  /** Where to persist the run. Null disables persistence. */
  storeRoot: string | null;
  /** Which reasoning backend Layer 2 uses. Only consulted when ai-reasoning runs. */
  reasoner: ReasonerChoice;
  /** Run the sandboxed verification step for Layer 2 findings. */
  verify: boolean;
}

export class ScanRefusedError extends Error {}

export async function runScan(options: ScanOptions): Promise<ScanReport> {
  const { target } = options;
  const startedAt = new Date().toISOString();
  const runId = randomUUID();

  // The gate runs before anything else touches the target.
  const decision = authorizeLayers(target, options.layers, { authorizedFlag: options.authorizedFlag });
  if (!decision.allowed) throw new ScanRefusedError(decision.reason ?? 'authorisation refused');

  const runStatic = options.layers.includes('static');
  const runAiReasoning = options.layers.includes('ai-reasoning');
  const runDynamic = options.layers.some(isDynamicLayer);
  const needsSource = runStatic || runAiReasoning;

  if (needsSource && target.source_type === 'runtime_url') {
    throw new ScanRefusedError(
      `layers ${options.layers.filter((l) => l !== 'dynamic-fuzzer').join(', ')} need source, but "${target.name}" ` +
        `is a runtime_url target with none. Run it with --layers dynamic-fuzzer, or point at a local clone.`,
    );
  }
  if (needsSource && target.source_type === 'git_url') {
    throw new ScanRefusedError(
      `source_type "git_url" is not supported yet. Clone the repository and point at it with source_type: local_path.`,
    );
  }

  const root = target.source_uri;
  if (needsSource && (!existsSync(root) || !statSync(root).isDirectory())) {
    throw new ScanRefusedError(`target source_uri is not an existing directory: ${root}`);
  }

  const notes: string[] = [];
  const scanners: ScannerOutcome[] = [];
  const findings: Finding[] = [];
  const verificationRuns: VerificationRun[] = [];
  const dynamicRequestLog: Array<Record<string, unknown>> = [];
  const now = new Date().toISOString();

  const layersRun: Layer[] = [];

  /* ---------------- Layer 1a: built-in AST + text rules ---------------- */

  // The file walk feeds both the Layer 1 rules and Layer 2 reasoning, so it runs
  // whenever either needs source. A dynamic-only run reads no source at all.
  const { files, skipped } = needsSource ? walkSource(root) : { files: [], skipped: [] };

  let builtinFilesAnalysed = 0;
  if (runStatic) {
    layersRun.push('static');
    const builtinStarted = Date.now();
    const builtin = runBuiltinRules(files);
    builtinFilesAnalysed = builtin.filesAnalysed;

    for (const ruleFinding of builtin.findings) {
      findings.push(
        buildFinding({ ...ruleFinding, scan_run_id: runId, layer: 'static', detected_by: BUILTIN_ENGINE, now }),
      );
    }

    scanners.push({
      name: BUILTIN_ENGINE,
      status: 'ran',
      detail: `${builtin.filesAnalysed} JavaScript/TypeScript file(s) parsed; ${files.length} file(s) read in total`,
      version: TOOL_VERSION,
      duration_ms: Date.now() - builtinStarted,
      findings_count: builtin.findings.length,
    });

    if (files.length === 0) {
      notes.push(
        'No analysable source files were found under the target. Nothing was examined — this is not a clean result.',
      );
    }
    if (builtin.filesAnalysed === 0 && files.length > 0) {
      notes.push(
        'No JavaScript or TypeScript files were found. The built-in AST rules cover JS/TS only, so the route, ' +
          'CORS, secret-fallback and validation rules did not apply to this target.',
      );
    }
    for (const failure of builtin.parseFailures) {
      notes.push(
        `${failure.relPath} did not parse cleanly (${failure.errors} parser diagnostic(s)); AST rules may have ` +
          `under-reported in this file.`,
      );
    }
    for (const entry of skipped) {
      notes.push(`Not analysed — ${entry.relPath}: ${entry.reason}`);
    }
  }

  /* ---------------- Layer 1b: external scanners ---------------- */

  if (runStatic) {
    const context: ScannerContext = {
      root,
      rulesDir: options.rulesDir,
      timeoutMs: options.timeoutMs,
      kevCatalogPath: options.kevCatalogPath,
    };

    const selected = options.onlyScanners.length > 0 ? new Set(options.onlyScanners) : null;

    for (const scanner of ALL_EXTERNAL_SCANNERS) {
      if (selected && !selected.has(scanner.name)) {
        scanners.push({
          name: scanner.name,
          status: 'skipped',
          detail: 'deselected by --scanners',
          version: null,
          duration_ms: 0,
          findings_count: 0,
        });
        continue;
      }

      const result = await scanner.run(context);
      scanners.push(result.outcome);
      notes.push(...result.notes);

      // A scanner that silently examined less of the tree than we did is a
      // coverage gap, and it reads as a clean result unless it is stated.
      // Semgrep in particular applies a default ignore list that excludes test,
      // fixture and vendor directories, so it can report zero findings on code
      // the built-in engine flagged.
      const examined = result.filesScanned;
      if (typeof examined === 'number' && examined < builtinFilesAnalysed) {
        notes.push(
          `Coverage gap: ${scanner.name} examined ${examined} file(s) where the built-in engine parsed ` +
            `${builtinFilesAnalysed}. ${scanner.name} applies its own default ignore list (test, fixture, vendor ` +
            `and similar directories), so a zero result from it does not mean those files are clean — they were ` +
            `not read. The built-in rules did cover them.`,
        );
      }

      for (const ruleFinding of result.findings) {
        findings.push(
          buildFinding({
            ...ruleFinding,
            scan_run_id: runId,
            layer: 'static',
            detected_by: scanner.name,
            now,
          }),
        );
      }
    }
  }

  /* ---------------- Layer 2: AI reasoning + sandboxed verification ---------------- */

  if (runAiReasoning) {
    layersRun.push('ai-reasoning');
    const startedReasoning = Date.now();

    const reasoning = await runReasoningLayer(files, { reasoner: options.reasoner });
    notes.push(...reasoning.notes);

    const verification = await verifyFindings(root, reasoning.findings, {
      timeoutMs: options.timeoutMs,
      enabled: options.verify,
      files,
      dynamicConfig: (target.dynamic ?? null) as never,
    });
    notes.push(...verification.notes);

    for (const verified of verification.findings) {
      const finding = buildFinding({
        ...verified.ruleFinding,
        scan_run_id: runId,
        layer: 'ai-reasoning',
        detected_by: `reasoner:${verified.reasoner}`,
        endpoint: `${verified.handler.method.toUpperCase()} ${verified.handler.path}`,
        status: verified.status,
        now,
      });
      findings.push(finding);

      if (verified.evidence) {
        verificationRuns.push({
          id: randomUUID(),
          finding_id: finding.id,
          executed_at: new Date().toISOString(),
          method: 'auto-repro',
          result: verified.evidence.result === 'verified-exploitable' ? 'pass' : 'fail',
          evidence: {
            result: verified.evidence.result,
            narrative: verified.evidence.narrative,
            requests: verified.evidence.requests,
            state_assertion: verified.evidence.stateAssertion,
            sandbox: verified.evidence.sandbox,
          },
          sandbox_ref: verified.evidence.sandboxRef,
        });
      }
    }

    scanners.push({
      name: `reasoner:${reasoning.reasonerUsed}`,
      status: 'ran',
      detail:
        `${reasoning.candidatesConsidered} mutation handler(s) considered; ${reasoning.findings.length} flagged; ` +
        `${verification.verified} verified-exploitable of ${verification.attempted} verification attempt(s)` +
        (reasoning.usage
          ? `; ${reasoning.usage.input_tokens} in / ${reasoning.usage.output_tokens} out tokens ` +
            `(${reasoning.usage.cache_read_input_tokens} cached)`
          : ''),
      version: TOOL_VERSION,
      duration_ms: Date.now() - startedReasoning,
      findings_count: reasoning.findings.length,
    });
  }

  /* ---------------- Layer 3: dynamic BOLA/IDOR fuzzer ---------------- */

  if (runDynamic) {
    layersRun.push('dynamic-fuzzer');
    const startedDynamic = Date.now();

    // The gate at the top already confirmed a full authorisation record and
    // --authorized, so runtime_base_url is present here.
    const baseUrl = target.runtime_base_url!;
    const dynamic = await runDynamicLayer({
      baseUrl,
      config: (target.dynamic ?? {}) as never,
      timeoutMs: options.timeoutMs,
    });
    notes.push(...dynamic.notes);
    dynamicRequestLog.push(...(dynamic.requestLog as unknown as Array<Record<string, unknown>>));

    for (const { ruleFinding, dynamic: d } of dynamic.findings) {
      findings.push(
        buildFinding({
          ...ruleFinding,
          scan_run_id: runId,
          layer: 'dynamic-fuzzer',
          detected_by: 'dynamic-fuzzer',
          endpoint: `${d.method} ${d.itemPath}`,
          // A dynamic finding is a live demonstration by construction — it only
          // exists because the exploit was observed to work. So it is verified.
          status: 'verified-exploitable',
          now,
        }),
      );
    }

    scanners.push({
      name: 'dynamic-fuzzer',
      status: 'ran',
      detail:
        `${dynamic.resourcesTested} resource(s) tested against ${baseUrl}; ${dynamic.findings.length} ` +
        `cross-user access finding(s); ${dynamic.requestLog.length} request(s) made (rate-limited, logged)`,
      version: TOOL_VERSION,
      duration_ms: Date.now() - startedDynamic,
      findings_count: dynamic.findings.length,
    });
  }

  /* ---------------- normalise ---------------- */

  const store = options.storeRoot ? new FileStore(options.storeRoot) : null;
  const previous = store ? store.previousFindings(runId) : [];
  const normalised = sortFindings(applyHistory(dedupe(findings), previous));

  const scanRun: ScanRun = {
    id: runId,
    target_id: target.id,
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    layers_run: layersRun,
    status: 'completed',
    scanners,
    tool_version: TOOL_VERSION,
  };

  const report: ScanReport = {
    scan_run: scanRun,
    target,
    findings: normalised,
    verification_runs: verificationRuns,
    notes,
  };

  /* ---------------- persist + audit ---------------- */

  if (store) {
    const auditLog = store.openAuditLog();
    const before = auditLog.all().length;

    auditLog.append({
      actor: 'system',
      action: 'scan.started',
      target_id: target.id,
      payload: {
        run_id: runId,
        layers: layersRun,
        tool_version: TOOL_VERSION,
        authorization: decision.record,
        source_uri: target.source_uri,
      },
      created_at: startedAt,
    });

    for (const finding of normalised) {
      auditLog.append({
        actor: 'system',
        action: 'finding.recorded',
        target_id: target.id,
        finding_id: finding.id,
        payload: {
          run_id: runId,
          rule_id: finding.rule_id,
          severity: finding.severity,
          status: finding.status,
          file_path: finding.file_path,
          line: finding.line,
          fingerprint: finding.fingerprint,
          detected_by: finding.detected_by,
        },
        created_at: now,
      });
    }

    // Every sandbox request the verification layer made is part of the record,
    // per the requirement that the dynamic layers log what they did to a target.
    for (const run of verificationRuns) {
      auditLog.append({
        actor: 'agent',
        action: 'verification.executed',
        target_id: target.id,
        finding_id: run.finding_id,
        payload: {
          run_id: runId,
          verification_id: run.id,
          method: run.method,
          result: run.result,
          sandbox_ref: run.sandbox_ref,
          requests: run.evidence.requests,
          state_assertion: run.evidence.state_assertion,
        },
        created_at: run.executed_at,
      });
    }

    // Every live request the dynamic fuzzer made against the running target,
    // per the requirement to log what the dynamic layer did to a real system.
    // One entry carries the full ordered request trail (target, path, method,
    // timestamp, status) so the audit log is a complete record of the traffic.
    if (dynamicRequestLog.length > 0) {
      auditLog.append({
        actor: 'agent',
        action: 'dynamic.requests',
        target_id: target.id,
        payload: {
          run_id: runId,
          base_url: target.runtime_base_url,
          request_count: dynamicRequestLog.length,
          requests: dynamicRequestLog,
        },
        created_at: now,
      });
    }

    auditLog.append({
      actor: 'system',
      action: 'scan.completed',
      target_id: target.id,
      payload: {
        run_id: runId,
        findings: normalised.length,
        verified_exploitable: normalised.filter((f) => f.status === 'verified-exploitable').length,
        scanners: scanners.map((s) => ({ name: s.name, status: s.status, findings: s.findings_count })),
      },
      created_at: scanRun.completed_at ?? now,
    });

    store.appendAuditEntries(auditLog.all().slice(before));
    store.saveReport(report);
  }

  return report;
}
