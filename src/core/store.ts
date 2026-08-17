import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AuditLogEntry, Finding, ScanReport } from '../types.js';
import { AuditLog } from './audit.js';

/**
 * JSON file store.
 *
 * Phase 1 only. The directory layout mirrors the Postgres tables in the spec so
 * that swapping in a real database later is a store-interface change and not a
 * schema redesign.
 *
 *   <root>/.proofscan/runs/<run-id>.json   one ScanReport per run
 *   <root>/.proofscan/audit.jsonl          the hash-chained audit log
 */
export class FileStore {
  readonly dir: string;

  constructor(root: string) {
    this.dir = join(root, '.proofscan');
  }

  private get runsDir(): string {
    return join(this.dir, 'runs');
  }

  private get auditPath(): string {
    return join(this.dir, 'audit.jsonl');
  }

  ensure(): void {
    mkdirSync(this.runsDir, { recursive: true });
  }

  saveReport(report: ScanReport): string {
    this.ensure();
    const path = join(this.runsDir, `${report.scan_run.id}.json`);
    writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    return path;
  }

  /** Findings from the most recent completed run, for first_seen_at carry-forward. */
  /** Every stored report, newest first. */
  private allReports(): ScanReport[] {
    if (!existsSync(this.runsDir)) return [];
    let names: string[];
    try {
      names = readdirSync(this.runsDir).filter((n) => n.endsWith('.json'));
    } catch {
      return [];
    }

    const reports: ScanReport[] = [];
    for (const name of names) {
      try {
        const parsed = JSON.parse(readFileSync(join(this.runsDir, name), 'utf8')) as ScanReport;
        if (parsed?.scan_run?.id) reports.push(parsed);
      } catch {
        // A corrupt report must not stop the caller. Skipped here; the caller
        // surfaces "no report found" rather than crashing.
      }
    }
    reports.sort((a, b) => b.scan_run.started_at.localeCompare(a.scan_run.started_at));
    return reports;
  }

  /** The most recent stored report, or null when none exists. */
  latestReport(): ScanReport | null {
    return this.allReports()[0] ?? null;
  }

  previousFindings(excludeRunId: string): Finding[] {
    return this.allReports().find((r) => r.scan_run.id !== excludeRunId)?.findings ?? [];
  }

  loadAuditEntries(): AuditLogEntry[] {
    if (!existsSync(this.auditPath)) return [];
    const lines = readFileSync(this.auditPath, 'utf8').split(/\r?\n/).filter((l) => l.trim());
    const entries: AuditLogEntry[] = [];
    for (const line of lines) {
      try {
        entries.push(JSON.parse(line) as AuditLogEntry);
      } catch {
        // Preserved as a chain break rather than dropped: verifyChain will fail
        // loudly, which is the correct outcome for a damaged audit log.
      }
    }
    return entries;
  }

  openAuditLog(): AuditLog {
    return new AuditLog(this.loadAuditEntries());
  }

  /** Append only the entries not already on disk. */
  appendAuditEntries(entries: AuditLogEntry[]): void {
    if (entries.length === 0) return;
    this.ensure();
    const existing = new Set(this.loadAuditEntries().map((e) => e.id));
    const fresh = entries.filter((e) => !existing.has(e.id));
    if (fresh.length === 0) return;
    const payload = fresh.map((e) => JSON.stringify(e)).join('\n');
    writeFileSync(this.auditPath, `${payload}\n`, { encoding: 'utf8', flag: 'a' });
  }
}
