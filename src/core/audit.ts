import { createHash, randomUUID } from 'node:crypto';
import type { AuditLogEntry } from '../types.js';

/**
 * Append-only, hash-chained audit log.
 *
 * Each entry's hash covers the previous entry's hash, so removing or editing
 * any entry breaks every hash after it. This makes tampering and truncation
 * detectable; it does not make them impossible. An attacker with write access
 * to the log file can recompute the whole chain. Detecting that requires
 * anchoring the head hash somewhere the attacker does not control (a signed
 * commit, an append-only bucket, a witness service) — not implemented here, and
 * called out in the README's limits rather than left implied.
 */

/** Deterministic JSON: keys sorted at every level, so hashes are reproducible. */
export function canonicalise(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalise).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalise(v)}`).join(',')}}`;
}

export function computeEntryHash(entry: Omit<AuditLogEntry, 'entry_hash'>): string {
  const material = canonicalise({
    id: entry.id,
    prev_entry_hash: entry.prev_entry_hash,
    actor: entry.actor,
    action: entry.action,
    target_id: entry.target_id,
    finding_id: entry.finding_id,
    payload: entry.payload,
    created_at: entry.created_at,
  });
  return createHash('sha256').update(material).digest('hex');
}

export class AuditLog {
  private entries: AuditLogEntry[];

  constructor(existing: AuditLogEntry[] = []) {
    this.entries = [...existing];
  }

  get head(): string | null {
    const last = this.entries.at(-1);
    return last ? last.entry_hash : null;
  }

  all(): AuditLogEntry[] {
    return [...this.entries];
  }

  append(input: {
    actor: string;
    action: string;
    target_id?: string | null;
    finding_id?: string | null;
    payload?: Record<string, unknown>;
    created_at: string;
  }): AuditLogEntry {
    const withoutHash: Omit<AuditLogEntry, 'entry_hash'> = {
      id: randomUUID(),
      prev_entry_hash: this.head,
      actor: input.actor,
      action: input.action,
      target_id: input.target_id ?? null,
      finding_id: input.finding_id ?? null,
      payload: input.payload ?? {},
      created_at: input.created_at,
    };
    const entry: AuditLogEntry = {
      ...withoutHash,
      entry_hash: computeEntryHash(withoutHash),
    };
    this.entries.push(entry);
    return entry;
  }
}

export interface ChainVerification {
  ok: boolean;
  entries_checked: number;
  problems: Array<{ index: number; id: string; problem: string }>;
}

export function verifyChain(entries: AuditLogEntry[]): ChainVerification {
  const problems: ChainVerification['problems'] = [];

  entries.forEach((entry, index) => {
    const expectedPrev = index === 0 ? null : (entries[index - 1]?.entry_hash ?? null);
    if (entry.prev_entry_hash !== expectedPrev) {
      problems.push({
        index,
        id: entry.id,
        problem: `prev_entry_hash is ${entry.prev_entry_hash ?? 'null'}, expected ${expectedPrev ?? 'null'} — an entry was removed, reordered, or inserted`,
      });
    }
    const { entry_hash, ...rest } = entry;
    const recomputed = computeEntryHash(rest);
    if (recomputed !== entry_hash) {
      problems.push({
        index,
        id: entry.id,
        problem: `entry_hash does not match its contents — this entry was edited after it was written`,
      });
    }
  });

  return { ok: problems.length === 0, entries_checked: entries.length, problems };
}
