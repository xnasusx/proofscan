import type { RuleFinding } from '../../../types.js';
import { compareTableDefs, extractTableDefs } from '../sql.js';
import type { TableDef } from '../sql.js';
import type { SourceFile } from '../../../core/walk.js';

export const RULE_ID = 'proofscan.schema-drift';

/**
 * The same table defined more than once, with different constraints.
 *
 * Not a security scanner rule as such, and cheap to run repo-wide. It catches a
 * specific failure mode of generated code: a schema written twice — once in the
 * server bootstrap, once in a migration or init script — that then diverges.
 * Because both use CREATE TABLE IF NOT EXISTS, whichever runs first silently
 * wins and the other definition is never applied. The constraints a reviewer
 * reads in one file are not the constraints the database is enforcing.
 */

/** Constraints whose absence weakens data integrity, for choosing where to report. */
const INTEGRITY_CONSTRAINTS = new Set(['NOT NULL', 'UNIQUE', 'PRIMARY KEY', 'REFERENCES', 'CHECK']);

function integrityScore(def: TableDef): number {
  let score = 0;
  for (const column of def.columns) {
    for (const constraint of column.constraints) {
      if (INTEGRITY_CONSTRAINTS.has(constraint)) score++;
    }
  }
  return score;
}

export function run(files: SourceFile[]): RuleFinding[] {
  const byTable = new Map<string, TableDef[]>();

  for (const file of files) {
    for (const def of extractTableDefs(file.relPath, file.text)) {
      const existing = byTable.get(def.table);
      if (existing) existing.push(def);
      else byTable.set(def.table, [def]);
    }
  }

  const findings: RuleFinding[] = [];

  for (const [table, defs] of [...byTable.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    if (defs.length < 2) continue;

    // Compare each definition against the first; collapse to unique messages.
    const base = defs[0]!;
    const differences = new Map<string, string>();
    for (const other of defs.slice(1)) {
      for (const diff of compareTableDefs(base, other)) {
        differences.set(`${diff.column}|${diff.kind}|${diff.detail}`, `\`${diff.column}\`: ${diff.detail}`);
      }
    }

    if (differences.size === 0) continue;

    // Report against the weakest definition — that is the one to bring up to
    // parity, and the one whose constraints the database may be missing.
    const weakest = [...defs].sort((a, b) => {
      const byScore = integrityScore(a) - integrityScore(b);
      if (byScore !== 0) return byScore;
      return a.filePath.localeCompare(b.filePath);
    })[0]!;

    const locations = defs.map((d) => `${d.filePath}:${d.line}`).join(', ');
    const detail = [...differences.values()].map((d) => `  - ${d}`).join('\n');

    findings.push({
      rule_id: RULE_ID,
      title: `Table \`${table}\` is defined ${defs.length} times with different constraints`,
      description:
        `\`${table}\` is created in ${defs.length} places (${locations}) and the definitions disagree:\n${detail}\n` +
        `With \`CREATE TABLE IF NOT EXISTS\`, whichever statement runs first creates the table and every later ` +
        `definition is a no-op — no error is raised and no migration is applied. Which set of constraints the ` +
        `database is actually enforcing therefore depends on start-up order, and the constraints a reviewer ` +
        `reads in one file may not be the ones in force. Keep one definition and have the other path use it.`,
      file_path: weakest.filePath,
      line: weakest.line,
      severity: 'medium',
      exploitability_note:
        `Not directly attacker-triggered. The consequence is an integrity gap: where the definition that wins ` +
        `omits NOT NULL or UNIQUE, the application can write rows the stricter definition would have rejected — ` +
        `for example duplicate accounts on a column only one file marks UNIQUE. Confirm which definition ran ` +
        `against the live database before deciding what the real constraint set is.`,
      code_excerpt: null,
      cwe: ['CWE-1078'],
    });
  }

  return findings;
}
