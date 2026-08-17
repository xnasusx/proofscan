import { lineAtOffset } from '../../core/walk.js';

/**
 * CREATE TABLE extraction.
 *
 * Runs over raw file text rather than the AST so it works identically for SQL
 * embedded in template literals, SQL in ordinary string literals, and .sql
 * files. The cost is that a CREATE TABLE inside a comment is still extracted —
 * acceptable, since a commented-out schema that disagrees with the live one is
 * itself worth surfacing.
 */

const CREATE_TABLE_RE =
  /\bCREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`"'[\]\w.]+)\s*\(/gi;

/** Column-level constraints that change the integrity guarantees of a column. */
const CONSTRAINT_PATTERNS: Array<{ flag: string; pattern: RegExp }> = [
  { flag: 'NOT NULL', pattern: /\bNOT\s+NULL\b/i },
  { flag: 'PRIMARY KEY', pattern: /\bPRIMARY\s+KEY\b/i },
  { flag: 'UNIQUE', pattern: /\bUNIQUE\b/i },
  { flag: 'AUTOINCREMENT', pattern: /\bAUTO_?INCREMENT\b/i },
  { flag: 'REFERENCES', pattern: /\bREFERENCES\b/i },
  { flag: 'CHECK', pattern: /\bCHECK\s*\(/i },
  { flag: 'ON DELETE CASCADE', pattern: /\bON\s+DELETE\s+CASCADE\b/i },
];

/** Table-level clauses that are not column definitions. */
const TABLE_LEVEL_RE = /^\s*(PRIMARY\s+KEY|FOREIGN\s+KEY|UNIQUE\s*\(|CHECK\s*\(|CONSTRAINT\b|INDEX\b|KEY\s*\()/i;

export interface ColumnDef {
  name: string;
  type: string;
  /** Sorted, normalised constraint flags. */
  constraints: string[];
  /** DEFAULT expression, normalised, or null. */
  defaultValue: string | null;
  raw: string;
}

export interface TableDef {
  table: string;
  filePath: string;
  line: number;
  columns: ColumnDef[];
}

function unquoteIdentifier(name: string): string {
  return name.replace(/[`"'[\]]/g, '').trim();
}

/** Read from the character after an opening paren to its match. Returns null if unbalanced. */
function readBalanced(text: string, openParenIndex: number): { body: string; end: number } | null {
  let depth = 0;
  let inSingle = false;
  let inDouble = false;

  for (let i = openParenIndex; i < text.length; i++) {
    const ch = text[i];

    if (inSingle) {
      if (ch === "'") inSingle = false;
      continue;
    }
    if (inDouble) {
      if (ch === '"') inDouble = false;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      continue;
    }

    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return { body: text.slice(openParenIndex + 1, i), end: i };
    }
  }
  return null;
}

/** Split a column list on commas that are at paren depth zero and outside quotes. */
function splitTopLevel(body: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  let current = '';

  for (const ch of body) {
    if (inSingle) {
      current += ch;
      if (ch === "'") inSingle = false;
      continue;
    }
    if (inDouble) {
      current += ch;
      if (ch === '"') inDouble = false;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      current += ch;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      current += ch;
      continue;
    }
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) {
      parts.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current);
  return parts;
}

function parseColumn(raw: string): ColumnDef | null {
  const trimmed = raw.trim().replace(/\s+/g, ' ');
  if (!trimmed || TABLE_LEVEL_RE.test(trimmed)) return null;

  const match = /^([`"'[\]\w]+)\s*(.*)$/.exec(trimmed);
  if (!match) return null;

  const name = unquoteIdentifier(match[1]!);
  if (!name) return null;
  const remainder = match[2] ?? '';

  const typeMatch = /^([A-Za-z_]+(?:\s*\([^)]*\))?)/.exec(remainder);
  const type = (typeMatch?.[1] ?? '').replace(/\s+/g, '').toUpperCase();

  const constraints = CONSTRAINT_PATTERNS.filter((c) => c.pattern.test(remainder)).map((c) => c.flag);

  const defaultMatch = /\bDEFAULT\s+('[^']*'|"[^"]*"|\S+)/i.exec(remainder);
  const defaultValue = defaultMatch ? defaultMatch[1]!.trim() : null;

  return { name, type, constraints: constraints.sort(), defaultValue, raw: trimmed };
}

export function extractTableDefs(filePath: string, text: string): TableDef[] {
  const tables: TableDef[] = [];
  CREATE_TABLE_RE.lastIndex = 0;

  let match: RegExpExecArray | null;
  while ((match = CREATE_TABLE_RE.exec(text)) !== null) {
    const rawName = match[1]!;
    // The regex consumed the '(' so it sits at the end of the match.
    const openParen = match.index + match[0].length - 1;
    const balanced = readBalanced(text, openParen);
    if (!balanced) continue;

    const columns = splitTopLevel(balanced.body)
      .map(parseColumn)
      .filter((c): c is ColumnDef => c !== null);

    if (columns.length === 0) continue;

    // Compare on the bare table name so `main.users` and `users` collide, which
    // is the behaviour we want for drift detection.
    const table = unquoteIdentifier(rawName).split('.').pop() ?? unquoteIdentifier(rawName);

    tables.push({
      table: table.toLowerCase(),
      filePath,
      line: lineAtOffset(text, match.index),
      columns,
    });

    CREATE_TABLE_RE.lastIndex = balanced.end;
  }

  return tables;
}

/** A single column-level disagreement between two definitions of one table. */
export interface ColumnDifference {
  column: string;
  kind: 'constraints' | 'type' | 'default' | 'presence';
  detail: string;
}

export function compareTableDefs(a: TableDef, b: TableDef): ColumnDifference[] {
  const differences: ColumnDifference[] = [];
  const aByName = new Map(a.columns.map((c) => [c.name.toLowerCase(), c]));
  const bByName = new Map(b.columns.map((c) => [c.name.toLowerCase(), c]));

  for (const [name, colA] of aByName) {
    const colB = bByName.get(name);
    if (!colB) {
      differences.push({
        column: colA.name,
        kind: 'presence',
        detail: `present in ${a.filePath} but missing from ${b.filePath}`,
      });
      continue;
    }

    const onlyInA = colA.constraints.filter((c) => !colB.constraints.includes(c));
    const onlyInB = colB.constraints.filter((c) => !colA.constraints.includes(c));
    if (onlyInA.length > 0 || onlyInB.length > 0) {
      const clauses: string[] = [];
      if (onlyInA.length > 0) clauses.push(`${a.filePath} has ${onlyInA.join(', ')}`);
      if (onlyInB.length > 0) clauses.push(`${b.filePath} has ${onlyInB.join(', ')}`);
      differences.push({ column: colA.name, kind: 'constraints', detail: clauses.join('; ') });
    }

    if (colA.type && colB.type && colA.type !== colB.type) {
      differences.push({
        column: colA.name,
        kind: 'type',
        detail: `${colA.type} in ${a.filePath} vs ${colB.type} in ${b.filePath}`,
      });
    }

    const defA = colA.defaultValue?.toLowerCase() ?? null;
    const defB = colB.defaultValue?.toLowerCase() ?? null;
    if (defA !== defB) {
      differences.push({
        column: colA.name,
        kind: 'default',
        detail: `DEFAULT ${colA.defaultValue ?? 'absent'} in ${a.filePath} vs ${colB.defaultValue ?? 'absent'} in ${b.filePath}`,
      });
    }
  }

  for (const [name, colB] of bByName) {
    if (!aByName.has(name)) {
      differences.push({
        column: colB.name,
        kind: 'presence',
        detail: `present in ${b.filePath} but missing from ${a.filePath}`,
      });
    }
  }

  return differences;
}
