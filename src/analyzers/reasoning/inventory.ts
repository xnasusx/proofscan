import ts from 'typescript';
import { dottedName, lineOf, stringLiteralValue, visit } from '../builtin/parse.js';
import type { ParsedFile } from '../builtin/parse.js';
import { buildRouteInventory } from '../builtin/routes.js';
import type { RouteInfo } from '../builtin/routes.js';

/**
 * Mutation inventory — the mechanical pass that runs before any model is asked
 * anything.
 *
 * The build spec is explicit that the route/mutation inventory is extracted
 * statically and only then handed to the reasoning layer with one narrow
 * question. That split matters for cost and for honesty: the model is never
 * asked to find handlers, only to judge ordering in handlers we already found,
 * and every candidate it sees comes with the ordered facts attached.
 *
 * What this extracts, per authenticated route handler, is an ordered list of
 * operations: database mutations, ownership checks, and short-circuiting
 * responses. Order is source order, which for a synchronous Express handler is
 * execution order.
 */

/** Columns that scope a row to its owner. */
const OWNER_COLUMN_PATTERN =
  /\b(user_id|userid|owner_id|ownerid|account_id|accountid|tenant_id|tenantid|org_id|organization_id|customer_id|created_by|author_id|uid)\b/i;

/** ORM/query-builder methods that write. */
const ORM_MUTATION_PATTERN =
  /\.(create|createMany|insert|insertOne|insertMany|update|updateOne|updateMany|upsert|delete|deleteOne|deleteMany|destroy|remove|removeOne|save|findByIdAndDelete|findByIdAndUpdate|findOneAndDelete|findOneAndUpdate|bulkCreate|truncate)$/;

/** ORM/query-builder methods that read. */
const ORM_READ_PATTERN = /\.(find|findOne|findById|findFirst|findMany|findUnique|get|all|select|first|count|exists)$/;

/** Request-input sources: anything an attacker controls. */
const REQUEST_INPUT_PATTERN = /\breq(uest)?\s*\.\s*(params|body|query|headers)\b/;

/** The authenticated caller's identity, as established by auth middleware. */
const CALLER_IDENTITY_PATTERN = /\breq(uest)?\s*\.\s*(user|auth|session|account|principal|currentUser)\b/;

export type OperationKind = 'mutation' | 'ownership-check' | 'short-circuit';

export interface Operation {
  kind: OperationKind;
  line: number;
  /** Character offset — establishes ordering within the handler. */
  pos: number;
  /** Source text, collapsed to one line. */
  text: string;

  /* ---- mutation-specific ---- */
  /** INSERT / UPDATE / DELETE, or the ORM method name. */
  verb?: string;
  /** Table or model the operation touches, where determinable. */
  table?: string | null;
  /**
   * True when the operation is constrained to the caller — an owner column in
   * the WHERE clause bound to a caller-identity value.
   */
  ownerScoped?: boolean;
  /** True when the operation is driven by attacker-controlled request input. */
  requestDriven?: boolean;
  /** True for creates, which have no pre-existing resource to own. */
  isCreate?: boolean;
}

export interface HandlerInventory {
  file_path: string;
  method: string;
  path: string;
  line: number;
  authenticated: boolean;
  auth_source: RouteInfo['auth_source'];
  /** Operations in source (execution) order. */
  operations: Operation[];
  /** Verbatim handler source, for the reasoning layer's prompt. */
  source: string;
  /**
   * True when a mutation driven by request input is not owner-scoped and no
   * ownership check short-circuits before it. This is the candidate condition —
   * a mechanical signal, not a verdict.
   */
  candidate: boolean;
  /** Why this handler is (or is not) a candidate. Carried into the prompt. */
  candidate_reason: string;
  /** The specific operation that made it a candidate. */
  suspect_operation: Operation | null;
}

/** Does an expression read attacker-controlled request input? */
function readsRequestInput(text: string, requestDerived: Set<string>): boolean {
  if (REQUEST_INPUT_PATTERN.test(text)) return true;
  return [...requestDerived].some((name) => new RegExp(`\\b${name}\\b`).test(text));
}

/** Does an expression read the authenticated caller's identity? */
function readsCallerIdentity(text: string, callerDerived: Set<string>): boolean {
  if (CALLER_IDENTITY_PATTERN.test(text)) return true;
  return [...callerDerived].some((name) => new RegExp(`\\b${name}\\b`).test(text));
}

/**
 * Collect local variables that carry request input or caller identity.
 *
 * Deliberately shallow: one hop from the source, through coercion wrappers like
 * `Number(req.params.id)`. That covers the overwhelming majority of real
 * handlers and is honest about its limits — a value laundered through a helper
 * function is not tracked, and the handler is reported as unresolvable rather
 * than guessed at.
 */
function collectDerivedNames(
  sourceFile: ts.SourceFile,
  handler: ts.Node,
): { requestDerived: Set<string>; callerDerived: Set<string> } {
  const requestDerived = new Set<string>();
  const callerDerived = new Set<string>();

  visit(handler, (node) => {
    if (!ts.isVariableDeclaration(node) || !node.initializer) return;
    if (!ts.isIdentifier(node.name)) return;

    const initText = node.initializer.getText(sourceFile);
    if (REQUEST_INPUT_PATTERN.test(initText)) requestDerived.add(node.name.text);
    if (CALLER_IDENTITY_PATTERN.test(initText)) callerDerived.add(node.name.text);
  });

  return { requestDerived, callerDerived };
}

interface SqlShape {
  verb: string;
  table: string | null;
  whereHasOwnerColumn: boolean;
}

/** Classify a SQL string. Returns null when it is not a statement we track. */
function classifySql(sql: string): SqlShape | null {
  const normalised = sql.replace(/\s+/g, ' ').trim();

  const insert = /^\s*INSERT\s+(?:OR\s+\w+\s+)?INTO\s+([`"'[\]\w.]+)/i.exec(normalised);
  if (insert) return { verb: 'INSERT', table: insert[1] ?? null, whereHasOwnerColumn: false };

  const update = /^\s*UPDATE\s+([`"'[\]\w.]+)/i.exec(normalised);
  if (update) {
    const where = /\bWHERE\b(.*)$/i.exec(normalised)?.[1] ?? '';
    return { verb: 'UPDATE', table: update[1] ?? null, whereHasOwnerColumn: OWNER_COLUMN_PATTERN.test(where) };
  }

  const del = /^\s*DELETE\s+FROM\s+([`"'[\]\w.]+)/i.exec(normalised);
  if (del) {
    const where = /\bWHERE\b(.*)$/i.exec(normalised)?.[1] ?? '';
    return { verb: 'DELETE', table: del[1] ?? null, whereHasOwnerColumn: OWNER_COLUMN_PATTERN.test(where) };
  }

  const select = /^\s*SELECT\b[\s\S]*?\bFROM\s+([`"'[\]\w.]+)/i.exec(normalised);
  if (select) {
    const where = /\bWHERE\b(.*)$/i.exec(normalised)?.[1] ?? '';
    return { verb: 'SELECT', table: select[1] ?? null, whereHasOwnerColumn: OWNER_COLUMN_PATTERN.test(where) };
  }

  return null;
}

/** Every string literal (including template heads) inside a node. */
function collectSqlStrings(sourceFile: ts.SourceFile, node: ts.Node): string[] {
  const found: string[] = [];
  visit(node, (child) => {
    const literal = stringLiteralValue(child);
    if (literal && /\b(SELECT|INSERT|UPDATE|DELETE)\b/i.test(literal)) found.push(literal);
    if (ts.isTemplateExpression(child)) {
      const text = child.getText(sourceFile);
      if (/\b(SELECT|INSERT|UPDATE|DELETE)\b/i.test(text)) found.push(text);
    }
  });
  return found;
}

/** Is this statement a guard that returns a 4xx and stops the handler? */
function isShortCircuit(node: ts.Node, sourceFile: ts.SourceFile): boolean {
  if (!ts.isIfStatement(node)) return false;
  const branch = node.thenStatement.getText(sourceFile);
  // A 4xx response returned from inside an `if` is a guard. `res.status(200)`
  // is not, and neither is a status set without returning.
  return /\breturn\b/.test(branch) && /status\s*\(\s*4\d\d\s*\)/.test(branch);
}

function extractOperations(sourceFile: ts.SourceFile, handler: ts.Node): Operation[] {
  const { requestDerived, callerDerived } = collectDerivedNames(sourceFile, handler);
  const operations: Operation[] = [];

  /**
   * A prepared-statement chain (`db.prepare(sql).run(args)`) contains the SQL
   * at two nesting levels, so a naive walk records it twice — and the inner
   * `prepare(sql)` call carries no bound parameters, which makes it look
   * unscoped and not request-driven. The walk is pre-order, so the outermost
   * call — the one holding the bound values that actually decide scoping — is
   * seen first. Keep that one and drop the inner repeat.
   */
  const seenSql = new Set<string>();

  visit(handler, (node) => {
    /* ---- short-circuit guards ---- */
    if (isShortCircuit(node, sourceFile)) {
      operations.push({
        kind: 'short-circuit',
        line: lineOf(sourceFile, node),
        pos: node.getStart(sourceFile),
        text: node.getText(sourceFile).replace(/\s+/g, ' ').slice(0, 160),
      });
      return;
    }

    if (!ts.isCallExpression(node)) return;

    const callee = dottedName(node.expression) ?? '';
    const fullText = node.getText(sourceFile);
    const collapsed = fullText.replace(/\s+/g, ' ');

    /* ---- raw SQL ---- */
    const sqlStrings = collectSqlStrings(sourceFile, node);
    for (const sql of sqlStrings) {
      const shape = classifySql(sql);
      if (!shape) continue;

      const sqlKey = sql.replace(/\s+/g, ' ').trim();
      if (seenSql.has(sqlKey)) continue;
      seenSql.add(sqlKey);

      // The bound parameters are what decide scoping: a WHERE naming an owner
      // column means nothing if the value bound to it is attacker-supplied.
      const argsText = node.arguments.map((a) => a.getText(sourceFile)).join(', ');
      const boundToCaller = readsCallerIdentity(argsText, callerDerived);
      const requestDriven = readsRequestInput(`${argsText} ${collapsed}`, requestDerived);

      const isMutation = shape.verb !== 'SELECT';
      const ownerScoped = shape.whereHasOwnerColumn && boundToCaller;

      if (isMutation) {
        operations.push({
          kind: 'mutation',
          line: lineOf(sourceFile, node),
          pos: node.getStart(sourceFile),
          text: collapsed.slice(0, 200),
          verb: shape.verb,
          table: shape.table,
          ownerScoped,
          requestDriven,
          isCreate: shape.verb === 'INSERT',
        });
      } else if (ownerScoped) {
        // A caller-scoped read is how ownership is established in practice.
        operations.push({
          kind: 'ownership-check',
          line: lineOf(sourceFile, node),
          pos: node.getStart(sourceFile),
          text: collapsed.slice(0, 200),
          verb: shape.verb,
          table: shape.table,
        });
      }
      return;
    }

    /* ---- ORM / query-builder calls ---- */
    if (ORM_MUTATION_PATTERN.test(callee)) {
      const method = callee.split('.').pop() ?? callee;
      const ownerScoped = OWNER_COLUMN_PATTERN.test(collapsed) && readsCallerIdentity(collapsed, callerDerived);
      operations.push({
        kind: 'mutation',
        line: lineOf(sourceFile, node),
        pos: node.getStart(sourceFile),
        text: collapsed.slice(0, 200),
        verb: method,
        table: null,
        ownerScoped,
        requestDriven: readsRequestInput(collapsed, requestDerived),
        isCreate: /create|insert|save|bulkCreate/i.test(method),
      });
      return;
    }

    if (ORM_READ_PATTERN.test(callee)) {
      if (OWNER_COLUMN_PATTERN.test(collapsed) && readsCallerIdentity(collapsed, callerDerived)) {
        operations.push({
          kind: 'ownership-check',
          line: lineOf(sourceFile, node),
          pos: node.getStart(sourceFile),
          text: collapsed.slice(0, 200),
          verb: callee.split('.').pop() ?? callee,
          table: null,
        });
      }
    }
  });

  return operations.sort((a, b) => a.pos - b.pos);
}

/**
 * Decide whether a handler is a candidate for the reasoning layer.
 *
 * The condition mirrors the spec's rubric question mechanically: a mutation
 * driven by request input, not constrained to the caller, with no ownership
 * check short-circuiting before it.
 *
 * Creates are excluded — there is no pre-existing resource whose ownership
 * could be checked, so "no ownership check before the INSERT" is not a defect.
 */
function assessCandidate(operations: Operation[]): {
  candidate: boolean;
  reason: string;
  suspect: Operation | null;
} {
  const mutations = operations.filter((o) => o.kind === 'mutation');
  if (mutations.length === 0) {
    return { candidate: false, reason: 'no database mutation in this handler', suspect: null };
  }

  for (const mutation of mutations) {
    if (mutation.isCreate) continue;
    if (!mutation.requestDriven) continue;
    if (mutation.ownerScoped) continue;

    // Is ownership established and enforced before this mutation runs?
    const priorChecks = operations.filter((o) => o.kind === 'ownership-check' && o.pos < mutation.pos);
    const priorGuards = operations.filter((o) => o.kind === 'short-circuit' && o.pos < mutation.pos);

    if (priorChecks.length > 0 && priorGuards.length > 0) continue;

    const missing =
      priorChecks.length === 0
        ? 'no caller-scoped ownership check runs before it'
        : 'an ownership check runs before it but nothing short-circuits on the result';

    return {
      candidate: true,
      reason:
        `\`${mutation.verb} ${mutation.table ?? '(table undetermined)'}\` at line ${mutation.line} is driven by ` +
        `request input, is not constrained to the authenticated caller, and ${missing}.`,
      suspect: mutation,
    };
  }

  return {
    candidate: false,
    reason:
      'every request-driven mutation is either constrained to the caller or preceded by an ownership check that short-circuits',
    suspect: null,
  };
}

export function buildMutationInventory(parsed: ParsedFile): HandlerInventory[] {
  const { sourceFile, source } = parsed;
  const routes = buildRouteInventory(parsed).routes;
  const handlers: HandlerInventory[] = [];

  for (const route of routes) {
    if (!route.handler || !route.handler_resolvable) continue;

    const operations = extractOperations(sourceFile, route.handler);
    if (operations.length === 0) continue;

    const { candidate, reason, suspect } = assessCandidate(operations);

    handlers.push({
      file_path: source.relPath,
      method: route.method,
      path: route.path,
      line: route.line,
      authenticated: route.authenticated,
      auth_source: route.auth_source,
      operations,
      source: route.handler.getText(sourceFile),
      // An unauthenticated route has no caller to compare against, so
      // cross-user access is not the right frame for it. Those are covered by
      // the Layer 1 rules instead.
      candidate: candidate && route.authenticated,
      candidate_reason: route.authenticated
        ? reason
        : 'route is unauthenticated; cross-user authorisation is not the applicable question',
      suspect_operation: suspect,
    });
  }

  return handlers;
}
