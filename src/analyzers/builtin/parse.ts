import ts from 'typescript';
import type { SourceFile } from '../../core/walk.js';

export interface ParsedFile {
  source: SourceFile;
  sourceFile: ts.SourceFile;
  /** Non-zero when the file did not parse cleanly; reported as a coverage note. */
  parseErrorCount: number;
}

function scriptKindFor(ext: string): ts.ScriptKind {
  switch (ext) {
    case '.tsx':
      return ts.ScriptKind.TSX;
    case '.ts':
    case '.mts':
    case '.cts':
      return ts.ScriptKind.TS;
    case '.jsx':
      return ts.ScriptKind.JSX;
    default:
      return ts.ScriptKind.JS;
  }
}

export const JS_LIKE_EXTENSIONS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts']);

export function parseFile(source: SourceFile): ParsedFile {
  const sourceFile = ts.createSourceFile(
    source.relPath,
    source.text,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    scriptKindFor(source.ext),
  );

  // parseDiagnostics is not on the public type but is the only way to learn that
  // recovery happened. A file that failed to parse must not silently report zero
  // findings, so the count is surfaced to the caller.
  const diagnostics = (sourceFile as unknown as { parseDiagnostics?: unknown[] }).parseDiagnostics;

  return {
    source,
    sourceFile,
    parseErrorCount: Array.isArray(diagnostics) ? diagnostics.length : 0,
  };
}

/** Depth-first walk over every node. */
export function visit(node: ts.Node, callback: (node: ts.Node) => void): void {
  callback(node);
  node.forEachChild((child) => visit(child, callback));
}

/** 1-indexed line of a node's first token. */
export function lineOf(sourceFile: ts.SourceFile, node: ts.Node): number {
  const pos = node.getStart(sourceFile);
  return sourceFile.getLineAndCharacterOfPosition(pos).line + 1;
}

/** Dotted name for an identifier or property-access chain: `passport.authenticate`. */
export function dottedName(node: ts.Node): string | null {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) {
    const left = dottedName(node.expression);
    return left ? `${left}.${node.name.text}` : node.name.text;
  }
  if (ts.isCallExpression(node)) return dottedName(node.expression);
  return null;
}

/** The literal text of a string or no-substitution template, else null. */
export function stringLiteralValue(node: ts.Node): string | null {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return null;
}

export function isFunctionLike(node: ts.Node): boolean {
  return (
    ts.isArrowFunction(node) ||
    ts.isFunctionExpression(node) ||
    ts.isFunctionDeclaration(node)
  );
}

/** Property name of an object-literal member, for identifier, string and computed-string keys. */
export function propertyName(prop: ts.ObjectLiteralElementLike): string | null {
  const name = prop.name;
  if (!name) return null;
  if (ts.isIdentifier(name) || ts.isPrivateIdentifier(name)) return name.text;
  if (ts.isStringLiteral(name) || ts.isNumericLiteral(name)) return name.text;
  if (ts.isComputedPropertyName(name)) return stringLiteralValue(name.expression);
  return null;
}

/** Every module specifier the file imports or requires. */
export function importedModules(sourceFile: ts.SourceFile): string[] {
  const modules: string[] = [];
  visit(sourceFile, (node) => {
    if (ts.isImportDeclaration(node)) {
      const value = stringLiteralValue(node.moduleSpecifier);
      if (value) modules.push(value);
      return;
    }
    if (ts.isCallExpression(node)) {
      const callee = dottedName(node.expression);
      const isRequire = callee === 'require';
      const isDynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      if ((isRequire || isDynamicImport) && node.arguments.length > 0) {
        const value = stringLiteralValue(node.arguments[0]!);
        if (value) modules.push(value);
      }
    }
  });
  return modules;
}
