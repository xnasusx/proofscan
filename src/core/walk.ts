import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

/** Directories never worth scanning. Kept small and explicit. */
const DEFAULT_IGNORE_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  'out',
  'coverage',
  '.next',
  '.nuxt',
  '.svelte-kit',
  'vendor',
  '__pycache__',
  '.venv',
  'venv',
  '.tox',
  '.mypy_cache',
  '.pytest_cache',
  '.gradle',
  'target',
  '.terraform',
  '.proofscan',
]);

const ANALYSABLE_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.mts',
  '.cts',
  '.sql',
]);

/** Files above this size are skipped; they are generated or vendored in practice. */
const MAX_FILE_BYTES = 2 * 1024 * 1024;

export interface SourceFile {
  /** Absolute path on disk. */
  absPath: string;
  /** Path relative to the scan root, with forward slashes. Used in reports. */
  relPath: string;
  ext: string;
  text: string;
}

export interface WalkResult {
  files: SourceFile[];
  /** Paths skipped, with the reason. Surfaced as coverage notes. */
  skipped: Array<{ relPath: string; reason: string }>;
}

function toPosix(p: string): string {
  return p.split(sep).join('/');
}

export function extensionOf(path: string): string {
  const idx = path.lastIndexOf('.');
  return idx === -1 ? '' : path.slice(idx).toLowerCase();
}

/**
 * Collect analysable source files under `root`.
 *
 * Deliberately does not honour .gitignore: a scanner that skips files because
 * the repo ignores them will miss committed-then-ignored secrets. It honours
 * only the fixed directory list above.
 */
export function walkSource(root: string): WalkResult {
  const files: SourceFile[] = [];
  const skipped: Array<{ relPath: string; reason: string }> = [];

  const visit = (dir: string): void => {
    let entries: ReturnType<typeof readdirSync>;
    try {
      entries = readdirSync(dir, { withFileTypes: true }) as never;
    } catch (err) {
      skipped.push({
        relPath: toPosix(relative(root, dir)) || '.',
        reason: `unreadable directory: ${(err as Error).message}`,
      });
      return;
    }

    for (const entry of entries as unknown as Array<{
      name: string;
      isDirectory(): boolean;
      isFile(): boolean;
      isSymbolicLink(): boolean;
    }>) {
      const abs = join(dir, entry.name);
      const rel = toPosix(relative(root, abs));

      // Do not follow symlinks: they can escape the scan root entirely.
      if (entry.isSymbolicLink()) {
        skipped.push({ relPath: rel, reason: 'symlink not followed' });
        continue;
      }

      if (entry.isDirectory()) {
        if (DEFAULT_IGNORE_DIRS.has(entry.name)) continue;
        visit(abs);
        continue;
      }

      if (!entry.isFile()) continue;

      const ext = extensionOf(entry.name);
      if (!ANALYSABLE_EXTENSIONS.has(ext)) continue;

      let size: number;
      try {
        size = statSync(abs).size;
      } catch {
        skipped.push({ relPath: rel, reason: 'unreadable file' });
        continue;
      }

      if (size > MAX_FILE_BYTES) {
        skipped.push({
          relPath: rel,
          reason: `larger than ${MAX_FILE_BYTES} bytes (${size}), not analysed`,
        });
        continue;
      }

      try {
        files.push({ absPath: abs, relPath: rel, ext, text: readFileSync(abs, 'utf8') });
      } catch (err) {
        skipped.push({ relPath: rel, reason: `read failed: ${(err as Error).message}` });
      }
    }
  };

  visit(root);
  files.sort((a, b) => a.relPath.localeCompare(b.relPath));
  return { files, skipped };
}

/** 1-indexed line number for a character offset. */
export function lineAtOffset(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

/** The 1-indexed source line, trimmed. Returns null when out of range. */
export function lineText(text: string, line: number): string | null {
  const lines = text.split(/\r?\n/);
  const value = lines[line - 1];
  return value === undefined ? null : value.trim();
}
