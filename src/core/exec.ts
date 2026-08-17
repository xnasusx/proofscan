import { spawn } from 'node:child_process';

export interface ExecResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** True when the binary itself could not be found. */
  notFound: boolean;
}

export interface ExecOptions {
  cwd?: string;
  timeoutMs?: number;
  /** Bytes of stdout to retain. Scanner JSON can be large but not unbounded. */
  maxBuffer?: number;
}

const DEFAULT_TIMEOUT_MS = 300_000;
const DEFAULT_MAX_BUFFER = 64 * 1024 * 1024;

/**
 * Resolve a bare command name to the form the OS can spawn without a shell.
 *
 * On Windows, `npm`, `npx`, `semgrep`, `gitleaks` and friends installed via npm
 * or scoop are `.cmd`/`.exe` shims, and `spawn` with `shell: false` will not
 * find a bare `npm` — it looks for a literal file called `npm` and ENOENTs.
 * `node` works only because it is a real `node.exe`. Appending `.cmd` for the
 * known shim-based tools keeps `shell: false` (so no command-injection surface)
 * while resolving correctly on Windows; POSIX is unaffected.
 */
const WINDOWS_CMD_SHIMS = new Set(['npm', 'npx', 'yarn', 'pnpm']);

export function resolveBinary(cmd: string): string {
  if (process.platform !== 'win32') return cmd;
  if (WINDOWS_CMD_SHIMS.has(cmd)) return `${cmd}.cmd`;
  return cmd;
}

/**
 * Run an external binary and capture output.
 *
 * `shell: false` throughout — arguments are passed as an array and never
 * interpolated into a command string, so target paths containing shell
 * metacharacters cannot become command injection in our own tool.
 */
export function exec(cmd: string, args: string[], options: ExecOptions = {}): Promise<ExecResult> {
  const resolved = resolveBinary(cmd);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBuffer = options.maxBuffer ?? DEFAULT_MAX_BUFFER;

  return new Promise((resolve) => {
    // Node 18.20+/20.12+/22+ refuse to spawn a Windows .cmd/.bat shim with
    // shell:false (the CVE-2024-27980 batch-file fix throws EINVAL), and
    // spawning it with shell:true + an args array is deprecated (DEP0190). The
    // warning-free, injection-free path is to run the shim through `cmd.exe /c`
    // (a real executable, so shell:false works). Scoped to the npm-family shims
    // resolveBinary rewrote; every other command spawns directly with
    // shell:false, so no user-controlled value is ever shell-interpolated.
    const isWindowsShim = process.platform === 'win32' && /\.(cmd|bat)$/i.test(resolved);
    const spawnCmd = isWindowsShim ? process.env.ComSpec || 'cmd.exe' : resolved;
    const spawnArgs = isWindowsShim ? ['/d', '/s', '/c', resolved, ...args] : args;

    let child;
    try {
      child = spawn(spawnCmd, spawnArgs, {
        cwd: options.cwd,
        shell: false,
        windowsHide: true,
      });
    } catch (err) {
      resolve({
        code: null,
        stdout: '',
        stderr: (err as Error).message,
        timedOut: false,
        notFound: true,
      });
      return;
    }

    const out: Buffer[] = [];
    const errOut: Buffer[] = [];
    let outBytes = 0;
    let settled = false;
    let timedOut = false;
    let notFound = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    child.stdout?.on('data', (chunk: Buffer) => {
      outBytes += chunk.length;
      if (outBytes <= maxBuffer) out.push(chunk);
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      if (errOut.length < 4096) errOut.push(chunk);
    });

    child.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ENOENT') notFound = true;
      errOut.push(Buffer.from(err.message));
    });

    const finish = (code: number | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        code,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(errOut).toString('utf8'),
        timedOut,
        notFound,
      });
    };

    child.on('close', finish);
  });
}

/**
 * Resolve a scanner's version string, or null when the binary is unavailable.
 * Used for both PATH detection and provenance in the report.
 */
export async function detectVersion(
  cmd: string,
  args: string[] = ['--version'],
): Promise<string | null> {
  const result = await exec(cmd, args, { timeoutMs: 20_000 });
  if (result.notFound) return null;
  // Some tools print the version to stderr, and some exit non-zero doing it.
  const text = `${result.stdout}${result.stderr}`.trim();
  if (!text) return null;
  const firstLine = text.split(/\r?\n/).find((l) => l.trim().length > 0);
  return firstLine ? firstLine.trim() : null;
}
