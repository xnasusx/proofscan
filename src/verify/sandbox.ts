import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { detectVersion, exec, resolveBinary } from '../core/exec.js';
import type { Sandbox, SandboxProvisionResult } from './types.js';

/**
 * Ephemeral local-process sandbox.
 *
 * Copies the target into a throwaway directory, repairs its dependencies for
 * this machine, starts it on a private port with an ephemeral signing key and
 * an isolated database, and tears the whole directory down afterwards.
 *
 * Why local-process rather than Docker: the build spec names Docker, and Docker
 * is the right isolation boundary for scanning an arbitrary untrusted target —
 * this process model shares the host kernel and network namespace and offers no
 * real containment. It is implemented because Docker is not always present (it
 * is not on the machine this was built on), and a verification layer that can
 * only run where Docker is installed cannot be demonstrated at all. The trade
 * is stated plainly in the README's limits, and the Docker provider is the
 * intended default once available. The gate that matters — only ever run
 * against authorised targets — lives above this layer regardless of provider.
 */

const PORT_RANGE_START = 47000;
const PORT_RANGE_END = 47999;

/** A deterministic-but-varied port from the instance id, to avoid collisions without Math.random. */
function portFor(ref: string): number {
  let hash = 0;
  for (const ch of ref) hash = (hash * 31 + ch.charCodeAt(0)) & 0x7fffffff;
  return PORT_RANGE_START + (hash % (PORT_RANGE_END - PORT_RANGE_START));
}

export interface LocalSandboxOptions {
  /** Absolute path to the target source. */
  sourceDir: string;
  /** Command to start the server, e.g. ['node', 'server.js']. */
  startCommand: string[];
  /** Environment variables to inject (the ephemeral signing key goes here). */
  env: Record<string, string>;
  /** How the server announces its port. */
  port: number;
  timeoutMs: number;
}

export interface NodeTargetProfile {
  startCommand: string[];
  /** Env the server needs; a fresh JWT secret and DB path are added by the provisioner. */
  baseEnv: Record<string, string>;
  /** Path under the sandbox that must be writable for the DB. */
  dbDir: string | null;
}

/**
 * Recognise how to launch a Node/Express target.
 *
 * Deliberately narrow: this reads package.json for a start script and an entry
 * file. A target it cannot confidently launch yields no profile, and the caller
 * reports the finding as unverified rather than guessing at a start command.
 */
export function detectNodeTarget(sourceDir: string): NodeTargetProfile | null {
  const pkgPath = join(sourceDir, 'package.json');
  if (!existsSync(pkgPath)) return null;

  // server.js is the fixture's entry and the most common Express convention.
  for (const entry of ['server.js', 'app.js', 'index.js', 'src/server.js', 'src/index.js']) {
    if (existsSync(join(sourceDir, entry))) {
      return {
        startCommand: ['node', entry],
        baseEnv: {},
        dbDir: existsSync(join(sourceDir, '..', 'db')) ? '../db' : null,
      };
    }
  }
  return null;
}

const SECRET_ENV_NAME = /secret|token|key|jwt|passphrase|password|signing|session|api[_-]?key|credential/i;

/**
 * Scan the target's source for `process.env.<NAME>` reads whose name is
 * secret-shaped, so the sandbox can inject an ephemeral value for each. This is
 * what keeps the sandbox from assuming a particular app's env var name — it
 * signs tokens with whatever variable the app actually reads.
 */
export function discoverSecretEnvVars(sourceDir: string): string[] {
  const names = new Set<string>();
  const pattern = /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g;

  const visit = (dir: string, depth: number): void => {
    if (depth > 6) return;
    let entries: Array<{ name: string; isDirectory(): boolean; isFile(): boolean }>;
    try {
      entries = readdirSync(dir, { withFileTypes: true }) as never;
    } catch {
      return;
    }
    for (const entry of entries) {
      if (/^(node_modules|\.git|\.proofscan|dist|build)$/.test(entry.name)) continue;
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) {
        visit(abs, depth + 1);
        continue;
      }
      if (!entry.isFile() || !/\.(js|mjs|cjs|ts|mts|cts)$/.test(entry.name)) continue;
      let text: string;
      try {
        if (statSync(abs).size > 2 * 1024 * 1024) continue;
        text = readFileSync(abs, 'utf8');
      } catch {
        continue;
      }
      let m: RegExpExecArray | null;
      pattern.lastIndex = 0;
      while ((m = pattern.exec(text)) !== null) {
        const name = m[1]!;
        if (SECRET_ENV_NAME.test(name)) names.add(name);
      }
    }
  };

  if (existsSync(sourceDir)) visit(sourceDir, 0);
  return [...names];
}

async function waitForReady(baseUrl: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  const paths = ['/api/health', '/health', '/'];
  while (Date.now() < deadline) {
    for (const path of paths) {
      try {
        const res = await fetch(`${baseUrl}${path}`, { signal: AbortSignal.timeout(2000) });
        if (res.status < 500) return true;
      } catch {
        // not up yet
      }
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

/**
 * Repair native dependencies for this Node version.
 *
 * A cloned target's node_modules (if any) was built for whatever Node produced
 * it; a native addon like better-sqlite3 will fail to load under a different
 * ABI. This is not hypothetical — it is exactly what happened bringing the
 * FlaudeCode fixture up on this machine. The fix is a scoped, offline-ish
 * install of the current version of the native deps into the sandbox copy.
 */
async function repairDependencies(
  sandboxDir: string,
  timeoutMs: number,
): Promise<{ ok: boolean; detail: string | null }> {
  const pkgPath = join(sandboxDir, 'package.json');
  if (!existsSync(pkgPath)) return { ok: true, detail: null };

  // Base install with --ignore-scripts. This is deliberate on two counts.
  // First, correctness: a target that pins an old native addon (the fixture
  // pins better-sqlite3@^9, which has no prebuild for a current Node and fails
  // to node-gyp-compile) would abort the whole install on the build step. With
  // scripts off, the pure-JS dependency tree installs cleanly and the native
  // binary is repaired separately below. Second, safety: install scripts are
  // arbitrary code from the target's dependency tree, and skipping them on the
  // bulk install shrinks what runs unattended while provisioning an untrusted
  // target's sandbox.
  const base = await exec(
    'npm',
    ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--loglevel', 'error'],
    { cwd: sandboxDir, timeoutMs },
  );
  if (base.notFound) return { ok: false, detail: 'npm not found on PATH' };
  if (base.code !== 0 && !existsSync(join(sandboxDir, 'node_modules'))) {
    return { ok: false, detail: `npm install failed: ${base.stderr.slice(0, 300)}` };
  }

  // Native addons still need their binary. Detect which ones the target
  // declares, then install the current version of each with scripts enabled so
  // its prebuilt binary is fetched for this Node's ABI — no local compiler
  // needed. Kept to a short allowlist of common addons rather than running
  // every dependency's scripts.
  let declared: Record<string, unknown> = {};
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { dependencies?: Record<string, unknown> };
    declared = pkg.dependencies ?? {};
  } catch {
    // A malformed package.json is the target's problem; the base install result stands.
  }

  // The probe must exercise the native binary, not just import the module.
  // better-sqlite3, for one, loads its addon lazily — `require()` succeeds even
  // when the compiled binary is absent, and the failure only surfaces when the
  // server instantiates a Database. So each addon gets an expression that
  // actually touches the binary.
  const NATIVE_ADDON_PROBES: Record<string, string> = {
    'better-sqlite3': "new (require('better-sqlite3'))(':memory:').close()",
    bcrypt: "require('bcrypt').hashSync('probe', 1)",
    argon2: "require('argon2')",
    sqlite3: "require('sqlite3').Database",
  };

  for (const [addon, probe] of Object.entries(NATIVE_ADDON_PROBES)) {
    if (!(addon in declared)) continue;

    const loads = await exec('node', ['-e', probe], { cwd: sandboxDir, timeoutMs: 20_000 });
    if (loads.code === 0) continue;

    // Fetch the current version's prebuilt binary (scripts run for this one
    // package only). Proven to work for better-sqlite3 on Node 24.
    const repair = await exec('npm', ['install', `${addon}@latest`, '--no-audit', '--no-fund'], {
      cwd: sandboxDir,
      timeoutMs,
    });
    if (repair.code !== 0) {
      return {
        ok: false,
        detail: `native dependency ${addon} could not be made loadable under this Node version (no prebuilt binary and no compiler)`,
      };
    }
  }

  return { ok: true, detail: null };
}

class LocalProcessSandbox implements Sandbox {
  readonly kind = 'local-process' as const;

  constructor(
    readonly baseUrl: string,
    readonly ref: string,
    private readonly dir: string,
    private readonly child: ReturnType<typeof spawn>,
  ) {}

  async teardown(): Promise<void> {
    try {
      this.child.kill('SIGKILL');
    } catch {
      // already gone
    }
    // Give the OS a moment to release the DB file handle before deleting.
    await new Promise((r) => setTimeout(r, 200));
    try {
      rmSync(this.dir, { recursive: true, force: true });
    } catch {
      // best effort; a leftover temp dir is harmless
    }
  }
}

export async function provisionLocalSandbox(sourceDir: string, timeoutMs: number): Promise<SandboxProvisionResult> {
  if ((await detectVersion('node', ['--version'])) === null) {
    return { ok: false, sandbox: null, detail: 'node not found on PATH; cannot start a local sandbox' };
  }

  const profile = detectNodeTarget(sourceDir);
  if (!profile) {
    return {
      ok: false,
      sandbox: null,
      detail:
        'could not determine how to start the target (no recognised entry file). The finding is reported as a ' +
        'static candidate rather than verified. Supply a Dockerfile or a start command to enable verification.',
    };
  }

  const ref = randomUUID();
  const sandboxRoot = mkdtempSync(join(tmpdir(), 'proofscan-sbx-'));
  const appDir = join(sandboxRoot, 'app');

  try {
    // Copy the target, excluding the host's node_modules and any existing DB —
    // both get rebuilt fresh so the sandbox is isolated from host state.
    cpSync(sourceDir, appDir, {
      recursive: true,
      filter: (src) => !/[\\/](node_modules|\.git|\.proofscan|db)([\\/]|$)/.test(src),
    });

    const repair = await repairDependencies(appDir, timeoutMs);
    if (!repair.ok) {
      rmSync(sandboxRoot, { recursive: true, force: true });
      return { ok: false, sandbox: null, detail: repair.detail };
    }

    const port = portFor(ref);
    const baseUrl = `http://127.0.0.1:${port}`;
    // Many targets open a database at a path relative to the app dir (the
    // fixture uses `../db/app.db`). Create a fresh, empty sibling `db/` so the
    // server can create its schema — and so the sandbox starts from clean,
    // isolated state rather than any database that came with the source.
    mkdirSync(join(sandboxRoot, 'db'), { recursive: true });

    // Inject an ephemeral value for every secret-shaped env var the source
    // actually reads, not a hardcoded JWT_SECRET. A vibe-coded app might sign
    // tokens with process.env.APP_TOKEN_SECRET, SESSION_KEY, or anything else;
    // discovering the names from the source keeps the sandbox target-agnostic.
    const secretEnv: Record<string, string> = {};
    for (const name of discoverSecretEnvVars(sourceDir)) {
      secretEnv[name] = `proofscan-sandbox-${name}-${ref}`;
    }

    const child = spawn(resolveBinary(profile.startCommand[0]!), profile.startCommand.slice(1), {
      cwd: appDir,
      env: {
        ...process.env,
        ...profile.baseEnv,
        ...secretEnv,
        PORT: String(port),
        // Kept for the common case even if the scan missed it; never a value
        // from the target's own config.
        JWT_SECRET: secretEnv['JWT_SECRET'] ?? `proofscan-sandbox-${ref}`,
        NODE_ENV: 'test',
      },
      stdio: ['ignore', 'ignore', 'pipe'],
      windowsHide: true,
    });

    let stderr = '';
    child.stderr?.on('data', (chunk: Buffer) => {
      if (stderr.length < 2000) stderr += chunk.toString();
    });

    const ready = await waitForReady(baseUrl, Math.min(timeoutMs, 25_000));
    if (!ready) {
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
      rmSync(sandboxRoot, { recursive: true, force: true });
      return {
        ok: false,
        sandbox: null,
        detail: `sandbox server did not become ready${stderr ? `: ${stderr.slice(0, 300)}` : ''}`,
      };
    }

    return {
      ok: true,
      sandbox: new LocalProcessSandbox(baseUrl, ref, sandboxRoot, child),
      detail: null,
    };
  } catch (err) {
    rmSync(sandboxRoot, { recursive: true, force: true });
    return { ok: false, sandbox: null, detail: `sandbox provisioning failed: ${(err as Error).message}` };
  }
}
