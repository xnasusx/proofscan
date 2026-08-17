#!/usr/bin/env node
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pc from 'picocolors';
import type { Layer, Severity } from './types.js';
import { SEVERITY_ORDER } from './types.js';
import { verifyChain } from './core/audit.js';
import { countBySeverity } from './core/findings.js';
import { ScanRefusedError, TOOL_VERSION, runScan } from './core/scan.js';
import { FileStore } from './core/store.js';
import { TargetConfigError, adHocTarget, loadTargets } from './config/targets.js';
import { renderText } from './report/text.js';
import { buildTicket, draftPullRequest } from './remediate/ticket.js';
import { reverifyFindings } from './remediate/reverify.js';

const HERE = dirname(fileURLToPath(import.meta.url));
/** rules/ sits next to dist/ in the installed package and in the repo. */
const DEFAULT_RULES_DIR = join(HERE, '..', 'rules', 'semgrep');

const USAGE = `
proofscan ${TOOL_VERSION} — layered application flaw scanner (static, AI-verified, dynamic, remediation)

Usage
  proofscan scan --path <dir> [options]
  proofscan scan --target <name> [--targets <file>] [options]
  proofscan remediate [--store <dir>] [--out <dir>]
  proofscan reverify --fix <dir> [--store <dir>]
  proofscan audit verify [--store <dir>]
  proofscan rules list

Remediation (Layer 4)
  remediate   Write a ticket (Markdown + Jira-shaped JSON) and a draft-PR body
              for every verified-exploitable finding in the latest stored report,
              carrying the repro evidence and a concrete fix recommendation.
  reverify    Re-run the exact exploit against a fix checkout (--fix). A finding
              flips to fixed-verified only when the repro no longer reproduces;
              exits 1 if any exploit still works (the merge gate).

Scan options
  --path <dir>           Scan a local directory directly, without a targets file.
  --target <name>        Scan a target defined in the targets file.
  --targets <file>       Targets file (default: ./targets.yaml).
  --layers <list>        Comma-separated: static, ai-reasoning, dynamic-fuzzer.
                         Default: static.
                         ai-reasoning adds Layer 2: authorisation-ordering
                         detection with sandboxed exploit verification.
                         dynamic-fuzzer adds Layer 3: a BOLA/IDOR fuzzer against a
                         running instance with no source access. It is gated on an
                         authorisation record in the targets file (authorized_by,
                         authorized_at, authorization_basis) plus --authorized.
  --reasoner <name>      Layer 2 backend: heuristic (default, deterministic, no
                         network) or anthropic (claude-opus-5; needs the optional
                         @anthropic-ai/sdk and ANTHROPIC_API_KEY).
  --no-verify            Skip Layer 2 sandboxed verification; findings stay
                         unverified-flagged.
  --scanners <list>      Limit external scanners, e.g. semgrep,trivy.
                         The built-in rules always run.
  --rules <dir>          Semgrep rule directory (default: bundled rules/semgrep).
  --kev-catalog <file>   Local CISA KEV catalog JSON, for exploitability context.
                         Never fetched over the network.
  --json <file>          Write the full JSON report to this path.
  --min-severity <sev>   Only print findings at or above: critical|high|medium|low.
  --fail-on <sev>        Exit 1 if any finding is at or above this severity.
  --no-store             Do not write .proofscan/ (no run history, no audit log).
  --timeout <ms>         Per-scanner timeout (default: 300000).
  --authorized           Per-invocation confirmation for dynamic layers.
  --quiet                Suppress the human-readable summary.

Exit codes
  0  completed (and no finding met --fail-on)
  1  completed, but a finding met --fail-on
  2  refused or failed to run
`;

interface ParsedArgs {
  command: string;
  subcommand: string | null;
  flags: Map<string, string | boolean>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const positional: string[] = [];
  const flags = new Map<string, string | boolean>();

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const name = arg.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      flags.set(name, next);
      i++;
    } else {
      flags.set(name, true);
    }
  }

  return {
    command: positional[0] ?? 'help',
    subcommand: positional[1] ?? null,
    flags,
  };
}

function stringFlag(flags: Map<string, string | boolean>, name: string): string | null {
  const value = flags.get(name);
  return typeof value === 'string' ? value : null;
}

function severityFlag(flags: Map<string, string | boolean>, name: string): Severity | null {
  const value = stringFlag(flags, name);
  if (value === null) return null;
  if (!['critical', 'high', 'medium', 'low'].includes(value)) {
    throw new Error(`--${name} must be one of critical, high, medium, low (got "${value}")`);
  }
  return value as Severity;
}

function fail(message: string): never {
  process.stderr.write(`${pc.red('proofscan:')} ${message}\n`);
  process.exit(2);
}

async function commandScan(flags: Map<string, string | boolean>): Promise<void> {
  const pathFlag = stringFlag(flags, 'path');
  const targetName = stringFlag(flags, 'target');

  if (!pathFlag && !targetName) fail('either --path <dir> or --target <name> is required.\n' + USAGE);
  if (pathFlag && targetName) fail('--path and --target are mutually exclusive.');

  let target;
  if (pathFlag) {
    const absolute = isAbsolute(pathFlag) ? pathFlag : resolve(process.cwd(), pathFlag);
    if (!existsSync(absolute)) fail(`--path does not exist: ${absolute}`);
    target = adHocTarget(absolute);
  } else {
    const targetsPath = stringFlag(flags, 'targets') ?? resolve(process.cwd(), 'targets.yaml');
    const targets = loadTargets(targetsPath);
    const found = targets.find((t) => t.name === targetName);
    if (!found) {
      fail(
        `target "${targetName}" is not defined in ${targetsPath}. Defined targets: ` +
          (targets.map((t) => t.name).join(', ') || '(none)'),
      );
    }
    target = found;
    if (target.source_type === 'local_path' && !isAbsolute(target.source_uri)) {
      target = { ...target, source_uri: resolve(dirname(targetsPath), target.source_uri) };
    }
  }

  const layers = (stringFlag(flags, 'layers') ?? 'static')
    .split(',')
    .map((l) => l.trim())
    .filter(Boolean) as Layer[];

  const scannersFlag = stringFlag(flags, 'scanners');
  const minSeverity = severityFlag(flags, 'min-severity');
  const failOn = severityFlag(flags, 'fail-on');
  const timeoutFlag = stringFlag(flags, 'timeout');

  const reasonerFlag = stringFlag(flags, 'reasoner');
  if (reasonerFlag && reasonerFlag !== 'heuristic' && reasonerFlag !== 'anthropic') {
    fail(`--reasoner must be "heuristic" or "anthropic" (got "${reasonerFlag}")`);
  }

  const report = await runScan({
    target,
    layers,
    rulesDir: stringFlag(flags, 'rules') ?? DEFAULT_RULES_DIR,
    onlyScanners: scannersFlag ? scannersFlag.split(',').map((s) => s.trim()).filter(Boolean) : [],
    timeoutMs: timeoutFlag ? Number(timeoutFlag) : 300_000,
    kevCatalogPath: stringFlag(flags, 'kev-catalog'),
    authorizedFlag: flags.get('authorized') === true,
    storeRoot: flags.get('no-store') === true ? null : target.source_uri,
    reasoner: (reasonerFlag as 'heuristic' | 'anthropic') ?? 'heuristic',
    verify: flags.get('no-verify') !== true,
  });

  const visible = minSeverity
    ? { ...report, findings: report.findings.filter((f) => SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[minSeverity]) }
    : report;

  if (flags.get('quiet') !== true) {
    process.stdout.write(renderText(visible));
  }

  const jsonPath = stringFlag(flags, 'json');
  if (jsonPath) {
    // The JSON report always carries every finding, regardless of
    // --min-severity: the file is the record, the terminal is the view.
    writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    if (flags.get('quiet') !== true) process.stdout.write(pc.dim(`JSON report written to ${jsonPath}\n`));
  }

  if (failOn) {
    const counts = countBySeverity(report.findings);
    const triggered = (['critical', 'high', 'medium', 'low'] as Severity[]).some(
      (s) => SEVERITY_ORDER[s] <= SEVERITY_ORDER[failOn] && counts[s] > 0,
    );
    if (triggered) {
      process.stderr.write(
        pc.red(`\nFailing: at least one finding is ${failOn} or above (--fail-on ${failOn}).\n`),
      );
      process.exit(1);
    }
  }
}

function commandAuditVerify(flags: Map<string, string | boolean>): void {
  const storeRoot = stringFlag(flags, 'store') ?? process.cwd();
  const store = new FileStore(storeRoot);
  const entries = store.loadAuditEntries();

  if (entries.length === 0) {
    process.stdout.write(`No audit log found under ${store.dir}. Nothing to verify.\n`);
    return;
  }

  const result = verifyChain(entries);
  if (result.ok) {
    process.stdout.write(
      pc.green(`Audit chain intact: ${result.entries_checked} entr${result.entries_checked === 1 ? 'y' : 'ies'} verified.\n`) +
        pc.dim(
          `Head hash: ${entries.at(-1)?.entry_hash}\n` +
            'This proves the log is internally consistent. It does not prove the log is complete: anyone who ' +
            'can rewrite the whole file can recompute a valid chain. Anchor the head hash somewhere outside ' +
            'this file to detect that.\n',
        ),
    );
    return;
  }

  process.stderr.write(pc.red(`Audit chain BROKEN — ${result.problems.length} problem(s):\n`));
  for (const problem of result.problems) {
    process.stderr.write(`  entry ${problem.index} (${problem.id}): ${problem.problem}\n`);
  }
  process.exit(1);
}

function commandRemediate(flags: Map<string, string | boolean>): void {
  const storeRoot = stringFlag(flags, 'store') ?? process.cwd();
  const store = new FileStore(storeRoot);
  const report = store.latestReport();
  if (!report) fail(`no stored scan report found under ${store.dir}. Run a scan first (without --no-store).`);

  const verified = report!.findings.filter((f) => f.status === 'verified-exploitable');
  if (verified.length === 0) {
    process.stdout.write('No verified-exploitable findings in the latest report; nothing to open a ticket for.\n');
    return;
  }

  const outDir = stringFlag(flags, 'out') ?? join(store.dir, 'remediation');
  mkdirSync(outDir, { recursive: true });

  process.stdout.write(pc.bold(`Remediation for ${verified.length} verified-exploitable finding(s)\n\n`));
  for (const finding of verified) {
    const ticket = buildTicket(finding, report!);
    const pr = draftPullRequest(ticket);
    const base = join(outDir, ticket.key);
    writeFileSync(`${base}.md`, `${ticket.markdown}\n`, 'utf8');
    writeFileSync(`${base}.jira.json`, `${JSON.stringify(ticket.jira, null, 2)}\n`, 'utf8');
    writeFileSync(`${base}.pr.md`, `# ${pr.title}\n\n${pr.body}\n`, 'utf8');

    process.stdout.write(`  ${pc.red(ticket.severity.toUpperCase())}  ${ticket.title}\n`);
    process.stdout.write(`      ${pc.cyan(ticket.endpoint ?? ticket.file_path ?? '')}  ${pc.dim(ticket.key)}\n`);
    process.stdout.write(pc.dim(`      ticket: ${base}.md · jira: ${base}.jira.json · draft PR: ${base}.pr.md\n\n`));
  }
  process.stdout.write(
    pc.dim(
      'These are filesystem tickets and a draft PR body. A Jira/GitHub integration posts the same payload to the ' +
        'respective API. proofscan does not auto-apply a source patch it cannot prove correct — validate any fix ' +
        'with `proofscan reverify`.\n',
    ),
  );
}

async function commandReverify(flags: Map<string, string | boolean>): Promise<void> {
  const storeRoot = stringFlag(flags, 'store') ?? process.cwd();
  const fixDir = stringFlag(flags, 'fix');
  if (!fixDir) fail('--fix <path> is required: the checkout of the fix branch to re-verify against.');
  const timeoutFlag = stringFlag(flags, 'timeout');

  const store = new FileStore(storeRoot);
  const report = store.latestReport();
  if (!report) fail(`no stored scan report found under ${store.dir}. Run a scan first (without --no-store).`);

  const summary = await reverifyFindings(resolve(fixDir!), report!.findings, {
    timeoutMs: timeoutFlag ? Number(timeoutFlag) : 300_000,
    dynamicConfig: (report!.target.dynamic ?? null) as never,
  });

  for (const note of summary.notes) process.stdout.write(pc.dim(`${note}\n`));
  if (summary.outcomes.length === 0) return;

  process.stdout.write(pc.bold(`\nRe-verification against ${fixDir}\n\n`));
  for (const o of summary.outcomes) {
    const label =
      o.newStatus === 'fixed-verified'
        ? pc.green('FIXED')
        : o.newStatus === 'verified-exploitable'
          ? pc.red('STILL VULNERABLE')
          : pc.yellow('UNCONFIRMED');
    process.stdout.write(`  ${label}  ${o.finding.endpoint ?? o.finding.title}\n`);
    process.stdout.write(pc.dim(`      ${o.previousStatus} -> ${o.newStatus}: ${o.detail}\n`));
  }
  process.stdout.write(
    `\n${pc.bold(`${summary.fixed} fixed`)} · ${summary.stillVulnerable} still vulnerable · ` +
      `${summary.outcomes.length - summary.fixed - summary.stillVulnerable} unconfirmed\n`,
  );

  // Exit non-zero if any finding still reproduces — this is the merge gate.
  if (summary.stillVulnerable > 0) {
    process.stderr.write(pc.red('\nMerge gate: at least one exploit still reproduces against the fix.\n'));
    process.exit(1);
  }
}

async function commandRulesList(): Promise<void> {
  const { BUILTIN_RULE_IDS } = await import('./analyzers/builtin/index.js');
  process.stdout.write(`\n${pc.bold('Built-in rules')} (always run, no external dependency)\n`);
  for (const id of BUILTIN_RULE_IDS) process.stdout.write(`  ${id}\n`);
  process.stdout.write(
    `\n${pc.bold('Semgrep rules')} (run when semgrep is installed; see docs/RULES.md for parity)\n` +
      `  ${DEFAULT_RULES_DIR}\n\n`,
  );
}

async function main(): Promise<void> {
  const { command, subcommand, flags } = parseArgs(process.argv.slice(2));

  if (flags.get('version') === true || command === 'version') {
    process.stdout.write(`${TOOL_VERSION}\n`);
    return;
  }

  try {
    switch (command) {
      case 'scan':
        await commandScan(flags);
        return;
      case 'audit':
        if (subcommand !== 'verify') fail('unknown audit subcommand. Use: proofscan audit verify');
        commandAuditVerify(flags);
        return;
      case 'rules':
        if (subcommand !== 'list') fail('unknown rules subcommand. Use: proofscan rules list');
        await commandRulesList();
        return;
      case 'remediate':
        commandRemediate(flags);
        return;
      case 'reverify':
        await commandReverify(flags);
        return;
      default:
        process.stdout.write(USAGE);
        return;
    }
  } catch (err) {
    if (err instanceof ScanRefusedError) fail(err.message);
    if (err instanceof TargetConfigError) fail(err.message);
    throw err;
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`${pc.red('proofscan: unexpected failure')}\n${(err as Error).stack ?? String(err)}\n`);
  process.exit(2);
});
