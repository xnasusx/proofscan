import type { RuleFinding, Severity } from '../types.js';
import { establishIdentities, runDifferential } from '../exploit/engine.js';
import type { CrossUserFinding } from '../exploit/engine.js';
import type { AuthPlan, ResourcePlan } from '../exploit/plan.js';
import { DEFAULT_AUTH } from '../exploit/plan.js';
import { DynamicClient } from './client.js';
import type { DynamicRequestLog } from './client.js';
import { RouteDiscoveryError, discoverOpenApi, routesFromManifest, routesFromOpenApi } from './routes.js';
import type { ResourceManifestEntry } from './routes.js';

export const DYNAMIC_RULE_ID = 'proofscan.bola-idor-dynamic';

/** The `dynamic:` block on a target, as seen by Layer 3. */
export interface DynamicConfig {
  auth?: {
    register_path?: string;
    login_path?: string;
    username_field?: string;
    password_field?: string;
    token_field?: string;
    extra_register_fields?: Record<string, unknown>;
    identities?: Array<{ username: string; password: string }>;
  };
  resources?: ResourceManifestEntry[];
  /** Set false to skip OpenAPI auto-discovery and use only the manifest. */
  discover_openapi?: boolean;
  /** Requests/second ceiling; converted to a minimum interval. */
  rate_limit_rps?: number;
}

export interface DynamicRunOptions {
  baseUrl: string;
  config: DynamicConfig;
  timeoutMs: number;
}

export interface DynamicResult {
  /** Each dynamic finding is a live demonstration; the caller marks these verified. */
  findings: Array<{ ruleFinding: RuleFinding; dynamic: CrossUserFinding }>;
  /** Every request the layer made, for the audit trail. */
  requestLog: DynamicRequestLog[];
  notes: string[];
  resourcesTested: number;
}

function authPlanFromConfig(config: DynamicConfig): AuthPlan {
  const a = config.auth ?? {};
  return {
    registerPath: a.register_path ?? DEFAULT_AUTH.registerPath,
    loginPath: a.login_path ?? DEFAULT_AUTH.loginPath,
    usernameField: a.username_field ?? DEFAULT_AUTH.usernameField,
    passwordField: a.password_field ?? DEFAULT_AUTH.passwordField,
    tokenField: a.token_field ?? DEFAULT_AUTH.tokenField,
    extraRegisterFields: a.extra_register_fields ?? {},
    ...(a.identities ? { identities: a.identities } : {}),
  };
}

function severityFor(finding: CrossUserFinding): Severity {
  if (finding.kind === 'unauthorized-side-effect') return 'critical';
  return finding.method === 'GET' ? 'high' : 'critical';
}

function toRuleFinding(baseUrl: string, finding: CrossUserFinding): RuleFinding {
  return {
    rule_id: DYNAMIC_RULE_ID,
    title: finding.title,
    description:
      `${finding.description}\n\n` +
      `Demonstrated live against the running target (${baseUrl}) by differential authorisation testing: two ` +
      `synthetic identities, one attacking the other's resource. Route discovered via ${finding.discoveredVia}. ` +
      `Before: ${JSON.stringify(finding.evidence.before)}; after: ${JSON.stringify(finding.evidence.after)}.`,
    file_path: null,
    line: 0,
    severity: severityFor(finding),
    exploitability_note:
      `Reproduced live: an authenticated non-owner performed ${finding.method} on another user's resource and ` +
      (finding.kind === 'unauthorized-side-effect'
        ? `changed the owner's data despite an HTTP ${finding.attackerStatus} response.`
        : `was allowed (HTTP ${finding.attackerStatus}).`),
    code_excerpt: `${finding.method} ${finding.itemPath}`,
    cwe: ['CWE-639', 'CWE-285', 'CWE-863'],
  };
}

export async function runDynamicLayer(options: DynamicRunOptions): Promise<DynamicResult> {
  const notes: string[] = [];
  const requestLog: DynamicRequestLog[] = [];

  const minIntervalMs = options.config.rate_limit_rps
    ? Math.max(1, Math.round(1000 / options.config.rate_limit_rps))
    : undefined;

  const client = new DynamicClient({
    baseUrl: options.baseUrl,
    timeoutMs: options.timeoutMs,
    minIntervalMs,
    onRequest: (log) => requestLog.push(log),
  });

  // Route discovery: OpenAPI first (unless disabled), then the manifest, merged
  // and de-duplicated by collection path so an operator can augment a spec.
  const resources: ResourcePlan[] = [];
  if (options.config.discover_openapi !== false) {
    const doc = await discoverOpenApi(client);
    if (doc) {
      const fromSpec = routesFromOpenApi(doc);
      resources.push(...fromSpec);
      notes.push(`Discovered ${fromSpec.length} testable resource(s) from the target's OpenAPI document.`);
    }
  }
  if (options.config.resources && options.config.resources.length > 0) {
    try {
      const known = new Set(resources.map((r) => r.collectionPath));
      for (const r of routesFromManifest(options.config.resources)) {
        if (!known.has(r.collectionPath)) resources.push(r);
      }
    } catch (err) {
      if (err instanceof RouteDiscoveryError) notes.push(`Route manifest error: ${err.message}`);
      else throw err;
    }
  }

  if (resources.length === 0) {
    notes.push(
      'No testable resources were discovered. The target served no OpenAPI document and no `dynamic.resources` ' +
        'manifest was supplied, so the fuzzer had no id-parameterised endpoint to exercise.',
    );
    return { findings: [], requestLog, notes, resourcesTested: 0 };
  }

  const [victim, attacker] = await establishIdentities(client, authPlanFromConfig(options.config));
  const result = await runDifferential(client, attacker, victim, resources);
  for (const s of result.skipped) notes.push(`Skipped resource "${s.resource}": ${s.reason}`);

  return {
    findings: result.findings.map((dynamic) => ({ ruleFinding: toRuleFinding(options.baseUrl, dynamic), dynamic })),
    requestLog,
    notes,
    resourcesTested: result.resourcesTested,
  };
}
