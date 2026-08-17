import type { HttpResponse } from './client.js';
import type { DynamicClient } from './client.js';
import type { ResourcePlan } from '../exploit/plan.js';

/**
 * Route discovery for Layer 3: turn an OpenAPI document or an operator manifest
 * into the shared `ResourcePlan` shape the differential engine consumes. The
 * unit is a resource collection (a create endpoint plus the id-parameterised
 * operations a non-owner should be denied), because cross-user testing needs
 * the create/attack pairing, not a flat URL list.
 */

/** The `dynamic.resources` manifest shape from targets.yaml. */
export interface ResourceManifestEntry {
  name?: string;
  collection: string;
  item?: string;
  id_field?: string;
  methods?: string[];
  child?: string;
  create_fields?: string[];
}

export class RouteDiscoveryError extends Error {}

function fillTemplate(collection: string, item: string | undefined): string {
  return item ?? `${collection.replace(/\/$/, '')}/:id`;
}

export function routesFromManifest(entries: ResourceManifestEntry[]): ResourcePlan[] {
  return entries.map((entry, index) => {
    if (!entry.collection || typeof entry.collection !== 'string') {
      throw new RouteDiscoveryError(`dynamic.resources[${index}]: \`collection\` is required`);
    }
    const item = fillTemplate(entry.collection, entry.item);
    if (!/:[A-Za-z_]\w*/.test(item)) {
      throw new RouteDiscoveryError(
        `dynamic.resources[${index}]: item path "${item}" has no :id parameter to vary between users`,
      );
    }
    return {
      name: entry.name ?? entry.collection.split('/').filter(Boolean).pop() ?? `resource-${index}`,
      collectionPath: entry.collection,
      idField: entry.id_field ?? 'id',
      itemPathTemplate: item,
      methods: (entry.methods ?? ['GET', 'PUT', 'PATCH', 'DELETE']).map((m) => m.toUpperCase()),
      childCollectionTemplate: entry.child ?? null,
      createFields: entry.create_fields ?? [],
      discoveredVia: 'manifest',
    };
  });
}

interface OpenApiDoc {
  paths?: Record<string, Record<string, unknown>>;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** OpenAPI uses `{id}`; the engine's fill logic uses `:id`. */
function toColonTemplate(openApiPath: string): string {
  return openApiPath.replace(/\{([^}]+)\}/g, ':$1');
}

/**
 * Derive resource plans from an OpenAPI document: each collection path with a
 * POST paired to the sibling id-parameterised path. A path with no discoverable
 * create is skipped — there would be nothing to create and then attack.
 */
export function routesFromOpenApi(doc: OpenApiDoc): ResourcePlan[] {
  const paths = doc.paths ?? {};
  const pathNames = Object.keys(paths);
  const resources: ResourcePlan[] = [];

  for (const collection of pathNames) {
    const ops = paths[collection] ?? {};
    if (!('post' in ops)) continue;
    if (/\{[^}]+\}/.test(collection)) continue;

    const item = pathNames.find((p) => new RegExp(`^${escapeRegExp(collection)}/\\{[^}]+\\}$`).test(p));
    if (!item) continue;

    const itemOps = paths[item] ?? {};
    const methods = ['get', 'put', 'patch', 'delete'].filter((m) => m in itemOps).map((m) => m.toUpperCase());
    if (methods.length === 0) continue;

    const child = pathNames.find((p) => new RegExp(`^${escapeRegExp(item)}/[A-Za-z][\\w-]*$`).test(p));

    resources.push({
      name: collection.split('/').filter(Boolean).pop() ?? collection,
      collectionPath: collection,
      idField: 'id',
      itemPathTemplate: toColonTemplate(item),
      methods,
      childCollectionTemplate: child ? toColonTemplate(child) : null,
      createFields: [],
      discoveredVia: 'openapi',
    });
  }

  return resources;
}

/**
 * Try to fetch an OpenAPI document from the running target at the usual paths.
 * Returns null when none is served — the caller falls back to the manifest.
 */
export async function discoverOpenApi(client: DynamicClient): Promise<OpenApiDoc | null> {
  const candidates = ['/openapi.json', '/swagger.json', '/api-docs', '/api/openapi.json', '/v3/api-docs'];
  for (const path of candidates) {
    let res: HttpResponse;
    try {
      res = await client.request('setup', 'GET', path);
    } catch {
      continue;
    }
    if (res.status === 200 && res.body && typeof res.body === 'object' && 'paths' in (res.body as object)) {
      return res.body as OpenApiDoc;
    }
  }
  return null;
}
