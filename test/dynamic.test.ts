import { describe, expect, it } from 'vitest';
import { DynamicClient } from '../src/dynamic/client.js';
import type { DynamicRequestLog } from '../src/dynamic/client.js';
import { routesFromManifest, routesFromOpenApi, RouteDiscoveryError } from '../src/dynamic/routes.js';
import { testResource } from '../src/exploit/engine.js';
import type { Identity } from '../src/exploit/engine.js';
import type { ResourcePlan } from '../src/exploit/plan.js';
import { authorizeLayers, parseTargetsFile } from '../src/config/targets.js';

describe('targets config — runtime_url and dynamic block', () => {
  it('parses a source-less runtime_url target with a dynamic manifest', () => {
    const yaml = `
targets:
  - name: live
    source_type: runtime_url
    runtime_base_url: https://staging.example
    authorized_by: rootcaws
    authorized_at: "2026-08-09"
    authorization_basis: own staging
    dynamic:
      resources:
        - collection: /api/tasks
          item: /api/tasks/:id
          methods: [GET, DELETE]
`;
    const [t] = parseTargetsFile(yaml, 'targets.yaml');
    expect(t!.source_type).toBe('runtime_url');
    expect(t!.source_uri).toBe('');
    expect(t!.runtime_base_url).toBe('https://staging.example');
    expect((t!.dynamic as { resources: unknown[] }).resources).toHaveLength(1);
  });

  it('requires runtime_base_url on a runtime_url target', () => {
    const yaml = `targets:\n  - name: x\n    source_type: runtime_url\n`;
    expect(() => parseTargetsFile(yaml, 'f')).toThrow(/runtime_base_url/);
  });

  it('gates the dynamic layer on record + flag + runtime_base_url', () => {
    const yaml = `
targets:
  - name: live
    source_type: runtime_url
    runtime_base_url: https://staging.example
    authorized_by: rootcaws
    authorized_at: "2026-08-09"
    authorization_basis: own staging
`;
    const t = parseTargetsFile(yaml, 'f')[0]!;
    expect(authorizeLayers(t, ['dynamic-fuzzer'], { authorizedFlag: false }).allowed).toBe(false);
    expect(authorizeLayers(t, ['dynamic-fuzzer'], { authorizedFlag: true }).allowed).toBe(true);
  });
});

describe('route discovery — manifest', () => {
  it('normalises a manifest entry, defaulting the item path and methods', () => {
    const [r] = routesFromManifest([{ collection: '/api/tasks', child: '/api/tasks/:id/notes' }]);
    expect(r!.itemPathTemplate).toBe('/api/tasks/:id');
    expect(r!.methods).toContain('DELETE');
    expect(r!.childCollectionTemplate).toBe('/api/tasks/:id/notes');
    expect(r!.discoveredVia).toBe('manifest');
  });

  it('rejects an item path with no id parameter to vary', () => {
    expect(() => routesFromManifest([{ collection: '/api/tasks', item: '/api/tasks/all' }])).toThrow(
      RouteDiscoveryError,
    );
  });
});

describe('route discovery — OpenAPI', () => {
  it('pairs a POST collection with its {id} item path and finds child collections', () => {
    const doc = {
      paths: {
        '/api/tasks': { post: {}, get: {} },
        '/api/tasks/{id}': { get: {}, put: {}, delete: {} },
        '/api/tasks/{id}/notes': { get: {}, post: {} },
        '/api/health': { get: {} },
      },
    };
    const resources = routesFromOpenApi(doc);
    expect(resources).toHaveLength(1);
    expect(resources[0]!.collectionPath).toBe('/api/tasks');
    expect(resources[0]!.itemPathTemplate).toBe('/api/tasks/:id'); // {id} -> :id
    expect(resources[0]!.methods.sort()).toEqual(['DELETE', 'GET', 'PUT']);
    expect(resources[0]!.childCollectionTemplate).toBe('/api/tasks/:id/notes');
    expect(resources[0]!.discoveredVia).toBe('openapi');
  });

  it('skips a collection with no id-parameterised sibling', () => {
    expect(routesFromOpenApi({ paths: { '/api/ping': { post: {} } } })).toHaveLength(0);
  });
});

describe('DynamicClient — rate limiting and backoff', () => {
  it('enforces a minimum interval between requests using the injected clock', async () => {
    let clock = 0;
    const sleeps: number[] = [];
    const client = new DynamicClient({
      baseUrl: 'http://t',
      minIntervalMs: 200,
      onRequest: () => {},
      now: () => clock,
      sleep: async (ms) => {
        sleeps.push(ms);
        clock += ms; // advancing the clock is the only effect that matters here
      },
    });
    // Stub fetch to return instantly without advancing the clock.
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response('{}', { status: 200 })) as typeof fetch;
    try {
      await client.request('a', 'GET', '/x');
      await client.request('a', 'GET', '/y'); // must wait ~200ms since last start
    } finally {
      globalThis.fetch = realFetch;
    }
    expect(sleeps.some((s) => s >= 200)).toBe(true);
  });

  it('backs off and retries on 429, honouring Retry-After', async () => {
    let clock = 0;
    const sleeps: number[] = [];
    const logs: DynamicRequestLog[] = [];
    const client = new DynamicClient({
      baseUrl: 'http://t',
      minIntervalMs: 0,
      maxRetries: 2,
      onRequest: (l) => logs.push(l),
      now: () => clock,
      sleep: async (ms) => {
        sleeps.push(ms);
        clock += ms;
      },
    });
    let call = 0;
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      call++;
      if (call === 1) return new Response('', { status: 429, headers: { 'retry-after': '3' } });
      return new Response('{"ok":true}', { status: 200 });
    }) as typeof fetch;
    try {
      const res = await client.request('a', 'GET', '/x');
      expect(res.status).toBe(200);
    } finally {
      globalThis.fetch = realFetch;
    }
    expect(sleeps).toContain(3000); // Retry-After: 3s honoured
    // One log for the backoff, one for the eventual success — same seq.
    expect(logs.filter((l) => l.error?.includes('backing off'))).toHaveLength(1);
  });
});

/** A scripted client: returns queued responses per (method, pathPattern). */
class FakeClient {
  requests: Array<{ actor: string; method: string; path: string }> = [];
  private state = { taskPresent: true, noteCount: 1 };

  async request(actor: string, method: string, path: string) {
    this.requests.push({ actor, method, path });
    const M = method.toUpperCase();

    if (M === 'POST' && path === '/api/tasks') return { status: 201, body: { id: 1 }, headers: {} };
    if (M === 'POST' && path === '/api/tasks/1/notes') return { status: 201, body: { id: 1 }, headers: {} };

    // Owner reads.
    if (M === 'GET' && path === '/api/tasks') {
      return { status: 200, body: this.state.taskPresent ? [{ id: 1 }] : [], headers: {} };
    }
    if (M === 'GET' && path === '/api/tasks/1/notes') {
      return { status: 200, body: Array.from({ length: this.state.noteCount }, (_, i) => ({ id: i })), headers: {} };
    }

    // The attack: DELETE returns 404 to the attacker but destroys the child
    // note first — the exact flagship bug.
    if (M === 'DELETE' && path === '/api/tasks/1') {
      this.state.noteCount = 0;
      return { status: 404, body: { message: 'Task not found' }, headers: {} };
    }
    // PUT is ownership-scoped: 404, no change.
    if (M === 'PUT' && path === '/api/tasks/1') {
      return { status: 404, body: { message: 'Task not found' }, headers: {} };
    }
    if (M === 'GET' && path === '/api/tasks/1') return { status: 404, body: null, headers: {} };

    return { status: 404, body: null, headers: {} };
  }
}

describe('engine — differential authorisation', () => {
  const resource: ResourcePlan = {
    name: 'tasks',
    collectionPath: '/api/tasks',
    idField: 'id',
    itemPathTemplate: '/api/tasks/:id',
    methods: ['GET', 'PUT', 'DELETE'],
    childCollectionTemplate: '/api/tasks/:id/notes',
    createFields: [],
    discoveredVia: 'manifest',
  };
  const alice: Identity = { label: 'A', username: 'a', token: 'ta' };
  const bob: Identity = { label: 'B', username: 'b', token: 'tb' };

  it('flags the 404-but-mutated DELETE as a side-effect finding, not the PUT or GET', async () => {
    const client = new FakeClient();
    const { findings } = await testResource(client as never, bob, alice, resource);

    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.method).toBe('DELETE');
    expect(f.kind).toBe('unauthorized-side-effect');
    expect(f.attackerStatus).toBe(404);
    expect(f.evidence.changed.join(' ')).toMatch(/child record/);
  });

  it('decides on victim state read back as the victim, not on the attacker status', async () => {
    const client = new FakeClient();
    await testResource(client as never, bob, alice, resource);
    // The verdict came from A-labelled reads bracketing B's attack.
    const ownerReads = client.requests.filter((r) => r.actor === 'A' && r.method === 'GET');
    expect(ownerReads.length).toBeGreaterThanOrEqual(2);
  });
});
