import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runBuiltinRules } from '../src/analyzers/builtin/index.js';
import type { SourceFile } from '../src/core/walk.js';
import { walkSource } from '../src/core/walk.js';
import type { RuleFinding } from '../src/types.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const VULNERABLE = join(HERE, 'fixtures', 'repo', 'vulnerable');
const CLEAN = join(HERE, 'fixtures', 'repo', 'clean');

/** Analyse an inline snippet as if it were a file in the repo. */
function analyse(code: string, relPath = 'server.js'): RuleFinding[] {
  const file: SourceFile = { absPath: `/virtual/${relPath}`, relPath, ext: '.js', text: code };
  return runBuiltinRules([file]).findings;
}

function ids(findings: RuleFinding[]): string[] {
  return findings.map((f) => f.rule_id);
}

/** Select by rule-id substring, so tests can name rules without the full prefix. */
function ofRule(findings: RuleFinding[], rule: string): RuleFinding[] {
  return findings.filter((f) => f.rule_id.includes(rule));
}

describe('hardcoded-fallback-secret', () => {
  it('flags a token-signing fallback as critical', () => {
    const findings = ofRule(
      analyse(`const s = process.env.JWT_SECRET || 'demo-jwt-secret-change-me';`),
      'hardcoded-fallback-secret',
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[0]!.line).toBe(1);
  });

  it('flags a non-signing credential fallback as high', () => {
    const findings = ofRule(
      analyse(`const k = process.env.API_SECRET || 'FAKE_API_KEY_123';`),
      'hardcoded-fallback-secret',
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
  });

  it('handles ?? and bracket access', () => {
    expect(ofRule(analyse(`const a = process.env.SESSION_SECRET ?? 'x1y2z3';`), 'hardcoded-fallback-secret')).toHaveLength(1);
    expect(ofRule(analyse(`const b = process.env['API_KEY'] || 'abc123';`), 'hardcoded-fallback-secret')).toHaveLength(1);
  });

  it('infers secret-ness from the assigned name when the env var is neutral', () => {
    const findings = ofRule(
      analyse(`const apiKey = process.env.UPSTREAM || 'literal-value-here';`),
      'hardcoded-fallback-secret',
    );
    expect(findings).toHaveLength(1);
  });

  it('never echoes the literal into the report', () => {
    const findings = ofRule(
      analyse(`const s = process.env.JWT_SECRET || 'super-secret-value';`),
      'hardcoded-fallback-secret',
    );
    const serialised = JSON.stringify(findings);
    expect(serialised).not.toContain('super-secret-value');
    expect(findings[0]!.code_excerpt).toContain('redacted');
  });

  it('ignores non-secret names and placeholder fallbacks', () => {
    expect(ofRule(analyse(`const p = process.env.PORT || '4000';`), 'hardcoded-fallback-secret')).toHaveLength(0);
    expect(ofRule(analyse(`const l = process.env.LOG_LEVEL || 'info';`), 'hardcoded-fallback-secret')).toHaveLength(0);
    expect(ofRule(analyse(`const t = process.env.API_TOKEN || '';`), 'hardcoded-fallback-secret')).toHaveLength(0);
    expect(ofRule(analyse(`const c = process.env.CLIENT_SECRET || 'changeme';`), 'hardcoded-fallback-secret')).toHaveLength(0);
  });

  it('ignores a secret read with no fallback at all', () => {
    expect(ofRule(analyse(`const s = process.env.JWT_SECRET;`), 'hardcoded-fallback-secret')).toHaveLength(0);
  });
});

describe('cors-credentials-reflected-origin', () => {
  it('flags origin:true with credentials:true', () => {
    const findings = ofRule(analyse(`app.use(cors({ origin: true, credentials: true }));`), 'cors-credentials');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
  });

  it('flags key order independently', () => {
    expect(ofRule(analyse(`app.use(cors({ credentials: true, origin: true }));`), 'cors-credentials')).toHaveLength(1);
  });

  it('flags an origin reflected from the request', () => {
    expect(
      ofRule(analyse(`app.use(cors({ origin: req.headers.origin, credentials: true }));`), 'cors-credentials'),
    ).toHaveLength(1);
  });

  it('flags an unconditional cb(null, true) callback', () => {
    const code = `app.use(cors({ origin: (o, cb) => cb(null, true), credentials: true }));`;
    expect(ofRule(analyse(code), 'cors-credentials')).toHaveLength(1);
  });

  it('does not flag a callback that checks an allowlist', () => {
    const code = `app.use(cors({ origin: (o, cb) => cb(null, LIST.includes(o)), credentials: true }));`;
    expect(ofRule(analyse(code), 'cors-credentials')).toHaveLength(0);
  });

  it('rates wildcard-with-credentials low, because browsers refuse it', () => {
    const findings = ofRule(analyse(`app.use(cors({ origin: '*', credentials: true }));`), 'cors-credentials');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('low');
  });

  it('does not flag an explicit allowlist, or reflection without credentials', () => {
    expect(ofRule(analyse(`app.use(cors({ origin: ['https://a.example'], credentials: true }));`), 'cors-credentials')).toHaveLength(0);
    expect(ofRule(analyse(`app.use(cors({ origin: true }));`), 'cors-credentials')).toHaveLength(0);
  });
});

describe('unauthenticated-secret-exposure', () => {
  it('flags a secret-shaped field on an unauthenticated route', () => {
    const code = `app.get('/api/health', (_req, res) => { res.json({ ok: true, apiKey: SECRET }); });`;
    const findings = ofRule(analyse(code), 'unauthenticated-secret-exposure');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
  });

  it('rates a truncated value medium rather than high', () => {
    const code = `app.get('/api/health', (_req, res) => { res.json({ preview: 'x', fakeAiKeyPreview: \`\${KEY.slice(0, 8)}...\` }); });`;
    const findings = ofRule(analyse(code), 'unauthenticated-secret-exposure');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('medium');
  });

  it('matches camelCase compounds, not just whole words', () => {
    const code = `app.get('/x', (q, res) => { res.json({ signingKeyId: 1 }); });`;
    expect(ofRule(analyse(code), 'unauthenticated-secret-exposure')).toHaveLength(1);
  });

  it('does not flag a login route returning a token', () => {
    const code = `app.post('/api/login', (req, res) => { res.json({ token: t, email: e }); });`;
    expect(ofRule(analyse(code), 'unauthenticated-secret-exposure')).toHaveLength(0);
  });

  it('does not flag a register route returning a token', () => {
    const code = `app.post('/api/register', (req, res) => { res.json({ token: t }); });`;
    expect(ofRule(analyse(code), 'unauthenticated-secret-exposure')).toHaveLength(0);
  });

  it('still flags a non-token secret on a login route', () => {
    const code = `app.post('/api/login', (req, res) => { res.json({ token: t, dbPassword: p }); });`;
    expect(ofRule(analyse(code), 'unauthenticated-secret-exposure')).toHaveLength(1);
  });

  it('does not flag a route behind auth middleware', () => {
    const code = `app.get('/api/me', requireAuth, (req, res) => { res.json({ apiKey: k }); });`;
    expect(ofRule(analyse(code), 'unauthenticated-secret-exposure')).toHaveLength(0);
  });

  it('respects auth applied globally before the route', () => {
    const code = [
      `app.use(requireAuth);`,
      `app.get('/api/me', (req, res) => { res.json({ apiKey: k }); });`,
    ].join('\n');
    expect(ofRule(analyse(code), 'unauthenticated-secret-exposure')).toHaveLength(0);
  });

  it('does not credit global auth registered after the route, since Express is order-dependent', () => {
    const code = [
      `app.get('/api/me', (req, res) => { res.json({ apiKey: k }); });`,
      `app.use(requireAuth);`,
    ].join('\n');
    expect(ofRule(analyse(code), 'unauthenticated-secret-exposure')).toHaveLength(1);
  });

  it('respects a mounted auth prefix that covers the route', () => {
    const code = [
      `app.use('/api', requireAuth);`,
      `app.get('/api/me', (req, res) => { res.json({ apiKey: k }); });`,
    ].join('\n');
    expect(ofRule(analyse(code), 'unauthenticated-secret-exposure')).toHaveLength(0);
  });

  it('does not apply a mounted prefix to a route outside it', () => {
    const code = [
      `app.use('/admin', requireAuth);`,
      `app.get('/api/me', (req, res) => { res.json({ apiKey: k }); });`,
    ].join('\n');
    expect(ofRule(analyse(code), 'unauthenticated-secret-exposure')).toHaveLength(1);
  });

  it('ignores words that merely contain "key"', () => {
    const code = `app.get('/x', (q, res) => { res.json({ keyboard: 1, monkey: 2, keyword: 3 }); });`;
    expect(ofRule(analyse(code), 'unauthenticated-secret-exposure')).toHaveLength(0);
  });
});

describe('missing-rate-limit-auth-route', () => {
  it('flags an unlimited login route', () => {
    const findings = ofRule(analyse(`app.post('/api/login', (req, res) => { res.json({}); });`), 'missing-rate-limit');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('medium');
  });

  it('does not flag a route with a limiter in its chain', () => {
    const code = `app.post('/api/login', authLimiter, (req, res) => { res.json({}); });`;
    expect(ofRule(analyse(code), 'missing-rate-limit')).toHaveLength(0);
  });

  it('does not flag when a limiter is applied globally beforehand', () => {
    const code = [
      `app.use(rateLimit({ windowMs: 1000, limit: 5 }));`,
      `app.post('/api/login', (req, res) => { res.json({}); });`,
    ].join('\n');
    expect(ofRule(analyse(code), 'missing-rate-limit')).toHaveLength(0);
  });

  it('does not flag non-credential routes', () => {
    expect(ofRule(analyse(`app.post('/api/tasks', (req, res) => { res.json({}); });`), 'missing-rate-limit')).toHaveLength(0);
  });

  it('does not flag a GET on an auth path, which renders rather than guesses', () => {
    expect(ofRule(analyse(`app.get('/login', (req, res) => { res.json({}); });`), 'missing-rate-limit')).toHaveLength(0);
  });
});

describe('missing-input-validation-schema', () => {
  it('rates credential routes medium and other mutating routes low', () => {
    const credential = ofRule(
      analyse(`app.post('/api/register', (req, res) => { res.status(400).json({}); });`),
      'missing-input-validation-schema',
    );
    expect(credential).toHaveLength(1);
    expect(credential[0]!.severity).toBe('medium');

    const other = ofRule(
      analyse(`app.post('/api/tasks', (req, res) => { res.status(400).json({}); });`),
      'missing-input-validation-schema',
    );
    expect(other).toHaveLength(1);
    expect(other[0]!.severity).toBe('low');
  });

  it('does not flag a route using a zod schema', () => {
    const code = `app.post('/api/register', (req, res) => { const p = schema.safeParse(req.body); res.json(p); });`;
    expect(ofRule(analyse(code), 'missing-input-validation-schema')).toHaveLength(0);
  });

  it('does not flag a route with validation middleware', () => {
    const code = `app.post('/api/register', validateBody(schema), (req, res) => { res.json({}); });`;
    expect(ofRule(analyse(code), 'missing-input-validation-schema')).toHaveLength(0);
  });

  it('does not flag DELETE, which carries no body', () => {
    expect(
      ofRule(analyse(`app.delete('/api/tasks/:id', (req, res) => { res.json({}); });`), 'missing-input-validation-schema'),
    ).toHaveLength(0);
  });

  it('does not flag GET', () => {
    expect(
      ofRule(analyse(`app.get('/api/tasks', (req, res) => { res.json({}); });`), 'missing-input-validation-schema'),
    ).toHaveLength(0);
  });

  it('says so when hand-rolled checks are present rather than implying none exist', () => {
    const withChecks = ofRule(
      analyse(`app.post('/api/tasks', (req, res) => { const t = String(req.body.t); if (!t) return res.status(400).json({}); res.json({}); });`),
      'missing-input-validation-schema',
    );
    expect(withChecks[0]!.description).toContain('hand-rolled checks');

    const withoutChecks = ofRule(
      analyse(`app.post('/api/tasks', (req, res) => { db.insert(req.body); res.json({}); });`),
      'missing-input-validation-schema',
    );
    expect(withoutChecks[0]!.description).toContain('No validation of any kind');
  });
});

describe('schema-drift', () => {
  it('flags the same table defined twice with different constraints', () => {
    const a: SourceFile = {
      absPath: '/v/a.js',
      relPath: 'a.js',
      ext: '.js',
      text: 'db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL);`);',
    };
    const b: SourceFile = {
      absPath: '/v/b.js',
      relPath: 'b.js',
      ext: '.js',
      text: 'db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE);`);',
    };
    const findings = ofRule(runBuiltinRules([a, b]).findings, 'schema-drift');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.description).toContain('NOT NULL');
    // Reported against the weaker definition — the one to bring up to parity.
    expect(findings[0]!.file_path).toBe('b.js');
  });

  it('does not flag identical definitions', () => {
    const text = 'db.exec(`CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, a TEXT NOT NULL);`);';
    const a: SourceFile = { absPath: '/v/a.js', relPath: 'a.js', ext: '.js', text };
    const b: SourceFile = { absPath: '/v/b.js', relPath: 'b.js', ext: '.js', text };
    expect(ofRule(runBuiltinRules([a, b]).findings, 'schema-drift')).toHaveLength(0);
  });

  it('does not flag a table defined only once', () => {
    const a: SourceFile = {
      absPath: '/v/a.sql',
      relPath: 'a.sql',
      ext: '.sql',
      text: 'CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL);',
    };
    expect(ofRule(runBuiltinRules([a]).findings, 'schema-drift')).toHaveLength(0);
  });

  it('detects type and default differences, not just constraints', () => {
    const a: SourceFile = {
      absPath: '/v/a.sql',
      relPath: 'a.sql',
      ext: '.sql',
      text: "CREATE TABLE t (id INTEGER PRIMARY KEY, status TEXT DEFAULT 'open');",
    };
    const b: SourceFile = {
      absPath: '/v/b.sql',
      relPath: 'b.sql',
      ext: '.sql',
      text: 'CREATE TABLE t (id INTEGER PRIMARY KEY, status VARCHAR(20));',
    };
    const findings = ofRule(runBuiltinRules([a, b]).findings, 'schema-drift');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.description).toMatch(/DEFAULT|VARCHAR/);
  });
});

describe('fixture repositories', () => {
  it('finds the expected defect set in the vulnerable fixture', () => {
    const findings = runBuiltinRules(walkSource(VULNERABLE).files).findings;
    const byRule = new Map<string, number>();
    for (const f of findings) byRule.set(f.rule_id, (byRule.get(f.rule_id) ?? 0) + 1);

    expect(byRule.get('proofscan.hardcoded-fallback-secret')).toBe(2);
    expect(byRule.get('proofscan.cors-credentials-reflected-origin')).toBe(1);
    expect(byRule.get('proofscan.unauthenticated-secret-exposure')).toBe(1);
    expect(byRule.get('proofscan.missing-rate-limit-auth-route')).toBe(2);
    expect(byRule.get('proofscan.schema-drift')).toBe(1);
    expect(byRule.get('proofscan.missing-input-validation-schema')).toBe(3);
  });

  it('reports nothing on the clean fixture', () => {
    const findings = runBuiltinRules(walkSource(CLEAN).files).findings;
    expect(findings.map((f) => `${f.rule_id} ${f.file_path}:${f.line}`)).toEqual([]);
  });
});

describe('parser resilience', () => {
  it('surfaces parse failures instead of silently reporting zero findings', () => {
    const broken: SourceFile = {
      absPath: '/v/broken.js',
      relPath: 'broken.js',
      ext: '.js',
      text: 'const a = {{{ ??? function(',
    };
    const result = runBuiltinRules([broken]);
    expect(result.parseFailures.length).toBeGreaterThan(0);
    expect(result.parseFailures[0]!.relPath).toBe('broken.js');
  });

  it('handles TypeScript and JSX without special-casing', () => {
    const ts: SourceFile = {
      absPath: '/v/a.ts',
      relPath: 'a.ts',
      ext: '.ts',
      text: `const s: string = process.env.JWT_SECRET || 'fallback-value';`,
    };
    expect(ofRule(runBuiltinRules([ts]).findings, 'hardcoded-fallback-secret')).toHaveLength(1);

    const tsx: SourceFile = {
      absPath: '/v/a.tsx',
      relPath: 'a.tsx',
      ext: '.tsx',
      text: `const K = process.env.API_KEY || 'abc123';\nexport const C = () => <div>{K}</div>;`,
    };
    expect(ofRule(runBuiltinRules([tsx]).findings, 'hardcoded-fallback-secret')).toHaveLength(1);
  });
});
