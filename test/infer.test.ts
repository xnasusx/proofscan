import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inferPlan, mergeConfig } from '../src/exploit/infer.js';
import type { SourceFile } from '../src/core/walk.js';

const HERE = dirname(fileURLToPath(import.meta.url));

function sourceOf(fixture: string): SourceFile {
  const path = join(HERE, 'fixtures', 'repo', fixture, 'server.js');
  return { absPath: path, relPath: 'server.js', ext: '.js', text: readFileSync(path, 'utf8') };
}

describe('exploit plan inference — agnosticism', () => {
  it('reconstructs FlaudeCode-shaped conventions from source', () => {
    const plan = inferPlan([sourceOf('vulnerable')]);
    expect(plan.auth.registerPath).toBe('/api/register');
    expect(plan.auth.loginPath).toBe('/api/login');
    expect(plan.auth.usernameField).toBe('email');
    expect(plan.auth.passwordField).toBe('password');
    expect(plan.auth.tokenField).toBe('token');

    const tasks = plan.resources.find((r) => r.collectionPath === '/api/tasks');
    expect(tasks).toBeDefined();
    expect(tasks!.itemPathTemplate).toBe('/api/tasks/:id');
    expect(tasks!.methods).toContain('DELETE');
    expect(tasks!.createFields).toContain('title');
    // (This hermetic fixture has no notes route; child-collection detection is
    // covered by the bookmarks fixture, which does have one.)
  });

  it('reconstructs a completely different app with zero shared naming', () => {
    // The bookmarks fixture shares nothing with FlaudeCode's surface.
    const plan = inferPlan([sourceOf('second-app')]);
    expect(plan.auth.registerPath).toBe('/auth/signup');
    expect(plan.auth.loginPath).toBe('/auth/token');
    expect(plan.auth.usernameField).toBe('username'); // not "email"
    expect(plan.auth.passwordField).toBe('passphrase'); // not "password"
    expect(plan.auth.tokenField).toBe('accessToken'); // not "token"

    const bookmarks = plan.resources.find((r) => r.collectionPath === '/v1/bookmarks');
    expect(bookmarks).toBeDefined();
    expect(bookmarks!.itemPathTemplate).toBe('/v1/bookmarks/:bookmarkId'); // not :id
    expect(bookmarks!.methods.sort()).toEqual(['DELETE', 'GET', 'PATCH']);
    expect(bookmarks!.childCollectionTemplate).toBe('/v1/bookmarks/:bookmarkId/tags'); // not /notes
    expect(bookmarks!.createFields.sort()).toEqual(['label', 'url']); // not title/content
  });

  it('does not invent a resource with no create endpoint', () => {
    const noCreate: SourceFile = {
      absPath: '/v/a.js',
      relPath: 'a.js',
      ext: '.js',
      text: `
        const requireAuth = (req, res, next) => next();
        app.delete('/api/widgets/:id', requireAuth, (req, res) => {
          db.prepare('DELETE FROM widgets WHERE id = ?').run(Number(req.params.id));
          res.json({});
        });`,
    };
    expect(inferPlan([noCreate]).resources).toHaveLength(0);
  });

  it('lets operator config override inference', () => {
    const base = inferPlan([sourceOf('vulnerable')]);
    const merged = mergeConfig(base, {
      auth: { token_field: 'jwt', identities: [{ username: 'x', password: 'y' }, { username: 'a', password: 'b' }] },
      resources: [{ collection: '/api/tasks', id_field: 'taskId', methods: ['DELETE'] }],
    });
    expect(merged.auth.tokenField).toBe('jwt');
    expect(merged.auth.identities).toHaveLength(2);
    const tasks = merged.resources.find((r) => r.collectionPath === '/api/tasks')!;
    expect(tasks.idField).toBe('taskId'); // config replaced the inferred resource
    expect(tasks.methods).toEqual(['DELETE']);
  });
});
