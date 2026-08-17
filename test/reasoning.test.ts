import { describe, expect, it } from 'vitest';
import { parseFile } from '../src/analyzers/builtin/parse.js';
import { buildMutationInventory } from '../src/analyzers/reasoning/inventory.js';
import { heuristicReasoner } from '../src/analyzers/reasoning/reasoner.js';
import { runReasoningLayer } from '../src/analyzers/reasoning/index.js';
import type { SourceFile } from '../src/core/walk.js';

function file(code: string, relPath = 'server.js'): SourceFile {
  return { absPath: `/virtual/${relPath}`, relPath, ext: '.js', text: code };
}

function inventoryOf(code: string) {
  return buildMutationInventory(parseFile(file(code)));
}

describe('mutation inventory', () => {
  it('flags a delete that runs before its ownership check as a candidate', () => {
    const code = `
      const requireAuth = (req, res, next) => next();
      app.delete('/api/tasks/:id', requireAuth, (req, res) => {
        const taskId = Number(req.params.id);
        db.prepare('DELETE FROM notes WHERE task_id = ?').run(taskId);
        const result = db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?').run(taskId, req.user.id);
        if (!result.changes) return res.status(404).json({ message: 'Task not found' });
        res.json({ ok: true });
      });`;
    const handlers = inventoryOf(code).filter((h) => h.candidate);
    expect(handlers).toHaveLength(1);
    expect(handlers[0]!.suspect_operation?.verb).toBe('DELETE');
    expect(handlers[0]!.suspect_operation?.table).toBe('notes');
  });

  it('does not flag a mutation already scoped to the caller', () => {
    const code = `
      const requireAuth = (req, res, next) => next();
      app.put('/api/tasks/:id', requireAuth, (req, res) => {
        const taskId = Number(req.params.id);
        const existing = db.prepare('SELECT * FROM tasks WHERE id = ? AND user_id = ?').get(taskId, req.user.id);
        if (!existing) return res.status(404).json({ message: 'not found' });
        db.prepare('UPDATE tasks SET title = ? WHERE id = ? AND user_id = ?').run(req.body.title, taskId, req.user.id);
        res.json({ ok: true });
      });`;
    expect(inventoryOf(code).filter((h) => h.candidate)).toHaveLength(0);
  });

  it('does not flag a create (no prior owner to check)', () => {
    const code = `
      const requireAuth = (req, res, next) => next();
      app.post('/api/tasks', requireAuth, (req, res) => {
        const title = String(req.body.title);
        if (!title) return res.status(400).json({ message: 'required' });
        db.prepare('INSERT INTO tasks (user_id, title) VALUES (?, ?)').run(req.user.id, title);
        res.status(201).json({ ok: true });
      });`;
    expect(inventoryOf(code).filter((h) => h.candidate)).toHaveLength(0);
  });

  it('does not treat an unauthenticated route as an authorisation candidate', () => {
    const code = `
      app.post('/api/register', (req, res) => {
        db.prepare('INSERT INTO users (email) VALUES (?)').run(req.body.email);
        res.json({ ok: true });
      });`;
    const handlers = inventoryOf(code);
    expect(handlers.every((h) => !h.candidate)).toBe(true);
  });

  it('records operations in source (execution) order', () => {
    const code = `
      const requireAuth = (req, res, next) => next();
      app.delete('/api/x/:id', requireAuth, (req, res) => {
        db.prepare('DELETE FROM child WHERE parent_id = ?').run(Number(req.params.id));
        const own = db.prepare('SELECT id FROM x WHERE id = ? AND user_id = ?').get(Number(req.params.id), req.user.id);
        if (!own) return res.status(404).json({});
        res.json({});
      });`;
    const handler = inventoryOf(code).find((h) => h.candidate)!;
    const kinds = handler.operations.map((o) => o.kind);
    // The delete comes before the ownership check — that ordering is the bug.
    expect(kinds.indexOf('mutation')).toBeLessThan(kinds.indexOf('ownership-check'));
  });

  it('does not double-count a prepared-statement chain', () => {
    const code = `
      const requireAuth = (req, res, next) => next();
      app.post('/api/tasks', requireAuth, (req, res) => {
        db.prepare('INSERT INTO tasks (user_id, title) VALUES (?, ?)').run(req.user.id, req.body.title);
        res.json({});
      });`;
    const handler = inventoryOf(code)[0]!;
    expect(handler.operations.filter((o) => o.kind === 'mutation')).toHaveLength(1);
  });
});

describe('heuristic reasoner', () => {
  it('is always available and needs no network', async () => {
    expect((await heuristicReasoner.available()).ok).toBe(true);
  });

  it('flags a candidate with a concrete exploit outline, never above medium confidence', async () => {
    const code = `
      const requireAuth = (req, res, next) => next();
      app.delete('/api/tasks/:id', requireAuth, (req, res) => {
        const taskId = Number(req.params.id);
        db.prepare('DELETE FROM notes WHERE task_id = ?').run(taskId);
        db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?').run(taskId, req.user.id);
        res.json({ ok: true });
      });`;
    const candidate = buildMutationInventory(parseFile(file(code))).find((h) => h.candidate)!;
    const { verdict } = await heuristicReasoner.judge(candidate);
    expect(verdict.flagged).toBe(true);
    expect(verdict.confidence).toBe('medium'); // never 'high' — it cannot see beyond the inventory
    expect(verdict.exploit_outline).toContain('DELETE');
    expect(verdict.observable_impact.length).toBeGreaterThan(0);
  });
});

describe('reasoning layer', () => {
  it('defaults to the heuristic reasoner and finds the ordering bug', async () => {
    const code = `
      const requireAuth = (req, res, next) => next();
      app.delete('/api/tasks/:id', requireAuth, (req, res) => {
        const taskId = Number(req.params.id);
        db.prepare('DELETE FROM notes WHERE task_id = ?').run(taskId);
        db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?').run(taskId, req.user.id);
        res.json({});
      });`;
    const result = await runReasoningLayer([file(code)], { reasoner: 'heuristic' });
    expect(result.reasonerUsed).toBe('heuristic');
    expect(result.candidatesConsidered).toBe(1);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.status).toBe('unverified-flagged'); // never verified by reasoning alone
    expect(result.usage).toBeNull(); // no model call
  });

  it('produces no findings on a correctly-scoped handler', async () => {
    const code = `
      const requireAuth = (req, res, next) => next();
      app.put('/api/tasks/:id', requireAuth, (req, res) => {
        const taskId = Number(req.params.id);
        const existing = db.prepare('SELECT * FROM tasks WHERE id = ? AND user_id = ?').get(taskId, req.user.id);
        if (!existing) return res.status(404).json({});
        db.prepare('UPDATE tasks SET title = ? WHERE id = ? AND user_id = ?').run(req.body.title, taskId, req.user.id);
        res.json({});
      });`;
    const result = await runReasoningLayer([file(code)], { reasoner: 'heuristic' });
    expect(result.findings).toHaveLength(0);
  });
});
