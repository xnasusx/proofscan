// TEST FIXTURE — intentionally vulnerable. Not deployable code.
//
// Every "secret" in this file is a fabricated placeholder written for the test
// suite. None of these values authorise anything anywhere. This file exists so
// the rules have a positive case to fire on; see ../clean/server.js for the
// negative control that the same rules must stay silent on.
//
// The patterns here mirror the FlaudeCode validation fixture named in the build
// spec, so the offline test suite covers the same defects as the acceptance run
// without needing to clone anything.

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const db = new Database('./app.db');

// Rule: proofscan.hardcoded-fallback-secret (critical — token-signing key)
const JWT_SECRET = process.env.JWT_SECRET || 'demo-jwt-secret-change-me';
// Rule: proofscan.hardcoded-fallback-secret (high — third-party credential)
const FAKE_AI_API_KEY = process.env.API_SECRET || 'FAKE_API_KEY_123';
// Must NOT fire: placeholder fallback, and a non-secret name.
const PORT = Number(process.env.PORT) || 4000;
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const OPTIONAL_TOKEN = process.env.OPTIONAL_TOKEN || '';

// Rule: proofscan.cors-credentials-reflected-origin (high)
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

const requireAuth = (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Rule: proofscan.unauthenticated-secret-exposure (medium — value is truncated)
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    mode: 'demo',
    fakeAiKeyPreview: `${FAKE_AI_API_KEY.slice(0, 8)}...`
  });
});

// Must NOT fire on unauthenticated-secret-exposure: a credential-issuing route
// is supposed to return a token. Firing here would be a false positive on
// essentially every application.
// Rules that SHOULD fire: missing-rate-limit-auth-route,
// missing-input-validation-schema (both medium — credential route).
app.post('/api/register', async (req, res) => {
  const email = String(req.body?.email || '').trim();
  const password = String(req.body?.password || '');
  if (!email || !password) return res.status(400).json({ message: 'Required' });
  const result = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)').run(email, password);
  res.status(201).json({ token: jwt.sign({ id: result.lastInsertRowid }, JWT_SECRET), email });
});

app.post('/api/login', async (req, res) => {
  const email = String(req.body?.email || '').trim();
  res.json({ token: jwt.sign({ email }, JWT_SECRET), email });
});

// Rule: proofscan.missing-input-validation-schema (low — authenticated, non-credential)
app.post('/api/tasks', requireAuth, (req, res) => {
  const title = String(req.body?.title || '').trim();
  if (!title) return res.status(400).json({ message: 'Title is required' });
  const result = db.prepare('INSERT INTO tasks (user_id, title) VALUES (?, ?)').run(req.user.id, title);
  res.status(201).json({ id: result.lastInsertRowid, title });
});

// Must NOT fire on unauthenticated-secret-exposure: authenticated via middleware.
app.get('/api/profile', requireAuth, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, apiKey: 'irrelevant-but-authenticated' });
});

// Must NOT fire on missing-input-validation-schema: DELETE carries no body.
app.delete('/api/tasks/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?').run(Number(req.params.id), req.user.id);
  res.json({ ok: true });
});

app.listen(PORT);
