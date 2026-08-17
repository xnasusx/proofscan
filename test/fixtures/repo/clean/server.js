// TEST FIXTURE — the negative control.
//
// The same application as ../vulnerable/server.js, written correctly. Every
// built-in rule must stay silent on this file. This is the half of a scanner's
// test suite that usually gets skipped, and it is the half that decides whether
// the tool is usable: a rule that fires here produces false positives on
// correct code, which is how scanners lose their audience.

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const Database = require('better-sqlite3');

const app = express();
const db = new Database('./app.db');

// No fallback: fail closed when the environment is not configured.
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET is required');

const PORT = Number(process.env.PORT) || 4000;

// Explicit allowlist rather than a reflected origin.
const ALLOWED_ORIGINS = ['https://app.example.com'];
app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));
app.use(express.json());

const authLimiter = rateLimit({ windowMs: 60_000, limit: 10 });

const credentialsSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(12).max(200)
});

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

// Liveness only — nothing key-derived.
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, mode: 'production' });
});

// Rate limited and schema validated.
app.post('/api/register', authLimiter, async (req, res) => {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: 'Invalid credentials payload' });
  const result = db
    .prepare('INSERT INTO users (email, password) VALUES (?, ?)')
    .run(parsed.data.email, parsed.data.password);
  res.status(201).json({ token: jwt.sign({ id: result.lastInsertRowid }, JWT_SECRET) });
});

app.post('/api/login', authLimiter, async (req, res) => {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: 'Invalid credentials payload' });
  res.json({ token: jwt.sign({ email: parsed.data.email }, JWT_SECRET) });
});

const taskSchema = z.object({ title: z.string().min(1).max(200) });

app.post('/api/tasks', requireAuth, (req, res) => {
  const parsed = taskSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: 'Invalid task payload' });
  const result = db
    .prepare('INSERT INTO tasks (user_id, title) VALUES (?, ?)')
    .run(req.user.id, parsed.data.title);
  res.status(201).json({ id: result.lastInsertRowid });
});

app.listen(PORT);
