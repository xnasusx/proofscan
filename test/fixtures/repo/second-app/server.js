// TEST FIXTURE — a second, deliberately different vulnerable app. Not deployable.
//
// This exists to prove proofscan is target-agnostic: it shares NOTHING with the
// FlaudeCode fixture's surface — different auth paths (/auth/signup, /auth/token
// rather than /api/register, /api/login), different credential fields (username
// / passphrase rather than email / password), a different token field
// (accessToken rather than token), a different resource (bookmarks with a tags
// child, not tasks with notes), a different id parameter name (:bookmarkId), and
// a different secret env var (APP_TOKEN_SECRET). The tool is given NO
// app-specific configuration; it must infer all of this from the source (Layer
// 2) or from a manifest (Layer 3) and still find the authorisation-ordering bug.
//
// The "secret" below is a fabricated placeholder for the test suite.

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const PORT = Number(process.env.PORT) || 4100;
// Note the non-standard env var name — the sandbox must inject a value for
// whatever secret-shaped env var the app actually reads, not a hardcoded one.
const APP_TOKEN_SECRET = process.env.APP_TOKEN_SECRET || 'placeholder-token-secret-change-me';

const db = new Database(':memory:');
db.exec(`
  CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, passphrase TEXT NOT NULL);
  CREATE TABLE bookmarks (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, url TEXT NOT NULL, label TEXT);
  CREATE TABLE tags (id INTEGER PRIMARY KEY AUTOINCREMENT, bookmark_id INTEGER NOT NULL, name TEXT NOT NULL);
`);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

const sign = (user) => jwt.sign({ id: user.id, username: user.username }, APP_TOKEN_SECRET, { expiresIn: '1d' });

const auth = (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    req.principal = jwt.verify(token, APP_TOKEN_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

app.get('/status', (_req, res) => res.json({ ok: true, service: 'bookmarks' }));

app.post('/auth/signup', (req, res) => {
  const username = String(req.body?.username || '').trim();
  const passphrase = String(req.body?.passphrase || '');
  if (!username || !passphrase) return res.status(400).json({ message: 'username and passphrase required' });
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ message: 'exists' });
  const result = db.prepare('INSERT INTO users (username, passphrase) VALUES (?, ?)').run(username, passphrase);
  const user = { id: result.lastInsertRowid, username };
  res.status(201).json({ accessToken: sign(user), username });
});

app.post('/auth/token', (req, res) => {
  const username = String(req.body?.username || '').trim();
  const passphrase = String(req.body?.passphrase || '');
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || user.passphrase !== passphrase) return res.status(401).json({ message: 'invalid' });
  res.json({ accessToken: sign(user), username: user.username });
});

app.get('/v1/bookmarks', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM bookmarks WHERE owner_id = ? ORDER BY id DESC').all(req.principal.id));
});

app.post('/v1/bookmarks', auth, (req, res) => {
  const url = String(req.body?.url || '').trim();
  const label = String(req.body?.label || '');
  if (!url) return res.status(400).json({ message: 'url required' });
  const result = db.prepare('INSERT INTO bookmarks (owner_id, url, label) VALUES (?, ?, ?)').run(req.principal.id, url, label);
  res.status(201).json(db.prepare('SELECT * FROM bookmarks WHERE id = ?').get(result.lastInsertRowid));
});

// Ownership-scoped read — must NOT be flagged.
app.get('/v1/bookmarks/:bookmarkId', auth, (req, res) => {
  const bookmark = db
    .prepare('SELECT * FROM bookmarks WHERE id = ? AND owner_id = ?')
    .get(Number(req.params.bookmarkId), req.principal.id);
  if (!bookmark) return res.status(404).json({ message: 'not found' });
  res.json(bookmark);
});

// Ownership-scoped update — must NOT be flagged.
app.patch('/v1/bookmarks/:bookmarkId', auth, (req, res) => {
  const bookmarkId = Number(req.params.bookmarkId);
  const owned = db.prepare('SELECT id FROM bookmarks WHERE id = ? AND owner_id = ?').get(bookmarkId, req.principal.id);
  if (!owned) return res.status(404).json({ message: 'not found' });
  db.prepare('UPDATE bookmarks SET label = ? WHERE id = ? AND owner_id = ?').run(
    String(req.body?.label || ''),
    bookmarkId,
    req.principal.id,
  );
  res.json({ ok: true });
});

// THE BUG: deletes the bookmark's tags before checking ownership. A non-owner's
// DELETE returns 404, but the victim's tags are already gone — the same
// authorisation-ordering class as the FlaudeCode notes-deletion bug, in a
// completely different app shape.
app.delete('/v1/bookmarks/:bookmarkId', auth, (req, res) => {
  const bookmarkId = Number(req.params.bookmarkId);
  db.prepare('DELETE FROM tags WHERE bookmark_id = ?').run(bookmarkId);
  const result = db.prepare('DELETE FROM bookmarks WHERE id = ? AND owner_id = ?').run(bookmarkId, req.principal.id);
  if (!result.changes) return res.status(404).json({ message: 'Bookmark not found' });
  res.json({ ok: true });
});

app.get('/v1/bookmarks/:bookmarkId/tags', auth, (req, res) => {
  const owned = db.prepare('SELECT id FROM bookmarks WHERE id = ? AND owner_id = ?').get(Number(req.params.bookmarkId), req.principal.id);
  if (!owned) return res.status(404).json({ message: 'not found' });
  res.json(db.prepare('SELECT * FROM tags WHERE bookmark_id = ?').all(Number(req.params.bookmarkId)));
});

app.post('/v1/bookmarks/:bookmarkId/tags', auth, (req, res) => {
  const bookmarkId = Number(req.params.bookmarkId);
  const owned = db.prepare('SELECT id FROM bookmarks WHERE id = ? AND owner_id = ?').get(bookmarkId, req.principal.id);
  if (!owned) return res.status(404).json({ message: 'not found' });
  const result = db.prepare('INSERT INTO tags (bookmark_id, name) VALUES (?, ?)').run(bookmarkId, String(req.body?.name || 'tag'));
  res.status(201).json(db.prepare('SELECT * FROM tags WHERE id = ?').get(result.lastInsertRowid));
});

app.listen(PORT, () => console.log(`bookmarks API on http://localhost:${PORT}`));
