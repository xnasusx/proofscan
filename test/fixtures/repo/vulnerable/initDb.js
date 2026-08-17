// TEST FIXTURE — intentionally drifted schema. Not deployable code.
//
// Defines the same `users` table as server.js but without the NOT NULL
// constraints, which is the positive case for proofscan.schema-drift. Because
// both use CREATE TABLE IF NOT EXISTS, whichever runs first wins silently.

const Database = require('better-sqlite3');

const db = new Database('./app.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

console.log('Database initialised');
