const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'vault.db');
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('super_admin', 'admin', 'editor', 'viewer')),
    scope TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    last_used_at TEXT,
    is_active INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    uploaded_by TEXT,
    uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    version INTEGER NOT NULL DEFAULT 1,
    is_archived INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS categories (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    slug TEXT NOT NULL UNIQUE,
    description TEXT,
    icon TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    min_role TEXT NOT NULL DEFAULT 'viewer'
  );

  CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    token_name TEXT,
    ip_address TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);
  CREATE INDEX IF NOT EXISTS idx_documents_uploaded_at ON documents(uploaded_at);
  CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at);
  CREATE INDEX IF NOT EXISTS idx_activity_log_created_at ON activity_log(created_at);

  CREATE TABLE IF NOT EXISTS equity_pools (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    total_shares INTEGER NOT NULL,
    class TEXT NOT NULL DEFAULT 'Common',
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS shareholders (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT,
    type TEXT NOT NULL CHECK(type IN ('founder','investor','employee','advisor')),
    shares_owned INTEGER NOT NULL DEFAULT 0,
    equity_pool_id TEXT NOT NULL REFERENCES equity_pools(id),
    vesting_start TEXT,
    vesting_end TEXT,
    cliff_date TEXT,
    vested_shares INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','vesting','fully_vested','exited')),
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS cap_table_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL CHECK(event_type IN ('issuance','transfer','vest','cancel','convert','edit','pool_create','pool_update')),
    shareholder_id TEXT REFERENCES shareholders(id),
    shares_before INTEGER,
    shares_after INTEGER,
    delta_shares INTEGER,
    equity_pool_id TEXT REFERENCES equity_pools(id),
    description TEXT,
    performed_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_shareholders_pool ON shareholders(equity_pool_id);
  CREATE INDEX IF NOT EXISTS idx_cap_events_shareholder ON cap_table_events(shareholder_id);
  CREATE INDEX IF NOT EXISTS idx_cap_events_created ON cap_table_events(created_at);
`);

// Migration: add scope column if it doesn't exist
try {
  db.exec(`ALTER TABLE tokens ADD COLUMN scope TEXT`);
  console.log('Migration: added scope column to tokens');
} catch (e) {
  // Column already exists — ignore
}

module.exports = db;
