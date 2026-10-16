const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');
const cap = require('./captable');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
const TOKEN_EXPIRY_HOURS = parseInt(process.env.TOKEN_EXPIRY_HOURS || '24');

// Ensure upload dirs exist
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));

// File upload config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => cb(null, true)
});

// ============ AUTH MIDDLEWARE ============
function authenticate(requiredRoles = []) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing or invalid authorization header' });
    }

    const tokenKey = authHeader.split(' ')[1];

    try {
      // Try JWT first (issued after key verification)
      const decoded = jwt.verify(tokenKey, JWT_SECRET);
      req.token = decoded;
      
      if (requiredRoles.length > 0 && !requiredRoles.includes(decoded.role)) {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }
      
      // Parse scope from JWT
      req.token.scope = decoded.scope ? JSON.parse(decoded.scope) : null;
      
      // Update last used
      db.prepare('UPDATE tokens SET last_used_at = datetime(\'now\') WHERE id = ?').run(decoded.tokenId);
      
      next();
    } catch (jwtErr) {
      // Try direct key auth
      const token = db.prepare('SELECT * FROM tokens WHERE is_active = 1 AND expires_at > datetime(\'now\')').all();
      const matched = token.find(t => bcrypt.compareSync(tokenKey, t.key_hash));
      
      if (!matched) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }

      if (requiredRoles.length > 0 && !requiredRoles.includes(matched.role)) {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }

      req.token = { ...matched, tokenId: matched.id };
      req.token.scope = matched.scope ? JSON.parse(matched.scope) : null;
      
      // Update last used
      db.prepare('UPDATE tokens SET last_used_at = datetime(\'now\') WHERE id = ?').run(matched.id);
      
      next();
    }
  };
}

// ============ AUTH ROUTES ============

// Login with API key -> get JWT
app.post('/api/auth/login', (req, res) => {
  const { api_key } = req.body;
  if (!api_key) return res.status(400).json({ error: 'api_key is required' });

  const tokens = db.prepare('SELECT * FROM tokens WHERE is_active = 1 AND expires_at > datetime(\'now\')').all();
  const matched = tokens.find(t => bcrypt.compareSync(api_key, t.key_hash));

  if (!matched) {
    return res.status(401).json({ error: 'Invalid or expired API key' });
  }

  const jti = uuidv4();
  const token = jwt.sign(
    {
      tokenId: matched.id,
      name: matched.name,
      role: matched.role,
      scope: matched.scope,
      jti
    },
    JWT_SECRET,
    { expiresIn: `${TOKEN_EXPIRY_HOURS}h` }
  );

  // Log activity
  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('login', 'token', matched.id, matched.name, 'JWT issued');

  // Update last used
  db.prepare('UPDATE tokens SET last_used_at = datetime(\'now\') WHERE id = ?').run(matched.id);

  res.json({
    token,
    token_name: matched.name,
    role: matched.role,
    expires_in: `${TOKEN_EXPIRY_HOURS}h`,
    permissions: getPermissionsForRole(matched.role)
  });
});

// Verify current token
app.get('/api/auth/verify', authenticate(), (req, res) => {
  res.json({
    valid: true,
    name: req.token.name,
    role: req.token.role,
    permissions: getPermissionsForRole(req.token.role)
  });
});

// ============ TOKEN MANAGEMENT (admin+) ============

// List all tokens
app.get('/api/tokens', authenticate(['super_admin', 'admin']), (req, res) => {
  const tokens = db.prepare(
    'SELECT id, name, role, scope, created_at, expires_at, last_used_at, is_active FROM tokens ORDER BY created_at DESC'
  ).all();
  // Parse scope JSON for each token
  const parsed = tokens.map(t => ({
    ...t,
    scope: t.scope ? JSON.parse(t.scope) : null
  }));
  res.json({ tokens: parsed });
});

// Create a new token
app.post('/api/tokens', authenticate(['super_admin', 'admin']), (req, res) => {
  const { name, role, expiry_hours, scope } = req.body;
  
  if (!name || !role) {
    return res.status(400).json({ error: 'name and role are required' });
  }

  const validRoles = ['super_admin', 'admin', 'editor', 'viewer'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ error: `Invalid role. Must be one of: ${validRoles.join(', ')}` });
  }

  // Super admin can only be created by another super admin
  if (role === 'super_admin' && req.token.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only super admins can create super admin tokens' });
  }

  // Validate scope: must be an array of category slugs, or null/undefined for full access
  let scopeJson = null;
  if (scope && Array.isArray(scope) && scope.length > 0) {
    // Verify all slugs exist
    const validSlugs = db.prepare('SELECT slug FROM categories').all().map(c => c.slug);
    const invalid = scope.filter(s => !validSlugs.includes(s));
    if (invalid.length > 0) {
      return res.status(400).json({ error: `Invalid category slugs: ${invalid.join(', ')}` });
    }
    scopeJson = JSON.stringify(scope);
  }

  const rawKey = 'esk-' + role + '-' + uuidv4().replace(/-/g, '').substring(0, 24);
  const hash = bcrypt.hashSync(rawKey, 10);
  const hours = expiry_hours || (role === 'super_admin' ? 87600 : TOKEN_EXPIRY_HOURS);
  
  const expiresAt = new Date();
  expiresAt.setHours(expiresAt.getHours() + hours);

  const tokenId = uuidv4();
  db.prepare(
    'INSERT INTO tokens (id, name, key_hash, role, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(tokenId, name, hash, role, scopeJson, expiresAt.toISOString());

  // Log
  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('token_created', 'token', tokenId, req.token.name, `Created token "${name}" with role ${role}${scopeJson ? ', scoped to: ' + scope.join(', ') : ''}`);

  res.json({
    id: tokenId,
    name,
    role,
    scope: scope || null,
    raw_key: rawKey,
    expires_at: expiresAt.toISOString(),
    message: 'SAVE THIS KEY - It will not be shown again'
  });
});

// Revoke a token
app.delete('/api/tokens/:id', authenticate(['super_admin', 'admin']), (req, res) => {
  const token = db.prepare('SELECT * FROM tokens WHERE id = ?').get(req.params.id);
  if (!token) return res.status(404).json({ error: 'Token not found' });

  // Super admin tokens can only be revoked by super admin
  if (token.role === 'super_admin' && req.token.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only super admins can revoke super admin tokens' });
  }

  // Can't revoke yourself
  if (token.id === req.token.tokenId) {
    return res.status(400).json({ error: 'Cannot revoke your own token' });
  }

  db.prepare('UPDATE tokens SET is_active = 0 WHERE id = ?').run(req.params.id);

  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('token_revoked', 'token', req.params.id, req.token.name, `Revoked token "${token.name}"`);

  res.json({ message: 'Token revoked successfully' });
});

// Extend token expiry
app.patch('/api/tokens/:id/extend', authenticate(['super_admin', 'admin']), (req, res) => {
  const { hours } = req.body;
  if (!hours || hours < 1) return res.status(400).json({ error: 'hours is required (min 1)' });

  const token = db.prepare('SELECT * FROM tokens WHERE id = ?').get(req.params.id);
  if (!token) return res.status(404).json({ error: 'Token not found' });

  if (token.role === 'super_admin' && req.token.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only super admins can extend super admin tokens' });
  }

  const expiresAt = new Date(token.expires_at);
  expiresAt.setHours(expiresAt.getHours() + hours);

  db.prepare('UPDATE tokens SET expires_at = ? WHERE id = ?').run(expiresAt.toISOString(), req.params.id);

  res.json({ message: 'Token extended', new_expiry: expiresAt.toISOString() });
});

// ============ DOCUMENT ROUTES ============

// List documents (with filters and scope enforcement)
app.get('/api/documents', authenticate(), (req, res) => {
  const { category, search, page = 1, limit = 20 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  
  let sql = 'SELECT id, title, description, category, original_name, mime_type, file_size, uploaded_by, uploaded_at, updated_at, version, is_archived FROM documents WHERE is_archived = 0';
  let countSql = 'SELECT COUNT(*) as total FROM documents WHERE is_archived = 0';
  const params = [];
  const countParams = [];

  // Scope enforcement: if token has a scope, restrict to those categories
  if (req.token.scope && Array.isArray(req.token.scope) && req.token.scope.length > 0) {
    const placeholders = req.token.scope.map(() => '?').join(',');
    sql += ` AND category IN (${placeholders})`;
    countSql += ` AND category IN (${placeholders})`;
    params.push(...req.token.scope);
    countParams.push(...req.token.scope);
  }

  if (category) {
    sql += ' AND category = ?';
    countSql += ' AND category = ?';
    params.push(category);
    countParams.push(category);
  }

  if (search) {
    sql += ' AND (title LIKE ? OR description LIKE ? OR original_name LIKE ?)';
    countSql += ' AND (title LIKE ? OR description LIKE ? OR original_name LIKE ?)';
    const searchTerm = `%${search}%`;
    params.push(searchTerm, searchTerm, searchTerm);
    countParams.push(searchTerm, searchTerm, searchTerm);
  }

  sql += ' ORDER BY uploaded_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), offset);

  const documents = db.prepare(sql).all(...params);
  const { total } = db.prepare(countSql).get(...countParams);

  res.json({
    documents,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / parseInt(limit))
    }
  });
});

// Get single document (scope enforced)
app.get('/api/documents/:id', authenticate(), (req, res) => {
  let sql = 'SELECT * FROM documents WHERE id = ? AND is_archived = 0';
  const params = [req.params.id];

  // Scope enforcement
  if (req.token.scope && Array.isArray(req.token.scope) && req.token.scope.length > 0) {
    const placeholders = req.token.scope.map(() => '?').join(',');
    sql += ` AND category IN (${placeholders})`;
    params.push(...req.token.scope);
  }

  const doc = db.prepare(sql).get(...params);

  if (!doc) return res.status(404).json({ error: 'Document not found' });

  res.json({ document: doc });
});

// Download document (scope enforced)
app.get('/api/documents/:id/download', authenticate(), (req, res) => {
  let sql = 'SELECT * FROM documents WHERE id = ? AND is_archived = 0';
  const params = [req.params.id];

  // Scope enforcement
  if (req.token.scope && Array.isArray(req.token.scope) && req.token.scope.length > 0) {
    const placeholders = req.token.scope.map(() => '?').join(',');
    sql += ` AND category IN (${placeholders})`;
    params.push(...req.token.scope);
  }

  const doc = db.prepare(sql).get(...params);

  if (!doc) return res.status(404).json({ error: 'Document not found' });

  const filePath = path.join(UPLOAD_DIR, doc.filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found on disk' });
  }

  // Log download
  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('download', 'document', doc.id, req.token.name, `Downloaded "${doc.title}"`);

  res.setHeader('Content-Disposition', `attachment; filename="${doc.original_name}"`);
  res.setHeader('Content-Type', doc.mime_type);
  res.sendFile(filePath);
});

// Upload document (super_admin only)
app.post('/api/documents', authenticate(['super_admin']), upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const { title, description, category } = req.body;
  if (!title || !category) {
    // Clean up uploaded file
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'title and category are required' });
  }

  const docId = uuidv4();
  db.prepare(
    `INSERT INTO documents (id, title, description, category, filename, original_name, mime_type, file_size, uploaded_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    docId,
    title,
    description || '',
    category,
    req.file.filename,
    req.file.originalname,
    req.file.mimetype,
    req.file.size,
    req.token.name
  );

  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('upload', 'document', docId, req.token.name, `Uploaded "${title}" (${req.file.originalname})`);

  res.status(201).json({
    id: docId,
    title,
    category,
    filename: req.file.filename,
    original_name: req.file.originalname,
    file_size: req.file.size,
    message: 'Document uploaded successfully'
  });
});

// Update document metadata (scope enforced)
app.patch('/api/documents/:id', authenticate(['super_admin', 'admin', 'editor']), (req, res) => {
  let sql = 'SELECT * FROM documents WHERE id = ? AND is_archived = 0';
  const lookupParams = [req.params.id];

  if (req.token.scope && Array.isArray(req.token.scope) && req.token.scope.length > 0) {
    const placeholders = req.token.scope.map(() => '?').join(',');
    sql += ` AND category IN (${placeholders})`;
    lookupParams.push(...req.token.scope);
  }

  const doc = db.prepare(sql).get(...lookupParams);
  if (!doc) return res.status(404).json({ error: 'Document not found' });

  const { title, description, category } = req.body;
  const updates = [];
  const params = [];

  if (title) { updates.push('title = ?'); params.push(title); }
  if (description !== undefined) { updates.push('description = ?'); params.push(description); }
  if (category) { updates.push('category = ?'); params.push(category); }
  
  updates.push('updated_at = datetime(\'now\')');
  updates.push('version = version + 1');

  if (updates.length > 2) {
    params.push(req.params.id);
    db.prepare(`UPDATE documents SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  }

  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('update', 'document', req.params.id, req.token.name, `Updated "${doc.title}"`);

  const updated = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
  res.json({ document: updated });
});

// Delete (archive) document (scope enforced)
app.delete('/api/documents/:id', authenticate(['super_admin', 'admin']), (req, res) => {
  let sql = 'SELECT * FROM documents WHERE id = ? AND is_archived = 0';
  const params = [req.params.id];

  if (req.token.scope && Array.isArray(req.token.scope) && req.token.scope.length > 0) {
    const placeholders = req.token.scope.map(() => '?').join(',');
    sql += ` AND category IN (${placeholders})`;
    params.push(...req.token.scope);
  }

  const doc = db.prepare(sql).get(...params);
  if (!doc) return res.status(404).json({ error: 'Document not found' });

  db.prepare('UPDATE documents SET is_archived = 1, updated_at = datetime(\'now\') WHERE id = ?').run(req.params.id);

  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('archive', 'document', req.params.id, req.token.name, `Archived "${doc.title}"`);

  res.json({ message: 'Document archived' });
});

// ============ CATEGORY ROUTES ============

app.get('/api/categories', authenticate(), (req, res) => {
  const categories = db.prepare(
    'SELECT c.*, (SELECT COUNT(*) FROM documents d WHERE d.category = c.slug AND d.is_archived = 0) as document_count FROM categories c ORDER BY c.sort_order ASC'
  ).all();
  res.json({ categories });
});

// ============ ACTIVITY LOG ============

app.get('/api/activity', authenticate(['super_admin', 'admin']), (req, res) => {
  const { limit = 50 } = req.query;
  const logs = db.prepare(
    'SELECT * FROM activity_log ORDER BY created_at DESC LIMIT ?'
  ).all(parseInt(limit));
  res.json({ logs });
});

// ============ STATS ============

app.get('/api/stats', authenticate(), (req, res) => {
  const totalDocs = db.prepare('SELECT COUNT(*) as count FROM documents WHERE is_archived = 0').get();
  const totalSize = db.prepare('SELECT COALESCE(SUM(file_size), 0) as total FROM documents WHERE is_archived = 0').get();
  const totalTokens = db.prepare('SELECT COUNT(*) as count FROM tokens WHERE is_active = 1').get();
  const docsByCategory = db.prepare(
    'SELECT category, COUNT(*) as count FROM documents WHERE is_archived = 0 GROUP BY category ORDER BY count DESC'
  ).all();

  res.json({
    total_documents: totalDocs.count,
    total_storage: totalSize.total,
    total_active_tokens: totalTokens.count,
    documents_by_category: docsByCategory
  });
});

// ============ CAP TABLE ROUTES ============

// --- Helpers ---
// NOTE: All vesting/ownership/dilution math lives in ./captable.js and is
// recomputed live on every read. Nothing derived is trusted from storage.

// Load raw state and run the single source-of-truth aggregation.
function buildCapTable(now = new Date()) {
  const pools = db.prepare('SELECT * FROM equity_pools ORDER BY created_at ASC').all();
  const holders = db.prepare("SELECT * FROM shareholders WHERE status != 'exited'").all();
  const convertibles = db.prepare("SELECT * FROM convertibles WHERE status = 'outstanding'").all();
  // Attach the latest round so SAFEs convert at cap/discount prices. The cap
  // price denominator must be the PRE-money fully-diluted share count
  // (outstanding + unissued authorized), not just this round's new shares.
  const lastRound = db.prepare('SELECT * FROM financing_rounds ORDER BY created_at DESC LIMIT 1').get() || null;
  const outstanding = holders.reduce((s, h) => s + (Number(h.shares_owned) || 0), 0);
  const authorized = pools.reduce((s, p) => s + (Number(p.total_shares) || 0), 0);
  const unissued = Math.max(authorized - outstanding, 0);
  const round = lastRound ? {
    ...lastRound,
    pre_shares: outstanding + unissued,            // pre-money fully-diluted base
    fully_diluted_pre_shares: outstanding + unissued
  } : { price_per_share: 0, pre_shares: outstanding + unissued };
  convertibles._round = round;
  return cap.recompute({ pools, holders, convertibles, now });
}

// --- Summary ---
app.get('/api/cap-table/summary', authenticate(), (req, res) => {
  const t = buildCapTable();
  res.json({
    total_authorized: t.total_authorized,
    total_outstanding: t.total_outstanding,
    total_unissued: t.total_unissued,
    total_vested: t.total_vested,
    total_unvested: t.total_unvested,
    fully_diluted: t.fully_diluted,
    convertible_shares: t.convertible_shares,
    ownership_pct_sum: t.ownership_pct_sum,
    shareholder_count: t.shareholder_count,
    pool_count: t.pool_count,
    pools: t.pools
  });
});

// --- Equity Pools ---
app.get('/api/cap-table/pools', authenticate(), (req, res) => {
  const t = buildCapTable();
  // Merge pool row fields (description, created_at) with recomputed issuance.
  const rows = db.prepare('SELECT * FROM equity_pools ORDER BY created_at ASC').all();
  const byId = new Map(t.pools.map(p => [p.id, p]));
  const enriched = rows.map(p => {
    const c = byId.get(p.id) || { issued: 0, remaining: p.total_shares, percent_issued: '0.00', shareholder_count: 0 };
    const count = db.prepare("SELECT COUNT(*) as c FROM shareholders WHERE equity_pool_id = ? AND status != 'exited'").get(p.id);
    return { ...p, shareholder_count: count.c, issued_shares: c.issued, remaining_shares: c.remaining };
  });
  res.json({ pools: enriched });
});

app.post('/api/cap-table/pools', authenticate(['super_admin']), (req, res) => {
  const { name, total_shares, class: poolClass, description, valuation } = req.body;
  if (!name || total_shares === undefined) return res.status(400).json({ error: 'name and total_shares are required' });

  try {
    cap.assertValidShares(total_shares, 'total_shares');
    if (parseInt(total_shares) === 0) { const e = new Error('total_shares must be greater than 0'); e.status = 400; throw e; }
  } catch (e) { return res.status(e.status || 400).json({ error: e.message }); }
  const totalInt = parseInt(total_shares);

  const poolId = uuidv4();
  db.prepare(
    'INSERT INTO equity_pools (id, name, total_shares, class, description, valuation) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(poolId, name, totalInt, poolClass || 'Common', description || '', valuation ?? null);

  db.prepare(
    'INSERT INTO cap_table_events (event_type, equity_pool_id, description, performed_by) VALUES (?, ?, ?, ?)'
  ).run('pool_create', poolId, `Created equity pool "${name}" with ${totalInt.toLocaleString()} shares`, req.token.name);

  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('cap_table', 'equity_pool', poolId, req.token.name, `Created pool "${name}"`);

  res.status(201).json({ id: poolId, name, total_shares: totalInt, class: poolClass || 'Common' });
});

app.patch('/api/cap-table/pools/:id', authenticate(['super_admin']), (req, res) => {
  const pool = db.prepare('SELECT * FROM equity_pools WHERE id = ?').get(req.params.id);
  if (!pool) return res.status(404).json({ error: 'Pool not found' });

  const { name, total_shares, class: poolClass, description, valuation } = req.body;
  const updates = [];
  const params = [];

  // Guard: cannot shrink authorized below already-issued shares.
  if (total_shares !== undefined) {
    try { cap.assertValidShares(total_shares, 'total_shares'); }
    catch (e) { return res.status(400).json({ error: e.message }); }
    const totalInt = parseInt(total_shares);
    const issued = db.prepare("SELECT COALESCE(SUM(shares_owned),0) as s FROM shareholders WHERE equity_pool_id = ? AND status != 'exited'").get(pool.id).s;
    if (totalInt < issued) {
      return res.status(400).json({ error: `Cannot set authorized to ${totalInt}: ${issued} shares already issued` });
    }
    updates.push('total_shares = ?'); params.push(totalInt);
  }
  if (name) { updates.push('name = ?'); params.push(name); }
  if (poolClass) { updates.push('class = ?'); params.push(poolClass); }
  if (description !== undefined) { updates.push('description = ?'); params.push(description); }
  if (valuation !== undefined) { updates.push('valuation = ?'); params.push(valuation); }

  if (updates.length > 0) {
    updates.push('updated_at = datetime(\'now\')');
    params.push(req.params.id);
    db.prepare(`UPDATE equity_pools SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  }

  db.prepare(
    'INSERT INTO cap_table_events (event_type, equity_pool_id, description, performed_by) VALUES (?, ?, ?, ?)'
  ).run('pool_update', req.params.id, `Updated pool "${pool.name}"`, req.token.name);

  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('cap_table', 'equity_pool', req.params.id, req.token.name, `Updated pool "${pool.name}"`);

  const updated = db.prepare('SELECT * FROM equity_pools WHERE id = ?').get(req.params.id);
  res.json({ pool: updated });
});

// --- Shareholders ---
app.get('/api/cap-table/shareholders', authenticate(), (req, res) => {
  const { pool_id } = req.query;
  let sql = 'SELECT * FROM shareholders';
  const params = [];

  if (pool_id) {
    sql += ' WHERE equity_pool_id = ?';
    params.push(pool_id);
  }

  sql += ' ORDER BY shares_owned DESC';
  const shareholders = db.prepare(sql).all(...params);

  const t = buildCapTable();
  let holders = t.holders;
  if (pool_id) holders = holders.filter(s => s.equity_pool_id === pool_id);

  // Map pool names for display.
  const poolMap = new Map(db.prepare('SELECT id, name FROM equity_pools').all().map(p => [p.id, p.name]));
  const enriched = holders.map(s => ({ ...s, pool_name: poolMap.get(s.equity_pool_id) || null }));

  res.json({ shareholders: enriched, total_outstanding: t.total_outstanding, fully_diluted: t.fully_diluted });
});

app.get('/api/cap-table/shareholders/:id', authenticate(), (req, res) => {
  const t = buildCapTable();
  const sh = t.holders.find(h => h.id === req.params.id);
  if (!sh) return res.status(404).json({ error: 'Shareholder not found' });

  const pool = db.prepare('SELECT * FROM equity_pools WHERE id = ?').get(sh.equity_pool_id);
  res.json({
    shareholder: {
      ...sh,
      pool_name: pool ? pool.name : null
    }
  });
});

app.post('/api/cap-table/shareholders', authenticate(['super_admin']), (req, res) => {
  const { name, email, type, shares_owned, equity_pool_id, vesting_start, vesting_end, cliff_date, notes } = req.body;

  if (!name || !type || shares_owned === undefined || !equity_pool_id) {
    return res.status(400).json({ error: 'name, type, shares_owned, and equity_pool_id are required' });
  }

  const shares = shares_owned;
  try {
    cap.assertValidShares(shares, 'shares_owned');
    if (parseInt(shares) === 0) { const e = new Error('shares_owned must be greater than 0'); e.status = 400; throw e; }
    cap.assertValidVesting(vesting_start, vesting_end, cliff_date);
  } catch (e) { return res.status(e.status || 400).json({ error: e.message }); }
  const sharesInt = parseInt(shares);

  const pool = db.prepare('SELECT * FROM equity_pools WHERE id = ?').get(equity_pool_id);
  if (!pool) return res.status(400).json({ error: 'Equity pool not found' });

  // CAP ENFORCEMENT: issued + new must not exceed authorized.
  const issued = db.prepare("SELECT COALESCE(SUM(shares_owned),0) as s FROM shareholders WHERE equity_pool_id = ? AND status != 'exited'").get(equity_pool_id).s;
  if (issued + sharesInt > pool.total_shares) {
    return res.status(400).json({ error: `Cannot issue ${sharesInt.toLocaleString()} shares: only ${(pool.total_shares - issued).toLocaleString()} remaining in "${pool.name}"` });
  }

  const vested = cap.computeVestedShares(vesting_start, vesting_end, cliff_date, sharesInt);
  const status = cap.computeShareholderStatus(vesting_start, vesting_end, cliff_date, sharesInt);

  const shId = uuidv4();
  const insert = db.transaction(() => {
    db.prepare(
      `INSERT INTO shareholders (id, name, email, type, shares_owned, equity_pool_id, vesting_start, vesting_end, cliff_date, vested_shares, status, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(shId, name, email || '', type, sharesInt, equity_pool_id, vesting_start || null, vesting_end || null, cliff_date || null, vested, status, notes || '');

    db.prepare(
      'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run('issuance', shId, 0, sharesInt, sharesInt, equity_pool_id, `Issued ${sharesInt.toLocaleString()} shares to ${name}`, req.token.name);

    db.prepare(
      'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
    ).run('cap_table', 'shareholder', shId, req.token.name, `Added shareholder "${name}"`);
  });
  insert();

  res.status(201).json({ id: shId, name, type, shares_owned: sharesInt, status, vested_shares: vested });
});

app.patch('/api/cap-table/shareholders/:id', authenticate(['super_admin']), (req, res) => {
  const sh = db.prepare('SELECT * FROM shareholders WHERE id = ?').get(req.params.id);
  if (!sh) return res.status(404).json({ error: 'Shareholder not found' });

  const { name, email, type, shares_owned, equity_pool_id, vesting_start, vesting_end, cliff_date, status, notes } = req.body;

  // Validate + cap-check the new share count (against the target pool).
  const targetPoolId = equity_pool_id || sh.equity_pool_id;
  const sharesChanged = shares_owned !== undefined && parseInt(shares_owned) !== sh.shares_owned;
  if (sharesChanged) {
    try {
      cap.assertValidShares(shares_owned, 'shares_owned');
      cap.assertValidVesting(vesting_start ?? sh.vesting_start, vesting_end ?? sh.vesting_end, cliff_date ?? sh.cliff_date);
    } catch (e) { return res.status(e.status || 400).json({ error: e.message }); }
    const newShares = parseInt(shares_owned);

    if (newShares > sh.shares_owned) {
      const pool = db.prepare('SELECT * FROM equity_pools WHERE id = ?').get(targetPoolId);
      const othersIssued = db.prepare("SELECT COALESCE(SUM(shares_owned),0) as s FROM shareholders WHERE equity_pool_id = ? AND status != 'exited' AND id != ?").get(targetPoolId, sh.id).s;
      if (othersIssued + newShares > pool.total_shares) {
        return res.status(400).json({ error: `Cannot set ${newShares.toLocaleString()} shares: exceeds "${pool.name}" authorized (only ${(pool.total_shares - othersIssued).toLocaleString()} available)` });
      }
    }
  }

  const updates = [];
  const params = [];
  if (name) { updates.push('name = ?'); params.push(name); }
  if (email !== undefined) { updates.push('email = ?'); params.push(email); }
  if (type) { updates.push('type = ?'); params.push(type); }
  if (equity_pool_id) { updates.push('equity_pool_id = ?'); params.push(equity_pool_id); }
  if (vesting_start !== undefined) { updates.push('vesting_start = ?'); params.push(vesting_start); }
  if (vesting_end !== undefined) { updates.push('vesting_end = ?'); params.push(vesting_end); }
  if (cliff_date !== undefined) { updates.push('cliff_date = ?'); params.push(cliff_date); }
  if (notes !== undefined) { updates.push('notes = ?'); params.push(notes); }

  const newSharesVal = sharesChanged ? parseInt(shares_owned) : sh.shares_owned;
  if (sharesChanged) { updates.push('shares_owned = ?'); params.push(newSharesVal); }

  // Recompute vested/status live whenever vesting or shares change.
  const vs = vesting_start !== undefined ? vesting_start : sh.vesting_start;
  const ve = vesting_end !== undefined ? vesting_end : sh.vesting_end;
  const cd = cliff_date !== undefined ? cliff_date : sh.cliff_date;
  if (sharesChanged || vesting_start !== undefined || vesting_end !== undefined || cliff_date !== undefined) {
    const vested = cap.computeVestedShares(vs, ve, cd, newSharesVal);
    const newStatus = cap.computeShareholderStatus(vs, ve, cd, newSharesVal);
    updates.push('vested_shares = ?'); params.push(vested);
    updates.push('status = ?'); params.push(newStatus);
  } else if (status && status !== 'exited') {
    updates.push('status = ?'); params.push(status);
  }

  const apply = db.transaction(() => {
    if (updates.length > 0) {
      updates.push('updated_at = datetime(\'now\')');
      params.push(req.params.id);
      db.prepare(`UPDATE shareholders SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    }
    if (sharesChanged) {
      const delta = newSharesVal - sh.shares_owned;
      db.prepare(
        'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).run('edit', sh.id, sh.shares_owned, newSharesVal, delta, sh.equity_pool_id, `Adjusted shares for ${sh.name}: ${sh.shares_owned.toLocaleString()} → ${newSharesVal.toLocaleString()}`, req.token.name);
    }
    db.prepare(
      'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
    ).run('cap_table', 'shareholder', req.params.id, req.token.name, `Updated shareholder "${sh.name}"`);
  });
  apply();

  const updated = db.prepare('SELECT * FROM shareholders WHERE id = ?').get(req.params.id);
  res.json({ shareholder: updated });
});

app.delete('/api/cap-table/shareholders/:id', authenticate(['super_admin']), (req, res) => {
  const sh = db.prepare('SELECT * FROM shareholders WHERE id = ?').get(req.params.id);
  if (!sh) return res.status(404).json({ error: 'Shareholder not found' });
  if (sh.status === 'exited') return res.status(400).json({ error: 'Shareholder already exited' });

  const exit = db.transaction(() => {
    db.prepare('UPDATE shareholders SET status = ?, updated_at = datetime(\'now\') WHERE id = ?').run('exited', req.params.id);
    db.prepare(
      'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run('cancel', sh.id, sh.shares_owned, 0, -sh.shares_owned, sh.equity_pool_id, `Marked ${sh.name} as exited (${sh.shares_owned.toLocaleString()} shares)`, req.token.name);
    db.prepare(
      'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
    ).run('cap_table', 'shareholder', req.params.id, req.token.name, `Exited shareholder "${sh.name}"`);
  });
  exit();

  res.json({ message: 'Shareholder marked as exited' });
});

// --- Transfer shares between holders (conserves total outstanding) ---
app.post('/api/cap-table/transfers', authenticate(['super_admin']), (req, res) => {
  const { from_id, to_id, shares } = req.body;

  try { cap.assertValidShares(shares, 'shares'); } catch (e) { return res.status(400).json({ error: e.message }); }
  const amount = parseInt(shares);
  if (!from_id || !to_id || !amount || amount <= 0) {
    return res.status(400).json({ error: 'from_id, to_id, and a positive share amount are required' });
  }
  if (from_id === to_id) return res.status(400).json({ error: 'Cannot transfer to the same holder' });

  const from = db.prepare('SELECT * FROM shareholders WHERE id = ?').get(from_id);
  const to = db.prepare('SELECT * FROM shareholders WHERE id = ?').get(to_id);
  if (!from || !to) return res.status(404).json({ error: 'Both shareholders must exist' });
  if (from.status === 'exited' || to.status === 'exited') return res.status(400).json({ error: 'Cannot transfer involving an exited shareholder' });
  if (from.shares_owned < amount) {
    return res.status(400).json({ error: `${from.name} only holds ${from.shares_owned.toLocaleString()} shares` });
  }

  if (to.equity_pool_id !== from.equity_pool_id) {
    const toPool = db.prepare('SELECT * FROM equity_pools WHERE id = ?').get(to.equity_pool_id);
    const othersIssued = db.prepare("SELECT COALESCE(SUM(shares_owned),0) as s FROM shareholders WHERE equity_pool_id = ? AND status != 'exited' AND id != ?").get(to.equity_pool_id, to.id).s;
    if (othersIssued + to.shares_owned + amount > toPool.total_shares) {
      return res.status(400).json({ error: `Transfer exceeds "${toPool.name}" authorized shares` });
    }
  }

  const doTransfer = db.transaction(() => {
    db.prepare('UPDATE shareholders SET shares_owned = shares_owned - ?, updated_at = datetime(\'now\') WHERE id = ?').run(amount, from_id);
    db.prepare('UPDATE shareholders SET shares_owned = shares_owned + ?, updated_at = datetime(\'now\') WHERE id = ?').run(amount, to_id);

    db.prepare(
      'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run('transfer', from_id, from.shares_owned, from.shares_owned - amount, -amount, from.equity_pool_id, `Transferred ${amount.toLocaleString()} shares to ${to.name}`, req.token.name);

    db.prepare(
      'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run('transfer', to_id, to.shares_owned, to.shares_owned + amount, amount, to.equity_pool_id, `Received ${amount.toLocaleString()} shares from ${from.name}`, req.token.name);

    db.prepare(
      'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
    ).run('cap_table', 'shareholder', from_id, req.token.name, `Transferred ${amount.toLocaleString()} shares ${from.name} → ${to.name}`);
  });
  doTransfer();

  res.json({ message: `Transferred ${amount.toLocaleString()} shares from ${from.name} to ${to.name}` });
});

// --- Events / History ---
app.get('/api/cap-table/events', authenticate(), (req, res) => {
  const { limit = 50, shareholder_id } = req.query;
  let sql = 'SELECT e.*, s.name as shareholder_name, p.name as pool_name FROM cap_table_events e LEFT JOIN shareholders s ON e.shareholder_id = s.id LEFT JOIN equity_pools p ON e.equity_pool_id = p.id';
  const params = [];

  if (shareholder_id) {
    sql += ' WHERE e.shareholder_id = ?';
    params.push(shareholder_id);
  }

  sql += ' ORDER BY e.created_at DESC LIMIT ?';
  params.push(parseInt(limit));

  const events = db.prepare(sql).all(...params);
  res.json({ events });
});

// --- Ledger self-check ---
app.get('/api/cap-table/verify', authenticate(), (req, res) => {
  const pools = db.prepare('SELECT * FROM equity_pools').all();
  const holders = db.prepare("SELECT * FROM shareholders WHERE status != 'exited'").all();
  const events = db.prepare('SELECT * FROM cap_table_events').all();
  const problems = cap.verify({ pools, holders, events });
  res.json({ healthy: problems.length === 0, problems });
});

// --- CSV export ---
app.get('/api/cap-table/export.csv', authenticate(['super_admin', 'admin']), (req, res) => {
  const t = buildCapTable();
  const poolMap = new Map(db.prepare('SELECT id, name FROM equity_pools').all().map(p => [p.id, p.name]));
  const rows = [['Name', 'Type', 'Pool', 'Shares', 'Ownership %', 'Fully-Diluted %', 'Vested', 'Unvested', 'Vesting Status']];
  for (const h of t.holders) {
    rows.push([
      h.name, h.type, poolMap.get(h.equity_pool_id) || '',
      h.shares_owned, h.ownership_pct, h.fd_ownership_pct,
      h.vested_shares, h.unvested_shares, h.derived_status
    ]);
  }
  const csv = rows.map(r => r.map(v => {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="cap-table.csv"');
  res.send(csv);
});

// --- Dilution simulator (read-only preview) ---
app.get('/api/cap-table/dilution-preview', authenticate(), (req, res) => {
  const newShares = parseInt(req.query.new_shares || '0');
  const roundValuation = req.query.valuation ? parseFloat(req.query.valuation) : null;
  const newPoolId = req.query.pool_id || null;

  const pools = db.prepare('SELECT * FROM equity_pools ORDER BY created_at ASC').all();
  const holders = db.prepare("SELECT * FROM shareholders WHERE status != 'exited'").all();
  const convertibles = db.prepare("SELECT * FROM convertibles WHERE status = 'outstanding'").all();
  const lastRound = db.prepare('SELECT * FROM financing_rounds ORDER BY created_at DESC LIMIT 1').get() || null;
  const outN = holders.reduce((s, h) => s + (Number(h.shares_owned) || 0), 0);
  const authN = pools.reduce((s, p) => s + (Number(p.total_shares) || 0), 0);
  const preFD = Math.max(outN + Math.max(authN - outN, 0), 1);
  convertibles._round = lastRound
    ? { ...lastRound, pre_shares: preFD, fully_diluted_pre_shares: preFD }
    : { price_per_share: 0, pre_shares: preFD };

  const sim = cap.simulateDilution({ pools, holders, convertibles, newShares, roundValuation, newPoolId });
  res.json(sim);
});

// --- Financing rounds ---
app.get('/api/cap-table/rounds', authenticate(), (req, res) => {
  const rounds = db.prepare('SELECT * FROM financing_rounds ORDER BY created_at DESC').all();
  res.json({ rounds });
});

app.post('/api/cap-table/rounds', authenticate(['super_admin']), (req, res) => {
  const { name, round_type, pre_money_valuation, price_per_share, new_shares, equity_pool_id, closed_at, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });

  const id = uuidv4();
  db.prepare(
    'INSERT INTO financing_rounds (id, name, round_type, pre_money_valuation, price_per_share, new_shares, equity_pool_id, closed_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(id, name, round_type || 'priced', pre_money_valuation != null ? parseInt(pre_money_valuation) : null, price_per_share != null ? parseFloat(price_per_share) : null, new_shares != null ? parseInt(new_shares) : 0, equity_pool_id || null, closed_at || null, notes || '');

  db.prepare(
    'INSERT INTO cap_table_events (event_type, description, performed_by) VALUES (?, ?, ?)'
  ).run('pool_update', `Recorded financing round "${name}"`, req.token.name);

  res.status(201).json({ id, name });
});

// --- Convertibles (SAFEs / notes) ---
app.get('/api/cap-table/convertibles', authenticate(), (req, res) => {
  const t = buildCapTable();
  res.json({ convertibles: t.convertibles, convertible_shares: t.convertible_shares });
});

app.post('/api/cap-table/convertibles', authenticate(['super_admin']), (req, res) => {
  const { name, instrument_type, amount, cap_amount, discount } = req.body;
  if (!name || !amount) return res.status(400).json({ error: 'name and amount are required' });

  const id = uuidv4();
  db.prepare(
    'INSERT INTO convertibles (id, name, instrument_type, amount, cap_amount, discount) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(id, name, instrument_type || 'safe', parseInt(amount), cap_amount != null ? parseInt(cap_amount) : null, discount != null ? parseFloat(discount) : null);

  db.prepare(
    'INSERT INTO cap_table_events (event_type, description, performed_by) VALUES (?, ?, ?)'
  ).run('pool_update', `Added convertible "${name}" (${parseInt(amount).toLocaleString()})`, req.token.name);

  res.status(201).json({ id, name });
});

// ============ SEED CHECK ============
app.post('/api/seed', (req, res) => {
  const { super_key } = req.body;
  // Only allow if no super admin exists
  const existing = db.prepare('SELECT COUNT(*) as count FROM tokens WHERE role = ?').get('super_admin');
  if (existing.count > 0) {
    return res.status(400).json({ error: 'Database already seeded' });
  }
  
  const seed = require('./seed');
  res.json({ message: 'Database seeded' });
});

// ============ HELPERS ============
function getPermissionsForRole(role) {
  const permissions = {
    super_admin: ['view', 'upload', 'edit', 'delete', 'manage_tokens', 'manage_admins', 'view_activity', 'export'],
    admin: ['view', 'edit', 'delete', 'manage_tokens', 'view_activity', 'export'],
    editor: ['view', 'edit'],
    viewer: ['view']
  };
  return permissions[role] || [];
}


// ============ FRONTEND ROUTES ============
// Serve the frontend assets (no nginx, no express.static for the frontend)
const frontendDir = path.join(__dirname, '..', 'frontend');

app.get('/', (req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'));
});

app.get('/styles.css', (req, res) => {
  res.sendFile(path.join(frontendDir, 'styles.css'));
});

app.get('/app.js', (req, res) => {
  res.sendFile(path.join(frontendDir, 'app.js'));
});

// Catch-all for SPA routing: serve index.html for any non-API path
app.get(/^\/?(?!api\/).*$/, (req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'));
});

// ============ START ============
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Eskaen Vault API running on port ${PORT}`);
  console.log(`Upload directory: ${UPLOAD_DIR}`);
  
  // Check if seeded
  const tokenCount = db.prepare('SELECT COUNT(*) as count FROM tokens').get();
  if (tokenCount.count === 0) {
    console.log('No tokens found. Run: node seed.js');
  }
});
