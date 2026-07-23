require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');

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
function computeVestedShares(vestingStart, vestingEnd, cliffDate, totalShares) {
  if (!vestingStart || !vestingEnd || !totalShares) return totalShares;
  const now = new Date();
  const start = new Date(vestingStart);
  const end = new Date(vestingEnd);

  if (now < start) return 0;
  if (now >= end) return totalShares;

  // Cliff check: if cliff date exists and hasn't passed, nothing vests
  if (cliffDate && now < new Date(cliffDate)) return 0;

  const totalDuration = end - start;
  const elapsed = now - start;
  const ratio = Math.min(elapsed / totalDuration, 1);
  return Math.floor(totalShares * ratio);
}

function computeShareholderStatus(vestingStart, vestingEnd, cliffDate, totalShares) {
  if (!vestingStart || !vestingEnd) return 'active';
  const now = new Date();
  const start = new Date(vestingStart);
  const end = new Date(vestingEnd);

  if (now < start) return 'active';
  if (now >= end) return 'fully_vested';
  if (cliffDate && now < new Date(cliffDate)) return 'active';
  return 'vesting';
}

// --- Summary ---
app.get('/api/cap-table/summary', authenticate(), (req, res) => {
  const pools = db.prepare('SELECT * FROM equity_pools ORDER BY created_at ASC').all();
  const shareholders = db.prepare('SELECT * FROM shareholders WHERE status != ?').all('exited');

  const totalAuthorized = pools.reduce((sum, p) => sum + p.total_shares, 0);
  const totalOutstanding = shareholders.reduce((sum, s) => sum + s.shares_owned, 0);
  const fullyDiluted = totalAuthorized; // authorized = fully diluted in this model

  const poolBreakdown = pools.map(p => {
    const issued = shareholders.filter(s => s.equity_pool_id === p.id).reduce((sum, s) => sum + s.shares_owned, 0);
    return {
      id: p.id,
      name: p.name,
      class: p.class,
      authorized: p.total_shares,
      issued,
      remaining: p.total_shares - issued,
      percent_issued: p.total_shares > 0 ? ((issued / p.total_shares) * 100).toFixed(2) : '0.00'
    };
  });

  res.json({
    total_authorized: totalAuthorized,
    total_outstanding: totalOutstanding,
    fully_diluted: fullyDiluted,
    shareholder_count: shareholders.length,
    pool_count: pools.length,
    pools: poolBreakdown
  });
});

// --- Equity Pools ---
app.get('/api/cap-table/pools', authenticate(), (req, res) => {
  const pools = db.prepare('SELECT * FROM equity_pools ORDER BY created_at ASC').all();
  const enriched = pools.map(p => {
    const count = db.prepare('SELECT COUNT(*) as count FROM shareholders WHERE equity_pool_id = ? AND status != ?').get(p.id, 'exited');
    const issued = db.prepare('SELECT COALESCE(SUM(shares_owned), 0) as total FROM shareholders WHERE equity_pool_id = ? AND status != ?').get(p.id, 'exited');
    return { ...p, shareholder_count: count.count, issued_shares: issued.total };
  });
  res.json({ pools: enriched });
});

app.post('/api/cap-table/pools', authenticate(['super_admin']), (req, res) => {
  const { name, total_shares, class: poolClass, description } = req.body;
  if (!name || !total_shares) return res.status(400).json({ error: 'name and total_shares are required' });

  const poolId = uuidv4();
  db.prepare(
    'INSERT INTO equity_pools (id, name, total_shares, class, description) VALUES (?, ?, ?, ?, ?)'
  ).run(poolId, name, total_shares, poolClass || 'Common', description || '');

  db.prepare(
    'INSERT INTO cap_table_events (event_type, equity_pool_id, description, performed_by) VALUES (?, ?, ?, ?)'
  ).run('pool_create', poolId, `Created equity pool "${name}" with ${total_shares.toLocaleString()} shares`, req.token.name);

  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('cap_table', 'equity_pool', poolId, req.token.name, `Created pool "${name}"`);

  res.status(201).json({ id: poolId, name, total_shares, class: poolClass || 'Common' });
});

app.patch('/api/cap-table/pools/:id', authenticate(['super_admin']), (req, res) => {
  const pool = db.prepare('SELECT * FROM equity_pools WHERE id = ?').get(req.params.id);
  if (!pool) return res.status(404).json({ error: 'Pool not found' });

  const { name, total_shares, class: poolClass, description } = req.body;
  const updates = [];
  const params = [];

  if (name) { updates.push('name = ?'); params.push(name); }
  if (total_shares !== undefined) { updates.push('total_shares = ?'); params.push(total_shares); }
  if (poolClass) { updates.push('class = ?'); params.push(poolClass); }
  if (description !== undefined) { updates.push('description = ?'); params.push(description); }

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

  // Compute total outstanding for ownership %
  const totalOutstanding = db.prepare(
    'SELECT COALESCE(SUM(shares_owned), 0) as total FROM shareholders WHERE status != ?'
  ).get('exited');

  const enriched = shareholders.map(s => ({
    ...s,
    ownership_pct: totalOutstanding.total > 0 ? ((s.shares_owned / totalOutstanding.total) * 100).toFixed(2) : '0.00'
  }));

  res.json({ shareholders: enriched, total_outstanding: totalOutstanding.total });
});

app.get('/api/cap-table/shareholders/:id', authenticate(), (req, res) => {
  const sh = db.prepare('SELECT * FROM shareholders WHERE id = ?').get(req.params.id);
  if (!sh) return res.status(404).json({ error: 'Shareholder not found' });

  const totalOutstanding = db.prepare(
    'SELECT COALESCE(SUM(shares_owned), 0) as total FROM shareholders WHERE status != ?'
  ).get('exited');

  const pool = db.prepare('SELECT * FROM equity_pools WHERE id = ?').get(sh.equity_pool_id);

  res.json({
    shareholder: {
      ...sh,
      ownership_pct: totalOutstanding.total > 0 ? ((sh.shares_owned / totalOutstanding.total) * 100).toFixed(2) : '0.00',
      pool_name: pool ? pool.name : null
    }
  });
});

app.post('/api/cap-table/shareholders', authenticate(['super_admin']), (req, res) => {
  const { name, email, type, shares_owned, equity_pool_id, vesting_start, vesting_end, cliff_date, notes } = req.body;

  if (!name || !type || !shares_owned || !equity_pool_id) {
    return res.status(400).json({ error: 'name, type, shares_owned, and equity_pool_id are required' });
  }

  const pool = db.prepare('SELECT * FROM equity_pools WHERE id = ?').get(equity_pool_id);
  if (!pool) return res.status(400).json({ error: 'Equity pool not found' });

  const vested = computeVestedShares(vesting_start, vesting_end, cliff_date, shares_owned);
  const status = computeShareholderStatus(vesting_start, vesting_end, cliff_date, shares_owned);

  const shId = uuidv4();
  db.prepare(
    `INSERT INTO shareholders (id, name, email, type, shares_owned, equity_pool_id, vesting_start, vesting_end, cliff_date, vested_shares, status, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(shId, name, email || '', type, shares_owned, equity_pool_id, vesting_start || null, vesting_end || null, cliff_date || null, vested, status, notes || '');

  db.prepare(
    'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run('issuance', shId, 0, shares_owned, shares_owned, equity_pool_id, `Issued ${shares_owned.toLocaleString()} shares to ${name}`, req.token.name);

  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('cap_table', 'shareholder', shId, req.token.name, `Added shareholder "${name}"`);

  res.status(201).json({ id: shId, name, type, shares_owned, status, vested_shares: vested });
});

app.patch('/api/cap-table/shareholders/:id', authenticate(['super_admin']), (req, res) => {
  const sh = db.prepare('SELECT * FROM shareholders WHERE id = ?').get(req.params.id);
  if (!sh) return res.status(404).json({ error: 'Shareholder not found' });

  const { name, email, type, shares_owned, equity_pool_id, vesting_start, vesting_end, cliff_date, status, notes } = req.body;
  const updates = [];
  const params = [];

  if (name) { updates.push('name = ?'); params.push(name); }
  if (email !== undefined) { updates.push('email = ?'); params.push(email); }
  if (type) { updates.push('type = ?'); params.push(type); }
  if (equity_pool_id) { updates.push('equity_pool_id = ?'); params.push(equity_pool_id); }
  if (vesting_start !== undefined) { updates.push('vesting_start = ?'); params.push(vesting_start); }
  if (vesting_end !== undefined) { updates.push('vesting_end = ?'); params.push(vesting_end); }
  if (cliff_date !== undefined) { updates.push('cliff_date = ?'); params.push(cliff_date); }
  if (status) { updates.push('status = ?'); params.push(status); }
  if (notes !== undefined) { updates.push('notes = ?'); params.push(notes); }

  // If shares changed, log a transfer/edit event
  const sharesChanged = shares_owned !== undefined && shares_owned !== sh.shares_owned;
  if (sharesChanged) {
    updates.push('shares_owned = ?');
    params.push(shares_owned);
  }

  // Recompute vested shares and status if vesting fields or shares changed
  const vs = vesting_start !== undefined ? vesting_start : sh.vesting_start;
  const ve = vesting_end !== undefined ? vesting_end : sh.vesting_end;
  const cd = cliff_date !== undefined ? cliff_date : sh.cliff_date;
  const so = sharesChanged ? shares_owned : sh.shares_owned;

  if (sharesChanged || vesting_start !== undefined || vesting_end !== undefined || cliff_date !== undefined) {
    const vested = computeVestedShares(vs, ve, cd, so);
    const newStatus = computeShareholderStatus(vs, ve, cd, so);
    updates.push('vested_shares = ?'); params.push(vested);
    updates.push('status = ?'); params.push(newStatus);
  }

  if (updates.length > 0) {
    updates.push('updated_at = datetime(\'now\')');
    params.push(req.params.id);
    db.prepare(`UPDATE shareholders SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  }

  if (sharesChanged) {
    const delta = shares_owned - sh.shares_owned;
    db.prepare(
      'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run('edit', sh.id, sh.shares_owned, shares_owned, delta, sh.equity_pool_id, `Adjusted shares for ${sh.name}: ${sh.shares_owned.toLocaleString()} → ${shares_owned.toLocaleString()}`, req.token.name);
  }

  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('cap_table', 'shareholder', req.params.id, req.token.name, `Updated shareholder "${sh.name}"`);

  const updated = db.prepare('SELECT * FROM shareholders WHERE id = ?').get(req.params.id);
  res.json({ shareholder: updated });
});

app.delete('/api/cap-table/shareholders/:id', authenticate(['super_admin']), (req, res) => {
  const sh = db.prepare('SELECT * FROM shareholders WHERE id = ?').get(req.params.id);
  if (!sh) return res.status(404).json({ error: 'Shareholder not found' });

  db.prepare('UPDATE shareholders SET status = ?, updated_at = datetime(\'now\') WHERE id = ?').run('exited', req.params.id);

  db.prepare(
    'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run('cancel', sh.id, sh.shares_owned, 0, -sh.shares_owned, sh.equity_pool_id, `Marked ${sh.name} as exited (${sh.shares_owned.toLocaleString()} shares)`, req.token.name);

  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('cap_table', 'shareholder', req.params.id, req.token.name, `Exited shareholder "${sh.name}"`);

  res.json({ message: 'Shareholder marked as exited' });
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
