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
    'SELECT id, name, role, created_at, expires_at, last_used_at, is_active FROM tokens ORDER BY created_at DESC'
  ).all();
  res.json({ tokens });
});

// Create a new token
app.post('/api/tokens', authenticate(['super_admin', 'admin']), (req, res) => {
  const { name, role, expiry_hours } = req.body;
  
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

  const rawKey = 'esk-' + role + '-' + uuidv4().replace(/-/g, '').substring(0, 24);
  const hash = bcrypt.hashSync(rawKey, 10);
  const hours = expiry_hours || (role === 'super_admin' ? 87600 : TOKEN_EXPIRY_HOURS);
  
  const expiresAt = new Date();
  expiresAt.setHours(expiresAt.getHours() + hours);

  const tokenId = uuidv4();
  db.prepare(
    'INSERT INTO tokens (id, name, key_hash, role, expires_at) VALUES (?, ?, ?, ?, ?)'
  ).run(tokenId, name, hash, role, expiresAt.toISOString());

  // Log
  db.prepare(
    'INSERT INTO activity_log (action, entity_type, entity_id, token_name, details) VALUES (?, ?, ?, ?, ?)'
  ).run('token_created', 'token', tokenId, req.token.name, `Created token "${name}" with role ${role}`);

  res.json({
    id: tokenId,
    name,
    role,
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

// List documents (with filters)
app.get('/api/documents', authenticate(), (req, res) => {
  const { category, search, page = 1, limit = 20 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  
  let sql = 'SELECT id, title, description, category, original_name, mime_type, file_size, uploaded_by, uploaded_at, updated_at, version, is_archived FROM documents WHERE is_archived = 0';
  let countSql = 'SELECT COUNT(*) as total FROM documents WHERE is_archived = 0';
  const params = [];
  const countParams = [];

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

// Get single document
app.get('/api/documents/:id', authenticate(), (req, res) => {
  const doc = db.prepare(
    'SELECT * FROM documents WHERE id = ? AND is_archived = 0'
  ).get(req.params.id);

  if (!doc) return res.status(404).json({ error: 'Document not found' });

  res.json({ document: doc });
});

// Download document
app.get('/api/documents/:id/download', authenticate(), (req, res) => {
  const doc = db.prepare(
    'SELECT * FROM documents WHERE id = ? AND is_archived = 0'
  ).get(req.params.id);

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

// Upload document
app.post('/api/documents', authenticate(['super_admin', 'admin', 'editor']), upload.single('file'), (req, res) => {
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

// Update document metadata
app.patch('/api/documents/:id', authenticate(['super_admin', 'admin', 'editor']), (req, res) => {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ? AND is_archived = 0').get(req.params.id);
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

// Delete (archive) document
app.delete('/api/documents/:id', authenticate(['super_admin', 'admin']), (req, res) => {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ? AND is_archived = 0').get(req.params.id);
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
    admin: ['view', 'upload', 'edit', 'delete', 'manage_tokens', 'view_activity', 'export'],
    editor: ['view', 'upload', 'edit'],
    viewer: ['view']
  };
  return permissions[role] || [];
}

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
