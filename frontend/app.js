/* ============================================
   Eskaen Vault - Frontend Application
   Minimalist, modern document management
   ============================================ */

const API_BASE = window.location.origin === 'http://localhost:5500' || window.location.origin === 'http://127.0.0.1:5500'
  ? 'http://localhost:3001'
  : '';

let state = {
  token: null,
  tokenData: null,
  documents: [],
  categories: [],
  tokens: [],
  activity: [],
  stats: {},
  currentTab: 'documents',
  currentCategory: '',
  searchQuery: ''
};

// ===== UTILITY FUNCTIONS =====
function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...options.headers };
  if (state.token) headers['Authorization'] = `Bearer ${state.token}`;
  
  if (options.body instanceof FormData) {
    delete headers['Content-Type'];
  } else if (options.body && typeof options.body === 'object') {
    options.body = JSON.stringify(options.body);
  }

  return fetch(`${API_BASE}${path}`, {
    ...options,
    headers
  }).then(async r => {
    const data = r.headers.get('content-type')?.includes('application/json') ? await r.json() : await r.text();
    if (!r.ok) throw new Error(data.error || data.message || `HTTP ${r.status}`);
    return data;
  });
}

function formatSize(bytes) {
  if (!bytes) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
}

function formatDate(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  const now = new Date();
  const diff = now - d;
  if (diff < 60000) return 'Just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  if (diff < 604800000) return `${Math.floor(diff / 86400000)}d ago`;
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function formatDateFull(dateStr) {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit'
  });
}

function isExpired(dateStr) {
  return new Date(dateStr) < new Date();
}

function showToast(message, type = 'success') {
  const toast = document.getElementById('toast') || createToast();
  toast.className = `toast show ${type}`;
  toast.innerHTML = `<i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i> ${message}`;
  clearTimeout(toast._timeout);
  toast._timeout = setTimeout(() => toast.classList.remove('show'), 3000);
}

function createToast() {
  const toast = document.createElement('div');
  toast.id = 'toast';
  document.body.appendChild(toast);
  return toast;
}

function showLoading(show = true) {
  let el = document.getElementById('loading-overlay');
  if (!show && el) { el.remove(); return; }
  if (show && !el) {
    el = document.createElement('div');
    el.id = 'loading-overlay';
    el.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.3);backdrop-filter:blur(2px);display:flex;align-items:center;justify-content:center;z-index:9999;';
    el.innerHTML = '<i class="fas fa-spinner spinner" style="font-size:32px;color:var(--accent)"></i>';
    document.body.appendChild(el);
  }
}

function modal(title, bodyHtml, footerHtml = '') {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay show';
  overlay.id = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <h2>${title}</h2>
        <button class="close-btn" onclick="closeModal()"><i class="fas fa-times"></i></button>
      </div>
      <div class="modal-body">${bodyHtml}</div>
      ${footerHtml ? `<div class="modal-footer">${footerHtml}</div>` : ''}
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });
}

function closeModal() {
  const overlay = document.getElementById('modal-overlay');
  if (overlay) overlay.remove();
}

// ===== AUTH =====
function showAuth() {
  document.getElementById('app').innerHTML = `
    <div class="auth-screen">
      <div class="auth-card">
        <div class="logo-big">
          <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
            <rect x="4" y="8" width="28" height="24" rx="3" stroke="#6c5ce7" stroke-width="2" fill="none"/>
            <rect x="8" y="12" width="20" height="16" rx="2" stroke="#a29bfe" stroke-width="1.5" fill="none"/>
            <path d="M14 20l3 3 5-6" stroke="#00d68f" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <rect x="10" y="4" width="16" height="6" rx="2" stroke="#6c5ce7" stroke-width="1.5" fill="none"/>
          </svg>
          <span>Eskaen Vault</span>
        </div>
        <p class="subtitle">Secure document management platform</p>
        <div id="auth-error" class="error-msg"></div>
        <div class="input-group">
          <label>API Key</label>
          <input type="password" id="api-key-input" placeholder="Enter your API key" autofocus />
        </div>
        <button class="btn btn-primary" onclick="handleLogin()">
          <i class="fas fa-lock"></i> Authenticate
        </button>
        <p style="text-align:center;margin-top:20px;font-size:12px;color:var(--text-muted)">
          <i class="fas fa-key"></i> Use your token to access the vault
        </p>
      </div>
    </div>
  `;
  
  document.getElementById('api-key-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') handleLogin();
  });
}

async function handleLogin() {
  const key = document.getElementById('api-key-input').value.trim();
  const errorEl = document.getElementById('auth-error');
  
  if (!key) {
    errorEl.textContent = 'Please enter your API key';
    errorEl.classList.add('show');
    return;
  }

  showLoading(true);
  try {
    const result = await api('/api/auth/login', {
      method: 'POST',
      body: { api_key: key }
    });
    
    state.token = result.token;
    state.tokenData = result;
    
    // Store in session
    sessionStorage.setItem('vault_token', result.token);
    sessionStorage.setItem('vault_token_name', result.token_name);
    sessionStorage.setItem('vault_role', result.role);
    
    showToast(`Authenticated as ${result.token_name}`);
    await initDashboard();
  } catch (err) {
    errorEl.textContent = err.message || 'Authentication failed';
    errorEl.classList.add('show');
  } finally {
    showLoading(false);
  }
}

// ===== DASHBOARD =====
async function initDashboard() {
  await Promise.all([
    loadStats(),
    loadDocuments(),
    loadCategories()
  ]);
  renderDashboard();
}

async function loadStats() {
  try {
    state.stats = await api('/api/stats');
  } catch (e) { console.error('Failed to load stats', e); }
}

async function loadDocuments() {
  try {
    let url = '/api/documents?limit=100';
    if (state.currentCategory) url += `&category=${state.currentCategory}`;
    if (state.searchQuery) url += `&search=${encodeURIComponent(state.searchQuery)}`;
    const result = await api(url);
    state.documents = result.documents || [];
  } catch (e) { console.error('Failed to load documents', e); state.documents = []; }
}

async function loadCategories() {
  try {
    const result = await api('/api/categories');
    state.categories = result.categories || [];
  } catch (e) { console.error('Failed to load categories', e); }
}

async function loadTokens() {
  try {
    const result = await api('/api/tokens');
    state.tokens = result.tokens || [];
  } catch (e) { console.error('Failed to load tokens', e); }
}

async function loadActivity() {
  try {
    const result = await api('/api/activity');
    state.activity = result.logs || [];
  } catch (e) { console.error('Failed to load activity', e); }
}

// ===== RENDER =====
function renderDashboard() {
  const role = state.tokenData?.role || sessionStorage.getItem('vault_role') || 'viewer';
  const name = state.tokenData?.token_name || sessionStorage.getItem('vault_token_name') || 'User';
  const perms = state.tokenData?.permissions || [];
  
  document.getElementById('app').innerHTML = `
    <header class="app-header">
      <div class="logo">
        <svg width="28" height="28" viewBox="0 0 36 36" fill="none">
          <rect x="4" y="8" width="28" height="24" rx="3" stroke="#6c5ce7" stroke-width="2" fill="none"/>
          <rect x="8" y="12" width="20" height="16" rx="2" stroke="#a29bfe" stroke-width="1.5" fill="none"/>
          <path d="M14 20l3 3 5-6" stroke="#00d68f" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          <rect x="10" y="4" width="16" height="6" rx="2" stroke="#6c5ce7" stroke-width="1.5" fill="none"/>
        </svg>
        <span>Eskaen Vault</span>
      </div>
      <div class="header-right">
        <span style="font-size:13px;color:var(--text-secondary)">${name}</span>
        <span class="role-badge ${role}">${role.replace('_', ' ')}</span>
        <button class="btn btn-icon" onclick="handleLogout()" title="Logout">
          <i class="fas fa-sign-out-alt"></i>
        </button>
      </div>
    </header>
    <main class="main-content">
      <div class="dashboard-header">
        <div>
          <h1>${state.currentTab === 'documents' ? 'Documents' : state.currentTab === 'tokens' ? 'Access Tokens' : 'Activity Log'}</h1>
          <p>${state.currentTab === 'documents' ? `Browse and manage ${state.stats.total_documents || 0} documents in the vault` : 
               state.currentTab === 'tokens' ? 'Manage API keys and access permissions' : 'Track all vault activity'}</p>
        </div>
        <div style="display:flex;gap:8px">
          ${perms.includes('upload') ? `<button class="btn btn-primary btn-sm" onclick="showUploadModal()"><i class="fas fa-upload"></i> Upload</button>` : ''}
          ${role === 'super_admin' || role === 'admin' ? `<button class="btn btn-secondary btn-sm" onclick="showCreateTokenModal()"><i class="fas fa-plus"></i> New Token</button>` : ''}
        </div>
      </div>

      <!-- Stats -->
      ${state.currentTab === 'documents' ? `
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-icon">📄</div>
          <div class="stat-value">${state.stats.total_documents || 0}</div>
          <div class="stat-label">Documents</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">💾</div>
          <div class="stat-value">${formatSize(state.stats.total_storage || 0)}</div>
          <div class="stat-label">Total Storage</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">🔑</div>
          <div class="stat-value">${state.stats.total_active_tokens || 0}</div>
          <div class="stat-label">Active Tokens</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">📂</div>
          <div class="stat-value">${state.categories.length}</div>
          <div class="stat-label">Categories</div>
        </div>
      </div>` : ''}

      <!-- Tabs -->
      <div class="tabs">
        <button class="tab ${state.currentTab === 'documents' ? 'active' : ''}" onclick="switchTab('documents')">
          <i class="fas fa-file-alt"></i> Documents
        </button>
        ${role === 'super_admin' || role === 'admin' ? `
        <button class="tab ${state.currentTab === 'tokens' ? 'active' : ''}" onclick="switchTab('tokens')">
          <i class="fas fa-key"></i> Tokens
        </button>
        <button class="tab ${state.currentTab === 'activity' ? 'active' : ''}" onclick="switchTab('activity')">
          <i class="fas fa-history"></i> Activity
        </button>` : ''}
      </div>

      <!-- Tab Content -->
      <div id="tab-content"></div>
    </main>
  `;
  
  renderTabContent();
}

function renderTabContent() {
  const el = document.getElementById('tab-content');
  if (!el) return;
  
  if (state.currentTab === 'documents') renderDocuments(el);
  else if (state.currentTab === 'tokens') renderTokens(el);
  else if (state.currentTab === 'activity') renderActivity(el);
}

function renderDocuments(container) {
  const perms = state.tokenData?.permissions || [];
  
  container.innerHTML = `
    <div class="documents-header">
      <div class="search-bar">
        <i class="fas fa-search"></i>
        <input type="text" placeholder="Search documents..." id="search-input" value="${state.searchQuery}" />
      </div>
      <div class="category-filter">
        <select id="category-select">
          <option value="">All Categories</option>
          ${state.categories.map(c => `<option value="${c.slug}" ${state.currentCategory === c.slug ? 'selected' : ''}>${c.name} (${c.document_count || 0})</option>`).join('')}
        </select>
      </div>
    </div>
    <div id="documents-container">
      ${state.documents.length === 0 ? `
        <div class="empty-state">
          <i class="fas fa-folder-open"></i>
          <h3>No documents yet</h3>
          <p>${perms.includes('upload') ? 'Upload your first document to get started.' : 'No documents are available in this category.'}</p>
        </div>
      ` : `
        <div class="documents-grid">
          ${state.documents.map(doc => renderDocCard(doc)).join('')}
        </div>
      `}
    </div>
  `;

  // Event listeners
  const searchInput = document.getElementById('search-input');
  const catSelect = document.getElementById('category-select');
  
  let searchTimer;
  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(async () => {
      state.searchQuery = searchInput.value;
      await loadDocuments();
      renderDocuments(document.getElementById('tab-content'));
    }, 300);
  });

  catSelect.addEventListener('change', async () => {
    state.currentCategory = catSelect.value;
    await loadDocuments();
    renderDocuments(document.getElementById('tab-content'));
  });
}

function renderDocCard(doc) {
  const iconMap = {
    'founder-agreement': '🤝',
    'incorporation-documents': '🏛️',
    'shareholders-agreement': '📜',
    'cap-table': '📊',
    'esop-plan': '🎯',
    'board-resolution': '📋',
    'ip-assignment': '💡',
    'financial-model': '📈',
    'corporate-documents': '📁',
    'regulatory-compliance': '✅',
    'financial-statements': '💰',
    'investment-memorandum': '📘',
    'due-diligence': '🔍'
  };
  
  const icon = iconMap[doc.category] || '📄';
  const perms = state.tokenData?.permissions || [];
  
  return `
    <div class="doc-card" onclick="showDocDetail('${doc.id}')">
      <div class="doc-icon">${icon}</div>
      <div class="doc-title">${doc.title}</div>
      <div class="doc-desc">${doc.description || 'No description'}</div>
      <div class="doc-meta">
        <span>${formatSize(doc.file_size)}</span>
        <span>v${doc.version}</span>
        <span>${formatDate(doc.uploaded_at)}</span>
      </div>
      <div class="doc-category" style="margin-top:8px">${doc.category}</div>
    </div>
  `;
}

// ===== DOCUMENT DETAIL =====
async function showDocDetail(docId) {
  showLoading(true);
  try {
    const result = await api(`/api/documents/${docId}`);
    const doc = result.document;
    const perms = state.tokenData?.permissions || [];
    
    const iconMap = {
      'founder-agreement': '🤝', 'incorporation-documents': '🏛️', 'shareholders-agreement': '📜',
      'cap-table': '📊', 'esop-plan': '🎯', 'board-resolution': '📋', 'ip-assignment': '💡',
      'financial-model': '📈', 'corporate-documents': '📁', 'regulatory-compliance': '✅',
      'financial-statements': '💰', 'investment-memorandum': '📘', 'due-diligence': '🔍'
    };
    const icon = iconMap[doc.category] || '📄';

    modal(doc.title, `
      <div style="text-align:center;margin-bottom:20px">
        <div style="font-size:48px;margin-bottom:8px">${icon}</div>
        <div style="font-size:12px;color:var(--text-secondary)">${doc.category}</div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
        <div><small style="color:var(--text-muted)">Size</small><br>${formatSize(doc.file_size)}</div>
        <div><small style="color:var(--text-muted)">Version</small><br>${doc.version}</div>
        <div><small style="color:var(--text-muted)">Uploaded</small><br>${formatDateFull(doc.uploaded_at)}</div>
        <div><small style="color:var(--text-muted)">Uploaded by</small><br>${doc.uploaded_by || '—'}</div>
      </div>
      <div style="margin-bottom:16px">
        <small style="color:var(--text-muted)">Description</small>
        <p style="margin-top:4px;font-size:14px;color:var(--text-secondary)">${doc.description || 'No description'}</p>
      </div>
      <div>
        <small style="color:var(--text-muted)">Original filename</small>
        <p style="font-size:13px;font-family:monospace;color:var(--text-secondary);word-break:break-all">${doc.original_name}</p>
      </div>
    `, `
      <button class="btn btn-secondary btn-sm" onclick="closeModal()">Close</button>
      <button class="btn btn-primary btn-sm" onclick="downloadDoc('${doc.id}')"><i class="fas fa-download"></i> Download</button>
      ${perms.includes('edit') ? `<button class="btn btn-secondary btn-sm" onclick="showEditDocModal('${doc.id}')"><i class="fas fa-edit"></i> Edit</button>` : ''}
      ${perms.includes('delete') ? `<button class="btn btn-danger btn-sm" onclick="deleteDoc('${doc.id}')"><i class="fas fa-trash"></i> Delete</button>` : ''}
    `);

  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    showLoading(false);
  }
}

async function downloadDoc(docId) {
  try {
    const response = await fetch(`${API_BASE}/api/documents/${docId}/download`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    if (!response.ok) throw new Error('Download failed');
    
    const blob = await response.blob();
    const disposition = response.headers.get('Content-Disposition');
    const filename = disposition ? disposition.split('filename=')[1]?.replace(/"/g, '') : 'document';
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Download started');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deleteDoc(docId) {
  if (!confirm('Are you sure you want to archive this document?')) return;
  try {
    await api(`/api/documents/${docId}`, { method: 'DELETE' });
    closeModal();
    showToast('Document archived');
    await loadDocuments();
    renderDocuments(document.getElementById('tab-content'));
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ===== UPLOAD =====
function showUploadModal() {
  const cats = state.categories;
  
  modal('Upload Document', `
    <div class="form-group">
      <label>Title</label>
      <input type="text" id="upload-title" placeholder="Document title" />
    </div>
    <div class="form-group">
      <label>Description</label>
      <textarea id="upload-desc" placeholder="Brief description..."></textarea>
    </div>
    <div class="form-group">
      <label>Category</label>
      <select id="upload-category">
        <option value="">Select category...</option>
        ${cats.map(c => `<option value="${c.slug}">${c.name}</option>`).join('')}
      </select>
    </div>
    <div class="form-group">
      <label>File</label>
      <div class="upload-area" id="upload-area">
        <i class="fas fa-cloud-upload-alt"></i>
        <p>Click or drag a file here</p>
        <div class="file-name" id="file-name"></div>
        <input type="file" id="file-input" style="display:none" />
      </div>
    </div>
  `, `
    <button class="btn btn-secondary btn-sm" onclick="closeModal()">Cancel</button>
    <button class="btn btn-primary btn-sm" onclick="handleUpload()"><i class="fas fa-upload"></i> Upload</button>
  `);

  const area = document.getElementById('upload-area');
  const fileInput = document.getElementById('file-input');
  
  area.addEventListener('click', () => fileInput.click());
  area.addEventListener('dragover', e => { e.preventDefault(); area.classList.add('dragover'); });
  area.addEventListener('dragleave', () => area.classList.remove('dragover'));
  area.addEventListener('drop', e => {
    e.preventDefault();
    area.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
      fileInput.files = e.dataTransfer.files;
      document.getElementById('file-name').textContent = e.dataTransfer.files[0].name;
    }
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
      document.getElementById('file-name').textContent = fileInput.files[0].name;
    }
  });
}

async function handleUpload() {
  const title = document.getElementById('upload-title').value.trim();
  const desc = document.getElementById('upload-desc').value.trim();
  const category = document.getElementById('upload-category').value;
  const fileInput = document.getElementById('file-input');
  
  if (!title) { showToast('Title is required', 'error'); return; }
  if (!category) { showToast('Category is required', 'error'); return; }
  if (!fileInput.files.length) { showToast('Please select a file', 'error'); return; }

  showLoading(true);
  try {
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('title', title);
    formData.append('description', desc);
    formData.append('category', category);
    
    await api('/api/documents', {
      method: 'POST',
      body: formData
    });
    
    closeModal();
    showToast('Document uploaded successfully');
    await loadDocuments();
    await loadStats();
    renderDocuments(document.getElementById('tab-content'));
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    showLoading(false);
  }
}

// ===== EDIT DOCUMENT =====
async function showEditDocModal(docId) {
  showLoading(true);
  try {
    const result = await api(`/api/documents/${docId}`);
    const doc = result.document;
    
    modal('Edit Document', `
      <div class="form-group">
        <label>Title</label>
        <input type="text" id="edit-title" value="${doc.title}" />
      </div>
      <div class="form-group">
        <label>Description</label>
        <textarea id="edit-desc">${doc.description || ''}</textarea>
      </div>
      <div class="form-group">
        <label>Category</label>
        <select id="edit-category">
          ${state.categories.map(c => `<option value="${c.slug}" ${doc.category === c.slug ? 'selected' : ''}>${c.name}</option>`).join('')}
        </select>
      </div>
    `, `
      <button class="btn btn-secondary btn-sm" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary btn-sm" onclick="handleEditDoc('${docId}')"><i class="fas fa-save"></i> Save</button>
    `);
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    showLoading(false);
  }
}

async function handleEditDoc(docId) {
  const title = document.getElementById('edit-title').value.trim();
  const desc = document.getElementById('edit-desc').value.trim();
  const category = document.getElementById('edit-category').value;
  
  if (!title) { showToast('Title is required', 'error'); return; }

  try {
    await api(`/api/documents/${docId}`, {
      method: 'PATCH',
      body: { title, description: desc, category }
    });
    closeModal();
    showToast('Document updated');
    await loadDocuments();
    renderDocuments(document.getElementById('tab-content'));
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ===== TOKENS =====
function renderTokens(container) {
  const role = state.tokenData?.role;
  
  container.innerHTML = `
    <div style="margin-bottom:16px">
      <p style="font-size:13px;color:var(--text-secondary)">
        <i class="fas fa-info-circle"></i> Tokens are API keys with expiring access. 
        Roles control permissions: ${role === 'super_admin' ? 'Super Admin (full access), ' : ''}Admin, Editor, Viewer.
        Scope restricts which categories a token can access.
      </p>
    </div>
    ${state.tokens.length === 0 ? `
      <div class="empty-state">
        <i class="fas fa-key"></i>
        <h3>No tokens created</h3>
        <p>Create API tokens to grant access to the vault.</p>
      </div>
    ` : `
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Role</th>
            <th>Scope</th>
            <th>Status</th>
            <th>Created</th>
            <th>Expires</th>
            <th>Last Used</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${state.tokens.map(t => `
            <tr>
              <td><strong>${t.name}</strong></td>
              <td><span class="role-badge ${t.role}" style="font-size:10px">${t.role.replace('_', ' ')}</span></td>
              <td style="font-size:11px">${t.scope && t.scope.length > 0 ? t.scope.map(s => `<span class="scope-badge">${s}</span>`).join(' ') : '<span style="color:var(--text-muted)">All</span>'}</td>
              <td><span class="status-badge ${t.is_active && !isExpired(t.expires_at) ? 'active' : 'expired'}">${t.is_active && !isExpired(t.expires_at) ? 'Active' : 'Inactive'}</span></td>
              <td style="font-size:12px">${formatDate(t.created_at)}</td>
              <td style="font-size:12px;color:${isExpired(t.expires_at) ? 'var(--red)' : 'var(--text-secondary)'}">${formatDate(t.expires_at)}</td>
              <td style="font-size:12px">${t.last_used_at ? formatDate(t.last_used_at) : '—'}</td>
              <td>
                <div style="display:flex;gap:4px">
                  ${t.is_active ? `<button class="btn btn-secondary btn-sm" onclick="extendToken('${t.id}')" title="Extend expiry"><i class="fas fa-clock"></i></button>` : ''}
                  ${t.is_active ? `<button class="btn btn-danger btn-sm" onclick="revokeToken('${t.id}')" title="Revoke"><i class="fas fa-ban"></i></button>` : ''}
                </div>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>`}
  `;
}

function showCreateTokenModal() {
  const role = state.tokenData?.role;
  const cats = state.categories;
  
  modal('Create Access Token', `
    <div class="form-group">
      <label>Token Name</label>
      <input type="text" id="token-name" placeholder="e.g., Marketing Team" />
    </div>
    <div class="form-group">
      <label>Role</label>
      <select id="token-role">
        ${role === 'super_admin' ? '<option value="super_admin">Super Admin</option>' : ''}
        <option value="admin">Admin</option>
        <option value="editor">Editor</option>
        <option value="viewer" selected>Viewer</option>
      </select>
    </div>
    <div class="form-group">
      <label>Scope (categories this token can access)</label>
      <div class="scope-selector" id="scope-selector">
        <label class="scope-option">
          <input type="checkbox" id="scope-all" checked onchange="toggleAllScopes()" />
          <span>All Categories (unrestricted)</span>
        </label>
        ${cats.map(c => `
          <label class="scope-option scope-cat">
            <input type="checkbox" value="${c.slug}" class="scope-check" disabled />
            <span>${c.icon || ''} ${c.name}</span>
          </label>
        `).join('')}
      </div>
      <small style="color:var(--text-muted);font-size:11px">Uncheck "All Categories" to restrict access to specific categories.</small>
    </div>
    <div class="form-group">
      <label>Expiry (hours)</label>
      <input type="number" id="token-hours" value="24" min="1" max="87600" />
      <small style="color:var(--text-muted);font-size:11px">Default: 24 hours. Max: 10 years (87600h).</small>
    </div>
    <div id="new-token-result" style="display:none">
      <div style="padding:12px;background:var(--yellow-bg);border:1px solid rgba(255,217,61,0.2);border-radius:var(--radius-sm);margin-top:8px">
        <p style="color:var(--yellow);font-size:12px;font-weight:600;margin-bottom:8px"><i class="fas fa-exclamation-triangle"></i> SAVE THIS KEY NOW — IT WILL NOT BE SHOWN AGAIN</p>
        <div class="token-key-display" id="token-raw-key"></div>
        <button class="copy-btn" onclick="copyTokenKey()"><i class="fas fa-copy"></i> Copy to clipboard</button>
      </div>
    </div>
  `, `
    <button class="btn btn-secondary btn-sm" onclick="closeModal()">Cancel</button>
    <button class="btn btn-primary btn-sm" id="create-token-btn" onclick="handleCreateToken()"><i class="fas fa-plus"></i> Create</button>
  `);
}

function toggleAllScopes() {
  const allChecked = document.getElementById('scope-all').checked;
  document.querySelectorAll('.scope-check').forEach(cb => {
    cb.disabled = allChecked;
    if (allChecked) cb.checked = false;
  });
}

async function handleCreateToken() {
  const name = document.getElementById('token-name').value.trim();
  const role = document.getElementById('token-role').value;
  const hours = parseInt(document.getElementById('token-hours').value) || 24;
  
  if (!name) { showToast('Token name is required', 'error'); return; }
  
  // Determine scope
  const allChecked = document.getElementById('scope-all').checked;
  let scope = null;
  if (!allChecked) {
    scope = Array.from(document.querySelectorAll('.scope-check:checked')).map(cb => cb.value);
  }
  
  const btn = document.getElementById('create-token-btn');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner spinner"></i> Creating...';
  
  try {
    const result = await api('/api/tokens', {
      method: 'POST',
      body: { name, role, expiry_hours: hours, scope }
    });
    
    // Show the key
    document.getElementById('new-token-result').style.display = 'block';
    document.getElementById('token-raw-key').textContent = result.raw_key;
    document.getElementById('create-token-btn').style.display = 'none';
    
    showToast('Token created successfully');
    
    // Refresh token list
    await loadTokens();
  } catch (err) {
    showToast(err.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-plus"></i> Create';
  }
}

function copyTokenKey() {
  const key = document.getElementById('token-raw-key').textContent;
  navigator.clipboard.writeText(key).then(() => {
    showToast('Key copied to clipboard');
  });
}

async function revokeToken(tokenId) {
  if (!confirm('Are you sure you want to revoke this token? This cannot be undone.')) return;
  try {
    await api(`/api/tokens/${tokenId}`, { method: 'DELETE' });
    showToast('Token revoked');
    await loadTokens();
    renderTokens(document.getElementById('tab-content'));
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function extendToken(tokenId) {
  const hours = prompt('Extend by how many hours?', '24');
  if (!hours || isNaN(hours)) return;
  try {
    await api(`/api/tokens/${tokenId}/extend`, {
      method: 'PATCH',
      body: { hours: parseInt(hours) }
    });
    showToast(`Token extended by ${hours}h`);
    await loadTokens();
    renderTokens(document.getElementById('tab-content'));
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ===== ACTIVITY =====
function renderActivity(container) {
  container.innerHTML = state.activity.length === 0 ? `
    <div class="empty-state">
      <i class="fas fa-history"></i>
      <h3>No activity yet</h3>
      <p>Actions performed in the vault will appear here.</p>
    </div>
  ` : `
    <div class="activity-list">
      ${state.activity.map(log => {
        const iconMap = {
          'login': '🔑', 'upload': '📤', 'download': '📥', 'update': '✏️',
          'archive': '🗂️', 'token_created': '🔐', 'token_revoked': '🔒'
        };
        return `
          <div class="activity-item">
            <div class="activity-icon" style="background:var(--accent-subtle);color:var(--accent)">${iconMap[log.action] || '📋'}</div>
            <div class="activity-detail">
              <strong>${log.action.replace('_', ' ')}</strong>
              <div style="font-size:12px;color:var(--text-secondary)">${log.details || ''}</div>
              <div style="font-size:11px;color:var(--text-muted)">by ${log.token_name || 'system'} · ${formatDateFull(log.created_at)}</div>
            </div>
          </div>
        `;
      }).join('')}
    </div>
  `;
}

// ===== TAB SWITCHING =====
async function switchTab(tab) {
  state.currentTab = tab;
  
  if (tab === 'tokens') await loadTokens();
  if (tab === 'activity') await loadActivity();
  
  renderDashboard();
}

// ===== LOGOUT =====
function handleLogout() {
  state.token = null;
  state.tokenData = null;
  sessionStorage.clear();
  showAuth();
}

// ===== INIT =====
async function init() {
  const storedToken = sessionStorage.getItem('vault_token');
  if (storedToken) {
    state.token = storedToken;
    state.tokenData = {
      token_name: sessionStorage.getItem('vault_token_name') || 'User',
      role: sessionStorage.getItem('vault_role') || 'viewer'
    };
    try {
      await initDashboard();
      return;
    } catch (e) {
      sessionStorage.clear();
    }
  }
  showAuth();
}

document.addEventListener('DOMContentLoaded', init);
