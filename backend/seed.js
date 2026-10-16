const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const db = require('./db');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

function seed() {
  console.log('Seeding database...');

  // Seed categories matching the document taxonomy
  const categories = [
    { id: uuidv4(), name: 'Founder Agreement', slug: 'founder-agreement', description: 'Define roles, equity splits, and decision-making among founders', icon: '🤝', sort_order: 1, min_role: 'viewer' },
    { id: uuidv4(), name: 'Incorporation Documents', slug: 'incorporation-documents', description: 'Legal establishment of your company as a separate entity', icon: '🏛️', sort_order: 2, min_role: 'viewer' },
    { id: uuidv4(), name: 'Shareholders Agreement', slug: 'shareholders-agreement', description: 'Rights and obligations among shareholders', icon: '📜', sort_order: 3, min_role: 'viewer' },
    { id: uuidv4(), name: 'Cap Table', slug: 'cap-table', description: 'Ownership structure, equity distribution, and dilution tracking', icon: '📊', sort_order: 4, min_role: 'viewer' },
    { id: uuidv4(), name: 'ESOP Plan', slug: 'esop-plan', description: 'Employee Stock Ownership Plan for team motivation and retention', icon: '🎯', sort_order: 5, min_role: 'viewer' },
    { id: uuidv4(), name: 'Board Resolution', slug: 'board-resolution', description: 'Formal records of key decisions made by the board', icon: '📋', sort_order: 6, min_role: 'viewer' },
    { id: uuidv4(), name: 'IP', slug: 'ip', description: 'Intellectual property registrations, assignments, and ownership records', icon: '💡', sort_order: 7, min_role: 'viewer' },
    { id: uuidv4(), name: 'IP Assignment', slug: 'ip-assignment', description: 'Ensure all company IP is legally owned by the company', icon: '💡', sort_order: 8, min_role: 'viewer' },
    { id: uuidv4(), name: 'Financial Model', slug: 'financial-model', description: 'Revenue, costs, cash flow, and profitability projections', icon: '📈', sort_order: 9, min_role: 'viewer' },
    { id: uuidv4(), name: 'Corporate Documents', slug: 'corporate-documents', description: 'Certificate of Incorporation, M&A, statutory records', icon: '📁', sort_order: 10, min_role: 'viewer' },
    { id: uuidv4(), name: 'Regulatory Compliance', slug: 'regulatory-compliance', description: 'Tax, industry, data privacy, and employment compliance', icon: '✅', sort_order: 11, min_role: 'viewer' },
    { id: uuidv4(), name: 'Financial Statements', slug: 'financial-statements', description: 'Balance sheet, income statement, and cash flow', icon: '💰', sort_order: 12, min_role: 'viewer' },
    { id: uuidv4(), name: 'Investment Memorandum', slug: 'investment-memorandum', description: 'Comprehensive overview of the investment opportunity', icon: '📘', sort_order: 13, min_role: 'viewer' },
    { id: uuidv4(), name: 'Due Diligence', slug: 'due-diligence', description: 'Due diligence checklist and data room index', icon: '🔍', sort_order: 14, min_role: 'viewer' },
    { id: uuidv4(), name: 'General', slug: 'general', description: 'Other corporate and governance documents', icon: '📄', sort_order: 99, min_role: 'viewer' },
  ];

  const insertCat = db.prepare(
    'INSERT OR IGNORE INTO categories (id, name, slug, description, icon, sort_order, min_role) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );

  for (const cat of categories) {
    insertCat.run(cat.id, cat.name, cat.slug, cat.description, cat.icon, cat.sort_order, cat.min_role);
  }

  console.log(`Seeded ${categories.length} categories`);

  // Create super admin token
  const superTokenRaw = process.env.SUPER_ADMIN_KEY || 'esk-super-' + uuidv4().replace(/-/g, '').substring(0, 32);
  const hash = bcrypt.hashSync(superTokenRaw, 10);
  const expiresAt = new Date();
  expiresAt.setFullYear(expiresAt.getFullYear() + 10); // 10 years for super admin

  const existingSuper = db.prepare('SELECT id FROM tokens WHERE role = ?').get('super_admin');
  if (!existingSuper) {
    db.prepare(
      'INSERT INTO tokens (id, name, key_hash, role, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(uuidv4(), 'Super Admin (Auto-generated)', hash, 'super_admin', null, expiresAt.toISOString());
    console.log('Super admin token created');
    console.log(`SUPER ADMIN KEY: ${superTokenRaw}`);
    console.log('SAVE THIS KEY - IT WILL NOT BE SHOWN AGAIN');
  } else {
    console.log('Super admin token already exists');
  }

  console.log('Database seeded successfully!');
}

// Seed cap table data if tables are empty
function seedCapTable(db) {
  if (!db || typeof db.exec !== 'function') {
    throw new Error('Database connection is required to seed cap table data.');
  }

  db.exec(`
    PRAGMA foreign_keys = ON;
  `);

  let pool = db.prepare('SELECT * FROM equity_pools WHERE name = ?').get('Common Pool');
  if (!pool) {
    const poolId = uuidv4();
    // 10,000,000 authorized: 6,000,000 issued to founders + 4,000,000 reserved
    // (option pool + unreserved) so issued + remaining always equals authorized.
    db.prepare(
      'INSERT INTO equity_pools (id, name, total_shares, class, description, valuation) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(poolId, 'Common Pool', 10000000, 'Common', 'Founder common stock + reserved option pool', null);
    pool = db.prepare('SELECT * FROM equity_pools WHERE id = ?').get(poolId);
  }

  if (!pool) {
    throw new Error('Unable to create or find the Common Pool required for cap table seeding.');
  }

  // Founders vest 4 years with a 1-year cliff from 2 years ago, so the
  // table demonstrates live, partial vesting. Vested is computed, not hardcoded.
  const cap = require('./captable');
  const iso = (d) => d.toISOString().slice(0, 10);
  const yearsAgo = (n) => iso(new Date(Date.now() - n * 365 * 86400000));
  const vStart = yearsAgo(2);
  const vEnd = yearsAgo(-2); // 2 years in the future
  const cliff = yearsAgo(1);

  const founders = [
    { name: 'Alice Chen', shares: 3000000 },
    { name: 'Bob Park', shares: 3000000 }
  ];

  for (const f of founders) {
    let row = db.prepare('SELECT id FROM shareholders WHERE name = ? AND equity_pool_id = ?').get(f.name, pool.id);
    if (!row) {
      const id = uuidv4();
      const vested = cap.computeVestedShares(vStart, vEnd, cliff, f.shares);
      const status = cap.computeShareholderStatus(vStart, vEnd, cliff, f.shares);
      db.prepare(
        `INSERT INTO shareholders (id, name, email, type, shares_owned, equity_pool_id, vesting_start, vesting_end, cliff_date, vested_shares, status, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(id, f.name, '', 'founder', f.shares, pool.id, vStart, vEnd, cliff, vested, status, 'Initial founder issuance generated by seed script');
      row = { id };
    }
  }

  // Idempotent issuance events: only insert if this holder has no issuance yet.
  for (const f of founders) {
    const row = db.prepare('SELECT * FROM shareholders WHERE name = ? AND equity_pool_id = ?').get(f.name, pool.id);
    const has = db.prepare("SELECT id FROM cap_table_events WHERE shareholder_id = ? AND event_type = 'issuance' LIMIT 1").get(row.id);
    if (!has) {
      db.prepare(
        'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).run('issuance', row.id, 0, row.shares_owned, row.shares_owned, pool.id, `Initial issuance to ${f.name}`, 'seed');
    }
  }
}

seed();
seedCapTable(db);

console.log('Seeding complete!');

