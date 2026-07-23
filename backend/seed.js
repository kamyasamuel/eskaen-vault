const db = require('./db');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

function seed() {
  console.log('Seeding database...');

  // Seed categories matching the 15 documents
  const categories = [
    { id: uuidv4(), name: 'Founder Agreement', slug: 'founder-agreement', description: 'Define roles, equity splits, and decision-making among founders', icon: '🤝', sort_order: 1, min_role: 'viewer' },
    { id: uuidv4(), name: 'Incorporation Documents', slug: 'incorporation-documents', description: 'Legal establishment of your company as a separate entity', icon: '🏛️', sort_order: 2, min_role: 'viewer' },
    { id: uuidv4(), name: 'Shareholders Agreement', slug: 'shareholders-agreement', description: 'Rights and obligations among shareholders', icon: '📜', sort_order: 3, min_role: 'viewer' },
    { id: uuidv4(), name: 'Cap Table', slug: 'cap-table', description: 'Ownership structure, equity distribution, and dilution tracking', icon: '📊', sort_order: 4, min_role: 'viewer' },
    { id: uuidv4(), name: 'ESOP Plan', slug: 'esop-plan', description: 'Employee Stock Ownership Plan for team motivation and retention', icon: '🎯', sort_order: 5, min_role: 'viewer' },
    { id: uuidv4(), name: 'Board Resolution', slug: 'board-resolution', description: 'Formal records of key decisions made by the board', icon: '📋', sort_order: 6, min_role: 'viewer' },
    { id: uuidv4(), name: 'IP Assignment', slug: 'ip-assignment', description: 'Ensure all company IP is legally owned by the company', icon: '💡', sort_order: 7, min_role: 'viewer' },
    { id: uuidv4(), name: 'Financial Model', slug: 'financial-model', description: 'Revenue, costs, cash flow, and profitability projections', icon: '📈', sort_order: 8, min_role: 'viewer' },
    { id: uuidv4(), name: 'Corporate Documents', slug: 'corporate-documents', description: 'Certificate of Incorporation, M&A, statutory records', icon: '📁', sort_order: 9, min_role: 'viewer' },
    { id: uuidv4(), name: 'Regulatory Compliance', slug: 'regulatory-compliance', description: 'Tax, industry, data privacy, and employment compliance', icon: '✅', sort_order: 10, min_role: 'viewer' },
    { id: uuidv4(), name: 'Financial Statements', slug: 'financial-statements', description: 'Balance sheet, income statement, and cash flow', icon: '💰', sort_order: 11, min_role: 'viewer' },
    { id: uuidv4(), name: 'Investment Memorandum', slug: 'investment-memorandum', description: 'Comprehensive overview of the investment opportunity', icon: '📘', sort_order: 12, min_role: 'viewer' },
    { id: uuidv4(), name: 'Due Diligence', slug: 'due-diligence', description: 'Due diligence checklist and data room index', icon: '🔍', sort_order: 13, min_role: 'viewer' },
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
function seedCapTable() {
  const db = require('./db');
  const { v4: uuidv4 } = require('uuid');

  const existing = db.prepare('SELECT COUNT(*) as count FROM equity_pools').get();
  if (existing.count > 0) {
    console.log('Cap table already seeded, skipping.');
    return;
  }

  console.log('Seeding cap table data...');

  // Create equity pools
  const commonPoolId = uuidv4();
  const esopPoolId = uuidv4();

  db.prepare('INSERT INTO equity_pools (id, name, total_shares, class, description) VALUES (?, ?, ?, ?, ?)').run(
    commonPoolId, 'Common Stock', 10000000, 'Common', 'Founder and early employee common shares'
  );
  db.prepare('INSERT INTO equity_pools (id, name, total_shares, class, description) VALUES (?, ?, ?, ?, ?)').run(
    esopPoolId, 'ESOP Pool', 1500000, 'Common', 'Employee Stock Option Pool for future hires'
  );

  // Create shareholders
  const founder1Id = uuidv4();
  const founder2Id = uuidv4();
  const investorId = uuidv4();
  const employeeId = uuidv4();

  // Founder 1 — fully vested
  const f1Start = '2023-01-01';
  const f1End = '2025-01-01';
  db.prepare(
    `INSERT INTO shareholders (id, name, email, type, shares_owned, equity_pool_id, vesting_start, vesting_end, cliff_date, vested_shares, status, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(founder1Id, 'Alice Chen', 'alice@example.com', 'founder', 4500000, commonPoolId, f1Start, f1End, '2023-07-01', 4500000, 'fully_vested', 'CEO & Co-Founder');

  // Founder 2 — fully vested
  db.prepare(
    `INSERT INTO shareholders (id, name, email, type, shares_owned, equity_pool_id, vesting_start, vesting_end, cliff_date, vested_shares, status, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(founder2Id, 'Bob Park', 'bob@example.com', 'founder', 3500000, commonPoolId, f1Start, f1End, '2023-07-01', 3500000, 'fully_vested', 'CTO & Co-Founder');

  // Angel investor — active (no vesting)
  db.prepare(
    `INSERT INTO shareholders (id, name, email, type, shares_owned, equity_pool_id, vested_shares, status, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(investorId, 'Seed Ventures LLC', 'legal@seedventures.com', 'investor', 2000000, commonPoolId, 2000000, 'active', 'Seed round, $2M at $10M post-money');

  // Employee — vesting in progress
  const empStart = '2025-03-01';
  const empEnd = '2029-03-01';
  const empCliff = '2025-09-01';
  db.prepare(
    `INSERT INTO shareholders (id, name, email, type, shares_owned, equity_pool_id, vesting_start, vesting_end, cliff_date, vested_shares, status, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(employeeId, 'Diana Reyes', 'diana@example.com', 'employee', 250000, esopPoolId, empStart, empEnd, empCliff, 0, 'vesting', 'First engineering hire, 4-year vest with 1-year cliff');

  // Create events
  db.prepare(
    'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run('issuance', founder1Id, 0, 4500000, 4500000, commonPoolId, 'Initial issuance to Alice Chen', 'seed', '2023-01-15T00:00:00Z');
  db.prepare(
    'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run('issuance', founder2Id, 0, 3500000, 3500000, commonPoolId, 'Initial issuance to Bob Park', 'seed', '2023-01-15T00:00:00Z');
  db.prepare(
    'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run('issuance', investorId, 0, 2000000, 2000000, commonPoolId, 'Seed round investment by Seed Ventures LLC', 'seed', '2024-06-01T00:00:00Z');
  db.prepare(
    'INSERT INTO cap_table_events (event_type, shareholder_id, shares_before, shares_after, delta_shares, equity_pool_id, description, performed_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run('issuance', employeeId, 0, 250000, 250000, esopPoolId, 'Employee grant to Diana Reyes', 'seed', '2025-03-01T00:00:00Z');

  console.log('Cap table seeded: 2 pools, 4 shareholders, 4 events');
}

seedCapTable();

console.log('Seeding complete!');

seed();

