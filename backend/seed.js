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
      'INSERT INTO tokens (id, name, key_hash, role, expires_at) VALUES (?, ?, ?, ?, ?)'
    ).run(uuidv4(), 'Super Admin (Auto-generated)', hash, 'super_admin', expiresAt.toISOString());
    console.log('Super admin token created');
    console.log(`SUPER ADMIN KEY: ${superTokenRaw}`);
    console.log('SAVE THIS KEY - IT WILL NOT BE SHOWN AGAIN');
  } else {
    console.log('Super admin token already exists');
  }

  console.log('Database seeded successfully!');
}

seed();
