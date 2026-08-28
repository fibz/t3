// src/seeds/01_dev_users.js
// Dev seed: admin + testuser with known passwords
// Run: npx knex seed:run

const bcrypt = require('bcrypt');

exports.seed = async function(knex) {
  const now = Date.now();

  // Clear existing data (dev only)
  await knex('audit_logs').del();
  await knex('recovery_requests').del();
  await knex('scheduled_scans').del();
  await knex('scans').del();
  await knex('mfa_pending').del();
  await knex('sessions').del();
  await knex('users').del();

  // Create users
  const adminHash = await bcrypt.hash('admin123', 10);
  const userHash = await bcrypt.hash('test123', 10);

  await knex('users').insert([
    {
      id: 1,
      username: 'admin',
      password_hash: adminHash,
      email: 'admin@local',
      company: 'Admin Corp',
      server_ip: 'scanme.npm.org',
      role: 'admin',
      enabled: true,
      mfa_enabled: true,
      created_at: now,
    },
    {
      id: 2,
      username: 'operator1',
      password_hash: userHash,
      email: 'operator@local',
      company: 'Test Corp',
      server_ip: 'example.com',
      role: 'operator',
      enabled: true,
      mfa_enabled: true,
      created_at: now,
    },
  ]);

  // Sample scan for admin
  await knex('scans').insert({
    id: 'seed-scan-001',
    user_id: 1,
    company: 'Admin Corp',
    target: 'scanme.npm.org',
    started_at: now - 3600000,
    finished_at: now - 3500000,
    status: 'done',
    results: JSON.stringify({
      dns: { type: 'A', records: ['45.33.32.156'] },
      ports: { host: 'scanme.npm.org', ports: [22, 80] },
    }),
  });

  // Sample scheduled scan
  await knex('scheduled_scans').insert({
    id: 'seed-sched-001',
    user_id: 1,
    target: 'scanme.npm.org',
    company: 'Admin Corp',
    cron: '0 2 * * 1',
    enabled: true,
    created_at: now,
  });
};
