#!/usr/bin/env node
// scripts/migrate-json-to-db.js
// Migrates data from JSON files (users.json, scans.json, scheduled-scans.json)
// into the SQLite/Postgres database via Knex.
//
// Usage: node scripts/migrate-json-to-db.js
// Safe to re-run — skips records that already exist (by id/username).

require('dotenv').config();
const path = require('path');
const fs = require('fs');
const db = require('../src/db');

const DATA_DIR = path.join(__dirname, '..', 'data');

function loadJson(filename) {
  const filepath = path.join(DATA_DIR, filename);
  if (!fs.existsSync(filepath)) {
    console.log(`  [skip] ${filename} not found`);
    return [];
  }
  const raw = fs.readFileSync(filepath, 'utf8');
  try {
    return JSON.parse(raw);
  } catch (e) {
    console.error(`  [error] Failed to parse ${filename}: ${e.message}`);
    return [];
  }
}

async function migrateUsers() {
  console.log('\n── Users ──');
  const users = loadJson('users.json');
  if (!users.length) return 0;

  let migrated = 0;
  for (const u of users) {
    const existing = await db('users').where({ username: u.username }).first();
    if (existing) {
      console.log(`  [skip] ${u.username} (already exists)`);
      continue;
    }
    await db('users').insert({
      username: u.username,
      password_hash: u.passwordHash,
      email: u.email || null,
      company: u.company || null,
      server_ip: u.serverIp || null,
      role: u.role || 'operator',
      enabled: u.enabled !== undefined ? u.enabled : true,
      mfa_enabled: true,
      mfa_secret: null,
      mfa_setup_at: null,
      created_at: Date.now(),
      last_login_at: null,
    });
    console.log(`  [ok] ${u.username} (${u.role})`);
    migrated++;
  }
  console.log(`  → ${migrated} users migrated`);
  return migrated;
}

async function migrateScans() {
  console.log('\n── Scans ──');
  const scans = loadJson('scans.json');
  if (!scans.length) return 0;

  // Build user_id lookup (by username, since JSON scans reference user by name)
  const users = await db('users').select('id', 'username');
  const userMap = {};
  for (const u of users) userMap[u.username] = u.id;

  let migrated = 0;
  for (const s of scans) {
    const existing = await db('scans').where({ id: s.id }).first();
    if (existing) {
      console.log(`  [skip] scan ${s.id.slice(0, 8)}…`);
      continue;
    }

    const userId = userMap[s.user];
    if (!userId) {
      console.log(`  [warn] scan ${s.id.slice(0, 8)}… — user "${s.user}" not found, skipping`);
      continue;
    }

    await db('scans').insert({
      id: s.id,
      user_id: userId,
      company: s.company || null,
      target: s.target,
      started_at: s.startedAt,
      finished_at: s.finishedAt || null,
      status: s.status || 'done',
      results: JSON.stringify(s.results || {}),
      scheduled_scan_id: s.scheduledScanId || null,
    });
    console.log(`  [ok] scan ${s.id.slice(0, 8)}… → ${s.target} (${s.status})`);
    migrated++;
  }
  console.log(`  → ${migrated} scans migrated`);
  return migrated;
}

async function migrateScheduledScans() {
  console.log('\n── Scheduled Scans ──');
  const scheduled = loadJson('scheduled-scans.json');
  if (!scheduled.length) return 0;

  // Build user_id lookup
  const users = await db('users').select('id', 'username');
  const userMap = {};
  for (const u of users) userMap[u.username] = u.id;

  let migrated = 0;
  for (const ss of scheduled) {
    const existing = await db('scheduled_scans').where({ id: ss.id }).first();
    if (existing) {
      console.log(`  [skip] scheduled ${ss.id.slice(0, 8)}…`);
      continue;
    }

    const userId = userMap[ss.username];
    if (!userId) {
      console.log(`  [warn] scheduled ${ss.id.slice(0, 8)}… — user "${ss.username}" not found, skipping`);
      continue;
    }

    await db('scheduled_scans').insert({
      id: ss.id,
      user_id: userId,
      target: ss.target,
      company: ss.company || null,
      cron: ss.cron,
      enabled: ss.enabled !== undefined ? ss.enabled : true,
      created_at: ss.createdAt,
      last_run: ss.lastRun || null,
    });
    console.log(`  [ok] scheduled ${ss.id.slice(0, 8)}… → ${ss.target} (${ss.cron})`);
    migrated++;
  }
  console.log(`  → ${migrated} scheduled scans migrated`);
  return migrated;
}

async function main() {
  console.log('T3MP3ST Portal — JSON → DB Migration');
  console.log(`Environment: ${db.env}`);
  console.log(`Data dir: ${DATA_DIR}`);

  try {
    const users = await migrateUsers();
    const scans = await migrateScans();
    const scheduled = await migrateScheduledScans();

    console.log('\n── Summary ──');
    console.log(`  Users:           ${users}`);
    console.log(`  Scans:           ${scans}`);
    console.log(`  Scheduled scans: ${scheduled}`);
    console.log('\nDone.');
  } catch (err) {
    console.error('\nMigration failed:', err.message);
    process.exitCode = 1;
  } finally {
    await db.destroy();
  }
}

main();
