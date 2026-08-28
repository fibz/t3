// src/db-helpers.js — Database query helpers
// Abstracts JSON file operations → Knex queries
// Handles camelCase ↔ snake_case mapping and username ↔ user_id

const db = require('./db');

// ── Users ────────────────────────────────────────────────────────────────────

async function getUsers() {
  const rows = await db('users').select('*').where({ enabled: true });
  return rows.map(dbRowToUser);
}

async function getUserByUsername(username) {
  const row = await db('users').where({ username }).first();
  return row ? dbRowToUser(row) : null;
}

async function getUserById(id) {
  const row = await db('users').where({ id }).first();
  return row ? dbRowToUser(row) : null;
}

async function createUser(userData) {
  const now = Date.now();
  const [id] = await db('users').insert({
    username: userData.username,
    password_hash: userData.passwordHash,
    email: userData.email || null,
    company: userData.company || null,
    server_ip: userData.serverIp || null,
    role: userData.role || 'operator',
    enabled: userData.enabled !== undefined ? userData.enabled : true,
    mfa_enabled: true,
    created_at: now,
  });
  return { ...userData, id, createdAt: now };
}

async function updateUser(username, updates) {
  const dbUpdates = {};
  if (updates.passwordHash !== undefined) dbUpdates.password_hash = updates.passwordHash;
  if (updates.email !== undefined) dbUpdates.email = updates.email;
  if (updates.company !== undefined) dbUpdates.company = updates.company;
  if (updates.serverIp !== undefined) dbUpdates.server_ip = updates.serverIp;
  if (updates.role !== undefined) dbUpdates.role = updates.role;
  if (updates.enabled !== undefined) dbUpdates.enabled = updates.enabled;
  if (updates.mfaSecret !== undefined) dbUpdates.mfa_secret = updates.mfaSecret;
  if (updates.mfaSetupAt !== undefined) dbUpdates.mfa_setup_at = updates.mfaSetupAt;
  if (updates.lastLoginAt !== undefined) dbUpdates.last_login_at = updates.lastLoginAt;
  
  await db('users').where({ username }).update(dbUpdates);
}

async function getUserCount() {
  const result = await db('users').count('* as count').first();
  return parseInt(result.count, 10);
}

// ── Scans ────────────────────────────────────────────────────────────────────

async function getScans() {
  const rows = await db('scans').select('scans.*', 'users.username')
    .leftJoin('users', 'scans.user_id', 'users.id')
    .orderBy('scans.started_at', 'desc');
  return rows.map(dbRowToScan);
}

async function getScansByUsername(username) {
  const rows = await db('scans').select('scans.*', 'users.username')
    .leftJoin('users', 'scans.user_id', 'users.id')
    .where('users.username', username)
    .orderBy('scans.started_at', 'desc');
  return rows.map(dbRowToScan);
}

async function getScanById(id) {
  const row = await db('scans').select('scans.*', 'users.username')
    .leftJoin('users', 'scans.user_id', 'users.id')
    .where('scans.id', id)
    .first();
  return row ? dbRowToScan(row) : null;
}

async function createScan(scanData) {
  const user = await getUserByUsername(scanData.user);
  if (!user) throw new Error(`User ${scanData.user} not found`);
  
  await db('scans').insert({
    id: scanData.id,
    user_id: user.id,
    company: scanData.company || null,
    target: scanData.target,
    started_at: scanData.startedAt,
    finished_at: scanData.finishedAt || null,
    status: scanData.status || 'queued',
    results: JSON.stringify(scanData.results || {}),
    scheduled_scan_id: scanData.scheduledScanId || null,
  });
}

async function updateScan(id, updates) {
  const dbUpdates = {};
  if (updates.status !== undefined) dbUpdates.status = updates.status;
  if (updates.results !== undefined) dbUpdates.results = JSON.stringify(updates.results);
  if (updates.finishedAt !== undefined) dbUpdates.finished_at = updates.finishedAt;
  
  await db('scans').where({ id }).update(dbUpdates);
}

// ── Scheduled Scans ──────────────────────────────────────────────────────────

async function getScheduledScans() {
  const rows = await db('scheduled_scans').select('scheduled_scans.*', 'users.username')
    .leftJoin('users', 'scheduled_scans.user_id', 'users.id')
    .orderBy('scheduled_scans.created_at', 'desc');
  return rows.map(dbRowToScheduled);
}

async function getScheduledScansByUsername(username) {
  const rows = await db('scheduled_scans').select('scheduled_scans.*', 'users.username')
    .leftJoin('users', 'scheduled_scans.user_id', 'users.id')
    .where('users.username', username)
    .orderBy('scheduled_scans.created_at', 'desc');
  return rows.map(dbRowToScheduled);
}

async function getScheduledScanById(id) {
  const row = await db('scheduled_scans').select('scheduled_scans.*', 'users.username')
    .leftJoin('users', 'scheduled_scans.user_id', 'users.id')
    .where('scheduled_scans.id', id)
    .first();
  return row ? dbRowToScheduled(row) : null;
}

async function createScheduledScan(scanData) {
  const user = await getUserByUsername(scanData.username);
  if (!user) throw new Error(`User ${scanData.username} not found`);
  
  await db('scheduled_scans').insert({
    id: scanData.id,
    user_id: user.id,
    target: scanData.target,
    company: scanData.company || null,
    cron: scanData.cron,
    enabled: scanData.enabled !== undefined ? scanData.enabled : true,
    created_at: scanData.createdAt,
    last_run: scanData.lastRun || null,
  });
}

async function updateScheduledScan(id, updates) {
  const dbUpdates = {};
  if (updates.enabled !== undefined) dbUpdates.enabled = updates.enabled;
  if (updates.lastRun !== undefined) dbUpdates.last_run = updates.lastRun;
  
  await db('scheduled_scans').where({ id }).update(dbUpdates);
}

async function deleteScheduledScan(id) {
  await db('scheduled_scans').where({ id }).delete();
}

// ── Row mappers ──────────────────────────────────────────────────────────────

function dbRowToUser(row) {
  return {
    id: row.id,
    username: row.username,
    passwordHash: row.password_hash,
    email: row.email,
    company: row.company,
    serverIp: row.server_ip,
    role: row.role,
    enabled: row.enabled,
    mfaEnabled: row.mfa_enabled,
    mfaSecret: row.mfa_secret,
    mfaSetupAt: row.mfa_setup_at,
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at,
  };
}

function dbRowToScan(row) {
  let results = row.results;
  if (typeof results === 'string') {
    try { results = JSON.parse(results); } catch (_) {}
  }
  return {
    id: row.id,
    user: row.username, // Map back to username for compatibility
    company: row.company,
    target: row.target,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
    status: row.status,
    results: results,
    scheduledScanId: row.scheduled_scan_id,
  };
}

function dbRowToScheduled(row) {
  return {
    id: row.id,
    username: row.username, // Map back to username for compatibility
    target: row.target,
    company: row.company,
    cron: row.cron,
    enabled: row.enabled,
    createdAt: row.created_at,
    lastRun: row.last_run,
  };
}

module.exports = {
  // Users
  getUsers,
  getUserByUsername,
  getUserById,
  createUser,
  updateUser,
  getUserCount,
  
  // Scans
  getScans,
  getScansByUsername,
  getScanById,
  createScan,
  updateScan,
  
  // Scheduled
  getScheduledScans,
  getScheduledScansByUsername,
  getScheduledScanById,
  createScheduledScan,
  updateScheduledScan,
  deleteScheduledScan,
};
