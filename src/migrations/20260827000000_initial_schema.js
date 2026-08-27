// src/migrations/20260827000000_initial_schema.js
// Knex migration — dialect-agnostic (SQLite + PostgreSQL)
// Run: knex migrate:latest

exports.up = function(knex) {
  // Users table
  return knex.schema.createTable('users', (table) => {
    table.increments('id').primary();
    table.string('username', 255).unique().notNullable();
    table.string('password_hash', 255).notNullable();
    table.string('email', 255);
    table.string('company', 255);
    table.string('server_ip', 45);
    table.string('role', 50).defaultTo('operator');
    table.boolean('enabled').defaultTo(true);
    table.boolean('mfa_enabled').defaultTo(true);
    table.string('mfa_secret', 64);
    table.bigInteger('mfa_setup_at');
    table.bigInteger('created_at').notNullable();
    table.bigInteger('last_login_at');
    
    table.index('username');
    table.index('email');
    table.index('role');
  })

  // Sessions table
  .then(() => knex.schema.createTable('sessions', (table) => {
    table.increments('id').primary();
    table.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.string('session_token', 255).unique().notNullable();
    table.bigInteger('created_at').notNullable();
    table.bigInteger('expires_at').notNullable();
    table.bigInteger('mfa_verified_at');
    table.boolean('active').defaultTo(true);
    
    table.index('session_token');
    table.index('user_id');
    table.index('active');
  }))

  // MFA pending challenges
  .then(() => knex.schema.createTable('mfa_pending', (table) => {
    table.increments('id').primary();
    table.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.string('challenge_token', 255).unique().notNullable();
    table.bigInteger('created_at').notNullable();
    table.bigInteger('expires_at').notNullable();
    table.bigInteger('consumed_at');
    table.string('status', 20).defaultTo('pending');
    
    table.index('challenge_token');
    table.index('status');
    table.index('user_id');
  }))

  // Scans
  .then(() => knex.schema.createTable('scans', (table) => {
    table.string('id', 36).primary();
    table.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.string('company', 255);
    table.string('target', 255).notNullable();
    table.bigInteger('started_at').notNullable();
    table.bigInteger('finished_at');
    table.string('status', 20).defaultTo('queued');
    table.json('results');
    table.string('scheduled_scan_id', 36);
    
    table.index('user_id');
    table.index('status');
    table.index('scheduled_scan_id');
    table.index('started_at');
  }))

  // Scheduled scans
  .then(() => knex.schema.createTable('scheduled_scans', (table) => {
    table.string('id', 36).primary();
    table.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.string('target', 255).notNullable();
    table.string('company', 255);
    table.string('cron', 50).notNullable();
    table.boolean('enabled').defaultTo(true);
    table.bigInteger('created_at').notNullable();
    table.bigInteger('last_run');
    
    table.index('user_id');
    table.index('enabled');
  }))

  // Recovery requests
  .then(() => knex.schema.createTable('recovery_requests', (table) => {
    table.string('id', 36).primary();
    table.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.string('status', 20).defaultTo('pending');
    table.text('evidence_path');
    table.integer('verified_by').references('id').inTable('users').onDelete('SET NULL');
    table.bigInteger('verified_at');
    table.text('rejection_reason');
    table.text('notes');
    table.bigInteger('created_at').notNullable();
    
    table.index('user_id');
    table.index('status');
    table.index('created_at');
  }))

  // Audit logs
  .then(() => knex.schema.createTable('audit_logs', (table) => {
    table.increments('id').primary();
    table.integer('user_id').references('id').inTable('users').onDelete('SET NULL');
    table.integer('session_id').references('id').inTable('sessions').onDelete('SET NULL');
    table.string('action', 100).notNullable();
    table.bigInteger('timestamp').notNullable();
    table.string('ip', 45);
    table.text('user_agent');
    table.json('metadata');
    
    table.index('user_id');
    table.index('action');
    table.index('timestamp');
  }));
};

exports.down = function(knex) {
  return knex.schema
    .dropTableIfExists('audit_logs')
    .dropTableIfExists('recovery_requests')
    .dropTableIfExists('scheduled_scans')
    .dropTableIfExists('scans')
    .dropTableIfExists('mfa_pending')
    .dropTableIfExists('sessions')
    .dropTableIfExists('users');
};
