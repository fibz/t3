// src/db.js — Database connection layer using Knex
// Abstracts SQLite (dev) vs PostgreSQL (prod)
//
// Usage:
//   const db = require('./db');
//   const users = await db('users').select('*');

require('dotenv').config();

const knex = require('knex');
const config = require('../knexfile');

const env = process.env.NODE_ENV || 'development';
const db = knex(config[env]);

// Helper: JSON storage — serialize for insert, parse for select
// SQLite stores JSON as TEXT; Postgres can use JSONB natively
const isJsonNative = () => env === 'production'; // pg supports JSONB

function jsonCol(value) {
  return isJsonNative() ? value : JSON.stringify(value);
}

function jsonParse(row, field) {
  if (!row || !row[field]) return row;
  if (typeof row[field] === 'string') {
    try { row[field] = JSON.parse(row[field]); } catch (_) {}
  }
  return row;
}

module.exports = Object.assign(db, {
  jsonCol,
  jsonParse,
  env,
  isJsonNative,
});
