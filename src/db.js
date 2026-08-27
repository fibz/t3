// src/db.js — Database connection layer using Knex
// Abstracts SQLite (dev) vs PostgreSQL (prod)
//
// Usage:
//   const db = require('./db');
//   const users = await db('users').select('*');

const knex = require('knex');
const config = require('../knexfile');

const env = process.env.NODE_ENV || 'development';
const db = knex(config[env]);

module.exports = db;
