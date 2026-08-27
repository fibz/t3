-- T3MP3ST Portal Schema
-- Primary: PostgreSQL (production)
-- Fallback: SQLite (development)
-- 
-- This file uses Postgres syntax. For SQLite dev environment, see src/migrations/ 
-- or use Knex migrations which are dialect-agnostic.
--
-- Security posture: ephemeral sessions, mandatory MFA, no cached credentials,
-- no device trust, no backup codes (recovery via proof-of-person + PDPA).

-- ─────────────────────────────────────────────────────────────────────────────
-- Users — primary credential store + MFA binding
-- mfaSecret: TOTP shared secret (algorithmic verification only).
-- mfaEnabled: hardcoded to true; included for future flexibility but policy = mandatory.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,           -- bcrypt
  email VARCHAR(255),
  company VARCHAR(255),
  server_ip VARCHAR(45),                         -- IPv4/IPv6
  role VARCHAR(50) DEFAULT 'operator',           -- 'admin' | 'operator'
  enabled BOOLEAN DEFAULT true,
  mfa_enabled BOOLEAN DEFAULT true,              -- always true by policy
  mfa_secret VARCHAR(64),                        -- TOTP shared secret (base32)
  mfa_setup_at BIGINT,                           -- epoch ms
  created_at BIGINT NOT NULL,                    -- epoch ms
  last_login_at BIGINT                           -- epoch ms
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- ─────────────────────────────────────────────────────────────────────────────
-- Sessions — ephemeral, one-time per login
-- Token dies with session. No remember-me, no device trust, no caching.
-- mfaVerifiedAt: records when MFA was successfully presented for THIS session.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_token VARCHAR(255) UNIQUE NOT NULL,    -- random, high-entropy
  created_at BIGINT NOT NULL,                    -- epoch ms
  expires_at BIGINT NOT NULL,                    -- epoch ms (configurable, e.g. 8h)
  mfa_verified_at BIGINT,                        -- epoch ms, null until MFA presented
  active BOOLEAN DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(active);

-- ─────────────────────────────────────────────────────────────────────────────
-- MFA pending challenges — time-limited window between password-verified and
-- MFA-verified. Token expires in 30–60 min (configurable). If expired without
-- MFA presented, login is invalidated.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mfa_pending (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  challenge_token VARCHAR(255) UNIQUE NOT NULL,  -- binds password-verified → MFA step
  created_at BIGINT NOT NULL,                    -- epoch ms
  expires_at BIGINT NOT NULL,                    -- epoch ms (30–60 min)
  consumed_at BIGINT,                            -- epoch ms, null until MFA verified
  status VARCHAR(20) DEFAULT 'pending',          -- 'pending' | 'verified' | 'expired'
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mfa_pending_token ON mfa_pending(challenge_token);
CREATE INDEX IF NOT EXISTS idx_mfa_pending_status ON mfa_pending(status);
CREATE INDEX IF NOT EXISTS idx_mfa_pending_user_id ON mfa_pending(user_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- Scans — one row per scan execution
-- results stored as JSONB (Postgres) / TEXT (SQLite fallback)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
  id VARCHAR(36) PRIMARY KEY,                    -- uuid, matches existing code
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  company VARCHAR(255),
  target VARCHAR(255) NOT NULL,
  started_at BIGINT NOT NULL,
  finished_at BIGINT,
  status VARCHAR(20) DEFAULT 'queued',           -- 'queued' | 'running' | 'done' | 'error'
  results JSONB,                                 -- JSON blob (modules output)
  scheduled_scan_id VARCHAR(36)
);

CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_scheduled_scan_id ON scans(scheduled_scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);

-- ─────────────────────────────────────────────────────────────────────────────
-- Scheduled scans — cron-based recurring scan definitions
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scheduled_scans (
  id VARCHAR(36) PRIMARY KEY,                    -- uuid
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target VARCHAR(255) NOT NULL,
  company VARCHAR(255),
  cron VARCHAR(50) NOT NULL,                     -- 5-field cron expression
  enabled BOOLEAN DEFAULT true,
  created_at BIGINT NOT NULL,
  last_run BIGINT
);

CREATE INDEX IF NOT EXISTS idx_scheduled_scans_user_id ON scheduled_scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_scans_enabled ON scheduled_scans(enabled);

-- ─────────────────────────────────────────────────────────────────────────────
-- Recovery requests — proof-of-person workflow
-- User lost authenticator → submit evidence → admin verifies under PDPA rules.
-- No backup codes. This is the ONLY recovery path.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS recovery_requests (
  id VARCHAR(36) PRIMARY KEY,                    -- uuid
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(20) DEFAULT 'pending',          -- 'pending' | 'reviewing' | 'approved' | 'rejected'
  evidence_path TEXT,                            -- path to uploaded evidence (or reference)
  verified_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  verified_at BIGINT,                            -- epoch ms
  rejection_reason TEXT,                         -- if rejected
  notes TEXT,                                    -- internal notes
  created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recovery_requests_user_id ON recovery_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_requests_status ON recovery_requests(status);
CREATE INDEX IF NOT EXISTS idx_recovery_requests_created_at ON recovery_requests(created_at);

-- ─────────────────────────────────────────────────────────────────────────────
-- Audit logs — PDPA compliance trail
-- Every security-relevant action recorded: logins, MFA failures, recovery
-- requests, admin actions, scan launches, etc.
-- metadata is JSONB (Postgres) / TEXT (SQLite fallback) for flexible event-specific data.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,  -- null if action is pre-auth
  session_id INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
  action VARCHAR(100) NOT NULL,                  -- e.g. 'login.success', 'mfa.fail', 'recovery.requested'
  timestamp BIGINT NOT NULL,                     -- epoch ms
  ip VARCHAR(45),                                -- source IP (IPv4/IPv6)
  user_agent TEXT,
  metadata JSONB                                 -- JSON blob, event-specific
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

-- ─────────────────────────────────────────────────────────────────────────────
-- SQLite Fallback Notes
-- ─────────────────────────────────────────────────────────────────────────────
-- If running SQLite for development:
--   SERIAL → INTEGER PRIMARY KEY AUTOINCREMENT
--   BIGINT → INTEGER
--   BOOLEAN → INTEGER (0/1)
--   JSONB → TEXT
--   VARCHAR(n) → TEXT
--   TIMESTAMPTZ → INTEGER (epoch ms)
--
-- Use Knex migrations (see knexfile.js) for dialect-agnostic schema management.
-- ─────────────────────────────────────────────────────────────────────────────
