# MFA & Security Decisions

**Date:** 2026-08-27
**Status:** Locked
**Context:** Post-gold-image (v1.0, commit 8206162) feature design

---

## Core Security Posture

Minimal server-side credential footprint. Every access requires fresh proof of identity. No escape hatches.

| Principle | Implementation |
|-----------|----------------|
| Mandatory MFA | All users must have MFA bound; no opt-out |
| No cached credentials | Nothing persists between sessions |
| No device trust | Fresh MFA challenge every login |
| Ephemeral sessions | Tokens die with session; no remember-me |
| No backup codes | Recovery only via proof-of-person workflow |
| SQLite persistence | Replaces JSON files for queryability + ACID |

---

## Locked Decisions

### 1. Data Layer: SQLite
**Decision:** Migrate from JSON files to SQLite.
**Rationale:** Queryable, ACID-compliant, single-file deployment matches current architecture.

### 2. MFA Policy: Mandatory for All Users
**Decision:** MFA is always on, no admin toggle, no user opt-out.
**Rationale:** Compliance/policy requirement.

### 3. Recovery: Proof-of-Person + PDPA Workflow
**Decision:** No backup codes. User must submit identity evidence; admin verifies under PDPA rules before resetting MFA.
**Rationale:** Legal/compliance. Requires audit trail, evidence storage, retention policy.
**Open:** Exact evidence format, verification SLA, evidence retention period — depends on PDPA research.

### 4. MFA Pending Session Timeout: 30–60 Minutes
**Decision:** Window between password-verified and MFA-verified is configurable (30–60 min), exact value pending compliance research.
**Rationale:** Compliance policy dependent.

### 5. Device Trust: None
**Decision:** No "remember this browser" or persistent tokens tied to devices.
**Rationale:** Fresh authentication every session.

### 6. Cached Credentials: None
**Decision:** No OAuth credential caching, no persistent tokens, no escape hatches.
**Rationale:** Minimal attack surface.

### 7. Backup Codes: Not Stored Server-Side
**Decision:** No backup codes at all. Recovery path is entirely through the proof-of-person workflow.
**Rationale:** Smaller footprint. If user loses authenticator, they go through recovery.

### 8. MFA Secret Usage (Clarification)
**Decision:** TOTP secret is stored server-side only to verify "user owns this authenticator app." Secret is for identification/creation only. Session token is ephemeral, single-use, scoped to this login, dies with session.
**Rationale:** No way to tie MFA verification back to user after session ends (unlinkable).

---

## Schema (6 Tables)

1. `users` — credentials + MFA secret
2. `sessions` — ephemeral login tracking
3. `mfa_pending` — time-limited challenge between password and MFA verification
4. `scans` — scan history + results (migrated from JSON)
5. `scheduled_scans` — cron jobs (migrated from JSON)
6. `recovery_requests` — proof-of-person workflow
7. `audit_logs` — compliance trail

**File:** `src/schema.sql`

---

## Migration Plan (Next Steps)

1. Install `better-sqlite3` (sync, no async overhead, matches current code style)
2. Write migration script: `users.json` + `scans.json` + `scheduled-scans.json` → SQLite
3. Refactor `server.js` to split into modules:
   - `src/db.js` — SQLite connection + query helpers
   - `src/auth.js` — login, MFA gate, session middleware
   - `src/scan-queue.js` — queue + runScan logic
   - `src/scheduler.js` — cron matching + scheduled scan dispatch
   - `src/views/` — one file per page renderer
4. Implement MFA flow:
   - Registration: password → MFA setup (QR code) → verify → session
   - Login: password → mfa_pending challenge → verify → session
   - Recovery: lost authenticator → submit evidence → admin queue → PDPA verify → reset
5. Implement recovery workflow (depends on PDPA research)
6. Add audit logging throughout

---

## Open Questions (Deferred)

- [ ] PDPA research: exact evidence format, SLA, retention period
- [ ] OAuth integration timing (standalone MFA first, or design for OAuth from day one)
- [ ] Recovery evidence storage (local filesystem vs object store)
- [ ] Admin UI for recovery queue
- [ ] Session timeout exact value (30 vs 60 min)

---

## Feature Modules (To Build)

1. MFA (TOTP) — setup, verify, mandatory flow
2. OAuth SSO — Google (or multi-provider), account linking
3. Scan State Machine — queued → running → retry/done/error
4. Email Delivery — SMTP, report templates, delivery queue
5. One-Time Scheduled Scans — "run once at X time"
6. Audit Trail — log all actions, retention, export
7. Security Hardening — CSRF, rate limiting, session rotation
8. Settings/Profile — user self-service (password change, MFA reset request)
9. Report Formats — PDF generation, JSON/CSV export
10. Notifications — scan completion alerts, scheduled scan reminders
