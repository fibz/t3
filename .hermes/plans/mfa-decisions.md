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

### 3. MFA Method: Google Authenticator (TOTP)
**Decision:** TOTP via Google Authenticator for Phase 1. Architecture supports future methods.
**Rationale:** Simple, works now, no infrastructure beyond QR generation.
**Future additions:** Passkeys/WebAuthn, hardware tokens (YubiKey), other TOTP apps (Authy, Microsoft Auth).

### 4. Recovery: Proof-of-Person + PDPA Workflow
**Decision:** No backup codes. User must submit identity evidence; admin verifies under PDPA rules before resetting MFA.
**Rationale:** Legal/compliance. Requires audit trail, evidence storage, retention policy.
**Open:** Exact evidence format, verification SLA, evidence retention period — depends on PDPA research.

### 5. MFA Pending Session Timeout: 30–60 Minutes
**Decision:** Window between password-verified and MFA-verified is configurable (30–60 min), exact value pending compliance research.
**Rationale:** Compliance policy dependent.

### 6. Device Trust: None
**Decision:** No "remember this browser" or persistent tokens tied to devices.
**Rationale:** Fresh authentication every session.

### 7. Cached Credentials: None
**Decision:** No OAuth credential caching, no persistent tokens, no escape hatches.
**Rationale:** Minimal attack surface.

### 8. Backup Codes: Not Stored Server-Side
**Decision:** No backup codes at all. Recovery path is entirely through the proof-of-person workflow.
**Rationale:** Smaller footprint. If user loses authenticator, they go through recovery.

### 9. MFA Secret Usage (Clarification)
**Decision:** TOTP secret is stored server-side only to verify "user owns this authenticator app." Secret is for identification/creation only. Session token is ephemeral, single-use, scoped to this login, dies with session.
**Rationale:** No way to tie MFA verification back to user after session ends (unlinkable).

### 10. Blob Storage: AWS S3
**Decision:** AWS S3 for all large blob storage — scan results AND recovery evidence.
**Rationale:** DB stays lean (just references/keys). Separation of concerns. Scales independently.
**Implications:**
- `scans` table: JSONB `results` → `results_s3_key` (reference to S3 object)
- `recovery_requests`: `evidence_path` → `evidence_s3_key`
- DB holds metadata, S3 holds payloads
- 7-year retention policy applies to both (lifecycle rules on S3 bucket)
- kilo-asv already uses MinIO internally; portal uses AWS S3 (separate backend, or same via S3-compatible endpoint)

### 11. Audit Log Retention: Postgres, Partitioned Year → Quarter
**Decision:** Audit logs stay in Postgres (not S3) for queryability. Partitioned by year, sub-partitioned by quarter. 7-year retention.
**Rationale:** Audit logs must be searchable for compliance queries. S3 is poor for ad-hoc queries. Partitioning keeps performance consistent and retention manageable.
**Structure:**
```
audit_logs (parent, partitioned by year)
├── audit_logs_2026 (sub-partitioned by quarter)
│   ├── audit_logs_2026_q1
│   ├── audit_logs_2026_q2
│   ├── audit_logs_2026_q3
│   └── audit_logs_2026_q4
├── audit_logs_2027 ...
└── audit_logs_2032 ...
```
**Lifecycle:**
- Hot data (Postgres): Current quarter + previous quarter (~6 months)
- Cold archive (S3): Full 7 years, quarterly partitions as JSON
- End of each quarter: cron job exports partition older than Q-1 to S3, then drops from Postgres
- Only PCI Council queries old audit data (written notice)
- 30-day SLA to respond with requested data
- Restore process: Admin pulls S3 partition → restores to Postgres → queries → responds to PCI
**Implications:**
- `src/schema.sql` must change `audit_logs` from regular table to `PARTITION BY RANGE` parent
- Needs `pg_partman` or equivalent for auto-creation, OR custom cron + DDL
- S3 cold archive uses same bucket strategy as blob storage (separate bucket or prefix)

### 12. No Hard Deletes — Records Only Marked Inactive
**Decision:** No records are ever deleted from the database. IDs are auto-increment running numbers per policy — gaps from hard deletes would break audit trails.
**Rationale:**
- 7-year retention applies to everything — can't purge anything
- CYA / compliance principle — no records ever disappear
- IDs must remain contiguous running numbers
**Implementation:**
| Action | Implementation |
|--------|---------------|
| "Delete user" | `enabled = false` |
| "Delete scan" | Add `ARCHIVED` status to existing status column |
| "Delete scheduled scan" | `enabled = false` |
| "Delete recovery request" | Terminal status (`closed`/`rejected`) |
**Implications:**
- No `deleted_at` timestamp columns needed anywhere
- `enabled` / `status` columns already exist on most tables
- `scans` and `recovery_requests` may need additional terminal states added to status enums
- Query patterns must filter by `enabled = true` or non-terminal status

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

- [ ] PDPA research: exact evidence format, SLA
- [ ] OAuth integration timing (standalone MFA first, or design for OAuth from day one)
- [ ] Recovery evidence storage (local filesystem vs object store)
- [ ] Admin UI for recovery queue
- [ ] Session timeout exact value (30 vs 60 min)

## Retention Policies (Locked)

| Data | Retention | Rationale |
|------|-----------|-----------|
| Audit logs | **7 years** | PDPA compliance |

## DB Design Gaps (Deferred — to revisit when building)

- Scan results: keep in `scans` JSONB or separate `scan_results` table?
- File storage (recovery evidence): DB `bytea` vs filesystem vs S3/MinIO?
- Audit log archival: partition by year, cold data → object store?
- Soft deletes vs hard deletes?
- Multi-instance support (concurrent scan limits in DB)?
- JSONB GIN indexes for nested queries?
- Connection pool tuning for production?
- Backup/pg_dump schedule?

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
