# Schema TODO — Deferred Items

**Checkpoint:** `schema` (commit 68758d6, 2026-08-27)
**Status:** Core schema complete. Items below to return to later.

## Completed

- ✅ Postgres-compatible schema (7 tables)
- ✅ Knex abstraction (SQLite dev / Postgres prod)
- ✅ Migration file (dialect-agnostic)
- ✅ `Schema-redis.md` entry point
- ✅ Audit log retention locked at 7 years
- ✅ All MFA/security decisions documented

## Pending (Return To)

### Migration & Data
- [ ] JSON → SQLite/Postgres migration script (users.json, scans.json, scheduled-scans.json)
- [ ] Seed script for dev data
- [ ] Verify migration round-trip (JSON → DB → JSON export?)

### Code Refactor
- [ ] Replace `loadUsers/saveUsers` with Knex queries in `server.js`
- [ ] Replace `loadScans/saveScans` with Knex queries
- [ ] Replace `loadScheduled/saveScheduled` with Knex queries
- [ ] Refactor `server.js` into modules:
  - `src/db.js` — already stubbed, needs implementation
  - `src/auth.js` — login, MFA gate, session middleware
  - `src/scan-queue.js` — queue + runScan logic
  - `src/scheduler.js` — cron matching + dispatch
  - `src/views/` — one file per page renderer

### DB Performance
- [ ] JSONB GIN indexes for `scans.results` (if we keep it) or removed if all results go to S3
- [x] Partition `audit_logs` by year → quarter (7-year retention) — LOCKED (decision #11)
- [x] Hot data: current + previous quarter only (~6 months) — LOCKED
- [x] Cold archive: quarterly partitions to S3 as JSON — LOCKED
- [x] Restore SLA: 30 days (PCI written notice) — LOCKED
- [ ] Cron job for automated quarterly archive (end of each quarter)
- [ ] Restore procedure documentation (admin pulls S3 partition → Postgres → query)
- [ ] Connection pool tuning for production load
- [ ] Slow query log setup
- [ ] Backup/pg_dump schedule

### DB Design Decisions (Deferred)
- [ ] Scan results: keep in `scans` JSONB or separate `scan_results` table?
- [ ] Multi-instance support (concurrent scan limits in DB)?
- [ ] Enums vs strings for `role`, `status` fields — Postgres enums faster but harder to migrate; strings more flexible
- [x] Soft deletes vs hard deletes → **LOCKED: No deletes, records marked inactive only** (decision #12)
- [x] Blob storage → **LOCKED: AWS S3** (decision #10)
- [x] Audit log retention → **LOCKED: Postgres partitioned year→quarter, 7yr, hot=2Q, cold=S3** (decision #11)

### File Storage (LOCKED)
- [x] Recovery evidence + scan results → **AWS S3**
- [x] DB stores S3 keys only (references), not blobs
- [ ] S3 bucket naming scheme (e.g., `t3-portal-{env}-results`, `t3-portal-{env}-evidence`)
- [ ] S3 lifecycle rules (archive to Glacier after X years, delete at 7 years)
- [ ] S3 access policy (presigned URLs vs public-read with auth layer?)
- [ ] S3 SDK integration (`@aws-sdk/client-s3` for Node.js)
- [ ] kilo-asv MinIO ↔ portal S3 data handoff (do scan results live in both?)
- [ ] Soft deletes vs hard deletes?
- [ ] Multi-instance support (concurrent scan limits in DB)?

### Redis (Future)
- [ ] Session cache (reduce DB hits)
- [ ] Scan queue (currently in-memory)
- [ ] Rate limiting
- [ ] Real-time pub/sub (replaces SSE polling)
