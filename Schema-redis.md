# Schema-redis.md — DB Performance Tuning

**Strategy:** SQLite (development) → PostgreSQL (production)

## Architecture

| Environment | Database | Purpose |
|-------------|----------|---------|
| Development | SQLite | Single-file, zero-config, fast iteration |
| Production | PostgreSQL | ACID, concurrency, JSONB, scaling |
| Testing | SQLite (in-memory) | Fast test runs, no persistence |

## Abstraction Layer

**Knex.js** — query builder that generates dialect-specific SQL from the same code.

- Migration files are dialect-agnostic
- Code uses Knex query builder (no raw SQL needed)
- Switch environments via `NODE_ENV`

## Files

- `src/schema.sql` — Postgres schema (reference)
- `src/migrations/20260827000000_initial_schema.js` — Knex migration (dialect-agnostic)
- `src/db.js` — Knex connection instance
- `knexfile.js` — Environment-specific config

## Performance Tuning Topics

### SQLite (Dev)
- WAL mode for concurrent reads
- Indexing strategy
- Query optimization

### PostgreSQL (Prod)
- Connection pooling (via Knex pool config)
- JSONB indexing for scan results
- Partitioning audit_logs by timestamp
- Query plan analysis (EXPLAIN ANALYZE)

### Redis (Future)
- Session cache (reduce DB hits)
- Scan queue (currently in-memory)
- Rate limiting
- Real-time pub/sub (replaces SSE polling)

## Next Steps

1. Install dependencies: `knex`, `better-sqlite3`, `pg`
2. Run migrations: `npm run migrate`
3. Refactor `server.js` to use `db.js` instead of `loadUsers/saveUsers`
4. Test both SQLite and PostgreSQL
5. Performance baseline (query times, concurrent connections)

---

Entry point for DB performance tuning.
