# CLAUDE.md — T3MP3ST Portal Context for Agents

## Project Overview
Self-hosted red-team scanner web UI. Express.js single-process backend, multi-page server-rendered HTML (no SPA), file-based JSON persistence. Built from T3MP3ST's scanner arsenal.

## Key Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| No database | Simple deployment, JSON files suffice for single-instance |
| SSE not WebSockets | Simpler, works over HTTP/1.1, auto-reconnect, no extra deps |
| Server-rendered HTML | No build step, works without JS, easy to modify |
| Session cookies (express-session) | No JWT complexity, HttpOnly secure by default |
| Cron parser custom | Zero deps, 5-field standard cron, supports `*/n`, ranges, commas |
| Concurrency limit (2) | Prevents resource exhaustion on scan-heavy targets |

## File Map

```
src/server.js       # Main app: routes, auth, scan queue, scheduler, renderers
src/scanners.js     # 8 scanner implementations (pure Node + optional nmap/whois)
public/style.css    # Complete theming, responsive, print styles
data/users.json     # User accounts with roles, serverIp
data/scans.json     # Scan history + results
data/scheduled-scans.json  # Per-user cron jobs
ecosystem.config.js # PM2 production config
```

## Critical Functions (server.js)

- `cronMatches(cron, date)` — cron parser, used by scheduler
- `processQueue()` — pulls waiting jobs up to `MAX_CONCURRENT_SCANS`
- `runScan(id, host, username, scheduledScanId)` — executes 8 modules sequentially, emits SSE progress
- `emitProgress(id, step, status)` — updates in-memory Map + pushes to SSE clients
- `loadUsers/saveUsers`, `loadScans/saveScans`, `loadScheduled/saveScheduled` — file I/O
- `render*` functions — server-side HTML templates (all in server.js)

## Auth Model

- Login: `username` + `password` + `company` (company becomes default scan target)
- Session: `{ username, company, email, serverIp, role }`
- Roles: `admin` (full access) / `operator` (own scans + scheduled only)
- First registered user → `admin` (open mode)
- Registration disabled once users exist

## Scanner Modules (scanners.js)

All async, return plain objects. Errors caught per-module, scan continues.
- `dnsLookup(domain, type)` — uses `dns.promises`
- `subdomainEnum(domain)` — parallel `dns.resolve` on 50 common subs
- `portScan(host, ports)` — parallel `net.Socket` connects
- `headerAnalysis(url)` — `fetch` HEAD, checks 6 security headers
- `sslScan(host, port)` — `tls.connect`, parses peer certificate
- `robotsTxtFetch(url)` — `fetch /robots.txt`
- `whoisLookup(domain)` — `execFile('whois', [domain])`
- `nmapScan(target)` — `execFile('nmap', ['-Pn', '-sT', '--top-ports', '100', target])`

## Scheduled Scan Flow

1. Background `setInterval` (60s) calls `cronMatches()` on each enabled scheduled scan
2. Match → push to `scanQueue` with `status: 'waiting'`, create scan record `status: 'queued'`
3. `processQueue()` starts up to 2 jobs, calls `runScan()` with `scheduledScanId`
4. On completion: `runScan` updates `scheduledScan.lastRun = Date.now()`

## Adding a Scanner Module

1. Add function to `scanners.js`, export
2. Add step name to `SCAN_STEPS` array in `server.js`
3. Add `emitProgress + await` call in `runScan()`
4. Add case to `moduleSummary()` for results dashboard summary

## Common Tasks for Agents

### "Add a new scanner"
- Edit `scanners.js` + `server.js` (see above)

### "Change theming"
- Edit `public/style.css` — CSS custom properties at `:root` and `[data-theme="light"]`

### "Add admin-only feature"
- Add route with `requireAuth, requireAdmin` middleware
- Add link/button in `renderAdmin()` or `renderDashboard()` for admins

### "Modify cron parser"
- Edit `cronMatches()` — supports `*`, `*/n`, `a-b`, `a,b,c` per field

### "Scale to multiple instances"
- Replace file I/O with Redis/shared DB
- Replace in-memory `progress` Map + `sseClients` Map with Redis pub/sub
- Session store → `connect-redis`

## Testing Commands

```bash
cd portal
node -e "require('./src/server.js')"  # syntax check
npm run dev                           # manual test on :8080
# Automated test (from project root):
node test-comprehensive.js            # if exists
```

## Known Limitations

- No rate limiting on login/scan endpoints
- File writes not atomic (rare corruption risk under heavy concurrent writes)
- SSE clients not cleaned up on server restart (clients reconnect automatically)
- nmap/whois optional — graceful degradation if binaries missing
- No email/password reset for users (admin-only reset)

## Credentials for Testing

After first registration (open mode):
- Admin: whatever you registered
- Password: whatever you set
- Company: becomes default scan target

To pre-seed: `node seed-user.js` (creates `admin`/`admin` if users.json empty)