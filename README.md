# T3MP3ST Portal

Self-hosted scanner web UI built from T3MP3ST's scanner arsenal. Single-process Express backend, multi-page (no SPA), file-based JSON persistence.

## Features

- **8 Scanner Modules**: DNS, Subdomain Enum, Port Scan, Header Analysis, SSL/TLS, robots.txt, WHOIS, Nmap
- **Authentication**: Session cookies, bcrypt passwords, roles (admin/operator)
- **Real-time Progress**: Server-Sent Events (SSE) live updates during scans
- **Scheduling**: Cron-based automated scans with concurrency control (max 2 parallel)
- **Theming**: Dark/light mode with CSS custom properties, persists in localStorage
- **Reports**: Printable/PDF scan reports
- **Approved target gate**: admins set exact FQDN/IP targets per user; the server denies scans and schedules outside that scope
- **JSON persistence**: `users.json`, `scans.json`, and `scheduled-scans.json` are the active persistence path

## Quick Start

```bash
cd portal
npm install
npm run dev        # Development: node src/server.js on :8080
# or
npm start          # Production: PM2 via ecosystem.config.js
```

First visit → `/register` (open mode, first user becomes admin) → `/login` → `/dashboard`

### Approved targets

After recovery or first registration, the administrator must open **Administration** and add each user's exact approved FQDN or IP address before any scan can run. Existing users intentionally start with no approved targets, so they are default-denied until this is completed. The active portal reads and writes only the JSON files under `data/`; the Knex/SQLite files are unfinished migration material and are not part of the running request path.

## Project Structure

```
portal/
├── src/
│   ├── server.js       # Express backend (~800 lines)
│   └── scanners.js     # 8 pure-Node scanner implementations
├── public/
│   └── style.css       # Complete themed stylesheet
├── data/
│   ├── users.json      # {username, passwordHash, email, company, serverIp, role, enabled}
│   ├── scans.json      # Scan history with results
│   └── scheduled-scans.json  # Cron jobs per user
├── ecosystem.config.js # PM2 production config
├── package.json
└── seed-user.js        # Optional: pre-seed admin user
```

## User Flow

1. **Register** — username, password, email, company (default scan target), serverIp (optional)
2. **Login** — username + password + company (company becomes scan target)
3. **Dashboard** — run ad-hoc scans, view history, link to Scheduled
4. **Scan Results** — live SSE progress bar, collapsible module JSON, printable report
5. **Save-IP Prompt** — after scan completes, one-click updates `serverIp` field
6. **Scheduled Scans** — users create cron jobs (e.g., `0 2 * * *` = daily 2am); admin manages all

## Admin Features (`/admin`)

- User management: enable/disable, promote/demote, reset password (shows temp PW once)
- Scheduled scans management: CRUD for any user's cron jobs

## Scheduled Scans

- **Cron format**: `minute hour dayOfMonth month dayOfWeek` (5 fields)
- Examples: `0 2 * * *` (daily 2am), `*/15 * * * *` (every 15 min), `0 9-17 * * 1-5` (business hours weekdays)
- Background checker runs every minute
- Queue respects `MAX_CONCURRENT_SCANS = 2`
- `lastRun` timestamp prevents duplicate runs within same minute

## Scanner Modules (in `src/scanners.js`)

| Module | Description |
|--------|-------------|
| `dnsLookup(domain, type)` | A, AAAA, MX, TXT, NS, CNAME, SOA |
| `subdomainEnum(domain)` | Brute-forces 50 common subdomains |
| `portScan(host, ports)` | TCP connect scan on comma-separated ports |
| `headerAnalysis(url)` | Security headers check (CSP, HSTS, X-Frame, etc.) |
| `sslScan(host, port)` | TLS cert details, expiry, SANs, cipher, protocol |
| `robotsTxtFetch(url)` | Fetches and parses robots.txt |
| `whoisLookup(domain)` | Shells out to `whois` CLI if available |
| `nmapScan(target)` | Shells out to `nmap` (top 100 ports) if installed |

## Data Schemas

**users.json**
```json
{
  "username": "string",
  "passwordHash": "bcrypt",
  "email": "string",
  "company": "string",
  "serverIp": "string",
  "role": "admin|operator",
  "enabled": true
}
```

**scans.json**
```json
{
  "id": "uuid",
  "user": "username",
  "company": "string",
  "target": "host",
  "startedAt": "timestamp",
  "finishedAt": "timestamp",
  "status": "queued|running|done|error",
  "results": { "target": "...", "modules": { "dns": {}, "ports": {}, ... } },
  "scheduledScanId": "uuid|null"
}
```

**scheduled-scans.json**
```json
{
  "id": "uuid",
  "username": "string",
  "target": "host",
  "company": "string",
  "cron": "0 2 * * *",
  "enabled": true,
  "createdAt": "timestamp",
  "lastRun": "timestamp|null"
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP port |
| `HOST` | `127.0.0.1` | Bind address; set explicitly only for a trusted network deployment |
| `SESSION_SECRET` | random 32 bytes | Cookie signing secret |
| `NODE_ENV` | `development` | `production` enables PM2 config |

## Production Deployment

```bash
# Via PM2 (recommended)
npm install -g pm2
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

`ecosystem.config.js` runs `src/server.js` with `NODE_ENV=production`, auto-restart on crash.

## Security Notes

- The backend requires an explicit authorization acknowledgement and exact administrator-approved FQDN/IP target before it queues either an immediate or scheduled scan. Empty scope denies scanning.
- Scheduled scans are re-checked against the current approved target list before execution; an invalidated schedule is disabled rather than run.
- Passwords bcrypt-hashed (cost 10)
- Sessions: HttpOnly, SameSite=Lax, 8-hour maxAge
- Admin-only endpoints guarded by `requireAdmin` middleware
- No email infrastructure — password reset is admin-only (temp PW shown once)

## Extending

- Add scanner modules in `src/scanners.js`, export, then add to `SCAN_STEPS` and `runScan()` in `server.js`
- UI: edit `public/style.css` (CSS custom properties for theming) and renderer functions in `server.js`
- Auth: replace session store with Redis for multi-instance scaling
