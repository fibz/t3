# T3MP3ST Portal — Session Notes (2026-08-26)

## Quick Facts
- **URL**: http://localhost:8888
- **Admin creds**: `admin` / `123`
- **Stack**: Express + PM2 in Docker, `network_mode:host`

## Changes Made Today

### Infrastructure
- Changed port from **8080 → 8888**
  - Updated `docker-compose.yml` (PORT env)
  - Updated `Dockerfile` (EXPOSE)
  - Updated `ecosystem.config.js` (PM2 hardcodes PORT — easy to forget!)

### Login Flow Simplification
- Login form now asks **only for username + password** (company field removed from form)
- Company is still stored in user records, pulled into session from DB
- Registration form still collects company (needed for scan targets)
- Admin password reset to `123` (original unknown)

### Scan Pipeline (src/server.js SCAN_STEPS)
New pipeline order:
```
dns → subdomains → ports → cve → headers → ssl → robots → whois → nmap → owasp
```

### Phase 1: Enhanced Port Scanning
- **Banner grabber** (`checkPortWithBanner`) — connects to open ports, reads banners for SSH/FTP/SMTP/HTTP/MySQL
- **Banner parser** (`parseBanner`) — extracts product + version strings
- **nmap `-sV`** integration — structured XML output parsing for reliable version detection
- **Combined function** `portScanEnhanced()` — banner scan first, then nmap enrichment
- Port results now include: `{ port, open, service, product, version }`

### Phase 2: CVE Lookup Service (src/cve-service.js)
- **NVD API integration** (https://services.nvd.nist.gov)
- Rate-limited to 6s between requests (no API key needed for basic queries)
- **CPE generation**: converts product+version to `cpe:2.3:a:vendor:product:version` format
- **SERVICE_TO_CPE** map: ~30 common services (ssh→openssh, apache→http_server, nginx, iis, mysql, redis, etc.)
- Returns: total CVEs, severity breakdown, sorted by CVSS score (highest first)
- Extracts: description, CVSS score, severity (CRITICAL/HIGH/MEDIUM/LOW), top 5 references

### Phase 3: OWASP Integration (src/owasp-service.js)
- **WSTG v4.2 mapping** — maps CVEs to specific test procedures (WSTG-INPV-*, WSTG-CONF-*, WSTG-CRYP-*, etc.)
- **ASVS v4.0 compliance** — checks 20+ requirement categories with pass/fail per requirement
- **Compliance score**: percentage of passed requirements
- **Special checks**: SSL protocol version, cert expiry, missing security headers
- Output: `{ owaspTestingGuide: {...}, asvsCompliance: {...} }`

### Phase 4: Report UI + PDF
- Smart `moduleSummary()` entries for `cve` and `owasp` (colored severity badges)
- `renderCVESection()` — top 10 CVEs with severity coloring, CVSS scores, descriptions
- `renderOWASPSection()` — ASVS score display (color-coded), WSTG test mapping, failed requirements list
- Severity colors: `#ff4444` CRITICAL, `#ff8800` HIGH, `#cc0` MEDIUM, `#8c0` LOW

## Bug Found
- `runScan()` was defined **twice** in server.js (lines 95 and 392) — second definition overwrites first
- The duplicate at line 392 doesn't handle `scheduledScanId` properly (won't update `lastRun` for scheduled scans)
- **Not yet fixed** — low priority but worth cleaning up

## Known Limitations / Next Steps
- NVD API rate limit is brutal (5 req/30s without key) — consider getting a free API key for faster scans
- CVE matching relies on banner product+version accuracy — nmap sometimes returns generic product names
- OWASP mapping is keyword-based — could miss novel CVE descriptions
- No caching of CVE lookups — same target scanned twice = duplicate API calls
- Exploit-DB integration (from original plan) — still TODO when their site is back up

## Files Modified
- `src/server.js` — pipeline wiring, report rendering, login form, SCAN_STEPS array
- `src/scanners.js` — new `checkPortWithBanner`, `parseBanner`, `portScanEnhanced`, `nmapVersionScan`
- `src/cve-service.js` — **NEW**
- `src/owasp-service.js` — **NEW**
- `docker-compose.yml` — PORT env
- `Dockerfile` — EXPOSE
- `ecosystem.config.js` — PORT
- `data/users.json` — admin password hash reset

## Rebuild Command
```bash
cd /home/cchock/projects/t3/portal
docker compose down
docker compose up -d --build
```
