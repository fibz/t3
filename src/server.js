// T3MP3ST Portal — single-process Express backend, multi-page (no SPA).
// Login: username + password + company. Company becomes the scan target.
// Auth: local bcrypt users with roles (admin/operator), session cookies.
// No scope gate — scanner runs whatever target is supplied (by design).

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const scanners = require('./scanners');
const cveService = require('./cve-service');
const owaspService = require('./owasp-service');

const PORT = process.env.PORT || 8080;
const DATA = path.join(__dirname, '..', 'data');
const PUBLIC = path.join(__dirname, '..', 'public');
const USERS_FILE = path.join(DATA, 'users.json');
const SCANS_FILE = path.join(DATA, 'scans.json');
const SCHEDULED_FILE = path.join(DATA, 'scheduled-scans.json');

// In-memory progress tracker for live SSE updates (keyed by scan id).
const progress = new Map();
// Map of connected SSE clients: scanId -> Set(res)
const sseClients = new Map();

function loadUsers() { try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { return []; } }
function saveUsers(u) { fs.writeFileSync(USERS_FILE, JSON.stringify(u, null, 2)); }
function loadScans() { try { return JSON.parse(fs.readFileSync(SCANS_FILE, 'utf8')); } catch { return []; } }
function saveScans(s) { fs.writeFileSync(SCANS_FILE, JSON.stringify(s, null, 2)); }
function loadScheduled() { try { return JSON.parse(fs.readFileSync(SCHEDULED_FILE, 'utf8')); } catch { return []; } }
function saveScheduled(s) { fs.writeFileSync(SCHEDULED_FILE, JSON.stringify(s, null, 2)); }
function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
// Generate a temporary password for admin-initiated resets.
function genTempPassword() { return crypto.randomBytes(6).toString('hex'); }

const SCAN_STEPS = ['dns', 'subdomains', 'ports', 'cve', 'headers', 'ssl', 'robots', 'whois', 'nmap', 'owasp'];

// ── Scheduling constants ──────────────────────────────────────────────────
const MAX_CONCURRENT_SCANS = 2;
const scanQueue = []; // { id, host, user, scheduledScanId, status: 'waiting'|'running'|'done'|'error' }
let runningCount = 0;

function cronMatches(cron, date = new Date()) {
  // cron: "minute hour dayOfMonth month dayOfWeek" (5 fields, standard cron)
  // Supports: *, */n, comma-separated, ranges a-b
  const parts = cron.trim().split(/\s+/);
  if (parts.length !== 5) return false;
  const [min, hour, dom, month, dow] = parts;
  const d = date;
  const vals = {
    min: d.getMinutes(),
    hour: d.getHours(),
    dom: d.getDate(),
    month: d.getMonth() + 1,
    dow: d.getDay(), // 0=Sun..6=Sat
  };
  function match(field, val) {
    if (field === '*') return true;
    if (field.includes('/')) {
      const [, step] = field.split('/');
      return val % parseInt(step, 10) === 0;
    }
    if (field.includes(',')) return field.split(',').map(Number).includes(val);
    if (field.includes('-')) {
      const [a, b] = field.split('-').map(Number);
      return val >= a && val <= b;
    }
    return parseInt(field, 10) === val;
  }
  return match(min, vals.min) && match(hour, vals.hour) && match(dom, vals.dom) && match(month, vals.month) && match(dow, vals.dow);
}

function emitProgress(id, step, status) {
  const rec = progress.get(id) || {};
  rec[step] = status;
  progress.set(id, rec);
  const clients = sseClients.get(id);
  if (clients) {
    const payload = `data: ${JSON.stringify({ step, status, progress: rec })}\n\n`;
    clients.forEach(res => res.write(payload));
  }
}

// ── Scan queue processor ───────────────────────────────────────────────────
function processQueue() {
  while (runningCount < MAX_CONCURRENT_SCANS && scanQueue.length > 0) {
    const job = scanQueue.find(j => j.status === 'waiting');
    if (!job) break;
    job.status = 'running';
    runningCount++;
    runScan(job.id, job.host, job.user, job.scheduledScanId);
  }
}

function runScan(id, host, username, scheduledScanId = null) {
  (async () => {
    const out = { target: host, modules: {} };
    try {
      emitProgress(id, 'dns', 'active'); out.modules.dns = await scanners.dnsLookup(host, 'A'); emitProgress(id, 'dns', 'done');
      emitProgress(id, 'subdomains', 'active'); out.modules.subdomains = await scanners.subdomainEnum(host); emitProgress(id, 'subdomains', 'done');
      emitProgress(id, 'ports', 'active'); out.modules.ports = await scanners.portScanEnhanced(host, '21,22,25,53,80,110,143,443,445,8080,8443'); emitProgress(id, 'ports', 'done');
      emitProgress(id, 'cve', 'active');
      try {
        const portData = out.modules.ports.ports || [];
        out.modules.cve = await cveService.lookupCVEs(portData);
        emitProgress(id, 'cve', 'done');
      } catch (e) {
        out.modules.cve = { error: e.message, totalVulnerabilities: 0, vulnerabilities: [], errors: [] };
        emitProgress(id, 'cve', 'error');
      }
      emitProgress(id, 'headers', 'active'); out.modules.headers = await scanners.headerAnalysis(host); emitProgress(id, 'headers', 'done');
      emitProgress(id, 'ssl', 'active'); out.modules.ssl = await scanners.sslScan(host, 443); emitProgress(id, 'ssl', 'done');
      emitProgress(id, 'robots', 'active'); out.modules.robots = await scanners.robotsTxtFetch(host); emitProgress(id, 'robots', 'done');
      try { emitProgress(id, 'whois', 'active'); out.modules.whois = await scanners.whoisLookup(host); emitProgress(id, 'whois', out.modules.whois.error ? 'error' : 'done'); } catch (e) { out.modules.whois = { error: e.message }; emitProgress(id, 'whois', 'error'); }
      try { emitProgress(id, 'nmap', 'active'); out.modules.nmap = await scanners.nmapScan(host); emitProgress(id, 'nmap', out.modules.nmap.error ? 'error' : 'done'); } catch (e) { out.modules.nmap = { error: e.message }; emitProgress(id, 'nmap', 'error'); }
      
      // Generate OWASP compliance report
      emitProgress(id, 'owasp', 'active');
      try {
        const scanData = {
          cve: out.modules.cve,
          headers: out.modules.headers,
          ssl: out.modules.ssl
        };
        out.modules.owasp = owaspService.generateOWASPReport(scanData);
        emitProgress(id, 'owasp', 'done');
      } catch (e) {
        out.modules.owasp = { error: e.message };
        emitProgress(id, 'owasp', 'error');
      }
    } catch (e) { out.error = e.message; }
    const all = loadScans();
    const r = all.find(x => x.id === id);
    if (r) { r.status = 'done'; r.results = out; r.finishedAt = Date.now(); saveScans(all); }
    emitProgress(id, 'complete', 'done');

    // Update scheduled scan lastRun if this was a scheduled scan
    if (scheduledScanId) {
      const scheduled = loadScheduled();
      const s = scheduled.find(x => x.id === scheduledScanId);
      if (s) { s.lastRun = Date.now(); saveScheduled(scheduled); }
    }

    // Free up slot and process next
    runningCount--;
    const jobIdx = scanQueue.findIndex(j => j.id === id);
    if (jobIdx !== -1) scanQueue.splice(jobIdx, 1);
    processQueue();
  })();
}

// ── Background scheduler (checks every minute) ─────────────────────────────
setInterval(() => {
  const now = new Date();
  const scheduled = loadScheduled();
  scheduled.forEach(s => {
    if (!s.enabled) return;
    if (cronMatches(s.cron, now)) {
      // Check if already run this minute (avoid duplicate runs)
      if (s.lastRun && Math.abs(s.lastRun - now.getTime()) < 60000) return;
      const id = crypto.randomUUID();
      scanQueue.push({ id, host: s.target, user: s.username, scheduledScanId: s.id, status: 'waiting' });
      // Create scan record immediately so user sees it
      const scans = loadScans();
      scans.unshift({ id, user: s.username, company: s.company, target: s.target, startedAt: Date.now(), status: 'queued', results: null, scheduledScanId: s.id });
      saveScans(scans);
    }
  });
  processQueue();
}, 60000); // Check every minute

const app = express();
app.use(express.static(PUBLIC));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 8 },
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'admin') return next();
  return res.status(403).send(renderError('Admin access required'));
}

// ── login (multi-page form POST) ────────────────────────────────────────
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.send(renderLogin(''));
});
app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.send(renderLogin('username and password are required'));
  const users = loadUsers();
  if (users.length > 0) {
    const u = users.find(x => x.username === username && x.enabled !== false);
    if (!u || !(await bcrypt.compare(password, u.passwordHash))) {
      return res.send(renderLogin('invalid credentials'));
    }
    req.session.user = {
      username: u.username,
      company: u.company || '',
      email: u.email,
      serverIp: u.serverIp || '',
      role: u.role || 'operator'
    };
  } else {
    // Open mode: no users exist yet, accept any credentials
    req.session.user = { username, company, email: '', serverIp: '', role: 'operator' };
  }
  res.redirect('/dashboard');
});
app.post('/logout', (req, res) => { req.session.destroy(() => res.redirect('/login')); });

// ── registration ─────────────────────────────────────────────────────────
app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  const users = loadUsers();
  if (users.length > 0) return res.redirect('/login'); // Registration only allowed in open mode
  res.send(renderRegister(''));
});
app.post('/register', async (req, res) => {
  const { username, password, email, company, serverIp } = req.body || {};
  if (!username || !password || !email || !company) {
    return res.send(renderRegister('username, password, email, and company are required'));
  }
  const users = loadUsers();
  if (users.find(u => u.username === username)) {
    return res.send(renderRegister('username already taken'));
  }
  const isFirst = users.length === 0;
  users.push({
    username,
    passwordHash: bcrypt.hashSync(password, 10),
    email,
    company,
    serverIp: serverIp || '',
    role: isFirst ? 'admin' : 'operator',
    enabled: true
  });
  saveUsers(users);
  req.session.user = { username, company, email, serverIp: serverIp || '', role: isFirst ? 'admin' : 'operator' };
  res.redirect('/dashboard');
});

// ── pages ───────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));
app.get('/dashboard', requireAuth, (req, res) => {
  const scans = loadScans().filter(s => s.user === req.session.user.username);
  res.send(renderDashboard(req.session.user, scans));
});
app.get('/scan/:id', requireAuth, (req, res) => {
  const s = loadScans().find(x => x.id === req.params.id && x.user === req.session.user.username);
  if (!s) return res.redirect('/dashboard');
  res.send(renderResults(req.session.user, s));
});

// ── live scan progress over SSE ────────────────────────────────────────
app.get('/scan/:id/stream', requireAuth, (req, res) => {
  const s = loadScans().find(x => x.id === req.params.id && x.user === req.session.user.username);
  if (!s) return res.status(404).end();
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  const id = req.params.id;
  // Send current progress snapshot immediately.
  const snap = progress.get(id);
  if (snap) res.write(`data: ${JSON.stringify({ step: null, status: null, progress: snap })}\n\n`);
  if (s.status === 'done') {
    res.write(`data: ${JSON.stringify({ step: 'complete', status: 'done', progress: progress.get(id) || {} })}\n\n`);
  }
  if (!sseClients.has(id)) sseClients.set(id, new Set());
  sseClients.get(id).add(res);
  req.on('close', () => {
    const clients = sseClients.get(id);
    if (clients) { clients.delete(res); if (clients.size === 0) sseClients.delete(id); }
  });
});

// ── scan API (form POST, then redirect to results) ─────────────────────
app.post('/scan', requireAuth, async (req, res) => {
  const target = (req.body.target || req.session.user.company || '').trim();
  if (!target) return res.redirect('/dashboard');
  const host = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const id = crypto.randomUUID();
  const scans = loadScans();
  scans.unshift({ id, user: req.session.user.username, company: req.session.user.company, target: host, startedAt: Date.now(), status: 'queued', results: null });
  saveScans(scans);
  res.redirect('/scan/' + id);
  scanQueue.push({ id, host, user: req.session.user.username, scheduledScanId: null, status: 'waiting' });
  processQueue();
});

// ── admin dashboard ──────────────────────────────────────────────────────
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  const users = loadUsers();
  res.send(renderAdmin(req.session.user, users));
});
app.post('/admin/:username/toggle', requireAuth, requireAdmin, (req, res) => {
  const users = loadUsers();
  const u = users.find(x => x.username === req.params.username);
  if (!u) return res.redirect('/admin');
  if (u.username === req.session.user.username) return res.redirect('/admin'); // Can't disable self
  u.enabled = !u.enabled;
  saveUsers(users);
  res.redirect('/admin');
});
app.post('/admin/:username/role', requireAuth, requireAdmin, (req, res) => {
  const users = loadUsers();
  const u = users.find(x => x.username === req.params.username);
  if (!u) return res.redirect('/admin');
  if (u.username === req.session.user.username) return res.redirect('/admin'); // Can't change own role
  u.role = u.role === 'admin' ? 'operator' : 'admin';
  saveUsers(users);
  res.redirect('/admin');
});
app.post('/admin/:username/reset-password', requireAuth, requireAdmin, (req, res) => {
  const users = loadUsers();
  const u = users.find(x => x.username === req.params.username);
  if (!u) return res.redirect('/admin');
  const temp = genTempPassword();
  u.passwordHash = bcrypt.hashSync(temp, 10);
  saveUsers(users);
  // Show temp password once via flash - simplified: render admin with temp shown
  res.send(renderAdmin(req.session.user, users, { resetMsg: `Password reset for ${u.username}: ${temp}` }));
});

// ── admin: scheduled scans management ──────────────────────────────────────
app.get('/admin/scheduled', requireAuth, requireAdmin, (req, res) => {
  const scheduled = loadScheduled();
  res.send(renderAdminScheduled(req.session.user, scheduled));
});
app.post('/admin/scheduled', requireAuth, requireAdmin, (req, res) => {
  const { username, target, company, cron, enabled } = req.body || {};
  if (!username || !target || !company || !cron) return res.redirect('/admin/scheduled');
  const users = loadUsers();
  if (!users.find(u => u.username === username)) return res.redirect('/admin/scheduled');
  const id = crypto.randomUUID();
  const scheduled = loadScheduled();
  scheduled.push({ id, username, target, company, cron, enabled: enabled === 'on', createdAt: Date.now(), lastRun: null });
  saveScheduled(scheduled);
  res.redirect('/admin/scheduled');
});
app.post('/admin/scheduled/:id/toggle', requireAuth, requireAdmin, (req, res) => {
  const scheduled = loadScheduled();
  const s = scheduled.find(x => x.id === req.params.id);
  if (s) { s.enabled = !s.enabled; saveScheduled(scheduled); }
  res.redirect('/admin/scheduled');
});
app.post('/admin/scheduled/:id/delete', requireAuth, requireAdmin, (req, res) => {
  let scheduled = loadScheduled();
  scheduled = scheduled.filter(x => x.id !== req.params.id);
  saveScheduled(scheduled);
  res.redirect('/admin/scheduled');
});

// ── user: scheduled scans (per-user) ───────────────────────────────────────
app.get('/scheduled', requireAuth, (req, res) => {
  const scheduled = loadScheduled().filter(s => s.username === req.session.user.username);
  res.send(renderUserScheduled(req.session.user, scheduled));
});
app.post('/scheduled', requireAuth, (req, res) => {
  const { target, company, cron, enabled } = req.body || {};
  if (!target || !company || !cron) return res.redirect('/scheduled');
  const id = crypto.randomUUID();
  const scheduled = loadScheduled();
  scheduled.push({ id, username: req.session.user.username, target, company, cron, enabled: enabled === 'on', createdAt: Date.now(), lastRun: null });
  saveScheduled(scheduled);
  res.redirect('/scheduled');
});
app.post('/scheduled/:id/toggle', requireAuth, (req, res) => {
  const scheduled = loadScheduled();
  const s = scheduled.find(x => x.id === req.params.id && x.username === req.session.user.username);
  if (s) { s.enabled = !s.enabled; saveScheduled(scheduled); }
  res.redirect('/scheduled');
});
app.post('/scheduled/:id/delete', requireAuth, (req, res) => {
  let scheduled = loadScheduled();
  scheduled = scheduled.filter(x => !(x.id === req.params.id && x.username === req.session.user.username));
  saveScheduled(scheduled);
  res.redirect('/scheduled');
});

// ── save scanned target to user's serverIp ───────────────────────────────
app.get('/scan/:id/save-ip', requireAuth, (req, res) => {
  const s = loadScans().find(x => x.id === req.params.id && x.user === req.session.user.username);
  if (!s || s.status !== 'done') return res.redirect('/dashboard');
  res.send(renderSaveIp(req.session.user, s));
});
app.post('/scan/:id/save-ip', requireAuth, (req, res) => {
  const s = loadScans().find(x => x.id === req.params.id && x.user === req.session.user.username);
  if (!s) return res.redirect('/dashboard');
  const { save } = req.body || {};
  if (save === 'yes') {
    const users = loadUsers();
    const u = users.find(x => x.username === req.session.user.username);
    if (u) {
      u.serverIp = s.target;
      saveUsers(users);
      // Update session
      req.session.user.serverIp = s.target;
    }
  }
  res.redirect('/scan/' + req.params.id);
});

function runScan(id, host) {
  (async () => {
    const out = { target: host, modules: {} };
    try {
      emitProgress(id, 'dns', 'active'); out.modules.dns = await scanners.dnsLookup(host, 'A'); emitProgress(id, 'dns', 'done');
      emitProgress(id, 'subdomains', 'active'); out.modules.subdomains = await scanners.subdomainEnum(host); emitProgress(id, 'subdomains', 'done');
      emitProgress(id, 'ports', 'active'); out.modules.ports = await scanners.portScanEnhanced(host, '21,22,25,53,80,110,143,443,445,8080,8443'); emitProgress(id, 'ports', 'done');
      emitProgress(id, 'cve', 'active');
      try {
        const portData = out.modules.ports.ports || [];
        out.modules.cve = await cveService.lookupCVEs(portData);
        emitProgress(id, 'cve', 'done');
      } catch (e) {
        out.modules.cve = { error: e.message, totalVulnerabilities: 0, vulnerabilities: [], errors: [] };
        emitProgress(id, 'cve', 'error');
      }
      emitProgress(id, 'headers', 'active'); out.modules.headers = await scanners.headerAnalysis(host); emitProgress(id, 'headers', 'done');
      emitProgress(id, 'ssl', 'active'); out.modules.ssl = await scanners.sslScan(host, 443); emitProgress(id, 'ssl', 'done');
      emitProgress(id, 'robots', 'active'); out.modules.robots = await scanners.robotsTxtFetch(host); emitProgress(id, 'robots', 'done');
      try { emitProgress(id, 'whois', 'active'); out.modules.whois = await scanners.whoisLookup(host); emitProgress(id, 'whois', out.modules.whois.error ? 'error' : 'done'); } catch (e) { out.modules.whois = { error: e.message }; emitProgress(id, 'whois', 'error'); }
      try { emitProgress(id, 'nmap', 'active'); out.modules.nmap = await scanners.nmapScan(host); emitProgress(id, 'nmap', out.modules.nmap.error ? 'error' : 'done'); } catch (e) { out.modules.nmap = { error: e.message }; emitProgress(id, 'nmap', 'error'); }
      
      // Generate OWASP compliance report
      emitProgress(id, 'owasp', 'active');
      try {
        const scanData = {
          cve: out.modules.cve,
          headers: out.modules.headers,
          ssl: out.modules.ssl
        };
        out.modules.owasp = owaspService.generateOWASPReport(scanData);
        emitProgress(id, 'owasp', 'done');
      } catch (e) {
        out.modules.owasp = { error: e.message };
        emitProgress(id, 'owasp', 'error');
      }
    } catch (e) { out.error = e.message; }
    const all = loadScans();
    const r = all.find(x => x.id === id);
    if (r) { r.status = 'done'; r.results = out; r.finishedAt = Date.now(); saveScans(all); }
    emitProgress(id, 'complete', 'done');
  })();
}

// ── renderers (server-side HTML, external CSS) ──────────────────────────

function renderRegister(err) {
  return shell('Register', `
<main class="auth-shell"><form class="card auth-card" method="POST" action="/register">
  <div class="auth-brand"><span class="brand-mark">T3</span><span><strong>T3MP3ST</strong><small>Security portal</small></span></div>
  <p class="eyebrow">Set up workspace</p><h1>Create your first account</h1><p class="auth-copy">This account will manage your scanning workspace.</p>
  <label for="username">Username</label><input id="username" name="username" autocomplete="username" required/>
  <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="new-password" required/>
  <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="email" required/>
  <label for="company">Company (default scan target)</label><input id="company" name="company" placeholder="e.g. example.com" required/>
  <label for="serverIp">Server IP (optional)</label><input id="serverIp" name="serverIp" placeholder="e.g. 192.168.1.10 or myserver.example.com"/>
  <button type="submit" style="margin-top:18px;width:100%">Create Account</button>
  <div class="error-msg" role="alert">${esc(err || '')}</div>
</form></main>`, { theme: 'dark' });
}

function renderAdmin(user, users, opts = {}) {
  const list = users.map(u => `
    <tr>
      <td><strong>${esc(u.username)}</strong></td>
      <td>${esc(u.email)}</td>
      <td>${esc(u.company || '—')}</td>
      <td>${esc(u.serverIp || '—')}</td>
      <td><span class="pill ${u.role === 'admin' ? 'done' : ''}">${esc(u.role)}</span></td>
      <td><span class="pill ${u.enabled !== false ? 'done' : 'error'}">${u.enabled !== false ? 'enabled' : 'disabled'}</span></td>
      <td>
        <form method="POST" action="/admin/${esc(u.username)}/toggle" style="display:inline"><button class="ghost" type="submit">${u.enabled !== false ? 'Disable' : 'Enable'}</button></form>
        <form method="POST" action="/admin/${esc(u.username)}/role" style="display:inline;margin-left:4px"><button class="ghost" type="submit">${u.role === 'admin' ? 'Demote' : 'Promote'}</button></form>
        <form method="POST" action="/admin/${esc(u.username)}/reset-password" style="display:inline;margin-left:4px"><button class="ghost danger" type="submit">Reset PW</button></form>
      </td>
    </tr>`).join('');
  return shell('Admin Dashboard', `
<header><h1>🌩️ ADMIN</h1>
<div style="display:flex;align-items:center;gap:12px">
  ${themeToggleHtml()}
  <span class="tag">${esc(user.username)} (admin)</span>
  <a class="linkbtn" href="/admin/scheduled">Scheduled Scans</a>
  <a class="linkbtn" href="/dashboard">← Dashboard</a>
  <form method="POST" action="/logout" style="display:inline"><button type="submit" class="secondary">Logout</button></form>
</div></header>
${opts.resetMsg ? `<div class="scan-progress" style="background:rgba(63,185,80,0.15);border-color:var(--ok)"><strong>✓ ${esc(opts.resetMsg)}</strong></div>` : ''}
<table style="width:100%;border-collapse:collapse;margin-top:16px;font-size:13px">
  <thead><tr style="text-align:left;color:var(--muted);border-bottom:1px solid var(--border)">
    <th style="padding:8px">Username</th><th style="padding:8px">Email</th><th style="padding:8px">Company</th><th style="padding:8px">Server IP</th>
    <th style="padding:8px">Role</th><th style="padding:8px">Status</th><th style="padding:8px">Actions</th>
  </tr></thead>
  <tbody>${list}</tbody>
</table>`, { theme: 'dark' });
}

function renderSaveIp(user, s) {
  return shell('Save Target as Server IP', `
<header><h1>🌩️ T3MP3ST PORTAL</h1>
<div style="display:flex;align-items:center;gap:12px">
  ${themeToggleHtml()}
  <span class="tag">${esc(user.username)} @ ${esc(user.company)}</span>
  <form method="POST" action="/logout" style="display:inline"><button type="submit" class="secondary">Logout</button></form>
</div></header>
<div class="card" style="max-width:520px;margin:4vh auto;text-align:center">
  <h2>Save scan target as your Server IP?</h2>
  <p class="tag">The scan for <strong>${esc(s.target)}</strong> completed.</p>
  <p>Your current Server IP: <strong>${esc(user.serverIp || '(none)')}</strong></p>
  <p>Update it to <strong>${esc(s.target)}</strong>?</p>
  <form method="POST" action="/scan/${s.id}/save-ip" style="margin-top:20px;display:flex;gap:12px;justify-content:center">
    <button type="submit" name="save" value="yes" style="min-width:120px">Yes, save</button>
    <button type="submit" name="save" value="no" class="secondary" style="min-width:120px">No, keep current</button>
  </form>
  <p class="tag" style="margin-top:16px"><a class="linkbtn" href="/scan/${s.id}">← Back to results</a></p>
</div>`, { theme: 'dark' });
}

function renderError(msg) {
  return shell('Error', `
<div class="card" style="max-width:400px;margin:8vh auto;text-align:center">
  <h2>Error</h2>
  <p class="tag">${esc(msg)}</p>
  <p><a class="linkbtn" href="/dashboard">← Back to dashboard</a></p>
</div>`, { theme: 'dark' });
}

function renderAdminScheduled(user, scheduled) {
  const list = scheduled.map(s => `
    <tr>
      <td>${esc(s.username)}</td>
      <td>${esc(s.target)}</td>
      <td>${esc(s.company)}</td>
      <td><code>${esc(s.cron)}</code></td>
      <td><span class="pill ${s.enabled ? 'done' : 'error'}">${s.enabled ? 'enabled' : 'disabled'}</span></td>
      <td>${s.lastRun ? new Date(s.lastRun).toLocaleString() : '—'}</td>
      <td>
        <form method="POST" action="/admin/scheduled/${esc(s.id)}/toggle" style="display:inline"><button class="ghost" type="submit">${s.enabled ? 'Disable' : 'Enable'}</button></form>
        <form method="POST" action="/admin/scheduled/${esc(s.id)}/delete" style="display:inline;margin-left:4px"><button class="ghost danger" type="submit">Delete</button></form>
      </td>
    </tr>`).join('');
  return shell('Admin — Scheduled Scans', `
<header><h1>🌩️ ADMIN — SCHEDULED SCANS</h1>
<div style="display:flex;align-items:center;gap:12px">
  ${themeToggleHtml()}
  <span class="tag">${esc(user.username)} (admin)</span>
  <a class="linkbtn" href="/admin">← Users</a>
  <a class="linkbtn" href="/dashboard">Dashboard</a>
  <form method="POST" action="/logout" style="display:inline"><button type="submit" class="secondary">Logout</button></form>
</div></header>
<form class="card" method="POST" action="/admin/scheduled" style="max-width:800px;margin:0 auto 24px">
  <h2>Add Scheduled Scan</h2>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px">
    <label>Username<select name="username" required>${loadUsers().map(u => `<option value="${esc(u.username)}">${esc(u.username)}</option>`).join('')}</select></label>
    <label>Target<input name="target" placeholder="example.com" required/></label>
    <label>Company<input name="company" placeholder="Company Name" required/></label>
    <label>Cron (min hour dom month dow)<input name="cron" placeholder="0 2 * * *" required title="e.g. 0 2 * * * = daily at 2am"/></label>
    <label style="align-self:end"><input type="checkbox" name="enabled" checked/> Enabled</label>
  </div>
  <button type="submit" style="margin-top:12px">Add</button>
</form>
<table style="width:100%;border-collapse:collapse;margin-top:16px;font-size:13px">
  <thead><tr style="text-align:left;color:var(--muted);border-bottom:1px solid var(--border)">
    <th style="padding:8px">User</th><th style="padding:8px">Target</th><th style="padding:8px">Company</th><th style="padding:8px">Cron</th>
    <th style="padding:8px">Status</th><th style="padding:8px">Last Run</th><th style="padding:8px">Actions</th>
  </tr></thead>
  <tbody>${list || '<tr><td colspan="7" style="padding:16px;color:var(--muted);text-align:center">No scheduled scans</td></tr>'}</tbody>
</table>`, { theme: 'dark' });
}

function renderUserScheduled(user, scheduled) {
  const list = scheduled.map(s => `
    <tr>
      <td>${esc(s.target)}</td>
      <td>${esc(s.company)}</td>
      <td><code>${esc(s.cron)}</code></td>
      <td><span class="pill ${s.enabled ? 'done' : 'error'}">${s.enabled ? 'enabled' : 'disabled'}</span></td>
      <td>${s.lastRun ? new Date(s.lastRun).toLocaleString() : '—'}</td>
      <td>
        <form method="POST" action="/scheduled/${esc(s.id)}/toggle" style="display:inline"><button class="ghost" type="submit">${s.enabled ? 'Disable' : 'Enable'}</button></form>
        <form method="POST" action="/scheduled/${esc(s.id)}/delete" style="display:inline;margin-left:4px"><button class="ghost danger" type="submit">Delete</button></form>
      </td>
    </tr>`).join('');
  return shell('Scheduled Scans', `
<header><h1>🌩️ SCHEDULED SCANS</h1>
<div style="display:flex;align-items:center;gap:12px">
  ${themeToggleHtml()}
  <span class="tag">${esc(user.username)} @ ${esc(user.company)}</span>
  <a class="linkbtn" href="/dashboard">← Dashboard</a>
  <form method="POST" action="/logout" style="display:inline"><button type="submit" class="secondary">Logout</button></form>
</div></header>
<form class="card" method="POST" action="/scheduled" style="max-width:800px;margin:0 auto 24px">
  <h2>Add Scheduled Scan</h2>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px">
    <label>Target<input name="target" placeholder="example.com" required/></label>
    <label>Company<input name="company" value="${esc(user.company)}" required/></label>
    <label>Cron (min hour dom month dow)<input name="cron" placeholder="0 2 * * *" required title="e.g. 0 2 * * * = daily at 2am"/></label>
    <label style="align-self:end"><input type="checkbox" name="enabled" checked/> Enabled</label>
  </div>
  <button type="submit" style="margin-top:12px">Add</button>
</form>
<table style="width:100%;border-collapse:collapse;margin-top:16px;font-size:13px">
  <thead><tr style="text-align:left;color:var(--muted);border-bottom:1px solid var(--border)">
    <th style="padding:8px">Target</th><th style="padding:8px">Company</th><th style="padding:8px">Cron</th>
    <th style="padding:8px">Status</th><th style="padding:8px">Last Run</th><th style="padding:8px">Actions</th>
  </tr></thead>
  <tbody>${list || '<tr><td colspan="6" style="padding:16px;color:var(--muted);text-align:center">No scheduled scans</td></tr>'}</tbody>
</table>`, { theme: 'dark' });
}

function themeToggleHtml() {
  return `<button class="theme-toggle" id="themeToggle" aria-label="Toggle theme" type="button">
    <svg class="theme-icon-dark" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 3a9 9 0 1 0 9 9c0-.46-.04-.92-.1-1.36a5.39 5.39 0 0 1-4.4 2.26 5.4 5.4 0 0 1-3.98-9A9 9 0 0 0 12 3z"/></svg>
    <svg class="theme-icon-light" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" style="display:none"><path d="M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10zm0-5v3m0 14v3M4.22 4.22l2.12 2.12m11.32 11.32l2.12 2.12M1 12h3m16 0h3M4.22 19.78l2.12-2.12M17.66 6.34l2.12-2.12" stroke="currentColor" stroke-width="2" stroke-linecap="round" fill="none"/></svg>
    <span class="theme-label">Theme</span>
  </button>`;
}

function shell(title, body, opts = {}) {
  const extraHead = opts.extraHead || '';
  const extraScripts = opts.extraScripts || '';
  return `<!doctype html><html lang="en" data-theme="${esc(opts.theme || 'dark')}"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${esc(title)} · T3MP3ST Portal</title>
<link rel="stylesheet" href="/style.css"/>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🌩️</text></svg>"/>
${extraHead}
<script>
(function(){
  try { var t = localStorage.getItem('theme'); if (t) document.documentElement.setAttribute('data-theme', t); } catch(e){}
})();
</script>
</head><body><div class="wrap">${body}</div>
<script>
(function(){
  var btn = document.getElementById('themeToggle');
  if (btn) {
    btn.addEventListener('click', function(){
      var cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', cur);
      try { localStorage.setItem('theme', cur); } catch(e){}
      updateIcons(cur);
    });
  }
  function updateIcons(theme){
    var dark = document.querySelector('.theme-icon-dark');
    var light = document.querySelector('.theme-icon-light');
    if (dark && light) { dark.style.display = theme === 'light' ? 'none' : 'block'; light.style.display = theme === 'light' ? 'block' : 'none'; }
  }
  var initTheme = document.documentElement.getAttribute('data-theme');
  if (initTheme) updateIcons(initTheme);
})();
</script>
${extraScripts}</body></html>`;
}

function renderLogin(err) {
  return shell('Login', `
<main class="auth-shell"><form class="card auth-card" method="POST" action="/login">
  <div class="auth-brand"><span class="brand-mark">T3</span><span><strong>T3MP3ST</strong><small>Security portal</small></span></div>
  <p class="eyebrow">Welcome back</p><h1>Sign in to your workspace</h1><p class="auth-copy">Your assessment history and live scan activity are ready.</p>
  <label for="username">Username</label><input id="username" name="username" autocomplete="username" required/>
  <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required/>
  <button type="submit" style="margin-top:18px;width:100%">Enter</button>
  <div class="error-msg" role="alert">${esc(err || '')}</div>
</form></main>`, { theme: 'dark' });
}

function renderDashboard(user, scans) {
  const completed = scans.filter(s => s.status === 'done').length;
  const active = scans.filter(s => s.status !== 'done' && s.status !== 'error').length;
  const latest = scans[0];
  const list = scans.length
    ? scans.map(s => {
        const cls = s.status === 'done' ? 'done' : s.status === 'error' ? 'error' : 'running';
        const modules = s.results && s.results.modules ? Object.keys(s.results.modules).length : 0;
        return `<article class="scan-item"><a href="/scan/${s.id}">
          <div class="scan-item-top"><div><strong>${esc(s.target)}</strong><span class="pill ${cls}">${esc(s.status)}</span></div><span class="scan-arrow" aria-hidden="true">→</span></div>
          <div class="scan-item-meta"><span>${new Date(s.startedAt).toLocaleString()}</span><span>${modules ? `${modules} checks complete` : s.status === 'queued' ? 'Waiting to begin' : 'View live progress'}</span></div>
        </a></article>`;
      }).join('')
    : `<div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 21l-6-6m2-5a7 7 0 1 1-14 0 7 7 0 0 1 14 0z"/></svg>
        <p>No scans yet. Run your first scan above.</p>
      </div>`;
  const managementLink = user.role === 'admin' ? '<a class="nav-link" href="/admin">Administration</a>' : '';
  const schedLink = user.role === 'admin' ? '<a class="nav-link" href="/admin/scheduled">Scheduled scans</a>' : '<a class="nav-link" href="/scheduled">Scheduled scans</a>';
  return shell('Dashboard', `
<header class="app-header"><a class="brand" href="/dashboard"><span class="brand-mark">T3</span><span><strong>T3MP3ST</strong><small>Security portal</small></span></a>
<div class="header-actions">
  ${themeToggleHtml()}
  <span class="user-chip"><span class="user-avatar">${esc(user.username.slice(0, 1).toUpperCase())}</span>${esc(user.username)}</span>
  <form method="POST" action="/logout" style="display:inline"><button type="submit" class="secondary">Logout</button></form>
</div></header>
<main>
  <section class="dashboard-hero">
    <div><p class="eyebrow">${esc(user.company || 'Your workspace')}</p><h1>Security, clearly in view.</h1><p class="hero-copy">Launch scans, follow progress, and turn findings into a concise security picture.</p></div>
    <div class="hero-links">${schedLink}${managementLink}${user.serverIp ? `<span class="server-note">Saved target: <strong>${esc(user.serverIp)}</strong></span>` : ''}</div>
  </section>
  <section class="summary-grid" aria-label="Scan overview">
    <div class="summary-card"><span class="summary-label">Total scans</span><strong>${scans.length}</strong><span>in this workspace</span></div>
    <div class="summary-card ${active ? 'is-active' : ''}"><span class="summary-label">In progress</span><strong>${active}</strong><span>${active ? 'Live updates available' : 'Nothing running now'}</span></div>
    <div class="summary-card"><span class="summary-label">Completed</span><strong>${completed}</strong><span>${latest ? `Latest: ${esc(latest.target)}` : 'Ready when you are'}</span></div>
  </section>
  <section class="launch-card"><div><p class="eyebrow">New assessment</p><h2>Run a scan</h2><p>Enter a host or domain to start an on-demand assessment.</p></div>
    <form class="scanbox" method="POST" action="/scan"><input name="target" placeholder="example.com" aria-label="Target host"/><button type="submit">Start scan <span aria-hidden="true">→</span></button></form>
  </section>
  <section class="history-section"><div class="section-heading"><div><p class="eyebrow">History</p><h2>Recent scans</h2></div><span>${scans.length} total</span></div><div class="scan-list">${list}</div></section>
</main>`, { theme: 'dark' });
}

function renderResults(user, s) {
  let body = `<header class="app-header results-header">
  <div>
    <a class="back-link" href="/dashboard">← All scans</a>
    <h1>${esc(s.target)}</h1>
    <div class="tag">${esc(s.company)} · Started ${new Date(s.startedAt).toLocaleString()}</div>
  </div>
  <div class="header-actions">${themeToggleHtml()}<span class="pill ${s.status === 'done' ? 'done' : 'running'}">${esc(s.status)}</span></div>
</header>
<main class="results-page">`;
  // Show save-ip prompt on results page if scan done and target differs from saved serverIp
  if (s.status === 'done' && s.results && user.serverIp !== s.target) {
    body += `<div class="scan-progress" style="background:rgba(210,153,34,0.15);border-color:var(--warn)">
      <strong>Scan complete.</strong> Target <strong>${esc(s.target)}</strong> differs from your saved Server IP (<strong>${esc(user.serverIp || '(none)')}</strong>).
      <a class="linkbtn" href="/scan/${s.id}/save-ip" style="margin-left:12px">Update Server IP →</a>
    </div>`;
  }
  if (s.status !== 'done' || !s.results) {
    // Live progress UI driven by SSE.
    const steps = SCAN_STEPS.map(st => `<div class="scan-step" data-step="${st}">
      <span class="scan-step-icon">○</span><span>${esc(st)}</span>
    </div>`).join('');
    body += `<div class="scan-progress" id="scanProgress">
      <div class="scan-progress-header">
        <span class="scan-progress-title">Scanning ${esc(s.target)}…</span>
        <span class="scan-progress-spinner" aria-hidden="true"></span>
      </div>
      <div class="scan-progress-steps">${steps}</div>
    </div>
    <p class="tag" id="progressHint">Live progress — this page updates automatically.</p>`;
  } else {
    body += renderResultModules(s);
  }
  body += `<div class="results-actions"><a class="report-button" href="/scan/${s.id}/report" target="_blank">Download / print report <span aria-hidden="true">↗</span></a></div></main>`;
  return shell('Results', body, {
    theme: 'dark',
    extraScripts: s.status !== 'done'
      ? `<script>
      (function(){
        var stepsEl = document.getElementById('scanProgress');
        var ev = new EventSource('/scan/${s.id}/stream');
        var ICON = { active: '◔', done: '✓', error: '✕' };
        ev.onmessage = function(e){
          var msg = JSON.parse(e.data);
          if (msg.progress) {
            Object.keys(msg.progress).forEach(function(step){
              var el = document.querySelector('[data-step="'+step+'"]');
              if (!el) return;
              var st = msg.progress[step];
              el.classList.remove('active','done','error');
              el.classList.add(st === 'active' ? 'active' : (st === 'error' ? 'error' : 'done'));
              var ic = el.querySelector('.scan-step-icon');
              if (ic) ic.textContent = ICON[st] || '○';
            });
          }
          if (msg.step === 'complete' && msg.status === 'done') {
            ev.close();
            setTimeout(function(){ window.location.href = '/scan/${s.id}/save-ip'; }, 600);
          }
        };
        ev.onerror = function(){
          fetch('/scan/${s.id}/stream', { method: 'GET' }).catch(function(){});
        };
      })();
      </script>`
      : '',
  });
}

function renderResultModules(s) {
  const mods = (s.results && s.results.modules) ? s.results.modules : {};
  const summaries = Object.entries(mods).map(([k, v]) => `<div class="finding-card"><span>${esc(moduleLabel(k))}</span><strong>${stripTags(moduleSummary(k, v)) || 'Complete'}</strong></div>`).join('');
  let html = `<section class="results-overview"><div><p class="eyebrow">Assessment complete</p><h2>Findings at a glance</h2></div><div class="finding-grid">${summaries}</div></section><section class="results-modules"><div class="section-heading"><div><p class="eyebrow">Detailed findings</p><h2>Assessment results</h2></div><span>${Object.keys(mods).length} checks</span></div>`;
  for (const [k, v] of Object.entries(mods)) {
    const summary = moduleSummary(k, v);
    const json = esc(JSON.stringify(v, null, 2));
    html += `<article class="module-card">
      <button class="module-header" type="button" aria-expanded="true" onclick="var c=this.parentElement.classList.toggle('collapsed');this.setAttribute('aria-expanded', String(!c))">
        <span class="module-title">
          <span class="module-toggle">▾</span>
          <span>${esc(moduleLabel(k))}</span>
        </span>
        <span class="module-summary">${summary}</span>
      </button>
      <div class="module-content">${renderModuleBody(k, v)}<details class="technical-details"><summary>View technical details</summary><pre>${json}</pre></details></div>
    </article>`;
  }
  html += '</section>';
  return html;
}

function moduleLabel(key) { return ({ dns: 'DNS records', subdomains: 'Subdomains', ports: 'Open ports', cve: 'Vulnerability assessment', headers: 'Security headers', ssl: 'TLS certificate', robots: 'Robots.txt', whois: 'WHOIS', nmap: 'Network discovery', owasp: 'OWASP compliance' }[key] || key); }
function stripTags(value) { return String(value || '').replace(/<[^>]*>/g, ''); }
function renderModuleBody(key, value) {
  if (!value) return '<p class="module-empty">No data returned for this check.</p>';
  if (value.error) return `<div class="module-alert error"><strong>This check could not be completed.</strong><span>${esc(value.error)}</span></div>`;
  if (key === 'ports') { const ports = (value.ports || []).filter(p => p.open); return ports.length ? `<div class="chip-list">${ports.map(p => `<span class="data-chip"><strong>${esc(p.port)}</strong> ${esc(p.service || p.protocol || 'open')}</span>`).join('')}</div>` : '<p class="module-empty">No open ports were detected in the scanned range.</p>'; }
  if (key === 'subdomains') { const items = value.subdomains || []; return items.length ? `<div class="chip-list">${items.map(x => `<span class="data-chip">${esc(typeof x === 'string' ? x : x.host || x.subdomain || JSON.stringify(x))}</span>`).join('')}</div>` : '<p class="module-empty">No subdomains were found.</p>'; }
  if (key === 'dns') { const items = value.records || []; return items.length ? `<div class="chip-list">${items.map(x => `<span class="data-chip">${esc(typeof x === 'string' ? x : JSON.stringify(x))}</span>`).join('')}</div>` : '<p class="module-empty">No DNS records were returned.</p>'; }
  if (key === 'headers') { const missing = value.missingSecurityHeaders || []; return missing.length ? `<div class="module-alert warning"><strong>${missing.length} security headers need attention.</strong><div class="chip-list">${missing.map(x => `<span class="data-chip">${esc(x)}</span>`).join('')}</div></div>` : '<div class="module-alert success"><strong>Security header checks passed.</strong><span>No missing headers were reported.</span></div>'; }
  if (key === 'cve') { const sev = value.bySeverity || {}; const total = value.totalVulnerabilities || 0; return `<div class="severity-row"><span><strong>${total}</strong> total</span><span class="severity critical"><strong>${sev.CRITICAL || 0}</strong> critical</span><span class="severity high"><strong>${sev.HIGH || 0}</strong> high</span><span class="severity medium"><strong>${sev.MEDIUM || 0}</strong> medium</span></div>${total ? `<div class="simple-list">${(value.vulnerabilities || []).slice(0, 5).map(v => `<div><strong>${esc(v.cveId || 'Vulnerability')}</strong><span>${esc(v.product || 'Unknown product')}${v.version ? ` · ${esc(v.version)}` : ''}</span></div>`).join('')}</div>` : '<p class="module-empty">No known CVEs were matched to the observed services.</p>'}`; }
  if (key === 'ssl') return `<div class="metric-row"><span><small>Days to expiry</small><strong>${value.daysToExpiry != null ? esc(value.daysToExpiry) : '—'}</strong></span><span><small>Issuer</small><strong>${esc(value.issuer || value.subject || 'Not reported')}</strong></span></div>`;
  if (key === 'owasp') { const asvs = value.asvsCompliance || {}; return `<div class="owasp-score"><strong>${esc(asvs.score != null ? asvs.score : '—')}<small>%</small></strong><span>ASVS compliance score</span><span>${esc(asvs.passed || 0)} of ${esc(asvs.totalRequirements || 0)} requirements passed</span></div>`; }
  return '<p class="module-empty">This check completed. Open technical details for the full response.</p>';
}

function moduleSummary(k, v) {
  if (!v) return '';
  if (v.error) return `<span style="color:var(--bad)">error</span>`;
  if (v.skipped) return `<span style="color:var(--muted)">skipped</span>`;
  switch (k) {
    case 'ports': {
      const open = (v.ports || []).filter(p => p.open);
      return `<span>${open.length} open</span>`;
    }
    case 'subdomains': {
      return `<span>${(v.subdomains || []).length} found</span>`;
    }
    case 'dns': {
      return `<span>${(v.records || []).length} recs</span>`;
    }
    case 'headers': {
      const miss = (v.missingSecurityHeaders || []).length;
      return miss ? `<span style="color:var(--warn)">${miss} missing hdrs</span>` : `<span style="color:var(--ok)">headers ok</span>`;
    }
    case 'ssl': {
      return v.daysToExpiry != null ? `<span>${v.daysToExpiry}d left</span>` : `<span>—</span>`;
    }
    case 'cve': {
      const total = v.totalVulnerabilities || 0;
      if (total === 0) return `<span style="color:var(--ok)">no CVEs</span>`;
      const crit = (v.bySeverity?.CRITICAL || 0);
      const high = (v.bySeverity?.HIGH || 0);
      const parts = [];
      if (crit) parts.push(`<span style="color:var(--bad)">${crit} CRIT</span>`);
      if (high) parts.push(`<span style="color:var(--warn)">${high} HIGH</span>`);
      return `<span>${total} CVEs ${parts.join(' · ')}</span>`;
    }
    case 'owasp': {
      if (v.error) return `<span style="color:var(--bad)">error</span>`;
      const score = v.asvsCompliance?.score;
      if (score == null) return `<span>—</span>`;
      const color = score >= 80 ? 'var(--ok)' : score >= 50 ? 'var(--warn)' : 'var(--bad)';
      return `<span style="color:${color}">ASVS ${score}%</span>`;
    }
    default:
      return `<span>${(typeof v === 'object' ? Object.keys(v).length : 0)} fields</span>`;
  }
}

// ── standalone report (self-contained, print to PDF) ───────────────────
app.get('/scan/:id/report', requireAuth, (req, res) => {
  const s = loadScans().find(x => x.id === req.params.id && x.user === req.session.user.username);
  if (!s) return res.redirect('/dashboard');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderReport(s));
});

function renderReport(s) {
  const started = new Date(s.startedAt).toLocaleString();
  const finished = s.finishedAt ? new Date(s.finishedAt).toLocaleString() : '—';
  const mods = (s.results && s.results.modules) ? s.results.modules : {};
  
  // Render each module with smart formatting
  const modHtml = Object.entries(mods).map(([k, v]) => {
    if (k === 'cve' && v && !v.error) {
      return renderCVESection(v);
    }
    if (k === 'owasp' && v && !v.error) {
      return renderOWASPSection(v);
    }
    // Default: JSON dump
    return `
    <section class="mod">
      <h2>${esc(k)}</h2>
      <pre>${esc(JSON.stringify(v, null, 2))}</pre>
    </section>`;
  }).join('');

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<title>Scan Report — ${esc(s.target)}</title>
<link rel="stylesheet" href="/style.css"/>
<style>
  body.report-page{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
  .report-section{margin:20px 0;padding:16px;border:1px solid var(--border);border-radius:8px}
  .report-section h2{margin-top:0;color:var(--accent)}
  .severity-critical{color:#ff4444;font-weight:bold}
  .severity-high{color:#ff8800;font-weight:bold}
  .severity-medium{color:#ffcc00}
  .severity-low{color:#88cc00}
  .cve-item{margin:12px 0;padding:10px;background:var(--card);border-left:3px solid var(--accent)}
  .asvs-score{font-size:2em;font-weight:bold}
  .asvs-requirement{margin:8px 0;padding:8px;background:var(--card)}
  .asvs-pass{border-left:3px solid var(--ok)}
  .asvs-fail{border-left:3px solid var(--bad)}
  .wstg-test{margin:8px 0;padding:8px;background:var(--card)}
</style></head><body class="report-page">
  <div class="toolbar"><button onclick="window.print()">Print / Save as PDF</button></div>
  <div class="page">
    <header>
      <h1>🌩️ T3MP3ST Scan Report</h1>
      <div class="meta">
        <div><strong>Target:</strong> ${esc(s.target)}</div>
        <div><strong>Company:</strong> ${esc(s.company || '—')}</div>
        <div><strong>Requested by:</strong> ${esc(s.user)}</div>
        <div><strong>Started:</strong> ${esc(started)}</div>
        <div><strong>Completed:</strong> ${esc(finished)}</div>
        <div><strong>Status:</strong> ${esc(s.status)}</div>
      </div>
    </header>
    ${modHtml || '<p>No module output.</p>'}
    <footer class="meta" style="margin-top:40px;border-top:1px solid var(--line);padding-top:12px">
      Generated by T3MP3ST Portal · ${esc(new Date().toLocaleString())}
    </footer>
  </div>
</body></html>`;
}

function renderCVESection(cve) {
  const total = cve.totalVulnerabilities || 0;
  const bySev = cve.bySeverity || {};
  
  let html = `
    <section class="report-section">
      <h2>🔴 Vulnerability Assessment (CVE)</h2>
      <div class="meta">
        <div><strong>Total CVEs Found:</strong> ${total}</div>
        ${bySev.CRITICAL ? `<div class="severity-critical"><strong>CRITICAL:</strong> ${bySev.CRITICAL}</div>` : ''}
        ${bySev.HIGH ? `<div class="severity-high"><strong>HIGH:</strong> ${bySev.HIGH}</div>` : ''}
        ${bySev.MEDIUM ? `<div class="severity-medium"><strong>MEDIUM:</strong> ${bySev.MEDIUM}</div>` : ''}
        ${bySev.LOW ? `<div class="severity-low"><strong>LOW:</strong> ${bySev.LOW}</div>` : ''}
      </div>`;
  
  if (total > 0) {
    html += '<h3 style="margin-top:20px">Top Vulnerabilities</h3>';
    const topCVEs = (cve.vulnerabilities || []).slice(0, 10);
    topCVEs.forEach(vuln => {
      html += `
        <div class="cve-item">
          <div><strong>${esc(vuln.cveId || 'Unknown CVE')}</strong> <span class="severity-${(vuln.severity || 'unknown').toLowerCase()}">[${esc(vuln.severity || 'UNKNOWN')}]</span></div>
          <div><strong>Product:</strong> ${esc(vuln.product || 'Unknown')} ${vuln.version ? `v${esc(vuln.version)}` : ''}</div>
          ${vuln.cvssScore ? `<div><strong>CVSS Score:</strong> ${vuln.cvssScore}</div>` : ''}
          ${vuln.description ? `<div style="margin-top:6px;font-size:0.9em;color:var(--muted)">${esc(vuln.description.substring(0, 300))}${vuln.description.length > 300 ? '...' : ''}</div>` : ''}
        </div>`;
    });
  }
  
  html += '</section>';
  return html;
}

function renderOWASPSection(owasp) {
  const wstg = owasp.owaspTestingGuide || {};
  const asvs = owasp.asvsCompliance || {};
  const score = asvs.score || 0;
  const scoreColor = score >= 80 ? 'var(--ok)' : score >= 50 ? 'var(--warn)' : 'var(--bad)';
  
  let html = `
    <section class="report-section">
      <h2>🛡️ OWASP Compliance Report</h2>
      
      <div style="text-align:center;margin:20px 0">
        <div class="asvs-score" style="color:${scoreColor}">${score}%</div>
        <div>ASVS Compliance Score</div>
        <div style="margin-top:10px">
          <strong>Requirements:</strong> ${asvs.passed || 0} passed / ${asvs.totalRequirements || 0} total
        </div>
      </div>`;
  
  // OWASP Testing Guide
  if (wstg.tests && wstg.tests.length > 0) {
    html += `
      <h3 style="margin-top:20px">OWASP Testing Guide (WSTG v4.2)</h3>
      <div class="meta"><strong>Tests Mapped:</strong> ${wstg.totalTestsMapped || 0}</div>`;
    
    wstg.tests.slice(0, 15).forEach(test => {
      html += `
        <div class="wstg-test">
          <div><strong>${esc(test.testId)}</strong> — ${esc(test.description || 'Unknown test')}</div>
          <div style="font-size:0.9em;margin-top:4px">
            <span class="severity-${(test.severity || 'unknown').toLowerCase()}">[${esc(test.severity || 'UNKNOWN')}]</span>
            CVEs: ${(test.cves || []).map(c => c.cveId).join(', ') || 'None'}
          </div>
        </div>`;
    });
  }
  
  // ASVS Failed Requirements
  if (asvs.requirements) {
    const failed = Object.values(asvs.requirements).filter(r => r.status === 'FAIL');
    if (failed.length > 0) {
      html += `<h3 style="margin-top:20px">ASVS v4.0 — Failed Requirements</h3>`;
      failed.forEach(req => {
        html += `
          <div class="asvs-requirement asvs-fail">
            <div><strong>${esc(req.requirementId)}</strong> — ${esc(req.name || 'Unknown requirement')}</div>
            <div style="font-size:0.9em;margin-top:4px;color:var(--muted)">
              ${req.findings.length} finding(s): ${req.findings.slice(0, 3).map(f => f.cveId || f.type).join(', ')}${req.findings.length > 3 ? '...' : ''}
            </div>
          </div>`;
      });
    }
  }
  
  html += '</section>';
  return html;
}

app.listen(PORT, () => console.log(`T3MP3ST portal listening on :${PORT}`));
