// Standalone reimplementation of T3MP3ST's scanner arsenal tools.
// Lifted out of src/arsenal/index.ts — pure-Node scanners (dns/net/tls) reimplemented here,
// nmap shelled out when present. No scope gate, no approval controller (by design).

const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);
const dnsResolve = promisify(require('dns').resolve);

const TIMEOUT = 4000;

function withTimeout(promise, ms = TIMEOUT, label = 'op') {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`${label} timed out`)), ms)),
  ]);
}

// ── port check (single) ────────────────────────────────────────────────
function checkPort(host, port, timeout = 2000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.on('connect', () => { socket.destroy(); resolve({ port, open: true }); });
    socket.on('timeout', () => { socket.destroy(); resolve({ port, open: false }); });
    socket.on('error', () => { socket.destroy(); resolve({ port, open: false }); });
    try { socket.connect(port, host); } catch { resolve({ port, open: false }); }
  });
}

// ── DNS ───────────────────────────────────────────────────────────────
async function dnsLookup(domain, type = 'A') {
  const map = {
    A: 'resolve4', AAAA: 'resolve6', MX: 'resolveMx', TXT: 'resolveTxt',
    NS: 'resolveNs', CNAME: 'resolveCname', SOA: 'resolveSoa',
  };
  const fn = map[type] || 'resolve4';
  try {
    const res = await withTimeout(dns[fn](domain), TIMEOUT, `dns ${type}`);
    return { type, records: Array.isArray(res) ? res.map(r => (typeof r === 'object' ? JSON.stringify(r) : r)) : [res] };
  } catch (e) {
    return { type, records: [], error: e.message };
  }
}

// ── subdomain enum (brute via common subdomains) ──────────────────────
const COMMON_SUBS = ['www','mail','ftp','webmail','admin','api','dev','test','stage','staging','shop','blog','ns1','ns2','smtp','pop','portal','vpn','remote','git','cloud','app','cdn','m','mobile','secure','login','auth','dashboard','intranet','internal','support','docs','wiki'];

async function subdomainEnum(domain) {
  const found = [];
  await Promise.all(COMMON_SUBS.map(async (sub) => {
    const host = `${sub}.${domain}`;
    try {
      const ips = await withTimeout(dnsResolve(host), 2500, host);
      if (ips && ips.length) found.push({ subdomain: host, ips });
    } catch { /* not found */ }
  }));
  return { domain, subdomains: found };
}

// ── port scan (with service banner grab) ─────────────────────────────
async function checkPortWithBanner(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = '';
    socket.setTimeout(timeout);
    
    socket.on('connect', () => {
      const portNum = parseInt(port);
      // HTTP-like: send a probe
      if ([80, 443, 8080, 8443].includes(portNum)) {
        socket.write(`HEAD / HTTP/1.0\r\nHost: ${host}\r\n\r\n`);
      }
      
      socket.on('data', (data) => {
        banner += data.toString('utf8', 0, Math.min(500, data.length));
        if (banner.length > 200) socket.destroy();
      });
      
      setTimeout(() => socket.destroy(), 1200);
    });
    
    socket.on('timeout', () => { socket.destroy(); resolve({ port, open: true, banner: '' }); });
    socket.on('error', () => { socket.destroy(); resolve({ port, open: false, banner: '' }); });
    socket.on('close', () => {
      resolve({ port, open: true, banner: banner.trim().substring(0, 300) });
    });
    
    try { socket.connect(port, host); } catch { resolve({ port, open: false, banner: '' }); }
  });
}

function parseBanner(banner, port) {
  if (!banner) {
    // Port was open but no banner — infer from port number
    const portServices = { 22: 'SSH', 21: 'FTP', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP', 8443: 'HTTPS', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis' };
    return { service: portServices[parseInt(port)] || 'unknown', version: '' };
  }
  const portNum = parseInt(port);
  
  // SSH
  if (banner.startsWith('SSH-')) {
    const m = banner.match(/SSH-(\d+\.\d+)-(.+?)(?:\s|$)/);
    if (m) return { service: 'SSH', version: m[2].trim() };
  }
  
  // FTP
  if (/^220\s/.test(banner)) {
    const m = banner.match(/220\s+(.+)/);
    return { service: 'FTP', version: (m && m[1]) || banner.substring(4, 80).trim() };
  }
  
  // SMTP
  if (/^220\s/.test(banner) && /smtp|mail|postfix|exim/i.test(banner)) {
    const m = banner.match(/220\s+(.+)/i);
    return { service: 'SMTP', version: (m && m[1]) || banner.substring(4, 60) };
  }
  
  // HTTP / HTTPS — look for Server: header or status line
  const serverMatch = banner.match(/[Ss]erver:\s*(.+)/i);
  if (serverMatch) {
    return { service: portNum === 443 || portNum === 8443 ? 'HTTPS' : 'HTTP', version: serverMatch[1].trim().substring(0, 80) };
  }
  
  // HTTP response line (e.g. "HTTP/1.0 301 Moved Permanently")
  if (/^HTTP\/\d/.test(banner)) {
    const m = banner.match(/^HTTP\/[\d.]+\s+(\d+\s+\S+)/);
    return { service: portNum === 443 || portNum === 8443 ? 'HTTPS' : 'HTTP', version: m ? m[1].trim() : banner.split('\n')[0].substring(0, 60) };
  }
  
  // MySQL / MariaDB
  if (banner.includes('mysql') || banner.includes('MariaDB')) {
    const m = banner.match(/(\d+\.\d+\.\d+[^\x00]*)/);
    return { service: banner.includes('MariaDB') ? 'MariaDB' : 'MySQL', version: m ? m[1] : 'unknown' };
  }
  
  // PostgreSQL — port hint
  if (portNum === 5432) return { service: 'PostgreSQL', version: '' };
  
  // Redis
  if (/^\-ERR/.test(banner) || banner.includes('redis')) return { service: 'Redis', version: '' };
  
  // Generic: first line
  const firstLine = banner.split('\n')[0].trim().substring(0, 80);
  return { service: 'unknown', version: firstLine };
}

async function portScan(host, ports = '22,80,443,8080', timeout = 2000) {
  const list = String(ports).split(',').map(p => parseInt(p.trim(), 10)).filter(Boolean);
  const raw = await Promise.all(list.map(p => checkPortWithBanner(host, p, timeout)));
  const results = raw.filter(r => r.open).map(r => {
    const parsed = parseBanner(r.banner, r.port);
    return { port: r.port, open: true, service: parsed.service, version: parsed.version };
  });
  return { host, ports: results };
}

// ── header analysis ───────────────────────────────────────────────────
async function headerAnalysis(url) {
  try {
    const u = new URL(url.startsWith('http') ? url : `https://${url}`);
    const res = await withTimeout(fetch(u, { method: 'HEAD', redirect: 'manual' }), TIMEOUT, 'header fetch');
    const headers = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const security = ['content-security-policy','strict-transport-security','x-frame-options','x-content-type-options','x-xss-protection','referrer-policy']
      .filter(h => !headers[h.toLowerCase()]);
    return { url: u.toString(), status: res.status, headers, missingSecurityHeaders: security };
  } catch (e) {
    return { url, error: e.message };
  }
}

// ── SSL / TLS scan ────────────────────────────────────────────────────
function sslScan(host, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port, timeout: TIMEOUT, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate(true);
      const cipher = socket.getCipher();
      const proto = socket.getProtocol();
      socket.destroy();
      resolve({
        host, port, protocol: proto, cipher: cipher && cipher.name,
        subject: cert.subject ? cert.subject.CN : null,
        issuer: cert.issuer ? cert.issuer.CN : null,
        validFrom: cert.valid_from || null,
        validTo: cert.valid_to || null,
        sans: cert.subjectaltname || null,
        daysToExpiry: cert.valid_to ? Math.round((new Date(cert.valid_to) - Date.now()) / 86400000) : null,
      });
    });
    socket.on('timeout', () => { socket.destroy(); resolve({ host, port, error: 'tls timeout' }); });
    socket.on('error', (e) => resolve({ host, port, error: e.message }));
  });
}

// ── whois (lightweight: use the whois CLI if present, else fallback) ───
async function whoisLookup(domain) {
  // Best-effort: shell out to `whois` if installed.
  try {
    const { stdout } = await execFileAsync('whois', [domain], { timeout: 8000 });
    return { domain, raw: stdout.slice(0, 4000) };
  } catch (e) {
    return { domain, error: 'whois unavailable: ' + e.message };
  }
}

// ── robots.txt ────────────────────────────────────────────────────────
async function robotsTxtFetch(url) {
  try {
    const u = new URL(url.startsWith('http') ? url : `https://${url}`);
    const res = await withTimeout(fetch(new URL('/robots.txt', u), { redirect: 'manual' }), TIMEOUT, 'robots');
    if (!res.ok) return { url: u.origin, status: res.status, note: 'no robots.txt' };
    const text = await res.text();
    const disallowed = text.split('\n').map(l => l.trim()).filter(l => /^disallow:/i.test(l));
    return { url: u.origin, status: res.status, disallowed };
  } catch (e) {
    return { url, error: e.message };
  }
}

// ── nmap (shell out, graceful if absent) ──────────────────────────────
async function hasBinary(name) {
  try { await execFileAsync('which', [name], { timeout: 3000 }); return true; }
  catch { return false; }
}

async function nmapScan(target, ports = '1-1000') {
  if (!(await hasBinary('nmap'))) return { target, skipped: true, reason: 'nmap not installed' };
  try {
    const { stdout } = await execFileAsync('nmap', ['-Pn', '-sV', '--top-ports', ports === '1-1000' ? '100' : ports, target], { timeout: 120000 });
    const open = stdout.split('\n').filter(l => /\d+\/tcp\s+open/.test(l));
    return { target, openPorts: open, raw: stdout.slice(0, 6000) };
  } catch (e) {
    return { target, error: e.message };
  }
}

// ── nmap version scan (structured output) ─────────────────────────────
async function nmapVersionScan(target, ports = '1-1000') {
  if (!(await hasBinary('nmap'))) return { target, skipped: true, reason: 'nmap not installed' };
  try {
    const { stdout } = await execFileAsync('nmap', ['-Pn', '-sV', '-oX', '-', '--top-ports', ports === '1-1000' ? '100' : ports, target], { timeout: 120000 });
    
    // Parse XML output for structured data
    const results = [];
    const portRegex = /<port protocol="tcp" portid="(\d+)">[\s\S]*?<state state="open"[\s\S]*?<service name="([^"]*)"([\s\S]*?)\/>/g;
    const versionRegex = /product="([^"]*)"[\s\S]*?version="([^"]*)"/g;
    
    let match;
    while ((match = portRegex.exec(stdout)) !== null) {
      const port = parseInt(match[1]);
      const service = match[2];
      const serviceBlock = match[3];
      
      const versionMatch = versionRegex.exec(serviceBlock);
      const product = versionMatch ? versionMatch[1] : '';
      const version = versionMatch ? versionMatch[2] : '';
      
      results.push({ port, service, product, version, cpe: '' });
    }
    
    return { target, ports: results };
  } catch (e) {
    return { target, error: e.message };
  }
}

// ── combined port scan (banner + nmap) ────────────────────────────────
async function portScanEnhanced(host, ports = '22,80,443,8080') {
  // Fast banner scan first
  const bannerResults = await portScan(host, ports, 2000);
  
  // If nmap is available and we have open ports, enrich with version detection
  if (await hasBinary('nmap') && bannerResults.ports.length > 0) {
    const nmapResults = await nmapVersionScan(host, ports);
    
    if (nmapResults.ports) {
      // Merge nmap data into banner results
      bannerResults.ports.forEach(bannerPort => {
        const nmapPort = nmapResults.ports.find(n => n.port === bannerPort.port);
        if (nmapPort) {
          bannerPort.product = nmapPort.product;
          bannerPort.version = nmapPort.version || bannerPort.version;
          bannerPort.service = nmapPort.service || bannerPort.service;
        }
      });
    }
  }
  
  return bannerResults;
}

module.exports = {
  dnsLookup, subdomainEnum, portScan, portScanEnhanced, headerAnalysis, sslScan, whoisLookup,
  robotsTxtFetch, nmapScan, nmapVersionScan, hasBinary, checkPort,
};
