const net = require('net');

// Customer scan scope is deliberately exact-match only in this first portal
// slice. CIDR support belongs in a future, separately reviewed change.
function normalizeTarget(value) {
  let target = String(value || '').trim().toLowerCase();
  target = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!target || target.includes('@')) return null;
  if (net.isIP(target)) return target;
  if (target.includes(':')) return null;
  if (target.length > 253) return null;

  const labels = target.split('.');
  if (labels.length < 2 || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    return null;
  }
  return target;
}

function normalizeApprovedTargets(values) {
  const unique = new Set();
  for (const value of values || []) {
    const target = normalizeTarget(value);
    if (!target) return { targets: [], error: `Invalid approved target: ${String(value || '').trim() || '(blank)'}` };
    unique.add(target);
  }
  return { targets: [...unique], error: null };
}

function isApprovedTarget(target, approvedTargets) {
  const normalized = normalizeTarget(target);
  return Boolean(normalized && Array.isArray(approvedTargets) && approvedTargets.includes(normalized));
}

module.exports = { normalizeTarget, normalizeApprovedTargets, isApprovedTarget };
