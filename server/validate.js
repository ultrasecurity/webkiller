const path = require('path');

// A scan target flows into tool arguments (subfinder -d <target>) and into the
// workspace directory path (output/<target>/...). Anything but a bare host must
// be rejected at the boundary: spaces inject extra flags into downstream tools,
// path separators escape the output tree.
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const HOSTNAME = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*\.[a-z][a-z0-9-]{1,62}$/i;
const FORBIDDEN = /[\s/\\?#@%*'"`$;|&<>(){}\[\]]/;

function normalizeTarget(raw) {
  return String(raw || '').trim().toLowerCase().replace(/\.+$/, '');
}

// A target may carry an explicit port (host:port) for single-host scans of apps
// not served on 80/443 (e.g. a local lab). The host is still validated strictly;
// the port is digits only. Returns { host, port|null }.
function splitTarget(raw) {
  const t = normalizeTarget(raw);
  const m = t.match(/^(.+?):(\d{1,5})$/);
  if (m) {
    const port = parseInt(m[2], 10);
    if (port >= 1 && port <= 65535) return { host: m[1], port };
  }
  return { host: t, port: null };
}

function isValidTarget(raw) {
  const t = normalizeTarget(raw);
  if (!t || t.length > 253) return false;
  const { host, port } = splitTarget(t);
  if (t.includes(':') && port === null) return false; // a colon that isn't a valid port
  if (FORBIDDEN.test(host)) return false;
  if (host.includes('..') || host.startsWith('-')) return false;
  if (host.length > 253) return false;
  return IPV4.test(host) || HOSTNAME.test(host);
}

// A result-file name from a request must stay a plain basename inside the scan
// workspace — no separators, no traversal.
function safeBasename(name) {
  const base = path.basename(String(name || ''));
  if (!base || base === '.' || base === '..') return null;
  if (base.includes('/') || base.includes('\\') || base.includes('\0')) return null;
  return base;
}

module.exports = { isValidTarget, normalizeTarget, safeBasename, splitTarget };
