const { execFileSync } = require('child_process');

const TOOLS = {
  subfinder:           { check: 'subfinder -version',           required_for: ['subdomains_passive'] },
  httpx:               { check: 'httpx -version',               required_for: ['probe'] },
  dnsx:                { check: 'dnsx -version',                required_for: ['subdomains_active', 'subdomains_permute'] },
  naabu:               { check: 'naabu -version',               required_for: ['portscan'] },
  nmap:                { check: 'nmap --version',               required_for: ['portscan', 'service_cve'] },
  nuclei:              { check: 'nuclei -version',              required_for: ['vuln_signal', 'vuln_confirm', 'cve_verify'] },
  katana:              { check: 'katana -version',              required_for: ['urls'] },
  gau:                 { check: 'gau -version',                 required_for: ['urls'] },
  ffuf:                { check: 'ffuf -V',                      required_for: ['content'] },
  dalfox:              { check: 'dalfox version',               required_for: ['xss_confirm'] },
  ghauri:              { check: 'ghauri --version',             required_for: ['sqli_confirm'] },
  arjun:               { check: 'arjun --help',                 required_for: ['params'] },
  wafw00f:             { check: 'wafw00f -V',                   required_for: ['fingerprint'] },
  puredns:             { check: 'puredns -h',                   required_for: ['subdomains_active'] },
  gotator:             { check: 'gotator -h',                   required_for: ['subdomains_active'] },
  gf:                  { check: 'gf -h',                        required_for: ['tagging'] },
  trufflehog:          { check: 'trufflehog --version',         required_for: ['secret_verify'] },
  'interactsh-client': { check: 'interactsh-client -version',   required_for: ['vuln_confirm'] },
  gowitness:           { check: 'gowitness version',            required_for: ['screenshots'] },
};

const _cache = {};

// Probe-based detection is the single source of truth. registry delegates to it
// for every tool in the manifest; tools not in the manifest (nmap, puredns, gf,
// interactsh-client, gotator) still fall back to a plain PATH lookup.
let _det = null; let _detTs = 0; let _detRefreshing = false;
// Tool detection is expensive — it spawns every managed tool with `--version`
// (~1–4s cold). Installs/uninstalls call clearCache(), so a long TTL is safe: it
// only guards against tools installed out-of-band in a terminal. Stale results
// are served immediately and re-probed off the request path, so a page that needs
// module status (New Scan, Settings) never blocks on a re-probe.
const DET_TTL_MS = 10 * 60 * 1000;
function _probeDetections() {
  try { const { detectAll, buildContext } = require('./tools/detect'); _det = detectAll(buildContext()); }
  catch { if (!_det) _det = {}; }
  _detTs = Date.now();
}
function detections() {
  if (!_det) { _probeDetections(); return _det; } // cold: block once (warmed at startup → rare)
  if (Date.now() - _detTs > DET_TTL_MS && !_detRefreshing) {
    _detRefreshing = true; // stale: serve what we have, refresh in the background
    setTimeout(() => { try { _probeDetections(); } finally { _detRefreshing = false; } }, 0);
  }
  return _det;
}
// Build the detection cache ahead of the first request (called once the server is
// listening) so the first New Scan / Settings navigation is instant, not a ~2–4s probe.
function warmDetections() { setImmediate(() => { try { if (!_det) _probeDetections(); } catch { /* best effort */ } }); }
function manifestTools() {
  try { return require('./tools/manifest').TOOLS; } catch { return {}; }
}
// Absolute path to the exact binary to run (managed install or system), or null.
function toolPath(name) {
  const d = detections()[name];
  return (d && d.chosen && d.chosen.path) || null;
}

function whichSync(name) {
  try {
    const cmd = process.platform === 'win32' ? 'where' : 'which';
    const result = execFileSync(cmd, [name], { timeout: 3000, encoding: 'utf8' });
    return result.trim().split('\n')[0] || null;
  } catch {
    return null;
  }
}

function isInstalled(tool) {
  if (tool in _cache) return _cache[tool];
  let found;
  if (tool in manifestTools()) {
    const d = detections()[tool];
    found = !!(d && (d.status === 'ready' || d.status === 'untested'));
  } else {
    found = whichSync(tool) !== null; // nmap, puredns, gf, interactsh-client, gotator
  }
  _cache[tool] = found;
  return found;
}

function checkAll() {
  const result = {};
  for (const name of Object.keys(TOOLS)) {
    result[name] = isInstalled(name);
  }
  return result;
}

function toolsForModule(moduleName) {
  const result = [];
  for (const [name, info] of Object.entries(TOOLS)) {
    if (info.required_for.includes(moduleName)) {
      result.push({ name, installed: isInstalled(name) });
    }
  }
  return result;
}

function missingForModule(moduleName) {
  return toolsForModule(moduleName)
    .filter(t => !t.installed)
    .map(t => t.name);
}

function clearCache() {
  for (const k of Object.keys(_cache)) delete _cache[k];
  _det = null; _detTs = 0; // force a fresh probe pass on next lookup
}

module.exports = { TOOLS, isInstalled, checkAll, toolsForModule, missingForModule, clearCache, whichSync, toolPath, detections, warmDetections };
