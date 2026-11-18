// Persistent per-module + global settings, stored in WEBKILLER_HOME. Separate
// from ai-settings.json (which holds the encrypted provider key).
const fs = require('fs');
const os = require('os');
const path = require('path');

function homeDir() { return process.env.WEBKILLER_HOME || path.join(os.homedir(), '.webkiller'); }
function settingsPath() { return path.join(homeDir(), 'module-settings.json'); }

const GLOBAL_DEFAULTS = {
  user_agent: 'WebKiller/2.0 (+authorized-security-testing)',
  rate_limit: 50,
  concurrency: 20,
  timeout: 15,
  out_of_scope: '',
};

function load() {
  try {
    const raw = JSON.parse(fs.readFileSync(settingsPath(), 'utf8'));
    return { global: raw.global || {}, modules: raw.modules || {}, enabled: raw.enabled || {} };
  } catch { return { global: {}, modules: {}, enabled: {} }; }
}

function save(input = {}) {
  const cur = load();
  const out = {
    global: { ...cur.global, ...(input.global || {}) },
    modules: { ...cur.modules, ...(input.modules || {}) },
    enabled: { ...cur.enabled, ...(input.enabled || {}) },
  };
  fs.mkdirSync(homeDir(), { recursive: true });
  fs.writeFileSync(settingsPath(), JSON.stringify(out, null, 2), { mode: 0o600 });
  return out;
}

function globals() { return { ...GLOBAL_DEFAULTS, ...(load().global || {}) }; }

// Flatten global + every module's saved params into the one flat config object
// the scan modules read (this.config.<key>).
function toOverrides() {
  const s = load();
  const o = { ...GLOBAL_DEFAULTS, ...(s.global || {}) };
  for (const cfg of Object.values(s.modules || {})) if (cfg) Object.assign(o, cfg);
  return o;
}

function isEnabled(key) {
  const e = load().enabled || {};
  return e[key] !== false; // modules are enabled unless explicitly turned off
}

module.exports = { load, save, globals, toOverrides, isEnabled, GLOBAL_DEFAULTS };
