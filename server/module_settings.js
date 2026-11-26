// Persistent per-module + global settings, stored in WEBKILLER_HOME. Separate
// from ai-settings.json (which holds the encrypted provider key).
const fs = require('fs');
const os = require('os');
const path = require('path');

const { MODULE_META } = require('./module_meta');
const { DEFAULT_UA, resolveUA, displayUA } = require('./user_agents');

function homeDir() { return process.env.WEBKILLER_HOME || path.join(os.homedir(), '.webkiller'); }
function settingsPath() { return path.join(homeDir(), 'module-settings.json'); }

// Which params are secrets (API tokens etc.), per module — derived from the meta.
// Secrets are stored locally but never sent back to the UI in plaintext, and a
// blank value on save means "keep the stored one".
const SECRET_KEYS = {};
for (const m of MODULE_META) {
  const ks = (m.params || []).filter(p => p.type === 'secret').map(p => p.key);
  if (ks.length) SECRET_KEYS[m.key] = ks;
}

// Replace secret values with a {set} marker so the UI can show "set / not set"
// without ever receiving the token itself.
function maskSecrets(modKey, values = {}) {
  const ks = SECRET_KEYS[modKey];
  if (!ks) return values;
  const out = { ...values };
  for (const k of ks) out[k] = { __secret: true, set: !!(out[k] && String(out[k]).length) };
  return out;
}

const GLOBAL_DEFAULTS = {
  user_agent: DEFAULT_UA,
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
  const modules = { ...cur.modules };
  for (const [mk, vals] of Object.entries(input.modules || {})) {
    const merged = { ...(vals || {}) };
    // A blank/omitted secret means "keep the stored token" — never let a save
    // that didn't re-enter the token wipe it, and never persist the {set} marker.
    for (const sk of SECRET_KEYS[mk] || []) {
      const v = merged[sk];
      if (v === '__CLEAR__') { delete merged[sk]; continue; } // explicit remove
      if (v == null || v === '' || typeof v === 'object') {
        if (cur.modules[mk] && cur.modules[mk][sk] != null) merged[sk] = cur.modules[mk][sk];
        else delete merged[sk];
      }
    }
    modules[mk] = merged;
  }
  const out = {
    global: { ...cur.global, ...(input.global || {}) },
    modules,
    enabled: { ...cur.enabled, ...(input.enabled || {}) },
  };
  fs.mkdirSync(homeDir(), { recursive: true });
  fs.writeFileSync(settingsPath(), JSON.stringify(out, null, 2), { mode: 0o600 });
  return out;
}

function globals() {
  const g = { ...GLOBAL_DEFAULTS, ...(load().global || {}) };
  g.user_agent = displayUA(g.user_agent); // never surface empty / legacy WebKiller* to the UI
  return g;
}

// Flatten global + every module's saved params into the one flat config object
// the scan modules read (this.config.<key>).
function toOverrides() {
  const s = load();
  const o = { ...GLOBAL_DEFAULTS, ...(s.global || {}) };
  for (const cfg of Object.values(s.modules || {})) if (cfg) Object.assign(o, cfg);
  o.user_agent = resolveUA(o.user_agent); // random -> a concrete UA for this scan; never WebKiller*
  return o;
}

function isEnabled(key) {
  const e = load().enabled || {};
  return e[key] !== false; // modules are enabled unless explicitly turned off
}

module.exports = { load, save, globals, toOverrides, isEnabled, maskSecrets, SECRET_KEYS, GLOBAL_DEFAULTS };
