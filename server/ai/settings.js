// AI settings store. Lives in WEBKILLER_HOME (default ~/.webkiller) so it
// survives app restarts and is separate from scan output. The API key is
// encrypted with Electron safeStorage when available (the server runs in the
// Electron main process); outside Electron it falls back to a 0600 plaintext
// file and flags itself insecure, so a dev run still works but never pretends
// to be safe.

const fs = require('fs');
const os = require('os');
const path = require('path');

function homeDir() {
  return process.env.WEBKILLER_HOME || path.join(os.homedir(), '.webkiller');
}
function settingsPath() {
  return path.join(homeDir(), 'ai-settings.json');
}

function getSafeStorage() {
  try {
    const { safeStorage } = require('electron');
    if (safeStorage && safeStorage.isEncryptionAvailable()) return safeStorage;
  } catch { /* not running under Electron */ }
  return null;
}

const DEFAULTS = {
  enabled: false,
  provider: 'openrouter',
  baseURL: 'https://openrouter.ai/api/v1',
  model: 'deepseek/deepseek-chat',
  // The agentic loop is latency-bound, so it defaults to a fast cheap model;
  // the single-shot hooks (report/triage) keep `model`. Blank = use `model`.
  agentModel: 'google/gemini-3.1-flash-lite',
  maxToolCalls: 50, // how many tools the agentic loop may run — user-tunable
};

function readRaw() {
  try { return JSON.parse(fs.readFileSync(settingsPath(), 'utf8')); } catch { return {}; }
}

// Full settings including the decrypted key — server-side only, never sent to UI.
function load() {
  const raw = readRaw();
  const out = { ...DEFAULTS, enabled: !!raw.enabled, apiKey: '', insecureKey: false };
  for (const k of ['provider', 'baseURL', 'model', 'agentModel', 'maxToolCalls']) if (raw[k] !== undefined) out[k] = raw[k];

  if (raw.apiKeyEnc) {
    const ss = getSafeStorage();
    if (ss) {
      try { out.apiKey = ss.decryptString(Buffer.from(raw.apiKeyEnc, 'base64')); }
      catch { /* key was encrypted on another machine/user; treat as missing */ }
    }
  } else if (raw.apiKeyPlain) {
    out.apiKey = raw.apiKeyPlain;
    out.insecureKey = true;
  }
  return out;
}

function save(input = {}) {
  const dir = homeDir();
  fs.mkdirSync(dir, { recursive: true });

  const cur = load();
  const toWrite = {
    enabled: input.enabled !== undefined ? !!input.enabled : cur.enabled,
    provider: input.provider !== undefined ? input.provider : cur.provider,
    baseURL: input.baseURL !== undefined ? input.baseURL : cur.baseURL,
    model: input.model !== undefined ? input.model : cur.model,
    agentModel: input.agentModel !== undefined ? input.agentModel : cur.agentModel,
    maxToolCalls: input.maxToolCalls !== undefined ? Math.max(1, Math.min(200, parseInt(input.maxToolCalls, 10) || 50)) : cur.maxToolCalls,
  };

  const key = input.apiKey !== undefined ? input.apiKey : cur.apiKey;
  if (key) {
    const ss = getSafeStorage();
    if (ss) toWrite.apiKeyEnc = ss.encryptString(key).toString('base64');
    else toWrite.apiKeyPlain = key; // dev fallback; flagged insecure on load
  }

  fs.writeFileSync(settingsPath(), JSON.stringify(toWrite, null, 2), { mode: 0o600 });
  try { fs.chmodSync(settingsPath(), 0o600); } catch { /* best effort — mode only applies on create otherwise */ }
  return loadPublic();
}

function maskKey(k) {
  if (!k) return '';
  return k.length <= 8 ? '••••' : `${k.slice(0, 4)}…${k.slice(-4)}`;
}

// Safe shape for the UI: never includes the raw key.
function loadPublic() {
  const s = load();
  return {
    enabled: s.enabled,
    provider: s.provider,
    baseURL: s.baseURL,
    model: s.model,
    agentModel: s.agentModel,
    hasKey: !!s.apiKey,
    keyMasked: maskKey(s.apiKey),
    insecureKey: s.insecureKey,
    maxToolCalls: s.maxToolCalls,
  };
}

// Dev-only stub so the UI can be exercised without a real key/network.
// Guarded by WK_AI_MOCK, which is never set in a shipped build.
function makeMockProvider() {
  return {
    model: 'mock-model',
    async chat({ system = '', user = '', tools } = {}) {
      if (tools && tools.length) {
        this._step = (this._step || 0) + 1;
        const mk = (name, args) => ({ id: 'call_' + this._step, type: 'function', function: { name, arguments: JSON.stringify(args || {}) } });
        if (this._step === 1) return { content: 'Enumerating subdomains first.', toolCalls: [mk('enumerate_subdomains')], usage: { total_tokens: 220 } };
        if (this._step === 2) return { content: 'Probing which hosts are live.', toolCalls: [mk('probe_live_hosts')], usage: { total_tokens: 210 } };
        if (this._step === 3) return { content: 'Reviewing what was gathered so far.', toolCalls: [mk('read_artifact', { artifact: 'subdomains' })], usage: { total_tokens: 160 } };
        return { content: 'Reconnaissance complete.', toolCalls: [mk('finish', { summary: 'Enumerated subdomains and probed live hosts; no high-severity issues surfaced in this pass.' })], usage: { total_tokens: 170 } };
      }
      if (/triage/i.test(system)) {
        let ids = [];
        try { ids = (JSON.parse((user.match(/\[[\s\S]*\]/) || ['[]'])[0]) || []).map(x => x.id); } catch { /* none */ }
        const verdicts = ids.map((id, i) => ({
          id,
          keep: i % 4 !== 0,
          priority: (i % 5) + 1,
          reason: i % 4 === 0 ? 'Reflection only — almost certainly a false positive' : 'Parameter looks reachable; worth a manual check',
        }));
        return { content: JSON.stringify({ verdicts }), usage: { total_tokens: 430 } };
      }
      return {
        content: '## Executive Summary\n\nRecon of the target surfaced a small set of candidate issues worth manual review. Most are heuristic and need validation before they are treated as real.\n\n## Attack Surface\n\n- Subdomains, live hosts and URLs were enumerated and de-duplicated.\n- A handful of candidate findings came out of the confirm phase.\n\n## Key Findings\n\n- **High** — possible time-based SQL injection on a query parameter. **Needs manual validation.**\n- **Medium** — user input reflected without encoding; a candidate for reflected XSS.\n\n## Confirmed Issues\n\n- None independently confirmed yet; treat the above as leads.\n\n## Recommended Next Steps\n\n- Manually validate the high-severity SQLi candidate first with a controlled payload.\n- Review authentication and access control on the API endpoints.\n- Re-test reflected inputs in a browser context for executable XSS.\n',
        usage: { total_tokens: 1180 },
      };
    },
  };
}

function getProvider(overrides = {}) {
  if (process.env.WK_AI_MOCK) return makeMockProvider();
  const s = load();
  const { OpenAICompatProvider } = require('./provider');
  return new OpenAICompatProvider({
    baseURL: overrides.baseURL || s.baseURL,
    apiKey: overrides.apiKey || s.apiKey,
    model: overrides.model || s.model,
  });
}

module.exports = { load, save, loadPublic, getProvider, DEFAULTS, homeDir, settingsPath };
