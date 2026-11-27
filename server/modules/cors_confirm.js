const { BaseModule, ModuleResult } = require('./base');
const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
const { endpointCandidates, dedupEndpoints } = require('./massassign_confirm');

// Send a hostile Origin and read the CORS response headers. Reflecting the
// attacker origin (or "null") together with Allow-Credentials lets a malicious
// site read authenticated responses.
const EVIL = 'https://wk-attacker.example';

class CorsConfirm extends BaseModule {
  static moduleName = 'cors_confirm';
  static phase = 'P6d';
  static toolsNeeded = [];

  async execute() {
    const candidates = endpointCandidates(this.workspace, this.scope, false);
    if (!candidates.length) return new ModuleResult({ module: CorsConfirm.moduleName, status: 'skipped', errors: ['No candidate endpoints'] });
    const ua = this.config.user_agent || 'WebKiller/3.0';
    const confirmed = [];
    pushInsecureTLS();
    try {
      for (const ep of candidates.slice(0, this.config.cors_max_urls || 60)) {
        for (const origin of [EVIL, 'null']) {
          try {
            const resp = await fetch(ep, { headers: { 'User-Agent': ua, Origin: origin }, signal: AbortSignal.timeout(8000) });
            const acao = resp.headers.get('access-control-allow-origin');
            const acac = (resp.headers.get('access-control-allow-credentials') || '').toLowerCase() === 'true';
            if (acao === origin || (origin === EVIL && acao === '*' && acac)) {
              confirmed.push({ name: `CORS misconfiguration${acac ? ' + credentials' : ''}`, severity: acac ? 'high' : 'low', url: ep, evidence: { reflected_origin: acao, allow_credentials: acac, note: acac ? `${origin === 'null' ? 'null origin' : 'arbitrary origin'} reflected WITH credentials — authenticated data readable cross-origin` : 'origin reflected without credentials — limited impact' }, type: 'dast_confirmed', vuln_class: 'cors', module: CorsConfirm.moduleName });
              break;
            }
          } catch { /* skip */ }
        }
      }
    } finally { popInsecureTLS(); }
    const out = dedupEndpoints(confirmed);
    if (out.length) { this.workspace.appendJsonl('confirmed.jsonl', out); this.workspace.appendJsonl('findings.jsonl', out); }
    return new ModuleResult({ module: CorsConfirm.moduleName, items: out.map(c => c.url), records: out, toolUsed: 'origin-reflection' });
  }
}
module.exports = CorsConfirm;
