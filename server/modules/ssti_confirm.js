const { BaseModule, ModuleResult } = require('./base');
const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');

// Inject an arithmetic marker in several template syntaxes; if the server
// returns the COMPUTED product (1787569) rather than the literal payload, the
// input reached a server-side template engine (SSTI → frequently RCE).
const EXPECT = String(1337 * 1337); // 1787569
const PAYLOADS = ['{{1337*1337}}', '${1337*1337}', '#{1337*1337}', '<%= 1337*1337 %>', '{1337*1337}'];

class SstiConfirm extends BaseModule {
  static moduleName = 'ssti_confirm';
  static phase = 'P6c';
  static toolsNeeded = [];

  async execute() {
    const targets = dedupParamUrls(this.workspace, this.scope);
    if (!targets.length) return new ModuleResult({ module: SstiConfirm.moduleName, status: 'skipped', errors: ['No parameterized URLs'] });
    const ua = this.config.user_agent || 'WebKiller/2.0';
    const confirmed = [];
    pushInsecureTLS();
    try {
      for (const url of targets.slice(0, this.config.ssti_max_urls || 40)) {
        let parsed; try { parsed = new URL(url); } catch { continue; }
        // Baseline: if the computed marker is already present without injection,
        // this endpoint can't serve as an oracle — skip it (false-positive guard).
        try { const b = await fetch(url, { headers: { 'User-Agent': ua }, signal: AbortSignal.timeout(8000) }); if ((await b.text()).includes(EXPECT)) continue; } catch { /* keep going */ }
        let hit = false;
        for (const pName of [...parsed.searchParams.keys()]) {
          for (const pl of PAYLOADS) {
            try {
              const t = new URL(url); t.searchParams.set(pName, pl);
              const resp = await fetch(t.href, { headers: { 'User-Agent': ua }, signal: AbortSignal.timeout(8000) });
              const body = await resp.text();
              if (body.includes(EXPECT) && !pl.includes(EXPECT)) {
                confirmed.push({ name: `SSTI: ${pName}`, severity: 'critical', url, evidence: { param: pName, payload: pl, marker: EXPECT, note: 'arithmetic evaluated server-side — template injection, frequently RCE' }, type: 'dast_confirmed', vuln_class: 'ssti', module: SstiConfirm.moduleName });
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
    return new ModuleResult({ module: SstiConfirm.moduleName, items: out.map(c => c.url), records: out, toolUsed: 'template-probe' });
  }
}

// Shared helpers for the Phase B confirm modules.
function dedupParamUrls(ws, scope) {
  return [...new Set([...ws.readLines('urls.txt'), ...ws.readLines('params.txt')])]
    .filter(u => /\?[^=]*=/.test(u))
    .filter(u => { if (!scope) return true; try { return scope.inScope(new URL(u).hostname); } catch { return false; } });
}
function dedupByEndpointParam(arr) {
  const seen = new Set();
  return arr.filter(c => { let k; try { k = new URL(c.url).pathname + '|' + ((c.evidence && c.evidence.param) || ''); } catch { k = c.url; } if (seen.has(k)) return false; seen.add(k); return true; });
}

module.exports = SstiConfirm;
module.exports.dedupParamUrls = dedupParamUrls;
module.exports.dedupByEndpointParam = dedupByEndpointParam;
