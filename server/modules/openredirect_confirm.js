const { BaseModule, ModuleResult } = require('./base');
const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
const { dedupByEndpointParam, dedupParamUrls } = require('./ssti_confirm');

// Point redirect-like parameters at a unique attacker host (with filter-evasion
// variants) and follow NO redirect; if the Location header targets that host,
// it's an open redirect.
const EVIL = 'wk-redirect-oob.example';
const PAYLOADS = [`https://${EVIL}/`, `//${EVIL}/`, `https:/${EVIL}/`, `https:\\\\${EVIL}/`, `/\\${EVIL}/`];
const REDIR_PARAMS = /^(url|redirect|redirect_uri|redirecturl|redirect_url|next|return|returnurl|returnto|return_url|dest|destination|continue|to|goto|out|target|redir|go|next_url|link|forward|u|r)$/i;

class OpenRedirectConfirm extends BaseModule {
  static moduleName = 'openredirect_confirm';
  static phase = 'P6d';
  static toolsNeeded = [];

  async execute() {
    const urls = dedupParamUrls(this.workspace, this.scope);
    if (!urls.length) return new ModuleResult({ module: OpenRedirectConfirm.moduleName, status: 'skipped', errors: ['No parameterized URLs'] });
    const ua = this.config.user_agent || 'WebKiller/2.0';
    const confirmed = [];
    pushInsecureTLS();
    try {
      for (const url of urls.slice(0, this.config.openredir_max_urls || 50)) {
        let parsed; try { parsed = new URL(url); } catch { continue; }
        const rparams = [...parsed.searchParams.keys()].filter(k => REDIR_PARAMS.test(k));
        if (!rparams.length) continue;
        let hit = false;
        for (const pName of rparams) {
          for (const pl of PAYLOADS) {
            try {
              const t = new URL(url); t.searchParams.set(pName, pl);
              const resp = await fetch(t.href, { headers: { 'User-Agent': ua }, redirect: 'manual', signal: AbortSignal.timeout(8000) });
              const loc = resp.headers.get('location') || '';
              let locHost = ''; try { locHost = new URL(loc, url).hostname; } catch { /* unparseable */ }
              if (resp.status >= 300 && resp.status < 400 && locHost === EVIL) {
                confirmed.push({ name: `Open redirect: ${pName}`, severity: 'medium', url, evidence: { param: pName, payload: pl, location: loc, note: 'redirect Location points to an attacker-controlled host' }, type: 'dast_confirmed', vuln_class: 'open_redirect', module: OpenRedirectConfirm.moduleName });
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
    return new ModuleResult({ module: OpenRedirectConfirm.moduleName, items: out.map(c => c.url), records: out, toolUsed: 'redirect-probe' });
  }
}
module.exports = OpenRedirectConfirm;
