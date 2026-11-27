const { BaseModule, ModuleResult } = require('./base');
const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');

// POST a body carrying privileged fields; if the response reflects one back that
// a benign baseline did NOT, the server mass-assigned attacker-controlled fields.
const ELEVATED = { name: 'wk_probe', role: 'admin', is_admin: true, isAdmin: true, admin: true, verified: true, isAdministrator: true, account_type: 'admin' };
const CHECKS = [/"role"\s*:\s*"admin"/i, /"is_admin"\s*:\s*true/i, /"isAdmin"\s*:\s*true/i, /"admin"\s*:\s*true/i, /"isAdministrator"\s*:\s*true/i, /"account_type"\s*:\s*"admin"/i];

class MassAssignConfirm extends BaseModule {
  static moduleName = 'massassign_confirm';
  static phase = 'P6d';
  static toolsNeeded = [];

  async execute() {
    const candidates = endpointCandidates(this.workspace, this.scope, true);
    if (!candidates.length) return new ModuleResult({ module: MassAssignConfirm.moduleName, status: 'skipped', errors: ['No candidate endpoints'] });
    const ua = this.config.user_agent || 'WebKiller/3.0';
    const confirmed = [];
    pushInsecureTLS();
    try {
      for (const ep of candidates.slice(0, this.config.massassign_max_urls || 60)) {
        try {
          const base = await postJson(ep, '{"name":"wk_baseline"}', ua);
          const elev = await postJson(ep, JSON.stringify(ELEVATED), ua);
          for (const re of CHECKS) {
            if (re.test(elev) && !re.test(base)) {
              // Medium, not high: a response reflecting the field is a strong
              // candidate but not proof it persisted — that needs a re-fetch of
              // the resource, which is app-specific.
              confirmed.push({ name: 'Mass assignment (candidate)', severity: 'medium', url: ep, evidence: { matched: (elev.match(re) || [''])[0], note: 'privileged field accepted into the response; verify it persists by re-fetching the resource' }, type: 'dast_confirmed', vuln_class: 'mass_assignment', module: MassAssignConfirm.moduleName });
              break;
            }
          }
        } catch { /* skip */ }
      }
    } finally { popInsecureTLS(); }
    const out = dedup(confirmed);
    if (out.length) { this.workspace.appendJsonl('confirmed.jsonl', out); this.workspace.appendJsonl('findings.jsonl', out); }
    return new ModuleResult({ module: MassAssignConfirm.moduleName, items: out.map(c => c.url), records: out, toolUsed: 'field-injection' });
  }
}

// Shared across the Phase C confirm modules.
// Paths that look state-changing/destructive — never POST active payloads to
// them even in scope (could create, delete, charge, or notify).
const DESTRUCTIVE = /(delete|destroy|remove|logout|signout|sign-out|unsubscribe|\bcancel\b|refund|payment|checkout|purchase|\border\b|invite|deactivate|revoke|disable|wipe|terminate|withdraw|transfer|\bsend\b|\bpay\b|\bemail\b|\breset\b)/i;
function endpointCandidates(ws, scope, safeOnly) {
  const set = new Set();
  for (const u of [...ws.readLines('urls.txt'), ...ws.readLines('live.txt')]) {
    try {
      const p = new URL(u);
      if (scope && !scope.inScope(p.hostname)) continue;          // never leave scope
      if (safeOnly && DESTRUCTIVE.test(p.pathname)) continue;     // never POST to destructive-looking paths
      set.add(p.origin + p.pathname);
    } catch { /* skip */ }
  }
  return [...set];
}
async function postJson(url, body, ua) {
  const resp = await fetch(url, { method: 'POST', headers: { 'User-Agent': ua, 'Content-Type': 'application/json' }, body, signal: AbortSignal.timeout(8000) });
  return await resp.text();
}
function dedup(arr) { const s = new Set(); return arr.filter(c => { if (s.has(c.url)) return false; s.add(c.url); return true; }); }

module.exports = MassAssignConfirm;
module.exports.endpointCandidates = endpointCandidates;
module.exports.postJson = postJson;
module.exports.dedupEndpoints = dedup;
