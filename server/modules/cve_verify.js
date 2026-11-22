const { BaseModule, ModuleResult } = require('./base');
const { runTool } = require('../runner');
const { classifyVerifiability } = require('../verify/classify');

let registry = {};
try { registry = require('../registry'); } catch { /* optional */ }
const isInstalled = registry.isInstalled || (() => true);
const toolPath = registry.toolPath || ((b) => b);

// L2 verification engine for the version-based CVE leads that service_cve emits.
// Three honest tiers, never destructive:
//   • classify (deterministic) → DoS/RCE/memory/unclear = "unverifiable" (never
//     actively tested; the UI logs the reason).
//   • Layer 1 nuclei → an in-scope template for that CVE fires = "verified".
//   • Layer 2 agent (AI/agentic only) → a model proposes SAFE GET checks; the
//     harness executes them and confirms the tell in the REAL response.
// Output: a side-file verifications.jsonl ({cve,url,status,method,reason,evidence})
// joined at render; verified leads are ALSO promoted into confirmed.jsonl with the
// SAME dedup key (vuln_class:'cve'|cve|url) so counts don't double.
class CveVerify extends BaseModule {
  static moduleName = 'cve_verify';
  static phase = 'P6a';
  static toolsNeeded = ['nuclei'];

  async execute() {
    const findings = this.workspace.readJsonl('findings.jsonl');
    const leads = findings.filter(f => f.vuln_class === 'cve' && f.type === 'potential' && f.cve);
    if (!leads.length) {
      return new ModuleResult({ module: CveVerify.moduleName, status: 'skipped', errors: ['No CVE leads to verify — run service_cve first'] });
    }

    const verifications = [];
    const promoted = [];
    const seen = new Set();
    const candidates = [];

    // 1) Classify. Unverifiable (DoS/RCE/memory/unclear) is logged and never tested.
    for (const lead of leads) {
      const key = `${lead.cve}|${lead.url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const cls = classifyVerifiability(lead);
      if (cls.verifiable) candidates.push(lead);
      else verifications.push(this._vrec(lead, 'unverifiable', null, cls.reason, null));
    }
    this.emit('log', { msg: `${seen.size} CVE lead(s): ${candidates.length} candidate(s), ${verifications.length} not safely verifiable` });

    // 2) Layer 1 — nuclei, one run per host (CVE ids differ per host).
    const stillUnverified = [];
    if (candidates.length && isInstalled('nuclei')) {
      const byUrl = new Map();
      for (const l of candidates) { if (!byUrl.has(l.url)) byUrl.set(l.url, []); byUrl.get(l.url).push(l); }
      for (const [url, group] of byUrl) {
        let fired = new Map();
        try { fired = await this._nuclei(url, group.map(l => l.cve)); } catch { fired = new Map(); }
        for (const l of group) {
          const hit = fired.get(l.cve);
          if (hit) { verifications.push(this._vrec(l, 'verified', 'nuclei', null, hit)); promoted.push(this._promote(l, 'nuclei', hit)); }
          else stillUnverified.push(l);
        }
      }
    } else {
      stillUnverified.push(...candidates);
      if (candidates.length && !isInstalled('nuclei')) this.emit('log', { msg: 'nuclei not installed — candidates stay unverified' });
    }

    // 3) Layer 2 — agent verify (agentic scans with an AI key only).
    if (stillUnverified.length && this.config.__mode === 'ai' && this._aiEnabled()) {
      let results = [];
      try {
        const { verifyLeadsWithAgent } = require('../ai/verify_agent');
        results = await verifyLeadsWithAgent(stillUnverified, { scope: this.scope, emit: this.emit });
      } catch (e) {
        results = stillUnverified.map(l => ({ lead: l, verified: false, reason: `agent verify error: ${String(e.message || e).slice(0, 60)}` }));
      }
      for (const r of results) {
        if (r.verified) { verifications.push(this._vrec(r.lead, 'verified', 'agent', null, r.evidence)); promoted.push(this._promote(r.lead, 'agent', r.evidence)); }
        else verifications.push(this._vrec(r.lead, 'unverified', null, r.reason || 'no safe check confirmed it', null));
      }
    } else {
      for (const l of stillUnverified) {
        verifications.push(this._vrec(l, 'unverified', null, 'version match only — not actively confirmed', null));
      }
    }

    if (verifications.length) this.workspace.appendJsonl('verifications.jsonl', verifications);
    if (promoted.length) this.workspace.appendJsonl('confirmed.jsonl', promoted);

    const nVerified = promoted.length;
    const nUnverifiable = verifications.filter(v => v.status === 'unverifiable').length;
    this.emit('log', { msg: `verify: ${nVerified} verified · ${nUnverifiable} not safely verifiable · ${verifications.length - nVerified - nUnverifiable} unverified` });
    return new ModuleResult({ module: CveVerify.moduleName, items: verifications.map(v => `${v.cve} ${v.status}`), records: verifications, toolUsed: 'nuclei' });
  }

  _vrec(lead, status, method, reason, evidence) {
    return { cve: lead.cve, url: lead.url, status, method: method || null, reason: reason || null, evidence: evidence || null };
  }

  // SAME dedup key as the lead so _countFindings merges them (confirmed +1,
  // findings count unchanged). Deliberately NOT the agent's record_finding.
  _promote(lead, method, evidence) {
    return {
      name: lead.name, vuln_class: 'cve', cve: lead.cve, cpe: lead.cpe,
      url: lead.url, severity: lead.severity, cvss: lead.cvss,
      type: 'dast_confirmed', module: CveVerify.moduleName,
      verification: { status: 'verified', method, evidence: evidence || null },
      evidence: { detail: (lead.evidence && lead.evidence.detail) || '', verified_by: method },
    };
  }

  async _nuclei(url, cves) {
    const fired = new Map();
    const bin = toolPath('nuclei') || 'nuclei';
    const ids = [...new Set(cves)].join(',');
    const target = /^https?:\/\//.test(url) ? url : `http://${url}`;
    // -jsonl (nuclei v3 renamed -json) + -duc (never auto-update templates mid-scan,
    // which otherwise hangs/varies by network). Templates limited to these CVE ids;
    // destructive template classes excluded (defense-in-depth).
    const res = await runTool(`${bin} -u ${target} -id ${ids} -jsonl -silent -duc -exclude-tags dos,intrusive,fuzz -timeout 10 -retries 1`, 180);
    for (const line of (res.stdout || '').split('\n')) {
      if (!line.trim()) continue;
      let d; try { d = JSON.parse(line); } catch { continue; }
      const tid = String(d['template-id'] || '');
      const m = tid.toUpperCase().match(/CVE-\d{4}-\d+/);
      const cve = m ? m[0] : cves.find(c => tid.toUpperCase().includes(String(c).toUpperCase()));
      if (cve) fired.set(cve, { matcher: d['matcher-name'] || d['template-id'], matched_at: d['matched-at'] || target, template: d['template-id'] });
    }
    return fired;
  }

  _aiEnabled() {
    try { const s = require('../ai/settings').loadPublic(); return !!(s.enabled && s.hasKey); } catch { return false; }
  }
}

module.exports = CveVerify;
