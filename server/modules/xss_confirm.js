const fs = require('fs');
const { BaseModule, ModuleResult } = require('./base');
const { runTool } = require('../runner');
const { isInstalled } = require('../registry');

class XssConfirm extends BaseModule {
  static moduleName = 'xss_confirm';
  static phase = 'P6b';
  static toolsNeeded = ['dalfox'];

  async execute() {
    const urls = this.workspace.readLines('urls.txt');
    const paramsFilePath = this.workspace.file('params.txt');
    const paramUrls = fs.existsSync(paramsFilePath) ? this.workspace.readLines('params.txt') : [];

    let targets = [...new Set([...urls, ...paramUrls])];
    targets = targets.filter(u => u.includes('?') || u.includes('='));

    if (targets.length === 0) {
      // Fall back to XSS-related findings from nuclei
      const findings = this.workspace.readJsonl('findings.jsonl');
      const xssFindings = findings.filter(f =>
        (f.name || '').toLowerCase().includes('xss') ||
        (f.template_id || '').toLowerCase().includes('xss')
      );
      if (xssFindings.length > 0) {
        targets = xssFindings.filter(f => f.url).map(f => f.url);
      }
    }

    if (targets.length === 0) {
      return new ModuleResult({
        module: XssConfirm.moduleName,
        status: 'skipped',
        errors: ['No URLs with parameters for XSS testing'],
      });
    }

    const maxUrls = this.config.xss_max_urls || 50;
    targets = targets.slice(0, maxUrls);
    let allConfirmed = [];
    const toolUsed = [];
    let fallback = false;

    if (isInstalled('dalfox')) {
      toolUsed.push('dalfox');
      allConfirmed = await this._runDalfox(targets);
    } else {
      fallback = true;
      toolUsed.push('python-reflect');
      this.emit('log', { msg: 'dalfox not available, testing reflection only' });
      allConfirmed = await this._reflectionCheck(targets);
    }

    // One finding per endpoint+parameter — the same bug is reported once per seed
    // URL (e.g. the ?q=test and ?q forms of the same endpoint).
    {
      const seen = new Set();
      allConfirmed = allConfirmed.filter(c => {
        let key; try { key = new URL(c.url).pathname + '|' + ((c.evidence && c.evidence.param) || ''); } catch { key = c.url; }
        if (seen.has(key)) return false; seen.add(key); return true;
      });
    }

    // Only DAST-confirmed findings belong in confirmed.jsonl; reflection-only
    // leads (type 'potential') go to findings.jsonl for manual review.
    const dast = allConfirmed.filter(c => c.type === 'dast_confirmed');
    if (dast.length) this.workspace.appendJsonl('confirmed.jsonl', dast);
    if (allConfirmed.length) this.workspace.appendJsonl('findings.jsonl', allConfirmed);

    return new ModuleResult({
      module: XssConfirm.moduleName,
      items: allConfirmed.map(c => c.url),
      records: allConfirmed,
      toolUsed: toolUsed.join(', '),
      fallback,
    });
  }

  async _runDalfox(targets) {
    const confirmed = [];
    const urlsFilePath = this.workspace.file('_xss_targets.txt');
    fs.writeFileSync(urlsFilePath, targets.join('\n'));

    this.emit('log', { msg: `dalfox: testing ${targets.length} URLs` });
    const result = await runTool(
      `dalfox file ${urlsFilePath} --silence --format json --timeout ${this.config.xss_timeout || 10}${this.config.xss_workers ? ` -w ${this.config.xss_workers}` : ''}${this.config.xss_delay ? ` --delay ${this.config.xss_delay}` : ''}`,
      300,
    );
    try { fs.unlinkSync(urlsFilePath); } catch { /* ignore */ }

    // dalfox exits 1 when it finds vulns (that is not an error), and v3+ emits a
    // single JSON object { findings: [...] } rather than one JSON per line — so
    // the old `rc === 0` + line-by-line parse silently dropped every finding.
    const out = (result.stdout || '').trim();
    if (!out) return confirmed;
    let findings = [];
    try {
      const parsed = JSON.parse(out);
      if (Array.isArray(parsed)) findings = parsed;
      else if (parsed && Array.isArray(parsed.findings)) findings = parsed.findings;
    } catch {
      for (const line of out.split('\n')) {
        const t = line.trim(); if (!t) continue;
        try { findings.push(JSON.parse(t)); } catch { /* skip */ }
      }
    }
    for (const data of findings) {
      // Keep dalfox's asserted-vulnerable findings (type 'V'); skip grep/info noise.
      if (data.type && data.type !== 'V') continue;
      confirmed.push({
        name: `XSS: ${data.inject_type || data.location || 'reflected'}`,
        severity: 'high',
        url: data.data || data.url || '',
        evidence: {
          type: data.inject_type || data.type || '',
          payload: data.payload || '',
          param: data.param || '',
          method: data.method || 'GET',
        },
        type: 'dast_confirmed',
        vuln_class: 'xss',
        module: XssConfirm.moduleName,
      });
    }
    return confirmed;
  }

  async _reflectionCheck(targets) {
    const canary = 'wk2xss7probe';
    const findings = [];
    const ua = this.config.user_agent || 'WebKiller/3.0';

    // Target TLS certs are often self-signed/expired; skip verification for
    // these probes only, race-safely (ref-counted, see tls_guard).
    const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
    pushInsecureTLS();

    try {
      for (const url of targets) {
        try {
          let parsed;
          try {
            parsed = new URL(url);
          } catch {
            continue;
          }
          if (!parsed.search || parsed.searchParams.size === 0) continue;

          const paramNames = [...parsed.searchParams.keys()];
          for (const paramName of paramNames) {
            const testUrl = new URL(url);
            testUrl.searchParams.set(paramName, canary);
            const resp = await fetch(testUrl.toString(), {
              headers: { 'User-Agent': ua },
              signal: AbortSignal.timeout(8000),
            });
            const text = await resp.text();
            if (text.includes(canary)) {
              findings.push({
                name: `XSS Reflection: ${paramName}`,
                severity: 'medium',
                url,
                evidence: {
                  param: paramName,
                  reflected: true,
                  note: 'Reflection found — needs manual confirmation',
                },
                type: 'potential',
                vuln_class: 'xss',
                module: XssConfirm.moduleName,
              });
              break; // one reflection per URL is enough
            }
          }
        } catch {
          // fetch error — skip URL
        }
      }
    } finally {
      popInsecureTLS();
    }

    return findings;
  }
}

module.exports = XssConfirm;
