const { BaseModule, ModuleResult } = require('./base');
const { runTool } = require('../runner');
const { isInstalled } = require('../registry');

class VulnConfirm extends BaseModule {
  static moduleName = 'vuln_confirm';
  static phase = 'P6b';
  static toolsNeeded = ['nuclei'];

  async execute() {
    const urls = this.workspace.readLines('urls.txt');
    if (urls.length === 0) {
      return new ModuleResult({ module: VulnConfirm.moduleName, status: 'skipped', errors: ['No URLs to test'] });
    }

    if (!isInstalled('nuclei')) {
      return new ModuleResult({ module: VulnConfirm.moduleName, status: 'skipped', errors: ['nuclei not installed'] });
    }

    const urlsFile = this.workspace.file('urls.txt');
    const confirmed = [];
    const items = [];

    this.emit('log', { msg: `Running nuclei DAST on ${urls.length} URLs` });
    const rateLimit = this.config.rate_limit || 30;
    const result = await runTool(
      `nuclei -l ${urlsFile} -silent -json -dast -severity critical,high,medium -rate-limit ${rateLimit} -timeout 20 -retries 0`,
      900,
    );

    for (const line of (result.stdout || '').split('\n')) {
      if (!line.trim()) continue;
      try {
        const data = JSON.parse(line);
        const info = data.info || {};
        const finding = {
          template_id: data['template-id'] || '',
          name: info.name || '',
          severity: info.severity || '',
          url: data['matched-at'] || data.host || '',
          type: 'dast_confirmed',
          matched: data['matcher-name'] || '',
          curl_command: data['curl-command'] || '',
          extracted: data['extracted-results'] || [],
          evidence: {
            request: (data.request || '').slice(0, 500),
            response: (data.response || '').slice(0, 500),
          },
        };
        confirmed.push(finding);
        items.push(`[CONFIRMED:${finding.severity.toUpperCase()}] ${finding.name} → ${finding.url}`);
        this.emit('confirmed', { severity: finding.severity, name: finding.name, url: finding.url });
      } catch {
        // JSON parse error — skip line
      }
    }

    this.workspace.appendJsonl('confirmed.jsonl', confirmed);
    return new ModuleResult({ module: VulnConfirm.moduleName, items, records: confirmed, toolUsed: 'nuclei-dast' });
  }
}

module.exports = VulnConfirm;
