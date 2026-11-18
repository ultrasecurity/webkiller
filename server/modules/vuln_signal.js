const { BaseModule, ModuleResult } = require('./base');
const { runTool } = require('../runner');
const { isInstalled } = require('../registry');

class VulnSignal extends BaseModule {
  static moduleName = 'vuln_signal';
  static phase = 'P6a';
  static toolsNeeded = ['nuclei'];

  async execute() {
    const live = this.workspace.readLines('live.txt');
    if (live.length === 0) {
      return new ModuleResult({ module: VulnSignal.moduleName, status: 'skipped', errors: ['No live hosts'] });
    }

    if (!isInstalled('nuclei')) {
      return new ModuleResult({ module: VulnSignal.moduleName, status: 'skipped', errors: ['nuclei not installed'] });
    }

    const liveFile = this.workspace.file('live.txt');
    const findings = [];
    const items = [];

    this.emit('log', { msg: `Running nuclei on ${live.length} targets (passive templates)` });
    const rateLimit = this.config.rate_limit || 50;
    const severity = this.config.nuclei_severity || 'critical,high,medium';
    const tags = this.config.nuclei_tags ? ` -tags ${this.config.nuclei_tags}` : '';
    const nTimeout = this.config.nuclei_timeout || 15;
    const conc = this.config.nuclei_concurrency ? ` -c ${this.config.nuclei_concurrency}` : '';
    const result = await runTool(
      `nuclei -l ${liveFile} -silent -json -severity ${severity}${tags} -type http -rate-limit ${rateLimit} -timeout ${nTimeout}${conc} -retries 1`,
      600,
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
          type: data.type || '',
          matched: data['matcher-name'] || '',
          extracted: data['extracted-results'] || [],
          tags: info.tags || [],
        };
        findings.push(finding);
        items.push(`[${finding.severity.toUpperCase()}] ${finding.name} → ${finding.url}`);
        this.emit('finding', { severity: finding.severity, name: finding.name, url: finding.url });
      } catch {
        // JSON parse error — skip line
      }
    }

    this.workspace.appendJsonl('findings.jsonl', findings);
    return new ModuleResult({ module: VulnSignal.moduleName, items, records: findings, toolUsed: 'nuclei' });
  }
}

module.exports = VulnSignal;
