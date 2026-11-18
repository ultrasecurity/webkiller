const { BaseModule, ModuleResult } = require('./base');
const { runTool, batchAsync } = require('../runner');
const { isInstalled } = require('../registry');

class Fingerprint extends BaseModule {
  static moduleName = 'fingerprint';
  static phase = 'P3';
  static toolsNeeded = ['wafw00f'];

  async execute() {
    const live = this.workspace.readLines('live.txt');
    if (!live.length) {
      return new ModuleResult({ module: Fingerprint.moduleName, status: 'skipped', errors: ['No live hosts'] });
    }

    const results = [];
    const items = [];

    if (isInstalled('wafw00f')) {
      const targets = live.slice(0, 30);
      this.emit('log', { msg: `WAF detection on ${targets.length} hosts (5 concurrent)` });
      const wafResults = await batchAsync(targets, 5, async (url) => {
        const result = await runTool(`wafw00f ${url} -o /dev/stdout -f json`, 30);
        try {
          const data = JSON.parse(result.stdout);
          return data.filter(e => e.firewall && e.firewall !== 'None')
            .map(e => ({ url, waf: e.firewall }));
        } catch { return []; }
      });
      for (const batch of wafResults) {
        for (const entry of batch) {
          items.push(`${entry.url} → WAF: ${entry.waf}`);
          results.push(entry);
        }
      }
    }

    const hostsData = this.workspace.readJsonl('hosts.jsonl');
    const techSummary = {};
    for (const h of hostsData) {
      for (const t of (h.tech || [])) {
        techSummary[t] = (techSummary[t] || 0) + 1;
      }
    }

    if (Object.keys(techSummary).length) {
      results.push({ type: 'tech_summary', technologies: techSummary });
    }

    this.workspace.appendJsonl('fingerprint.jsonl', results);

    return new ModuleResult({
      module: Fingerprint.moduleName,
      items,
      records: results,
      toolUsed: 'wafw00f + httpx-tech',
    });
  }
}

module.exports = Fingerprint;
