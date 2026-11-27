const crypto = require('crypto');
const fs = require('fs');
const { BaseModule, ModuleResult } = require('./base');

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

class Tagging extends BaseModule {
  static moduleName = 'tagging';
  static phase = 'P8';
  static toolsNeeded = [];

  async execute() {
    const findings = this.workspace.readJsonl('findings.jsonl');
    const confirmed = this.workspace.readJsonl('confirmed.jsonl');

    if (findings.length === 0 && confirmed.length === 0) {
      return new ModuleResult({ module: Tagging.moduleName, status: 'skipped', errors: ['No findings to process'] });
    }

    this.emit('log', { msg: `Processing ${findings.length} findings + ${confirmed.length} confirmed` });

    const deduped = this._dedup(findings);
    const tagged = this._tagSeverity(deduped);
    const grouped = this._groupByClass(tagged);

    const summary = {
      total_raw: findings.length,
      total_confirmed: confirmed.length,
      total_unique: deduped.length,
      by_severity: {},
      by_class: {},
    };

    for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
      const count = tagged.filter(f => f.severity === sev).length;
      if (count) {
        summary.by_severity[sev] = count;
      }
    }

    for (const [cls, items] of Object.entries(grouped)) {
      summary.by_class[cls] = items.length;
    }

    this.workspace.appendJsonl('findings_deduped.jsonl', deduped);

    const reportLines = this._buildReport(summary, tagged, confirmed);
    const reportPath = this.workspace.file('report.md');
    fs.writeFileSync(reportPath, reportLines.join('\n'), 'utf8');

    const summaryPath = this.workspace.file('summary.json');
    fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2), 'utf8');

    return new ModuleResult({
      module: Tagging.moduleName,
      items: Object.entries(summary.by_severity).map(([k, v]) => `${k}: ${v}`),
      records: [summary],
      toolUsed: 'python-tagger',
      fallback: false,
    });
  }

  _dedup(findings) {
    const seen = new Set();
    const unique = [];
    for (const f of findings) {
      const key = this._findingKey(f);
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(f);
      }
    }
    return unique;
  }

  _findingKey(f) {
    const parts = [
      f.name || '',
      f.url || '',
      f.vuln_class || '',
      f.template_id || '',
    ];
    const raw = parts.map(String).join('|');
    return crypto.createHash('md5').update(raw).digest('hex');
  }

  _tagSeverity(findings) {
    for (const f of findings) {
      if (!f.severity) {
        f.severity = this._inferSeverity(f);
      }
    }
    return findings.sort((a, b) => {
      const sa = SEVERITY_ORDER[a.severity || 'info'] ?? 4;
      const sb = SEVERITY_ORDER[b.severity || 'info'] ?? 4;
      return sa - sb;
    });
  }

  _inferSeverity(f) {
    const name = ((f.name || '') + ' ' + (f.vuln_class || '')).toLowerCase();
    if (['sqli', 'rce', 'command injection', 'ssrf', 'ssti'].some(w => name.includes(w))) {
      return 'critical';
    }
    if (['xss', 'idor', 'secret', 'private key', 'token'].some(w => name.includes(w))) {
      return 'high';
    }
    if (['redirect', 'cors', 'csrf', 'header injection'].some(w => name.includes(w))) {
      return 'medium';
    }
    if (['info', 'disclosure', 'version', 'server'].some(w => name.includes(w))) {
      return 'low';
    }
    return 'info';
  }

  _groupByClass(findings) {
    const groups = {};
    for (const f of findings) {
      const cls = f.vuln_class || f.type || 'other';
      if (!groups[cls]) groups[cls] = [];
      groups[cls].push(f);
    }
    return groups;
  }

  _buildReport(summary, findings, confirmed) {
    const lines = [
      '# WebKiller 3.0 — Recon Report',
      '',
      `**Total findings:** ${summary.total_unique} unique (${summary.total_confirmed} confirmed)`,
      '',
      '## Severity Breakdown',
      '',
    ];

    const emojiMap = { critical: '!!!', high: '!!', medium: '!', low: '.', info: '-' };
    for (const [sev, count] of Object.entries(summary.by_severity)) {
      lines.push(`- [${emojiMap[sev] || '?'}] ${sev.toUpperCase()}: ${count}`);
    }

    lines.push('', '## Vulnerability Classes', '');
    for (const [cls, count] of Object.entries(summary.by_class)) {
      lines.push(`- ${cls}: ${count}`);
    }

    if (confirmed.length > 0) {
      lines.push('', '## Confirmed Vulnerabilities', '');
      for (const c of confirmed) {
        lines.push(`### ${c.name || 'Unknown'}`);
        lines.push(`- **URL:** \`${c.url || ''}\``);
        lines.push(`- **Severity:** ${c.severity || 'unknown'}`);
        const ev = c.evidence || {};
        if (Object.keys(ev).length > 0) {
          lines.push(`- **Evidence:** \`${JSON.stringify(ev).slice(0, 200)}\``);
        }
        lines.push('');
      }
    }

    if (findings.length > 0) {
      lines.push('', '## All Findings', '');
      for (const f of findings.slice(0, 50)) {
        lines.push(`- [${f.severity || '?'}] ${f.name || '?'} — \`${f.url || ''}\``);
      }
    }

    return lines;
  }
}

module.exports = Tagging;
