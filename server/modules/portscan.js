const { BaseModule, ModuleResult } = require('./base');
const { runTool } = require('../runner');
const { isInstalled } = require('../registry');

class Portscan extends BaseModule {
  static moduleName = 'portscan';
  static phase = 'P3';
  static toolsNeeded = ['naabu'];

  async execute() {
    const subs = this.workspace.readLines('subdomains.txt');
    if (!subs.length) {
      return new ModuleResult({ module: Portscan.moduleName, status: 'skipped', errors: ['No targets'] });
    }

    const subsFile = this.workspace.file('subdomains.txt');
    const results = [];
    let items = [];

    if (isInstalled('naabu')) {
      this.emit('log', { msg: `Port scanning ${subs.length} hosts with naabu` });
      const rateLimit = this.config.rateLimit || this.config.rate_limit || 50;
      const topPorts = this.config.top_ports || 1000;
      const portSpec = this.config.ports ? `-p ${this.config.ports}` : `-top-ports ${topPorts}`;
      const result = await runTool(
        `naabu -l ${subsFile} -silent -json ${portSpec} -rate ${rateLimit}`,
        300
      );
      for (const line of (result.stdout || '').split('\n')) {
        if (!line.trim()) continue;
        try {
          const data = JSON.parse(line);
          const host = data.host || data.ip || '';
          const port = data.port || 0;
          items.push(`${host}:${port}`);
          results.push({ host, port, protocol: data.protocol || 'tcp' });
        } catch {
          // skip non-JSON lines
        }
      }
    } else if (isInstalled('nmap')) {
      this.emit('log', { msg: 'naabu not found, falling back to nmap (slower)' });
      const targetsStr = subs.slice(0, 50).map(s => s.split(':')[0]).join(' ');
      const portSpec = this.config.ports ? `-p ${this.config.ports}` : `--top-ports ${this.config.top_ports || 100}`;
      const result = await runTool(`nmap -sT -T4 -Pn ${portSpec} -oG - ${targetsStr}`, 300);
      // Parse grepable output into host/port records so ports.jsonl is actually
      // populated (the old path only built display strings, leaving ports.jsonl
      // empty — which silently starved service_cve on nmap-only hosts).
      for (const line of (result.stdout || '').split('\n')) {
        const hm = /^Host:\s+(\S+)/.exec(line);
        const pm = line.match(/Ports:\s*(.+)$/);
        if (!hm || !pm) continue;
        const host = hm[1];
        for (const seg of pm[1].split(',')) {
          const m = /\s*(\d+)\/open\/(tcp|udp)/.exec(seg);
          if (m) { items.push(`${host}:${m[1]}`); results.push({ host, port: parseInt(m[1], 10), protocol: m[2] }); }
        }
      }
    } else {
      return new ModuleResult({
        module: Portscan.moduleName,
        status: 'skipped',
        errors: ['No port scanner installed'],
      });
    }

    this.workspace.appendJsonl('ports.jsonl', results);

    return new ModuleResult({
      module: Portscan.moduleName,
      items,
      records: results,
      toolUsed: isInstalled('naabu') ? 'naabu' : 'nmap',
    });
  }
}

module.exports = Portscan;
