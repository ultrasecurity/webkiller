const { BaseModule, ModuleResult } = require('./base');
const { runToolLines } = require('../runner');
const { isInstalled } = require('../registry');

class SubdomainsPassive extends BaseModule {
  static moduleName = 'subdomains_passive';
  static phase = 'P1';
  static toolsNeeded = ['subfinder'];

  async execute() {
    const target = this.workspace.target;
    const allSubs = new Set();
    const toolUsed = [];
    let fallback = false;

    if (isInstalled('subfinder')) {
      this.emit('log', { msg: `Running subfinder on ${target}` });
      const lines = await runToolLines(
        `subfinder -d ${target} -silent ${this.config.subfinder_all === false ? '' : '-all '}-timeout ${this.config.subfinder_timeout || 30}`,
        120
      );
      for (const l of lines) allSubs.add(l);
      toolUsed.push('subfinder');
    }

    this.emit('log', { msg: `Querying crt.sh for ${target}` });
    const crtSubs = await this._crtsh(target);
    if (crtSubs.length) {
      for (const s of crtSubs) allSubs.add(s);
      toolUsed.push('crt.sh');
      if (!isInstalled('subfinder')) {
        fallback = true;
      }
    }

    if (isInstalled('subfinder') && isInstalled('github-subdomains')) {
      const lines = await runToolLines(
        `github-subdomains -d ${target} -raw -o /dev/stdout`,
        60
      );
      for (const l of lines) allSubs.add(l);
      toolUsed.push('github-subdomains');
    }

    let filtered = this.scope.filterDomains([...allSubs]);
    filtered = [...new Set(filtered.map(s => s.toLowerCase().trim()).filter(Boolean))].sort();

    this.workspace.appendLines('subdomains.txt', filtered);
    this.workspace.appendJsonl('hosts.jsonl',
      filtered.map(s => ({ subdomain: s, source: 'passive', target }))
    );

    return new ModuleResult({
      module: SubdomainsPassive.moduleName,
      items: filtered,
      toolUsed: toolUsed.join(', '),
      fallback,
    });
  }

  async _crtsh(domain) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 30000);
      const resp = await fetch(
        `https://crt.sh/?q=%.${domain}&output=json`,
        {
          signal: controller.signal,
          headers: { 'User-Agent': this.config.userAgent || 'WebKiller/3.0' },
        }
      );
      clearTimeout(timer);

      if (!resp.ok) return [];

      const data = await resp.json();
      const subs = new Set();
      for (const entry of data) {
        const nameValue = entry.name_value || '';
        for (let line of nameValue.split('\n')) {
          line = line.trim().toLowerCase();
          if (line && !line.startsWith('*')) {
            subs.add(line);
          }
        }
      }
      return [...subs];
    } catch (e) {
      this.emit('log', { msg: `crt.sh error: ${e.message}` });
      return [];
    }
  }
}

module.exports = SubdomainsPassive;
