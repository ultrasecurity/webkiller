const dns = require('dns');
const { promisify } = require('util');
const fs = require('fs');
const { BaseModule, ModuleResult } = require('./base');
const { runTool, runToolLines } = require('../runner');
const { isInstalled } = require('../registry');

const dnsResolve4 = promisify(dns.resolve4);

class SubdomainsActive extends BaseModule {
  static moduleName = 'subdomains_active';
  static phase = 'P2';
  static toolsNeeded = ['dnsx'];

  async execute() {
    const target = this.workspace.target;
    const existing = new Set(this.workspace.readLines('subdomains.txt'));
    let newSubs = new Set();
    const toolUsed = [];
    let fallback = false;

    if (isInstalled('dnsx')) {
      this.emit('log', { msg: `Running dnsx brute-force on ${target}` });
      const wordlist = this.config.dnsWordlist || this.config.dns_wordlist || '';
      let cmd;
      if (wordlist) {
        cmd = `dnsx -d ${target} -w ${wordlist} -silent -resp-only`;
      } else {
        cmd = `dnsx -d ${target} -silent -resp-only`;
      }
      const lines = await runToolLines(cmd, 300);
      for (const l of lines) newSubs.add(l);
      toolUsed.push('dnsx');
    }

    if (isInstalled('gotator') && existing.size > 0) {
      this.emit('log', { msg: 'Running gotator permutations' });
      const subsFile = this.workspace.file('subdomains.txt');
      const result = await runTool(
        `gotator -sub ${subsFile} -perm -depth 1 -numbers 3 -mindup -adv -silent`,
        120
      );
      if (result.returncode === 0) {
        const perms = result.stdout.split('\n').map(l => l.trim()).filter(Boolean);
        for (const p of perms) newSubs.add(p);
        toolUsed.push('gotator');
      }
    }

    if (isInstalled('puredns') && newSubs.size > 0) {
      this.emit('log', { msg: `Resolving ${newSubs.size} permutations with puredns` });
      const permFile = this.workspace.file('_perms_tmp.txt');
      fs.writeFileSync(permFile, [...newSubs].join('\n'));
      const result = await runTool(`puredns resolve ${permFile} --quiet`, 300);
      if (result.returncode === 0) {
        const resolved = new Set(
          result.stdout.split('\n').map(l => l.trim()).filter(Boolean)
        );
        newSubs = resolved;
        toolUsed.push('puredns');
      }
      try { fs.unlinkSync(permFile); } catch {}
    }

    if (toolUsed.length === 0) {
      fallback = true;
      this.emit('log', { msg: 'No active tools available, using DNS A-record check' });
      newSubs = await this._dnsResolveFallback(existing, target);
      toolUsed.push('node-dns');
    }

    const combined = new Set([...existing, ...newSubs]);
    const filtered = this.scope.filterDomains([...combined].sort());
    const diff = [...new Set(filtered)].filter(s => !existing.has(s)).sort();

    if (diff.length) {
      this.workspace.appendLines('subdomains.txt', diff);
      this.workspace.appendJsonl('hosts.jsonl',
        diff.map(s => ({ subdomain: s, source: 'active', target }))
      );
    }

    return new ModuleResult({
      module: SubdomainsActive.moduleName,
      items: diff,
      toolUsed: toolUsed.join(', '),
      fallback,
    });
  }

  async _dnsResolveFallback(known, target) {
    const resolved = new Set();
    const commonPrefixes = [
      'www', 'mail', 'ftp', 'admin', 'dev', 'staging', 'api',
      'app', 'beta', 'test', 'portal', 'vpn', 'ns1', 'ns2',
      'cdn', 'static', 'assets', 'media', 'blog', 'shop',
    ];

    const checks = commonPrefixes.map(async (prefix) => {
      const sub = `${prefix}.${target}`;
      if (known.has(sub)) return;
      try {
        await dnsResolve4(sub);
        resolved.add(sub);
      } catch {
        // not resolvable
      }
    });

    await Promise.all(checks);
    return resolved;
  }
}

module.exports = SubdomainsActive;
