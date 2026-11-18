const { BaseModule, ModuleResult } = require('./base');
const { runTool, runToolLines } = require('../runner');
const { isInstalled } = require('../registry');
const dns = require('dns');

class OsintDNS extends BaseModule {
  static moduleName = 'osint_dns';
  static phase = 'P7';
  static toolsNeeded = [];

  async execute() {
    const target = this.workspace.target;
    const results = [];
    const items = [];

    // WHOIS lookup
    this.emit('log', { msg: `WHOIS lookup for ${target}` });
    const whoisData = await this._whois(target);
    if (whoisData) {
      results.push({ type: 'whois', domain: target, data: whoisData });
      items.push(`WHOIS: ${target}`);
    }

    // DNS records
    this.emit('log', { msg: `DNS records for ${target}` });
    for (const rtype of ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']) {
      const records = await this._dnsQuery(target, rtype);
      if (records.length > 0) {
        results.push({ type: 'dns', domain: target, record_type: rtype, records });
        items.push(`DNS ${rtype}: ${records.length} records`);
      }
    }

    this.workspace.appendJsonl('osint.jsonl', results);
    return new ModuleResult({ module: OsintDNS.moduleName, items, records: results, toolUsed: 'whois+dns' });
  }

  async _whois(domain) {
    try {
      const result = await runTool(`whois ${domain}`, 15);
      return result.returncode === 0 ? result.stdout.slice(0, 3000) : '';
    } catch {
      return '';
    }
  }

  async _dnsQuery(domain, rtype) {
    // Prefer dnsx if available
    if (isInstalled('dnsx')) {
      const lines = await runToolLines(`dnsx -d ${domain} -silent -resp-only -${rtype.toLowerCase()}`, 15);
      return lines;
    }

    // Fallback to Node.js built-in DNS resolver
    try {
      const resolver = new dns.promises.Resolver();
      // Map record types to the appropriate dns.promises method
      switch (rtype) {
        case 'A':
          return await resolver.resolve4(domain);
        case 'AAAA':
          return await resolver.resolve6(domain);
        case 'MX': {
          const mx = await resolver.resolveMx(domain);
          return mx.map(r => `${r.priority} ${r.exchange}`);
        }
        case 'NS':
          return await resolver.resolveNs(domain);
        case 'TXT': {
          const txt = await resolver.resolveTxt(domain);
          return txt.map(r => r.join(''));
        }
        case 'CNAME':
          return await resolver.resolveCname(domain);
        case 'SOA': {
          const soa = await resolver.resolveSoa(domain);
          return [`${soa.nsname} ${soa.hostmaster} ${soa.serial} ${soa.refresh} ${soa.retry} ${soa.expire} ${soa.minttl}`];
        }
        default:
          return [];
      }
    } catch {
      return [];
    }
  }
}

module.exports = OsintDNS;
