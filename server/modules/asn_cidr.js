const { BaseModule, ModuleResult } = require('./base');
const { runTool } = require('../runner');
const dns = require('dns');

// Wide-recon / asset expansion: resolve the target to IP(s), map each IP to its
// ASN + announced BGP prefix via Team Cymru's IP-to-ASN whois, then (optionally)
// expand the ASN to every prefix it announces via RADB — turning one host into
// the org's full IP footprint. Passive, read-only (public whois), no tool to
// install (uses the system `whois`, like osint_dns).

class AsnCidr extends BaseModule {
  static moduleName = 'asn_cidr';
  static phase = 'P1';
  static toolsNeeded = [];

  async execute() {
    const ips = await this._targetIps();
    if (!ips.length) {
      return new ModuleResult({ module: AsnCidr.moduleName, status: 'skipped', errors: ['No resolvable IP for target'] });
    }

    const items = [];
    const records = [];
    const seenAsn = new Set();
    const maxIps = this.config.asn_max_ips || 10;

    for (const ip of ips.slice(0, maxIps)) {
      const info = await this._cymru(ip);
      if (!info || !info.asn) continue;
      records.push({ type: 'asn', ip, asn: info.asn, cidr: info.prefix, as_name: info.name, cc: info.cc, registry: info.registry });
      items.push(`${ip} → AS${info.asn} ${info.prefix} (${info.name})`);
      this.emit('log', { msg: `${ip} → AS${info.asn} · ${info.prefix} · ${info.name}` });

      if (!seenAsn.has(info.asn)) {
        seenAsn.add(info.asn);
        const prefixes = await this._radbPrefixes(info.asn);
        if (prefixes.length) {
          const cap = this.config.asn_max_prefixes || 200;
          records.push({ type: 'asn_ranges', asn: info.asn, as_name: info.name, prefix_count: prefixes.length, prefixes: prefixes.slice(0, cap) });
          items.push(`AS${info.asn} announces ${prefixes.length} prefixes${prefixes.length > cap ? ` (showing ${cap})` : ''}`);
          this.emit('log', { msg: `AS${info.asn} announces ${prefixes.length} prefixes` });
        }
      }
    }

    if (records.length) this.workspace.appendJsonl('osint.jsonl', records);
    return new ModuleResult({ module: AsnCidr.moduleName, items, records, toolUsed: 'whois' });
  }

  async _targetIps() {
    const host = String(this.workspace.target || '').replace(/:\d+$/, '');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return [host];
    try { return await dns.promises.resolve4(host); } catch { return []; }
  }

  // Team Cymru bulk whois: " -v <ip>" returns
  // "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name"
  async _cymru(ip) {
    const r = await runTool(`whois -h whois.cymru.com " -v ${ip}"`, 20);
    if (r.returncode !== 0 || !r.stdout) return null;
    for (const line of r.stdout.trim().split('\n')) {
      if (!line.includes('|') || /^\s*AS\s*\|/i.test(line)) continue; // skip header
      const c = line.split('|').map(s => s.trim());
      if (c.length >= 7 && /^\d+$/.test(c[0])) {
        return { asn: c[0], prefix: c[2], cc: c[3], registry: c[4], name: c[6] };
      }
    }
    return null;
  }

  // RADB route objects for an ASN → every announced prefix (v4 + v6).
  async _radbPrefixes(asn) {
    const r = await runTool(`whois -h whois.radb.net -- "-i origin AS${asn}"`, 25);
    if (r.returncode !== 0 || !r.stdout) return [];
    const out = [];
    for (const line of r.stdout.split('\n')) {
      const m = line.match(/^route6?:\s*(\S+)/i);
      if (m) out.push(m[1]);
    }
    return [...new Set(out)];
  }
}

module.exports = AsnCidr;
