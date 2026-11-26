const { BaseModule, ModuleResult } = require('./base');
const { runTool } = require('../runner');
const { runPrivileged } = require('../privileged');

let registry = {};
try { registry = require('../registry'); } catch { /* optional */ }
const isInstalled = registry.isInstalled || (() => true);
const toolPath = registry.toolPath || ((b) => b);

// L2 — service-version intelligence. After portscan finds open ports, nmap -sV
// reads each service's version banner → CPE → NVD maps the CPE to known CVEs.
//
// These are VERSION-BASED LEADS, not proof: a matching version is necessary but
// not sufficient — the service may be back-ported/patched, a honeypot, or serving
// a faked banner. So every CVE is written to findings.jsonl with
// type:'potential', confidence:'version-based' (NEVER to confirmed.jsonl), so the
// engine never counts them as confirmed and the UI badges them "unverified".
//
// OS detection (`nmap -O`) needs root; it runs via the macOS admin helper only
// when the user enabled it AND the engine acquired root upfront
// (config.__rootGranted). Otherwise it degrades silently to version-only.
class ServiceCve extends BaseModule {
  static moduleName = 'service_cve';
  static phase = 'P3';
  static toolsNeeded = ['nmap'];

  async execute() {
    if (!isInstalled('nmap')) {
      return new ModuleResult({ module: ServiceCve.moduleName, status: 'skipped', errors: ['nmap not installed'] });
    }

    // host -> Set(open ports), from portscan output, in-scope only.
    const byHost = new Map();
    for (const r of this.workspace.readJsonl('ports.jsonl')) {
      const host = r.host || r.ip;
      const port = parseInt(r.port, 10);
      if (!host || !port) continue;
      if (this.scope && this.scope.inScope && !this.scope.inScope(host)) continue;
      if (!byHost.has(host)) byHost.set(host, new Set());
      byHost.get(host).add(port);
    }
    if (!byHost.size) {
      return new ModuleResult({ module: ServiceCve.moduleName, status: 'skipped', errors: ['No open ports from portscan — run portscan first'] });
    }

    const maxHosts = Math.max(1, parseInt(this.config.svc_cve_max_hosts, 10) || 15);
    const maxPerCpe = Math.max(1, Math.min(15, parseInt(this.config.svc_cve_max_per_cpe, 10) || 5));
    // How the engine's pre-flight decided we can elevate (set in engine._preflightRoot):
    // 'caps' (Linux, no prompt), 'osascript' (mac, must be granted), 'pkexec' (Linux, lazy prompt).
    const osMethod = this.config.__osElevation || 'none';
    const osGranted = osMethod === 'caps' || osMethod === 'pkexec' || (osMethod === 'osascript' && this.config.__osascriptGranted);
    const osDetect = !!this.config.svc_cve_os_detect && osGranted;
    const nmapBin = toolPath('nmap') || 'nmap';

    const services = [];
    const leads = [];
    const cveCache = new Map(); // cpe23 -> [cve] — dedupe NVD calls within a scan
    this._lastNvd = 0;
    this._osGaveUp = false; // once the user declines an elevation prompt, stop re-prompting for later hosts
    let hostCount = 0;

    for (const [host, portSet] of byHost) {
      if (hostCount >= maxHosts) break;
      // Defense-in-depth: the OS-detect path runs nmap through a shell (osascript
      // "do shell script"), so refuse any host that isn't a plain hostname/IP —
      // it can never carry shell metacharacters into that command.
      if (!/^[a-zA-Z0-9._:-]+$/.test(host)) { this.emit('log', { msg: `skip host with unusual characters: ${host}` }); continue; }
      hostCount++;
      const ports = [...portSet].sort((a, b) => a - b).slice(0, 50).join(',');
      this.emit('log', { msg: `nmap -sV${osDetect ? ' -O' : ''} ${host} :${ports}` });

      const xml = await this._runNmap(nmapBin, host, ports, (osDetect && !this._osGaveUp) ? osMethod : null);
      if (!xml) continue;
      const parsed = this._parseNmapXml(xml);

      for (const svc of parsed.services) {
        services.push({
          host, port: svc.port, protocol: svc.protocol,
          service: svc.name, product: svc.product, version: svc.version,
          extrainfo: svc.extrainfo, cpe: svc.cpes,
        });
        for (const cpe of svc.cpes) {
          for (const c of await this._cvesFor(cpe, cveCache, maxPerCpe)) leads.push(this._lead(host, svc, cpe, c));
        }
      }

      if (parsed.os && parsed.os.name) {
        services.push({ host, kind: 'os', os: parsed.os.name, accuracy: parsed.os.accuracy, cpe: parsed.os.cpes });
        const osSvc = { port: 0, name: 'os', product: parsed.os.name, version: '' };
        for (const cpe of parsed.os.cpes) {
          for (const c of await this._cvesFor(cpe, cveCache, maxPerCpe)) leads.push(this._lead(host, osSvc, cpe, c));
        }
      }
    }

    if (services.length) this.workspace.appendJsonl('services.jsonl', services);
    // Version-based leads go to findings.jsonl ONLY — never confirmed.jsonl — so
    // _countFindings keeps them out of the "confirmed" tally.
    if (leads.length) this.workspace.appendJsonl('findings.jsonl', leads);

    const items = services.map(s => s.kind === 'os'
      ? `${s.host} OS: ${s.os}`
      : `${s.host}:${s.port} ${[s.product, s.version].filter(Boolean).join(' ') || s.service || ''}`.trim());
    this.emit('log', { msg: `${services.length} service record(s), ${leads.length} CVE lead(s) (version-based, unverified)` });

    return new ModuleResult({ module: ServiceCve.moduleName, items, records: services, toolUsed: 'nmap' });
  }

  // method: null = unprivileged -sV; 'caps' = nmap --privileged -O (Linux, no
  // prompt); 'osascript'/'pkexec' = nmap -O via the privileged runner (argv, no
  // shell). --host-timeout bounds each host so an un-killable privileged nmap
  // can't outlive the scan.
  async _runNmap(bin, host, ports, method) {
    const common = ['-sV', '-Pn', '-T4', '--host-timeout', '90s', '-oX', '-', '-p', ports, host];
    if (method) {
      const osArgs = ['-O', ...common];
      if (method === 'caps') {
        // Binary carries cap_net_raw — run directly (own euid) with --privileged.
        const res = await runTool(`${bin} --privileged ${osArgs.join(' ')}`, 240);
        if (res.returncode === 0 && res.stdout) return res.stdout;
        this.emit('log', { msg: 'capability-based nmap -O failed — version-only' });
      } else {
        const r = await runPrivileged(bin, osArgs, { timeout: 240 });
        if (r.ok && r.stdout) return r.stdout;
        // On cancel, stop prompting for the remaining hosts (pkexec has no cache, so
        // otherwise a multi-host scan could throw one dialog per host).
        if (r.canceled) this._osGaveUp = true;
        this.emit('log', { msg: r.canceled ? 'OS detection declined — version-only for the rest of this scan' : 'privileged nmap -O failed — version-only' });
        // On a privileged TIMEOUT the elevated nmap may still be running; don't
        // double-hit the same host with a second (unprivileged) scan.
        if (r.timedOut) return '';
      }
    }
    const res = await runTool(`${bin} ${common.join(' ')}`, 180);
    return res.stdout || '';
  }

  _lead(host, svc, cpe, c) {
    return {
      name: `${c.id} — ${[svc.product, svc.version].filter(Boolean).join(' ') || svc.name || 'service'}`.trim(),
      vuln_class: 'cve',
      type: 'potential',
      confidence: 'version-based',
      severity: c.severity || 'info',
      cvss: c.cvss,
      cve: c.id,
      cpe,
      cwe: c.cwe || [],
      summary: c.summary || '', // full NVD description — classifier input (display uses evidence.detail)
      url: svc.port ? `${host}:${svc.port}` : host,
      module: ServiceCve.moduleName,
      evidence: { detail: `nmap -sV banner → ${cpe}. ${c.summary || ''}`.slice(0, 600), version_based: true },
    };
  }

  // ── CVE lookup (NVD 2.0, keyless; optional NVD_API_KEY for higher limits) ──

  async _cvesFor(cpe, cache, maxPerCpe) {
    const match = this._toCpe23(cpe);
    if (!match) return [];
    if (cache.has(match)) return cache.get(match);
    let out = [];
    try { out = await this._nvdQuery(match, maxPerCpe); }
    catch (e) { this.emit('log', { msg: `NVD lookup failed (${cpe}): ${String(e.message || e).slice(0, 80)}` }); out = []; }
    cache.set(match, out);
    return out;
  }

  // nmap emits CPE 2.2 (cpe:/a:apache:http_server:2.2.8). NVD virtualMatchString
  // wants CPE 2.3 (cpe:2.3:a:apache:http_server:2.2.8). Require a version so the
  // match is specific — a versionless CPE would pull in every CVE for the product.
  _toCpe23(cpe) {
    const m = /^cpe:\/([aoh]):([^:]+):([^:]+)(?::([^:]+))?/.exec(String(cpe || ''));
    if (!m) return null;
    const [, part, vendor, product, version] = m;
    if (!version) return null;
    return `cpe:2.3:${part}:${vendor}:${product}:${version}`;
  }

  async _nvdQuery(matchString, maxPerCpe) {
    // NVD keyless limit is 5 requests / rolling 30s. Pace calls ~6.5s apart.
    const key = process.env.NVD_API_KEY || this.config.nvd_api_key;
    const gap = key ? 800 : 6500;
    const wait = this._lastNvd + gap - Date.now();
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    this._lastNvd = Date.now();

    return new Promise((resolve, reject) => {
      const https = require('https');
      const params = new URLSearchParams({ virtualMatchString: matchString, resultsPerPage: String(Math.min(30, maxPerCpe * 3)) });
      const headers = { 'User-Agent': 'WebKiller/2.0' };
      if (key) headers.apiKey = key;
      const req = https.get(`https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`, { headers, timeout: 20000 }, (res) => {
        if (res.statusCode && res.statusCode !== 200) { res.resume(); return reject(new Error(`NVD HTTP ${res.statusCode}`)); }
        let data = '';
        // Without these, a mid-stream disconnect (ECONNRESET / graceful FIN after
        // headers) emits 'error'/'aborted' on res with no listener, so the Promise
        // never settles and the whole scan hangs (base.run has no timeout).
        res.on('error', reject);
        res.on('aborted', () => reject(new Error('NVD response aborted')));
        res.on('data', c => { data += c; if (data.length > 8 * 1024 * 1024) res.destroy(new Error('response too large')); });
        res.on('end', () => {
          try {
            const j = JSON.parse(data);
            const vulns = Array.isArray(j.vulnerabilities) ? j.vulnerabilities : [];
            const cves = vulns.map(v => this._cveFromNvd(v.cve)).filter(Boolean);
            cves.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
            resolve(cves.slice(0, maxPerCpe));
          } catch (e) { reject(e); }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => req.destroy(new Error('timeout')));
    });
  }

  _cveFromNvd(cve) {
    if (!cve || !cve.id) return null;
    const desc = (cve.descriptions || []).find(d => d.lang === 'en');
    const m = cve.metrics || {};
    const pick = (m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0];
    const cvss = pick && pick.cvssData ? pick.cvssData.baseScore : undefined;
    let severity = pick && ((pick.cvssData && pick.cvssData.baseSeverity) || pick.baseSeverity);
    severity = String(severity || this._sevFromScore(cvss) || 'info').toLowerCase();
    // CWE ids are the strongest signal for the verifiability classifier; keep them
    // plus the full (untruncated) description so classification runs on clean data.
    const cwe = (cve.weaknesses || [])
      .flatMap(w => (w.description || []).map(d => d.value))
      .filter(v => /^CWE-\d+$/.test(v));
    return { id: cve.id, cvss, severity, summary: desc ? desc.value : '', cwe: [...new Set(cwe)] };
  }

  _sevFromScore(s) {
    if (s == null) return null;
    if (s >= 9) return 'critical';
    if (s >= 7) return 'high';
    if (s >= 4) return 'medium';
    if (s > 0) return 'low';
    return 'info';
  }

  // ── nmap XML parsing (regex over nmap's stable XML) ──

  _parseNmapXml(xml) {
    const services = [];
    const portRe = /<port\b[^>]*\bprotocol="([^"]*)"[^>]*\bportid="([^"]*)"[^>]*>([\s\S]*?)<\/port>/g;
    let pm;
    while ((pm = portRe.exec(xml))) {
      const [, protocol, portid, inner] = pm;
      if (!/<state\b[^>]*\bstate="open"/.test(inner)) continue;
      const svcM = /<service\b([^>]*?)\/?>/.exec(inner);
      const attrs = svcM ? this._attrs(svcM[1]) : {};
      const cpes = [];
      const cpeRe = /<cpe>([^<]+)<\/cpe>/g;
      let cm;
      while ((cm = cpeRe.exec(inner))) {
        const c = cm[1].trim();
        if (c.startsWith('cpe:/a') || c.startsWith('cpe:/h')) cpes.push(c);
      }
      services.push({
        port: parseInt(portid, 10), protocol,
        name: attrs.name || '', product: attrs.product || '',
        version: attrs.version || '', extrainfo: attrs.extrainfo || '',
        cpes,
      });
    }

    let os = null;
    const osM = /<osmatch\b([^>]*?)>([\s\S]*?)<\/osmatch>/.exec(xml) || /<osmatch\b([^>]*?)\/>/.exec(xml);
    if (osM) {
      const a = this._attrs(osM[1]);
      const cpes = [];
      if (osM[2]) {
        const r = /<cpe>([^<]+)<\/cpe>/g;
        let c;
        while ((c = r.exec(osM[2]))) { const v = c[1].trim(); if (v.startsWith('cpe:/o')) cpes.push(v); }
      }
      os = { name: a.name || '', accuracy: a.accuracy || '', cpes };
    }
    return { services, os };
  }

  _attrs(s) {
    const out = {};
    const r = /(\w+)="([^"]*)"/g;
    let m;
    while ((m = r.exec(s))) out[m[1]] = this._unxml(m[2]);
    return out;
  }

  _unxml(s) {
    return String(s)
      .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  }
}

module.exports = ServiceCve;
