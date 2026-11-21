const { BaseModule, ModuleResult } = require('./base');
const tls = require('tls');

// Wide-recon / asset expansion: pull the TLS leaf certificate from each live
// host and mine its Subject Alternative Names — SANs routinely leak sibling and
// internal hostnames (admin., api., staging., *.internal) that are otherwise
// invisible. Also records issuer / validity / self-signed, which are leads of
// their own. Built-in (Node tls), no external tool, never sends a payload.

function grabCert(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    let sock;
    try {
      sock = tls.connect({
        host, port,
        // SNI must be a hostname, never an IP literal.
        servername: /^[\d.]+$/.test(host) ? undefined : host,
        rejectUnauthorized: false,
        ALPNProtocols: ['http/1.1'],
      }, () => {
        const c = sock.getPeerCertificate(true);
        sock.end();
        finish(c && Object.keys(c).length ? c : null);
      });
    } catch { return finish(null); }
    sock.setTimeout(timeoutMs, () => { try { sock.destroy(); } catch {} finish(null); });
    sock.on('error', () => finish(null));
  });
}

function parseSans(str) {
  if (!str) return { dns: [], ip: [] };
  const dns = [], ip = [];
  for (const part of String(str).split(',')) {
    const m = part.trim().match(/^(DNS|IP Address):(.+)$/i);
    if (!m) continue;
    if (/^ip/i.test(m[1])) ip.push(m[2].trim()); else dns.push(m[2].trim());
  }
  return { dns, ip };
}

class CertIntel extends BaseModule {
  static moduleName = 'cert_intel';
  static phase = 'P4';
  static toolsNeeded = [];

  async execute() {
    const live = this.workspace.readLines('live.txt').filter(Boolean);
    const tport = this.config.targetPort;
    const raw = live.length ? live : [tport ? `${this.workspace.target}:${tport}` : this.workspace.target];

    // host -> ordered set of candidate TLS ports
    const extra = this.config.cert_ports
      ? String(this.config.cert_ports).split(',').map(x => parseInt(x, 10)).filter(Boolean)
      : [443, 8443];
    const hostPorts = new Map();
    const add = (h, p) => { if (!h || !p) return; if (!hostPorts.has(h)) hostPorts.set(h, new Set()); hostPorts.get(h).add(p); };
    for (const u of raw) {
      try {
        const url = u.startsWith('http') ? new URL(u) : new URL('http://' + u);
        if (url.protocol === 'https:') add(url.hostname, Number(url.port) || 443);
        for (const p of extra) add(url.hostname, p);
        if (tport) add(url.hostname, tport);
      } catch { /* skip malformed */ }
    }

    const items = [];
    const records = [];
    const maxHosts = this.config.cert_max_hosts || 25;
    const timeoutMs = (this.config.cert_timeout || 8) * 1000;
    let scanned = 0;
    for (const [host, ports] of hostPorts) {
      if (scanned++ >= maxHosts) break;
      for (const port of ports) {
        const cert = await grabCert(host, port, timeoutMs);
        if (!cert || !cert.subject) continue;
        const { dns, ip } = parseSans(cert.subjectaltname);
        const issuerCn = (cert.issuer && cert.issuer.CN) || '';
        const subjectCn = cert.subject.CN || '';
        const rec = {
          type: 'cert',
          host, port,
          subject_cn: subjectCn,
          issuer_cn: issuerCn,
          self_signed: !!(subjectCn && issuerCn && subjectCn === issuerCn),
          valid_from: cert.valid_from || '',
          valid_to: cert.valid_to || '',
          fingerprint256: cert.fingerprint256 || '',
          sans: dns,       // sibling/internal hostnames — the asset-expansion win
          san_ips: ip,
        };
        records.push(rec);
        items.push(`cert ${host}:${port} CN=${subjectCn || '?'} · ${dns.length} SAN domains${rec.self_signed ? ' · self-signed' : ''}`);
        this.emit('log', { msg: `cert ${host}:${port} — ${dns.length} SAN domains${dns.length ? ': ' + dns.slice(0, 4).join(', ') : ''}` });
        break; // first working TLS port per host is enough
      }
    }

    if (records.length) this.workspace.appendJsonl('osint.jsonl', records);
    return new ModuleResult({ module: CertIntel.moduleName, items, records, toolUsed: 'tls' });
  }
}

module.exports = CertIntel;
