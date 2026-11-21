const { BaseModule, ModuleResult } = require('./base');
const crypto = require('crypto');

// Wide-recon / asset expansion: hash a host's favicon and emit a Shodan/ZoomEye
// "http.favicon.hash" pivot (and a Censys md5 pivot), so the operator can find
// sibling/hidden hosts that serve the same icon. Shodan's convention is
// mmh3(base64.encodebytes(favicon_bytes)) as a SIGNED 32-bit int — matched here
// exactly so the emitted query works against real Shodan data. Built-in: no tool.

// MurmurHash3 x86_32 (canonical, seed 0), returns a signed 32-bit int.
function mmh3_x86_32(buf, seed = 0) {
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  let h1 = seed >>> 0;
  const len = buf.length;
  const nblocks = len >> 2;
  for (let i = 0; i < nblocks; i++) {
    let k1 = buf.readUInt32LE(i * 4);
    k1 = Math.imul(k1, c1) >>> 0;
    k1 = ((k1 << 15) | (k1 >>> 17)) >>> 0;
    k1 = Math.imul(k1, c2) >>> 0;
    h1 ^= k1;
    h1 = ((h1 << 13) | (h1 >>> 19)) >>> 0;
    h1 = (Math.imul(h1, 5) + 0xe6546b64) >>> 0;
  }
  let k1 = 0;
  const tail = nblocks * 4;
  switch (len & 3) {
    case 3: k1 ^= buf[tail + 2] << 16; // falls through
    case 2: k1 ^= buf[tail + 1] << 8;  // falls through
    case 1:
      k1 ^= buf[tail];
      k1 = Math.imul(k1 >>> 0, c1) >>> 0;
      k1 = ((k1 << 15) | (k1 >>> 17)) >>> 0;
      k1 = Math.imul(k1, c2) >>> 0;
      h1 ^= k1;
  }
  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b) >>> 0;
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35) >>> 0;
  h1 ^= h1 >>> 16;
  return h1 | 0; // signed
}

// Shodan hashes base64.encodebytes() output: standard base64 wrapped at 76 cols
// with a trailing newline.
function shodanFaviconHash(bytes) {
  const b64 = Buffer.from(bytes).toString('base64');
  const wrapped = (b64.match(/.{1,76}/g) || []).join('\n') + '\n';
  return mmh3_x86_32(Buffer.from(wrapped, 'utf8'), 0);
}

class FaviconHash extends BaseModule {
  static moduleName = 'favicon_hash';
  static phase = 'P4';
  static toolsNeeded = [];

  async execute() {
    // Live hosts first; fall back to the target itself for a single-host scan.
    let hosts = this.workspace.readLines('live.txt').filter(Boolean);
    if (!hosts.length) {
      const port = this.config.targetPort;
      const base = port ? `${this.workspace.target}:${port}` : this.workspace.target;
      hosts = [`http://${base}`];
    }
    hosts = [...new Set(hosts)].slice(0, this.config.favicon_max_hosts || 25);

    const items = [];
    const records = [];
    for (const host of hosts) {
      try {
        const rec = await this._hashOne(host);
        if (rec) {
          records.push(rec);
          items.push(`favicon ${rec.hash} (${rec.bytes}b) ${rec.host} → Shodan ${rec.shodan_query}`);
          this.emit('log', { msg: `favicon hash ${rec.hash} for ${rec.host}` });
        }
      } catch { /* per-host best effort */ }
    }

    if (records.length) this.workspace.appendJsonl('osint.jsonl', records);
    return new ModuleResult({ module: FaviconHash.moduleName, items, records, toolUsed: 'mmh3' });
  }

  async _fetch(url) {
    const resp = await fetch(url, {
      signal: AbortSignal.timeout((this.config.favicon_timeout || 10) * 1000),
      headers: { 'User-Agent': this.config.user_agent || this.config.userAgent || 'WebKiller/2.0' },
      redirect: 'follow',
    });
    return resp;
  }

  async _hashOne(host) {
    const base = host.startsWith('http') ? host : `http://${host}`;
    let faviconUrl = new URL('/favicon.ico', base).toString();
    let resp = await this._fetch(faviconUrl);

    // If /favicon.ico is missing, parse the homepage for a declared icon link.
    if (!resp.ok || !(resp.headers.get('content-type') || '').match(/image|icon|octet-stream/i)) {
      const declared = await this._declaredIcon(base);
      if (declared) { faviconUrl = declared; resp = await this._fetch(declared); }
    }
    if (!resp.ok) return null;
    const buf = Buffer.from(await resp.arrayBuffer());
    if (!buf.length) return null;

    const hash = shodanFaviconHash(buf);
    const md5 = crypto.createHash('md5').update(buf).digest('hex');
    return {
      type: 'favicon',
      host: new URL(base).host,
      url: faviconUrl,
      hash,                                   // Shodan/ZoomEye mmh3 (signed int32)
      md5,                                    // Censys-style
      bytes: buf.length,
      shodan_query: `http.favicon.hash:${hash}`,
      zoomeye_query: `iconhash:"${hash}"`,
      censys_query: `services.http.response.favicons.md5_hash:${md5}`,
    };
  }

  async _declaredIcon(base) {
    try {
      const resp = await this._fetch(base);
      if (!resp.ok) return null;
      const html = (await resp.text()).slice(0, 200000);
      const m = html.match(/<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]*>/i);
      if (!m) return null;
      const href = (m[0].match(/href=["']([^"']+)["']/i) || [])[1];
      return href ? new URL(href, base).toString() : null;
    } catch { return null; }
  }
}

module.exports = FaviconHash;
