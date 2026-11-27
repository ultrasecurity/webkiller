const { BaseModule, ModuleResult } = require('./base');

// Depth-recon: mine endpoints the crawler misses — robots.txt Disallow paths,
// sitemap.xml <loc> entries, and historical URLs from the Wayback CDX — then
// harvest their query parameters (paramspider-style passive param discovery).
// Feeds urls.txt / params.txt for the confirm phase. Passive: a couple of GETs
// to declared files + read-only Wayback queries.

class ArchiveRecon extends BaseModule {
  static moduleName = 'archive_recon';
  static phase = 'P5';
  static toolsNeeded = [];

  async execute() {
    const port = this.config.targetPort;
    const live = this.workspace.readLines('live.txt').filter(Boolean);
    const bases = (live.length ? live : [port ? `http://${this.workspace.target}:${port}` : `http://${this.workspace.target}`])
      .slice(0, this.config.archive_max_hosts || 10);

    const urls = new Set();
    const params = new Set();
    const records = [];
    const maxUrls = this.config.archive_max_urls || 3000;

    for (const base of bases) {
      const origin = base.startsWith('http') ? base : `http://${base}`;
      // robots.txt
      const robots = await this._get(new URL('/robots.txt', origin).toString());
      if (robots) {
        const paths = []; const sitemaps = [];
        for (const line of robots.split('\n')) {
          let m;
          if ((m = line.match(/^\s*(?:Dis)?[Aa]llow:\s*(\S+)/))) { if (m[1] && m[1] !== '/') paths.push(m[1]); }
          else if ((m = line.match(/^\s*Sitemap:\s*(\S+)/i))) sitemaps.push(m[1]);
        }
        for (const p of paths) { try { urls.add(new URL(p, origin).toString()); } catch {} }
        records.push({ type: 'robots', host: origin, disallow_count: paths.length, sitemaps });
        if (paths.length) this.emit('log', { msg: `robots.txt: ${paths.length} paths on ${origin}` });
        // sitemaps declared in robots + the default
        for (const sm of [...sitemaps, new URL('/sitemap.xml', origin).toString()]) {
          const locs = await this._sitemap(sm);
          for (const u of locs) { if (urls.size < maxUrls) urls.add(u); }
          if (locs.length) { records.push({ type: 'sitemap', url: sm, loc_count: locs.length }); this.emit('log', { msg: `sitemap: ${locs.length} URLs from ${sm}` }); }
        }
      } else {
        // still try a default sitemap even without robots
        const locs = await this._sitemap(new URL('/sitemap.xml', origin).toString());
        for (const u of locs) { if (urls.size < maxUrls) urls.add(u); }
        if (locs.length) this.emit('log', { msg: `sitemap: ${locs.length} URLs on ${origin}` });
      }
    }

    // Wayback CDX (historical URLs) — once, for the apex domain.
    const apex = String(this.workspace.target || '').replace(/:\d+$/, '');
    if (apex && !/^\d{1,3}(\.\d{1,3}){3}$/.test(apex)) {
      const hist = await this._wayback(apex, this.config.archive_wayback_limit || 1000);
      let added = 0;
      for (const u of hist) { if (urls.size < maxUrls) { urls.add(u); added++; } }
      if (added) { records.push({ type: 'wayback', domain: apex, url_count: added }); this.emit('log', { msg: `wayback: ${added} historical URLs for ${apex}` }); }
    }

    // Harvest parameters from every URL that has a query string, plus whatever
    // the crawler already found — this is the paramspider-style passive pass.
    const allUrls = [...urls, ...this.workspace.readLines('urls.txt')];
    for (const u of allUrls) {
      try {
        const qs = new URL(u).searchParams;
        for (const k of qs.keys()) if (k) params.add(k);
      } catch { /* skip */ }
    }

    // Scope gate: sitemap <loc>, robots Sitemap:, and Wayback URLs are absolute and
    // may point out of scope — the confirm phase attacks urls.txt, so drop them.
    const urlList = [...urls].filter(u => { try { return this.scope.inScope(new URL(u).hostname); } catch { return false; } });
    if (urlList.length) this.workspace.appendLines('urls.txt', urlList);
    if (params.size) this.workspace.appendLines('params.txt', [...params]);
    if (records.length) this.workspace.appendJsonl('osint.jsonl', records);

    const items = [`${urlList.length} archived/declared URLs`, `${params.size} params harvested`];
    return new ModuleResult({ module: ArchiveRecon.moduleName, items, records, toolUsed: 'wayback+robots' });
  }

  async _get(url) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout((this.config.archive_timeout || 12) * 1000), headers: { 'User-Agent': this.config.user_agent || 'WebKiller/3.0' } });
      if (!r.ok) return null;
      return (await r.text()).slice(0, 2 * 1024 * 1024);
    } catch { return null; }
  }

  async _sitemap(url) {
    const xml = await this._get(url);
    if (!xml) return [];
    const locs = [];
    const re = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
    let m;
    while ((m = re.exec(xml)) && locs.length < 5000) locs.push(this._decode(m[1]));
    return locs;
  }

  // sitemap <loc> values are XML-escaped (&amp; etc.) — decode before use so URL
  // parsing and param harvesting see the real query string.
  _decode(s) {
    return String(s)
      .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&apos;/g, "'");
  }

  async _wayback(domain, limit) {
    const api = `http://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*&output=text&fl=original&collapse=urlkey&limit=${limit}`;
    const body = await this._get(api);
    if (!body) return [];
    return body.split('\n').map(l => l.trim()).filter(l => /^https?:\/\//.test(l));
  }
}

module.exports = ArchiveRecon;
