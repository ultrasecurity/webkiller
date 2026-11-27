const { BaseModule, ModuleResult } = require('./base');
const { runToolLines } = require('../runner');
const { isInstalled } = require('../registry');

class URLs extends BaseModule {
  static moduleName = 'urls';
  static phase = 'P4';
  static toolsNeeded = ['gau', 'katana'];

  async execute() {
    const target = this.workspace.target;
    const live = this.workspace.readLines('live.txt');
    const allUrls = new Set();
    const toolUsed = [];
    let fallback = false;

    // Bare IPs and explicit-port app targets have no meaningful web archive, so
    // skip the archive sources (gau/wayback) that would just burn their timeout;
    // the depth-1 live crawl below is what surfaces their URLs.
    const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(target);
    const singleHost = isIp || !!this.config.targetPort;

    if (!singleHost && isInstalled('gau')) {
      this.emit('log', { msg: `Running gau on ${target}` });
      const lines = await runToolLines(`gau ${target} --threads ${this.config.gau_threads || 5} --timeout 30`, 120);
      for (const l of lines) allUrls.add(l);
      toolUsed.push('gau');
    }

    if (isInstalled('katana') && live.length) {
      const liveFile = this.workspace.file('live.txt');
      this.emit('log', { msg: `Running katana on ${live.length} live hosts` });
      // Bounded so it never dominates an interactive scan: depth 2, a 15s crawl
      // budget (-ct), and a 45s hard cap. Unbounded depth-3 could run for minutes.
      const depth = this.config.crawl_depth || 2;
      const jc = this.config.crawl_js === false ? '' : '-jc ';
      const lines = await runToolLines(
        `katana -list ${liveFile} -silent ${jc}-d ${depth} -ct 15 -timeout 10`,
        45
      );
      for (const l of lines) allUrls.add(l);
      toolUsed.push('katana');
    }

    if (!toolUsed.length && !singleHost) {
      this.emit('log', { msg: 'No URL tools found, using Wayback Machine fallback' });
      const wbUrls = await this._waybackFallback(target);
      for (const u of wbUrls) allUrls.add(u);
      toolUsed.push('wayback-api');
      fallback = true;
    }

    // Depth-1 live crawl. Single-host / fresh-SPA targets usually have no gau
    // archive or katana coverage, so pull same-origin links straight from the
    // live pages — this is what gives a bare host a testable URL surface.
    if (live.length) {
      const crawled = await this._crawlLive(live);
      for (const u of crawled) allUrls.add(u);
      if (crawled.length) { toolUsed.push('live-crawl'); }
    }

    let filtered = this.scope.filterUrls([...allUrls]);
    filtered = [...new Set(filtered)].sort();

    this.workspace.appendLines('urls.txt', filtered);

    return new ModuleResult({
      module: URLs.moduleName,
      items: filtered,
      toolUsed: toolUsed.join(', '),
      fallback,
    });
  }

  // Fetch each live host once and harvest same-origin links from href/action
  // attributes. Bounded (hosts + links capped) and GET-only — safe recon.
  async _crawlLive(liveHosts) {
    const out = new Set();
    const ua = this.config.userAgent || this.config.user_agent || 'WebKiller/3.0';
    const maxHosts = this.config.crawl_max_hosts || 10;
    for (const host of liveHosts.slice(0, maxHosts)) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 10000);
        const resp = await fetch(host, { headers: { 'User-Agent': ua }, signal: controller.signal, redirect: 'follow' });
        clearTimeout(timer);
        if (resp.status !== 200) continue;
        const html = await resp.text();
        const base = resp.url || host;
        const re = /(?:href|action)\s*=\s*["']([^"'#>\s]+)["']/gi;
        let m, n = 0;
        while ((m = re.exec(html)) !== null && n < 300) {
          n++;
          const link = m[1];
          if (/^(?:javascript:|mailto:|tel:|data:)/i.test(link)) continue;
          try {
            const abs = new URL(link, base).href;
            if (/^https?:/i.test(abs)) out.add(abs.split('#')[0]);
          } catch { /* skip bad link */ }
        }
      } catch { /* host unreachable — skip */ }
    }
    return [...out];
  }

  async _waybackFallback(domain) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 30000);
      const resp = await fetch(
        `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey`,
        {
          signal: controller.signal,
          headers: { 'User-Agent': this.config.userAgent || this.config.user_agent || 'WebKiller/3.0' },
        }
      );
      clearTimeout(timer);

      if (resp.ok) {
        const text = await resp.text();
        return text.split('\n').map(l => l.trim()).filter(Boolean);
      }
    } catch (e) {
      this.emit('log', { msg: `Wayback error: ${e.message}` });
    }
    return [];
  }
}

module.exports = URLs;
