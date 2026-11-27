const fs = require('fs');
const path = require('path');
const { BaseModule, ModuleResult } = require('./base');
const { runTool } = require('../runner');
const { isInstalled } = require('../registry');

class Screenshots extends BaseModule {
  static moduleName = 'screenshots';
  static phase = 'P5';
  static toolsNeeded = ['gowitness'];

  async execute() {
    const liveHosts = this.workspace.readLines('live.txt');
    if (liveHosts.length === 0) {
      return new ModuleResult({ module: Screenshots.moduleName, status: 'skipped', errors: ['No live hosts'] });
    }

    const maxHosts = this.config.screenshot_max_hosts || 50;
    const targets = liveHosts.slice(0, maxHosts);
    const toolUsed = [];
    let fallback = false;
    let items = [];
    let records = [];

    if (isInstalled('gowitness')) {
      toolUsed.push('gowitness');
      ({ items, records } = await this._gowitness(targets));
    } else {
      fallback = true;
      toolUsed.push('python-headers');
      this.emit('log', { msg: 'gowitness not available, collecting page metadata' });
      ({ items, records } = await this._metadataFallback(targets));
    }

    if (records.length > 0) {
      this.workspace.appendJsonl('screenshots.jsonl', records);
    }

    return new ModuleResult({
      module: Screenshots.moduleName,
      items,
      records,
      toolUsed: toolUsed.join(', '),
      fallback,
    });
  }

  async _gowitness(targets) {
    const urlsFilePath = this.workspace.file('_screenshot_urls.txt');
    fs.writeFileSync(urlsFilePath, targets.join('\n'));
    const outDir = this.workspace.file('screenshots');
    fs.mkdirSync(outDir, { recursive: true });

    this.emit('log', { msg: `gowitness: screenshotting ${targets.length} hosts` });
    await runTool(
      `gowitness file -f ${urlsFilePath} -P ${outDir} --timeout ${this.config.screenshot_timeout || 15} --resolution-x ${this.config.screenshot_width || 1280} --resolution-y ${this.config.screenshot_height || 800}`,
      300,
    );
    try { fs.unlinkSync(urlsFilePath); } catch { /* ignore */ }

    const items = [];
    const records = [];
    if (fs.existsSync(outDir)) {
      const files = fs.readdirSync(outDir).sort();
      for (const f of files) {
        const ext = path.extname(f).toLowerCase();
        if (['.png', '.jpg', '.jpeg'].includes(ext)) {
          const relPath = path.relative(this.workspace.root, path.join(outDir, f));
          items.push(relPath);
          const stem = path.basename(f, ext);
          records.push({
            url: stem.replace('_', '://', 1).replace(/_/g, '/'),
            screenshot: relPath,
            type: 'screenshot',
          });
        }
      }
    }

    const dbPath = path.join(outDir, 'gowitness.sqlite3');
    if (fs.existsSync(dbPath)) {
      const dbRecords = await this._parseGowitnesDb(dbPath);
      records.push(...dbRecords);
    }

    return { items, records };
  }

  async _parseGowitnesDb(dbPath) {
    // Use sqlite3 CLI since there's no native Node sqlite binding guaranteed
    try {
      const { runToolLines } = require('../runner');
      const lines = await runToolLines(
        `sqlite3 -json ${dbPath} "SELECT final_url, response_code, title FROM urls ORDER BY id"`,
        10,
      );
      if (lines.length === 0) return [];
      const raw = lines.join('\n');
      const rows = JSON.parse(raw);
      return rows.map(row => ({
        url: row.final_url || '',
        status: row.response_code || 0,
        title: row.title || '',
        type: 'screenshot_meta',
      }));
    } catch {
      return [];
    }
  }

  async _metadataFallback(targets) {
    const items = [];
    const records = [];
    const ua = this.config.user_agent || 'WebKiller/3.0';

    // Target TLS certs are often self-signed/expired; skip verification for
    // this metadata fetch only, race-safely (ref-counted, see tls_guard).
    const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
    pushInsecureTLS();

    try {
      for (const url of targets) {
        try {
          const resp = await fetch(url, {
            headers: { 'User-Agent': ua },
            redirect: 'follow',
            signal: AbortSignal.timeout(8000),
          });
          const text = await resp.text();
          const titleMatch = text.match(/<title[^>]*>([^<]+)<\/title>/i);
          const title = titleMatch ? titleMatch[1].trim() : '';
          const server = resp.headers.get('server') || '';
          const techHeaders = {};
          for (const hdr of ['x-powered-by', 'x-generator', 'x-aspnet-version']) {
            const val = resp.headers.get(hdr);
            if (val) techHeaders[hdr] = val;
          }
          records.push({
            url,
            status: resp.status,
            title,
            server,
            headers: techHeaders,
            length: Buffer.byteLength(text, 'utf8'),
            type: 'page_meta',
          });
          items.push(url);
        } catch {
          // fetch error — skip host
        }
      }
    } finally {
      popInsecureTLS();
    }

    return { items, records };
  }
}

module.exports = Screenshots;

// Note: Python's stem.replace("_", "://", 1) replaces only the first underscore.
// JS String.replace with a string arg already replaces only the first occurrence,
// then we replace remaining underscores with '/' via .replace(/_/g, '/').
