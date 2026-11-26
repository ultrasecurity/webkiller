const fs = require('fs');
const path = require('path');
const { BaseModule, ModuleResult } = require('./base');
const { runTool, batchAsync } = require('../runner');
const { isInstalled } = require('../registry');

class Content extends BaseModule {
  static moduleName = 'content';
  static phase = 'P4';
  static toolsNeeded = ['ffuf'];

  static _BUILTIN_WORDS = [
    'admin', 'login', 'dashboard', 'api', 'docs', 'swagger',
    '.env', 'config', 'backup', 'robots.txt', 'sitemap.xml',
    '.git/HEAD', 'wp-admin', 'wp-login.php', 'server-status',
    'phpinfo.php', '.well-known/security.txt', 'graphql',
    'debug', 'test', 'status', 'health', 'info',
    'console', 'portal', 'panel', 'manager', 'upload',
    'uploads', 'assets', 'static', 'media', 'images',
    'css', 'js', 'fonts', 'vendor', 'node_modules',
    'package.json', 'composer.json', '.htaccess', 'web.config',
    'crossdomain.xml', 'clientaccesspolicy.xml',
    'actuator', 'actuator/health', 'actuator/env',
    '.DS_Store', 'README.md', 'LICENSE', 'CHANGELOG.md',
    'v1', 'v2', 'api/v1', 'api/v2', 'api/docs',
    'swagger-ui.html', 'api-docs', 'openapi.json',
    'wp-content', 'wp-includes', 'wp-json',
    'cgi-bin', 'server-info', 'trace.axd',
    'elmah.axd', 'error_log', 'debug.log',
  ];

  async execute() {
    const liveHosts = this.workspace.readLines('live.txt');
    if (!liveHosts.length) {
      return new ModuleResult({ module: Content.moduleName, status: 'skipped', errors: ['No live hosts'] });
    }

    const allPaths = [];
    const allRecords = [];
    const toolUsed = [];
    let fallback = false;

    const maxHosts = this.config.contentMaxHosts || this.config.content_max_hosts || 10;
    let wordlist = this.config.contentWordlist || this.config.content_wordlist || '';
    const targets = liveHosts.slice(0, maxHosts);

    if (!wordlist) {
      wordlist = this._findDefaultWordlist();
    }

    const mc = this.config.content_match_codes || '200,301,302,403';
    const ffufThreads = this.config.content_threads || 40;
    const ffufTimeout = this.config.content_timeout || 10;
    const ext = this.config.content_extensions ? ` -e ${this.config.content_extensions}` : '';
    if (isInstalled('ffuf') && wordlist) {
      toolUsed.push('ffuf');
      this.emit('log', { msg: `ffuf: ${targets.length} hosts (3 concurrent)` });
      const ffufResults = await batchAsync(targets, 3, async (url) => {
        this.emit('log', { msg: `ffuf: ${url}` });
        const result = await runTool(
          `ffuf -u ${url}/FUZZ -w ${wordlist} -mc ${mc} -t ${ffufThreads} -timeout ${ffufTimeout}${ext} -o /dev/stdout -of json -s`,
          180
        );
        if (result.returncode === 0 && result.stdout.trim()) {
          return this._parseFfuf(result.stdout, url);
        }
        return [];
      });
      for (const records of ffufResults) {
        allRecords.push(...records);
        allPaths.push(...records.map(r => r.url));
      }
    } else {
      fallback = true;
      toolUsed.push('node-fetch');
      this.emit('log', { msg: `Fetch fallback: ${targets.length} hosts (5 concurrent)` });
      const fetchResults = await batchAsync(targets, 5, async (url) => {
        return this._bruteFallback(url);
      });
      for (const records of fetchResults) {
        allRecords.push(...records);
        allPaths.push(...records.map(r => r.url));
      }
    }

    if (allPaths.length) {
      this.workspace.appendLines('content.txt', allPaths);
    }
    if (allRecords.length) {
      this.workspace.appendJsonl('content.jsonl', allRecords);
    }

    return new ModuleResult({
      module: Content.moduleName,
      items: allPaths,
      records: allRecords,
      toolUsed: toolUsed.join(', '),
      fallback,
    });
  }

  _findDefaultWordlist() {
    const candidates = [
      '/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt',
      '/usr/share/seclists/Discovery/Web-Content/common.txt',
      '/usr/share/wordlists/dirb/common.txt',
    ];
    for (const p of candidates) {
      if (fs.existsSync(p)) return p;
    }

    const builtinDir = path.join(__dirname, '..', '..', 'wordlists');
    const builtinPath = path.join(builtinDir, 'common.txt');
    if (!fs.existsSync(builtinDir)) {
      fs.mkdirSync(builtinDir, { recursive: true });
    }
    if (!fs.existsSync(builtinPath)) {
      fs.writeFileSync(builtinPath, Content._BUILTIN_WORDS.join('\n') + '\n');
    }
    return builtinPath;
  }

  _parseFfuf(stdout, baseUrl) {
    const records = [];
    try {
      const data = JSON.parse(stdout);
      for (const r of (data.results || [])) {
        records.push({
          url: r.url || '',
          status: r.status || 0,
          length: r.length || 0,
          words: r.words || 0,
          source: baseUrl,
        });
      }
    } catch {
      for (const line of stdout.split('\n')) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('{')) {
          records.push({ url: `${baseUrl}/${trimmed}`, source: baseUrl });
        }
      }
    }
    return records;
  }

  async _bruteFallback(baseUrl) {
    const common = [
      'admin', 'login', 'dashboard', 'api', 'docs', 'swagger',
      '.env', 'config', 'backup', 'robots.txt', 'sitemap.xml',
      '.git/HEAD', 'wp-admin', 'wp-login.php', 'server-status',
      'phpinfo.php', '.well-known/security.txt', 'graphql',
      'debug', 'test', 'status', 'health', 'info',
    ];
    const records = [];
    const ua = this.config.userAgent || this.config.user_agent || 'WebKiller/2.0';

    for (const p of common) {
      const url = `${baseUrl.replace(/\/+$/, '')}/${p}`;
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        const resp = await fetch(url, {
          signal: controller.signal,
          headers: { 'User-Agent': ua },
          redirect: 'manual',
        });
        clearTimeout(timer);

        if ([200, 301, 302, 403].includes(resp.status)) {
          const body = await resp.text();
          records.push({
            url,
            status: resp.status,
            length: body.length,
            source: baseUrl,
          });
        }
      } catch {
        // skip failed requests
      }
    }
    return records;
  }
}

module.exports = Content;
