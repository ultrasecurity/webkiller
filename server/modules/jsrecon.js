const { BaseModule, ModuleResult } = require('./base');
const { isInstalled } = require('../registry');

class JsRecon extends BaseModule {
  static moduleName = 'jsrecon';
  static phase = 'P4';
  static toolsNeeded = [];

  async execute() {
    const urls = this.workspace.readLines('urls.txt');
    const liveHosts = this.workspace.readLines('live.txt');
    let jsUrls = urls.filter(u => this._isJs(u));

    if (jsUrls.length === 0 && liveHosts.length > 0) {
      this.emit('log', { msg: 'No JS URLs found, scraping live hosts for scripts' });
      for (const host of liveHosts.slice(0, 10)) {
        const scraped = await this._scrapeScripts(host);
        jsUrls.push(...scraped);
      }
      jsUrls = [...new Set(jsUrls)];
    }

    if (jsUrls.length === 0) {
      return new ModuleResult({ module: JsRecon.moduleName, status: 'skipped', errors: ['No JS files found'] });
    }

    this.emit('log', { msg: `Analyzing ${jsUrls.length} JS files` });
    const allEndpoints = [];
    const allSecrets = [];
    const allRecords = [];

    const maxFiles = this.config.jsrecon_max_files || 50;
    const ua = this.config.user_agent || 'WebKiller/3.0';
    const surfaced = new Set(); // in-scope endpoints resolved to absolute URLs

    for (const jsUrl of jsUrls.slice(0, maxFiles)) {
      try {
        const resp = await fetch(jsUrl, {
          headers: { 'User-Agent': ua },
          signal: AbortSignal.timeout(10000),
        });
        if (resp.status !== 200) continue;
        const body = await resp.text();

        const endpoints = this._extractEndpoints(body);
        const secrets = this._extractSecrets(body, jsUrl);

        if (endpoints.length > 0) {
          allEndpoints.push(...endpoints);
          allRecords.push({
            file: jsUrl,
            endpoints,
            type: 'js_endpoints',
          });
          let origin = '';
          try { origin = new URL(jsUrl).origin; } catch { /* keep '' */ }
          for (const ep of endpoints) {
            const abs = this._toAbsolute(ep, origin);
            if (!abs) continue;
            try { if (!this.scope || this.scope.inScope(new URL(abs).hostname)) surfaced.add(abs); } catch { /* skip */ }
          }
        }
        if (secrets.length > 0) {
          allSecrets.push(...secrets);
        }
      } catch {
        // fetch error — skip
      }
    }

    const items = [...new Set(allEndpoints)];
    if (items.length > 0) {
      this.workspace.appendLines('js_endpoints.txt', items);
    }
    // Surface in-scope JS endpoints into the main URL set so find_parameters,
    // the confirm modules and the agent treat them as testable SPA surface
    // instead of leaving them stranded in a side file.
    const surfacedUrls = [...surfaced];
    if (surfacedUrls.length > 0) {
      this.workspace.appendLines('urls.txt', surfacedUrls);
    }
    if (allSecrets.length > 0) {
      this.workspace.appendJsonl('findings.jsonl', allSecrets);
    }
    if (allRecords.length > 0) {
      this.workspace.appendJsonl('jsrecon.jsonl', allRecords);
    }

    return new ModuleResult({
      module: JsRecon.moduleName,
      items,
      records: allRecords,
      toolUsed: 'python-regex',
      fallback: true,
    });
  }

  _isJs(url) {
    const pathPart = url.split('?')[0].toLowerCase();
    return pathPart.endsWith('.js') || pathPart.endsWith('.mjs');
  }

  // Resolve an extracted endpoint to an absolute URL. Only absolute URLs and
  // host-rooted paths ("/api/x") become real URLs; bare relative fragments are
  // too ambiguous to place safely, so they are dropped.
  _toAbsolute(ep, origin) {
    try {
      if (/^https?:\/\//i.test(ep)) return new URL(ep).href;
      if (ep.startsWith('/') && origin) return new URL(ep, origin).href;
    } catch { /* malformed — drop */ }
    return '';
  }

  async _scrapeScripts(hostUrl) {
    try {
      const ua = this.config.user_agent || 'WebKiller/3.0';
      const resp = await fetch(hostUrl, {
        headers: { 'User-Agent': ua },
        signal: AbortSignal.timeout(10000),
      });
      if (resp.status !== 200) return [];
      const text = await resp.text();
      const srcPattern = /<script[^>]+src=["']([^"']+)["']/gi;
      const matches = [...text.matchAll(srcPattern)].map(m => m[1]);
      const result = [];
      for (let src of matches) {
        if (src.startsWith('//')) {
          src = 'https:' + src;
        } else if (src.startsWith('/')) {
          src = hostUrl.replace(/\/+$/, '') + src;
        } else if (!src.startsWith('http')) {
          src = hostUrl.replace(/\/+$/, '') + '/' + src;
        }
        result.push(src);
      }
      return result;
    } catch {
      return [];
    }
  }

  _extractEndpoints(jsBody) {
    const patterns = [
      /["']\/api\/[a-zA-Z0-9_/\-.]+["']/g,
      /["']\/v[0-9]+\/[a-zA-Z0-9_/\-.]+["']/g,
      /fetch\s*\(\s*["']([^"']+)["']/g,
      /\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']/g,
      /["']https?:\/\/[a-zA-Z0-9\-.]+(?:\/[a-zA-Z0-9_/\-.]*)+["']/g,
    ];
    const endpoints = new Set();
    for (const pat of patterns) {
      for (const match of jsBody.matchAll(pat)) {
        const cleaned = (match[1] || match[0]).replace(/^["']|["']$/g, '');
        if (cleaned.length > 4 && !/\.(js|css|png|jpg|svg)$/.test(cleaned)) {
          endpoints.add(cleaned);
        }
      }
    }
    return [...endpoints].sort();
  }

  _extractSecrets(jsBody, sourceUrl) {
    const secretPatterns = {
      aws_key: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g,
      google_api: /AIza[0-9A-Za-z\-_]{35}/g,
      slack_token: /xox[bpsorta]-[0-9a-zA-Z\-]{10,}/g,
      github_token: /gh[ps]_[0-9a-zA-Z]{36}/g,
      jwt: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
      private_key: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,
      bearer_token: /[Bb]earer\s+[a-zA-Z0-9\-_.~+/]+=*/g,
      generic_secret: /(?:secret|password|api_?key|token)\s*[:=]\s*["'][a-zA-Z0-9\-_.]{8,}["']/g,
    };
    const findings = [];
    for (const [name, pattern] of Object.entries(secretPatterns)) {
      for (const m of jsBody.matchAll(pattern)) {
        findings.push({
          name: `JS Secret: ${name}`,
          severity: 'high',
          url: sourceUrl,
          evidence: { pattern: name, match: m[0].slice(0, 60) },
          type: 'js_secret',
          module: JsRecon.moduleName,
        });
      }
    }
    return findings;
  }
}

module.exports = JsRecon;
