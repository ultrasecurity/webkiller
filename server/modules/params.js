const { BaseModule, ModuleResult } = require('./base');
const { runTool } = require('../runner');
const { isInstalled } = require('../registry');

class Params extends BaseModule {
  static moduleName = 'params';
  static phase = 'P4';
  static toolsNeeded = ['arjun'];

  async execute() {
    const liveHosts = this.workspace.readLines('live.txt');
    const urls = this.workspace.readLines('urls.txt');

    if (liveHosts.length === 0 && urls.length === 0) {
      return new ModuleResult({ module: Params.moduleName, status: 'skipped', errors: ['No targets'] });
    }

    const allParams = [];
    const allRecords = [];
    const toolUsed = [];
    let fallback = false;
    const maxHosts = this.config.params_max_hosts || 10;

    const paramsFromUrls = this._extractParamsFromUrls(urls);
    if (paramsFromUrls.length > 0) {
      allRecords.push(...paramsFromUrls);
      toolUsed.push('url-parse');
    }

    if (isInstalled('arjun')) {
      toolUsed.push('arjun');
      for (const url of liveHosts.slice(0, maxHosts)) {
        this.emit('log', { msg: `arjun: ${url}` });
        const result = await runTool(
          `arjun -u ${url} -oJ /dev/stdout -t ${this.config.params_threads || 10}${this.config.params_method ? ` -m ${this.config.params_method}` : ''} -q`,
          120,
        );
        if (result.returncode === 0 && result.stdout.trim()) {
          const records = this._parseArjun(result.stdout, url);
          allRecords.push(...records);
        }
      }
    } else {
      fallback = true;
      toolUsed.push('python-probe');
      for (const url of liveHosts.slice(0, maxHosts)) {
        this.emit('log', { msg: `Parameter probing: ${url}` });
        const records = await this._probeParams(url);
        allRecords.push(...records);
      }
    }

    for (const rec of allRecords) {
      for (const p of (rec.params || [])) {
        allParams.push(`${rec.url || ''}?${p}`);
      }
    }

    const items = [...new Set(allParams)];
    if (items.length > 0) {
      this.workspace.appendLines('params.txt', items);
    }
    if (allRecords.length > 0) {
      this.workspace.appendJsonl('params.jsonl', allRecords);
    }

    return new ModuleResult({
      module: Params.moduleName,
      items,
      records: allRecords,
      toolUsed: toolUsed.join(', '),
      fallback,
    });
  }

  _extractParamsFromUrls(urls) {
    const paramMap = {};
    for (const url of urls) {
      let parsed;
      try {
        parsed = new URL(url);
      } catch {
        continue;
      }
      if (!parsed.search || parsed.search === '?') continue;
      const base = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
      if (!paramMap[base]) paramMap[base] = new Set();
      for (const key of parsed.searchParams.keys()) {
        paramMap[base].add(key);
      }
    }
    return Object.entries(paramMap)
      .filter(([, params]) => params.size > 0)
      .map(([url, params]) => ({
        url,
        params: [...params].sort(),
        source: 'url_mining',
      }));
  }

  _parseArjun(stdout, url) {
    try {
      const data = JSON.parse(stdout);
      const records = [];
      for (const [target, params] of Object.entries(data)) {
        records.push({
          url: target,
          params: Array.isArray(params) ? params : Object.keys(params),
          source: 'arjun',
        });
      }
      return records;
    } catch {
      return [];
    }
  }

  async _probeParams(url) {
    const commonParams = [
      'id', 'page', 'q', 'search', 'query', 'name', 'user',
      'email', 'file', 'path', 'url', 'redirect', 'next',
      'callback', 'return', 'token', 'action', 'type',
      'category', 'sort', 'order', 'limit', 'offset',
      'lang', 'debug', 'test', 'admin', 'cmd', 'exec',
    ];
    const found = [];
    const ua = this.config.user_agent || 'WebKiller/3.0';

    let baseLen;
    let baseStatus;
    try {
      const baseResp = await fetch(url, {
        headers: { 'User-Agent': ua },
        signal: AbortSignal.timeout(5000),
      });
      const baseBody = await baseResp.arrayBuffer();
      baseLen = baseBody.byteLength;
      baseStatus = baseResp.status;
    } catch {
      return [];
    }

    for (const param of commonParams) {
      try {
        const testUrl = `${url.replace(/\/+$/, '')}?${param}=webkiller_test_value`;
        const resp = await fetch(testUrl, {
          headers: { 'User-Agent': ua },
          signal: AbortSignal.timeout(5000),
        });
        const body = await resp.arrayBuffer();
        const diff = Math.abs(body.byteLength - baseLen);
        if (diff > 50 || resp.status !== baseStatus) {
          found.push(param);
        }
      } catch {
        // skip
      }
    }

    if (found.length > 0) {
      return [{ url, params: found, source: 'python-probe' }];
    }
    return [];
  }
}

module.exports = Params;
