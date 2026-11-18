const { BaseModule, ModuleResult } = require('./base');
const { runTool } = require('../runner');
const { isInstalled } = require('../registry');

class Probe extends BaseModule {
  static moduleName = 'probe';
  static phase = 'P3';
  static toolsNeeded = ['httpx'];

  async execute() {
    const subs = this.workspace.readLines('subdomains.txt');
    // Always probe the target host itself so single-host / no-subdomain scans are
    // not skipped; honour an explicit port the scan carried (host:port).
    const port = this.config.targetPort;
    const self = port ? `${this.workspace.target}:${port}` : this.workspace.target;
    const hosts = [...new Set([self, ...subs])].filter(Boolean);
    if (!hosts.length) {
      return new ModuleResult({ module: Probe.moduleName, status: 'skipped', errors: ['No hosts to probe'] });
    }

    // Combined probe list (target + any subdomains) — httpx reads it, the
    // fallback uses it directly.
    this.workspace.appendLines('probe_targets.txt', hosts);
    const subsFile = this.workspace.file('probe_targets.txt');
    let live = [];
    let records = [];
    let usedHttpx = false;

    if (isInstalled('httpx')) {
      this.emit('log', { msg: `Probing ${hosts.length} hosts with httpx` });
      const result = await runTool(
        `httpx -l ${subsFile} -silent -json -status-code -title -tech-detect ${this.config.probe_follow_redirects === false ? '' : '-follow-redirects '}-timeout ${this.config.probe_timeout || this.config.timeout || 15}${this.config.probe_ports ? ` -ports ${this.config.probe_ports}` : ''}`,
        300
      );
      if (result.returncode === 0 && result.stdout.trim()) {
        usedHttpx = true;
        for (const line of result.stdout.split('\n')) {
          if (!line.trim()) continue;
          try {
            const data = JSON.parse(line);
            const url = data.url || '';
            if (url) {
              live.push(url);
              records.push({
                url,
                host: data.host || '',
                status_code: data.status_code || 0,
                title: data.title || '',
                tech: data.tech || [],
                content_length: data.content_length || 0,
                webserver: data.webserver || '',
              });
            }
          } catch {
            if (line.trim().startsWith('http')) {
              live.push(line.trim());
            }
          }
        }
      }
    }

    if (!usedHttpx) {
      this.emit('log', { msg: `httpx not found, using fetch fallback for ${hosts.length} hosts` });
      const fb = await this._fallbackProbe(hosts);
      live = fb.live;
      records = fb.records;
    }

    // Never let a redirect carry us out of scope into live.txt — every
    // downstream confirm module builds its targets from this file and would
    // otherwise send active payloads to an out-of-scope host.
    const inScope = (u) => { try { return this.scope.inScope(new URL(u).hostname); } catch { return false; } };
    live = live.filter(inScope);
    records = records.filter(r => inScope(r.url));

    this.workspace.appendLines('live.txt', live);
    this.workspace.appendJsonl('hosts.jsonl', records);

    return new ModuleResult({
      module: Probe.moduleName,
      items: live,
      records,
      toolUsed: usedHttpx ? 'httpx' : 'node-fetch',
      fallback: !usedHttpx,
    });
  }

  async _fallbackProbe(subs) {
    const live = [];
    const records = [];
    const ua = this.config.userAgent || this.config.user_agent || '';
    const maxHosts = 500;
    const concurrency = 20;
    const targets = subs.slice(0, maxHosts);

    if (subs.length > maxHosts) {
      this.emit('log', { msg: `Capping fallback probe to ${maxHosts} of ${subs.length} hosts` });
    }

    for (let i = 0; i < targets.length; i += concurrency) {
      const batch = targets.slice(i, i + concurrency);
      const results = await Promise.allSettled(
        batch.map(sub => this._probeSingle(sub, ua))
      );
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value) {
          live.push(r.value.url);
          records.push(r.value);
          this.emit('log', { msg: `[LIVE] ${r.value.status_code} ${r.value.url}` });
        }
      }
    }
    return { live, records };
  }

  async _probeSingle(sub, ua) {
    for (const scheme of ['https', 'http']) {
      const url = `${scheme}://${sub}`;
      try {
        const resp = await fetch(url, {
          signal: AbortSignal.timeout(10000),
          headers: { 'User-Agent': ua },
          redirect: 'follow',
        });
        const body = await resp.text();
        const finalUrl = resp.url || url;
        let title = '';
        const titleStart = body.toLowerCase().indexOf('<title>');
        if (titleStart !== -1) {
          const contentStart = titleStart + 7;
          const titleEnd = body.toLowerCase().indexOf('</title>', contentStart);
          if (titleEnd !== -1) {
            title = body.substring(contentStart, titleEnd).trim().substring(0, 200);
          }
        }
        return {
          url: finalUrl,
          host: sub,
          status_code: resp.status,
          title,
          tech: [],
          content_length: body.length,
        };
      } catch {
        continue;
      }
    }
    return null;
  }
}

module.exports = Probe;
