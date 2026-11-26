const { BaseModule, ModuleResult } = require('./base');

class AuthzProbe extends BaseModule {
  static moduleName = 'authz_probe';
  static phase = 'P6b';
  static toolsNeeded = [];

  async execute() {
    const urls = this.workspace.readLines('urls.txt');
    if (urls.length === 0) {
      return new ModuleResult({ module: AuthzProbe.moduleName, status: 'skipped', errors: ['No URLs'] });
    }

    const apiUrls = urls
      .filter(u => u.includes('/api/') || u.includes('/v1/') || u.includes('/v2/'))
      .slice(0, 50);

    const confirmed = [];
    const items = [];
    const ua = this.config.user_agent || 'WebKiller/2.0';

    const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
    pushInsecureTLS();

    try {
      for (const url of apiUrls) {
        this.emit('log', { msg: `AuthZ probing ${url}` });

        // Response diff check: with vs without auth
        const authResp = await this._safeGet(url, { 'User-Agent': ua });
        const noauthResp = await this._safeGet(url, { 'User-Agent': ua, Authorization: '' });

        if (authResp && noauthResp) {
          const ratio = this._similarity(
            authResp.body.slice(0, 2000),
            noauthResp.body.slice(0, 2000),
          );
          if (ratio > 0.9 && authResp.status === 200 && noauthResp.status === 200) {
            const finding = {
              url,
              vuln_class: 'broken_access_control',
              severity: 'high',
              method: 'response_diff',
              evidence: { similarity: Math.round(ratio * 1000) / 1000, status: authResp.status },
            };
            confirmed.push(finding);
            items.push(`[AUTHZ] Response diff ${Math.round(ratio * 100)}% — ${url}`);
          }
        }

        // Method tampering
        for (const method of ['PUT', 'DELETE', 'PATCH']) {
          const resp = await this._safeRequest(method, url, { 'User-Agent': ua });
          if (resp && ![405, 501, 404, 403, 401].includes(resp.status)) {
            const finding = {
              url,
              vuln_class: 'method_tampering',
              severity: 'medium',
              method: `HTTP_${method}`,
              evidence: { status: resp.status, body_preview: resp.body.slice(0, 200) },
            };
            confirmed.push(finding);
            items.push(`[METHOD] ${method} accepted (${resp.status}) — ${url}`);
          }
        }

        // IDOR via sequential IDs — bump a trailing /<n> path segment or an
        // id-style query value. A blind url.replace('/1','/2') corrupted the
        // host (it matched the "//1" of http://1.2.3.4), so parse the URL.
        const idorUrl = this._bumpId(url);
        if (idorUrl) {
          const resp = await this._safeGet(idorUrl, { 'User-Agent': ua });
          if (resp && resp.status === 200 && resp.body.length > 50) {
            const finding = {
              url: idorUrl,
              vuln_class: 'IDOR',
              severity: 'high',
              method: 'sequential_id',
              evidence: { status: resp.status, body_length: resp.body.length },
            };
            confirmed.push(finding);
            items.push(`[IDOR] Sequential ID accessible — ${idorUrl}`);
          }
        }
      }
    } finally {
      popInsecureTLS();
    }

    this.workspace.appendJsonl('confirmed.jsonl', confirmed);
    return new ModuleResult({ module: AuthzProbe.moduleName, items, records: confirmed, toolUsed: 'python-authz' });
  }

  /**
   * Dice coefficient similarity between two strings.
   * Approximates Python's SequenceMatcher.ratio().
   */
  _similarity(a, b) {
    if (a === b) return 1.0;
    if (a.length === 0 || b.length === 0) return 0.0;

    const bigramsA = new Map();
    for (let i = 0; i < a.length - 1; i++) {
      const bg = a.slice(i, i + 2);
      bigramsA.set(bg, (bigramsA.get(bg) || 0) + 1);
    }

    const bigramsB = new Map();
    for (let i = 0; i < b.length - 1; i++) {
      const bg = b.slice(i, i + 2);
      bigramsB.set(bg, (bigramsB.get(bg) || 0) + 1);
    }

    let intersection = 0;
    for (const [bg, countA] of bigramsA) {
      const countB = bigramsB.get(bg) || 0;
      intersection += Math.min(countA, countB);
    }

    return (2.0 * intersection) / ((a.length - 1) + (b.length - 1));
  }

  // Return the URL with one numeric identifier incremented, or null if there is
  // none to bump. Operates on the parsed URL so the scheme/host is never touched.
  _bumpId(rawUrl) {
    try {
      const u = new URL(rawUrl);
      for (const [k, v] of u.searchParams) {
        if (/(^|_)id$/i.test(k) && /^\d+$/.test(v)) {
          u.searchParams.set(k, String(Number(v) + 1));
          return u.toString();
        }
      }
      const m = u.pathname.match(/^(.*\/)(\d+)$/);
      if (m) { u.pathname = m[1] + String(Number(m[2]) + 1); return u.toString(); }
      return null;
    } catch {
      return null;
    }
  }

  async _safeGet(url, headers) {
    try {
      const resp = await fetch(url, {
        method: 'GET',
        headers,
        signal: AbortSignal.timeout(10000),
        redirect: 'manual',
      });
      const body = await resp.text();
      return { status: resp.status, body, headers: Object.fromEntries(resp.headers) };
    } catch {
      return null;
    }
  }

  async _safeRequest(method, url, headers) {
    try {
      const resp = await fetch(url, {
        method,
        headers,
        signal: AbortSignal.timeout(10000),
        redirect: 'manual',
      });
      const body = await resp.text();
      return { status: resp.status, body };
    } catch {
      return null;
    }
  }
}

module.exports = AuthzProbe;
