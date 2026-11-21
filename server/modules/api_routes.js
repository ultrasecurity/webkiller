const { BaseModule, ModuleResult } = require('./base');

// API-surface discovery: probe common OpenAPI/Swagger spec locations, parse the
// spec, and expand every documented path+method into concrete URLs (path params
// filled, query params attached) so the confirm phase can test the REST surface
// that a crawler never links to. Feeds urls.txt / params.txt. Passive: read-only
// GETs to a short list of well-known spec paths.

const SPEC_PATHS = [
  '/openapi.json', '/swagger.json', '/swagger/v1/swagger.json', '/v2/api-docs', '/v3/api-docs',
  '/api-docs', '/api/swagger.json', '/api/openapi.json', '/api-docs/swagger.json',
  '/.well-known/openapi.json', '/api/v1/openapi.json', '/docs/openapi.json',
];

class ApiRoutes extends BaseModule {
  static moduleName = 'api_routes';
  static phase = 'P4';
  static toolsNeeded = [];

  async execute() {
    const port = this.config.targetPort;
    const live = this.workspace.readLines('live.txt').filter(Boolean);
    const bases = (live.length ? live : [port ? `http://${this.workspace.target}:${port}` : `http://${this.workspace.target}`])
      .slice(0, this.config.api_max_hosts || 10);

    const urls = new Set();
    const params = new Set();
    const records = [];

    for (const base of bases) {
      const origin = base.startsWith('http') ? base : `http://${base}`;
      for (const sp of SPEC_PATHS) {
        const specUrl = new URL(sp, origin).toString();
        const spec = await this._getJson(specUrl);
        if (!spec || !spec.paths || typeof spec.paths !== 'object') continue;

        const roots = this._roots(spec, origin);
        let routeCount = 0;
        for (const [rawPath, item] of Object.entries(spec.paths)) {
          if (!item || typeof item !== 'object') continue;
          const methods = Object.keys(item).filter(k => ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(k.toLowerCase()));
          const qp = this._queryParams(item, methods);
          qp.forEach(p => params.add(p));
          const concretePath = rawPath.replace(/\{[^}]+\}/g, '1'); // fill path templates
          for (const root of roots) {
            try {
              const u = new URL(root.replace(/\/$/, '') + '/' + concretePath.replace(/^\//, ''));
              if (qp.length) qp.forEach(p => u.searchParams.set(p, 'test'));
              urls.add(u.toString());
              routeCount++;
            } catch { /* skip malformed */ }
          }
        }
        if (routeCount) {
          records.push({ type: 'api_spec', url: specUrl, title: (spec.info && spec.info.title) || '', version: (spec.info && spec.info.version) || '', path_count: Object.keys(spec.paths).length, routes: routeCount });
          this.emit('log', { msg: `OpenAPI at ${specUrl}: ${Object.keys(spec.paths).length} paths → ${routeCount} routes` });
        }
        break; // one spec per host is enough
      }
    }

    const urlList = [...urls];
    if (urlList.length) this.workspace.appendLines('urls.txt', urlList);
    if (params.size) this.workspace.appendLines('params.txt', [...params]);
    if (records.length) this.workspace.appendJsonl('osint.jsonl', records);

    const items = records.map(r => `${r.url} (${r.routes} routes)`);
    if (urlList.length) items.push(`${urlList.length} API URLs, ${params.size} params`);
    return new ModuleResult({ module: ApiRoutes.moduleName, items, records, toolUsed: 'openapi' });
  }

  _roots(spec, origin) {
    const roots = new Set();
    if (Array.isArray(spec.servers)) {
      for (const s of spec.servers) {
        if (s && s.url) { try { roots.add(new URL(s.url, origin).toString()); } catch { /* skip */ } }
      }
    }
    if (spec.basePath) { try { roots.add(new URL(spec.basePath, origin).toString()); } catch { /* skip */ } } // Swagger 2
    if (!roots.size) roots.add(origin);
    return [...roots];
  }

  _queryParams(item, methods) {
    const names = new Set();
    const collect = (arr) => { if (Array.isArray(arr)) for (const p of arr) if (p && p.in === 'query' && p.name) names.add(p.name); };
    collect(item.parameters);
    for (const m of methods) collect(item[m] && item[m].parameters);
    return [...names];
  }

  async _getJson(url) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout((this.config.api_timeout || 10) * 1000), headers: { 'User-Agent': this.config.user_agent || 'WebKiller/2.0', Accept: 'application/json' } });
      if (!r.ok) return null;
      const ct = r.headers.get('content-type') || '';
      const body = (await r.text()).slice(0, 4 * 1024 * 1024);
      if (!/json/i.test(ct) && !/^\s*[{[]/.test(body)) return null;
      return JSON.parse(body);
    } catch { return null; }
  }
}

module.exports = ApiRoutes;
