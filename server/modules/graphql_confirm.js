const { BaseModule, ModuleResult } = require('./base');
const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');
const { endpointCandidates, postJson, dedupEndpoints } = require('./massassign_confirm');

// Find GraphQL endpoints and run an introspection query. A full schema coming
// back means introspection is enabled in production — it maps the entire API
// (types, queries, mutations) for an attacker and often exposes hidden fields.
const INTROSPECTION = '{"query":"{__schema{queryType{name} types{name}}}"}';

class GraphqlConfirm extends BaseModule {
  static moduleName = 'graphql_confirm';
  static phase = 'P6d';
  static toolsNeeded = [];

  async execute() {
    const all = endpointCandidates(this.workspace, this.scope, false);
    // GraphQL lives at a few conventional paths; probe those plus anything that
    // already looks like a GraphQL endpoint.
    const CONV = ['/graphql', '/graphql/1', '/graphql/2', '/graphql/3', '/api/graphql', '/v1/graphql', '/query', '/gql'];
    const origins = [...new Set(all.map(u => { try { return new URL(u).origin; } catch { return null; } }).filter(Boolean))];
    const candidates = new Set(all.filter(u => /graphql|\/gql|\/query/i.test(u)));
    for (const o of origins) for (const c of CONV) candidates.add(o + c);

    const ua = this.config.user_agent || 'WebKiller/3.0';
    const confirmed = [];
    pushInsecureTLS();
    try {
      for (const ep of [...candidates].slice(0, this.config.graphql_max_urls || 40)) {
        try {
          const text = await postJson(ep, INTROSPECTION, ua);
          // Require a real introspection RESULT (data.__schema as an object), not
          // just the substrings — an echoed query or an error message has those too.
          let ok = false;
          try { const j = JSON.parse(text); ok = !!(j && j.data && j.data.__schema && (j.data.__schema.types || j.data.__schema.queryType)); } catch { ok = false; }
          if (ok) {
            confirmed.push({ name: 'GraphQL introspection enabled', severity: 'medium', url: ep, evidence: { note: 'introspection returns the full schema — maps the entire API surface' }, type: 'dast_confirmed', vuln_class: 'graphql', module: GraphqlConfirm.moduleName });
          }
        } catch { /* skip */ }
      }
    } finally { popInsecureTLS(); }
    const out = dedupEndpoints(confirmed);
    if (out.length) { this.workspace.appendJsonl('confirmed.jsonl', out); this.workspace.appendJsonl('findings.jsonl', out); }
    return new ModuleResult({ module: GraphqlConfirm.moduleName, items: out.map(c => c.url), records: out, toolUsed: 'introspection' });
  }
}
module.exports = GraphqlConfirm;
