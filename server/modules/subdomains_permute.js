const { BaseModule, ModuleResult } = require('./base');
const { runTool } = require('../runner');
const { isInstalled } = require('../registry');
const dns = require('dns');

// Depth-recon: take the subdomains already discovered (passive) and generate
// likely permutations (dev-, -staging, api2, internal.<label>, …), then RESOLVE
// them so only live ones survive. This is how hunters turn a handful of known
// subdomains into the forgotten/internal ones. Passive (DNS resolution only);
// prefers dnsx, falls back to Node's resolver.

const WORDS = [
  'dev', 'development', 'staging', 'stage', 'stg', 'test', 'testing', 'qa', 'uat', 'sandbox',
  'demo', 'preview', 'prod', 'production', 'api', 'api2', 'apis', 'admin', 'internal', 'intranet',
  'corp', 'vpn', 'remote', 'mail', 'webmail', 'portal', 'dashboard', 'panel', 'app', 'apps',
  'web', 'beta', 'alpha', 'cdn', 'static', 'assets', 'media', 'files', 'git', 'gitlab',
  'jenkins', 'ci', 'build', 'docker', 'registry', 'k8s', 'db', 'backup', 'old', 'new',
  'legacy', 'v1', 'v2', 'v3', 'secure', 'login', 'auth', 'sso', 'oauth', 'billing',
  'status', 'monitor', 'grafana', 'kibana', 'logs', 'jira', 'wiki', 'docs', 'shop', 'store',
  'mobile', 'ftp', 'gateway', 'proxy', 'edge', 'origin', 'us', 'eu', 'stage1', 'dev1',
];
// Smaller set for the heavier label×word combinations, to keep the candidate list bounded.
const COMBO = ['dev', 'staging', 'test', 'qa', 'uat', 'api', 'admin', 'internal', 'old', 'new', 'v2', 'beta', 'prod'];

class SubdomainsPermute extends BaseModule {
  static moduleName = 'subdomains_permute';
  static phase = 'P1';
  static toolsNeeded = ['dnsx'];

  async execute() {
    const apex = String(this.workspace.target || '').replace(/:\d+$/, '').toLowerCase();
    if (!apex || /^\d{1,3}(\.\d{1,3}){3}$/.test(apex)) {
      return new ModuleResult({ module: SubdomainsPermute.moduleName, status: 'skipped', errors: ['Permutation needs a domain target'] });
    }
    const known = new Set(this.workspace.readLines('subdomains.txt').map(s => s.trim().toLowerCase()).filter(Boolean));
    known.add(apex);
    // labels already seen under the apex (e.g. "www" from www.acumo.app)
    const labels = new Set();
    for (const s of known) {
      if (s.endsWith('.' + apex)) {
        const label = s.slice(0, -(apex.length + 1));
        if (label && !label.includes('.')) labels.add(label);
      }
    }

    const cap = this.config.perm_max_candidates || 1500;
    const cand = new Set();
    for (const w of WORDS) cand.add(`${w}.${apex}`);
    for (const label of labels) {
      for (const w of COMBO) {
        cand.add(`${w}-${label}.${apex}`);
        cand.add(`${label}-${w}.${apex}`);
        cand.add(`${w}.${label}.${apex}`);
      }
    }
    const candidates = [...cand].filter(c => !known.has(c)).slice(0, cap);
    if (!candidates.length) {
      return new ModuleResult({ module: SubdomainsPermute.moduleName, items: [], records: [], toolUsed: 'none' });
    }

    this.emit('log', { msg: `Resolving ${candidates.length} permutation candidates` });
    const resolved = await this._resolve(candidates);
    const fresh = resolved.filter(h => !known.has(h.toLowerCase()));

    if (fresh.length) {
      this.workspace.appendLines('subdomains.txt', fresh); // feed the rest of the pipeline
      this.workspace.appendJsonl('osint.jsonl', fresh.map(h => ({ type: 'permuted_subdomain', host: h })));
    }
    fresh.forEach(h => this.emit('log', { msg: `[PERMUTED] ${h}` }));
    return new ModuleResult({
      module: SubdomainsPermute.moduleName,
      items: fresh,
      records: fresh.map(h => ({ type: 'permuted_subdomain', host: h })),
      toolUsed: isInstalled('dnsx') ? 'dnsx' : 'node-dns',
    });
  }

  async _resolve(candidates) {
    if (isInstalled('dnsx')) {
      const file = this.workspace.file('_perm_candidates.txt');
      this.workspace.appendLines('_perm_candidates.txt', candidates);
      const r = await runTool(`dnsx -l ${file} -silent`, 120);
      if (r.returncode === 0) {
        return r.stdout.split('\n').map(l => l.trim()).filter(Boolean);
      }
      // fall through to node resolver on dnsx failure
    }
    const live = [];
    const concurrency = 50;
    for (let i = 0; i < candidates.length; i += concurrency) {
      const batch = candidates.slice(i, i + concurrency);
      const settled = await Promise.allSettled(batch.map(h => dns.promises.resolve4(h).then(() => h)));
      for (const s of settled) if (s.status === 'fulfilled' && s.value) live.push(s.value);
    }
    return live;
  }
}

module.exports = SubdomainsPermute;
