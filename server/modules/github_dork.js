const { BaseModule, ModuleResult } = require('./base');

// Wide-recon: search PUBLIC GitHub code for the target's domain/brand alongside
// secret-ish keywords, surfacing leaked keys, internal endpoints and configs that
// reference the target. Read-only (GitHub code-search API). Needs a token — set
// it in Settings → GitHub dork (stored locally, never shown back) or $GITHUB_TOKEN.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class GithubDork extends BaseModule {
  static moduleName = 'github_dork';
  static phase = 'P1';
  static toolsNeeded = [];

  async execute() {
    const token = String(this.config.github_token || process.env.GITHUB_TOKEN || '').trim();
    if (!token) {
      return new ModuleResult({ module: GithubDork.moduleName, status: 'skipped', errors: ['No GitHub token — add one in Settings → GitHub dork'] });
    }
    const apex = String(this.workspace.target || '').replace(/:\d+$/, '').toLowerCase();
    if (!apex || /^\d{1,3}(\.\d{1,3}){3}$/.test(apex)) {
      return new ModuleResult({ module: GithubDork.moduleName, status: 'skipped', errors: ['GitHub dork needs a domain target'] });
    }
    const brand = apex.split('.')[0];
    const dorks = [
      `"${apex}"`,
      `"${apex}" password`,
      `"${apex}" (api_key OR apikey OR secret OR token)`,
      `"${apex}" filename:.env`,
      `"${brand}" (aws_access_key_id OR BEGIN RSA PRIVATE KEY)`,
    ].slice(0, this.config.github_max_dorks || 5);

    const seen = new Set();
    const records = [];
    const items = [];
    for (let i = 0; i < dorks.length; i++) {
      const q = dorks[i];
      const res = await this._search(q, token);
      if (res === 'ratelimited') { this.emit('log', { msg: 'GitHub rate limit reached — stopping early' }); break; }
      if (!Array.isArray(res)) continue;
      let fresh = 0;
      for (const it of res) {
        const repo = it.repository && it.repository.full_name;
        if (!repo) continue;
        const k = `${repo}|${it.path}`;
        if (seen.has(k)) continue;
        seen.add(k);
        fresh++;
        records.push({ type: 'github_hit', dork: q, repo, path: it.path, url: it.html_url });
      }
      items.push(`${q} → ${fresh} hits`);
      this.emit('log', { msg: `dork ${q} → ${fresh} new hits` });
      if (i < dorks.length - 1) await sleep(this.config.github_delay_ms || 7000); // code search ~10 req/min
    }

    if (records.length) this.workspace.appendJsonl('osint.jsonl', records);
    return new ModuleResult({ module: GithubDork.moduleName, items, records, toolUsed: 'github-api' });
  }

  async _search(q, token) {
    try {
      const r = await fetch('https://api.github.com/search/code?per_page=20&q=' + encodeURIComponent(q), {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'WebKiller/2.0',
          'X-GitHub-Api-Version': '2022-11-28',
        },
        signal: AbortSignal.timeout(20000),
      });
      if (r.status === 403 || r.status === 429) return 'ratelimited';
      if (!r.ok) return null;
      const j = await r.json();
      return Array.isArray(j.items) ? j.items : [];
    } catch { return null; }
  }
}

module.exports = GithubDork;
