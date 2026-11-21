const { BaseModule, ModuleResult } = require('./base');

// Pre-confirm lead triage (TomNomNom gf-style): classify collected URLs by the
// vuln class their parameters hint at, so testing is focused instead of blind.
// Reads urls.txt, tags each parameterized URL per class, and writes a prioritized
// leads list (osint.jsonl) + per-class candidate files the confirm phase can use.
// Passive: pure pattern-matching, no requests.

const PATTERNS = {
  xss:         ['q', 'query', 's', 'search', 'keyword', 'term', 'text', 'name', 'message', 'msg', 'comment', 'title', 'content', 'callback', 'return', 'q1'],
  sqli:        ['id', 'uid', 'user', 'userid', 'pid', 'item', 'cat', 'category', 'page', 'order', 'sort', 'col', 'column', 'select', 'where', 'from', 'num', 'code', 'key'],
  lfi:         ['file', 'path', 'page', 'doc', 'document', 'folder', 'root', 'include', 'inc', 'template', 'tpl', 'lang', 'view', 'dir', 'download', 'read', 'load'],
  ssrf:        ['url', 'uri', 'link', 'src', 'source', 'dest', 'destination', 'redirect', 'next', 'return', 'returnto', 'callback', 'forward', 'out', 'target', 'domain', 'host', 'site', 'feed', 'to', 'continue', 'image', 'img', 'proxy', 'fetch', 'open'],
  redirect:    ['url', 'uri', 'redirect', 'redir', 'next', 'return', 'returnto', 'return_url', 'goto', 'go', 'dest', 'destination', 'continue', 'forward', 'out', 'target', 'to', 'rurl', 'u'],
  ssti:        ['name', 'template', 'tpl', 'msg', 'message', 'content', 'preview', 'text', 'greeting'],
  idor:        ['id', 'uid', 'user', 'userid', 'account', 'acc', 'doc', 'document', 'order', 'invoice', 'number', 'no', 'ref'],
};

class LeadTriage extends BaseModule {
  static moduleName = 'lead_triage';
  static phase = 'P6a';
  static toolsNeeded = [];

  async execute() {
    const urls = [...new Set(this.workspace.readLines('urls.txt').filter(Boolean))];
    const perClass = {};
    for (const k of Object.keys(PATTERNS)) perClass[k] = new Set();
    const records = [];

    for (const u of urls) {
      let params;
      try { params = [...new URL(u).searchParams.keys()].map(p => p.toLowerCase()); } catch { continue; }
      if (!params.length) continue;
      for (const [cls, names] of Object.entries(PATTERNS)) {
        const matched = params.filter(p => names.includes(p));
        if (matched.length) {
          perClass[cls].add(u);
          records.push({ type: 'lead', vuln_class: cls, url: u, params: matched });
        }
      }
    }

    const cap = this.config.triage_max_per_class || 200;
    const items = [];
    for (const [cls, set] of Object.entries(perClass)) {
      if (!set.size) continue;
      const list = [...set].slice(0, cap);
      // a per-class candidate file the confirm modules (and the operator) can use
      this.workspace.appendLines(`leads_${cls}.txt`, list);
      items.push(`${cls}: ${set.size} candidate URLs`);
    }
    if (records.length) this.workspace.appendJsonl('osint.jsonl', records);

    return new ModuleResult({ module: LeadTriage.moduleName, items, records, toolUsed: 'gf-patterns' });
  }
}

module.exports = LeadTriage;
