function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

class Scope {
  constructor(targets, outOfScope) {
    this.targets = (targets || []).map(t => t.trim().toLowerCase()).filter(Boolean);
    this.outOfScope = (outOfScope || []).map(o => o.trim().toLowerCase()).filter(Boolean);
    this._inPatterns = this.targets.map(Scope._toPattern);
    this._outPatterns = this.outOfScope.map(Scope._toPattern);
  }

  static _toPattern(entry) {
    if (entry.startsWith('*.')) {
      const suffix = escapeRegex(entry.slice(2));
      return new RegExp(`^(?:.*\\.)?${suffix}$`, 'i');
    }
    return new RegExp(`^${escapeRegex(entry)}$`, 'i');
  }

  inScope(domain) {
    domain = domain.trim().toLowerCase();
    if (this._outPatterns.some(p => p.test(domain))) return false;
    return this._inPatterns.some(p => p.test(domain));
  }

  filterDomains(domains) {
    return domains.filter(d => this.inScope(d));
  }

  filterUrls(urls) {
    const result = [];
    for (const url of urls) {
      try {
        const host = new URL(url).hostname || '';
        if (this.inScope(host)) result.push(url);
      } catch {}
    }
    return result;
  }
}

module.exports = { Scope };
