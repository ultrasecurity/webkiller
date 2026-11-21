const { BaseModule, ModuleResult } = require('./base');

// Wide-recon / asset expansion: derive bucket-name candidates from the target's
// brand + known labels, then probe S3 / GCS / Azure for ones that EXIST — 200 =
// world-readable (listable), 403 = exists but private. Read-only existence
// checks against the cloud providers (never the target), no tool to install.

const AFFIX = [
  '', 'dev', 'development', 'staging', 'stage', 'prod', 'production', 'test', 'qa', 'uat',
  'backup', 'backups', 'bak', 'assets', 'static', 'media', 'files', 'data', 'db', 'dump',
  'logs', 'public', 'private', 'uploads', 'upload', 'images', 'img', 'cdn', 'web', 'app',
  'internal', 'archive', 'old', 'new', 'storage', 'store', 's3', 'config', 'secret', 'tmp',
];

class CloudBuckets extends BaseModule {
  static moduleName = 'cloud_buckets';
  static phase = 'P1';
  static toolsNeeded = [];

  async execute() {
    const keywords = this._keywords();
    if (!keywords.length) {
      return new ModuleResult({ module: CloudBuckets.moduleName, status: 'skipped', errors: ['No keyword to derive bucket names'] });
    }

    const names = new Set();
    for (const kw of keywords) {
      for (const a of AFFIX) {
        names.add(kw);
        if (a) { names.add(`${kw}-${a}`); names.add(`${a}-${kw}`); names.add(`${kw}${a}`); }
      }
    }
    const candidates = [...names]
      .filter(n => /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(n)) // valid bucket-name shape
      .slice(0, this.config.bucket_max_candidates || 120);

    this.emit('log', { msg: `Probing ${candidates.length} bucket names across S3/GCS/Azure` });
    const found = [];
    const concurrency = 12;
    for (let i = 0; i < candidates.length; i += concurrency) {
      const batch = candidates.slice(i, i + concurrency);
      const settled = await Promise.allSettled(batch.map(n => this._probe(n)));
      for (const s of settled) if (s.status === 'fulfilled' && s.value) found.push(...s.value);
    }

    if (found.length) this.workspace.appendJsonl('osint.jsonl', found);
    found.forEach(f => this.emit('log', { msg: `[BUCKET] ${f.provider} ${f.bucket} — ${f.access}` }));
    const items = found.map(f => `${f.provider}:${f.bucket} (${f.access})`);
    return new ModuleResult({ module: CloudBuckets.moduleName, items, records: found, toolUsed: 'http' });
  }

  _keywords() {
    const apex = String(this.workspace.target || '').replace(/:\d+$/, '').toLowerCase();
    const kws = new Set();
    if (apex && !/^\d{1,3}(\.\d{1,3}){3}$/.test(apex)) {
      kws.add(apex.split('.')[0]);          // brand label, e.g. "acumo"
      kws.add(apex.replace(/\./g, '-'));     // "acumo-app"
      kws.add(apex.replace(/\.[a-z]+$/, '').replace(/\./g, '')); // "acumo"
    }
    for (const s of this.workspace.readLines('subdomains.txt')) {
      const label = String(s).split('.')[0].toLowerCase();
      if (/^[a-z0-9-]{2,30}$/.test(label)) kws.add(label);
    }
    return [...kws].filter(Boolean).slice(0, this.config.bucket_max_keywords || 6);
  }

  async _probe(name) {
    const targets = [
      { provider: 's3', url: `https://s3.amazonaws.com/${name}/` }, // path-style: works for any name, no TLS-SNI issue
      { provider: 'gcs', url: `https://storage.googleapis.com/${name}/` },
      { provider: 'azure', url: `https://${name}.blob.core.windows.net/?restype=container&comp=list` },
    ];
    const hits = [];
    for (const t of targets) {
      try {
        const r = await fetch(t.url, { method: 'GET', signal: AbortSignal.timeout((this.config.bucket_timeout || 7) * 1000), redirect: 'manual' });
        if (r.status === 200) hits.push({ type: 'bucket', provider: t.provider, bucket: name, url: t.url, status: 200, access: 'PUBLIC (listable)' });
        else if (r.status === 401 || r.status === 403) hits.push({ type: 'bucket', provider: t.provider, bucket: name, url: t.url, status: r.status, access: 'exists (private)' });
        else if (r.status === 301 || r.status === 307) hits.push({ type: 'bucket', provider: t.provider, bucket: name, url: t.url, status: r.status, access: 'exists (other region)' });
        // 404 / NoSuchBucket => does not exist; ignore
      } catch { /* timeout / network — treat as no hit */ }
    }
    return hits;
  }
}

module.exports = CloudBuckets;
