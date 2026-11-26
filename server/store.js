const fs = require('fs');
const path = require('path');

class AssetStore {
  constructor(workspaceRoot) {
    this.path = path.join(workspaceRoot, 'assets.jsonl');
    this._seen = new Set();
    this._loadExisting();
  }

  _loadExisting() {
    if (!fs.existsSync(this.path)) return;
    for (const line of fs.readFileSync(this.path, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const rec = JSON.parse(line);
        if (rec.key) this._seen.add(rec.key);
      } catch { /* skip malformed line */ }
    }
  }

  _makeKey(assetType, value) {
    return `${assetType}:${value.trim().toLowerCase()}`;
  }

  add(assetType, value, meta) {
    const key = this._makeKey(assetType, value);
    if (this._seen.has(key)) return false;
    this._seen.add(key);
    const record = {
      key,
      type: assetType,
      value: value.trim(),
      discovered_at: Date.now() / 1000,
      ...(meta || {}),
    };
    fs.appendFileSync(this.path, JSON.stringify(record) + '\n');
    return true;
  }

  addMany(assetType, values, meta) {
    let count = 0;
    for (const v of values) {
      if (this.add(assetType, v, meta)) count++;
    }
    return count;
  }

  getAll(assetType) {
    if (!fs.existsSync(this.path)) return [];
    return fs.readFileSync(this.path, 'utf8')
      .split('\n')
      .filter(l => l.trim())
      .reduce((acc, l) => {
        try { acc.push(JSON.parse(l)); } catch { /* skip */ }
        return acc;
      }, [])
      .filter(r => !assetType || r.type === assetType);
  }

  count(assetType) {
    return this.getAll(assetType).length;
  }

  diff(otherStorePath) {
    if (!fs.existsSync(otherStorePath)) return this.getAll();
    const oldKeys = new Set();
    for (const line of fs.readFileSync(otherStorePath, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const rec = JSON.parse(line);
        if (rec.key) oldKeys.add(rec.key);
      } catch { /* skip malformed line */ }
    }
    return this.getAll().filter(a => !oldKeys.has(a.key));
  }
}

module.exports = { AssetStore };
