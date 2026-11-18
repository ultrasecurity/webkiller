const fs = require('fs');
const path = require('path');
const { OUTPUT_DIR } = require('./config');

class Workspace {
  constructor(target, scanId) {
    this.target = target.trim().toLowerCase();
    this.scanId = scanId || `scan_${Math.floor(Date.now() / 1000)}`;
    this.root = path.join(OUTPUT_DIR, this.target, this.scanId);
    fs.mkdirSync(this.root, { recursive: true });
    this.stateFile = path.join(this.root, 'state.json');
    this.state = this._loadState();
  }

  _loadState() {
    if (fs.existsSync(this.stateFile)) {
      try {
        return JSON.parse(fs.readFileSync(this.stateFile, 'utf8'));
      } catch {
        // corrupted state file — start fresh
      }
    }
    return {
      target: this.target,
      scan_id: this.scanId,
      started_at: Date.now() / 1000,
      phases_completed: [],
      current_phase: null,
      status: 'created',
    };
  }

  saveState() {
    fs.writeFileSync(this.stateFile, JSON.stringify(this.state, null, 2));
  }

  markPhase(phase, status = 'completed') {
    if (status === 'completed' && !this.state.phases_completed.includes(phase)) {
      this.state.phases_completed.push(phase);
    }
    this.state.current_phase = status === 'running' ? phase : null;
    this.saveState();
  }

  file(name) {
    return path.join(this.root, name);
  }

  appendLines(name, lines) {
    const data = lines.map(l => l.trim() + '\n').join('');
    fs.appendFileSync(this.file(name), data);
  }

  readLines(name) {
    const filePath = this.file(name);
    if (!fs.existsSync(filePath)) return [];
    return fs.readFileSync(filePath, 'utf8')
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean);
  }

  appendJsonl(name, records) {
    const data = records.map(r => JSON.stringify(r) + '\n').join('');
    fs.appendFileSync(this.file(name), data);
  }

  readJsonl(name) {
    const filePath = this.file(name);
    if (!fs.existsSync(filePath)) return [];
    return fs.readFileSync(filePath, 'utf8')
      .split('\n')
      .filter(l => l.trim())
      .reduce((acc, l) => {
        try { acc.push(JSON.parse(l)); } catch { /* skip malformed line */ }
        return acc;
      }, []);
  }
}

module.exports = { Workspace };
