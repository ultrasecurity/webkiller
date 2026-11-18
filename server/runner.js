const { execFile, spawn } = require('child_process');
const readline = require('readline');

function splitCmd(cmd) {
  const args = [];
  let current = '';
  let inQuote = false;
  let quoteChar = '';
  for (const ch of cmd) {
    if (inQuote) {
      if (ch === quoteChar) { inQuote = false; continue; }
      current += ch;
    } else if (ch === '"' || ch === "'") {
      inQuote = true;
      quoteChar = ch;
    } else if (ch === ' ' || ch === '\t') {
      if (current) { args.push(current); current = ''; }
    } else {
      current += ch;
    }
  }
  if (current) args.push(current);
  return args;
}

// Resolve a tool name to the exact binary detect() chose (managed install in
// the app folder, or system). This is how a tool installed via the Dependencies
// tab — which is NOT on PATH — actually gets used by a scan. Non-tool commands
// pass through unchanged.
function resolveBin(bin) {
  try { const { toolPath } = require('./registry'); const p = toolPath(bin); if (p) return p; } catch { /* fall back to PATH */ }
  return bin;
}

function runTool(cmd, timeout = 300, cwd = undefined) {
  return new Promise((resolve) => {
    const start = Date.now();
    const parts = splitCmd(cmd);
    const [bin, ...args] = parts;
    const opts = { timeout: timeout * 1000, maxBuffer: 50 * 1024 * 1024 };
    if (cwd) opts.cwd = cwd;

    execFile(resolveBin(bin), args, opts, (err, stdout, stderr) => {
      const duration = (Date.now() - start) / 1000;
      if (err) {
        if (err.killed || err.code === 'ETIMEDOUT') {
          return resolve({ command: cmd, returncode: -1, stdout: '', stderr: 'timeout', duration, timedOut: true });
        }
        if (err.code === 'ENOENT') {
          return resolve({ command: cmd, returncode: -1, stdout: '', stderr: `tool not found: ${bin}`, duration, timedOut: false });
        }
        return resolve({ command: cmd, returncode: err.code || 1, stdout: stdout || '', stderr: stderr || err.message, duration, timedOut: false });
      }
      resolve({ command: cmd, returncode: 0, stdout: stdout || '', stderr: stderr || '', duration, timedOut: false });
    });
  });
}

async function runToolLines(cmd, timeout = 300) {
  const result = await runTool(cmd, timeout);
  if (result.returncode !== 0) return [];
  return result.stdout.split('\n').map(l => l.trim()).filter(Boolean);
}

class StreamRunner {
  constructor(cmd, onLine, timeout = 600) {
    this.cmd = cmd;
    this.onLine = onLine;
    this.timeout = timeout;
    this.proc = null;
    this.lines = [];
    this._done = null;
  }

  start() {
    const parts = splitCmd(this.cmd);
    const [bin, ...args] = parts;
    this.proc = spawn(resolveBin(bin), args, { stdio: ['ignore', 'pipe', 'pipe'] });

    const rl = readline.createInterface({ input: this.proc.stdout });
    rl.on('line', (line) => {
      line = line.trim();
      if (line) {
        this.lines.push(line);
        if (this.onLine) this.onLine(line);
      }
    });

    this._done = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.kill(); reject(new Error('timeout')); }, this.timeout * 1000);
      this.proc.on('close', () => { clearTimeout(timer); resolve(this.lines); });
      this.proc.on('error', (err) => { clearTimeout(timer); reject(err); });
    });

    return this;
  }

  wait() {
    return this._done;
  }

  kill() {
    if (this.proc) {
      try { this.proc.kill(); } catch {}
    }
  }
}

async function batchAsync(items, concurrency, fn) {
  const results = [];
  for (let i = 0; i < items.length; i += concurrency) {
    const batch = items.slice(i, i + concurrency);
    const settled = await Promise.allSettled(batch.map((item, idx) => fn(item, i + idx)));
    for (const r of settled) {
      if (r.status === 'fulfilled' && r.value != null) results.push(r.value);
    }
  }
  return results;
}

module.exports = { runTool, runToolLines, StreamRunner, splitCmd, batchAsync };
