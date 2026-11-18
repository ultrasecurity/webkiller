#!/usr/bin/env node
// ============================================================
// tools-doctor — the acceptance gate for the whole subsystem.
// For each named tool it simulates a CLEAN machine: a fresh
// managed dir and an EMPTY system PATH, then runs the real
// download → verify → extract → probe loop and asserts the tool
// ends up usable FROM THE MANAGED COPY. This is the path that
// never runs on the developer's already-set-up Mac otherwise.
//
//   node server/tools/doctor.js httpx
//   node server/tools/doctor.js            # every archive tool in the lock
// ============================================================

const os = require('os');
const path = require('path');
const fs = require('fs');
const { installTool } = require('./install');
const { buildContext, detectTool } = require('./detect');
const { TOOLS } = require('./manifest');

async function doctor(id, opts = {}) {
  const spec = TOOLS[id];
  if (!spec) throw new Error(`unknown tool ${id}`);
  const managedDir = opts.managedDir || fs.mkdtempSync(path.join(os.tmpdir(), 'wk-doctor-'));
  const ownsDir = !opts.managedDir;
  const isUv = !!(spec.install && spec.install.kind === 'uv-tool');
  try {
    process.stderr.write(`[doctor] ${id}: install → fresh dir, EMPTY PATH${isUv ? ' (via uv)' : ''}\n`);
    let res;
    if (isUv) {
      res = await require('./uv').installUvTool(id, { managedDir });
    } else {
      let lastPct = -1;
      res = await installTool(id, { managedDir, onProgress: p => { const pct = Math.floor(p * 100); if (pct !== lastPct && pct % 10 === 0) { lastPct = pct; process.stderr.write(`\r  download ${pct}%   `); } } });
    }
    process.stderr.write(`\n[doctor] placed ${res.path} (v${res.version})\n`);

    // Detect with NO system dirs — only manual/managed can satisfy it.
    const det = detectTool(spec, buildContext({ managedDir, systemDirs: [] }));
    const c = det.chosen;
    const pass = !!(c && c.source === 'managed' && (det.status === 'ready' || det.status === 'untested'));
    process.stderr.write(`[doctor] detect → status=${det.status} source=${c && c.source} version=${c && c.probe.version} ${pass ? 'PASS ✓' : 'FAIL ✗'}\n`);
    return { id, ok: pass, status: det.status, source: c && c.source, version: c && c.probe.version, reasons: det.reasons };
  } finally {
    if (ownsDir) { try { fs.rmSync(managedDir, { recursive: true, force: true }); } catch { /* ignore */ } }
  }
}

if (require.main === module) {
  let ids = process.argv.slice(2);
  if (!ids.length) {
    const lock = (() => { try { return require('./tools.lock.json'); } catch { return { tools: {} }; } })();
    ids = Object.keys(lock.tools);
  }
  (async () => {
    let fail = 0;
    for (const id of ids) {
      try { const r = await doctor(id); if (!r.ok) fail++; }
      catch (e) { process.stderr.write(`[doctor] ${id} ERROR ${e.message}\n`); fail++; }
    }
    process.stderr.write(`\n[doctor] ${ids.length - fail}/${ids.length} passed\n`);
    process.exit(fail ? 1 : 0);
  })();
}
module.exports = { doctor };
