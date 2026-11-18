const express = require('express');
const path = require('path');
const fs = require('fs');
const net = require('net');
const { ScanEngine } = require('./engine');
const { checkAll, TOOLS, clearCache, toolsForModule, whichSync } = require('./registry');
const { listProfiles, loadProfile, OUTPUT_DIR } = require('./config');
const { MODULE_META } = require('./module_meta');
const moduleSettings = require('./module_settings');
const { isValidTarget, normalizeTarget, safeBasename } = require('./validate');
const aiSettings = require('./ai/settings');
const { PRESETS, SUGGESTED_MODELS } = require('./ai/provider');

let app = null;
let server = null;
let engine = null;

function esc(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function findFreePort(preferred = 8443) {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(preferred, '127.0.0.1', () => {
      srv.close(() => resolve(preferred));
    });
    srv.on('error', () => {
      const srv2 = net.createServer();
      srv2.listen(0, '127.0.0.1', () => {
        const port = srv2.address().port;
        srv2.close(() => resolve(port));
      });
      srv2.on('error', reject);
    });
  });
}

function setupRoutes(app) {
  const webDir = path.join(__dirname, '..', 'web');
  app.use(express.static(webDir));
  app.use(express.json());

  app.get('/', (req, res) => {
    res.sendFile(path.join(webDir, 'index.html'));
  });

  // --- Scan ---

  app.post('/api/scan', (req, res) => {
    const { target, profile, out_of_scope, mode } = req.body || {};
    if (!target || !String(target).trim()) {
      return res.status(400).json({ error: 'target required' });
    }
    if (!isValidTarget(target)) {
      return res.status(400).json({ error: 'invalid target: expected a bare hostname or IPv4 address (no spaces, slashes, or special characters)' });
    }
    let scanId;
    try {
      scanId = engine.startScan(normalizeTarget(target), profile || 'quick', out_of_scope || null, null, mode === 'ai' ? 'ai' : 'classic');
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    res.json({ scan_id: scanId, status: 'started' });
  });

  app.get('/api/scan/:scanId', (req, res) => {
    const scan = engine.getScan(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'not found' });
    res.json(scan);
  });

  app.get('/api/scans', (req, res) => {
    res.json(engine.listScans());
  });

  // --- SSE Events ---

  app.get('/api/scan/:scanId/events', (req, res) => {
    const { scanId } = req.params;
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    });

    let lastSeq = 0;
    const interval = setInterval(() => {
      const events = engine.getEvents(scanId, lastSeq);
      for (const ev of events) {
        lastSeq = ev.seq;
        res.write(`data: ${JSON.stringify(ev)}\n\n`);
      }
      const scan = engine.getScan(scanId);
      if (scan && (scan.status === 'completed' || scan.status === 'error')) {
        res.write(`data: ${JSON.stringify({ type: 'end', status: scan.status })}\n\n`);
        clearInterval(interval);
        res.end();
      }
    }, 500);

    req.on('close', () => clearInterval(interval));
  });

  // --- Result Files ---

  app.get('/api/scan/:scanId/results/:filename', (req, res) => {
    const scan = engine.getScan(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'not found' });
    const safe = safeBasename(req.params.filename);
    if (!safe) return res.status(400).json({ error: 'invalid filename' });
    const root = path.resolve(scan.workspace_path);
    const fpath = path.resolve(root, safe);
    if (path.dirname(fpath) !== root) return res.status(400).json({ error: 'invalid path' });
    if (!fs.existsSync(fpath)) return res.status(404).json({ error: 'file not found' });
    if (safe.endsWith('.jsonl')) {
      const lines = fs.readFileSync(fpath, 'utf8').split('\n').filter(l => l.trim());
      const parsed = [];
      for (const line of lines) {
        try { parsed.push(JSON.parse(line)); } catch {}
      }
      return res.json(parsed);
    }
    res.type('text/plain').send(fs.readFileSync(fpath, 'utf8'));
  });

  // --- AI hooks (per scan) ---

  app.post('/api/scan/:scanId/ai/report', async (req, res) => {
    const scan = engine.getScan(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'not found' });
    const aiCfg = aiSettings.load();
    if (!aiCfg.enabled || !aiCfg.apiKey) return res.status(400).json({ ok: false, error: 'AI is off or has no API key — configure it in Settings', code: 'ai_disabled' });
    try {
      const out = await require('./ai/hooks/report').generateReport(aiSettings.getProvider(), scan.workspace_path, scan.target);
      res.json({ ok: true, ...out });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message, code: err.code || 'error' });
    }
  });

  app.post('/api/scan/:scanId/ai/triage', async (req, res) => {
    const scan = engine.getScan(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'not found' });
    const aiCfg = aiSettings.load();
    if (!aiCfg.enabled || !aiCfg.apiKey) return res.status(400).json({ ok: false, error: 'AI is off or has no API key — configure it in Settings', code: 'ai_disabled' });
    try {
      const out = await require('./ai/hooks/triage').triageFindings(aiSettings.getProvider(), scan.workspace_path);
      res.json({ ok: true, ...out });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message, code: err.code || 'error' });
    }
  });

  // --- AI ---

  app.get('/api/ai/settings', (req, res) => {
    res.json({ ...aiSettings.loadPublic(), presets: PRESETS, suggestedModels: SUGGESTED_MODELS });
  });

  app.post('/api/ai/settings', (req, res) => {
    const b = req.body || {};
    const patch = {};
    for (const k of ['enabled', 'provider', 'baseURL', 'model', 'agentModel']) {
      if (b[k] !== undefined) patch[k] = b[k];
    }
    if (typeof b.apiKey === 'string' && b.apiKey.trim()) patch.apiKey = b.apiKey.trim();
    try {
      res.json(aiSettings.save(patch));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/ai/test', async (req, res) => {
    try {
      const provider = aiSettings.getProvider();
      const r = await provider.chat({
        system: 'You are a connectivity check. Reply with exactly: OK',
        user: 'ping',
        temperature: 0,
        maxTokens: 5,
      });
      res.json({ ok: true, model: provider.model, sample: (r.content || '').slice(0, 40), usage: r.usage });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message, code: err.code || 'error' });
    }
  });

  // --- Tools ---

  app.get('/api/tools', (req, res) => {
    const status = checkAll();
    const result = [];
    for (const [name, installed] of Object.entries(status)) {
      const info = TOOLS[name] || {};
      result.push({ name, installed, required_for: info.required_for || [] });
    }
    res.json(result);
  });

  app.post('/api/tools/refresh', (req, res) => {
    clearCache();
    const status = checkAll();
    const result = [];
    for (const [name, installed] of Object.entries(status)) {
      const info = TOOLS[name] || {};
      result.push({ name, installed, required_for: info.required_for || [] });
    }
    res.json(result);
  });

  // --- Profiles ---

  app.get('/api/profiles', (req, res) => {
    const result = [];
    for (const name of listProfiles()) {
      try { result.push(loadProfile(name)); } catch {}
    }
    res.json(result);
  });

  // --- Module settings ---

  // Every module + its install status + current saved values. Drives Settings.
  app.get('/api/modules', (req, res) => {
    const st = moduleSettings.load();
    const modules = MODULE_META.map(m => {
      const tools = m.tool ? toolsForModule(m.key) : [];
      let status = m.tool ? 'ready' : 'builtin';
      if (m.tool) {
        const anyInstalled = tools.some(t => t.installed);
        if (!anyInstalled) status = m.fallback ? 'fallback' : 'blocked';
      }
      return {
        ...m,
        tools,
        status,
        values: st.modules[m.key] || {},
        enabled: st.enabled[m.key] !== false,
      };
    });
    // What this machine can actually install with, so the UI only offers real
    // options (e.g. brew on a Mac that has it) instead of a generic list.
    const platform = {
      os: process.platform,
      installers: {
        brew: !!whichSync('brew'),
        go: !!whichSync('go'),
        apt: !!(whichSync('apt-get') || whichSync('apt')),
        pipx: !!whichSync('pipx'),
        pip: !!(whichSync('pip3') || whichSync('pip')),
      },
    };
    res.json({ modules, global: moduleSettings.globals(), defaults: moduleSettings.GLOBAL_DEFAULTS, platform });
  });

  // Persist { global, modules, enabled } (shallow-merged with what's stored).
  app.post('/api/settings', (req, res) => {
    try {
      const saved = moduleSettings.save(req.body || {});
      res.json({ ok: true, saved });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  // --- Dependencies (managed tool install/detect) ---

  app.get('/api/deps', (req, res) => {
    try { res.json(require('./tools/deps').payload()); }
    catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Cheap progress snapshot the UI polls during a download (no re-probing).
  app.get('/api/deps/progress', (req, res) => {
    res.json(require('./tools/deps').progressSnapshot());
  });

  // Downloads a third-party binary into the app folder. Fire-and-forget: the UI
  // polls /api/deps/progress, then reloads /api/deps when the entry clears.
  app.post('/api/deps/install', (req, res) => {
    const id = (req.body || {}).id;
    if (!id) return res.status(400).json({ ok: false, error: 'id required' });
    const deps = require('./tools/deps');
    deps.install(id).then(() => clearCache()).catch(() => { /* surfaced via progress snapshot */ });
    res.json({ ok: true, started: true });
  });

  app.post('/api/deps/install-all', (req, res) => {
    const deps = require('./tools/deps');
    deps.installAllMissing().then(() => clearCache()).catch(() => {});
    res.json({ ok: true, started: true });
  });

  app.post('/api/deps/uninstall', (req, res) => {
    const id = (req.body || {}).id;
    if (!id) return res.status(400).json({ ok: false, error: 'id required' });
    try { require('./tools/deps').uninstall(id); clearCache(); res.json({ ok: true }); }
    catch (err) { res.status(400).json({ ok: false, error: err.message }); }
  });

  app.post('/api/deps/recheck', (req, res) => {
    clearCache();
    res.json(require('./tools/deps').payload());
  });

  // --- Export JSON ---

  app.get('/api/scan/:scanId/export/json', (req, res) => {
    const scan = engine.getScan(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'not found' });
    const wsPath = scan.workspace_path;
    const exp = {
      scan_id: req.params.scanId,
      target: scan.target,
      profile: scan.profile,
      status: scan.status,
      started_at: scan.started_at,
      finished_at: scan.finished_at,
      modules: scan.results || {},
      files: {},
    };
    try {
      const entries = fs.readdirSync(wsPath);
      for (const entry of entries) {
        const fpath = path.join(wsPath, entry);
        if (!fs.statSync(fpath).isFile()) continue;
        const ext = path.extname(entry);
        if (!['.txt', '.jsonl', '.json', '.md'].includes(ext)) continue;
        try {
          const text = fs.readFileSync(fpath, 'utf8');
          if (ext === '.jsonl') {
            exp.files[entry] = text.split('\n').filter(l => l.trim()).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
          } else if (ext === '.json') {
            exp.files[entry] = JSON.parse(text);
          } else {
            exp.files[entry] = text.split('\n');
          }
        } catch {}
      }
    } catch {}

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="webkiller_${scan.target}_${req.params.scanId}.json"`);
    res.send(JSON.stringify(exp, null, 2));
  });

  // --- Export HTML ---

  app.get('/api/scan/:scanId/export/html', (req, res) => {
    const scan = engine.getScan(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'not found' });
    const wsPath = scan.workspace_path;

    function readLines(name) {
      const p = path.join(wsPath, name);
      if (!fs.existsSync(p)) return [];
      return fs.readFileSync(p, 'utf8').split('\n').filter(Boolean);
    }
    function readJsonl(name) {
      const p = path.join(wsPath, name);
      if (!fs.existsSync(p)) return [];
      return fs.readFileSync(p, 'utf8').split('\n').filter(l => l.trim()).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    }

    const subdomains = readLines('subdomains.txt');
    const live = readLines('live.txt');
    const urls = readLines('urls.txt');
    const findings = readJsonl('findings.jsonl');
    const confirmed = readJsonl('confirmed.jsonl');
    const results = scan.results || {};
    const started = scan.started_at ? new Date(scan.started_at * 1000).toISOString().replace('T', ' ').slice(0, 19) : '—';
    const finished = scan.finished_at ? new Date(scan.finished_at * 1000).toISOString().replace('T', ' ').slice(0, 19) : '—';
    const duration = scan.finished_at ? `${Math.round(scan.finished_at - scan.started_at)}s` : '—';

    const sevColors = { critical: '#ff4444', high: '#ff8c00', medium: '#ffcc00', low: '#00d4aa', info: '#5a7a80' };

    let findingsHtml = '';
    for (const f of findings.slice(0, 100)) {
      const sev = f.severity || 'info';
      const c = sevColors[sev] || '#5a7a80';
      findingsHtml += `<tr><td><span style="background:${c};color:#000;padding:2px 8px;border-radius:2px;font-size:11px;font-weight:700">${sev.toUpperCase()}</span></td>`;
      findingsHtml += `<td>${esc(f.name || f.vuln_class || 'Unknown')}</td>`;
      findingsHtml += `<td style="word-break:break-all;font-size:12px">${esc(f.url || '')}</td></tr>`;
    }

    let confirmedHtml = '';
    for (const c of confirmed.slice(0, 50)) {
      const sev = c.severity || 'info';
      const col = sevColors[sev] || '#5a7a80';
      confirmedHtml += `<div style="border-left:3px solid ${col};padding:8px 16px;margin:8px 0;background:#161d1f">`;
      confirmedHtml += `<strong>${esc(c.name || '')}</strong><br>`;
      confirmedHtml += `<code style="font-size:12px;color:#5a7a80">${esc(c.url || '')}</code>`;
      if (c.evidence) confirmedHtml += `<br><span style="font-size:11px;color:#888">Evidence: ${esc(JSON.stringify(c.evidence).slice(0, 200))}</span>`;
      confirmedHtml += '</div>';
    }

    let modulesHtml = '';
    for (const [name, r] of Object.entries(results)) {
      const sc = r.status === 'success' ? '#00d4aa' : r.status === 'error' ? '#ff4444' : '#5a7a80';
      modulesHtml += `<tr><td>${name}</td><td>${r.tool_used || 'node'}</td>`;
      modulesHtml += `<td style="color:${sc}">${r.status}</td>`;
      modulesHtml += `<td>${r.items_count}</td><td>${r.duration}s</td></tr>`;
    }

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebKiller 2.0 — ${esc(scan.target)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e0f;color:#c8d8da;font-family:'Inter',system-ui,sans-serif;padding:40px;line-height:1.6}
h1{color:#00d4aa;font-size:28px;margin-bottom:4px}
h2{color:#00d4aa;font-size:18px;margin:32px 0 12px;text-transform:uppercase;letter-spacing:2px;font-weight:600}
h3{font-size:14px;color:#5a7a80;margin-bottom:16px}
.meta{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:24px 0}
.meta-card{background:#111618;border:1px solid #1a2528;border-radius:10px;padding:16px}
.meta-label{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:#5a7a80;margin-bottom:4px}
.meta-value{font-size:24px;font-weight:700;font-family:'JetBrains Mono',monospace}
.teal{color:#00d4aa} .amber{color:#ffcc00} .red{color:#ff4444}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 12px;border-bottom:1px solid #1a2528;color:#5a7a80;font-size:11px;text-transform:uppercase;letter-spacing:1px}
td{padding:8px 12px;border-bottom:1px solid #111618}
code{font-family:'JetBrains Mono',monospace;font-size:12px}
.list{background:#111618;border:1px solid #1a2528;border-radius:10px;padding:16px;max-height:400px;overflow-y:auto;font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.8}
.footer{margin-top:48px;padding-top:16px;border-top:1px solid #1a2528;font-size:11px;color:#5a7a80;text-align:center}
@media(max-width:600px){
  body{padding:16px}
  h1{font-size:22px}
  .meta{grid-template-columns:1fr 1fr;gap:10px}
  .meta-value{font-size:20px}
  table{font-size:11px}
  th,td{padding:6px 8px}
  th:nth-child(5),td:nth-child(5){display:none}
  .list{font-size:11px;word-break:break-all;max-height:300px}
}
</style>
</head>
<body>
<h1>WebKiller 2.0 — Recon Report</h1>
<h3>${esc(scan.target)} · Profile: ${esc(scan.profile)} · ${started}</h3>

<div class="meta">
  <div class="meta-card"><div class="meta-label">Subdomains</div><div class="meta-value teal">${subdomains.length}</div></div>
  <div class="meta-card"><div class="meta-label">Live Hosts</div><div class="meta-value teal">${live.length}</div></div>
  <div class="meta-card"><div class="meta-label">Findings</div><div class="meta-value amber">${findings.length}</div></div>
  <div class="meta-card"><div class="meta-label">Confirmed</div><div class="meta-value red">${confirmed.length}</div></div>
</div>

<h2>Module Results</h2>
<table>
<thead><tr><th>Module</th><th>Tool</th><th>Status</th><th>Items</th><th>Duration</th></tr></thead>
<tbody>${modulesHtml}</tbody>
</table>

${confirmedHtml ? '<h2>Confirmed Vulnerabilities</h2>' + confirmedHtml : ''}
${findingsHtml ? '<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Name</th><th>URL</th></tr></thead><tbody>' + findingsHtml + '</tbody></table>' : ''}
${subdomains.length ? '<h2>Subdomains (' + subdomains.length + ')</h2><div class="list">' + subdomains.slice(0, 500).map(s => esc(s)).join('<br>') + '</div>' : ''}
${live.length ? '<h2>Live Hosts (' + live.length + ')</h2><div class="list">' + live.slice(0, 500).map(s => esc(s)).join('<br>') + '</div>' : ''}
${urls.length ? '<h2>URLs (' + urls.length + ')</h2><div class="list">' + urls.slice(0, 500).map(s => esc(s)).join('<br>') + '</div>' : ''}

<div class="footer">
  Generated by WebKiller 2.0 · ${started} — ${finished} · Duration: ${duration}
</div>
</body></html>`;

    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Disposition', `attachment; filename="webkiller_${scan.target}_${req.params.scanId}.html"`);
    res.send(html);
  });

  // --- Workspace ---

  app.get('/api/workspace/:target', (req, res) => {
    if (!isValidTarget(req.params.target)) return res.status(400).json({ error: 'invalid target' });
    const targetDir = path.join(OUTPUT_DIR, normalizeTarget(req.params.target));
    if (!fs.existsSync(targetDir)) return res.json([]);
    const scans = [];
    const entries = fs.readdirSync(targetDir).sort().reverse();
    for (const entry of entries) {
      const scanDir = path.join(targetDir, entry);
      if (!fs.statSync(scanDir).isDirectory()) continue;
      const stateFile = path.join(scanDir, 'state.json');
      if (fs.existsSync(stateFile)) {
        try { scans.push(JSON.parse(fs.readFileSync(stateFile, 'utf8'))); } catch {}
      } else {
        scans.push({ scan_id: entry, target: req.params.target });
      }
    }
    res.json(scans);
  });
}

async function startServer(preferredPort = 8443) {
  const port = await findFreePort(preferredPort);
  app = express();
  engine = new ScanEngine();
  setupRoutes(app);

  return new Promise((resolve, reject) => {
    server = app.listen(port, '127.0.0.1', () => {
      console.log(`WebKiller server on http://127.0.0.1:${port}`);
      resolve(port);
    });
    server.on('error', reject);
  });
}

function stopServer() {
  if (server) {
    server.close();
    server = null;
  }
}

if (require.main === module) {
  const port = parseInt(process.env.WEBKILLER_PORT || '8443', 10);
  startServer(port).then((p) => {
    console.log(`Listening on port ${p}`);
  }).catch((err) => {
    console.error('Failed to start:', err);
    process.exit(1);
  });
}

module.exports = { startServer, stopServer };
