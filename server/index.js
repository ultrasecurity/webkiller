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
const userAgents = require('./user_agents');

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
      if (scan && (scan.status === 'completed' || scan.status === 'error' || scan.status === 'stopped')) {
        res.write(`data: ${JSON.stringify({ type: 'end', status: scan.status })}\n\n`);
        clearInterval(interval);
        res.end();
      }
    }, 500);

    req.on('close', () => clearInterval(interval));
  });

  app.post('/api/scan/:scanId/stop', (req, res) => {
    const ok = engine.stopScan(req.params.scanId);
    res.json({ ok: !!ok });
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
        values: moduleSettings.maskSecrets(m.key, st.modules[m.key] || {}),
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
    res.json({ modules, global: moduleSettings.globals(), defaults: moduleSettings.GLOBAL_DEFAULTS, platform, uaPresets: userAgents.PRESETS, uaRandom: userAgents.RANDOM });
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

  // Validate the stored GitHub token (the "Test" button on the github_dork secret
  // field) without ever returning it — a cheap read-only /rate_limit call.
  app.post('/api/github/validate-token', async (req, res) => {
    try {
      const mods = moduleSettings.load().modules || {};
      const token = (mods.github_dork && mods.github_dork.github_token) || process.env.GITHUB_TOKEN;
      if (!token) return res.json({ ok: false, error: 'no token stored — paste one and Save first' });
      const r = await fetch('https://api.github.com/rate_limit', {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'WebKiller/2.0' },
        signal: AbortSignal.timeout(15000),
      });
      if (r.status === 200) {
        const j = await r.json();
        const search = j.resources && j.resources.search;
        return res.json({ ok: true, remaining: search ? search.remaining : undefined });
      }
      if (r.status === 401) return res.json({ ok: false, error: 'invalid or expired token' });
      if (r.status === 403) return res.json({ ok: false, error: 'forbidden / rate-limited' });
      return res.json({ ok: false, error: `GitHub returned ${r.status}` });
    } catch (e) {
      return res.json({ ok: false, error: e.message });
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

  // Self-contained stylesheet for the exported report: the app's design tokens +
  // the ag-* component rules, inlined (no external fonts/CSS) so the file renders
  // offline and matches the in-app results screen. System fonts only.
  const REPORT_CSS = `
:root{--bg:#0A0E0F;--surface:#111618;--raised:#161D1F;--txt:#C8D8DA;--txt2:#5A7A80;--mut:#4A6670;--primary:#00D4AA;--red:#FF4444;--high:#FF6B35;--amber:#FFAA00;--info:#4488FF;--bsub:rgba(0,212,170,.10);--bneu:#1E2A2D;--mono:ui-monospace,Menlo,Consolas,monospace}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--txt);font-family:system-ui,-apple-system,sans-serif;line-height:1.6}
.rp{max-width:1100px;margin:0 auto;padding:40px 28px}
.ag-head{margin-bottom:24px}
.ag-title{font-family:var(--mono);font-size:26px;color:var(--txt)}
.ag-sub{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.ag-pill{font-family:var(--mono);font-size:11px;letter-spacing:.04em;padding:4px 10px;border-radius:999px;border:1px solid var(--bneu);color:var(--txt2)}
.ag-pill.mode{color:var(--high);border-color:rgba(255,107,53,.3)}
.ag-pill.done{color:var(--primary);border-color:rgba(0,212,170,.3)}
.ag-hero{display:grid;grid-template-columns:1.3fr 1fr;gap:16px;margin-bottom:28px}
.ag-verdict{background:linear-gradient(160deg,var(--raised),var(--surface));border:1px solid rgba(0,212,170,.18);border-radius:20px;padding:22px}
.ag-verdict.leads{border-color:rgba(255,170,0,.3)}.ag-verdict.clean{border-color:var(--bneu)}
.bigrow{display:flex;align-items:baseline;gap:16px;flex-wrap:wrap}
.big{font-family:var(--mono);font-size:34px;line-height:1;color:var(--red)}.big.clean{color:var(--txt2)}.big.lead{color:var(--amber);font-size:22px}
.cap{color:var(--txt2);font-size:13px;margin-top:6px}
.sevlbl{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--mut);margin-top:16px}
.sevrow{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.ag-sev{display:inline-flex;align-items:center;gap:7px;font-family:var(--mono);font-size:12px;padding:6px 12px;border-radius:999px;border:1px solid}
.ag-sev .n{font-size:14px;font-weight:600}
.ag-sev.crit{color:var(--red);border-color:rgba(255,68,68,.3);background:rgba(255,68,68,.07)}
.ag-sev.high{color:var(--high);border-color:rgba(255,107,53,.3);background:rgba(255,107,53,.07)}
.ag-sev.med{color:var(--amber);border-color:rgba(255,170,0,.3);background:rgba(255,170,0,.07)}
.ag-sev.low{color:var(--info);border-color:rgba(68,136,255,.3);background:rgba(68,136,255,.07)}
.ag-sev.info{color:var(--txt2);border-color:var(--bneu)}
.ag-sev.lead{background:none;border-style:dashed}
.ag-statgrid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.ag-stat{background:var(--surface);border:1px solid var(--bsub);border-radius:12px;padding:12px 16px}
.ag-stat .k{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--mut)}
.ag-stat .v{font-family:var(--mono);font-size:20px;margin-top:4px}.ag-stat .v.ac{color:var(--primary)}.ag-stat .v small{font-size:12px;color:var(--mut)}
.ag-sec{font-family:var(--mono);font-size:16px;margin:28px 0 12px}.ag-sec .ct{font-size:12px;color:var(--mut)}
.ag-fcard{background:var(--surface);border:1px solid var(--bsub);border-left:3px solid var(--red);border-radius:12px;margin-bottom:12px;overflow:hidden}
.ag-fcard.high{border-left-color:var(--high)}.ag-fcard.med{border-left-color:var(--amber)}.ag-fcard.low{border-left-color:var(--info)}.ag-fcard.info{border-left-color:var(--bneu)}.ag-fcard.lead{border-left-style:dashed}
.ag-fcard>summary{display:flex;align-items:center;gap:12px;padding:14px 16px;cursor:pointer;list-style:none}
.ag-fcard>summary::-webkit-details-marker{display:none}
.ag-fh .title{flex:1;font-weight:600;font-size:15px}
.ag-fh .cls{font-family:var(--mono);font-size:11px;color:var(--mut);background:var(--raised);padding:3px 9px;border-radius:999px}
.ag-fh .chev{color:var(--mut);transition:transform .2s}.ag-fcard[open]>summary .chev{transform:rotate(90deg)}
.ag-fb{padding:0 16px 16px;border-top:1px solid var(--bsub)}
.ag-kv{display:flex;gap:10px;padding:8px 0;font-size:13px;border-bottom:1px solid var(--bsub)}
.ag-kv .k{width:88px;color:var(--mut);flex-shrink:0;font-size:12px}.ag-kv .v{font-family:var(--mono);word-break:break-all}
.ag-poc{margin-top:12px}.ag-poc .lbl{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--primary);margin-bottom:6px}
.ag-code{background:var(--bg);border:1px solid var(--bneu);border-radius:8px;padding:12px 14px;font-family:var(--mono);font-size:12px;line-height:1.7;white-space:pre-wrap;word-break:break-word}
.ag-fold{margin-top:16px;border:1px solid var(--bsub);border-radius:12px;background:var(--surface)}
.ag-fold>summary{padding:14px 16px;cursor:pointer;color:var(--txt2);font-size:14px;list-style:none;display:flex;justify-content:space-between}
.ag-fold>summary::-webkit-details-marker{display:none}.ag-fold .ct{font-family:var(--mono);font-size:12px;color:var(--mut)}
.rp-list{border-top:1px solid var(--bsub);max-height:460px;overflow:auto}
.rp-row{display:flex;gap:12px;align-items:center;padding:8px 16px;border-bottom:1px solid var(--bsub);font-size:13px}
.rp-row .u{flex:1;font-family:var(--mono);word-break:break-all}.rp-row .u small{color:var(--mut)}.rp-row .t{color:var(--mut);font-family:var(--mono);font-size:12px;white-space:nowrap}
.rp-row .sc{font-family:var(--mono);font-size:11px;padding:2px 7px;border-radius:4px;flex-shrink:0}
.sc.s2{color:var(--primary)}.sc.s3{color:var(--amber)}.sc.s4{color:var(--high)}.sc.s5{color:var(--red)}.sc.s0{color:var(--mut)}
.rp-line{padding:5px 16px;border-bottom:1px solid var(--bsub);font-family:var(--mono);font-size:12px;word-break:break-all}
.rp-empty{padding:16px;color:var(--mut)}
.rp-foot{margin-top:40px;padding-top:16px;border-top:1px solid var(--bneu);font-size:11px;color:var(--mut);text-align:center}
@media(max-width:700px){.ag-hero{grid-template-columns:1fr}.rp{padding:20px 14px}.ag-statgrid{grid-template-columns:1fr 1fr}}
@media print{body{background:#fff;color:#111}.ag-verdict,.ag-stat,.ag-fcard,.ag-fold{background:none}.rp-list{max-height:none}.ag-fcard,.ag-stat{break-inside:avoid}}
`;

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

    const params = readLines('params.txt');
    const hosts = readJsonl('hosts.jsonl');
    // Merge findings exactly like the app's results view: confirmed wins, rest are leads.
    const fkey = f => `${String(f.vuln_class || f.name || '').toLowerCase()}|${f.url || ''}|${(f.evidence && f.evidence.param) || ''}|${f.cve || ''}`;
    const fmap = new Map();
    confirmed.forEach(f => fmap.set(fkey(f), { ...f, _kind: 'confirmed' }));
    findings.forEach(f => { const k = fkey(f); if (!fmap.has(k)) fmap.set(k, { ...f, _kind: (f.type === 'dast_confirmed' || f.type === 'agent_confirmed') ? 'confirmed' : 'potential' }); });
    const ord = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const bySev = (a, b) => (ord[(a.severity || 'info').toLowerCase()] ?? 9) - (ord[(b.severity || 'info').toLowerCase()] ?? 9);
    const conf = [...fmap.values()].filter(f => f._kind === 'confirmed').sort(bySev);
    const leads = [...fmap.values()].filter(f => f._kind === 'potential').sort(bySev);
    // CVE verification side-file → attach status onto each cve finding for the card.
    const verifs = readJsonl('verifications.jsonl');
    const vmap = {}; verifs.forEach(v => { vmap[`${v.cve}|${v.url}`] = v; });
    [...conf, ...leads].forEach(f => { if ((f.vuln_class === 'cve' || f.cve) && !f.verification) { const v = vmap[`${f.cve}|${f.url}`]; if (v) f.verification = v; } });
    const sevCount = list => { const c = {}; list.forEach(f => { const s = (f.severity || 'info').toLowerCase(); c[s] = (c[s] || 0) + 1; }); return c; };
    const confSev = sevCount(conf), leadSev = sevCount(leads);
    const modsRan = Object.keys(results).length, modsTotal = scan.modules_total || modsRan;

    const sevCls = s => { s = String(s || 'info').toLowerCase(); return s === 'critical' ? 'crit' : s === 'high' ? 'high' : s === 'medium' ? 'med' : s === 'low' ? 'low' : 'info'; };
    const pills = (c, lead) => ['critical', 'high', 'medium', 'low', 'info'].filter(s => c[s]).map(s => `<span class="ag-sev ${sevCls(s)}${lead ? ' lead' : ''}"><span class="n">${c[s]}</span> ${s}</span>`).join('');
    const scCls = s => { const n = String(s || '').charAt(0); return n === '2' ? 's2' : n === '3' ? 's3' : n === '4' ? 's4' : n === '5' ? 's5' : 's0'; };
    const poc = f => {
      const ev = f.evidence || {}; let p = '';
      if (ev.payload) p += `${ev.method || 'GET'} ${f.url || ''}${ev.param ? `   (param: ${ev.param})` : ''}\npayload: ${ev.payload}\n`;
      if (ev.matched) p += `matched: ${ev.matched}\n`;
      if (ev.reflected_origin) p += `Access-Control-Allow-Origin: ${ev.reflected_origin}\nAllow-Credentials: ${ev.allow_credentials}\n`;
      if (ev.location) p += `Location: ${ev.location}\n`;
      if (ev.base_time !== undefined) p += `baseline ${ev.base_time}s -> payload ${ev.delay_time}s\n`;
      if (ev.detail && !ev.payload) p += `${ev.detail}\n`;
      if (!p.trim()) p = JSON.stringify(ev, null, 2);
      return p.trim();
    };
    const card = (f, open) => {
      const cls = sevCls(f.severity), ev = f.evidence || {};
      // Version-based CVE leads render like the in-app agCveCard: dashed (non-filled)
      // severity chip, a "version-based · unverified" badge, a "lead, not proof"
      // note, and NO proof-of-concept block — never let them read as confirmed.
      if (f.vuln_class === 'cve') {
        const cvss = (f.cvss != null && f.cvss !== '') ? esc(String(f.cvss)) : '';
        const nvd = f.cve ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve)}` : '';
        const summary = esc((ev.detail || '').replace(/^nmap -sV banner → \S+\.\s*/, ''));
        const vf = f.verification || null, st = vf && vf.status;
        let chipStyle, badge, note;
        if (st === 'verified') {
          const method = esc(String(vf.method || '').toUpperCase());
          const e = vf.evidence || {};
          const tell = e.check ? `${esc(e.check)}${e.tell ? ` → ${esc(e.tell)}` : ''}` : (e.matcher ? `nuclei: ${esc(e.matcher)}` : '');
          chipStyle = '';
          badge = `<span class="cls" style="color:#00D4AA;border:1px solid rgba(0,212,170,.4);background:rgba(0,212,170,.07)">✓ verified${method ? ' · ' + method : ''}</span>`;
          note = `✓ Confirmed${method ? ' by ' + method : ''}${tell ? ' — ' + tell : ''}. Actively reproduced, not just a version match.`;
        } else if (st === 'unverifiable') {
          chipStyle = 'background:none;border-style:dashed';
          const reason = (vf && vf.reason) || 'manual review';
          const why = /unclear/i.test(reason) ? 'its class could not be determined' : 'proving it would need a destructive exploit';
          badge = `<span class="cls" style="color:#FFAA00;border:1px solid rgba(255,170,0,.5);background:rgba(255,170,0,.10)">⚠ not safely verifiable</span>`;
          note = `⚠ Not safely verifiable remotely — ${esc(reason)}. Version match only; ${why}, so verify manually.`;
        } else {
          chipStyle = 'background:none;border-style:dashed';
          badge = `<span class="cls" style="color:#FFAA00;border:1px dashed rgba(255,170,0,.4);background:rgba(255,170,0,.06)">version-based · unverified</span>`;
          note = `⚠ Lead, not proof — matched on the version banner only${(vf && vf.reason) ? ` (${esc(vf.reason)})` : ''}. Verify before reporting.`;
        }
        return `<details class="ag-fcard ${cls}${st === 'verified' ? '' : ' lead'}"${open ? ' open' : ''}>
          <summary class="ag-fh"><span class="ag-sev ${cls}" style="${chipStyle}"><span class="n">${cvss || esc((f.severity || 'info').slice(0, 4).toUpperCase())}</span></span><span class="title">${esc(f.name || f.cve || 'CVE')}</span>${badge}<span class="chev">▸</span></summary>
          <div class="ag-fb">
            <div class="ag-kv"><span class="k">Note</span><span class="v">${note}</span></div>
            ${f.url ? `<div class="ag-kv"><span class="k">Service</span><span class="v">${esc(f.url)}</span></div>` : ''}
            ${f.cpe ? `<div class="ag-kv"><span class="k">CPE</span><span class="v">${esc(f.cpe)}</span></div>` : ''}
            ${cvss ? `<div class="ag-kv"><span class="k">CVSS</span><span class="v">${cvss} · ${esc((f.severity || '').toLowerCase())}</span></div>` : ''}
            ${f.cve ? `<div class="ag-kv"><span class="k">CVE</span><span class="v"><a href="${nvd}">${esc(f.cve)}</a></span></div>` : ''}
            ${summary ? `<div class="ag-kv"><span class="k">Summary</span><span class="v">${summary}</span></div>` : ''}
          </div></details>`;
      }
      return `<details class="ag-fcard ${cls}${f._kind === 'potential' ? ' lead' : ''}"${open ? ' open' : ''}>
        <summary class="ag-fh"><span class="ag-sev ${cls}"><span class="n">${esc((f.severity || 'info').slice(0, 4).toUpperCase())}</span></span><span class="title">${esc(f.name || f.vuln_class || 'Finding')}</span>${f.vuln_class ? `<span class="cls">${esc(f.vuln_class)}</span>` : ''}<span class="chev">▸</span></summary>
        <div class="ag-fb">
          ${f.url ? `<div class="ag-kv"><span class="k">Endpoint</span><span class="v">${esc(f.url)}</span></div>` : ''}
          ${ev.param ? `<div class="ag-kv"><span class="k">Parameter</span><span class="v">${esc(ev.param)}</span></div>` : ''}
          ${(ev.note || ev.detail) ? `<div class="ag-kv"><span class="k">Impact</span><span class="v">${esc(ev.note || ev.detail)}</span></div>` : ''}
          <div class="ag-poc"><div class="lbl">Proof of concept</div><div class="ag-code">${esc(poc(f))}</div></div>
        </div></details>`;
    };
    const hostRows = (hosts.length
      ? hosts.map(h => `<div class="rp-row"><span class="sc ${scCls(h.status_code)}">${esc(String(h.status_code || '—'))}</span><span class="u">${esc(h.url || '')}</span><span class="t">${esc((h.tech || []).join(', '))}</span></div>`).join('')
      : live.map(u => `<div class="rp-row"><span class="u">${esc(u)}</span></div>`).join('')) || '<div class="rp-empty">none</div>';
    const urlRows = urls.length ? urls.slice(0, 500).map(u => `<div class="rp-line">${esc(u)}</div>`).join('') : '<div class="rp-empty">none</div>';
    const modRows = Object.entries(results).map(([name, r]) => `<div class="rp-row"><span class="sc ${r.status === 'success' ? 's2' : r.status === 'skipped' ? 's0' : 's5'}">${esc(r.status || '')}</span><span class="u">${esc(name)} <small>${esc(r.tool_used || 'built-in')}${r.fallback ? ' · fallback' : ''}</small></span><span class="t">${r.items_count} · ${r.duration}s</span></div>`).join('') || '<div class="rp-empty">none</div>';

    const html = `<!doctype html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebKiller — ${esc(scan.target)}</title>
<style>${REPORT_CSS}</style></head><body><main class="rp">
  <div class="ag-head"><div>
    <div class="ag-title">${esc(scan.target)}</div>
    <div class="ag-sub"><span class="ag-pill">WEBKILLER 2.0</span><span class="ag-pill mode">⚔ ${esc(scan.profile || '')}</span><span class="ag-pill done">✓ ${esc(scan.status || 'completed')}</span><span class="ag-pill">${esc(started)} · ${esc(duration)}</span></div>
  </div></div>
  <div class="ag-hero">
    <div class="ag-verdict ${conf.length ? '' : leads.length ? 'leads' : 'clean'}">
      <div class="bigrow"><div class="big ${conf.length ? '' : 'clean'}">${conf.length} confirmed</div>${leads.length ? `<div class="big lead">+ ${leads.length} unconfirmed</div>` : ''}</div>
      <div class="cap">${conf.length ? 'proven with evidence' : leads.length ? 'detected but not reproduced' : 'no vulnerabilities confirmed'}</div>
      ${pills(confSev, false) ? `<div class="sevlbl">Confirmed</div><div class="sevrow">${pills(confSev, false)}</div>` : ''}
      ${pills(leadSev, true) ? `<div class="sevlbl">Leads to verify</div><div class="sevrow">${pills(leadSev, true)}</div>` : ''}
    </div>
    <div class="ag-statgrid">
      <div class="ag-stat"><div class="k">Hosts</div><div class="v ac">${subdomains.length || hosts.length}<small> · ${live.length} live</small></div></div>
      <div class="ag-stat"><div class="k">Endpoints</div><div class="v">${urls.length}</div></div>
      <div class="ag-stat"><div class="k">Params</div><div class="v">${params.length}</div></div>
      <div class="ag-stat"><div class="k">Modules</div><div class="v">${modsRan}<small>/${modsTotal} ran</small></div></div>
    </div>
  </div>
  ${conf.length ? `<div class="ag-sec">Confirmed vulnerabilities <span class="ct">· ${conf.length}</span></div>${conf.map(f => card(f, (f.severity || '').toLowerCase() === 'critical' || (f.severity || '').toLowerCase() === 'high')).join('')}` : ''}
  ${leads.length ? `<div class="ag-sec">Leads to verify <span class="ct">· ${leads.length}</span></div>${leads.map(f => card(f, false)).join('')}` : ''}
  <details class="ag-fold" open><summary><span>Hosts</span><span class="ct">${subdomains.length || hosts.length} · ${live.length} live</span></summary><div class="rp-list">${hostRows}</div></details>
  <details class="ag-fold"><summary><span>Endpoints</span><span class="ct">${urls.length}</span></summary><div class="rp-list">${urlRows}</div></details>
  <details class="ag-fold"><summary><span>Modules</span><span class="ct">${modsRan}/${modsTotal} ran</span></summary><div class="rp-list">${modRows}</div></details>
  <footer class="rp-foot">Generated by WebKiller 2.0 · ${esc(started)} — ${esc(finished)} · ${esc(duration)}</footer>
</main></body></html>`;

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
