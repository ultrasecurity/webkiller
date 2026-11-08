/* ============================================================
   WEBKILLER 2.0 — SPA Frontend
   ============================================================ */

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const app = $('#app');

let currentScanId = null;
let eventSource = null;

/* ── ROUTER ──────────────────────── */

function route() {
  const hash = location.hash.slice(1) || '/';
  $$('.nav-link').forEach(l => l.classList.toggle('active', l.dataset.route === hash.split('/').slice(0,2).join('/')));
  if (hash === '/setup') renderSetup();
  else if (hash === '/') renderDashboard();
  else if (hash === '/scan') renderNewScan();
  else if (hash.startsWith('/scan/')) renderScanProgress(hash.split('/')[2]);
  else if (hash.startsWith('/results/')) renderResults(hash.split('/')[2]);
  else if (hash === '/tools') renderTools();
  else renderDashboard();
}

window.addEventListener('hashchange', route);
window.addEventListener('load', route);

/* ── API ──────────────────────── */

async function api(path, opts = {}) {
  const res = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  return res.json();
}

/* ── DASHBOARD ──────────────────────── */

async function renderDashboard() {
  app.innerHTML = `
    <div class="section-header animate-in">
      <div>
        <h1 class="section-title">Dashboard</h1>
        <p class="section-sub">Recon orchestration engine</p>
      </div>
      <a href="#/scan" class="btn btn-primary">
        <svg class="icon" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>
        New Scan
      </a>
    </div>
    <div class="stat-row animate-in" id="stats" style="animation-delay:.05s">
      <div class="stat-card"><div class="stat-label">Total Scans</div><div class="stat-value teal" id="statScans">—</div></div>
      <div class="stat-card"><div class="stat-label">Running</div><div class="stat-value amber" id="statRunning">—</div></div>
      <div class="stat-card"><div class="stat-label">Completed</div><div class="stat-value green" id="statDone">—</div></div>
      <div class="stat-card"><div class="stat-label">Findings</div><div class="stat-value red" id="statFindings">—</div></div>
    </div>
    <div class="card animate-in" style="animation-delay:.1s">
      <div class="card-header"><span class="card-title">Recent Scans</span></div>
      <div id="scanList"></div>
    </div>
  `;

  const scans = await api('/scans');
  $('#statScans').textContent = scans.length;
  $('#statRunning').textContent = scans.filter(s => s.status === 'running').length;
  $('#statDone').textContent = scans.filter(s => s.status === 'completed').length;

  let totalFindings = 0;
  scans.forEach(s => {
    Object.values(s.results || {}).forEach(r => { totalFindings += r.items_count || 0; });
  });
  $('#statFindings').textContent = totalFindings;

  if (!scans.length) {
    $('#scanList').innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">⚡</div>
        <div class="empty-text">No scans yet</div>
        <a href="#/scan" class="btn btn-primary">Start Your First Scan</a>
      </div>`;
    return;
  }

  $('#scanList').innerHTML = `
    <div class="table-wrap"><table>
      <thead><tr><th>Target</th><th>Profile</th><th>Status</th><th>Modules</th><th>Started</th><th></th></tr></thead>
      <tbody>${scans.map(s => `
        <tr>
          <td class="mono">${esc(s.target)}</td>
          <td><span class="badge badge-info">${esc(s.profile)}</span></td>
          <td>${statusBadge(s.status)}</td>
          <td>${s.modules_done || 0}/${s.modules_total || 0}</td>
          <td>${timeAgo(s.started_at)}</td>
          <td>
            ${s.status === 'running'
              ? `<a href="#/scan/${s.scan_id}" class="btn btn-sm btn-ghost">Watch</a>`
              : `<a href="#/results/${s.scan_id}" class="btn btn-sm btn-ghost">Results</a>`}
          </td>
        </tr>`).join('')}
      </tbody>
    </table></div>`;
}

/* ── NEW SCAN ──────────────────────── */

async function renderNewScan() {
  const profiles = await api('/profiles');

  app.innerHTML = `
    <div class="section-header">
      <div>
        <h1 class="section-title">New Scan</h1>
        <p class="section-sub">Configure and launch a recon scan</p>
      </div>
    </div>
    <div class="card animate-in" style="max-width:720px;animation-delay:.05s">
      <div class="card-body">
        <div class="form-group">
          <label class="form-label">Target Domain</label>
          <input class="form-input" id="targetInput" placeholder="example.com" autofocus>
        </div>
        <div class="form-group">
          <label class="form-label">Scan Profile</label>
          <div class="profile-grid" id="profileGrid">
            ${profiles.map((p, i) => `
              <div class="profile-card${i === 1 ? ' selected' : ''}" data-profile="${esc(p.name)}">
                <div class="profile-name">${esc(p.name)}</div>
                <div class="profile-desc">${esc(p.description)}</div>
                <div class="profile-modules">${(p.modules || []).length} modules</div>
              </div>`).join('')}
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Out of Scope (one per line, optional)</label>
          <textarea class="form-textarea form-input" id="outScope" placeholder="staging.example.com&#10;internal.example.com"></textarea>
        </div>
        <button class="btn btn-primary btn-lg" id="startBtn" style="width:100%;justify-content:center;margin-top:var(--space-4)">
          <svg class="icon" viewBox="0 0 24 24"><polygon points="5,3 19,12 5,21"/></svg>
          Launch Scan
        </button>
      </div>
    </div>
  `;

  let selectedProfile = profiles[1]?.name || 'quick';

  $$('.profile-card').forEach(card => {
    card.addEventListener('click', () => {
      $$('.profile-card').forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      selectedProfile = card.dataset.profile;
    });
  });

  $('#startBtn').addEventListener('click', async () => {
    const target = $('#targetInput').value.trim();
    if (!target) { toast('Enter a target domain', 'error'); return; }
    $('#startBtn').disabled = true;
    $('#startBtn').textContent = 'Launching...';
    const outScope = $('#outScope').value.split('\n').map(s => s.trim()).filter(Boolean);
    const res = await api('/scan', { method: 'POST', body: { target, profile: selectedProfile, out_of_scope: outScope } });
    if (res.scan_id) {
      location.hash = `/scan/${res.scan_id}`;
    } else {
      toast(res.error || 'Failed to start scan', 'error');
      $('#startBtn').disabled = false;
      $('#startBtn').textContent = 'Launch Scan';
    }
  });
}

/* ── SCAN PROGRESS ──────────────────────── */

async function renderScanProgress(scanId) {
  currentScanId = scanId;
  const scan = await api(`/scan/${scanId}`);
  if (!scan || scan.error) { location.hash = '/'; return; }

  const profile = scan.profile || 'unknown';
  const moduleNames = Object.keys(scan.results || {});

  app.innerHTML = `
    <div class="section-header">
      <div>
        <h1 class="section-title">${esc(scan.target)}</h1>
        <p class="section-sub">Profile: <span class="badge badge-info">${esc(profile)}</span> · ${scan.modules_done}/${scan.modules_total} modules</p>
      </div>
      <div>${statusBadge(scan.status)}</div>
    </div>
    <div class="progress-bar" style="margin-bottom:var(--space-5)">
      <div class="progress-fill" id="progressFill" style="width:${pct(scan)}%"></div>
    </div>
    <div class="pipeline" id="pipelineChips"></div>
    <div class="scan-grid">
      <div class="card">
        <div class="card-header"><span class="card-title">Module Results</span></div>
        <div id="moduleResults"></div>
      </div>
      <div class="terminal">
        <div class="terminal-bar">
          <div class="terminal-dots"><div class="terminal-dot red"></div><div class="terminal-dot amber"></div><div class="terminal-dot green"></div></div>
          <div class="terminal-title">live log</div>
        </div>
        <div class="terminal-body" id="terminal"></div>
      </div>
    </div>
  `;

  updateModuleResults(scan);
  startSSE(scanId);
}

function updateModuleResults(scan) {
  const el = $('#moduleResults');
  if (!el) return;
  const results = scan.results || {};
  if (!Object.keys(results).length) {
    el.innerHTML = '<div style="color:var(--text-muted);padding:var(--space-4);font-size:var(--text-sm)">Waiting for modules...</div>';
    return;
  }
  el.innerHTML = Object.entries(results).map(([name, r]) => `
    <div class="tool-row">
      <div>
        <div class="tool-name">${esc(name)}</div>
        <div class="tool-modules">${r.tool_used || 'python'}${r.fallback ? ' (fallback)' : ''} · ${r.duration}s</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-family:var(--font-mono);font-size:var(--text-sm);color:var(--accent-primary)">${r.items_count}</span>
        <div class="tool-status ${r.status === 'success' ? 'installed' : r.status === 'skipped' ? '' : 'missing'}"></div>
      </div>
    </div>`).join('');
}

function startSSE(scanId) {
  if (eventSource) eventSource.close();
  eventSource = new EventSource(`/api/scan/${scanId}/events`);
  const term = $('#terminal');

  eventSource.onmessage = async (e) => {
    const ev = JSON.parse(e.data);

    if (ev.type === 'end') {
      eventSource.close();
      setStatus(ev.status === 'completed' ? 'Ready' : 'Error', ev.status === 'error' ? 'error' : '');
      if ($('#progressFill')) $('#progressFill').style.width = '100%';
      const scan = await api(`/scan/${scanId}`);
      updateModuleResults(scan);
      const hdr = $$('.section-header')[0];
      if (hdr && ev.status === 'completed') {
        const btn = document.createElement('a');
        btn.href = `#/results/${scanId}`;
        btn.className = 'btn btn-primary';
        btn.textContent = 'View Results';
        hdr.querySelector('div:last-child')?.replaceWith(btn);
      }
      return;
    }

    if (term) {
      const t = new Date(ev.time * 1000).toLocaleTimeString('en', {hour12: false});
      term.innerHTML += `<div class="terminal-line"><span class="time">${t}</span><span class="type type-${ev.type}">[${ev.type}]</span>${esc(ev.data)}</div>`;
      term.scrollTop = term.scrollHeight;
    }

    if (ev.type === 'module_start') {
      setStatus(`Scanning: ${ev.data}`, 'scanning');
    }
    if (ev.type === 'module_done') {
      const scan = await api(`/scan/${scanId}`);
      if ($('#progressFill')) $('#progressFill').style.width = `${pct(scan)}%`;
      updateModuleResults(scan);
    }
  };
}

/* ── RESULTS ──────────────────────── */

async function renderResults(scanId) {
  const scan = await api(`/scan/${scanId}`);
  if (!scan || scan.error) { location.hash = '/'; return; }

  app.innerHTML = `
    <div class="section-header">
      <div>
        <h1 class="section-title">${esc(scan.target)}</h1>
        <p class="section-sub">Scan: ${esc(scanId)} · ${statusBadge(scan.status)}</p>
      </div>
      <div style="display:flex;gap:var(--space-2)">
        <button class="btn btn-ghost btn-sm" onclick="exportResults('${scanId}','json')">Export JSON</button>
        <button class="btn btn-ghost btn-sm" onclick="exportResults('${scanId}','html')">Export HTML</button>
      </div>
    </div>
    <div class="tabs" id="resultTabs"></div>
    <div id="resultContent"></div>
  `;

  const tabs = [
    { id: 'subdomains', label: 'Subdomains', file: 'subdomains.txt' },
    { id: 'live', label: 'Live Hosts', file: 'live.txt' },
    { id: 'urls', label: 'URLs', file: 'urls.txt' },
    { id: 'findings', label: 'Findings', file: 'findings.jsonl' },
    { id: 'confirmed', label: 'Confirmed', file: 'confirmed.jsonl' },
    { id: 'hosts', label: 'Hosts', file: 'hosts.jsonl' },
    { id: 'osint', label: 'OSINT', file: 'osint.jsonl' },
    { id: 'js', label: 'JS Recon', file: 'jsrecon.jsonl' },
    { id: 'params', label: 'Params', file: 'params.txt' },
  ];

  async function loadTab(tab) {
    $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab.id));
    const content = $('#resultContent');

    try {
      const data = await fetch(`/api/scan/${scanId}/results/${tab.file}`).then(r => r.ok ? (tab.file.endsWith('.jsonl') ? r.json() : r.text()) : null);
      if (!data || (typeof data === 'string' && !data.trim()) || (Array.isArray(data) && !data.length)) {
        content.innerHTML = '<div class="empty-state"><div class="empty-text">No data in this file</div></div>';
        return;
      }

      if (tab.file.endsWith('.jsonl')) {
        if (tab.id === 'findings' || tab.id === 'confirmed') {
          content.innerHTML = `<div class="card">${data.map(f => `
            <div class="finding-row">
              <div>${severityBadge(f.severity || 'info')}${f.type === 'dast_confirmed' || tab.id === 'confirmed' ? ' <span class="badge badge-confirmed">confirmed</span>' : ''}</div>
              <div style="flex:1">
                <div class="finding-name">${esc(f.name || f.vuln_class || f.template_id || 'Unknown')}</div>
                <div class="finding-url">${esc(f.url || '')}</div>
                ${f.evidence ? `<div class="finding-evidence">${esc(JSON.stringify(f.evidence).slice(0,200))}</div>` : ''}
              </div>
            </div>`).join('')}</div>`;
        } else {
          content.innerHTML = `<div class="table-wrap"><table>
            <thead><tr>${Object.keys(data[0] || {}).map(k => `<th>${esc(k)}</th>`).join('')}</tr></thead>
            <tbody>${data.slice(0, 200).map(row => `<tr>${Object.values(row).map(v =>
              `<td class="mono">${esc(typeof v === 'object' ? JSON.stringify(v) : String(v)).slice(0,100)}</td>`
            ).join('')}</tr>`).join('')}</tbody>
          </table></div>`;
        }
      } else {
        const lines = data.split('\n').filter(Boolean);
        content.innerHTML = `
          <div style="margin-bottom:var(--space-3);color:var(--text-secondary);font-size:var(--text-sm)">${lines.length} items</div>
          <div class="terminal" style="max-height:600px">
            <div class="terminal-bar"><div class="terminal-dots"><div class="terminal-dot red"></div><div class="terminal-dot amber"></div><div class="terminal-dot green"></div></div><div class="terminal-title">${esc(tab.file)}</div></div>
            <div class="terminal-body">${lines.map(l => `<div class="terminal-line">${esc(l)}</div>`).join('')}</div>
          </div>`;
      }
    } catch (e) {
      content.innerHTML = `<div class="empty-state"><div class="empty-text">Error loading data</div></div>`;
    }
  }

  const tabsEl = $('#resultTabs');
  for (const tab of tabs) {
    const el = document.createElement('div');
    el.className = 'tab' + (tab.id === 'subdomains' ? ' active' : '');
    el.dataset.tab = tab.id;
    el.innerHTML = `${tab.label}`;
    el.addEventListener('click', () => loadTab(tab));
    tabsEl.appendChild(el);
  }

  loadTab(tabs[0]);
}

/* ── TOOLS ──────────────────────── */

async function renderTools() {
  const tools = await api('/tools');

  const installed = tools.filter(t => t.installed).length;
  const total = tools.length;

  app.innerHTML = `
    <div class="section-header animate-in">
      <div>
        <h1 class="section-title">Tools Registry</h1>
        <p class="section-sub">${installed}/${total} tools installed</p>
      </div>
    </div>
    <div class="card animate-in" style="animation-delay:.05s">
      ${tools.map(t => `
        <div class="tool-row">
          <div>
            <div class="tool-name">${esc(t.name)}</div>
            <div class="tool-modules">${t.required_for.join(', ')}</div>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:var(--text-xs);color:${t.installed ? 'var(--accent-green)' : 'var(--accent-red)'}">${t.installed ? 'Installed' : 'Missing'}</span>
            <div class="tool-status ${t.installed ? 'installed' : 'missing'}"></div>
          </div>
        </div>`).join('')}
    </div>
  `;
}

/* ── HELPERS ──────────────────────── */

function esc(s) { const d = document.createElement('div'); d.textContent = String(s || ''); return d.innerHTML; }

function pct(scan) { return scan.modules_total ? Math.round((scan.modules_done / scan.modules_total) * 100) : 0; }

function statusBadge(status) {
  const map = { running: 'badge-medium', completed: 'badge-low', error: 'badge-critical', created: 'badge-info' };
  return `<span class="badge ${map[status] || 'badge-info'}">${status}</span>`;
}

function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${sev}</span>`;
}

function timeAgo(ts) {
  if (!ts) return '—';
  const diff = Math.floor((Date.now() / 1000) - ts);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return new Date(ts * 1000).toLocaleDateString();
}

function setStatus(text, cls) {
  const pill = $('#statusPill');
  const txt = $('#statusText');
  if (txt) txt.textContent = text;
  if (pill) { pill.className = 'status-pill' + (cls ? ` ${cls}` : ''); }
}

function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

async function exportResults(scanId, format = 'json') {
  const url = `/api/scan/${scanId}/export/${format}`;
  const a = document.createElement('a');
  a.href = url;
  a.download = '';
  document.body.appendChild(a);
  a.click();
  a.remove();
  toast(`Downloading ${format.toUpperCase()} report...`, 'info');
}

/* ── SETUP WIZARD ──────────────────────── */

async function renderSetup() {
  const isElectron = !!(window.electronAPI && window.electronAPI.isElectron);

  app.innerHTML = `
    <div class="setup-wizard">
      <div class="setup-header animate-in">
        <div class="setup-logo">
          <svg viewBox="0 0 48 48" width="48" height="48"><circle cx="24" cy="24" r="20" fill="none" stroke="var(--accent-primary)" stroke-width="2"/><path d="M24 12 L24 36 M16 20 L24 12 L32 20" fill="none" stroke="var(--accent-primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </div>
        <h1 class="section-title">WebKiller 2.0 Setup</h1>
        <p class="section-sub">Configure your recon environment</p>
      </div>
      <div class="setup-steps" id="setupSteps"></div>
      <div class="setup-content" id="setupContent"></div>
      <div class="setup-nav" id="setupNav"></div>
    </div>
  `;

  let step = 0;
  const steps = ['Environment', 'Tools', 'Ready'];

  function renderSteps() {
    $('#setupSteps').innerHTML = steps.map((s, i) => `
      <div class="setup-step ${i < step ? 'done' : i === step ? 'active' : ''}">
        <div class="step-dot">${i < step ? '✓' : i + 1}</div>
        <div class="step-label">${s}</div>
      </div>
    `).join('<div class="step-line"></div>');
  }

  async function renderStep0() {
    renderSteps();
    const content = $('#setupContent');

    if (!isElectron) {
      content.innerHTML = `
        <div class="card animate-in" style="max-width:600px;margin:0 auto">
          <div class="card-body" style="text-align:center">
            <div class="setup-check-icon ok">✓</div>
            <h2 style="color:var(--text-primary);margin:var(--space-3) 0">Running in Browser Mode</h2>
            <p style="color:var(--text-secondary)">Python environment detected. Tools can be installed manually.</p>
          </div>
        </div>`;
      $('#setupNav').innerHTML = `<button class="btn btn-primary" id="nextBtn">Continue</button>`;
      $('#nextBtn').addEventListener('click', () => { step = 1; renderStep1(); });
      return;
    }

    content.innerHTML = `
      <div class="card animate-in" style="max-width:600px;margin:0 auto">
        <div class="card-body" style="text-align:center">
          <div class="setup-spinner"></div>
          <p style="color:var(--text-secondary);margin-top:var(--space-3)">Checking Python installation...</p>
        </div>
      </div>`;
    $('#setupNav').innerHTML = '';

    const result = await window.electronAPI.checkPython();
    if (result.found && result.meetsMinimum) {
      content.innerHTML = `
        <div class="card animate-in" style="max-width:600px;margin:0 auto">
          <div class="card-body" style="text-align:center">
            <div class="setup-check-icon ok">✓</div>
            <h2 style="color:var(--text-primary);margin:var(--space-3) 0">Python ${esc(result.version)} Found</h2>
            <p class="mono" style="color:var(--text-muted);font-size:var(--text-sm)">${esc(result.path)}</p>
          </div>
        </div>`;
      $('#setupNav').innerHTML = `<button class="btn btn-primary" id="nextBtn">Continue</button>`;
      $('#nextBtn').addEventListener('click', () => { step = 1; renderStep1(); });
    } else {
      const ver = result.found ? `Python ${result.version} found, but 3.8+ required` : 'Python 3.8+ not found';
      content.innerHTML = `
        <div class="card animate-in" style="max-width:600px;margin:0 auto">
          <div class="card-body" style="text-align:center">
            <div class="setup-check-icon fail">✗</div>
            <h2 style="color:var(--accent-red);margin:var(--space-3) 0">${esc(ver)}</h2>
            <p style="color:var(--text-secondary)">Install Python 3.8+ and click Re-check.</p>
            <div class="setup-instructions">
              <code>brew install python@3.12</code> (macOS)<br>
              <code>sudo apt install python3.12</code> (Linux)<br>
              <code>python.org/downloads</code> (Windows)
            </div>
          </div>
        </div>`;
      $('#setupNav').innerHTML = `<button class="btn btn-primary" id="recheckBtn">Re-check</button>`;
      $('#recheckBtn').addEventListener('click', () => renderStep0());
    }
  }

  async function renderStep1() {
    step = 1;
    renderSteps();
    const content = $('#setupContent');

    const toolsStatus = isElectron
      ? await window.electronAPI.getToolsStatus()
      : await api('/tools').then(tools => {
          const r = {};
          tools.forEach(t => { r[t.name] = { installed: t.installed, location: t.installed ? 'system' : 'missing', type: 'unknown' }; });
          return r;
        });

    const entries = Object.entries(toolsStatus);
    const installedCount = entries.filter(([, v]) => v.installed).length;

    content.innerHTML = `
      <div class="animate-in" style="max-width:720px;margin:0 auto">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-4)">
          <div>
            <span style="color:var(--accent-primary);font-size:var(--text-lg);font-weight:700" id="toolCounter">${installedCount}</span>
            <span style="color:var(--text-muted)">/ ${entries.length} tools installed</span>
          </div>
          ${isElectron ? '<button class="btn btn-primary" id="installAllBtn">Install All</button>' : ''}
        </div>
        <div class="progress-bar" style="margin-bottom:var(--space-4)">
          <div class="progress-fill" id="toolsProgress" style="width:${(installedCount / entries.length * 100).toFixed(0)}%"></div>
        </div>
        <div class="tool-grid" id="toolGrid">
          ${entries.map(([name, info]) => `
            <div class="setup-tool-card ${info.installed ? 'installed' : ''}" id="tool-${name}">
              <div class="setup-tool-name">${esc(name)}</div>
              <div class="setup-tool-status">
                ${info.installed
                  ? `<span class="badge badge-low">${info.location === 'system' ? 'System' : 'Installed'}</span>`
                  : info.type === 'system'
                    ? '<span class="badge badge-medium">Manual</span>'
                    : '<span class="badge badge-info">Not installed</span>'}
              </div>
              ${!info.installed && info.installInstructions
                ? `<div class="setup-tool-hint">${esc(info.installInstructions[detectPlatform()] || '')}</div>`
                : ''}
            </div>
          `).join('')}
        </div>
        <div class="terminal" style="margin-top:var(--space-4);display:none" id="installTerminal">
          <div class="terminal-bar"><div class="terminal-dots"><div class="terminal-dot red"></div><div class="terminal-dot amber"></div><div class="terminal-dot green"></div></div><div class="terminal-title">install log</div></div>
          <div class="terminal-body" id="installLog"></div>
        </div>
      </div>`;

    $('#setupNav').innerHTML = `
      <button class="btn btn-ghost" id="skipBtn">Skip</button>
      <button class="btn btn-primary" id="doneBtn">${installedCount === entries.length ? 'Continue' : 'Continue Anyway'}</button>
    `;

    $('#skipBtn').addEventListener('click', async () => {
      if (isElectron) await window.electronAPI.skipSetup();
      location.hash = '/';
    });
    $('#doneBtn').addEventListener('click', () => { step = 2; renderStep2(); });

    if (isElectron && $('#installAllBtn')) {
      $('#installAllBtn').addEventListener('click', async () => {
        $('#installAllBtn').disabled = true;
        $('#installAllBtn').textContent = 'Installing...';
        const termEl = $('#installTerminal');
        if (termEl) termEl.style.display = 'block';

        window.electronAPI.onInstallProgress((data) => {
          const card = $(`#tool-${data.tool}`);
          if (card) {
            const statusEl = card.querySelector('.setup-tool-status');
            if (data.status === 'done') {
              card.classList.add('installed');
              if (statusEl) statusEl.innerHTML = '<span class="badge badge-low">Installed</span>';
            } else if (data.status === 'error') {
              if (statusEl) statusEl.innerHTML = `<span class="badge badge-critical">Error</span>`;
            } else if (data.status === 'starting' || data.status === 'downloading' || data.status === 'extracting' || data.status === 'pip-install') {
              if (statusEl) statusEl.innerHTML = `<span class="badge badge-medium">${data.status}</span>`;
            }
          }
          const log = $('#installLog');
          if (log && data.message) {
            log.innerHTML += `<div class="terminal-line">${esc(data.message)}</div>`;
            log.scrollTop = log.scrollHeight;
          }

          const done = $$('.setup-tool-card.installed').length;
          const counter = $('#toolCounter');
          if (counter) counter.textContent = done;
          const prog = $('#toolsProgress');
          if (prog) prog.style.width = `${(done / entries.length * 100).toFixed(0)}%`;
        });

        await window.electronAPI.installAllTools();
        window.electronAPI.removeInstallProgress();

        await fetch('/api/tools/refresh', { method: 'POST' });

        const btn = $('#installAllBtn');
        if (btn) { btn.textContent = 'Done'; btn.disabled = true; }
        const doneBtn = $('#doneBtn');
        if (doneBtn) doneBtn.textContent = 'Continue';
      });
    }
  }

  async function renderStep2() {
    step = 2;
    renderSteps();
    const content = $('#setupContent');
    content.innerHTML = `
      <div class="card animate-in" style="max-width:600px;margin:0 auto">
        <div class="card-body" style="text-align:center">
          <div class="setup-check-icon ok" style="font-size:48px">⚡</div>
          <h2 style="color:var(--text-primary);margin:var(--space-3) 0">Ready to Hunt</h2>
          <p style="color:var(--text-secondary)">Your recon environment is configured. Start scanning targets.</p>
        </div>
      </div>`;
    $('#setupNav').innerHTML = `<button class="btn btn-primary btn-lg" id="launchBtn">Launch WebKiller</button>`;
    $('#launchBtn').addEventListener('click', async () => {
      if (isElectron) await window.electronAPI.completeSetup();
      location.hash = '/';
    });
  }

  renderStep0();
}

function detectPlatform() {
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('mac')) return 'darwin';
  if (ua.includes('win')) return 'win32';
  return 'linux';
}
