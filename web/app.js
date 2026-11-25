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
  else if (hash === '/scan' || hash.startsWith('/scan?')) renderNewScan(new URLSearchParams(hash.split('?')[1] || '').get('mode'));
  else if (hash.startsWith('/scan/')) renderScanProgress(hash.split('/')[2]);
  else if (hash.startsWith('/results/')) renderResults(hash.split('/')[2]);
  else if (hash === '/tools') { location.hash = '/settings'; return; } // merged into Settings → Dependencies
  else if (hash === '/settings') renderSettings();
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
        <p class="section-sub">Your scans and findings</p>
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
  scans.forEach(s => { totalFindings += (s.findings || 0); });
  $('#statFindings').textContent = totalFindings;

  if (!scans.length) {
    app.innerHTML = `
      <div class="section-header animate-in"><div><h1 class="section-title">Welcome to WebKiller</h1><p class="section-sub">Authorized web reconnaissance & security testing</p></div></div>
      <div class="card animate-in dash-hero">
        <div class="dash-hero-ic">◢◤</div>
        <h2 class="dash-hero-t">Start your first scan</h2>
        <p class="dash-hero-d">Point it at a target. It maps the attack surface — and in agent mode, tests it and confirms findings with proof.</p>
        <div class="dash-modes">
          <a href="#/scan?mode=ai" class="dash-mode"><div class="dm-ic">◇</div><div class="dm-t">AI agent <span class="badge badge-confirmed">beta</span></div><div class="dm-d">The agent picks the steps and confirms findings itself.</div></a>
          <a href="#/scan" class="dash-mode"><div class="dm-ic">▤</div><div class="dm-t">Classic recon</div><div class="dm-d">A fixed pipeline you control, module by module.</div></a>
        </div>
      </div>
      <div class="card animate-in" style="animation-delay:.05s"><div class="card-header"><span class="card-title">How it works</span></div>
        <div class="dash-steps">
          <div class="dash-step"><span class="ds-n">1</span><div><b>Enter a target</b><div class="ds-d"><span class="mono">example.com</span></div></div></div>
          <div class="dash-step"><span class="ds-n">2</span><div><b>Pick a mode</b><div class="ds-d">classic or AI agent</div></div></div>
          <div class="dash-step"><span class="ds-n">3</span><div><b>Review findings</b><div class="ds-d">confirmed, with PoC</div></div></div>
        </div>
      </div>`;
    return;
  }

  const findingsOf = s => s.findings || 0;
  $('#scanList').innerHTML = `
    <div class="scan-rows">${scans.map(s => {
      const err = s.status === 'error';
      const href = s.status === 'running' ? `#/scan/${s.scan_id}` : `#/results/${s.scan_id}`;
      const f = findingsOf(s);
      const modeBadge = s.mode === 'ai' ? '<span class="badge badge-confirmed">AI</span>' : `<span class="badge badge-info">${esc(s.profile)}</span>`;
      const prog = s.mode === 'ai' ? '' : `<span class="sr-find">${s.modules_done || 0}/${s.modules_total || 0} modules</span>`;
      const find = err ? `<span class="sr-find none">—</span>` : (f > 0 ? `<span class="sr-find"><b>${f}</b> findings</span>` : (s.status === 'completed' ? '<span class="sr-find none">no findings</span>' : prog));
      const sub = err ? 'failed' : (s.status === 'running' ? 'in progress' : 'completed');
      return `<a href="${href}" class="scan-row">
        <div class="sr-main"><div class="sr-target">${esc(s.target)} ${modeBadge}</div><div class="sr-sub">${sub}</div></div>
        ${statusBadge(s.status)}
        ${find}
        <span class="sr-time">${timeAgo(s.started_at)}</span>
        <span class="sr-go">${s.status === 'running' ? 'Watch →' : err ? 'Details →' : 'Results →'}</span>
      </a>`;
    }).join('')}</div>`;
}

/* ── NEW SCAN ──────────────────────── */

function prettyModuleKey(k) {
  return String(k).replace(/_confirm$/, '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

async function renderNewScan(initialMode) {
  const [profiles, aiCfg, modData] = await Promise.all([api('/profiles'), api('/ai/settings'), api('/modules')]);
  const startAi = initialMode === 'ai'; // deep-linked from the dashboard "AI agent" card → open in AI mode
  const ORDER = { passive: 0, quick: 1, full: 2, aggressive: 3 };
  const sorted = [...profiles].sort((a, b) => (ORDER[a.name] ?? 9) - (ORDER[b.name] ?? 9));
  const aiReady = !!(aiCfg && aiCfg.enabled && aiCfg.hasKey);
  const metaByKey = {};
  (modData.modules || []).forEach(m => { metaByKey[m.key] = m; });
  const SEC_ORDER = ['Discovery', 'Mapping', 'Checks', 'Other'];

  app.innerHTML = `
    <div class="ns">
      <div class="section-header">
        <div>
          <h1 class="section-title">New Scan</h1>
          <p class="section-sub">Pick a target and a mode</p>
        </div>
      </div>

      <div class="ns-grid animate-in" style="animation-delay:.05s">
        <div class="card ns-form">
          <div class="card-body">
            <div class="form-group">
              <label class="form-label">Target</label>
              <input class="form-input" id="targetInput" placeholder="example.com" autofocus>
            </div>

            <div class="form-group">
              <label class="form-label">Out of scope <span class="label-hint">— one per line, optional</span></label>
              <textarea class="form-textarea form-input" id="outScope" rows="2" placeholder="staging.example.com&#10;internal.example.com"></textarea>
            </div>

            <div class="form-group">
              <label class="form-label">Mode</label>
              <div class="choice-grid" id="modeGrid">
                <div class="choice-card${startAi ? '' : ' selected'}" data-mode="classic">
                  <div class="choice-name">Classic</div>
                  <div class="choice-desc">A fixed pipeline you control.</div>
                </div>
                <div class="choice-card${startAi ? ' selected' : ''}" data-mode="ai">
                  <div class="choice-name">AI Agent <span class="choice-tag">beta</span></div>
                  <div class="choice-desc">The agent picks the steps.</div>
                  <div class="choice-status ${aiReady ? 'ok' : 'warn'}">${aiReady ? '✓ provider configured' : '⚠ needs a provider key'}</div>
                </div>
              </div>
            </div>

            <div class="form-group" id="classicProfile"${startAi ? ' hidden' : ''}>
              <label class="form-label">Profile</label>
              <div class="np-seg" id="profileSeg">
                ${sorted.map(p => { const n = (p.modules || []).length; return `
                  <button class="np-pill${p.name === 'quick' ? ' on' : ''}" data-profile="${esc(p.name)}" title="${esc(p.description)}">
                    <span class="pn">${esc(p.name)}</span><span class="pc">${n} module${n === 1 ? '' : 's'}</span>
                  </button>`; }).join('')}
              </div>
            </div>

            <div class="form-group" id="aiScope"${startAi ? '' : ' hidden'}>
              <label class="form-label">What the agent may do</label>
              <div class="choice-grid">
                <div class="choice-card selected" data-aiscope="recon">
                  <div class="choice-name">Recon only</div>
                  <div class="choice-desc">Map the surface — no payloads sent.</div>
                </div>
                <div class="choice-card" data-aiscope="active">
                  <div class="choice-name">Active tests</div>
                  <div class="choice-desc">Also confirm vulnerabilities (intrusive).</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="ns-preview">
          <div class="np-plan" id="npPlan"${startAi ? ' hidden' : ''}></div>
          <div class="np-plan pb" id="aiPlaybook"${startAi ? '' : ' hidden'}></div>
        </div>
      </div>

      <div class="ns-bar">
        <div class="ns-sum" id="nsSum"></div>
        <button class="btn btn-primary btn-md" id="startBtn">
          <svg class="icon" viewBox="0 0 24 24"><polygon points="5,3 19,12 5,21"/></svg>
          <span id="startLbl">Launch Scan</span>
        </button>
      </div>
    </div>
  `;

  let selectedProfile = 'quick';
  let scanMode = startAi ? 'ai' : 'classic';
  let aiScopeChoice = 'recon';

  // Scan-plan preview: the chosen profile's modules grouped by section,
  // greyed when disabled in Settings, dashed when a required tool is missing.
  function renderPlan(profileName) {
    const prof = profiles.find(p => p.name === profileName);
    const keys = (prof && prof.modules) || [];
    const bySec = {};
    let off = 0, blocked = 0;
    keys.forEach(k => {
      const m = metaByKey[k];
      const sec = (m && m.group) || 'Other';
      (bySec[sec] = bySec[sec] || []).push({ key: k, m });
    });
    const secHtml = SEC_ORDER.filter(s => bySec[s]).map(sec => {
      const chips = bySec[sec].map(({ key, m }) => {
        const label = m ? m.label : prettyModuleKey(key);
        let cls = '', title = '';
        if (m && m.status === 'blocked') { cls = 'blocked'; blocked++; title = `${m.tool} not installed`; }
        else if (m && m.enabled === false) { cls = 'off'; off++; title = 'disabled in Settings'; }
        if (m && m.intrusive) cls += ' intr';
        return `<span class="np-chip ${cls}" title="${esc(title)}"><span class="dot"></span>${esc(label)}</span>`;
      }).join('');
      return `<div class="np-sec"><div class="np-sec-h">${sec}<span class="ln"></span></div><div class="np-chips">${chips}</div></div>`;
    }).join('');
    const notes = [];
    if (off) notes.push(`${off} off`);
    if (blocked) notes.push(`${blocked} need a tool`);
    $('#npPlan').innerHTML = `
      <div class="np-plan-h"><span class="t">Scan plan</span><span class="c">${keys.length} modules${notes.length ? ' · ' + notes.join(' · ') : ''} · <a href="#/settings">tune</a></span></div>
      ${secHtml || '<div class="np-empty">No modules in this profile.</div>'}`;
  }
  renderPlan('quick');

  // Agentic "playbook": how the agent will work, phase by phase, with the
  // capabilities it MAY reach for — not a fixed checklist. The Confirm phase is
  // locked unless the run allows active tests.
  const PLAYBOOK = [
    { name: 'Recon', desc: 'Enumerate subdomains, probe live hosts, map DNS', keys: ['subdomains_passive', 'subdomains_active', 'probe', 'portscan', 'osint_dns'] },
    { name: 'Surface', desc: 'Collect URLs, brute-force paths, pull endpoints & params from JS', keys: ['urls', 'content', 'params', 'jsrecon'] },
    { name: 'Fingerprint', desc: 'Identify tech stack, servers and WAF', keys: ['fingerprint', 'screenshots'] },
    { name: 'Confirm', desc: 'Actively test the surface and prove vulnerabilities with evidence', intrusive: true, keys: ['vuln_signal', 'xss_confirm', 'sqli_confirm', 'ssti_confirm', 'lfi_confirm', 'ssrf_confirm', 'xxe_confirm', 'deser_confirm', 'jwt_confirm', 'massassign_confirm', 'nosqli_confirm', 'cors_confirm', 'openredirect_confirm', 'protopollution_confirm', 'graphql_confirm', 'secret_verify'] },
    { name: 'Report', desc: 'Summarize confirmed findings with proof-of-concept', keys: [] },
  ];
  function renderPlaybook(scope) {
    const box = $('#aiPlaybook'); if (!box) return;
    const rows = PLAYBOOK.map((ph, i) => {
      const locked = ph.intrusive && scope !== 'active';
      const chips = ph.keys.map(k => {
        const m = metaByKey[k];
        const label = m ? m.label : prettyModuleKey(k);
        let cls = '';
        if (m && m.status === 'blocked') cls = 'blocked';
        else if (m && m.enabled === false) cls = 'off';
        if (m && m.intrusive) cls += ' intr';
        return `<span class="np-chip ${cls}"><span class="dot"></span>${esc(label)}</span>`;
      }).join('');
      const desc = locked ? `${ph.keys.length} active checks · unlocked with Active tests` : esc(ph.desc);
      return `<div class="pb-phase${locked ? ' locked' : ''}">
        <div class="pb-num">${locked ? '🔒' : i + 1}</div>
        <div class="pb-body">
          <div class="pb-head"><span class="pb-name">${ph.name}</span><span class="pb-desc">${desc}</span></div>
          ${ph.keys.length && !locked ? `<div class="np-chips">${chips}</div>` : ''}
        </div>
      </div>`;
    }).join('');
    box.innerHTML = `
      <div class="np-plan-h"><span class="t">Agent playbook</span><span class="c">the agent picks which steps to run · <a href="#/settings">tune tools</a></span></div>
      <div class="pb-rail">${rows}</div>`;
  }
  renderPlaybook('recon');

  // A one-line, always-visible summary of what Launch will run (the sticky bar
  // keeps selections in view even when the left column scrolls off).
  function renderSum() {
    const el = $('#nsSum'); if (!el) return;
    const t = ((($('#targetInput') || {}).value) || '').trim() || 'target';
    el.innerHTML = scanMode === 'ai'
      ? `$ scan <b>${esc(t)}</b> · ai agent${aiScopeChoice === 'active' ? ' · <span class="intr">active tests</span>' : ' · recon only'}`
      : `$ scan <b>${esc(t)}</b> · ${esc(selectedProfile)}`;
  }
  renderSum();

  const wireGroup = (sel, onPick) => $$(sel).forEach(card => card.addEventListener('click', () => {
    $$(sel).forEach(c => c.classList.remove('selected'));
    card.classList.add('selected');
    onPick(card);
  }));
  $$('#profileSeg .np-pill').forEach(pill => pill.addEventListener('click', () => {
    $$('#profileSeg .np-pill').forEach(p => p.classList.remove('on'));
    pill.classList.add('on');
    selectedProfile = pill.dataset.profile;
    renderPlan(selectedProfile); renderSum();
  }));
  wireGroup('#aiScope .choice-card', c => { aiScopeChoice = c.dataset.aiscope; renderPlaybook(aiScopeChoice); renderSum(); });
  wireGroup('#modeGrid .choice-card', c => {
    scanMode = c.dataset.mode;
    const ai = scanMode === 'ai';
    $('#classicProfile').hidden = ai;
    $('#aiScope').hidden = !ai;
    $('#npPlan').hidden = ai;
    $('#aiPlaybook').hidden = !ai;
    renderSum();
  });

  const launch = async () => {
    const target = $('#targetInput').value.trim();
    if (!target) { const ti = $('#targetInput'); if (ti) { ti.classList.add('err'); ti.focus(); } toast('Enter a target domain', 'error'); return; }
    if (scanMode === 'ai' && !aiReady) { toast('Set a provider key in Settings first', 'error'); location.hash = '/settings'; return; }
    // In AI mode the "profile" only gates intrusive tools, so map the agent's
    // scope choice onto a backend profile (aggressive = intrusive allowed).
    const profile = scanMode === 'ai' ? (aiScopeChoice === 'active' ? 'aggressive' : 'quick') : selectedProfile;
    $('#startBtn').disabled = true;
    const lbl = $('#startLbl'); if (lbl) lbl.textContent = 'Launching…';
    const outScope = $('#outScope').value.split('\n').map(s => s.trim()).filter(Boolean);
    const res = await api('/scan', { method: 'POST', body: { target, profile, out_of_scope: outScope, mode: scanMode } });
    if (res.scan_id) {
      location.hash = `/scan/${res.scan_id}`;
    } else {
      toast(res.error || 'Failed to start scan', 'error');
      $('#startBtn').disabled = false;
      if (lbl) lbl.textContent = 'Launch Scan';
    }
  };
  $('#startBtn').addEventListener('click', launch);
  const tin = $('#targetInput');
  if (tin) {
    tin.addEventListener('input', () => { tin.classList.remove('err'); renderSum(); });
    tin.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); launch(); } });
  }
}

/* ── SCAN PROGRESS ──────────────────────── */

async function renderScanProgress(scanId) {
  currentScanId = scanId;
  const scan = await api(`/scan/${scanId}`);
  if (!scan || !scan.status) { location.hash = "/"; return; } // a real 404 has no status; an errored scan keeps its status
  if (scan.mode === 'ai') return renderAgenticProgress(scanId, scan);

  const profile = scan.profile || 'unknown';
  const moduleNames = Object.keys(scan.results || {});

  if (agTimer) { clearInterval(agTimer); agTimer = null; }
  app.innerHTML = `
    <div class="ag-head">
      <div>
        <div class="ag-title">${esc(scan.target)}</div>
        <div class="ag-sub">
          <span class="ag-pill">▤ CLASSIC</span>
          <span class="ag-pill mode">⚔ ${esc(profile)}</span>
          <span class="ag-pill live" id="agPhasePill"><span class="dot"></span>${scan.status === 'running' ? 'running…' : esc(scan.status)}</span>
          ${scan.status === 'running' ? '<button class="btn btn-ghost btn-sm" id="scStop" style="margin-left:8px">■ Stop</button>' : ''}
        </div>
      </div>
      <div class="ag-meters">
        <div class="ag-meter"><div class="k">Elapsed</div><div class="val" id="agElapsed">00:00</div></div>
        <div class="ag-meter"><div class="k">Modules</div><div class="val" id="scMods">${scan.modules_done || 0}/${scan.modules_total || 0}</div></div>
        <div class="ag-meter"><div class="k">Items</div><div class="val ac" id="scItems">0</div></div>
      </div>
    </div>
    <div class="progress-bar sc-progress"><div class="progress-fill" id="progressFill" style="width:${pct(scan)}%"></div></div>
    <div class="ag-now">
      <div class="terminal ag-term">
        <div class="terminal-bar"><div class="terminal-dots"><div class="terminal-dot red"></div><div class="terminal-dot amber"></div><div class="terminal-dot green"></div></div><div class="terminal-title">scan run — live</div><span class="cnt" id="agStepCnt"></span></div>
        <div class="terminal-body ag-stream" id="agStream"><div class="ag-empty" style="padding:var(--space-4)">waiting for modules…</div></div>
      </div>
    </div>
    <div class="ag-ftick" id="agFtick"></div>
  `;

  // Reuse the agentic timeline components (agStream/agAddStep/agFinishStep/agFinding)
  // by giving them the same DOM ids + state. No phase map in classic — just the stream.
  agProgressState = {
    reached: 0, steps: 0, stepEls: {}, http: 0, find: 0,
    sev: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, leadHits: {},
    t0: (scan.started_at ? scan.started_at * 1000 : Date.now()), done: false, stopped: false,
    target: scan.target, items: 0,
  };
  agTimer = setInterval(() => {
    const st = agProgressState; if (!st) return;
    const e = Math.max(0, Math.floor((Date.now() - st.t0) / 1000));
    const el = $('#agElapsed'); if (el) el.textContent = String(Math.floor(e / 60)).padStart(2, '0') + ':' + String(e % 60).padStart(2, '0');
    $$('.ag-step.run .tmr').forEach(t => { const s = +t.dataset.start || Date.now(); t.textContent = ((Date.now() - s) / 1000).toFixed(1) + 's'; });
  }, 200);

  startSSE(scanId);
  const scStop = $('#scStop');
  if (scStop) scStop.addEventListener('click', async () => {
    const ok = await depConfirm('Stop this scan?', '<p style="color:var(--text-secondary);line-height:1.6;margin:0">The scan halts now. Results gathered so far are kept. You can launch a new scan anytime.</p>', 'Stop scan');
    if (!ok) return;
    scStop.disabled = true; scStop.textContent = 'Stopping…';
    try { await api(`/scan/${scanId}/stop`, { method: 'POST' }); } catch { /* SSE reflects the stop */ }
  });
}

function startSSE(scanId) {
  if (eventSource) eventSource.close();
  eventSource = new EventSource(`/api/scan/${scanId}/events`);
  const seen = new Set(); // module_start/done arrive twice (engine string + module JSON) — dedupe by name

  eventSource.onmessage = async (e) => {
    let ev; try { ev = JSON.parse(e.data); } catch { return; }
    const d = ev.data;

    if (ev.type === 'end') {
      if (agTimer) { clearInterval(agTimer); agTimer = null; }
      eventSource.close(); eventSource = null;
      setStatus(ev.status === 'completed' ? 'Ready' : ev.status === 'stopped' ? 'Stopped' : 'Error', ev.status === 'error' ? 'error' : '');
      if ($('#progressFill')) $('#progressFill').style.width = '100%';
      const st = agProgressState; if (st) { st.done = ev.status !== 'stopped'; st.stopped = ev.status === 'stopped'; }
      const pill = $('#agPhasePill'); if (pill) { pill.classList.remove('live'); pill.innerHTML = ev.status === 'completed' ? '✓ complete' : ev.status === 'stopped' ? '■ stopped' : '✕ error'; }
      const stop = $('#scStop'); if (stop) stop.remove();
      const sub = $('.ag-sub');
      if (sub && !$('#scViewResults') && (ev.status === 'completed' || ev.status === 'stopped')) {
        const b = document.createElement('a'); b.id = 'scViewResults'; b.href = `#/results/${scanId}`;
        b.className = 'btn btn-primary btn-sm'; b.style.marginLeft = '8px'; b.textContent = 'View Results →';
        sub.appendChild(b);
      }
      return;
    }

    if (ev.type === 'module_start') {
      let name; try { name = JSON.parse(d).module; } catch { name = d; }
      if (!name || seen.has('s:' + name)) return; seen.add('s:' + name);
      agAddStep(name, ev.time);
      setStatus(`Scanning: ${name}`, 'scanning');
      return;
    }
    if (ev.type === 'module_done') {
      let name; try { name = JSON.parse(d).module; } catch { const m = String(d).match(/^(\S+):/); name = m ? m[1] : d; }
      if (!name || seen.has('d:' + name)) return; seen.add('d:' + name);
      const scan = await api(`/scan/${scanId}`);
      const r = (scan.results || {})[name] || {};
      const ok = !r.status || r.status === 'success' || r.status === 'completed';
      agFinishStep(name, { found: r.items_count || 0, status: ok ? 'success' : (r.status || 'error') });
      const rows = agProgressState.stepEls[name] || []; const row = rows[rows.length - 1];
      if (row && !row.querySelector('.smp')) { const smp = document.createElement('div'); smp.className = 'smp'; smp.textContent = (r.tool_used || 'built-in') + (r.fallback ? ' · fallback' : ''); row.appendChild(smp); }
      if (row && r.duration != null) { const tmr = row.querySelector('.tmr'); if (tmr) tmr.textContent = (+r.duration).toFixed(1) + 's'; } // authoritative server duration (correct on reload)
      if ($('#progressFill')) $('#progressFill').style.width = `${pct(scan)}%`;
      const mods = $('#scMods'); if (mods) mods.textContent = `${scan.modules_done || 0}/${scan.modules_total || 0}`;
      const items = Object.values(scan.results || {}).reduce((n, x) => n + (x.items_count || 0), 0);
      const its = $('#scItems'); if (its) its.textContent = items;
      return;
    }

    if (ev.type === 'confirmed' || ev.type === 'finding') {
      let o = {}; try { o = JSON.parse(d); } catch {}
      const sev = String(o.severity || o.sev || 'info'); const nm = o.name || o.vuln_class || o.title || ev.type;
      if (ev.type === 'confirmed') { agFinding(sev); agStream('hit', `${sev.toUpperCase()} — ${nm}${o.url ? ' ' + o.url : ''}`, ev.time); }
      else { agStream('sys', `lead: ${nm}`, ev.time); }
      return;
    }
    if (ev.type === 'scan_done') { agStream(d === 'completed' ? 'end' : 'end bad', 'scan ' + d, ev.time); return; }
    if (ev.type === 'log') { let msg = d; try { msg = JSON.parse(d).msg || d; } catch {} agStream('sys', msg, ev.time); return; }
    if (ev.type === 'error' || ev.type === 'module_error') { agStream('hit', 'error: ' + (typeof d === 'string' ? d : JSON.stringify(d)), ev.time); return; }
    // parallel_start / skip / warn / anything else → a muted line, so nothing is silently dropped
    agStream('sys', typeof d === 'string' ? (d || ev.type) : `${ev.type}: ${JSON.stringify(d)}`, ev.time);
  };
}

/* ── RESULTS ──────────────────────── */

/* Shared result views — used by the classic Results tabs AND the agentic
   recon fold, so discovered data reads the same rich way in both modes. */
async function resGrab(scanId, file) {
  try {
    const r = await fetch(`/api/scan/${scanId}/results/${file}`);
    if (!r.ok) return file.endsWith('.jsonl') ? [] : '';
    return file.endsWith('.jsonl') ? r.json() : r.text();
  } catch { return file.endsWith('.jsonl') ? [] : ''; }
}
const resLines = s => String(s || '').split('\n').map(x => x.trim()).filter(Boolean);
const resScClass = c => { const n = +c || 0; return n >= 500 ? 's5' : n >= 400 ? 's4' : n >= 300 ? 's3' : n >= 200 ? 's2' : 's0'; };
const resHostOf = u => { try { return new URL(u).host; } catch { return ''; } };
const resEmpty = m => `<div class="res-empty">${esc(m)}</div>`;
const resCopyBtn = () => `<button class="res-mini" data-copyall>Copy all</button>`;
function resWireSearch(scopeEl) {
  const input = scopeEl.querySelector('[data-search]');
  const apply = () => {
    const q = (input ? input.value : '').trim().toLowerCase();
    let shown = 0;
    scopeEl.querySelectorAll('[data-hay]').forEach(row => {
      const ok = (!q || row.dataset.hay.includes(q)) && row.dataset.filtered !== '1';
      row.style.display = ok ? '' : 'none';
      if (ok) shown++;
    });
    const live = scopeEl.querySelector('[data-shown]');
    if (live) live.textContent = shown;
  };
  if (input) input.addEventListener('input', apply);
  return apply;
}
function resWireCopyAll(scopeEl, getItems) {
  const b = scopeEl.querySelector('[data-copyall]');
  if (!b) return;
  b.addEventListener('click', () => {
    try { navigator.clipboard.writeText(getItems().join('\n')); const o = b.textContent; b.textContent = 'Copied ✓'; setTimeout(() => b.textContent = o, 1200); } catch {}
  });
}

// HOSTS: subdomains + live + hosts, merged
async function resHostsView(scanId, content) {
  const [subTxt, recs] = await Promise.all([resGrab(scanId, 'subdomains.txt'), resGrab(scanId, 'hosts.jsonl')]);
  const subs = resLines(subTxt);
  const byHost = {};
  (recs || []).forEach(r => {
    const h = r.host || resHostOf(r.url || '');
    if (!h) return;
    const prev = byHost[h];
    if (!prev || ((r.status_code || 0) && !(prev.status_code || 0))) byHost[h] = r;
  });
  const all = [...new Set([...subs, ...Object.keys(byHost)])];
  if (!all.length) { content.innerHTML = resEmpty('No hosts discovered yet.'); return; }
  const isLive = h => (byHost[h]?.status_code || 0) >= 200 && (byHost[h]?.status_code || 0) < 400;
  const liveCount = all.filter(isLive).length;
  all.sort((a, b) => (isLive(a) ? 0 : 1) - (isLive(b) ? 0 : 1) || a.localeCompare(b));
  const rows = all.map(h => {
    const r = byHost[h] || {};
    const sc = r.status_code || 0;
    const dot = sc >= 200 && sc < 400 ? 'up' : sc >= 400 ? 'warn' : 'down';
    const live = sc >= 200 && sc < 400;
    const tech = (r.tech || []).slice(0, 3).map(t => `<span class="res-tag">${esc(t)}</span>`).join('');
    const srv = r.webserver ? `<span class="res-tag srv">${esc(r.webserver)}</span>` : '';
    const open = (live && r.url) ? `<a class="res-open" href="${esc(r.url)}" target="_blank" rel="noopener">open ↗</a>` : '';
    return `<div class="res-host" data-hay="${esc(h.toLowerCase())}">
      <span class="res-dot ${dot}"></span>
      <span class="res-hname${live ? '' : ' dim'}">${esc(h)}</span>
      <span class="res-sc ${resScClass(sc)}">${sc || '—'}</span>
      <span class="res-htitle">${esc(r.title || '')}</span>
      <span class="res-hr">${tech}${srv}${open}</span>
    </div>`;
  }).join('');
  content.innerHTML = `
    <div class="res-bar">
      <div class="res-search"><span class="ic">⌕</span><input data-search placeholder="Filter hosts…"></div>
      <span class="res-count"><b data-shown>${all.length}</b> hosts · ${liveCount} live</span>
      ${resCopyBtn()}
    </div>
    <div class="res-list">${rows}</div>`;
  resWireSearch(content)();
  resWireCopyAll(content, () => all);
}

// ENDPOINTS: urls + params + js endpoints, merged
async function resEndpointsView(scanId, content) {
  const CAP = 500;
  const [urlTxt, paramTxt, jsTxt] = await Promise.all([resGrab(scanId, 'urls.txt'), resGrab(scanId, 'params.txt'), resGrab(scanId, 'js_endpoints.txt')]);
  const urls = resLines(urlTxt);
  const jsSet = new Set(resLines(jsTxt));
  const pmap = {};
  resLines(paramTxt).forEach(l => { const i = l.indexOf('?'); if (i < 0) return; const base = l.slice(0, i); const p = l.slice(i + 1).split('=')[0].split('&')[0]; if (p) (pmap[base] = pmap[base] || new Set()).add(p); });
  const all = [...new Set([...urls, ...Object.keys(pmap), ...jsSet])].sort();
  if (!all.length) { content.innerHTML = resEmpty('No endpoints collected yet.'); return; }
  const withParams = all.filter(u => { const b = u.split('?')[0]; return (pmap[b] && pmap[b].size) || u.includes('?'); }).length;
  const shown = all.slice(0, CAP);
  const rows = shown.map(u => {
    const base = u.split('?')[0];
    const params = new Set(pmap[base] ? [...pmap[base]] : []);
    const qi = u.indexOf('?');
    if (qi >= 0) u.slice(qi + 1).split('&').forEach(kv => { const k = kv.split('=')[0]; if (k) params.add(k); });
    const host = resHostOf(u);
    const path = host ? u.replace(/^https?:\/\/[^/]+/, '') || '/' : u;
    const pills = [...params].slice(0, 6).map(p => `<span class="p">${esc(p)}</span>`).join('');
    const src = jsSet.has(u) ? '<span class="res-src js">JS</span>' : '';
    return `<div class="res-ep" data-hay="${esc(u.toLowerCase())}">
      <span class="res-url"><span class="host">${esc(host)}</span>${esc(path)}</span>
      <span class="res-params">${pills}</span>
      ${src || '<span></span>'}
    </div>`;
  }).join('');
  content.innerHTML = `
    <div class="res-bar">
      <div class="res-search"><span class="ic">⌕</span><input data-search placeholder="Filter endpoints…"></div>
      <span class="res-count"><b data-shown>${shown.length}</b> endpoints · ${withParams} with params</span>
      ${resCopyBtn()}
    </div>
    <div class="res-list">${rows}</div>
    ${all.length > CAP ? `<div class="res-cap">Showing first ${CAP} of ${all.length} — use the filter to narrow.</div>` : ''}`;
  resWireSearch(content)();
  resWireCopyAll(content, () => all);
}

// Merge findings.jsonl + confirmed.jsonl, dedupe by endpoint/param/class.
// Single source of truth so the Leads badge and the rendered list always agree.
function resMergeFindings(find, conf) {
  const key = f => `${String(f.vuln_class || f.name || '').toLowerCase()}|${f.url || ''}|${(f.evidence && f.evidence.param) || ''}|${f.cve || ''}`;
  const map = new Map();
  (conf || []).forEach(f => map.set(key(f), { ...f, _kind: 'confirmed' }));
  (find || []).forEach(f => { const k = key(f); if (!map.has(k)) map.set(k, { ...f, _kind: f.type === 'dast_confirmed' ? 'confirmed' : 'potential' }); });
  return [...map.values()];
}

// FINDINGS: findings + confirmed, merged & deduped (confirmed wins)
async function resFindingsView(scanId, content, opts = {}) {
  const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const [find, conf, verifs] = await Promise.all([resGrab(scanId, 'findings.jsonl'), resGrab(scanId, 'confirmed.jsonl'), resGrab(scanId, 'verifications.jsonl')]);
  let all = resMergeFindings(find, conf);
  // Join CVE verification status (side-file) onto any cve lead that doesn't already
  // carry it (verified ones come pre-tagged from confirmed.jsonl).
  const vmap = {}; (verifs || []).forEach(v => { vmap[`${v.cve}|${v.url}`] = v; });
  all.forEach(f => { if ((f.vuln_class === 'cve' || f.cve) && !f.verification) { const v = vmap[`${f.cve}|${f.url}`]; if (v) f.verification = v; } });
  if (opts.only) all = all.filter(f => f._kind === opts.only);
  if (opts.service) all = all.filter(f => (f.url || '') === opts.service);
  all.sort((a, b) => (SEV[(a.severity || 'info').toLowerCase()] ?? 5) - (SEV[(b.severity || 'info').toLowerCase()] ?? 5));
  if (!all.length) { content.innerHTML = resEmpty(opts.service ? `No leads for ${esc(opts.service)}.` : (opts.emptyMsg || 'No findings — the surface looked clean, or active checks were off.')); return; }
  const nConf = all.filter(f => f._kind === 'confirmed').length;
  const cards = all.map(f => `<div data-hay="${esc((String(f.name || '') + ' ' + (f.url || '') + ' ' + (f.vuln_class || '')).toLowerCase())}" data-kind="${f._kind}">${agFindingCard(f)}</div>`).join('');
  const bar = opts.only ? '' : `
      <button class="res-chip on" data-fk="all">All <span class="n">${all.length}</span></button>
      <button class="res-chip" data-fk="confirmed">Confirmed <span class="n">${nConf}</span></button>
      <button class="res-chip" data-fk="potential">Potential <span class="n">${all.length - nConf}</span></button>`;
  const svcNote = opts.service ? `<button class="res-chip on" data-svcclear>service: ${esc(opts.service)} ✕</button>` : '';
  content.innerHTML = `
    <div class="res-bar">
      <div class="res-search"><span class="ic">⌕</span><input data-search placeholder="Filter findings…"></div>
      ${svcNote}${bar}
    </div>
    <div class="res-finds">${cards}</div>`;
  const clr = content.querySelector('[data-svcclear]');
  if (clr) clr.addEventListener('click', () => resFindingsView(scanId, content, { only: opts.only, emptyMsg: opts.emptyMsg }));
  const apply = resWireSearch(content);
  content.querySelectorAll('.ag-fh').forEach(h => h.addEventListener('click', () => h.parentElement.classList.toggle('open')));
  content.querySelectorAll('.ag-poc-actions .btn[data-copy]').forEach(b => b.addEventListener('click', () => { try { navigator.clipboard.writeText(b.dataset.copy); const o = b.textContent; b.textContent = 'Copied ✓'; setTimeout(() => b.textContent = o, 1200); } catch {} }));
  content.querySelectorAll('[data-fk]').forEach(ch => ch.addEventListener('click', () => {
    content.querySelectorAll('[data-fk]').forEach(x => x.classList.remove('on'));
    ch.classList.add('on');
    const k = ch.dataset.fk;
    content.querySelectorAll('[data-kind]').forEach(card => { card.dataset.filtered = (k === 'all' || card.dataset.kind === k) ? '' : '1'; });
    apply();
  }));
}

// OSINT / intel: services (nmap -sV → CVE leads), whois, DNS, favicon/cert/ASN.
// onJumpToLeads(service) — optional; a "N CVE leads" chip deep-links to the Leads
// tab filtered to that service.
async function resOsintView(scanId, content, onJumpToLeads) {
  const [recsRaw, services, findsForSvc] = await Promise.all([
    resGrab(scanId, 'osint.jsonl'), resGrab(scanId, 'services.jsonl'), resGrab(scanId, 'findings.jsonl'),
  ]);
  const recs = recsRaw || [];
  const svcs = services || [];
  if (!recs.length && !svcs.length) { content.innerHTML = resEmpty('No OSINT or service intel collected — run the DNS OSINT, port scan or Service CVEs modules.'); return; }
  const whois = recs.find(r => r.type === 'whois');
  const dns = recs.filter(r => r.type === 'dns');
  const favicons = recs.filter(r => r.type === 'favicon');
  let html = '<div class="res-osint">';

  // SERVICES panel — service versions + per-service version-based CVE lead counts.
  if (svcs.length) {
    const cveByUrl = {};
    (findsForSvc || []).forEach(f => { if ((f.vuln_class === 'cve' || f.cve) && f.url) (cveByUrl[f.url] = cveByUrl[f.url] || []).push(f); });
    const SHORT = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'info' };
    const rows = svcs.map(s => {
      if (s.kind === 'os') {
        const cpe = (s.cpe && s.cpe[0]) ? `<br><code>${esc(s.cpe[0])}</code>` : '';
        const leads = cveByUrl[s.host] || [];
        const chip = leads.length ? ` · <span class="svc-leads" data-svc-leads="${esc(s.host)}">${leads.length} CVE lead${leads.length > 1 ? 's' : ''}</span>` : '';
        return `<div class="k">OS</div><div class="v"><b>${esc(s.host || '')}</b> · ${esc(s.os || '?')}${s.accuracy ? ` <span class="mut">${esc(String(s.accuracy))}% match</span>` : ''}${chip}${cpe}</div>`;
      }
      const url = `${s.host}:${s.port}`;
      const leads = cveByUrl[url] || [];
      const sev = {}; leads.forEach(l => { const k = (l.severity || 'info').toLowerCase(); sev[k] = (sev[k] || 0) + 1; });
      const sevStr = ['critical', 'high', 'medium', 'low'].filter(k => sev[k]).map(k => `${sev[k]} ${SHORT[k]}`).join(' · ');
      const chip = leads.length
        ? ` · <span class="svc-leads" data-svc-leads="${esc(url)}">${leads.length} CVE lead${leads.length > 1 ? 's' : ''}</span>${sevStr ? ` <span class="mut">CVSS: ${sevStr}</span>` : ''}`
        : ' <span class="mut">· no CVE leads</span>';
      const ver = [s.product, s.version].filter(Boolean).join(' ') || s.service || '?';
      const cpe = (s.cpe && s.cpe.length) ? `<br><code>${esc(s.cpe[0])}</code>` : '';
      return `<div class="k">${esc((s.service || 'svc').toUpperCase()).slice(0, 6)}</div><div class="v"><b>${esc(url)}</b> · ${esc(ver)}${s.extrainfo ? ` <span class="mut">${esc(s.extrainfo)}</span>` : ''}${chip}${cpe}</div>`;
    }).join('');
    html += `<div class="res-panel"><div class="res-panel-h"><span class="rt">SVC</span> Service versions <span class="mut">· nmap -sV · CVE leads are version-based — unverified. See Leads.</span></div><div class="res-dns">${rows}</div></div>`;
  }

  if (dns.length) {
    const rows = dns.map(d => `<div class="k">${esc(d.record_type)}</div><div class="v">${(d.records || []).map(x => esc(typeof x === 'object' ? JSON.stringify(x) : String(x))).join('<br>')}</div>`).join('');
    html += `<div class="res-panel"><div class="res-panel-h"><span class="rt">DNS</span> Records</div><div class="res-dns">${rows}</div></div>`;
  }
  if (favicons.length) {
    const rows = favicons.map(f => `<div class="k">ICON</div><div class="v"><b>${esc(f.host || '')}</b> · hash <b>${esc(String(f.hash))}</b> · ${esc(String(f.bytes))}b<br><code>${esc(f.shodan_query || '')}</code> <span class="mut">· md5 ${esc(String(f.md5 || '').slice(0, 12))}…</span></div>`).join('');
    html += `<div class="res-panel"><div class="res-panel-h"><span class="rt">FAVICON</span> Hash pivots <span class="mut">· paste into Shodan/ZoomEye to find sibling hosts</span></div><div class="res-dns">${rows}</div></div>`;
  }
  const certs = recs.filter(r => r.type === 'cert');
  if (certs.length) {
    const rows = certs.map(c => `<div class="k">CERT</div><div class="v"><b>${esc(c.host || '')}:${esc(String(c.port || ''))}</b> · CN ${esc(c.subject_cn || '?')}${c.self_signed ? ' · <span class="mut">self-signed</span>' : ''} · exp ${esc(c.valid_to || '?')}<br>${(c.sans && c.sans.length) ? ('SANs: ' + c.sans.map(s => `<code>${esc(s)}</code>`).join(' ')) : '<span class="mut">no SAN hostnames</span>'}</div>`).join('');
    html += `<div class="res-panel"><div class="res-panel-h"><span class="rt">CERT</span> TLS cert SANs <span class="mut">· sibling / internal hostnames</span></div><div class="res-dns">${rows}</div></div>`;
  }
  const asns = recs.filter(r => r.type === 'asn');
  const asnRanges = recs.filter(r => r.type === 'asn_ranges');
  if (asns.length || asnRanges.length) {
    const r1 = asns.map(a => `<div class="k">ASN</div><div class="v"><b>${esc(a.ip || '')}</b> → <code>AS${esc(String(a.asn))}</code> · ${esc(a.cidr || '')} · ${esc(a.as_name || '')}${a.cc ? ` <span class="mut">(${esc(a.cc)})</span>` : ''}</div>`).join('');
    const r2 = asnRanges.map(x => `<div class="k">RANGES</div><div class="v">AS${esc(String(x.asn))} announces <b>${esc(String(x.prefix_count))}</b> prefixes${(x.prefixes && x.prefixes.length) ? (': ' + x.prefixes.slice(0, 8).map(p => `<code>${esc(p)}</code>`).join(' ') + (x.prefix_count > 8 ? ' …' : '')) : ''}</div>`).join('');
    html += `<div class="res-panel"><div class="res-panel-h"><span class="rt">ASN</span> IP → ASN → CIDR <span class="mut">· org IP footprint</span></div><div class="res-dns">${r1}${r2}</div></div>`;
  }
  if (whois) {
    const data = typeof whois.data === 'string' ? whois.data : JSON.stringify(whois.data, null, 2);
    html += `<div class="res-panel"><div class="res-panel-h"><span class="rt">WHOIS</span> ${esc(whois.domain || '')}</div><div class="res-whois">${esc(data)}</div></div>`;
  }
  html += '</div>';
  content.innerHTML = html;
  content.querySelectorAll('[data-svc-leads]').forEach(el => el.addEventListener('click', () => { if (onJumpToLeads) onJumpToLeads(el.dataset.svcLeads); }));
}

async function renderResults(scanId) {
  const scan = await api(`/scan/${scanId}`);
  if (!scan || !scan.status) { location.hash = "/"; return; } // a real 404 has no status; an errored scan keeps its status
  // Classic and AI scans write the same workspace files, so both render through the
  // one polished results view (hero + finding cards + recon fold). The pill just
  // says CLASSIC vs AGENTIC. This is how the classic results match the AI quality.
  return renderAgenticResults(scanId, scan);
}

/* ── TOOLS ──────────────────────── */

async function renderTools() {
  await drawTools();
}

async function drawTools() {
  const tools = await api('/tools');

  const installed = tools.filter(t => t.installed).length;
  const total = tools.length;
  // Missing first, so the gaps the user needs to act on are at the top.
  const sorted = [...tools].sort((a, b) => (a.installed === b.installed ? 0 : a.installed ? 1 : -1));

  app.innerHTML = `
    <div class="section-header animate-in">
      <div>
        <h1 class="section-title">Tools Registry</h1>
        <p class="section-sub">${installed}/${total} tools installed${installed < total ? ` · ${total - installed} missing` : ''}</p>
      </div>
      <button class="btn btn-ghost btn-sm" id="toolsRefresh">Refresh</button>
    </div>
    <div class="card animate-in" style="animation-delay:.05s">
      ${sorted.map(t => `
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

  $('#toolsRefresh').addEventListener('click', async () => {
    const btn = $('#toolsRefresh');
    btn.disabled = true; btn.textContent = 'Refreshing…';
    try { await fetch('/api/tools/refresh', { method: 'POST' }); } catch { /* ignore */ }
    drawTools();
  });
}

/* ── AI SETTINGS ──────────────────────── */

const SET_GO_PATH = {
  subfinder: 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
  dnsx: 'github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
  httpx: 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
  naabu: 'github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
  katana: 'github.com/projectdiscovery/katana/cmd/katana@latest',
  nuclei: 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
  gau: 'github.com/lc/gau/v2/cmd/gau@latest',
  ffuf: 'github.com/ffuf/ffuf/v2@latest',
  dalfox: 'github.com/hahwul/dalfox/v2@latest',
  gowitness: 'github.com/sensepost/gowitness@latest',
};
const SET_PIPX = { arjun: true, ghauri: true, wafw00f: true };

function setInstallCmd(tool, mode) {
  if (mode === 'go' && SET_GO_PATH[tool]) return `go install ${SET_GO_PATH[tool]}`;
  if (mode === 'pipx') return `pipx install ${tool}`;
  if (mode === 'pip') return `pip install ${tool}`;
  if (mode === 'apt') return `sudo apt install ${tool}`;
  return `brew install ${tool}`;
}

// Build install options for a tool, ordered by what's actually on THIS machine.
// Go tools prefer `go install`, Python tools prefer pipx; brew/apt fill in.
function setInstallers(tool, platform) {
  const has = (platform && platform.installers) || {};
  const os = (platform && platform.os) || 'darwin';
  // Only list package managers that CAN exist on this OS. apt is Linux-only, so
  // on macOS it is never shown (not even "not detected" — that would be absurd).
  // brew works on macOS + Linux; go/pipx/pip are cross-platform. Among the
  // OS-possible ones, we still mark honestly whether each is installed.
  const osOk = { brew: os === 'darwin' || os === 'linux', apt: os === 'linux', go: true, pipx: true, pip: true };
  const opts = [];
  const push = (mode, label, avail) => { if (osOk[mode]) opts.push({ mode, label, avail: !!avail, cmd: setInstallCmd(tool, mode) }); };
  if (SET_PIPX[tool]) {
    push('pipx', 'pipx', has.pipx); push('pip', 'pip', has.pip); push('brew', 'Homebrew', has.brew);
  } else {
    if (SET_GO_PATH[tool]) push('go', 'Go', has.go);
    push('brew', 'Homebrew', has.brew); push('apt', 'apt', has.apt);
  }
  const avail = opts.filter(o => o.avail), rest = opts.filter(o => !o.avail);
  return { options: [...avail, ...rest], anyAvail: avail.length > 0 };
}

async function renderSettings() {
  const [data, s] = await Promise.all([api('/modules'), api('/ai/settings')]);
  const modules = data.modules || [];
  const glob = data.global || {};
  const uaPresets = data.uaPresets || [];
  const UA_RANDOM = data.uaRandom || '__random__';
  const uaField = (() => {
    const cur = glob.user_agent || '';
    const isRandom = cur === UA_RANDOM;
    const match = uaPresets.find(p => p.value === cur);
    const isCustom = !isRandom && !match && cur !== '';
    const opts = uaPresets.map(p => `<option value="${esc(p.value)}" ${match && match.value === p.value ? 'selected' : ''}>${esc(p.label)}</option>`).join('')
      + `<option value="${esc(UA_RANDOM)}" ${isRandom ? 'selected' : ''}>Random — a different real browser each scan</option>`
      + `<option value="__custom__" ${isCustom ? 'selected' : ''}>Custom…</option>`;
    return `<div class="set-field wide"><label>User-Agent <span class="help">— what the target sees; your scanner stays anonymous</span></label>
        <div class="set-inwrap"><select id="gUAPreset" data-ua>${opts}</select></div>
        <input id="gUA" class="set-ua-custom${isCustom ? '' : ' hidden'}" data-ua placeholder="paste a custom User-Agent" value="${isCustom ? esc(cur) : ''}">
      </div>`;
  })();
  const presets = s.presets || {};
  const suggested = s.suggestedModels || {};
  const presetKeys = Object.keys(presets);

  depsDirty = false; // this fresh render already reflects the current tool state
  const total = modules.length;
  const blocked = modules.filter(m => m.status === 'blocked').length;
  const ready = total - blocked;
  const platform = data.platform || {};

  const GROUPS = ['Discovery', 'Mapping', 'Checks'];

  // ---- per-module param field ----
  function fieldHtml(m, p) {
    const disabled = m.status === 'blocked' ? 'disabled' : '';
    const val = m.values[p.key];
    if (p.type === 'bool') {
      const on = val === true || val === 'true';
      return `<div class="set-field"><label>${esc(p.label)}</label>
        <button class="set-sw" role="switch" aria-checked="${on}" data-mod="${esc(m.key)}" data-param="${esc(p.key)}" data-type="bool" data-def="${p.def === true}" ${disabled} aria-label="${esc(p.label)}"></button></div>`;
    }
    if (p.type === 'secret') {
      const isSet = val && typeof val === 'object' ? !!val.set : !!val;
      const h = p.hint ? `<span class="help">— ${esc(p.hint)}</span>` : '';
      const sel = `${esc(m.key)}:${esc(p.key)}`;
      // "leave blank to keep" lives in the persistent sub-note, not the placeholder
      // (placeholders vanish on focus and aren't screen-reader reliable).
      const note = isSet
        ? `✓ a token is stored — leave blank to keep it · <button type="button" class="set-linkbtn" data-secclear="${sel}">remove</button>`
        : `stored locally (0600), never shown back`;
      return `<div class="set-field wide">
        <label>${esc(p.label)} ${h}</label>
        <div class="set-inwrap">
          <input type="password" autocomplete="off" value="" placeholder="${isSet ? '••••••••' : esc(p.hint || 'paste token')}" data-mod="${esc(m.key)}" data-param="${esc(p.key)}" data-type="secret" ${disabled}>
          ${isSet ? `<button type="button" class="set-mini" data-sectest="${sel}">Test</button>` : ''}
        </div>
        <span class="set-inherit" data-secnote="${sel}">${note}</span>
      </div>`;
    }
    const wideCls = (p.type === 'file' || p.key === 'user_agent' || p.key === 'oob_url') ? ' wide' : '';
    const unit = p.unit ? `<span class="unit">${esc(p.unit)}</span>` : '';
    let ph = '';
    if (p.type === 'file') ph = 'path to a .txt list — blank = built-in';
    else if (p.def != null) ph = `default ${p.def}`;
    else if (p.hint) ph = p.hint;
    const inputType = p.type === 'number' ? 'number' : 'text';
    const hint = p.inheritsGlobal ? '<span class="help">— global default</span>' : (p.hint && p.type !== 'file' ? `<span class="help">— ${esc(p.hint)}</span>` : '');
    const inherit = p.inheritsGlobal ? '<span class="set-inherit">↳ inherits global — leave blank to use it</span>' : '';
    return `<div class="set-field${wideCls}">
      <label>${esc(p.label)} ${hint}</label>
      <div class="set-inwrap"><input type="${inputType}" value="${val != null ? esc(val) : ''}" placeholder="${esc(ph)}" data-mod="${esc(m.key)}" data-param="${esc(p.key)}" data-type="${esc(p.type)}" ${disabled}>${unit}</div>
      ${inherit}
    </div>`;
  }

  function badgeHtml(m) {
    const t = m.tool || (m.altTool ? `${m.tool}` : '');
    if (m.status === 'builtin') return `<span class="set-tbadge builtin">◆ built-in</span>`;
    if (m.status === 'ready') return `<span class="set-tbadge ready">● ${esc(m.tool)}${m.altTool ? '/' + esc(m.altTool) : ''}</span>`;
    if (m.status === 'fallback') return `<span class="set-tbadge fallback">▲ ${esc(m.tool)} missing · built-in</span>`;
    return `<span class="set-tbadge blocked">✕ ${esc(m.tool)} · not installed</span>`;
  }

  function bodyHtml(m) {
    let head = '';
    if (m.status === 'blocked') {
      const inst = setInstallers(m.tool, platform);
      const sel = inst.options.map((o, i) => `<option value="${o.mode}" ${i === 0 ? 'selected' : ''}>${esc(o.label)}${o.avail ? '' : ' — not detected'}</option>`).join('');
      head = `<div class="set-install-card">
        <div class="hd2"><span>✕</span> ${esc(m.tool)} is required and not installed — this module is off until you install it.</div>
        ${inst.anyAvail ? '' : '<div class="set-sub" style="color:var(--accent-amber);margin-bottom:8px">No package manager detected on this machine — install one (e.g. Homebrew or Go) first.</div>'}
        <div class="set-install-row">
          <select data-installsel="${esc(m.key)}">${sel}</select>
          <div class="set-cmd"><span data-cmd="${esc(m.key)}">${esc(inst.options[0].cmd)}</span><button class="copy" data-copy="${esc(m.key)}">Copy</button></div>
        </div>
        <div class="set-install-row"><span class="set-recheck"><button class="set-mini" data-recheck="1">Re-check tools</button> not found on PATH</span></div>
      </div>`;
    } else if (m.status === 'fallback') {
      head = `<div class="set-fallback-note"><span style="color:var(--accent-amber)">▲</span><div><b>Running on the built-in fallback.</b> It works; <code>${esc(m.tool)}</code> is faster and finds more. Your settings below still apply.</div></div>`;
    } else if (m.intrusive) {
      head = `<div class="set-note" style="margin-bottom:var(--space-3);color:var(--text-muted)">Active check — obeys the global rate cap. <b style="color:var(--text-readable)">Run only with authorization.</b></div>`;
    }
    const fields = (m.params || []).map(p => fieldHtml(m, p)).join('');
    const form = fields
      ? `<div class="set-form${m.status === 'blocked' ? ' disabled' : ''}">${fields}</div>`
      : `<div class="set-note" style="color:var(--text-muted)">No parameters — this module runs with sensible defaults.</div>`;
    const foot = m.status === 'blocked' ? '' :
      `<div class="set-mod-foot"><button class="set-btn ghost" data-reset="${esc(m.key)}">Reset to defaults</button><span class="set-mod-foot-hint">changes commit from the bar below</span></div>`;
    return head + form + foot;
  }

  function modHtml(m) {
    const checked = m.enabled && m.status !== 'blocked';
    const disabledSw = m.status === 'blocked' ? 'disabled' : '';
    const tag = (m.intrusive ? '<span class="set-tag intr">intrusive</span>' : '') + (m.agentic ? '<span class="set-tag ag">agentic only</span>' : '');
    const hay = `${m.label} ${m.key} ${m.tool || ''} ${m.desc}`.toLowerCase();
    return `<div class="set-mod" data-mod="${esc(m.key)}" data-group="${esc(m.group)}" data-status="${esc(m.status)}" data-hay="${esc(hay)}">
      <div class="set-mod-h">
        <button class="set-sw" role="switch" aria-checked="${checked}" data-enable="${esc(m.key)}" ${disabledSw} aria-label="Enable ${esc(m.label)}"></button>
        <button class="set-expand"><span><span class="set-name"><span class="set-dirty-dot" aria-hidden="true"></span>${esc(m.label)} ${tag}</span><span class="set-desc">${esc(m.desc)}</span></span></button>
        <div class="set-status">${badgeHtml(m)}</div>
        <span class="set-caret">▸</span>
      </div>
      <div class="set-mod-body">${bodyHtml(m)}</div>
    </div>`;
  }

  function groupHtml(g) {
    const ms = modules.filter(m => m.group === g);
    if (!ms.length) return '';
    const on = ms.filter(m => m.enabled && m.status !== 'blocked').length;
    const extra = g === 'Checks' ? ' · active testing' : '';
    return `<div class="set-group" data-group="${g}">
      <button class="set-group-h"><span class="caret">▾</span><span class="gn">${g}</span><span class="gc">${on} / ${ms.length} enabled${extra}</span><span class="ln"></span></button>
      ${ms.map(modHtml).join('')}
    </div>`;
  }

  app.innerHTML = `
  <div class="set-scope animate-in">
    <div class="section-header">
      <div>
        <h1 class="section-title">Settings</h1>
        <p class="section-sub">Modules, request defaults, and the AI provider</p>
      </div>
    </div>
    <div class="set-summary">
      <span class="set-sm">${total} <b>modules</b></span>
      <span class="set-sm ok">${ready} <b>ready</b></span>
      ${blocked ? `<span class="set-sm warn">${blocked} <b>need a tool</b></span>` : ''}
    </div>
    ${blocked ? `<div class="set-banner"><span class="ic">⚠</span><div class="t"><b>${blocked} helper tool${blocked > 1 ? 's' : ''} missing.</b> Modules without a built-in fallback stay off until installed.</div><button class="set-mini accent" data-gotodeps="1">Install tools</button></div>` : ''}

    <div class="set-tabs" role="tablist">
      <button class="on" data-tab="modules">Modules<span class="set-tab-dot" data-tabdot="modules"></span></button>
      <button data-tab="deps">Dependencies</button>
      <button data-tab="global">Global defaults<span class="set-tab-dot" data-tabdot="global"></span></button>
      <button data-tab="ai">AI provider</button>
    </div>

    <!-- MODULES -->
    <div class="set-pane on" data-pane="modules">
      <div class="set-toolbar">
        <div class="set-search"><span class="ic">⌕</span><input id="setSearch" placeholder="Search modules — name, tool, or what it checks…"></div>
        <button class="set-chip on" data-filter="all">All <span class="n">${total}</span></button>
        <button class="set-chip" data-filter="ready">Ready <span class="n">${ready}</span></button>
        ${blocked ? `<button class="set-chip" data-filter="blocked">Needs a tool <span class="n">${blocked}</span></button>` : ''}
      </div>
      ${GROUPS.map(groupHtml).join('')}
    </div>

    <!-- DEPENDENCIES -->
    <div class="set-pane" data-pane="deps">
      <div id="setDepsBody"><div class="res-empty">Loading…</div></div>
    </div>

    <!-- GLOBAL -->
    <div class="set-pane" data-pane="global">
      <div class="set-panel">
        <h4>Scope <span class="pri">most important</span></h4>
        <div class="set-sub">Hosts the scanner must never touch, even if discovered. One per line · wildcards allowed.</div>
        <textarea class="set-ta" id="gScope" placeholder="*.prod.example.com">${esc(glob.out_of_scope || '')}</textarea>
      </div>
      <div class="set-panel">
        <h4>Request defaults</h4>
        <div class="set-gform">
          ${uaField}
          <div class="set-field"><label>Rate limit</label><div class="set-inwrap"><input id="gRate" type="number" value="${esc(glob.rate_limit)}"><span class="unit">req/s</span></div><span class="set-sub">hard cap for every module</span></div>
          <div class="set-field"><label>Concurrency</label><div class="set-inwrap"><input id="gConc" type="number" value="${esc(glob.concurrency)}"></div></div>
          <div class="set-field"><label>Default timeout</label><div class="set-inwrap"><input id="gTimeout" type="number" value="${esc(glob.timeout)}"><span class="unit">s</span></div></div>
        </div>
      </div>
    </div>

    <!-- AI -->
    <div class="set-pane" data-pane="ai">
      <div class="set-panel">
        <h4>AI provider <span class="set-sub" style="margin:0 0 0 6px">— powers agentic scans, report &amp; triage</span></h4>
        <div class="setting-row" style="margin-bottom:var(--space-3)">
          <div><div class="setting-title">Enable AI features</div><div class="setting-hint">Off keeps classic mode exactly as it is.</div></div>
          <label class="toggle"><input type="checkbox" id="aiEnabled" ${s.enabled ? 'checked' : ''}><span class="toggle-track"></span></label>
        </div>
        <div class="form-group">
          <label class="form-label">Provider</label>
          <select class="form-select" id="aiProvider">
            ${presetKeys.map(k => `<option value="${esc(k)}" ${s.provider === k ? 'selected' : ''}>${esc(presets[k].label)}</option>`).join('')}
          </select>
        </div>
        <div class="form-group"><label class="form-label">API Base URL</label><input class="form-input" id="aiBaseURL" value="${esc(s.baseURL || '')}" placeholder="https://..."></div>
        <div class="form-group"><label class="form-label">API Key</label><input class="form-input" id="aiKey" type="password" placeholder="${s.hasKey ? '•••• ' + esc(s.keyMasked) + ' — leave blank to keep' : 'paste your API key'}">${s.insecureKey ? '<div class="inline-warn">⚠ stored unencrypted — dev run without Electron keychain</div>' : ''}</div>
        <div class="form-group"><label class="form-label">Model <span class="label-hint">— report &amp; triage</span></label><input class="form-input" id="aiModel" list="modelSuggest" value="${esc(s.model || '')}" placeholder="model id"><datalist id="modelSuggest"></datalist></div>
        <div class="form-group"><label class="form-label">Agent model <span class="label-hint">— fast model for the agentic loop</span></label><input class="form-input" id="aiAgentModel" value="${esc(s.agentModel || '')}" placeholder="e.g. google/gemini-3.1-flash-lite"></div>
        <div class="form-group" style="margin-bottom:0"><label class="form-label">Max agent tool-calls <span class="label-hint">— how hard the agent runs; higher = more thorough, more tokens</span></label><input class="form-input" id="aiMaxCalls" type="number" min="1" max="200" value="${esc(String(s.maxToolCalls || 50))}" placeholder="50"></div>
        <div class="ai-note">Recon data is sent to this provider, so it leaves your machine — for sensitive targets run a local model. DeepSeek or Qwen are plenty; Gemini Flash is a step up.</div>
        <div class="settings-actions"><button class="btn btn-primary" id="aiSave">Save</button><button class="btn btn-ghost" id="aiTest">Test connection</button><span id="aiTestStatus" class="test-status"></span></div>
      </div>
    </div>
  </div>
  <div class="set-savebar" id="setSavebar"><div class="inner"><span class="msg"><span class="dot"></span><span id="setDirtyMsg">Unsaved changes</span></span><button class="set-btn ghost" id="setDiscard">Discard</button><button class="set-btn primary" id="setSaveAll">Save changes</button></div></div>
  `;

  // ---- dirty tracking (baseline snapshot + diff; transient view state never counts) ----
  function stable(x) {
    if (Array.isArray(x)) return '[' + x.map(stable).join(',') + ']';
    if (x && typeof x === 'object') return '{' + Object.keys(x).sort().map(k => JSON.stringify(k) + ':' + stable(x[k])).join(',') + '}';
    return JSON.stringify(x);
  }
  function diffKeys(base, cur) {
    const out = new Set();
    const cmp = (prefix, a, b) => { a = a || {}; b = b || {}; new Set([...Object.keys(a), ...Object.keys(b)]).forEach(k => { if (stable(a[k]) !== stable(b[k])) out.add(prefix + k); }); };
    cmp('global.', base.global, cur.global);
    cmp('enabled.', base.enabled, cur.enabled);
    const mb = base.modules || {}, mc = cur.modules || {};
    new Set([...Object.keys(mb), ...Object.keys(mc)]).forEach(mk => {
      const a = mb[mk] || {}, b = mc[mk] || {};
      new Set([...Object.keys(a), ...Object.keys(b)]).forEach(pk => { if (stable(a[pk]) !== stable(b[pk])) out.add('modules.' + mk + '.' + pk); });
    });
    return [...out];
  }
  let baselineObj = collect();
  let dirty = false;
  let curTab = 'modules';
  function updateBar() {
    const changed = diffKeys(baselineObj, collect());
    dirty = changed.length > 0;
    $('#setSavebar').classList.toggle('show', dirty && curTab !== 'ai');
    $('#setDirtyMsg').textContent = changed.length === 1 ? '1 unsaved change' : `${changed.length} unsaved changes`;
    const changedMods = new Set();
    changed.forEach(k => { if (k.startsWith('modules.')) changedMods.add(k.split('.')[1]); else if (k.startsWith('enabled.')) changedMods.add(k.slice('enabled.'.length)); });
    $$('.set-mod[data-mod]').forEach(card => card.classList.toggle('dirty', changedMods.has(card.dataset.mod)));
    const md = $('[data-tabdot="modules"]'); if (md) md.classList.toggle('on', changed.some(k => k.startsWith('modules.') || k.startsWith('enabled.')));
    const gd = $('[data-tabdot="global"]'); if (gd) gd.classList.toggle('on', changed.some(k => k.startsWith('global.')));
  }
  const recompute = updateBar;

  // ---- tabs ----
  let depsLoaded = false;
  $$('.set-tabs button').forEach(b => b.addEventListener('click', () => {
    // A dependency was installed/removed since this render → the module banner/pills
    // are stale; re-render Settings fresh when the user returns to the Modules tab.
    if (b.dataset.tab === 'modules' && depsDirty) { depsDirty = false; renderSettings(); return; }
    $$('.set-tabs button').forEach(x => x.classList.remove('on'));
    b.classList.add('on');
    curTab = b.dataset.tab;
    $$('.set-pane').forEach(p => p.classList.toggle('on', p.dataset.pane === b.dataset.tab));
    // The module banner + pills count MODULES; hide them on the Dependencies tab,
    // which counts TOOLS, so the two "ready" numbers never sit side by side.
    const onDeps = b.dataset.tab === 'deps';
    const bn = $('.set-banner'); if (bn) bn.style.display = onDeps ? 'none' : '';
    const pills = $('.set-summary'); if (pills) pills.style.display = onDeps ? 'none' : '';
    if (b.dataset.tab === 'deps' && !depsLoaded) { depsLoaded = true; renderDepsTab(); }
    updateBar(); // bar hides on the AI tab (own Save) and reflects dirty elsewhere
  }));
  $$('[data-gotodeps]').forEach(b => b.addEventListener('click', () => { const t = $('.set-tabs button[data-tab="deps"]'); if (t) t.click(); }));

  // ---- group collapse ----
  $$('.set-group-h').forEach(h => h.addEventListener('click', () => h.closest('.set-group').classList.toggle('closed')));

  // ---- module expand ----
  $$('.set-expand').forEach(e => e.addEventListener('click', () => e.closest('.set-mod').classList.toggle('open')));
  $$('.set-caret').forEach(c => c.addEventListener('click', () => c.closest('.set-mod').classList.toggle('open')));

  // ---- switches (enable + bool params) ----
  $$('.set-sw').forEach(sw => sw.addEventListener('click', ev => {
    ev.stopPropagation();
    if (sw.disabled) return;
    sw.setAttribute('aria-checked', sw.getAttribute('aria-checked') === 'true' ? 'false' : 'true');
    recompute();
  }));

  // ---- only real config fields mark dirty (search / filter chips / expand never do) ----
  const DIRTY_SEL = '[data-param], [data-ua], #gRate, #gConc, #gTimeout, #gScope';
  app.addEventListener('input', ev => { if (ev.target.matches && ev.target.matches(DIRTY_SEL)) recompute(); });
  app.addEventListener('change', ev => { if (ev.target.matches && ev.target.matches(DIRTY_SEL)) recompute(); });

  // ---- search + filter ----
  let filter = 'all';
  function applyFilter() {
    const q = ($('#setSearch').value || '').trim().toLowerCase();
    $$('.set-mod').forEach(card => {
      const matchQ = !q || card.dataset.hay.includes(q);
      const matchF = filter === 'all' || (filter === 'ready' && card.dataset.status !== 'blocked') || (filter === 'blocked' && card.dataset.status === 'blocked');
      card.style.display = matchQ && matchF ? '' : 'none';
    });
    // hide empty groups
    $$('.set-group').forEach(g => {
      const any = [...g.querySelectorAll('.set-mod')].some(c => c.style.display !== 'none');
      g.style.display = any ? '' : 'none';
    });
  }
  $('#setSearch').addEventListener('input', applyFilter);
  // ---- User-Agent preset <-> custom input ----
  const uaSel = $('#gUAPreset');
  if (uaSel) uaSel.addEventListener('change', () => {
    const inp = $('#gUA');
    const custom = uaSel.value === '__custom__';
    if (inp) { inp.classList.toggle('hidden', !custom); if (custom) inp.focus(); }
  });
  $$('.set-chip').forEach(ch => ch.addEventListener('click', () => {
    $$('.set-chip').forEach(x => x.classList.remove('on'));
    ch.classList.add('on');
    filter = ch.dataset.filter;
    applyFilter();
  }));

  // ---- install helpers ----
  $$('[data-installsel]').forEach(sel => sel.addEventListener('change', () => {
    const key = sel.dataset.installsel;
    const m = modules.find(x => x.key === key);
    const span = app.querySelector(`[data-cmd="${key}"]`);
    if (m && span) span.textContent = setInstallCmd(m.tool, sel.value);
  }));
  $$('[data-copy]').forEach(btn => btn.addEventListener('click', () => {
    const span = app.querySelector(`[data-cmd="${btn.dataset.copy}"]`);
    if (span) { navigator.clipboard?.writeText(span.textContent); btn.textContent = 'Copied'; setTimeout(() => btn.textContent = 'Copy', 1200); }
  }));
  $$('[data-recheck]').forEach(btn => btn.addEventListener('click', async () => {
    btn.textContent = 'Checking…';
    await api('/tools/refresh', { method: 'POST' });
    renderSettings();
  }));

  // ---- reset one module's fields ----
  $$('[data-reset]').forEach(btn => btn.addEventListener('click', () => {
    const card = app.querySelector(`.set-mod[data-mod="${btn.dataset.reset}"]`);
    card.querySelectorAll('input[data-param]').forEach(i => { i.value = ''; if (i.dataset.type === 'secret') { delete i.dataset.clear; i.disabled = false; } });
    card.querySelectorAll('.set-sw[data-param]').forEach(sw => sw.setAttribute('aria-checked', sw.dataset.def === 'true' ? 'true' : 'false'));
    recompute();
  }));

  // ---- collect + save all ----
  function uaValue() {
    const sel = $('#gUAPreset');
    const inp = $('#gUA');
    if (!sel) return inp ? inp.value.trim() : '';
    if (sel.value === '__custom__') return inp ? inp.value.trim() : '';
    return sel.value; // a preset value or the Random sentinel
  }
  function collect() {
    const num = v => { const n = Number(v); return v !== '' && !Number.isNaN(n) ? n : undefined; };
    const global = {
      user_agent: uaValue(),
      rate_limit: num($('#gRate').value),
      concurrency: num($('#gConc').value),
      timeout: num($('#gTimeout').value),
      out_of_scope: $('#gScope').value.trim(),
    };
    Object.keys(global).forEach(k => { if (global[k] === undefined) delete global[k]; });
    const mods = {};
    $$('.set-mod[data-mod]').forEach(card => {
      const key = card.dataset.mod;
      const vals = {};
      card.querySelectorAll('[data-param]').forEach(el => {
        const pk = el.dataset.param, t = el.dataset.type;
        if (el.getAttribute('role') === 'switch') { vals[pk] = el.getAttribute('aria-checked') === 'true'; return; }
        if (t === 'secret') {
          if (el.dataset.clear === '1') { vals[pk] = '__CLEAR__'; return; } // explicit remove
          const sv = el.value.trim();
          if (sv) vals[pk] = sv; // blank = keep the stored token
          return;
        }
        const v = el.value.trim();
        if (v === '') return;
        vals[pk] = t === 'number' ? Number(v) : v;
      });
      if (Object.keys(vals).length) mods[key] = vals;
    });
    const enabled = {};
    $$('.set-sw[data-enable]').forEach(sw => { enabled[sw.dataset.enable] = sw.getAttribute('aria-checked') === 'true'; });
    return { global, modules: mods, enabled };
  }
  async function saveAll() {
    const btn = $('#setSaveAll'), disc = $('#setDiscard'), old = btn.textContent;
    btn.disabled = true; disc.disabled = true; btn.textContent = 'Saving…';
    const res = await api('/settings', { method: 'POST', body: collect() });
    btn.disabled = false; disc.disabled = false; btn.textContent = old;
    if (res.ok) {
      // typed secrets are now stored → clear them so they read as "keep", then re-baseline
      $$('input[data-type="secret"]').forEach(i => { i.value = ''; delete i.dataset.clear; i.disabled = false; });
      baselineObj = collect();
      updateBar();
      toast('Settings saved', 'success');
    } else toast(res.error || 'save failed', 'error');
  }
  $('#setSaveAll').addEventListener('click', saveAll);
  $('#setDiscard').addEventListener('click', () => renderSettings());
  // Cmd/Ctrl+S commits pending changes (never on the AI tab, which has its own Save)
  app.onkeydown = (e) => { if ((e.metaKey || e.ctrlKey) && (e.key === 's' || e.key === 'S') && dirty && curTab !== 'ai') { e.preventDefault(); saveAll(); } };

  // secret field — Test (validate the stored token) + remove (explicit clear on Save)
  $$('[data-sectest]').forEach(b => b.addEventListener('click', async () => {
    const note = document.querySelector(`[data-secnote="${b.dataset.sectest}"]`);
    b.disabled = true; const orig = b.textContent; b.textContent = '…';
    try {
      const res = await api('/github/validate-token', { method: 'POST', body: {} });
      if (res.ok) { b.textContent = '✓ valid'; if (note) note.textContent = `✓ token valid${res.remaining != null ? ` — ${res.remaining} code-search req left` : ''}`; }
      else { b.textContent = orig; b.disabled = false; if (note) note.textContent = `✕ ${res.error || 'invalid'}`; }
    } catch { b.textContent = orig; b.disabled = false; }
  }));
  $$('[data-secclear]').forEach(b => b.addEventListener('click', () => {
    const [mk, pk] = b.dataset.secclear.split(':');
    const inp = document.querySelector(`input[data-mod="${mk}"][data-param="${pk}"][data-type="secret"]`);
    if (inp) { inp.dataset.clear = '1'; inp.value = ''; inp.placeholder = '(will be removed on Save)'; inp.disabled = true; }
    const note = document.querySelector(`[data-secnote="${b.dataset.secclear}"]`);
    if (note) note.textContent = '⚠ token will be removed on Save';
    recompute();
  }));

  // ---- AI pane (provider/model/key) ----
  function fillModels(p) { $('#modelSuggest').innerHTML = (suggested[p] || []).map(m => `<option value="${esc(m)}"></option>`).join(''); }
  fillModels(s.provider);
  $('#aiProvider').addEventListener('change', () => {
    const p = $('#aiProvider').value;
    const preset = presets[p] || {};
    if (p !== 'custom') $('#aiBaseURL').value = preset.baseURL || '';
    fillModels(p);
    const sug = suggested[p] || [];
    if (sug.length) $('#aiModel').value = sug[0];
  });
  function aiBody() {
    const body = { enabled: $('#aiEnabled').checked, provider: $('#aiProvider').value, baseURL: $('#aiBaseURL').value.trim(), model: $('#aiModel').value.trim(), agentModel: $('#aiAgentModel').value.trim(), maxToolCalls: parseInt(($('#aiMaxCalls') || {}).value, 10) || 50 };
    const key = $('#aiKey').value.trim();
    if (key) body.apiKey = key;
    return body;
  }
  $('#aiSave').addEventListener('click', async () => {
    const res = await api('/ai/settings', { method: 'POST', body: aiBody() });
    if (res.error) { toast(res.error, 'error'); return; }
    $('#aiKey').value = '';
    if (res.hasKey) $('#aiKey').placeholder = '•••• ' + res.keyMasked + ' — leave blank to keep';
    toast('AI settings saved', 'success');
  });
  $('#aiTest').addEventListener('click', async () => {
    const status = $('#aiTestStatus');
    const base = $('#aiBaseURL').value.trim(), model = $('#aiModel').value.trim();
    if (!base || !model) { status.textContent = '✗ base URL and model required'; status.className = 'test-status fail'; return; }
    status.textContent = 'Testing…'; status.className = 'test-status testing';
    await api('/ai/settings', { method: 'POST', body: aiBody() });
    $('#aiKey').value = '';
    const res = await api('/ai/test', { method: 'POST' });
    if (res.ok) { status.textContent = `✓ Connected · ${res.model}`; status.className = 'test-status ok'; }
    else { status.textContent = `✗ ${res.error || 'connection failed'}`; status.className = 'test-status fail'; }
  });
}

/* ── DEPENDENCIES TAB (managed tool install) ──────────── */

const DEP_LABEL = { ready: 'ready', untested: 'untested version', incompatible: 'incompatible', broken: 'broken', missing: 'not installed' };
let depPollTimer = null;
let depPopWired = false;  // ⋯-menu outside-click closer is attached once, not per render
let depsDirty = false;    // a tool was installed/removed → the Modules banner/pills are stale

function depSize(b) { if (!b) return ''; const mb = b / 1048576; return mb >= 1 ? mb.toFixed(1) + ' MB' : Math.round(b / 1024) + ' KB'; }
function depRuntimeNote(t) {
  return (t.runtime || []).map(r => r.dep === 'chrome' ? 'needs Chrome installed to run' : r.dep === 'root' ? 'SYN scan needs sudo (else connect-scan)' : r.dep === 'npcap' ? 'needs Npcap on Windows' : r.dep === 'libpcap' ? 'needs libpcap' : 'needs ' + r.dep).join(' · ');
}

function depRow(t) {
  const usable = t.status === 'ready' || t.status === 'untested';
  // in-flight / errored download
  if (t.progress) {
    const p = t.progress;
    if (p.phase === 'error') {
      const mm = p.code === 'HASH_MISMATCH';
      return `<div class="dep-row" data-dep="${esc(t.id)}"><span class="res-dot down"></span>
        <div class="dep-main"><div class="dep-name">${esc(t.displayName)}</div>
          <div class="dep-sub"><span class="dep-err">${mm ? '⚠ checksum mismatch' : 'install failed'}: ${esc(p.error || '')}</span></div></div>
        <div class="dep-act"><button class="set-btn ghost" data-dep-install="${esc(t.id)}">Retry</button></div></div>`;
    }
    const pct = p.phase === 'downloading' ? (p.pct || 0) : 100;
    return `<div class="dep-row" data-dep="${esc(t.id)}"><span class="res-dot warn"></span>
      <div class="dep-main"><div class="dep-name">${esc(t.displayName)}</div>
        <div class="dep-sub">${esc(p.phase)}${p.phase === 'downloading' && p.pct ? ` · ${p.pct}%` : ''}</div>
        <div class="dep-bar"><i style="width:${pct}%"></i></div></div>
      <div class="dep-act"><span class="dep-tag">working…</span></div></div>`;
  }

  const tags = [];
  if (t.unverified && (!usable || t.source === 'managed')) tags.push('<span class="dep-tag warn" title="This release publishes no checksum, so the download can\'t be hash-verified">no checksum</span>');
  if (t.status === 'untested' && (t.reasons || []).includes('VERSION_OUT_OF_RANGE')) tags.push(`<span class="dep-tag" title="Our parsers were tested against a different version">v${esc(t.version || '')} untested</span>`);
  if (t.platformSupport === 'untested' && usable) tags.push('<span class="dep-tag">platform untested</span>');
  const rt = depRuntimeNote(t);

  if (usable) {
    const meta = [t.version ? 'v' + t.version : '', t.source].filter(Boolean).join(' · ');
    const menu = `<div class="dep-menu"><button class="dep-dots" data-dep-menu="${esc(t.id)}" aria-label="More">⋯</button><div class="dep-pop" hidden>
      ${t.installable ? `<button data-dep-install="${esc(t.id)}">Reinstall</button>` : ''}
      ${t.source === 'managed' ? `<button data-dep-uninstall="${esc(t.id)}">Uninstall</button>` : ''}
      ${t.path ? `<button data-dep-copy="${esc(t.path)}">Copy path</button>` : ''}
      ${t.homepage ? `<a href="${esc(t.homepage)}" target="_blank" rel="noopener">Homepage ↗</a>` : ''}
    </div></div>`;
    return `<div class="dep-row avail" data-dep="${esc(t.id)}"><span class="res-dot up"></span>
      <div class="dep-main"><div class="dep-name">${esc(t.displayName)} <span class="dep-meta">${esc(meta)}</span> ${tags.join(' ')}</div>
        <div class="dep-sub">${rt ? `<span class="dep-rt">ⓘ ${esc(rt)}</span> · ` : ''}<span class="mono">${esc(t.path || '')}</span></div></div>
      ${menu}</div>`;
  }

  // needs attention
  const info = [t.lockVersion ? 'v' + t.lockVersion : '', t.host || '', depSize(t.size)].filter(Boolean).join(' · ');
  const need = (t.neededBy || []).length ? `<span class="dep-need">needed by ${esc(t.neededBy.join(', '))}</span>` : '';
  let action;
  if (t.kind === 'manual') action = `<button class="res-mini" data-dep-copy="${esc(t.manualCommand || '')}">Copy command</button>`;
  else if (t.installable) action = `<button class="set-btn primary" data-dep-install="${esc(t.id)}"${t.unverified ? ' data-unverified="1"' : ''}>Install</button>`;
  else action = '<span class="dep-tag">no build for this OS</span>';
  return `<div class="dep-row" data-dep="${esc(t.id)}"><span class="res-dot down"></span>
    <div class="dep-main"><div class="dep-name">${esc(t.displayName)} ${tags.join(' ')}</div>
      <div class="dep-sub">${esc(DEP_LABEL[t.status] || '')}${info ? ' · ' + esc(info) : ''}${rt ? ' · ' + esc(rt) : ''} ${need}</div></div>
    <div class="dep-act">${action}</div></div>`;
}

// lightweight confirm sheet (explicit consent for downloading/running third-party binaries)
function depConfirm(title, bodyHtml, okLabel) {
  return new Promise(resolve => {
    const ov = document.createElement('div');
    ov.className = 'dep-modal';
    ov.innerHTML = `<div class="dep-sheet"><h3>${esc(title)}</h3><div class="dep-sheet-body">${bodyHtml}</div>
      <div class="dep-sheet-act"><button class="set-btn ghost" data-no>Cancel</button><button class="set-btn primary" data-yes>${esc(okLabel || 'Install')}</button></div></div>`;
    document.body.appendChild(ov);
    const close = v => { ov.remove(); resolve(v); };
    ov.querySelector('[data-no]').onclick = () => close(false);
    ov.querySelector('[data-yes]').onclick = () => close(true);
    ov.onclick = e => { if (e.target === ov) close(false); };
  });
}

function depPoll() {
  clearInterval(depPollTimer);
  depPollTimer = setInterval(async () => {
    let prog; try { prog = await api('/deps/progress'); } catch { return; }
    const ids = Object.keys(prog);
    if (!ids.length) { clearInterval(depPollTimer); depsDirty = true; renderDepsTab(); return; }
    ids.forEach(id => {
      const row = document.querySelector(`.dep-row[data-dep="${id}"]`); if (!row) return;
      const p = prog[id];
      const sub = row.querySelector('.dep-sub'); const bar = row.querySelector('.dep-bar i');
      if (p.phase === 'error') { clearInterval(depPollTimer); renderDepsTab(); return; }
      if (sub) sub.textContent = p.phase + (p.phase === 'downloading' && p.pct ? ` · ${p.pct}%` : '');
      if (bar) bar.style.width = (p.phase === 'downloading' ? (p.pct || 0) : 100) + '%';
    });
  }, 700);
}

async function renderDepsTab() {
  const box = $('#setDepsBody'); if (!box) return;
  if (!box.querySelector('.dep-row')) box.innerHTML = '<div class="res-empty">Checking your machine…</div>';
  let data;
  try { data = await api('/deps'); } catch { box.innerHTML = resEmptyMsg('Could not load dependencies.'); return; }
  const attention = data.tools.filter(t => !(t.status === 'ready' || t.status === 'untested'));
  const available = data.tools.filter(t => t.status === 'ready' || t.status === 'untested');
  const c = data.counts;
  const batchable = attention.filter(t => t.installable && t.verified && !t.progress);
  const checked = data.checkedAt ? new Date(data.checkedAt).toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit' }) : '';
  box.innerHTML = `
    <div class="res-bar">
      <span class="res-count"><b>${c.available}</b>/${c.total} tools available${c.attention ? ` · ${c.attention} to set up` : ''}</span>
      <span style="flex:1"></span>
      ${batchable.length >= 2 ? '<button class="set-btn primary" id="depInstallAll">Install all</button>' : ''}
      <button class="res-mini" id="depRecheck">Re-check${checked ? ` · ${checked}` : ''}</button>
    </div>
    <div class="dep-note">Installed into the app's own folder (<span class="mono">~/.webkiller/tools</span>) — no sudo, nothing added to your PATH. Each binary is pinned and checksum-verified against its official release.</div>
    ${!data.platform.tested ? `<div class="dep-note warn">⚠ This platform (<b>${esc(data.platform.key)}</b>) isn't verified yet — tools are marked untested until checked on real hardware.</div>` : ''}
    ${attention.length ? `<div class="res-ghead">Needs attention <b>${attention.length}</b></div><div class="res-list">${attention.map(depRow).join('')}</div>` : ''}
    <div class="res-ghead" style="margin-top:var(--space-3)">Available <b>${available.length}</b></div>
    <div class="res-list">${available.map(depRow).join('')}</div>`;

  const copyBtn = el => el.addEventListener('click', e => { e.stopPropagation(); try { navigator.clipboard.writeText(el.dataset.depCopy); const o = el.textContent; el.textContent = 'Copied ✓'; setTimeout(() => el.textContent = o, 1200); } catch {} });
  box.querySelectorAll('[data-dep-copy]').forEach(copyBtn);

  // ⋯ menus
  box.querySelectorAll('[data-dep-menu]').forEach(b => b.addEventListener('click', e => {
    e.stopPropagation();
    const pop = b.nextElementSibling; const open = !pop.hidden;
    box.querySelectorAll('.dep-pop').forEach(p => p.hidden = true);
    pop.hidden = open;
  }));
  // Close an open ⋯ menu on ANY outside click. Attached once at module scope so it
  // survives re-renders and queries the live DOM — the old per-render {once:true}
  // listener got consumed by an unrelated click before a menu was ever opened, so
  // clicking elsewhere never closed it.
  if (!depPopWired) {
    depPopWired = true;
    document.addEventListener('click', () => $$('#setDepsBody .dep-pop').forEach(p => p.hidden = true));
  }

  async function startInstall(id) { await api('/deps/install', { method: 'POST', body: { id } }); depPoll(); renderDepsTab(); }
  box.querySelectorAll('[data-dep-install]').forEach(b => b.addEventListener('click', async e => {
    e.stopPropagation();
    const id = b.dataset.depInstall;
    const t = data.tools.find(x => x.id === id) || {};
    if (b.dataset.unverified) {
      const ok = await depConfirm('Install without a checksum?',
        `<p><b>${esc(t.displayName)}</b>'s release publishes no checksum, so this download can't be hash-verified.</p>
         <p>Source: <span class="mono">${esc(t.host || '')}</span>${t.size ? ' · ' + depSize(t.size) : ''}</p>
         <p class="dep-sheet-warn">Install only if you trust the source.</p>`, 'Install anyway');
      if (!ok) return;
    }
    startInstall(id);
  }));

  box.querySelectorAll('[data-dep-uninstall]').forEach(b => b.addEventListener('click', async e => {
    e.stopPropagation();
    const id = b.dataset.depUninstall;
    await api('/deps/uninstall', { method: 'POST', body: { id } });
    depsDirty = true; toast(`${id} removed`, 'info'); renderDepsTab();
  }));

  const all = $('#depInstallAll');
  if (all) all.addEventListener('click', async () => {
    const rows = batchable.map(t => `<li><b>${esc(t.displayName)}</b> <span class="mono">${esc(t.lockVersion ? 'v' + t.lockVersion : '')}</span> — ${esc(t.host || '')}${t.size ? ' · ' + depSize(t.size) : ''}</li>`).join('');
    const ok = await depConfirm(`Install ${batchable.length} tools`,
      `<p>Downloads these from their official releases into the app folder (checksum-verified):</p><ul class="dep-sheet-list">${rows}</ul>
       <p class="dep-sheet-warn">Tools without a published checksum aren't included — install those individually.</p>`, `Install ${batchable.length}`);
    if (!ok) return;
    await api('/deps/install-all', { method: 'POST' }); depPoll(); renderDepsTab();
  });

  const rc = $('#depRecheck'); if (rc) rc.addEventListener('click', async () => { rc.textContent = 'Checking…'; await api('/deps/recheck', { method: 'POST' }); renderDepsTab(); });
}
function resEmptyMsg(m) { return `<div class="res-empty">${esc(m)}</div>`; }

/* ── HELPERS ──────────────────────── */

function esc(s) { const d = document.createElement('div'); d.textContent = String(s || ''); return d.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }

function pct(scan) { return scan.modules_total ? Math.round((scan.modules_done / scan.modules_total) * 100) : 0; }

function statusBadge(status) {
  const map = { running: 'badge-medium', completed: 'badge-low', error: 'badge-critical', failed: 'badge-critical', created: 'badge-info', stopped: 'badge-info' };
  const label = status === 'error' ? 'failed' : status;
  return `<span class="badge ${map[status] || 'badge-info'}">${label}</span>`;
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
  const steps = ['Tools', 'Ready'];

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
    await renderToolsStep();
  }

  async function renderToolsStep() {
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
                  : (info.type === 'system' || info.type === 'optional-pip')
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
    $('#doneBtn').addEventListener('click', () => { step = 1; renderStep1(); });

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

  async function renderStep1() {
    step = 1;
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

/* ============================================================
   AGENTIC RUN — progress ("The Hunt Map") + results ("Run Report")
   ============================================================ */
let agProgressState = null;
let agTimer = null;

const AG_PHASE_DEFS = [
  { key: 'recon', name: 'Recon' },
  { key: 'surface', name: 'Surface' },
  { key: 'fingerprint', name: 'Fingerprint' },
  { key: 'confirm', name: 'Confirm' },
  { key: 'report', name: 'Report' },
];
function agPhaseIndex(name) {
  const n = String(name || '').toLowerCase();
  if (/finish/.test(n)) return 4;
  if (/^confirm_|http_request|record_finding|scan_vuln|vuln_/.test(n)) return 3;
  if (/fingerprint/.test(n)) return 2;
  if (/url|param|js_?recon|jsrecon|crawl|content/.test(n)) return 1;
  if (/subdomain|enumerate|probe/.test(n)) return 0;
  return 3;
}
function agSevClass(s) { s = String(s || '').toLowerCase(); return s === 'critical' ? 'crit' : s === 'high' ? 'high' : s === 'medium' ? 'med' : s === 'low' ? 'low' : 'info'; }

// Dedicated failed-scan screen (auth/provider error, etc.) — replaces the live
// map/terminal so a 401 reads as a clear failure, not a red line in a log.
function agErrorCard(scan, scanId) {
  const msg = scan.error || 'The scan ended with an error.';
  const auth = /401|403|unauthor|api[\s_-]?key|expired|invalid.*(key|token)|not configured|no api key/i.test(msg);
  return `
    <div class="ag-head"><div>
      <div class="ag-title">${esc(scan.target || 'Scan')}</div>
      <div class="ag-sub"><span class="ag-pill agent">◇ AGENTIC</span><span class="ag-pill err">✕ failed</span></div>
    </div></div>
    <div class="ag-errscreen">
      <div class="ic">⚠</div>
      <h2>Scan failed</h2>
      <p class="msg">${esc(msg)}</p>
      ${auth ? `<p class="hint">This looks like an API-key problem — your provider key may be missing, invalid, or expired. Open Settings, paste a fresh key, and run <b>Test connection</b> before scanning.</p>` : ''}
      <div class="acts">
        <a href="#/settings" class="btn btn-primary">Open Settings</a>
        <a href="#/scan" class="btn btn-ghost">New scan</a>
      </div>
    </div>`;
}

async function renderAgenticProgress(scanId, scan) {
  currentScanId = scanId;
  if (agTimer) { clearInterval(agTimer); agTimer = null; }
  if (scan.status === 'error') { if (eventSource) { eventSource.close(); eventSource = null; } app.innerHTML = agErrorCard(scan, scanId); return; }
  app.innerHTML = `
    <div class="ag-head">
      <div>
        <div class="ag-title">${esc(scan.target)}</div>
        <div class="ag-sub">
          <span class="ag-pill agent">◇ AGENTIC</span>
          <span class="ag-pill mode">⚔ ${esc(scan.profile || '')}</span>
          <span class="ag-pill live" id="agPhasePill"><span class="dot"></span>starting…</span>
          <button class="btn btn-ghost btn-sm" id="agStop" style="margin-left:8px">■ Stop</button>
        </div>
      </div>
      <div class="ag-meters">
        <div class="ag-meter"><div class="k">Elapsed</div><div class="val" id="agElapsed">00:00</div></div>
        <div class="ag-meter"><div class="k">Tokens</div><div class="val" id="agTokens">—</div></div>
        <div class="ag-meter"><div class="k">Cost</div><div class="val ac" id="agCost">—</div></div>
      </div>
    </div>
    <div class="ag-map"><div class="ag-phases" id="agPhases" style="--done:0">
      ${AG_PHASE_DEFS.map((p, i) => `<div class="ag-phase fog" data-ph="${i}"><div class="ag-node">${i + 1}</div><div class="ag-pname">${p.name}</div><div class="ag-pmeta"></div></div>`).join('')}
    </div></div>
    <div class="ag-now">
      <div class="terminal ag-term">
        <div class="terminal-bar"><div class="terminal-dots"><div class="terminal-dot red"></div><div class="terminal-dot amber"></div><div class="terminal-dot green"></div></div><div class="terminal-title">agent run — live</div><span class="cnt" id="agStepCnt"></span></div>
        <div class="terminal-body ag-stream" id="agStream"><div class="ag-empty" style="padding:var(--space-4)">waiting for the agent…</div></div>
      </div>
    </div>
    <div class="ag-ftick" id="agFtick"></div>
  `;
  agProgressState = {
    reached: 0, steps: 0, stepEls: {}, http: 0, find: 0,
    sev: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, leadHits: {},
    t0: (scan.started_at ? scan.started_at * 1000 : Date.now()), done: false, stopped: false,
    target: scan.target, lastError: null,
  };
  agTimer = setInterval(() => {
    const st = agProgressState; if (!st) return;
    const e = Math.max(0, Math.floor((Date.now() - st.t0) / 1000));
    const el = $('#agElapsed'); if (el) el.textContent = String(Math.floor(e / 60)).padStart(2, '0') + ':' + String(e % 60).padStart(2, '0');
    $$('.ag-step.run .tmr').forEach(t => { const s = +t.dataset.start || Date.now(); t.textContent = ((Date.now() - s) / 1000).toFixed(1) + 's'; });
  }, 200);
  agSetPhase(0);
  startAgenticSSE(scanId, agProgressState);
  const agStopBtn = $('#agStop');
  if (agStopBtn) agStopBtn.addEventListener('click', async () => {
    const ok = await depConfirm('Stop this scan?', '<p style="color:var(--text-secondary);line-height:1.6;margin:0">The agent halts now. Findings confirmed so far are kept; in-flight recon is discarded. You can launch a new scan anytime.</p>', 'Stop scan');
    if (!ok) return;
    agStopBtn.disabled = true; agStopBtn.textContent = 'Stopping…';
    try { await api(`/scan/${scanId}/stop`, { method: 'POST' }); } catch { /* SSE reflects the stop */ }
  });
}

function agSetPhase(i) {
  const st = agProgressState; if (!st) return;
  st.reached = Math.max(st.reached, i);
  const r = st.reached, last = AG_PHASE_DEFS.length - 1;
  $$('#agPhases .ag-phase').forEach((el, idx) => {
    el.classList.remove('done', 'active', 'fog', 'stopped');
    const node = el.querySelector('.ag-node');
    if (idx < r) { el.classList.add('done'); node.textContent = '✓'; }
    else if (idx === r) {
      if (st.stopped) { el.classList.add('stopped'); node.textContent = '■'; }
      else if (st.done) { el.classList.add('done'); node.textContent = '✓'; }
      else { el.classList.add('active'); node.textContent = '⚡'; }
    }
    else { el.classList.add('fog'); node.textContent = idx + 1; }
  });
  const phasesEl = $('#agPhases');
  if (phasesEl) phasesEl.style.setProperty('--done', (st.done && !st.stopped) ? 1 : (r / last));
  const pill = $('#agPhasePill');
  if (pill && !st.done && !st.stopped) pill.innerHTML = `<span class="dot"></span>${AG_PHASE_DEFS[r] ? AG_PHASE_DEFS[r].name : ''}`;
}

function agPretty(s) { try { return decodeURIComponent(String(s)); } catch { return String(s); } }

function agRenderCnt() {
  const st = agProgressState, c = $('#agStepCnt'); if (!st || !c) return;
  c.innerHTML = `${st.steps} steps`
    + (st.http ? `<span class="sep">·</span><b>⇄ ${st.http}</b> req` : '')
    + (st.find ? `<span class="sep">·</span><b>✎ ${st.find}</b> confirmed` : '');
}

function agAddStep(name, t) {
  const st = agProgressState; if (!st) return;
  // Unified timeline: the step row lives inside its own "tool" line in the stream,
  // right under the think that caused it — no separate Activity panel.
  const ln = agStream('tool', name, t); if (!ln) return;
  ln.classList.add('step');
  const start = t ? t * 1000 : Date.now();
  ln.querySelector('.tx').innerHTML = `<div class="ag-step run"><div class="ico"></div><div class="nm"><span class="lbl">${esc(name)}</span></div><div class="tmr" data-start="${start}">0.0s</div></div>`;
  (st.stepEls[name] || (st.stepEls[name] = [])).push(ln.querySelector('.ag-step')); st.steps++;
  agRenderCnt();
}

function agFinishStep(name, meta) {
  const st = agProgressState; if (!st) return;
  const arr = st.stepEls[name]; const row = arr && arr.length ? arr.shift() : null; if (!row) return;
  const box = $('#agStream'); const stick = !!box && (box.scrollHeight - box.scrollTop - box.clientHeight < 48);
  let n = null, sample = [], status = 'success';
  if (meta && typeof meta === 'object') {
    n = (typeof meta.found === 'number') ? meta.found : null;
    sample = Array.isArray(meta.sample) ? meta.sample : [];
    status = meta.status || 'success';
  } else {
    const m = String(meta || '').match(/^(\d+) found(?: \((.*)\))? \((\w+)\)$/s);
    if (m) { n = +m[1]; sample = m[2] ? m[2].split(', ') : []; status = m[3]; }
  }
  const bad = status && status !== 'success';
  row.classList.remove('run'); row.classList.add(bad ? 'err' : 'done');
  row.querySelector('.ico').textContent = bad ? '✕' : '✓';
  const tmr = row.querySelector('.tmr'), s = +tmr.dataset.start || Date.now();
  tmr.textContent = ((Date.now() - s) / 1000).toFixed(1) + 's';
  const isConfirm = /^confirm_|_confirm$|^vuln_/.test(name); // agentic friendly name OR classic module name
  const sm = document.createElement('small');
  sm.textContent = (n == null) ? (typeof meta === 'string' ? meta : '')
    : (bad ? status : (isConfirm ? `${n} ${n === 1 ? 'hit' : 'hits'}` : `${n} found`));
  if (n > 0 && !bad) sm.className = isConfirm ? 'lead' : 'has';
  row.querySelector('.nm').appendChild(sm);
  if (sample && sample.length) {
    const origin = (() => { try { return new URL(st.target && st.target.includes('://') ? st.target : 'http://' + st.target).origin; } catch { return ''; } })();
    const clean = sample.map(u => agPretty(origin && String(u).startsWith(origin) ? (String(u).slice(origin.length) || '/') : u));
    const smp = document.createElement('div'); smp.className = 'smp';
    smp.textContent = clean.map(u => u.length > 120 ? u.slice(0, 96) + '…' + u.slice(-20) : u).join('  ·  ');
    smp.title = clean.join('\n');
    row.appendChild(smp);
  }
  if (isConfirm && n > 0 && !bad) { st.leadHits[name.replace(/^confirm_/, '')] = n; agRenderTick(); }
  if (stick && box) box.scrollTop = box.scrollHeight;
}

function agBump(kind) {
  const st = agProgressState; if (!st) return;
  st[kind === 'http' ? 'http' : 'find']++;
  agRenderCnt();
}

function agStream(type, text, t) {
  const box = $('#agStream'), st = agProgressState; if (!box) return null;
  const empty = box.querySelector('.ag-empty'); if (empty) empty.remove();
  const base = String(type).split(' ')[0];
  const TAG = { think: '◇ think', tool: '▸ tool', req: '→ req', hit: '● FOUND', sum: '✓ done', end: '■', sys: '·' };
  const ms = t ? t * 1000 : Date.now();
  const e = Math.max(0, Math.floor((ms - (st ? st.t0 : ms)) / 1000));
  const stamp = String(Math.floor(e / 60)).padStart(2, '0') + ':' + String(e % 60).padStart(2, '0');
  const same = box.dataset.last === stamp; box.dataset.last = stamp;
  if (base === 'think') box.dataset.turn = '1';
  else if (base === 'sum' || base === 'end' || base === 'sys') box.dataset.turn = '';
  const sub = box.dataset.turn === '1' && (base === 'tool' || base === 'req' || base === 'hit');
  const ln = document.createElement('div'); ln.className = 'ag-ln ' + type + (sub ? ' sub' : '');
  let body = esc(text);
  if (base === 'req') { const m = String(text).match(/^(\S+)\s+(.*)$/); if (m) { ln.title = text; body = `<b class="m">${esc(m[1])}</b> ${esc(agPretty(m[2]))}`; } }
  const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 48;
  ln.innerHTML = `<span class="ag-t">${same ? '' : stamp}</span><span class="tg">${TAG[base] || esc(type)}</span><span class="tx">${body}</span>`;
  box.appendChild(ln); if (stick) box.scrollTop = box.scrollHeight;
  return ln;
}

function agRenderTick() {
  const st = agProgressState, tick = $('#agFtick'); if (!st || !tick) return;
  const confirmed = [['critical', 'crit'], ['high', 'high'], ['medium', 'med'], ['low', 'low']]
    .filter(([k]) => st.sev[k] > 0)
    .map(([k, c]) => `<span class="ag-sev ${c}"><span class="n">${st.sev[k]}</span> ${k}</span>`).join('');
  const leads = Object.entries(st.leadHits || {}).filter(([, n]) => n > 0)
    .map(([k, n]) => `<span class="ag-sev med lead"><span class="n">${n}</span> ${esc(k)} hits</span>`).join('');
  tick.innerHTML = confirmed + leads;
}

function agFinding(sev, name) {
  const st = agProgressState; if (!st) return;
  const s = String(sev || 'info').toLowerCase();
  if (st.sev[s] !== undefined) st.sev[s]++;
  agRenderTick();
}

function startAgenticSSE(scanId, st) {
  if (eventSource) eventSource.close();
  eventSource = new EventSource(`/api/scan/${scanId}/events`);
  eventSource.onmessage = (e) => {
    let ev; try { ev = JSON.parse(e.data); } catch { return; }
    const d = ev.data || '';
    switch (ev.type) {
      case 'agent_start': agStream('sys', d, ev.time); break;
      case 'tool_call': agSetPhase(agPhaseIndex(d)); agAddStep(d, ev.time); break;
      case 'tool_result': { try { const r = JSON.parse(d); agFinishStep(r.tool, r); } catch { const m = String(d).match(/^(\S+):\s*(.+)$/); agFinishStep(m ? m[1] : d, m ? m[2] : ''); } break; }
      case 'agent_request': agSetPhase(3); agBump('http'); agStream('req', d, ev.time); break;
      case 'agent_finding': { const m = String(d).match(/^(\w+)\s*[—–-]\s*(.+)$/); const sev = m ? m[1] : 'info', nm = m ? m[2] : d; agSetPhase(3); agFinding(sev, nm); agBump('find'); agStream('hit', d, ev.time); break; }
      case 'agent_thought': agStream('think', d, ev.time); break;
      case 'agent_read': agStream('sys', 'read ' + d, ev.time); break;
      case 'agent_usage': { const tk = +d || 0; const te = $('#agTokens'); if (te) te.textContent = (tk / 1000).toFixed(1) + 'k'; const ce = $('#agCost'); if (ce) ce.textContent = '$' + (tk / 1e6 * 0.4).toFixed(3); break; }
      case 'agent_summary': { const tm = String(d).match(/([\d,]+)\s*tokens/); if (tm) { const tk = +tm[1].replace(/,/g, ''); const te = $('#agTokens'); if (te) te.textContent = (tk / 1000).toFixed(1) + 'k'; const ce = $('#agCost'); if (ce) ce.textContent = '$' + (tk / 1e6 * 0.4).toFixed(3); } break; }
      case 'agent_done': agStream('sum', d, ev.time); break;
      case 'agent_stop': agStream('sys', d, ev.time); break;
      case 'agent_error': case 'error': st.lastError = d; agStream('hit', 'error: ' + d, ev.time); break;
      case 'scan_done': agStream(d === 'completed' ? 'end' : 'end bad', 'scan ' + d, ev.time); break;
      case 'end': {
        if (agTimer) { clearInterval(agTimer); agTimer = null; }
        setStatus(ev.status === 'stopped' ? 'Stopped' : 'Ready', '');
        if (eventSource) { eventSource.close(); eventSource = null; }
        const sb = $('#agStop'); if (sb) sb.remove();
        // A failed run gets the dedicated error screen, not the "complete" map.
        if (ev.status === 'error') {
          app.innerHTML = agErrorCard({ target: st.target, error: st.lastError || 'The scan ended with an error.' }, scanId);
          break;
        }
        if (ev.status === 'stopped') { st.stopped = true; agSetPhase(st.reached); } // halt at the reached phase — don't fill the whole map
        else { st.done = true; agSetPhase(4); }
        const pill = $('#agPhasePill'); if (pill) { pill.classList.remove('live'); pill.innerHTML = ev.status === 'stopped' ? '■ stopped' : '✓ complete'; }
        const sub = $('.ag-sub');
        if (sub && !$('#agViewReport')) {
          const b = document.createElement('a'); b.id = 'agViewReport'; b.href = `#/results/${scanId}`;
          b.className = 'btn btn-primary btn-sm'; b.style.marginLeft = '8px'; b.textContent = 'View Report →';
          sub.appendChild(b);
        }
        break;
      }
    }
  };
}

/* ── AGENTIC RESULTS ── */
async function renderAgenticResults(scanId, scan) {
  if (agTimer) { clearInterval(agTimer); agTimer = null; }
  if (eventSource) { eventSource.close(); eventSource = null; } // don't leak the progress stream into the report
  if (scan.status === 'error') { app.innerHTML = agErrorCard(scan, scanId); return; }
  const grab = async (f, jsonl) => {
    try {
      const r = await fetch(`/api/scan/${scanId}/results/${f}`);
      if (!r.ok) return jsonl ? [] : '';
      if (!jsonl) return await r.text();
      const txt = await r.text();
      try { const j = JSON.parse(txt); return Array.isArray(j) ? j : (j ? [j] : []); }
      catch { return txt.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean); }
    } catch { return jsonl ? [] : ''; }
  };
  const [confirmed, findings, subs, live, urls, params, jsend] = await Promise.all([
    grab('confirmed.jsonl', true), grab('findings.jsonl', true),
    grab('subdomains.txt'), grab('live.txt'), grab('urls.txt'), grab('params.txt'), grab('js_endpoints.txt'),
  ]);
  const nlines = s => String(s || '').split('\n').filter(Boolean).length;
  const conf = Array.isArray(confirmed) ? confirmed.slice() : [];
  const ord = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  conf.sort((a, b) => (ord[(a.severity || 'info').toLowerCase()] ?? 9) - (ord[(b.severity || 'info').toLowerCase()] ?? 9));
  const sevCount = {}; conf.forEach(f => { const s = (f.severity || 'info').toLowerCase(); sevCount[s] = (sevCount[s] || 0) + 1; });
  // Leads = unconfirmed findings, counted via the same merge the Leads tab renders.
  const leadList = resMergeFindings(findings, confirmed).filter(f => f._kind === 'potential');
  const leads = leadList.length;
  const leadSev = {}; leadList.forEach(f => { const s = (f.severity || 'info').toLowerCase(); leadSev[s] = (leadSev[s] || 0) + 1; });
  const leadPills = ['critical', 'high', 'medium', 'low', 'info'].filter(s => leadSev[s]).map(s => `<span class="ag-sev ${agSevClass(s)} lead" data-goleads><span class="n">${leadSev[s]}</span> ${s}</span>`).join('');
  const classes = [...new Set(conf.map(f => f.vuln_class || f.name).filter(Boolean))].slice(0, 8);
  const sevPills = ['critical', 'high', 'medium', 'low'].filter(s => sevCount[s]).map(s => `<span class="ag-sev ${agSevClass(s)}"><span class="n">${sevCount[s]}</span> ${s}</span>`).join('');

  app.innerHTML = `
    <div class="ag-head">
      <div>
        <div class="ag-title">${esc(scan.target)}</div>
        <div class="ag-sub">
          <span class="ag-pill ${scan.mode === 'ai' ? 'agent' : ''}">${scan.mode === 'ai' ? '◇ AGENTIC' : '▤ CLASSIC'}</span>
          <span class="ag-pill mode">⚔ ${esc(scan.profile || '')}</span>
          <span class="ag-pill ${scan.status === 'completed' ? 'done' : scan.status === 'error' ? 'err' : 'live'}">${scan.status === 'completed' ? '✓' : scan.status === 'error' ? '✕' : '◴'} ${esc(scan.status)}</span>
        </div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn btn-ghost btn-sm" id="agAiBtn">AI report ✦</button>
        <button class="btn btn-ghost btn-sm" onclick="exportResults('${scanId}','json')">Export JSON</button>
        <button class="btn btn-ghost btn-sm" onclick="exportResults('${scanId}','html')">Export HTML</button>
      </div>
    </div>
    <div class="ag-hero">
      <div class="ag-verdict ${conf.length ? '' : leads ? 'leads' : 'clean'}">
        <div class="bigrow">
          <div class="big ${conf.length ? '' : 'clean'}">${conf.length} confirmed</div>
          ${leads ? `<div class="big lead">+ ${leads} unconfirmed</div>` : ''}
        </div>
        <div class="cap">${conf.length ? 'proven with evidence' : leads ? 'nothing proven yet — the hits below were detected but not reproduced' : 'no vulnerabilities confirmed in this run'}</div>
        ${sevPills ? `<div class="sevlbl">Confirmed</div><div class="sevrow">${sevPills}</div>` : ''}
        ${leadPills ? `<div class="sevlbl">Leads to verify</div><div class="sevrow">${leadPills}</div>` : ''}
        ${!sevPills && !leadPills ? '<div class="sevrow"><span class="ag-sev info"><span class="n">0</span> findings</span></div>' : ''}
      </div>
      <div class="ag-statgrid">
        <div class="ag-stat"><div class="k">Surface</div><div class="v ac">${nlines(urls)}<small> urls</small></div></div>
        <div class="ag-stat"><div class="k">Params</div><div class="v">${nlines(params)}</div></div>
        <div class="ag-stat"><div class="k">Subdomains</div><div class="v">${nlines(subs)}</div></div>
        <div class="ag-stat ${leads ? 'lead' : ''}"${leads ? ' data-goleads' : ''}><div class="k">Leads</div><div class="v">${leads}${leads ? '<small> to verify</small>' : ''}</div></div>
      </div>
    </div>
    <div id="agAiOut"></div>
    ${classes.length ? `<div class="ag-replay"><h3>${scan.mode === 'ai' ? 'WHAT THE AGENT DID' : 'WHAT RAN'}</h3><div class="ag-chain">
      <span class="c">recon</span><span class="arw">→</span>
      <span class="c">${nlines(urls)} urls / ${nlines(params)} params</span><span class="arw">→</span>
      ${nlines(jsend) ? `<span class="c">${nlines(jsend)} js endpoints</span><span class="arw">→</span>` : ''}
      ${classes.map(c => `<span class="c k">confirm ${esc(c)}</span>`).join('<span class="arw">→</span>')}
      <span class="arw">→</span><span class="c">report</span>
    </div></div>` : ''}
    <div class="ag-sec">Confirmed vulnerabilities <span class="ct">· ${conf.length} · sorted by severity</span></div>
    <div id="agCards"></div>
    <details class="ag-fold"${conf.length && !leads ? '' : ' open'}>
      <summary><span>Recon data &amp; leads</span><span class="mono" style="color:var(--text-muted)">▾</span></summary>
      <div class="res-subtabs" id="agReconTabs">
        <button data-rv="hosts" class="on">Hosts <b>${nlines(subs)}</b></button>
        <button data-rv="endpoints">Endpoints <b>${nlines(urls)}</b></button>
        <button data-rv="osint">OSINT</button>
        ${leads ? `<button data-rv="leads">Leads <b>${leads}</b></button>` : ''}
      </div>
      <div id="agReconView" style="padding:0 var(--space-4) var(--space-4)"></div>
    </details>
  `;

  const cardsEl = $('#agCards');
  cardsEl.innerHTML = conf.length
    ? conf.map(agFindingCard).join('')
    : `<div class="ag-empty">The agent completed recon and testing but confirmed no vulnerabilities. Any heuristic leads are under “Recon data &amp; leads”.</div>`;
  $$('.ag-fh').forEach(h => h.addEventListener('click', () => h.parentElement.classList.toggle('open')));
  $$('.ag-code [data-copy]').forEach(() => {});
  $$('.ag-poc-actions .btn[data-copy]').forEach(b => b.addEventListener('click', () => { try { navigator.clipboard.writeText(b.dataset.copy); const o = b.textContent; b.textContent = 'Copied ✓'; setTimeout(() => b.textContent = o, 1200); } catch {} }));
  // Recon fold reuses the shared rich views (same as the classic Results tabs).
  const reconView = $('#agReconView');
  const loadRecon = (k, opts) => {
    $$('#agReconTabs button').forEach(b => b.classList.toggle('on', b.dataset.rv === k));
    if (k === 'hosts') resHostsView(scanId, reconView);
    else if (k === 'endpoints') resEndpointsView(scanId, reconView);
    else if (k === 'osint') resOsintView(scanId, reconView, (svc) => loadRecon('leads', { service: svc }));
    else if (k === 'leads') resFindingsView(scanId, reconView, { only: 'potential', emptyMsg: 'No unconfirmed leads.', service: opts && opts.service });
  };
  $$('#agReconTabs button').forEach(b => b.addEventListener('click', () => loadRecon(b.dataset.rv)));
  loadRecon(leads && !conf.length ? 'leads' : 'hosts');
  $$('[data-goleads]').forEach(el => el.addEventListener('click', () => { const d = $('.ag-fold'); if (d) { d.open = true; loadRecon('leads'); d.scrollIntoView({ behavior: 'smooth' }); } }));
  const aiBtn = $('#agAiBtn'); if (aiBtn) aiBtn.addEventListener('click', () => agAiReport(scanId, aiBtn));
}

// Version-based CVE leads render distinctly from reproduced findings: a dashed
// (non-filled) severity chip, a dashed amber card frame, a "version-based ·
// unverified" badge, a "lead, not proof" note, and NO proof-of-concept block.
// This is the trust boundary — a version match is a lead, never confirmation.
function agCveCard(f) {
  const sev = (f.severity || 'info').toLowerCase(), cls = agSevClass(sev);
  const ev = f.evidence || {};
  const svc = esc(f.url || ''), cpe = esc(f.cpe || '');
  const cvss = (f.cvss !== undefined && f.cvss !== null && f.cvss !== '') ? esc(String(f.cvss)) : '';
  const cveId = f.cve || '';
  const nvd = cveId ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}` : '';
  const summary = esc((ev.detail || '').replace(/^nmap -sV banner → \S+\.\s*/, ''));
  // Three verification tiers (from cve_verify): verified (promoted/confirmed),
  // unverifiable (logged reason — never actively tested), or version-based lead.
  const v = f.verification || null;
  const status = v && v.status;
  let frameCls, chipLead, badge, note;
  if (status === 'verified') {
    const method = esc(String(v.method || '').toUpperCase());
    const e = (v.evidence) || {};
    const tell = e.check ? `${esc(e.check)}${e.tell ? ` → “${esc(e.tell)}”` : ''}` : (e.matcher ? `nuclei: ${esc(e.matcher)}${e.matched_at ? ` @ ${esc(e.matched_at)}` : ''}` : '');
    frameCls = cls; chipLead = '';
    badge = `<span class="ag-vbadge ok">✓ verified${method ? ' · ' + method : ''}</span>`;
    note = `<div class="ag-lead-note ok">✓ Confirmed${method ? ' by ' + method : ''}${tell ? ' — ' + tell : ''}. Actively reproduced, not just a version match.</div>`;
  } else if (status === 'unverifiable') {
    frameCls = 'lead'; chipLead = ' lead';
    const why = /unclear/i.test(v.reason || '') ? 'its class could not be determined' : 'proving it would need a destructive exploit';
    badge = `<span class="ag-vbadge warn">⚠ not safely verifiable</span>`;
    note = `<div class="ag-lead-note">⚠ Not safely verifiable remotely — <b>${esc(v.reason || 'manual review')}</b>. Version match only; ${why}, so verify manually.</div>`;
  } else {
    frameCls = 'lead'; chipLead = ' lead';
    badge = `<span class="ag-vbadge">version-based · unverified</span>`;
    note = `<div class="ag-lead-note">⚠ Lead, not proof. Matched on the version banner only${(v && v.reason) ? ` (${esc(v.reason)})` : ''} — it may be patched/back-ported or spoofed. Verify before reporting.</div>`;
  }
  return `<div class="ag-fcard ${frameCls}">
    <div class="ag-fh">
      <span class="ag-sev ${cls}${chipLead}"><span class="n">${cvss || sev.slice(0, 4).toUpperCase()}</span>${cvss ? ' ' + esc(sev) : ''}</span>
      <span class="title">${esc(f.name || cveId || 'CVE')}</span>
      ${badge}
      <span class="chev">▸</span>
    </div>
    <div class="ag-fb">
      ${note}
      ${svc ? `<div class="ag-kv"><span class="k">Service</span><span class="v">${svc}</span></div>` : ''}
      ${cpe ? `<div class="ag-kv"><span class="k">CPE</span><span class="v">${cpe}</span></div>` : ''}
      ${cvss ? `<div class="ag-kv"><span class="k">CVSS</span><span class="v">${cvss} · ${esc(sev)}</span></div>` : ''}
      ${cveId ? `<div class="ag-kv"><span class="k">CVE</span><span class="v"><a href="${nvd}" target="_blank" rel="noopener">${esc(cveId)} ↗</a></span></div>` : ''}
      ${summary ? `<div class="ag-kv"><span class="k">Summary</span><span class="v" style="white-space:normal;word-break:normal">${summary}</span></div>` : ''}
    </div>
  </div>`;
}

function agFindingCard(f) {
  if (f.vuln_class === 'cve' || f.cve) return agCveCard(f);
  const sev = (f.severity || 'info').toLowerCase(), cls = agSevClass(sev);
  const ev = f.evidence || {};
  const url = esc(f.url || ''), param = ev.param ? esc(ev.param) : '';
  const impact = esc(ev.note || ev.detail || '');
  let poc = '';
  if (ev.payload) poc += `${(ev.method || 'GET')} ${f.url || ''}` + (ev.param ? `   (param: ${ev.param})` : '') + `\npayload: ${ev.payload}\n`;
  if (ev.matched) poc += `matched: ${ev.matched}\n`;
  if (ev.canary) poc += `canary: ${ev.canary}\n`;
  if (ev.probe) poc += `probe: ${ev.probe}\n`;
  if (ev.reflected_origin) poc += `Access-Control-Allow-Origin: ${ev.reflected_origin}\nAllow-Credentials: ${ev.allow_credentials}\n`;
  if (ev.location) poc += `Location: ${ev.location}\n`;
  if (ev.marker) poc += `marker reflected: ${ev.marker}\n`;
  if (ev.base_time !== undefined) poc += `baseline ${ev.base_time}s → payload ${ev.delay_time}s` + (ev.reconfirmed ? ' (reconfirmed)' : '') + `\n`;
  if (ev.detail && !ev.payload) poc += ev.detail + '\n';
  if (!poc.trim()) poc = JSON.stringify(ev, null, 2);
  const open = (sev === 'critical' || sev === 'high') ? ' open' : '';
  return `<div class="ag-fcard ${cls}${open}">
    <div class="ag-fh"><span class="ag-sev ${cls}"><span class="n">${sev.slice(0, 4).toUpperCase()}</span></span><span class="title">${esc(f.name || f.vuln_class || 'Finding')}</span><span class="cls">${esc(f.vuln_class || '')}</span><span class="chev">▸</span></div>
    <div class="ag-fb">
      ${url ? `<div class="ag-kv"><span class="k">Endpoint</span><span class="v">${url}</span></div>` : ''}
      ${param ? `<div class="ag-kv"><span class="k">Parameter</span><span class="v">${param}</span></div>` : ''}
      ${impact ? `<div class="ag-kv"><span class="k">Impact</span><span class="v">${impact}</span></div>` : ''}
      <div class="ag-poc"><div class="lbl">Proof of concept</div><div class="ag-code">${esc(poc.trim())}</div>
        <div class="ag-poc-actions"><button class="btn btn-sm" data-copy="${esc(f.url || '')}">Copy URL</button></div>
      </div>
    </div>
  </div>`;
}

async function agLoadRaw(scanId, file) {
  const out = $('#agRawOut'); if (!out) return;
  out.innerHTML = `<div class="ag-empty" style="padding:var(--space-3)">loading ${esc(file)}…</div>`;
  try {
    const jsonl = file.endsWith('.jsonl');
    const r = await fetch(`/api/scan/${scanId}/results/${file}`);
    const data = r.ok ? (jsonl ? await r.json() : await r.text()) : null;
    const items = jsonl ? (data || []).map(x => x.name ? `${(x.severity || '').toUpperCase()} ${x.name} ${x.url || ''}` : JSON.stringify(x)) : String(data || '').split('\n').filter(Boolean);
    out.innerHTML = `<div style="margin:8px 0;color:var(--text-secondary);font-size:var(--text-sm)">${items.length} · ${esc(file)}</div>
      <div class="terminal" style="max-height:340px"><div class="terminal-body">${items.slice(0, 300).map(l => `<div class="terminal-line">${esc(l)}</div>`).join('') || '<div class="terminal-line">(empty)</div>'}</div></div>`;
  } catch { out.innerHTML = `<div class="ag-empty" style="padding:var(--space-3)">could not load ${esc(file)}</div>`; }
}

async function agAiReport(scanId, btn) {
  const out = $('#agAiOut'); if (!out) return;
  // No provider key → guide to Settings instead of firing a request that only fails.
  let cfg; try { cfg = await api('/ai/settings'); } catch { cfg = null; }
  if (!cfg || !cfg.enabled || !cfg.hasKey) {
    out.innerHTML = `<div class="ag-empty" style="padding:var(--space-4)">AI is ${cfg && cfg.enabled ? 'missing an API key' : 'turned off'} — <a href="#/settings" style="color:var(--accent-primary)">open AI Settings</a> to generate the report.</div>`;
    return;
  }
  btn.disabled = true; const label = btn.textContent; btn.textContent = 'Asking the model…';
  out.innerHTML = `<div class="ag-empty" style="padding:var(--space-4)">generating AI report…</div>`;
  let res; try { res = await api(`/scan/${scanId}/ai/report`, { method: 'POST' }); } catch { res = { ok: false, error: 'request failed' }; }
  btn.disabled = false; btn.textContent = label;
  if (!res || !res.ok) { out.innerHTML = `<div class="ag-empty" style="padding:var(--space-4)">AI report failed: ${esc((res && res.error) || 'unknown')}. Check AI settings.</div>`; return; }
  const tok = res.usage && res.usage.total_tokens ? ` · ${res.usage.total_tokens} tokens` : '';
  out.innerHTML = `<div class="ag-replay"><h3>AI REPORT${esc(tok)}</h3><div class="md-body">${agMd(res.markdown)}</div></div>`;
}
function agMd(md) {
  const inl = t => esc(t).replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/`([^`]+)`/g, '<code>$1</code>');
  let out = '', inList = false;
  for (const line of String(md || '').split('\n')) {
    if (/^\s*[-*]\s+/.test(line)) { if (!inList) { out += '<ul>'; inList = true; } out += '<li>' + inl(line.replace(/^\s*[-*]\s+/, '')) + '</li>'; continue; }
    if (inList) { out += '</ul>'; inList = false; }
    const h = line.match(/^(#{1,4})\s+(.*)/);
    if (h) { const lv = Math.min(h[1].length + 1, 6); out += `<h${lv} class="md-h">${inl(h[2])}</h${lv}>`; continue; }
    if (line.trim()) out += `<p>${inl(line)}</p>`;
  }
  if (inList) out += '</ul>';
  return out;
}
