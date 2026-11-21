const { loadProfile, getConfig } = require('./config');
const { Scope } = require('./scope');
const { Workspace } = require('./workspace');
const { AssetStore } = require('./store');
const { isValidTarget, splitTarget } = require('./validate');
const moduleSettings = require('./module_settings');

const MODULE_MAP = {};

function _loadModules() {
  const modules = {
    subdomains_passive: './modules/subdomains_passive',
    subdomains_active:  './modules/subdomains_active',
    subdomains_permute: './modules/subdomains_permute',
    probe:              './modules/probe',
    favicon_hash:       './modules/favicon_hash',
    cert_intel:         './modules/cert_intel',
    asn_cidr:           './modules/asn_cidr',
    cloud_buckets:      './modules/cloud_buckets',
    urls:               './modules/urls',
    portscan:           './modules/portscan',
    fingerprint:        './modules/fingerprint',
    content:            './modules/content',
    api_routes:         './modules/api_routes',
    jsrecon:            './modules/jsrecon',
    params:             './modules/params',
    archive_recon:      './modules/archive_recon',
    lead_triage:        './modules/lead_triage',
    screenshots:        './modules/screenshots',
    vuln_signal:        './modules/vuln_signal',
    vuln_confirm:       './modules/vuln_confirm',
    xss_confirm:        './modules/xss_confirm',
    sqli_confirm:       './modules/sqli_confirm',
    ssti_confirm:       './modules/ssti_confirm',
    lfi_confirm:        './modules/lfi_confirm',
    ssrf_confirm:       './modules/ssrf_confirm',
    xxe_confirm:        './modules/xxe_confirm',
    deser_confirm:      './modules/deser_confirm',
    jwt_confirm:        './modules/jwt_confirm',
    massassign_confirm: './modules/massassign_confirm',
    nosqli_confirm:     './modules/nosqli_confirm',
    cors_confirm:       './modules/cors_confirm',
    openredirect_confirm: './modules/openredirect_confirm',
    protopollution_confirm: './modules/protopollution_confirm',
    graphql_confirm:    './modules/graphql_confirm',
    authz_probe:        './modules/authz_probe',
    bypass_403:         './modules/bypass_403',
    secret_verify:      './modules/secret_verify',
    osint_dns:          './modules/osint_dns',
    tagging:            './modules/tagging',
  };
  for (const [name, modPath] of Object.entries(modules)) {
    MODULE_MAP[name] = require(modPath);
  }
}

_loadModules();

class ScanEngine {
  constructor() {
    this.scans = new Map();
    this.events = new Map();
    this.control = new Map(); // scanId -> AbortController, for user-initiated stop
  }

  startScan(target, profileName = 'quick', outOfScope = null, configOverrides = null, mode = 'classic') {
    if (!isValidTarget(target)) throw new Error('invalid target');
    const { host, port } = splitTarget(target);
    const profile = loadProfile(profileName);
    // Stored module/global settings form the base; explicit per-scan overrides win.
    const merged = { ...moduleSettings.toOverrides(), ...(configOverrides || {}) };
    if (port) merged.targetPort = port;
    const config = getConfig(merged);
    const workspace = new Workspace(host);
    // Seed the target host itself so a leaf/subdomain target (or an empty passive
    // enumeration) never produces an empty chain: probe/collect/test still proceed,
    // and read_artifact('subdomains') shows >=1 instead of looking broken.
    try { workspace.appendLines('subdomains.txt', [port ? `${host}:${port}` : host]); } catch { /* best-effort seed */ }
    const oos = outOfScope || moduleSettings.globals().out_of_scope || null;
    const scope = new Scope([`*.${host}`, host], oos);
    const store = new AssetStore(workspace.root);
    const scanId = workspace.scanId;

    this.scans.set(scanId, {
      scan_id: scanId,
      target: host,
      profile: profileName,
      mode,
      status: 'running',
      started_at: Date.now() / 1000,
      modules_total: mode === 'ai' ? 0 : profile.modules.length,
      modules_done: 0,
      current_module: null,
      results: {},
      workspace_path: workspace.root,
    });
    this.events.set(scanId, []);
    const controller = new AbortController();
    this.control.set(scanId, controller);

    const runner = mode === 'ai'
      ? this._runAgenticScan(scanId, workspace, scope, store, config, profileName, controller.signal)
      : this._runScan(scanId, profile, workspace, scope, store, config, controller.signal);
    runner.catch((err) => {
      const scan = this.scans.get(scanId);
      if (scan) {
        scan.status = 'error';
        scan.error = err.message;
      }
      this._addEvent(scanId, 'error', err.message);
    });

    return scanId;
  }

  async _runAgenticScan(scanId, workspace, scope, store, config, profileName, signal) {
    const scan = this.scans.get(scanId);
    const aiSettings = require('./ai/settings');
    const s = aiSettings.load();
    if (!s.enabled || !s.apiKey) throw new Error('AI is not configured — set a provider key in Settings');
    const { runAgenticScan, TOOL_MODULES } = require('./ai/agent');
    const allowIntrusive = ['aggressive', 'full'].includes(profileName);
    // Drop the agent tools whose module the user disabled in Settings.
    const exclude = Object.entries(TOOL_MODULES)
      .filter(([, moduleKey]) => !moduleSettings.isEnabled(moduleKey))
      .map(([friendly]) => friendly);
    const agentRan = new Set();
    const res = await runAgenticScan({
      target: workspace.target,
      scope,
      workspace,
      config,
      allowIntrusive,
      exclude,
      signal,
      model: s.agentModel || s.model,
      maxToolCalls: s.maxToolCalls,
      provider: aiSettings.getProvider(),
      emit: (type, data) => this._addEvent(scanId, type, typeof data === 'string' ? data : JSON.stringify(data || {})),
      runTool: (moduleName) => { agentRan.add(moduleName); return this._runModule(scanId, moduleName, workspace, scope, store, config); },
    });
    // Coverage guarantee: a cheap agent model often finishes before running every
    // finding module, so after it stops we deterministically run any it skipped over
    // the surface it discovered — an active agentic scan is then at least as thorough
    // as a classic aggressive one, with the agent's reasoning/chaining on top.
    if (allowIntrusive && scan.status === 'running' && !(signal && signal.aborted)) {
      const { CONFIRM_MODULES } = require('./ai/agent');
      const emit = (type, data) => this._addEvent(scanId, type, typeof data === 'string' ? data : JSON.stringify(data || {}));
      const todo = CONFIRM_MODULES.filter(m => !agentRan.has(m) && MODULE_MAP[m] && moduleSettings.isEnabled(m));
      if (todo.length) {
        emit('agent_thought', `Sweeping ${todo.length} remaining checks to guarantee full coverage.`);
        for (const m of todo) {
          if (signal && signal.aborted) break;
          emit('tool_call', m);
          let result;
          try { result = await this._runModule(scanId, m, workspace, scope, store, config); }
          catch (e) { result = { items: [], status: 'error' }; }
          const items = (result && result.items) || [];
          emit('tool_result', JSON.stringify({ tool: m, found: items.length, sample: items.slice(0, 2).map(x => typeof x === 'string' ? x : (x && (x.url || x.name)) || ''), status: (result && result.status) || 'error' }));
        }
      }
    }
    scan.finished_at = Date.now() / 1000;
    scan.current_module = null;
    const fc = this._countFindings(workspace);
    scan.findings = fc.findings; scan.confirmed = fc.confirmed;
    this._persistFindings(workspace, scan, fc);
    if (scan.status === 'stopped') return; // user stopped it — keep the stopped status
    // A provider/auth failure before the agent ran any tool is a failed scan,
    // not a completed one — surface it so the UI can guide the user to Settings.
    if (res && res.error && !res.calls) {
      scan.status = 'error';
      scan.error = res.error;
      this._addEvent(scanId, 'scan_done', 'error');
    } else {
      scan.status = 'completed';
      if (res && res.error) scan.warning = res.error; // partial run: tools ran, then the provider failed
      this._addEvent(scanId, 'scan_done', 'completed');
    }
  }

  // Modules that can safely run at the same time (verified I/O deps)
  static PARALLEL_GROUPS = {
    'probe':          'discover',    // reads subdomains.txt
    'portscan':       'discover',    // reads subdomains.txt
    'urls':           'harvest',     // reads live.txt
    'content':        'harvest',     // reads live.txt
    'jsrecon':        'enrich',      // reads urls.txt + live.txt
    'params':         'enrich',      // reads urls.txt
    'vuln_confirm':   'confirm',     // reads findings.jsonl
    'xss_confirm':    'confirm',     // reads urls.txt + findings.jsonl
    'sqli_confirm':   'confirm',     // reads findings.jsonl + params.txt
    'authz_probe':    'confirm',     // reads urls.txt
    'bypass_403':     'confirm',     // reads findings.jsonl + hosts.jsonl
    'secret_verify':  'confirm',     // reads findings.jsonl + urls.txt
  };

  async _runScan(scanId, profile, workspace, scope, store, config, signal) {
    const modules = profile.modules.filter(m => {
      if (!MODULE_MAP[m]) {
        this._addEvent(scanId, 'warn', `Unknown module: ${m}`);
        return false;
      }
      if (!moduleSettings.isEnabled(m)) {
        this._addEvent(scanId, 'skip', `Module disabled in Settings: ${m}`);
        return false;
      }
      return true;
    });
    // Keep modules_total honest once disabled ones are dropped.
    const scanRec = this.scans.get(scanId);
    if (scanRec) scanRec.modules_total = modules.length;

    const groups = this._buildGroups(modules);

    for (const group of groups) {
      if (signal && signal.aborted) break;
      if (group.length === 1) {
        await this._runModule(scanId, group[0], workspace, scope, store, config);
      } else {
        this._addEvent(scanId, 'parallel_start', `Running ${group.length} modules in parallel: ${group.join(', ')}`);
        await Promise.allSettled(
          group.map(modName => this._runModule(scanId, modName, workspace, scope, store, config))
        );
      }
    }

    const scan = this.scans.get(scanId);
    const fc = this._countFindings(workspace);
    scan.findings = fc.findings; scan.confirmed = fc.confirmed;
    if (scan.status === 'stopped') { this._persistFindings(workspace, scan, fc); return; } // user stopped it between groups
    scan.status = 'completed';
    scan.finished_at = Date.now() / 1000;
    scan.current_module = null;
    this._persistFindings(workspace, scan, fc);
    this._addEvent(scanId, 'scan_done', 'completed');
  }

  _buildGroups(modules) {
    const groups = [];
    let i = 0;
    while (i < modules.length) {
      const tag = ScanEngine.PARALLEL_GROUPS[modules[i]];
      if (!tag) {
        groups.push([modules[i]]);
        i++;
        continue;
      }
      const batch = [modules[i]];
      while (i + 1 < modules.length && ScanEngine.PARALLEL_GROUPS[modules[i + 1]] === tag) {
        batch.push(modules[++i]);
      }
      groups.push(batch);
      i++;
    }
    return groups;
  }

  async _runModule(scanId, modName, workspace, scope, store, config) {
    const scan = this.scans.get(scanId);
    scan.current_module = modName;
    this._addEvent(scanId, 'module_start', modName);
    workspace.markPhase(modName, 'running');

    const ModClass = MODULE_MAP[modName];
    const mod = new ModClass(workspace, scope, config, (type, kwargs) => {
      this._addEvent(scanId, type, JSON.stringify(kwargs || {}));
    });

    const result = await mod.run();
    workspace.markPhase(modName, result.status);

    scan.results[modName] = {
      status: result.status,
      items_count: result.items.length,
      duration: Math.round(result.duration * 10) / 10,
      tool_used: result.toolUsed,
      fallback: result.fallback,
      errors: result.errors,
    };
    scan.modules_done++;

    store.addMany(modName, result.items);
    this._addEvent(scanId, 'module_done', `${modName}: ${result.items.length} items in ${result.duration.toFixed(1)}s`);
    return result;
  }

  // "Findings" must mean vulnerabilities, never surface size. Count the unique
  // vuln records (confirmed ∪ potential, deduped by class|url|param) — the same
  // merge the Findings tab renders — so a target with 10k URLs never reads as
  // "10k findings". Cheap: reads two small jsonl files once at scan end.
  _countFindings(workspace) {
    try {
      const conf = workspace.readJsonl('confirmed.jsonl');
      const find = workspace.readJsonl('findings.jsonl');
      const key = f => `${String(f.vuln_class || f.name || '').toLowerCase()}|${f.url || ''}|${(f.evidence && f.evidence.param) || ''}`;
      const seen = new Set();
      for (const f of conf) seen.add(key(f));
      for (const f of find) seen.add(key(f));
      return { findings: seen.size, confirmed: conf.length };
    } catch { return { findings: 0, confirmed: 0 }; }
  }

  _persistFindings(workspace, scan, fc) {
    try {
      Object.assign(workspace.state, {
        findings: fc.findings, confirmed: fc.confirmed,
        results: scan.results, status: scan.status,
        mode: scan.mode, profile: scan.profile,
        started_at: scan.started_at, finished_at: scan.finished_at,
      });
      workspace.saveState();
    } catch { /* best effort — the live scan record still has the counts */ }
  }

  stopScan(scanId) {
    const scan = this.scans.get(scanId);
    if (!scan || scan.status !== 'running') return false;
    const ctrl = this.control.get(scanId);
    if (ctrl) { try { ctrl.abort(); } catch { /* ignore */ } } // aborts the agent loop + the in-flight LLM request
    try { require('./runner').killActive(); } catch { /* ignore */ } // hard-kill in-flight tool subprocesses
    scan.status = 'stopped';
    scan.finished_at = Date.now() / 1000;
    scan.current_module = null;
    this._addEvent(scanId, 'agent_stop', 'stopped by user');
    this._addEvent(scanId, 'scan_done', 'stopped');
    return true;
  }

  getScan(scanId) {
    return this.scans.get(scanId) || this._restoreFromDisk(scanId);
  }

  // Scans live in memory, so a restart loses them while their files remain on
  // disk. Rebuild a read-only view from the workspace so past scans (and their
  // AI report/triage) stay reachable. Returns null if not found on disk.
  _restoreFromDisk(scanId) {
    try {
      const fs = require('fs');
      const path = require('path');
      const { OUTPUT_DIR } = require('./config');
      if (!/^scan_[\w-]+$/.test(scanId) || !fs.existsSync(OUTPUT_DIR)) return null;
      for (const target of fs.readdirSync(OUTPUT_DIR)) {
        const dir = path.join(OUTPUT_DIR, target, scanId);
        const stateFile = path.join(dir, 'state.json');
        if (!fs.existsSync(stateFile)) continue;
        let st = {};
        try { st = JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch { /* keep defaults */ }
        return {
          scan_id: scanId,
          target: st.target || target,
          profile: st.profile || 'unknown',
          status: st.status || 'completed',
          started_at: st.started_at,
          finished_at: st.finished_at,
          results: st.results || {},
          findings: st.findings || 0,
          confirmed: st.confirmed || 0,
          mode: st.mode,
          workspace_path: dir,
          restored: true,
        };
      }
    } catch { /* fall through */ }
    return null;
  }

  listScans() {
    return [...this.scans.values()];
  }

  getEvents(scanId, after = 0) {
    const events = this.events.get(scanId) || [];
    return events.filter(e => e.seq > after);
  }

  _addEvent(scanId, eventType, data = '') {
    if (!this.events.has(scanId)) this.events.set(scanId, []);
    const events = this.events.get(scanId);
    const seq = events.length + 1;
    events.push({ seq, type: eventType, data, time: Date.now() / 1000 });
  }
}

module.exports = { ScanEngine };
