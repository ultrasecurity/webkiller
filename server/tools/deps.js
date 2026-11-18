// ============================================================
// Dependencies facade — the one place that assembles per-tool
// status, capability status, install progress and "needed by"
// for the Dependencies UI. The UI recomputes nothing.
// ============================================================

const { TOOLS, CAPABILITIES } = require('./manifest');
const { detectAll, buildContext, capabilityStatus, platformKey } = require('./detect');
const { installTool, uninstallTool, loadLock } = require('./install');

// In-memory install progress, keyed by tool id. The UI polls /api/deps and
// reads tool.progress while a download is in flight.
const _progress = {};
let _checkedAt = null;

// Only darwin-arm64 has been verified on real hardware so far; everything else
// is built from the same manifest but honestly marked untested.
function platformTested(plat) { return plat === 'darwin-arm64'; }

function prettyCap(capId) { return capId.replace(/_confirm$/, '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()); }

// Capabilities that use a tool (as primary or fallback) → what breaks without it.
function neededBy(id) {
  const out = [];
  for (const [capId, cap] of Object.entries(CAPABILITIES)) {
    if (cap.primary === id || (cap.fallbacks || []).includes(id)) out.push(prettyCap(capId));
  }
  return out;
}
// Runtime deps (chrome/root/npcap) a tool needs on THIS platform, beyond the binary.
function runtimeNeeds(id, plat) {
  for (const cap of Object.values(CAPABILITIES)) {
    if (cap.primary !== id || !cap.requires) continue;
    return cap.requires
      .filter(r => !r.platforms || r.platforms.includes(plat))
      .map(r => ({ dep: r.dep, severity: r.severity, note: r.degradedMode || null }));
  }
  return [];
}

function payload(ctxOver) {
  const ctx = buildContext(ctxOver);
  const det = detectAll(ctx);
  _checkedAt = Date.now();
  const lock = loadLock();
  const plat = ctx.platform;

  const tools = Object.values(TOOLS).map(spec => {
    const d = det[spec.id] || { status: 'missing', candidates: [], reasons: [], installable: false };
    const assets = ((lock.tools[spec.id] || {}).assets) || {};
    const asset = assets[plat];
    const chosen = d.chosen;
    const hasAsset = !!(asset && asset.url);
    return {
      id: spec.id,
      displayName: spec.displayName,
      homepage: spec.homepage,
      kind: spec.install ? spec.install.kind : 'manual',
      status: d.status,
      version: (chosen && chosen.probe && chosen.probe.version) || null,
      source: (chosen && chosen.source) || null,
      path: (chosen && chosen.path) || null,
      // archive tools are installable only where the LOCK resolved a real asset — pdAsset
      // lists every platform, but some (e.g. naabu win-arm64) have no actual build.
      installable: (spec.install && spec.install.kind === 'archive') ? hasAsset : d.installable,
      // precise: verified = we pinned a vendor checksum; unverified = asset exists but no checksum published
      verified: !!(asset && asset.sha256),
      unverified: !!(hasAsset && !asset.sha256),
      sha256: (asset && asset.sha256) || null,
      url: (asset && asset.url) || null,
      host: hasAsset ? hostOf(asset.url) : null,
      size: (asset && asset.size) || null,
      lockVersion: (lock.tools[spec.id] || {}).version || null,
      platformSupport: (spec.platforms[plat] || {}).support || 'untested',
      reasons: d.reasons || [],
      neededBy: neededBy(spec.id),
      runtime: runtimeNeeds(spec.id, plat),
      manualCommand: spec.install && spec.install.kind === 'manual' ? spec.install.command : null,
      progress: _progress[spec.id] || null,
    };
  });

  const capabilities = Object.keys(CAPABILITIES).map(c => capabilityStatus(c, det));
  const counts = {
    total: tools.length,
    available: tools.filter(t => t.status === 'ready' || t.status === 'untested').length,
    attention: tools.filter(t => !(t.status === 'ready' || t.status === 'untested')).length,
  };
  return { platform: { key: plat, tested: platformTested(plat) }, counts, tools, capabilities, checkedAt: _checkedAt };
}

function hostOf(u) { try { return new URL(u).host; } catch { return null; } }

async function install(id, opts = {}) {
  const spec = TOOLS[id];
  if (!spec) throw new Error(`unknown tool ${id}`);
  _progress[id] = { phase: 'starting', pct: 0 };
  const hooks = {
    onPhase: ph => { _progress[id] = { phase: ph, pct: _progress[id] ? _progress[id].pct : 0 }; },
    onProgress: p => { if (_progress[id]) _progress[id].pct = Math.round(p * 100); },
  };
  try {
    const r = spec.install && spec.install.kind === 'uv-tool'
      ? await require('./uv').installUvTool(id, { ...opts, ...hooks })
      : await installTool(id, { ...opts, ...hooks });
    delete _progress[id];
    return r;
  } catch (e) {
    _progress[id] = { phase: 'error', error: e.message, code: e.code || 'error' };
    setTimeout(() => { if (_progress[id] && _progress[id].phase === 'error') delete _progress[id]; }, 15000);
    throw e;
  }
}

async function installAllMissing(opts = {}) {
  const p = payload();
  // Never batch-install something we can't hash-verify — those need an explicit per-tool OK.
  const targets = p.tools.filter(t => t.status !== 'ready' && t.status !== 'untested' && t.installable && t.verified);
  const results = [];
  for (const t of targets) {
    try { await install(t.id, opts); results.push({ id: t.id, ok: true }); }
    catch (e) { results.push({ id: t.id, ok: false, error: e.message }); }
  }
  return results;
}

// Cheap snapshot for polling during installs (no re-probing).
function progressSnapshot() { return { ..._progress }; }

module.exports = { payload, install, installAllMissing, uninstall: uninstallTool, progressSnapshot };
