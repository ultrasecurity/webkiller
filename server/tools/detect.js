// ============================================================
// Headless tool detection — the SINGLE source of truth for
// "is this tool usable, and which exact binary do we run?".
//
// No Electron, no shell-outs to which/where: we walk candidate
// directories in Node (one code path for all platforms), run each
// candidate's probe command, and classify it. exec/fs/cache are
// injectable so this runs under CI and `tools-doctor` with an empty
// PATH and a fresh managed dir.
// ============================================================

const { spawnSync } = require('child_process');
const nodeFs = require('fs');
const os = require('os');
const path = require('path');
const { TOOLS, CAPABILITIES, PLATFORMS } = require('./manifest');

// ---- platform ----
function platformKey() {
  const p = `${process.platform}-${process.arch}`;
  return PLATFORMS.includes(p) ? p : `${process.platform}-x64`;
}

// ---- tiny semver (ranges like ">=1.6.0 <1.7.0") ----
// Tolerate 1-, 2- or 3-part versions (nmap reports "7.92"), padding missing
// components with 0. Manifest ranges stay 3-part, so only the probed version side
// is affected.
function parseV(v) { const m = String(v || '').match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/); return m ? [+m[1], +(m[2] || 0), +(m[3] || 0)] : null; }
function cmpV(a, b) { for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; }
function satisfies(version, range) {
  const v = parseV(version); if (!v || !range) return false;
  return String(range).trim().split(/\s+/).every(part => {
    const m = part.match(/^(>=|<=|>|<|=)?\s*(\d+\.\d+\.\d+)/); if (!m) return true;
    const op = m[1] || '='; const c = cmpV(v, parseV(m[2]));
    return op === '>=' ? c >= 0 : op === '<=' ? c <= 0 : op === '>' ? c > 0 : op === '<' ? c < 0 : c === 0;
  });
}

// ---- system search dirs (resolved once) ----
let _sysDirs = null;
function loginShellPath() {
  if (process.platform === 'win32') return [];
  try {
    const shell = process.env.SHELL || '/bin/zsh';
    // One shot, timeout-guarded, delimiter-wrapped so stray rc output can't poison it.
    const r = spawnSync(shell, ['-lic', 'printf "@@@%s@@@" "$PATH"'], { timeout: 2500, encoding: 'utf8' });
    const m = r.stdout && r.stdout.match(/@@@([\s\S]*?)@@@/);
    if (m) return m[1].split(':').filter(Boolean);
  } catch { /* fall back to fixed list */ }
  return [];
}
function resolveSystemDirs() {
  if (_sysDirs) return _sysDirs;
  const home = os.homedir();
  const envPath = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const wellKnown = process.platform === 'win32'
    ? [process.env.ChocolateyInstall ? path.join(process.env.ChocolateyInstall, 'bin') : null, path.join(home, 'go', 'bin')].filter(Boolean)
    : [path.join(home, 'go', 'bin'), path.join(home, '.local', 'bin'), path.join(home, 'bin'), '/opt/homebrew/bin', '/usr/local/bin', '/opt/local/bin', '/usr/bin', '/bin'];
  const seen = new Set(); const out = [];
  for (const d of [...envPath, ...loginShellPath(), ...wellKnown]) if (d && !seen.has(d)) { seen.add(d); out.push(d); }
  _sysDirs = out; return out;
}
function resetSystemDirs() { _sysDirs = null; } // for tests / tools-doctor empty-PATH runs

// ---- exec names (handle Windows PATHEXT / .exe) ----
function exeNames(base) {
  if (process.platform === 'win32') {
    const exts = (process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';').map(e => e.toLowerCase());
    return [base, ...exts.map(e => base + e)];
  }
  return [base];
}

// ---- default injected deps ----
function defaultExec(file, args, opts) {
  const r = spawnSync(file, args, { timeout: (opts && opts.timeout) || 8000, encoding: 'utf8', windowsHide: true });
  let error = r.error;
  if (!error && r.signal === 'SIGTERM') error = Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, signal: r.signal, error };
}
function makeCache() { const m = new Map(); return { get: k => m.get(k), set: (k, v) => m.set(k, v) }; }

function buildContext(over = {}) {
  return {
    platform: over.platform || platformKey(),
    manualPaths: over.manualPaths || {},                 // { toolId: absolutePath }
    managedDir: over.managedDir || path.join(os.homedir(), '.webkiller', 'tools'),
    systemDirs: over.systemDirs || resolveSystemDirs(),
    exec: over.exec || defaultExec,
    fs: over.fs || nodeFs,
    cache: over.cache || makeCache(),
  };
}

// ---- candidates ----
function candidatePaths(spec, ctx) {
  const names = [spec.bin, ...(spec.aliases || [])];
  const out = [];
  const manual = ctx.manualPaths[spec.id];
  if (manual) out.push({ path: manual, source: 'manual' });
  try {
    const mdir = path.join(ctx.managedDir, spec.id);
    if (ctx.fs.existsSync(mdir)) for (const ver of ctx.fs.readdirSync(mdir))
      for (const nm of names) for (const e of exeNames(nm)) { const p = path.join(mdir, ver, e); if (ctx.fs.existsSync(p)) out.push({ path: p, source: 'managed', ver }); }
  } catch { /* ignore */ }
  for (const dir of ctx.systemDirs) for (const nm of names) for (const e of exeNames(nm)) {
    const p = path.join(dir, e); try { if (ctx.fs.existsSync(p)) out.push({ path: p, source: 'system' }); } catch { /* ignore */ }
  }
  const seen = new Set(); const uniq = [];
  for (const c of out) { let rp = c.path; try { rp = ctx.fs.realpathSync(c.path); } catch { /* keep */ } if (!seen.has(rp)) { seen.add(rp); uniq.push({ ...c, realpath: rp }); } }
  return uniq;
}

// ---- probe one binary ----
function probeOne(ctx, p, spec) {
  const pr = spec.probe || {};
  const r = ctx.exec(p, pr.args || ['--version'], { timeout: pr.timeoutMs || 8000 });
  if (r.error) {
    const msg = r.error.message || String(r.error);
    const code = r.error.code === 'ETIMEDOUT' ? 'TIMEOUT' : r.error.code === 'EACCES' ? 'EACCES'
      : /exec format|bad cpu|arch/i.test(msg) ? 'BAD_ARCH' : r.error.code === 'ENOENT' ? 'AV_REMOVED' : 'OTHER';
    return { kind: 'exec-failed', code, detail: msg };
  }
  const out = String((pr.stream === 'stdout' ? r.stdout : pr.stream === 'stderr' ? r.stderr : `${r.stdout || ''}\n${r.stderr || ''}`) || '');
  if (pr.identity && !new RegExp(pr.identity, 'i').test(out)) return { kind: 'wrong-binary', output: out.slice(0, 400) };
  if (pr.versionSource === 'probe' && pr.version) {
    const m = out.match(new RegExp(pr.version)); return m ? { kind: 'ok', version: m[1] } : { kind: 'unparseable', output: out.slice(0, 400) };
  }
  return { kind: 'ok', version: null }; // install-record / no version regex
}

function classify(spec, platform, probe) {
  if (probe.kind === 'exec-failed' || probe.kind === 'wrong-binary' || probe.kind === 'unparseable') return 'broken';
  const ver = probe.version;
  if (ver && spec.version.broken && satisfies(ver, spec.version.broken)) return 'incompatible';
  const sup = (spec.platforms[platform] || {}).support || 'untested';
  if (sup === 'unsupported') return 'untested';
  if (ver) return (satisfies(ver, spec.version.compatible) && sup === 'supported') ? 'ready' : 'untested';
  // ran + identity matched but no parseable version: trust it if the platform is supported
  return sup === 'supported' ? 'ready' : 'untested';
}

const RANK = { ready: 3, untested: 2, incompatible: 1, broken: 0 };
const SRC = { manual: 0, managed: 1, system: 2 };

function detectTool(spec, ctx) {
  const cands = candidatePaths(spec, ctx).map(c => {
    let key = c.realpath;
    try { const st = ctx.fs.statSync(c.realpath); key = `${c.realpath}|${st.mtimeMs}|${st.size}`; } catch { /* keep */ }
    let probe = ctx.cache.get(key);
    if (!probe) { probe = probeOne(ctx, c.path, spec); ctx.cache.set(key, probe); }
    // install-record tools (no CLI --version flag, e.g. arjun/gau): take the version
    // from the managed dir name, which install.js/uv.js wrote. System copies stay null.
    if (c.source === 'managed' && c.ver && spec.probe && spec.probe.versionSource === 'install-record' && probe.kind === 'ok' && !probe.version) {
      probe = { ...probe, version: c.ver };
    }
    return { path: c.path, source: c.source, probe, status: classify(spec, ctx.platform, probe) };
  });

  const reasons = [];
  let chosen;
  if (ctx.manualPaths[spec.id]) {
    // A user-set path is authoritative — report it even if broken, never fall through.
    chosen = cands.find(c => c.source === 'manual');
    if (chosen && chosen.status === 'broken') reasons.push('MANUAL_PATH_BROKEN');
  } else {
    // Silently drop a wrong binary found on the system PATH (the httpx collision).
    const viable = cands.filter(c => !(c.probe.kind === 'wrong-binary' && c.source !== 'manual'));
    const pool = viable.slice().sort((a, b) => RANK[b.status] - RANK[a.status] || SRC[a.source] - SRC[b.source]);
    chosen = pool[0];
  }

  const status = chosen ? chosen.status : 'missing';
  if (status === 'untested') {
    const ver = chosen && chosen.probe.version;
    if (ver && !satisfies(ver, spec.version.compatible)) reasons.push('VERSION_OUT_OF_RANGE');
    else if ((spec.platforms[ctx.platform] || {}).support !== 'supported') reasons.push('PLATFORM_UNTESTED');
  }
  if (status === 'broken' && chosen) reasons.push('BROKEN_' + (chosen.probe.code || chosen.probe.kind || 'UNKNOWN').toString().toUpperCase());
  const installable = !!(spec.install && (spec.install.kind === 'uv-tool' || spec.install.kind === 'manual' || (spec.install.assets && spec.install.assets[ctx.platform])));
  return { toolId: spec.id, status, chosen, candidates: cands, reasons, installable };
}

function detectAll(ctx) {
  ctx = ctx || buildContext();
  const out = {};
  for (const id of Object.keys(TOOLS)) out[id] = detectTool(TOOLS[id], ctx);
  return out;
}

// capability state (ready / fallback / blocked) — computed from tool detections,
// not from a single tool. Runtime deps (chrome/root/npcap) are surfaced as the
// suggested action; live dep probing is a later refinement.
function capabilityStatus(capId, detections) {
  const cap = CAPABILITIES[capId];
  if (!cap) return { capId, status: 'ready', action: null }; // builtin-only capability
  const usable = t => { if (t === 'builtin') return true; const d = detections[t]; return !!(d && (d.status === 'ready' || d.status === 'untested')); };
  const primary = detections[cap.primary];
  const hard = (cap.requires || []).filter(r => r.severity === 'hard');
  if (primary && usable(cap.primary)) {
    if (hard.length) return { capId, status: 'fallback', action: 'install-' + hard[0].dep, note: `needs ${hard[0].dep}` };
    return { capId, status: primary.status === 'ready' ? 'ready' : 'untested', action: null };
  }
  const fb = (cap.fallbacks || []).find(usable);
  if (fb) return { capId, status: 'fallback', action: primary && primary.installable ? 'install' : null, via: fb };
  return { capId, status: 'blocked', action: primary && primary.installable ? 'install' : 'unsupported-platform' };
}

module.exports = {
  platformKey, satisfies, resolveSystemDirs, resetSystemDirs, buildContext,
  detectTool, detectAll, capabilityStatus, makeCache, defaultExec,
};
