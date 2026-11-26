// ============================================================
// Python tools via uv — installs into a managed, isolated env
// (uv's own managed Python, all UV_* dirs under the app's tools
// folder), then exposes the entrypoint where detect() looks:
// managedDir/<id>/<version>/<bin> (a symlink into uv's bin dir).
//
// uv is a single standalone binary; if it isn't present we throw
// NEEDS_UV and the UI shows a copyable command instead (Fable's
// "ship manual if uv isn't green" — same interface, isolated risk).
// ============================================================

const { spawnSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { TOOLS } = require('./manifest');

function managedRoot(over) { return over || path.join(os.homedir(), '.webkiller', 'tools'); }

// Prefer a managed uv, then a system uv.
function findUv(managedDir) {
  const managed = path.join(managedRoot(managedDir), '_uv', 'uv' + (process.platform === 'win32' ? '.exe' : ''));
  if (fs.existsSync(managed)) return managed;
  try { const r = spawnSync('uv', ['--version'], { encoding: 'utf8', timeout: 5000 }); if (r.status === 0) return 'uv'; } catch { /* none */ }
  return null;
}

async function installUvTool(id, opts = {}) {
  const spec = TOOLS[id];
  const inst = spec && spec.install;
  if (!inst || inst.kind !== 'uv-tool') throw new Error(`${id} is not a uv tool`);
  const uv = opts.uvPath || findUv(opts.managedDir);
  if (!uv) { const e = new Error('uv is required to install Python tools'); e.code = 'NEEDS_UV'; throw e; }

  const root = managedRoot(opts.managedDir);
  const uvHome = path.join(root, '_uv');
  const env = {
    ...process.env,
    UV_TOOL_DIR: path.join(uvHome, 'tools'),
    UV_TOOL_BIN_DIR: path.join(uvHome, 'bin'),
    UV_PYTHON_INSTALL_DIR: path.join(uvHome, 'python'),
    UV_CACHE_DIR: path.join(uvHome, 'cache'),
  };
  fs.mkdirSync(env.UV_TOOL_BIN_DIR, { recursive: true });

  const pkg = inst.version === 'git' ? inst.package : `${inst.package}==${inst.version}`;
  const args = ['tool', 'install', '--python', inst.python || '3.12'];
  if (inst.excludeNewer) args.push('--exclude-newer', inst.excludeNewer);
  args.push(pkg);
  const r = spawnSync(uv, args, { env, encoding: 'utf8', timeout: 300000 });
  if (r.status !== 0) throw new Error('uv tool install failed: ' + String(r.stderr || r.stdout || '').slice(-400));

  const binName = inst.entrypoint + (process.platform === 'win32' ? '.exe' : '');
  const uvBin = path.join(env.UV_TOOL_BIN_DIR, binName);
  if (!fs.existsSync(uvBin)) throw new Error(`uv installed ${id} but entrypoint ${binName} not found`);

  // Expose it where detect() looks: managed/<id>/<version>/<bin>
  const ver = inst.version === 'git' ? (spec.version.tested || '0.0.0') : inst.version;
  const finalDir = path.join(root, id, ver);
  fs.rmSync(finalDir, { recursive: true, force: true });
  fs.mkdirSync(finalDir, { recursive: true });
  const link = path.join(finalDir, spec.bin + (process.platform === 'win32' ? '.exe' : ''));
  try { fs.symlinkSync(uvBin, link); } catch { fs.copyFileSync(uvBin, link); fs.chmodSync(link, 0o755); }
  return { id, version: ver, path: link, via: 'uv' };
}

module.exports = { installUvTool, findUv };
