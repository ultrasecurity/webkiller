// GUI apps launched from Finder / `open` inherit a minimal launchd PATH that
// omits /opt/homebrew/bin, /usr/local/bin, ~/go/bin, etc. — so system tools
// (nmap, and any binary not resolved to an absolute path by the manifest) are
// invisible to registry's whichSync() and to runner's execFile(), even though
// they are installed and detect.js (which probes the login shell) finds them.
//
// Aligning process.env.PATH with the user's login shell at startup fixes both
// tool detection and scan-time execution. No-op on Windows.
const { spawnSync } = require('child_process');
const path = require('path');

function loginShellPath() {
  if (process.platform === 'win32') return '';
  try {
    const shell = process.env.SHELL || '/bin/zsh';
    // Markers isolate the PATH from any shell-startup noise (same trick as detect.js).
    const r = spawnSync(shell, ['-lic', 'printf "@@@%s@@@" "$PATH"'], { timeout: 2500, encoding: 'utf8' });
    const m = /@@@([^@]*)@@@/.exec(r.stdout || '');
    return m ? m[1] : '';
  } catch { return ''; }
}

function fixPath() {
  if (process.platform === 'win32') return process.env.PATH;
  const home = process.env.HOME || '';
  const current = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const shell = loginShellPath().split(path.delimiter).filter(Boolean);
  const common = [
    '/opt/homebrew/bin', '/opt/homebrew/sbin', '/usr/local/bin', '/opt/local/bin',
    path.join(home, 'go', 'bin'), path.join(home, '.local', 'bin'), path.join(home, 'bin'),
    '/usr/bin', '/bin', '/usr/sbin', '/sbin',
  ];
  // Login-shell PATH first (user's real setup), then common fallbacks, then whatever
  // we already had — de-duplicated, order preserved.
  process.env.PATH = [...new Set([...shell, ...common, ...current].filter(Boolean))].join(path.delimiter);
  return process.env.PATH;
}

module.exports = { fixPath, loginShellPath };
