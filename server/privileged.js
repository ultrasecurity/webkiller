// Cross-platform privilege handling for raw-socket nmap operations (-O OS
// detection now; SYN scans later). Design principles:
//   • OPT-IN — only used when the user enables OS detection.
//   • Best mechanism per platform, preferring a one-time setup over prompts.
//   • ALWAYS degradable — a scan never fails for lack of root; it drops -O and
//     uses connect-scan. Every call resolves (never rejects) and is timeout-bound.
//
// The API is ARGV-BASED (bin, args[]) so NO shell is involved on Linux/Windows.
// The only shell surface is macOS's osascript "do shell script", where every
// token is single-quoted AND the whole string is AppleScript-escaped. Callers
// pass a validated in-scope host and constant flags — never free text.

const { execFile, spawnSync } = require('child_process');

function isMac() { return process.platform === 'darwin'; }
function isLinux() { return process.platform === 'linux'; }

// macOS-only quoting: single-quote a token for /bin/sh, then escape the whole
// command for an AppleScript double-quoted string literal.
function shQuote(s) { return `'${String(s).replace(/'/g, `'\\''`)}'`; }
function escapeForAppleScript(cmd) { return String(cmd).replace(/\\/g, '\\\\').replace(/"/g, '\\"'); }

// Run `bin args...` elevated. Resolves (never rejects):
//   { ok, returncode, stdout, stderr, canceled, timedOut, method }
// On an unsupported/deferred platform resolves { ok:false } so the caller degrades.
function runPrivileged(bin, args = [], opts = {}) {
  const timeout = (opts.timeout || 180) * 1000;
  const MAXBUF = 50 * 1024 * 1024;
  return new Promise((resolve) => {
    let child;
    if (isMac()) {
      // Each token quoted for /bin/sh, then the whole line escaped for AppleScript.
      const cmd = [bin, ...args].map(shQuote).join(' ');
      const script = `do shell script "${escapeForAppleScript(cmd)}" with administrator privileges`;
      child = execFile('osascript', ['-e', script], { timeout, maxBuffer: MAXBUF }, (err, stdout, stderr) => {
        if (err) {
          const msg = String(stderr || err.message || '');
          const canceled = /-128|User canceled/i.test(msg);
          return resolve({ ok: false, returncode: err.code || 1, stdout: stdout || '', stderr: msg, canceled, timedOut: !!err.killed, method: 'osascript' });
        }
        resolve({ ok: true, returncode: 0, stdout: stdout || '', stderr: stderr || '', canceled: false, timedOut: false, method: 'osascript' });
      });
    } else if (isLinux()) {
      // pkexec: graphical polkit auth, runs argv directly (NO shell). The timeout
      // guarantees we never hang if no polkit agent answers.
      child = execFile('pkexec', [bin, ...args], { timeout, maxBuffer: MAXBUF }, (err, stdout, stderr) => {
        if (err) {
          // pkexec: 126 = dismissed/not authorized, 127 = auth-agent failure.
          const canceled = err.code === 126 || err.code === 127;
          return resolve({ ok: false, returncode: err.code || 1, stdout: stdout || '', stderr: String(stderr || err.message || ''), canceled, timedOut: !!err.killed, method: 'pkexec' });
        }
        resolve({ ok: true, returncode: 0, stdout: stdout || '', stderr: stderr || '', canceled: false, timedOut: false, method: 'pkexec' });
      });
    } else {
      // Windows / other: deferred. Always degrade, never throw.
      return resolve({ ok: false, returncode: -1, stdout: '', stderr: 'privileged execution not supported on this platform yet', canceled: false, timedOut: false, method: 'none' });
    }
    try { require('./runner').track(child); } catch { /* best effort — lets Stop kill it */ }
  });
}

// Timeout-bounded probe that never throws.
function probe(file, args, timeoutMs = 2500) {
  try {
    const r = spawnSync(file, args, { timeout: timeoutMs, encoding: 'utf8' });
    // Non-zero exit (or a killed/timed-out probe) means "not found / no match" for
    // every caller here (which, pgrep, getcap) — treat it as no result, so a guard
    // like onPath('pkexec') actually gates instead of seeing a truthy "\n".
    if (r.error || r.status !== 0) return null;
    return `${r.stdout || ''}\n${r.stderr || ''}`;
  } catch { return null; }
}
function onPath(bin) { return !!probe(process.platform === 'win32' ? 'where' : 'which', [bin]); }

// A polkit agent must be running for pkexec to prompt in a GUI session.
function polkitAgentPresent() {
  const out = probe('pgrep', ['-f', 'polkit.*(agent|auth)|polkit-gnome|polkit-kde|lxpolkit|xfce-polkit|mate-polkit']);
  return !!(out && out.trim());
}

// Decide how (if at all) to elevate for raw-socket nmap on THIS platform.
// `bin` must be the ABSOLUTE nmap path (registry.toolPath). Returns:
//   { method: 'caps'|'osascript'|'pkexec'|'none', setupHint?, note? }
function probeElevation(bin) {
  const abs = bin && bin[0] === '/';
  if (isMac()) {
    // No absolute path → we can't build a reliable privileged command; skip the
    // prompt entirely and let the caller go version-only.
    if (!abs) return { method: 'none', note: 'nmap path not resolved — OS detection skipped' };
    return { method: 'osascript' };
  }
  if (isLinux()) {
    const hint = `sudo setcap cap_net_raw,cap_net_admin+eip ${bin || 'nmap'}`;
    // Preferred: nmap already carries cap_net_raw (one-time setcap) → no prompt
    // ever; nmap then needs --privileged to actually use the capability.
    if (abs) {
      const caps = probe('getcap', [bin]);
      if (caps && /cap_net_raw/i.test(caps)) return { method: 'caps' };
    }
    // Else graphical sudo via polkit, only if both pkexec and an agent exist.
    if (onPath('pkexec') && polkitAgentPresent()) return { method: 'pkexec', setupHint: hint };
    return { method: 'none', setupHint: hint, note: 'OS detection needs root — grant nmap capabilities (no prompt) or install a polkit agent' };
  }
  if (process.platform === 'win32') {
    return { method: 'none', setupHint: 'Install Npcap from https://npcap.com', note: 'OS detection needs Npcap on Windows' };
  }
  return { method: 'none' };
}

// macOS pre-flight: trigger the admin prompt UPFRONT to prime the ~5-min auth
// cache and find out early if the user will decline (→ clean degrade, no mid-scan
// failure). Only macOS caches, so only macOS pre-flights.
async function preflightMac() {
  if (!isMac()) return { granted: false, canceled: false };
  const r = await runPrivileged('/bin/echo', ['wk-root-ok'], { timeout: 120 });
  return { granted: r.ok && /wk-root-ok/.test(r.stdout), canceled: r.canceled };
}

module.exports = { runPrivileged, probeElevation, preflightMac, isMac, isLinux };
