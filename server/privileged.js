// Run a command with administrator (root) privileges on macOS via a native GUI
// auth dialog (osascript "do shell script ... with administrator privileges").
// This is how the app acquires root for `nmap -O` (OS detection) WITHOUT a
// controlling terminal — a plain `sudo` cannot prompt from inside a GUI app.
// macOS caches the authorization right for ~5 minutes, so a pre-flight prompt
// at scan start and the real nmap run usually ask the user only once.
//
// Safety: callers pass a FIXED command built from a validated, in-scope host and
// constant flags — never user free-text. Non-macOS degrades to "no root" so the
// caller falls back to an unprivileged scan instead of failing.

const { execFile } = require('child_process');

function isMac() { return process.platform === 'darwin'; }

// Escape a command string for embedding inside an AppleScript double-quoted
// string literal: do shell script "<here>" with administrator privileges.
function escapeForAppleScript(cmd) {
  return String(cmd).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// Run `cmd` (a full shell command line) as root. Resolves:
//   { ok, returncode, stdout, stderr, canceled }
// canceled=true when the user dismissed the auth dialog (osascript error -128).
function runPrivileged(cmd, timeout = 180) {
  return new Promise((resolve) => {
    if (!isMac()) {
      return resolve({ ok: false, returncode: -1, stdout: '', stderr: 'privileged run is only supported on macOS', canceled: false });
    }
    const script = `do shell script "${escapeForAppleScript(cmd)}" with administrator privileges`;
    const child = execFile('osascript', ['-e', script], { timeout: timeout * 1000, maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        const msg = String(stderr || err.message || '');
        const canceled = /-128|User canceled/i.test(msg);
        return resolve({ ok: false, returncode: err.code || 1, stdout: stdout || '', stderr: msg, canceled });
      }
      resolve({ ok: true, returncode: 0, stdout: stdout || '', stderr: stderr || '', canceled: false });
    });
    // Register with the runner so a user "Stop" (killActive) can terminate the
    // osascript helper in-flight. Best-effort — lazy require avoids a cycle.
    try { require('./runner').track(child); } catch { /* best effort */ }
  });
}

// Pre-flight: trigger the admin prompt UPFRONT (before the scan's real work) and
// cache the credential, so a later privileged nmap -O does not prompt mid-scan —
// and so a user who is going to deny is found out early and the scan degrades
// gracefully to version-only, instead of failing part-way through.
// Returns { granted, canceled }.
async function preflightRoot() {
  if (!isMac()) return { granted: false, canceled: false };
  const r = await runPrivileged('echo wk-root-ok', 120);
  return { granted: r.ok && /wk-root-ok/.test(r.stdout), canceled: r.canceled };
}

module.exports = { runPrivileged, preflightRoot, isMac };
