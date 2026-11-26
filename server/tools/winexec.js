// ============================================================
// Windows batch-shim exec helper.
//
// Node >= 18.20 / 20.12 / 21.7 refuses to spawn a .cmd/.bat without a
// shell (throws EINVAL — the CVE-2024-27980 mitigation). Our PATH probes
// and tool runners can land on such a shim (a scoop shim, a hand-written
// .bat, or a user-set manual path), so route those through cmd.exe.
//
// A strict NO-OP for .exe and for every non-Windows platform: there it
// returns the original (file, args) untouched, so spawn/spawnSync/execFile
// behave exactly as before.
// ============================================================

// Build the cmd.exe argv that runs `file args` safely. Pure + platform-agnostic
// so it can be unit-tested off Windows. Each token (the batch path and every arg)
// is wrapped in double quotes — embedded quotes doubled — and the whole command is
// wrapped once more; `/s` then strips that outer pair, leaving cmd with a line of
// individually-quoted tokens. Quoting each arg keeps spaces intact and shields cmd
// metacharacters (& | < >) inside the quotes. `/d` skips registry AutoRun commands.
function buildCmdArgv(file, args, comspec) {
  const q = s => `"${String(s).replace(/"/g, '""')}"`;
  const inner = [file, ...(args || [])].map(q).join(' ');
  return {
    command: comspec || process.env.ComSpec || 'cmd.exe',
    args: ['/d', '/s', '/c', `"${inner}"`],
    options: { windowsVerbatimArguments: true },
  };
}

function isWinBatch(file) {
  return process.platform === 'win32' && /\.(cmd|bat)$/i.test(String(file || ''));
}

// Returns { command, args, options } to feed straight into spawn/spawnSync/execFile.
// Off Windows, or for a non-batch file, it's the original call with no extra options.
function winBatchArgv(file, args) {
  if (isWinBatch(file)) return buildCmdArgv(file, args);
  return { command: file, args, options: {} };
}

module.exports = { winBatchArgv, buildCmdArgv, isWinBatch };
