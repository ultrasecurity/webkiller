// Ref-counted toggle for skipping TLS verification while probing scan targets,
// whose certificates are frequently self-signed or expired.
//
// The previous per-module save/restore of NODE_TLS_REJECT_UNAUTHORIZED raced:
// confirm modules run concurrently (same 'confirm' parallel group), so one
// module would read the already-disabled '0' as the "original" value and then
// restore verification to OFF permanently — silently disabling TLS checks for
// every later HTTPS request in the process, tool downloads included. Ref
// counting makes only the first push disable and only the last pop restore.
let depth = 0;
let savedValue;

function pushInsecureTLS() {
  if (depth === 0) {
    savedValue = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }
  depth += 1;
}

function popInsecureTLS() {
  if (depth === 0) return;
  depth -= 1;
  if (depth === 0) {
    if (savedValue === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = savedValue;
  }
}

module.exports = { pushInsecureTLS, popInsecureTLS };
