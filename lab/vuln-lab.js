// WebKiller test lab — a DELIBERATELY VULNERABLE web app, 4 difficulty levels
// per class, bound to 127.0.0.1 only. For authorized testing of WebKiller's
// active modules (and dalfox/ghauri). Throwaway target — never expose it.
//
//   L1 = naked (one simple payload triggers)
//   L2 = light filter (needs an alternate payload)
//   L3 = stronger filter / obfuscation (needs advanced payloads)
//   L4 = properly patched (must NOT be detectable — false-positive control)
//
// Run:  node lab/vuln-lab.js      (PORT via VPORT, default 8900)

const http = require('http');
const https = require('https');
const os = require('os');
const fs = require('fs');
const path = require('path');
const PORT = Number(process.env.VPORT || 8900);
function readBody(req) {
  return new Promise((resolve) => {
    let b = ''; req.on('data', (c) => { b += c; if (b.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(b)); req.on('error', () => resolve(''));
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const page = (body) => `<!doctype html><html><body>${body}</body></html>`;
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const html = (res, code, body) => { res.writeHead(code, { 'Content-Type': 'text/html' }); res.end(page(body)); };

// A fixed favicon so the favicon-hash (wide-recon) module computes a stable
// Shodan/ZoomEye pivot hash against the lab. Deterministic bytes = deterministic hash.
const FAVICON = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAQUlEQVR42mNkYGD4z0ABYBxVSFSFjP///xkYGBgY/jP8Z2BgYGBg+M/wn4GBgYGB4T/DfwYGBgYGhv8M/xkYGBgYAFVQD/1V3W2yAAAAAElFTkSuQmCC', 'base64');

// A fixed set of "documents" for the UUID-id IDOR level.
const DOCS = { '7b2e4c10-0000-4000-8000-000000000001': 'alice', '7b2e4c10-0000-4000-8000-000000000002': 'bob' };

// ── Reflected XSS ─────────────────────────────────────────────────────────
function xss(res, lvl, q) {
  if (lvl === 1) return html(res, 200, `<h1>Results for: ${q}</h1>`);                       // raw reflection
  if (lvl === 2) return html(res, 200, `<h1>Results for: ${q.replace(/<script/gi, '')}</h1>`); // strips <script only
  if (lvl === 3) {                                                                            // tag chars encoded, but inside a quoted attribute → " breakout
    const e = q.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return html(res, 200, `<input type="text" value="${e}">`);
  }
  if (lvl === 4) return html(res, 200, `<h1>Search complete.</h1>`);                          // input not reflected (patched)
  return html(res, 404, 'no such level');
}

// ── Time-based SQLi ───────────────────────────────────────────────────────
async function sqli(res, lvl, id) {
  const timeish = /sleep|waitfor|benchmark|pg_sleep/i;
  if (lvl === 1) { if (timeish.test(id)) await sleep(5200); return html(res, 200, `<p>Product ${id}</p>`); }
  if (lvl === 2) { const f = id.replace(/sleep/gi, ''); if (/waitfor|benchmark/i.test(f)) await sleep(5200); return html(res, 200, `<p>Product</p>`); }
  if (lvl === 3) {                                                                            // WAF blocks plain keywords; DB executes comment-obfuscated ones
    const wafBlocked = timeish.test(id);
    if (!wafBlocked) { const db = id.replace(/\/\*.*?\*\//g, '').replace(/\s+/g, ''); if (timeish.test(db)) await sleep(5200); }
    return html(res, 200, `<p>Product</p>`);
  }
  if (lvl === 4) return html(res, 200, `<p>Product</p>`);                                     // parameterized — never delays
  return html(res, 404, 'no such level');
}

// ── IDOR / broken access control ──────────────────────────────────────────
function idor(res, lvl, id, req) {
  const authed = !!(req.headers.authorization || /(^|;\s*)sid=/.test(req.headers.cookie || ''));
  if (lvl === 1) {                                                                            // no auth, sequential; write methods accepted (method tampering)
    if (['PUT', 'DELETE', 'PATCH'].includes(req.method)) return json(res, 200, { ok: true, method: req.method });
    return json(res, 200, { id, email: `user${id}@corp.local`, note: `Private record for user ${id}, padded beyond the fifty-byte IDOR threshold for detection.` });
  }
  if (lvl === 2) {                                                                            // session-gated: no cookie → 401 (needs auth; sequential once in)
    if (!authed) return json(res, 401, { error: 'login required' });
    return json(res, 200, { id, email: `user${id}@corp.local`, note: `Private record for user ${id}, long enough to pass the length threshold.` });
  }
  if (lvl === 3) {                                                                            // non-sequential UUID ids → numeric bump fails (needs enumeration)
    if (!DOCS[id]) return json(res, 404, { error: 'not found' });
    return json(res, 200, { id, owner: DOCS[id], note: `Document owned by ${DOCS[id]}; still readable by anyone, long enough for detection.` });
  }
  if (lvl === 4) {                                                                            // proper authz: token must own the resource
    const owner = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');              // "token" is the owner's own id
    if (!owner) return json(res, 401, { error: 'login required' });
    if (owner !== String(id)) return json(res, 403, { error: 'forbidden' });
    return json(res, 200, { id, email: `user${id}@corp.local` });
  }
  return json(res, 404, { error: 'no such level' });
}

// ── 403 bypass ────────────────────────────────────────────────────────────
function secret(res, lvl, rest, req) {
  const hdr = req.headers['x-original-url'] || req.headers['x-rewrite-url'] || req.headers['x-custom-ip-authorization'];
  const hasVariant = rest.length > 0;                                                         // anything after /secret/N
  if (lvl === 1) { if (hasVariant || hdr || req.headers['x-forwarded-for']) return html(res, 200, 'ADMIN (L1 bypassed)'); return html(res, 403, 'Forbidden'); }
  if (lvl === 2) { if (hdr) return html(res, 200, 'ADMIN (L2 header bypass)'); return html(res, 403, 'Forbidden'); }   // only header bypass
  if (lvl === 3) {                                                                            // only an encoded/semicolon path trick bypasses
    if (/%2e|\.\.;|;\/|\/\.$/i.test(rest)) return html(res, 200, 'ADMIN (L3 path trick bypass)');
    return html(res, 403, 'Forbidden');
  }
  if (lvl === 4) return html(res, 403, 'Forbidden');                                          // all attempts blocked
  return html(res, 404, 'no such level');
}

// ═══ Phase B: advanced vuln classes ═════════════════════════════════════════
const text = (res, body) => { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end(body); };

// ── SSTI (Server-Side Template Injection) — safe arithmetic eval only ────────
function ssti(res, lvl, name) {
  const compute = (e) => { const m = e.replace(/\s/g, '').match(/^(\d{1,7})([*+\-])(\d{1,7})$/); if (!m) return null; const a = +m[1], b = +m[3]; return m[2] === '*' ? a * b : m[2] === '+' ? a + b : a - b; };
  const sub = (str, open, close) => { const i = str.indexOf(open); if (i < 0) return null; const j = str.indexOf(close, i + open.length); if (j < 0) return null; const v = compute(str.slice(i + open.length, j)); if (v === null) return null; return str.slice(0, i) + v + str.slice(j + close.length); };
  let out = name, r;
  if (lvl === 1) { r = sub(name, '{{', '}}'); if (r !== null) out = r; }               // {{7*7}} -> 49
  else if (lvl === 2) { r = sub(name, '${', '}'); if (r !== null) out = r; }            // {{ }} inert; ${ } evaluates
  else if (lvl === 3) { r = sub(name, '#{', '}'); if (r !== null) out = r; }            // only #{ }
  else { out = String(name).replace(/[{}$#]/g, ''); }                                   // L4 strips meta chars
  return html(res, 200, `<p>Hello ${out}</p>`);
}

// ── Shared loopback-only fetcher (SSRF + XXE). The lab can never proxy the
//    internet — it only ever talks to itself, so pointing it anywhere else is
//    refused at the socket. The "vuln" is that it fetches an INTERNAL canary.
function fetchLocal(target, cb) {
  let u; try { u = new URL(target); } catch { return cb('bad url'); }
  if (!/^(127\.0\.0\.1|localhost|0\.0\.0\.0|127\.1|2130706433|\[::1\]|::1)$/i.test(u.hostname)) return cb('blocked host');
  const req = http.get({ hostname: '127.0.0.1', port: u.port || PORT, path: (u.pathname || '/') + (u.search || '') }, (r) => {
    let b = ''; r.on('data', (c) => (b += c)); r.on('end', () => cb(null, b.slice(0, 2000)));
  });
  req.on('error', () => cb('fetch error'));
  req.setTimeout(3000, () => req.destroy());
}

// ── SSRF ────────────────────────────────────────────────────────────────────
function ssrf(res, lvl, urlParam) {
  const raw = String(urlParam);
  try { new URL(raw); } catch { return json(res, 400, { error: 'bad url' }); }
  // Realistic SSRF filters run on the RAW input, before the HTTP client
  // normalizes it — so 127.1 and the decimal IP bypass a string blocklist.
  const allowed = lvl === 1 ? true
    : lvl === 2 ? !/127\.0\.0\.1|localhost/i.test(raw)         // 127.1 / 0.0.0.0 bypass
    : lvl === 3 ? !/127|localhost|0\.0|::1/i.test(raw)         // decimal IP (2130706433) bypass
    : false;                                                    // L4 allowlist — nothing internal
  if (!allowed) return json(res, 403, { error: 'host not allowed' });
  fetchLocal(raw, (err, body) => err ? json(res, 502, { error: err }) : json(res, 200, { fetched: raw, body }));
}

// ── LFI (Local File Inclusion) — simulated: never touches the real filesystem ─
const FAKE_PASSWD = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwebkiller:x:1000:1000::/home/webkiller:/bin/bash\n';
function lfi(res, lvl, file) {
  const hits = (s) => /\.\.\//.test(s) && /etc\/passwd$/.test(s);
  let f = String(file || '');
  if (lvl === 1) { if (hits(f)) return text(res, FAKE_PASSWD); }                          // any ../ traversal
  else if (lvl === 2) { if (hits(f.replace(/\.\.\//g, ''))) return text(res, FAKE_PASSWD); } // strips ../ once -> ....// bypass
  else if (lvl === 3) { if (!/\.\.\//.test(f)) { let d = f; try { d = decodeURIComponent(f); } catch {} if (hits(d)) return text(res, FAKE_PASSWD); } } // blocks literal ../ -> double-encode bypass
  else { /* L4: basename only, patched */ }
  return html(res, 200, '<p>No such file</p>');
}

// ── XXE (XML External Entity) — resolves loopback SYSTEM entities on L1 ───────
function xxe(res, lvl, body) {
  const ent = String(body).match(/<!ENTITY\s+(\w+)\s+SYSTEM\s+["']([^"']+)["']\s*>/i);
  const used = /&(\w+);/.test(String(body));
  const done = (val) => json(res, 200, { parsed: val });
  if (lvl === 4 || !ent || !used) return done('(entities not processed)');
  if (lvl === 2 && /^https?:/i.test(ent[2])) return done('(http entity blocked)');     // L2 blocks http SYSTEM
  if (lvl === 3) return done('(external entities blocked)');                            // L3 blocks all external
  fetchLocal(ent[2], (err, data) => done(err ? '(entity error)' : data));              // L1 resolves -> canary
}

// ── Insecure deserialization — SIMULATED, never eval()s attacker input ───────
function deser(res, lvl, body) {
  let raw = String(body);
  if (lvl === 4) return json(res, 200, { ok: true, note: 'parsed as plain JSON' });      // safe
  if (lvl === 2) {
    if (!/^[A-Za-z0-9+/=]+\s*$/.test(raw.trim())) return json(res, 200, { ok: true });    // L2 wants base64...
    raw = Buffer.from(raw.trim(), 'base64').toString();                                    // ...then decodes before "unserialize"
  }
  const hasFunc = /_\$\$ND_FUNC\$\$_/.test(raw);
  const canary = (raw.match(/WK_DESER_([A-Za-z0-9]+)/) || [])[1];
  if (hasFunc && canary) return json(res, 200, { result: `WK_DESER_${canary}` });         // "function executed"
  return json(res, 200, { ok: true });
}

// ── JWT auth bypass ──────────────────────────────────────────────────────────
const _crypto = require('crypto');
const _b64url = (b) => Buffer.from(b).toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const _b64urlDec = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();
const JWT_STRONG = 'K7f3Qz9_strong-server-signing-key-not-guessable-2026';
const _hs256 = (data, secret) => _crypto.createHmac('sha256', secret).update(data).digest('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
function jwtLogin(res) {
  const h = _b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const p = _b64url(JSON.stringify({ user: 'guest', role: 'user' }));
  return json(res, 200, { token: `${h}.${p}.${_hs256(`${h}.${p}`, JWT_STRONG)}` });
}
function jwtProfile(res, lvl, auth) {
  const tok = String(auth || '').replace(/^Bearer\s+/i, '').trim();
  const parts = tok.split('.');
  if (parts.length < 2) return json(res, 401, { error: 'no token' });
  let header, payload;
  try { header = JSON.parse(_b64urlDec(parts[0])); payload = JSON.parse(_b64urlDec(parts[1])); } catch { return json(res, 400, { error: 'bad token' }); }
  const sigOk = (secret) => parts[2] === _hs256(`${parts[0]}.${parts[1]}`, secret);
  let ok;
  if (lvl === 1) ok = (String(header.alg).toLowerCase() === 'none') || sigOk(JWT_STRONG);  // accepts alg:none!
  else if (lvl === 2) ok = header.alg === 'HS256' && sigOk('secret');                       // weak secret "secret"
  else ok = header.alg === 'HS256' && sigOk(JWT_STRONG);                                     // L3/L4 proper
  if (!ok) return json(res, 403, { error: 'invalid token' });
  return json(res, 200, { role: payload.role, admin: payload.role === 'admin' });
}

// ═══ Phase C: modern "vibe-coding" vuln classes ═════════════════════════════

// ── Mass assignment ──────────────────────────────────────────────────────────
function account(res, lvl, body) {
  let obj = {}; try { obj = JSON.parse(body || '{}'); } catch { /* ignore */ }
  const user = { id: 1, name: typeof obj.name === 'string' ? obj.name : 'guest', role: 'user' };
  if (lvl === 1) Object.assign(user, obj);                                    // mass-assign: every field honoured
  else if (lvl === 2) { if ('is_admin' in obj) user.is_admin = obj.is_admin; } // only is_admin slips the filter
  else if (lvl === 3) { if ('isAdmin' in obj) user.isAdmin = obj.isAdmin; }     // only camelCase slips
  // L4: strict allowlist — all extra fields ignored
  return json(res, 200, user);
}

// ── NoSQL injection (auth bypass) ────────────────────────────────────────────
function nosql(res, lvl, body) {
  let o = {}; try { o = JSON.parse(body || '{}'); } catch { /* ignore */ }
  const win = () => json(res, 200, { ok: true, token: 'wk-session-abc', role: 'admin' });
  const deny = () => json(res, 401, { ok: false });
  const op = (v) => v && typeof v === 'object' && ('$ne' in v || '$gt' in v);
  if (lvl === 1) { if (o.user === 'admin' && op(o.pass)) return win(); return (o.user === 'admin' && o.pass === 'correcthorse') ? win() : deny(); }
  if (lvl === 2) { if (op(o.user)) return win(); return deny(); }              // casts pass to string; $ne on user still works
  if (lvl === 3) { if (o.user === 'admin' && o.pass && typeof o.pass === 'object' && '$regex' in o.pass) return win(); return deny(); } // $regex bypass
  return (o.user === 'admin' && o.pass === 'correcthorse') ? win() : deny();   // L4: strict string compare
}

// ── CORS misconfiguration ────────────────────────────────────────────────────
function cors(res, lvl, origin) {
  const trusted = 'trusted.example';
  let acao = null;
  if (origin) {
    if (lvl === 1) acao = origin;                                             // reflect ANY origin
    else if (lvl === 2) { if (new RegExp(escapeForRe(trusted) + '$').test(origin)) acao = origin; } // suffix regex -> evil-trusted.example bypass
    else if (lvl === 3) { if (origin === 'null' || origin === 'https://' + trusted) acao = origin; } // null origin allowed
    else { if (origin === 'https://' + trusted) acao = origin; }              // L4: strict allowlist
  }
  const h = { 'Content-Type': 'application/json' };
  if (acao) { h['Access-Control-Allow-Origin'] = acao; h['Access-Control-Allow-Credentials'] = 'true'; }
  res.writeHead(200, h); res.end(JSON.stringify({ secret: 'cross-origin-readable-user-data', origin: origin || null }));
}
function escapeForRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// ── Open redirect ────────────────────────────────────────────────────────────
function openredir(res, lvl, dest) {
  dest = String(dest || '');
  let target = null;
  if (lvl === 1) target = dest;                                              // any destination
  else if (lvl === 2) { if (!/^https?:\/\//i.test(dest)) target = dest; }    // blocks http(s):// ; //evil bypass
  else if (lvl === 3) { if (!/^https?:\/\//i.test(dest) && !/^\/\//.test(dest)) target = dest; } // blocks // too; \ or https:/ bypass
  else { if (dest.startsWith('/') && !dest.startsWith('//')) target = dest; } // L4: same-site relative only
  if (target) { res.writeHead(302, { Location: target }); return res.end(); }
  return html(res, 200, '<p>no redirect</p>');
}

// ── Prototype pollution — SIMULATED (no real global pollution) ────────────────
function protopollute(res, lvl, body) {
  const raw = String(body);
  const hasProto = /__proto__|"constructor"|"prototype"/.test(raw);
  const canary = (raw.match(/WKPP_([A-Za-z0-9]+)/) || [])[1];
  if (lvl === 4) return json(res, 200, { merged: true, polluted: false });    // safe merge
  if (hasProto && canary) return json(res, 200, { merged: true, polluted: true, value: `WKPP_${canary}` });
  return json(res, 200, { merged: true });
}

// ── GraphQL introspection / IDOR ─────────────────────────────────────────────
function graphql(res, lvl, body) {
  let q = ''; try { q = (JSON.parse(body || '{}').query) || ''; } catch { q = String(body); }
  if (/__schema|__type/i.test(q)) {
    if (lvl === 4) return json(res, 400, { errors: [{ message: 'introspection is disabled' }] });
    return json(res, 200, { data: { __schema: { queryType: { name: 'Query' }, types: [{ name: 'User' }, { name: 'Secret' }, { name: 'Query' }] } } });
  }
  return json(res, 200, { data: {} });
}

const INDEX = `<h1>WebKiller Vuln Lab</h1><p>Deliberately vulnerable — localhost only. Levels 1–4 (4 = patched).</p><ul>
${[1, 2, 3, 4].map((l) => `<li>XSS L${l}: <a href="/xss/${l}?q=test">/xss/${l}?q=</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>SQLi L${l}: <a href="/sqli/${l}?id=1">/sqli/${l}?id=</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>IDOR L${l}: <a href="/api/v${l}/user/1">/api/v${l}/user/1</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>403 L${l}: <a href="/secret/${l}">/secret/${l}</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>SSTI L${l}: <a href="/ssti/${l}?name=test">/ssti/${l}?name=</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>SSRF L${l}: <a href="/ssrf/${l}?url=http://example.com/">/ssrf/${l}?url=</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>LFI L${l}: <a href="/read/${l}?file=index.html">/read/${l}?file=</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>XXE L${l} (POST xml): <a href="/xxe/${l}">/xxe/${l}</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>Deser L${l} (POST): <a href="/deser/${l}">/deser/${l}</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>JWT L${l}: <a href="/jwt/${l}/profile">/jwt/${l}/profile</a> (token via <a href="/jwt/login">/jwt/login</a>)</li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>Mass-assign L${l} (POST): <a href="/account/${l}">/account/${l}</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>NoSQLi L${l} (POST): <a href="/nosql/${l}">/nosql/${l}</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>CORS L${l}: <a href="/cors/${l}">/cors/${l}</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>Open-redirect L${l}: <a href="/go/${l}?url=/home">/go/${l}?url=</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>Proto-pollution L${l} (POST): <a href="/pp/${l}">/pp/${l}</a></li>`).join('')}
${[1, 2, 3, 4].map((l) => `<li>GraphQL L${l} (POST): <a href="/graphql/${l}">/graphql/${l}</a></li>`).join('')}
</ul>`;

const handler = async (req, res) => {
  try {
    // Deliberately old/vulnerable service banners so the service_cve module
    // (nmap -sV) detects a version and maps it to CVEs. Fake, for testing only.
    res.setHeader('Server', 'Apache/2.4.49 (Unix)');
    res.setHeader('X-Powered-By', 'PHP/5.3.1');
    // Mimic CVE-2021-41773 / CVE-2021-42013 (Apache 2.4.49 path traversal) just
    // enough for a nuclei template to actually CONFIRM it: a traversal request that
    // reaches /etc/passwd gets a passwd-shaped body. Lets the CVE-verify engine
    // genuinely VERIFY a lead end-to-end in the local lab. Fake, for testing only.
    {
      let dec = req.url; try { dec = decodeURIComponent(req.url); } catch { /* keep raw */ }
      const traversal = req.url.includes('%2e') || dec.includes('../') || req.url.includes('/..');
      if (traversal && /etc\/passwd/i.test(dec)) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n');
      }
    }
    const u = new URL(req.url, 'http://127.0.0.1');
    const p = decodeURIComponent(u.pathname);
    if (p === '/' || p === '/index.html') return html(res, 200, INDEX);
    if (p === '/favicon.ico') { res.writeHead(200, { 'Content-Type': 'image/x-icon' }); return res.end(FAVICON); }
    // Declared-endpoint sources for the archive-recon (depth) module to mine.
    if (p === '/robots.txt') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end(`User-agent: *\nDisallow: /admin\nDisallow: /api/internal\nDisallow: /backup\nDisallow: /secret/1\nSitemap: http://127.0.0.1:${PORT}/sitemap.xml\n`);
    }
    if (p === '/sitemap.xml') {
      res.writeHead(200, { 'Content-Type': 'application/xml' });
      return res.end(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n<url><loc>http://127.0.0.1:${PORT}/xss/1?q=test</loc></url>\n<url><loc>http://127.0.0.1:${PORT}/hidden/report?doc=1&amp;fmt=pdf</loc></url>\n<url><loc>http://127.0.0.1:${PORT}/api/internal/users?id=1</loc></url>\n</urlset>\n`);
    }
    // OpenAPI spec for the api-routes (API-surface) module to parse.
    if (p === '/openapi.json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        openapi: '3.0.0', info: { title: 'Lab API', version: '1.0' },
        servers: [{ url: `http://127.0.0.1:${PORT}` }],
        paths: {
          '/api/orders': { get: { parameters: [{ name: 'status', in: 'query' }, { name: 'limit', in: 'query' }] } },
          '/api/users/{id}': { get: { parameters: [{ name: 'id', in: 'path' }] } },
          '/api/admin/config': { get: { parameters: [{ name: 'key', in: 'query' }] } },
          '/api/search': { get: { parameters: [{ name: 'q', in: 'query' }] } },
        },
      }));
    }

    let m;
    if ((m = p.match(/^\/xss\/([1-4])$/))) return xss(res, +m[1], u.searchParams.get('q') || '');
    if ((m = p.match(/^\/sqli\/([1-4])$/))) return sqli(res, +m[1], u.searchParams.get('id') || '');
    if ((m = p.match(/^\/api\/v([1-4])\/(?:user|doc)\/([^/]+)/))) return idor(res, +m[1], m[2], req);
    if ((m = p.match(/^\/secret\/([1-4])(.*)$/))) return secret(res, +m[1], m[2], req);

    // ── Phase B ──
    if ((m = p.match(/^\/ssti\/([1-4])$/))) return ssti(res, +m[1], u.searchParams.get('name') || '');
    if ((m = p.match(/^\/ssrf\/([1-4])$/))) return ssrf(res, +m[1], u.searchParams.get('url') || '');
    if ((m = p.match(/^\/read\/([1-4])$/))) return lfi(res, +m[1], u.searchParams.get('file') || '');
    if ((m = p.match(/^\/xxe\/([1-4])$/))) return xxe(res, +m[1], await readBody(req));
    if ((m = p.match(/^\/deser\/([1-4])$/))) return deser(res, +m[1], await readBody(req));
    if (p === '/jwt/login') return jwtLogin(res);
    if ((m = p.match(/^\/jwt\/([1-4])\/profile$/))) return jwtProfile(res, +m[1], req.headers.authorization || '');
    if (p === '/__canary') return text(res, 'WK_CANARY_PROVEN_' + (u.searchParams.get('token') || '')); // proof lives only in the RESPONSE

    // ── Phase C ──
    if ((m = p.match(/^\/account\/([1-4])$/))) return account(res, +m[1], await readBody(req));
    if ((m = p.match(/^\/nosql\/([1-4])$/))) return nosql(res, +m[1], await readBody(req));
    if ((m = p.match(/^\/cors\/([1-4])$/))) return cors(res, +m[1], req.headers.origin || '');
    if ((m = p.match(/^\/go\/([1-4])$/))) return openredir(res, +m[1], u.searchParams.get('url') || '');
    if ((m = p.match(/^\/pp\/([1-4])$/))) return protopollute(res, +m[1], await readBody(req));
    if ((m = p.match(/^\/graphql\/([1-4])$/))) return graphql(res, +m[1], await readBody(req));

    if (p === '/big') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('A'.repeat(4 * 1024 * 1024)); } // >2MB, for the response-cap regression

    html(res, 404, 'not found');
  } catch (e) {
    html(res, 500, 'error');
  }
};

// Optional HTTPS listener with a self-signed cert whose SANs seed the cert-intel
// (wide-recon) module with sibling/internal hostnames to discover. The cert is
// generated at startup into a temp dir (ephemeral) — never written to the repo.
function startTls(h) {
  const TLS_PORT = Number(process.env.VPORT_TLS || 8443);
  try {
    const { execFileSync } = require('child_process');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wk-lab-tls-'));
    const keyPath = path.join(dir, 'key.pem');
    const certPath = path.join(dir, 'cert.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '365', '-subj', '/CN=lab.local',
      '-addext', 'subjectAltName=DNS:lab.local,DNS:admin.lab.local,DNS:api-internal.lab.local,DNS:staging.lab.local,DNS:vpn.lab.local,IP:127.0.0.1'],
      { stdio: 'ignore' });
    https.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }, h)
      .listen(TLS_PORT, '127.0.0.1', () => console.log(`WebKiller vuln lab (TLS) on https://127.0.0.1:${TLS_PORT}  — self-signed, SANs for cert-intel`));
  } catch (e) {
    console.log('TLS listener skipped (openssl unavailable?):', e.message);
  }
}

const server = http.createServer(handler);
server.listen(PORT, '127.0.0.1', () => {
  console.log(`WebKiller vuln lab on http://127.0.0.1:${PORT}  (levels 1-4; 4 = patched)`);
});
startTls(handler);
