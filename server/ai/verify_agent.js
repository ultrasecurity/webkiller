// Layer 2 CVE verification. An LLM PROPOSES safe, read-only checks for a CVE lead;
// the harness EXECUTES them (GET/HEAD/OPTIONS only, in-scope) and decides the
// verdict deterministically — a lead is "verified" only when a proposed response
// "tell" actually appears in the REAL response the harness fetched. The model never
// self-reports a verdict, so it cannot hallucinate a confirmation. Leads the
// classifier marked "unverifiable" never reach here (cve_verify filters them out).

const http = require('http');
const https = require('https');
const { DEFAULT_UA } = require('../user_agents');

const MAX_CHECKS_PER_LEAD = 3;
const MAX_TOTAL_REQUESTS = 40; // cumulative HTTP cap across every lead in one scan
const MAX_LEADS = 25;          // cap model calls — only this many leads get an active agent check

async function verifyLeadsWithAgent(leads, { scope, emit, ua } = {}) {
  let provider;
  try { provider = require('./settings').getProvider(); } catch { provider = null; }
  if (!provider) return leads.map(l => ({ lead: l, verified: false, reason: 'AI provider unavailable' }));

  const out = [];
  let budget = MAX_TOTAL_REQUESTS;
  let i = 0;
  for (const lead of leads) {
    if (i++ >= MAX_LEADS) { out.push({ lead, verified: false, reason: 'verification cap reached (too many leads)' }); continue; }
    if (budget <= 0) { out.push({ lead, verified: false, reason: 'verification budget exhausted' }); continue; }
    let res;
    try { res = await verifyOne(lead, { scope, provider, emit, budget, ua }); }
    catch (e) { res = { verified: false, reason: `verify error: ${String(e.message || e).slice(0, 80)}`, used: 0 }; }
    budget -= (res.used || 0);
    out.push({ lead, verified: !!res.verified, evidence: res.evidence, reason: res.reason });
  }
  return out;
}

async function verifyOne(lead, { scope, provider, emit, budget, ua }) {
  const sys = [
    'You are a web-security verifier. Given a possible CVE on a host, propose up to',
    `${MAX_CHECKS_PER_LEAD} SAFE, READ-ONLY HTTP GET checks that would PROVE the host is actually affected`,
    '(not merely a version guess). Each check: {"path":"/...","where":"body"|"header","contains":"<exact substring only a vulnerable/affected target returns>"}.',
    'ONLY non-destructive GETs — never anything that changes state, crashes, floods, or exploits. If no safe check can prove it, return an empty list.',
    'Respond with ONLY JSON: {"checks":[{"path":"/..","where":"body","contains":".."}]}',
  ].join(' ');
  const user = `CVE: ${lead.cve}\nService: ${lead.name}\nCPE: ${lead.cpe}\nTarget: ${lead.url}\nSummary: ${String(lead.summary || '').slice(0, 800)}`;

  let resp;
  try { resp = await provider.chat({ messages: [{ role: 'system', content: sys }, { role: 'user', content: user }], temperature: 0.1, maxTokens: 500 }); }
  catch { return { verified: false, reason: 'model call failed', used: 0 }; }

  let checks = [];
  try {
    const j = JSON.parse((String(resp.content || '').match(/\{[\s\S]*\}/) || ['{}'])[0]);
    checks = (Array.isArray(j.checks) ? j.checks : []).slice(0, MAX_CHECKS_PER_LEAD);
  } catch { checks = []; }
  if (!checks.length) return { verified: false, reason: 'no safe check available', used: 0 };

  let used = 0;
  for (const chk of checks) {
    if (used >= MAX_CHECKS_PER_LEAD || used >= budget) break;
    const url = buildUrl(lead.url, chk.path);
    let u; try { u = new URL(url); } catch { continue; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
    if (!scope || !scope.inScope || !scope.inScope(u.hostname)) continue; // in-scope only — never trust the model on scope
    used++;
    if (emit) emit('log', { msg: `verify ${lead.cve}: GET ${u.pathname}${u.search}` });
    let r; try { r = await safeGet(u, ua); } catch { continue; }
    const hay = (chk.where === 'header' ? JSON.stringify(r.headers || {}) : (r.body || '')).toLowerCase();
    const needle = String(chk.contains || '').toLowerCase().trim();
    // Deterministic verdict: the tell must be present in the REAL response.
    if (needle && needle.length >= 3 && hay.includes(needle)) {
      return { verified: true, used, evidence: { check: `GET ${u.pathname}${u.search}`, tell: String(chk.contains).slice(0, 120), where: chk.where || 'body', status: r.status } };
    }
  }
  return { verified: false, reason: 'proposed checks did not confirm', used };
}

function buildUrl(base, path) {
  const b = /^https?:\/\//.test(base) ? base : `http://${base}`;
  try { return new URL(path || '/', b).toString(); } catch { return b; }
}

// GET-only fetch; forced safe method, bad certs tolerated, size + time capped.
function safeGet(u, ua) {
  return new Promise((resolve, reject) => {
    const mod = u.protocol === 'https:' ? https : http;
    const opts = { method: 'GET', headers: { 'User-Agent': ua || DEFAULT_UA } };
    if (u.protocol === 'https:') opts.agent = new https.Agent({ rejectUnauthorized: false });
    let settled = false; const done = (fn, a) => { if (!settled) { settled = true; fn(a); } };
    const req = mod.request(u, opts, (res) => {
      const chunks = []; let size = 0;
      const finish = () => done(resolve, { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.on('data', c => { if (settled) return; size += c.length; chunks.push(c); if (size > 1024 * 1024) { finish(); res.destroy(); } });
      res.on('end', finish); res.on('error', finish); res.on('aborted', finish);
    });
    req.on('error', e => done(reject, e));
    req.setTimeout(10000, () => req.destroy(new Error('timeout')));
    req.end();
  });
}

module.exports = { verifyLeadsWithAgent };
