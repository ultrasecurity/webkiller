// Agentic recon: an LLM drives a fixed, scope-bound set of recon tools.
//
// Safety model: the agent CANNOT run arbitrary commands. It only chooses which
// predefined module to run next; every tool takes no host argument, so it can
// never point a module outside the scan's scope — scope is enforced structurally
// by the engine, not by trusting the model.
//
// Cost model: raw result lists never go to the model — only counts plus a small
// sample. Iteration and token budgets cap the loop so a cheap model cannot run
// up an unbounded bill.

const DEFAULT_MAX_TOOL_CALLS = 50; // tunable in Settings; the agent runs "wide" by default
const MAX_TOKENS_BUDGET = 600000;  // across the whole agentic scan (generous — a cheap agent model)
const MAX_HTTP_REQUESTS = 150;     // fine-grained requests the agent may send

// Friendly tool name -> engine module name.
const TOOL_MODULES = {
  enumerate_subdomains: 'subdomains_passive',
  permute_subdomains:   'subdomains_permute',
  probe_live_hosts:     'probe',
  favicon_pivot:        'favicon_hash',
  inspect_cert:         'cert_intel',
  map_asn:              'asn_cidr',
  enum_buckets:         'cloud_buckets',
  dork_github:          'github_dork',
  collect_urls:         'urls',
  fingerprint_tech:     'fingerprint',
  crawl_content:        'content',
  discover_api:         'api_routes',
  js_recon:             'jsrecon',
  find_parameters:      'params',
  mine_archives:        'archive_recon',
  triage_leads:         'lead_triage',
  scan_vulnerabilities: 'vuln_signal',
  confirm_xss:          'xss_confirm',
  confirm_sqli:         'sqli_confirm',
  confirm_ssti:         'ssti_confirm',
  confirm_lfi:          'lfi_confirm',
  confirm_ssrf:         'ssrf_confirm',
  confirm_xxe:          'xxe_confirm',
  confirm_deser:        'deser_confirm',
  confirm_jwt:          'jwt_confirm',
  confirm_massassign:   'massassign_confirm',
  confirm_nosqli:       'nosqli_confirm',
  confirm_cors:         'cors_confirm',
  confirm_openredirect: 'openredirect_confirm',
  confirm_protopp:      'protopollution_confirm',
  confirm_graphql:      'graphql_confirm',
  confirm_access:       'authz_probe',
  confirm_secrets:      'secret_verify',
  confirm_bypass403:    'bypass_403',
  deep_scan:            'vuln_confirm',
};

const TOOL_DESC = {
  enumerate_subdomains: 'Passive subdomain enumeration (crt.sh, subfinder) for the in-scope target.',
  permute_subdomains:   'Generate likely permutations of discovered subdomains (dev-, -staging, api2, internal.) and resolve them to find forgotten/internal hosts.',
  probe_live_hosts:     'Probe enumerated subdomains to find which hosts are live (HTTP/HTTPS).',
  favicon_pivot:        'Hash each live host\'s favicon and emit a Shodan/ZoomEye/Censys pivot to find sibling or hidden hosts serving the same icon.',
  inspect_cert:         'Pull the TLS certificate from live hosts and mine its SAN list for sibling/internal hostnames (admin., api., staging., internal).',
  map_asn:              'Map the target IPs to their ASN and announced CIDR ranges (Team Cymru / RADB) to expand to the org\'s full IP footprint.',
  enum_buckets:         'Guess bucket names from the target brand and probe S3/GCS/Azure for ones that exist (public or private).',
  dork_github:          'Search public GitHub code for the target domain/brand next to secret keywords, surfacing leaked keys and internal endpoints (needs a configured token).',
  collect_urls:         'Collect URLs/endpoints for the live hosts (archives, crawl).',
  fingerprint_tech:     'Fingerprint technologies/servers on the live hosts.',
  crawl_content:        'Discover content/paths on the live hosts.',
  discover_api:         'Find an OpenAPI/Swagger spec and expand its documented REST paths + params into testable URLs.',
  js_recon:             'Analyze JavaScript for endpoints and secrets.',
  find_parameters:      'Discover request parameters on collected URLs.',
  mine_archives:        'Mine robots.txt, sitemap.xml and the Wayback archive for extra endpoints and historical parameters.',
  triage_leads:         'Classify collected URLs by likely vuln class from their parameter names (gf-style) to focus the confirm phase.',
  scan_vulnerabilities: 'Run signal-level vulnerability checks over collected data.',
  confirm_xss:          'Actively test parameterized URLs for reflected XSS (intrusive).',
  confirm_sqli:         'Actively test parameters for time-based SQL injection (intrusive).',
  confirm_ssti:         'Actively test parameters for server-side template injection — often RCE (intrusive).',
  confirm_lfi:          'Actively test parameters for local file inclusion / path traversal (intrusive).',
  confirm_ssrf:         'Actively test URL-like parameters for server-side request forgery (intrusive).',
  confirm_xxe:          'POST crafted XML to endpoints to test for XML external entity injection (intrusive).',
  confirm_deser:        'POST crafted payloads to test for insecure deserialization — often RCE (intrusive).',
  confirm_jwt:          'Test JWT auth for alg:none and weak-secret forgery — auth bypass (intrusive).',
  confirm_massassign:   'POST privileged fields (role/is_admin) to test for mass assignment (intrusive).',
  confirm_nosqli:       'POST MongoDB operator objects to test for NoSQL injection / auth bypass (intrusive).',
  confirm_cors:         'Send a hostile Origin to find CORS misconfiguration that leaks authenticated data (intrusive).',
  confirm_openredirect: 'Test redirect-like parameters for open redirect to an attacker host (intrusive).',
  confirm_protopp:      'POST __proto__ payloads to test for prototype pollution (intrusive).',
  confirm_graphql:      'Run a GraphQL introspection query to detect an exposed schema (intrusive).',
  confirm_access:       'Test API endpoints for broken access control, IDOR and HTTP method tampering (intrusive).',
  confirm_secrets:      'Verify secrets found in JS/responses (API keys, tokens) and report the live ones (intrusive).',
  confirm_bypass403:    'Try path and header tricks to reach 403-forbidden endpoints (intrusive).',
  deep_scan:            'Run deeper DAST vulnerability checks over the collected URLs (intrusive).',
};

const ARTIFACTS = {
  subdomains:   { file: 'subdomains.txt', jsonl: false },
  live:         { file: 'live.txt', jsonl: false },
  urls:         { file: 'urls.txt', jsonl: false },
  js_endpoints: { file: 'js_endpoints.txt', jsonl: false },
  params:       { file: 'params.txt', jsonl: false },
  findings:     { file: 'findings.jsonl', jsonl: true },
  confirmed:    { file: 'confirmed.jsonl', jsonl: true },
};

const INTRUSIVE = new Set([
  'confirm_xss', 'confirm_sqli', 'confirm_ssti', 'confirm_lfi', 'confirm_ssrf', 'confirm_xxe', 'confirm_deser', 'confirm_jwt',
  'confirm_massassign', 'confirm_nosqli', 'confirm_cors', 'confirm_openredirect', 'confirm_protopp', 'confirm_graphql',
  'confirm_access', 'confirm_secrets', 'confirm_bypass403', 'deep_scan',
]);

// Finding-producing engine modules, for the post-agent coverage sweep (engine.js).
const CONFIRM_MODULES = ['vuln_signal', 'vuln_confirm', 'xss_confirm', 'sqli_confirm', 'ssti_confirm', 'lfi_confirm', 'ssrf_confirm', 'xxe_confirm', 'deser_confirm', 'jwt_confirm', 'massassign_confirm', 'nosqli_confirm', 'cors_confirm', 'openredirect_confirm', 'protopollution_confirm', 'graphql_confirm', 'authz_probe', 'bypass_403', 'secret_verify'];

function buildTools({ allowIntrusive = false, exclude = [] } = {}) {
  const ex = new Set(exclude); // prod-safe: drop loud/active modules (ffuf brute, full nuclei) by friendly name
  const names = Object.keys(TOOL_MODULES).filter(n => (allowIntrusive || !INTRUSIVE.has(n)) && !ex.has(n));
  // Every tool takes a REQUIRED one-line `reason`. Cheap tool-calling models fill a
  // required argument reliably (unlike the assistant `content`, which is usually empty
  // on a tool call), so this is what makes the live reasoning stream actually populate.
  const REASON = { type: 'string', description: 'One short sentence (max ~15 words): what you are about to do and why. Streamed live to the operator.' };
  const tools = names.map(name => ({
    type: 'function',
    function: { name, description: TOOL_DESC[name], parameters: { type: 'object', properties: { reason: REASON }, required: ['reason'], additionalProperties: false } },
  }));
  tools.push({
    type: 'function',
    function: {
      name: 'read_artifact',
      description: 'Inspect what has been gathered so far (returns counts + a small sample, not the full list).',
      parameters: { type: 'object', properties: { reason: REASON, artifact: { type: 'string', enum: Object.keys(ARTIFACTS) } }, required: ['reason', 'artifact'] },
    },
  });
  tools.push({
    type: 'function',
    function: {
      name: 'http_request',
      description: 'Send ONE in-scope HTTP request and read the response (status, key headers, truncated body). Use it to inspect a specific endpoint, test one parameter with a tailored payload, follow a redirect, or chain two findings into a real multi-step check. The target host must be in scope; in recon-only mode only GET/HEAD/OPTIONS are allowed.',
      parameters: {
        type: 'object',
        properties: {
          reason: REASON,
          method: { type: 'string', enum: ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'DELETE', 'PATCH'] },
          url: { type: 'string', description: 'Absolute URL on an in-scope host' },
          headers: { type: 'object', description: 'Optional request headers' },
          body: { type: 'string', description: 'Optional request body' },
        },
        required: ['reason', 'url'],
      },
    },
  });
  tools.push({
    type: 'function',
    function: {
      name: 'record_finding',
      description: 'Record a vulnerability you have CONFIRMED with evidence (e.g. via http_request) so it appears in the results and the report. Only record real, evidence-backed findings — never guesses.',
      parameters: {
        type: 'object',
        properties: {
          reason: REASON,
          title: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          url: { type: 'string' },
          detail: { type: 'string', description: 'The evidence: what you sent and what proved it' },
        },
        required: ['reason', 'title', 'severity', 'url'],
      },
    },
  });
  tools.push({
    type: 'function',
    function: {
      name: 'finish',
      description: 'End the scan once enough reconnaissance is done. Provide a short summary of what was found.',
      parameters: { type: 'object', properties: { reason: REASON, summary: { type: 'string' } }, required: ['reason', 'summary'] },
    },
  });
  return tools;
}

function systemPrompt(target, allowIntrusive) {
  const lines = [
    'You are an authorized web-application security testing agent operating inside a sandboxed engine with written consent.',
    `The ONLY target in scope is "${target}" and its subdomains (*.${target}). The tools enforce this — you cannot act outside scope.`,
    'Your goal is NOT just reconnaissance: it is to find and CONFIRM real vulnerabilities with concrete evidence. Work one tool at a time, in two phases.',
    'PHASE 1 — MAP the surface: enumerate subdomains, probe live hosts, collect URLs, crawl content, analyze JS, and find parameters. Then call read_artifact on "urls", "js_endpoints" and "params" to see exactly what endpoints and parameters exist.',
    'If the target is a single host or subdomain, passive subdomain enumeration may return nothing — that is expected, not a failure. The target host itself is always probed, so just call probe_live_hosts next and keep going. Never call finish only because enumeration was empty.',
    'PHASE 2 — TEST the surface: for every URL that carries a parameter, actively test it. Use http_request to send a tailored payload to a specific parameter and read the response, follow a redirect, bump an id to reach another record, or chain two findings into a real exploit — this is how you go deeper than a fixed pipeline.',
    'A response proves a vulnerability when a payload is reflected unencoded in HTML (XSS), a time-based payload delays the response (SQLi), bumping an id returns another user\'s data (IDOR), or a protected path becomes reachable (access-control bypass). When you have such evidence, call record_finding with exactly what you sent and what proved it.',
  ];
  if (allowIntrusive) {
    lines.push('You also have a suite of active confirm tools, one per vulnerability class — confirm_xss, confirm_sqli, confirm_ssti, confirm_lfi, confirm_ssrf, confirm_xxe, confirm_deser, confirm_jwt, confirm_massassign, confirm_nosqli, confirm_cors, confirm_openredirect, confirm_protopp, confirm_graphql, confirm_access, confirm_secrets, confirm_bypass403 — that batch-test the discovered surface. Once you have parameters and endpoints, run EVERY one that could apply to what you found — breadth is the goal, do not test just a few classes — then verify or extend each hit with http_request.');
  }
  lines.push('With EVERY tool call, put ONE short sentence of reasoning in the REQUIRED "reason" argument — what you are about to do and why (e.g. "The /item endpoint takes an id, so I will test it for SQL injection."). This is streamed live to the operator, so keep it present and specific. Put it in the reason argument, not in the message body.');
  lines.push('Do not stop after only enumerating — a scan that lists parameters but never tests them is incomplete. Never narrate without also calling a tool.');
  lines.push('Operate exhaustively and aggressively: MAXIMUM COVERAGE is the objective. Keep going until every discovered parameter and endpoint has been run through every confirm tool that could apply, and you have chased the obvious chains — only THEN call finish, with a concise summary of what you CONFIRMED and what you ruled out. You have a generous tool budget; spend it. Finishing with the surface half-tested is a failed scan.');
  return lines.join(' ');
}

function summarizeResult(toolName, result) {
  if (!result) return { tool: toolName, status: 'error', error: 'no result' };
  const items = Array.isArray(result.items) ? result.items : [];
  return {
    tool: toolName,
    status: result.status,
    found: items.length,
    tool_used: result.toolUsed || '',
    sample: items.slice(0, 5).map(x => (typeof x === 'string' ? x : (x && (x.name || x.url)) || String(x))),
    errors: (result.errors || []).slice(0, 2),
  };
}

function readArtifactSummary(workspace, name) {
  const def = ARTIFACTS[name];
  if (!def) return { artifact: name, error: 'unknown artifact' };
  try {
    if (def.jsonl) {
      const rows = workspace.readJsonl(def.file);
      return {
        artifact: name, count: rows.length,
        sample: rows.slice(0, 8).map(f => ({ name: f.name || f.vuln_class || f.template_id || 'unknown', severity: f.severity || 'info', url: f.url || '' })),
      };
    }
    const lines = workspace.readLines(def.file);
    return { artifact: name, count: lines.length, sample: lines.slice(0, 10) };
  } catch {
    return { artifact: name, count: 0, sample: [] };
  }
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function rawRequest(method, u, headers, body) {
  return new Promise((resolve, reject) => {
    const https = require('https');
    const http = require('http');
    const isHttps = u.protocol === 'https:';
    const mod = isHttps ? https : http;
    const opts = { method, headers: { 'User-Agent': 'WebKiller/2.0', ...(headers || {}) } };
    if (isHttps) opts.agent = new https.Agent({ rejectUnauthorized: false }); // scan targets often have bad certs
    let settled = false;
    const done = (fn, arg) => { if (!settled) { settled = true; fn(arg); } };

    const req = mod.request(u, opts, (res) => {
      const chunks = [];
      let size = 0;
      const finish = () => done(resolve, { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.on('data', (c) => {
        if (settled) return;
        size += c.length;
        chunks.push(c);
        // Cap the body AND settle — destroying the request without an error
        // leaves the promise hanging forever (and the whole scan with it).
        if (size > 2 * 1024 * 1024) { finish(); res.destroy(); }
      });
      res.on('end', finish);
      res.on('error', finish);   // return whatever we have on a mid-stream error
      res.on('aborted', finish);
    });
    req.on('error', (e) => done(reject, e));
    req.setTimeout(12000, () => { req.destroy(new Error('timeout')); });
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

function pickHeaders(h) {
  const out = {};
  for (const k of ['content-type', 'server', 'location', 'x-powered-by', 'www-authenticate', 'content-length', 'set-cookie', 'access-control-allow-origin']) {
    if (h[k] !== undefined) out[k] = (Array.isArray(h[k]) ? h[k].join('; ') : String(h[k])).slice(0, 200);
  }
  return out;
}

// The agent's one fine-grained capability. Scope is enforced HERE, in code —
// the host must be in scope, only http/https, intrusive methods need
// Active-tests mode, and the count is capped. This is what enables custom
// payloads, response inspection and chaining without trusting the model.
async function doHttpRequest(args, scope, allowIntrusive, state, emit) {
  const { method = 'GET', url, headers, body } = args || {};
  if (!url) return { error: 'url required' };
  if (state.count >= MAX_HTTP_REQUESTS) return { error: `http_request budget reached (${MAX_HTTP_REQUESTS})` };
  let u;
  try { u = new URL(url); } catch { return { error: 'invalid url' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { error: 'only http/https is allowed' };
  if (!scope || !scope.inScope(u.hostname)) return { error: `refused: ${u.hostname} is out of scope` };
  const m = String(method).toUpperCase();
  if (!SAFE_METHODS.has(m) && !allowIntrusive) return { error: `method ${m} needs Active-tests mode (recon-only allows GET/HEAD/OPTIONS)` };
  state.count += 1;
  emit('agent_request', `${m} ${u.pathname}${u.search}`);
  try {
    const r = await rawRequest(m, u, headers, body);
    const text = r.body || '';
    return { status: r.status, headers: pickHeaders(r.headers), length: text.length, body: text.slice(0, 4000) };
  } catch (e) {
    return { error: e.message || 'request failed' };
  }
}

function recordFinding(args, workspace, emit) {
  const { title, severity = 'info', url = '', detail = '' } = args || {};
  if (!title) return { error: 'title required' };
  const rec = {
    name: String(title).slice(0, 200),
    severity: ['critical', 'high', 'medium', 'low', 'info'].includes(severity) ? severity : 'info',
    url: String(url).slice(0, 500),
    evidence: detail ? { detail: String(detail).slice(0, 600) } : undefined,
    type: 'agent_confirmed',
    vuln_class: 'agent',
    module: 'agent',
  };
  try { workspace.appendJsonl('confirmed.jsonl', [rec]); workspace.appendJsonl('findings.jsonl', [rec]); } catch { /* ignore */ }
  emit('agent_finding', `${rec.severity.toUpperCase()} — ${rec.name}`);
  return { recorded: true };
}

// opts: { target, scope, workspace, config, provider, model, allowIntrusive, emit(type,data), runTool(moduleName)->ModuleResult }
async function runAgenticScan(opts) {
  const { target, scope, provider, emit, runTool, workspace, allowIntrusive = false, model, exclude = [], signal, maxToolCalls: maxToolCallsOpt } = opts;
  const MAX_TOOL_CALLS = Math.max(1, Number(maxToolCallsOpt) || DEFAULT_MAX_TOOL_CALLS);
  const MAX_ITERS = MAX_TOOL_CALLS + 10;
  const tools = buildTools({ allowIntrusive, exclude });
  const httpState = { count: 0 };
  const messages = [
    { role: 'system', content: systemPrompt(target, allowIntrusive) },
    { role: 'user', content: `Begin reconnaissance of ${target}. Call one tool at a time.` },
  ];

  let tokens = 0;
  let calls = 0;
  let nudged = false;
  let fatalError = null;
  emit('agent_start', `AI agent started on ${target}`);

  for (let iter = 0; iter < MAX_ITERS; iter++) {
    if (signal && signal.aborted) { emit('agent_stop', 'stopped by user'); break; }
    if (tokens > MAX_TOKENS_BUDGET) { emit('agent_stop', `token budget reached (~${tokens})`); break; }

    let resp;
    try {
      resp = await provider.chat({ messages, tools, temperature: 0.3, maxTokens: 1024, model, signal });
    } catch (e) {
      if (signal && signal.aborted) { emit('agent_stop', 'stopped by user'); break; }
      fatalError = e.message || String(e);
      emit('agent_error', fatalError);
      break;
    }
    tokens += (resp.usage && resp.usage.total_tokens) || 0;
    emit('agent_usage', String(tokens)); // stream the running token total so the UI meters update live, not only at the end

    const toolCalls = resp.toolCalls || [];
    const assistantMsg = { role: 'assistant', content: resp.content || '' };
    if (toolCalls.length) assistantMsg.tool_calls = toolCalls;
    messages.push(assistantMsg);

    if (!toolCalls.length && resp.content && resp.content.trim()) emit('agent_thought', resp.content.trim().slice(0, 600)); // reason now rides each tool's required arg; only narrate bare messages here

    if (!toolCalls.length) {
      if (nudged) { emit('agent_done', 'agent ended without an explicit finish'); break; }
      nudged = true;
      messages.push({ role: 'user', content: 'If reconnaissance is complete, call finish(summary). Otherwise call the next tool.' });
      continue;
    }

    let finished = false;
    let capReached = false;
    for (const tc of toolCalls) {
      if (signal && signal.aborted) break;
      const fname = tc.function && tc.function.name;
      let args = {};
      try { args = JSON.parse((tc.function && tc.function.arguments) || '{}'); } catch { /* bad args */ }
      if (args && args.reason) emit('agent_thought', String(args.reason).slice(0, 200)); // per-call rationale → live think line

      let content;
      if (fname === 'finish') {
        emit('agent_done', args.summary || 'done');
        finished = true;
        content = 'acknowledged';
      } else if (fname === 'read_artifact') {
        emit('agent_read', args.artifact || '');
        content = JSON.stringify(readArtifactSummary(workspace, args.artifact));
      } else if (fname === 'http_request') {
        content = JSON.stringify(await doHttpRequest(args, scope, allowIntrusive, httpState, emit));
      } else if (fname === 'record_finding') {
        content = JSON.stringify(recordFinding(args, workspace, emit));
      } else if (TOOL_MODULES[fname]) {
        if (calls >= MAX_TOOL_CALLS) {
          // Enforce the budget per tool-call, not just per iteration: one model
          // response can carry many parallel tool calls.
          capReached = true;
          content = `tool budget reached (${MAX_TOOL_CALLS} max); call finish to end the scan`;
        } else {
          calls += 1;
          emit('tool_call', fname);
          let result;
          try { result = await runTool(TOOL_MODULES[fname]); }
          catch (e) { result = { status: 'error', items: [], errors: [e.message] }; }
          const summary = summarizeResult(fname, result);
          emit('tool_result', JSON.stringify({ tool: fname, found: summary.found, sample: (summary.sample || []).slice(0, 2), status: summary.status }));
          content = JSON.stringify(summary);
        }
      } else {
        content = `unknown tool: ${fname}`;
      }
      messages.push({ role: 'tool', tool_call_id: tc.id, name: fname, content: String(content).slice(0, 4000) });
    }

    if (finished) break;
    if (signal && signal.aborted) { emit('agent_stop', 'stopped by user'); break; }
    if (capReached) { emit('agent_stop', `max tool calls reached (${MAX_TOOL_CALLS})`); break; }
  }

  emit('agent_summary', `agent ran ${calls} recon tools, ~${tokens} tokens`);
  return { calls, tokens, error: fatalError };
}

module.exports = { runAgenticScan, buildTools, TOOL_MODULES, CONFIRM_MODULES };
