// AI hook: turn a scan's artifacts into a readable Markdown report.
// Cost lever: the high-volume raw lists (urls/subs) never go to the model —
// only counts plus a severity-capped sample of findings. Keeps token spend flat
// no matter how large the scan.

const fs = require('fs');
const path = require('path');

function readJsonl(file) {
  try {
    return fs.readFileSync(file, 'utf8').split('\n').filter(l => l.trim())
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(f => f && typeof f === 'object');
  } catch { return []; }
}
function readLines(file) {
  try { return fs.readFileSync(file, 'utf8').split('\n').map(s => s.trim()).filter(Boolean); }
  catch { return []; }
}

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const slim = f => ({
  name: f.name || f.vuln_class || f.template_id || 'unknown',
  severity: f.severity || 'info',
  url: f.url || '',
  vuln_class: f.vuln_class || undefined,
  evidence: f.evidence || undefined,
});

function buildContext(wsPath, target) {
  const findings = readJsonl(path.join(wsPath, 'findings.jsonl'));
  const confirmed = readJsonl(path.join(wsPath, 'confirmed.jsonl'));
  const subs = readLines(path.join(wsPath, 'subdomains.txt'));
  const live = readLines(path.join(wsPath, 'live.txt'));
  const urls = readLines(path.join(wsPath, 'urls.txt'));

  const topFindings = [...findings]
    .sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9))
    .slice(0, 40).map(slim);

  return {
    target,
    counts: {
      subdomains: subs.length, live_hosts: live.length, urls: urls.length,
      findings: findings.length, confirmed: confirmed.length,
    },
    confirmed: confirmed.slice(0, 30).map(slim),
    topFindings,
  };
}

async function generateReport(provider, wsPath, target) {
  const context = buildContext(wsPath, target);
  const system = [
    'You are a senior web-application penetration tester writing the summary of a recon engagement.',
    'Write clear, factual GitHub-flavored Markdown. Never invent findings beyond the supplied data.',
    'Sections, in order: ## Executive Summary (2-4 sentences), ## Attack Surface (the counts), ',
    '## Key Findings (group by severity; each: what, the URL, why it matters), ## Confirmed Issues, ',
    '## Recommended Next Steps (concrete manual tests). Mark heuristic/unconfirmed findings as needing manual validation. Be concise.',
  ].join('');
  const user = `Engagement data (JSON):\n${JSON.stringify(context)}\n\nWrite the Markdown report now.`;
  const r = await provider.chat({ system, user, temperature: 0.3, maxTokens: 2000 });
  return { markdown: r.content || '', usage: r.usage || null, context };
}

module.exports = { generateReport, buildContext };
