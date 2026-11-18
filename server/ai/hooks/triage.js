// AI hook: triage raw findings to cut false positives and rank what a human
// should check first. Returns every finding with a keep flag, a 1-5 priority,
// and a one-line reason, sorted best-first.

const fs = require('fs');
const path = require('path');

function readJsonl(file) {
  try {
    return fs.readFileSync(file, 'utf8').split('\n').filter(l => l.trim())
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(f => f && typeof f === 'object');
  } catch { return []; }
}

async function triageFindings(provider, wsPath) {
  const findings = readJsonl(path.join(wsPath, 'findings.jsonl'));
  if (!findings.length) return { items: [], total: 0, usage: null };

  // Cap what we send; attach a stable id so verdicts map back cleanly.
  const slim = findings.slice(0, 80).map((f, i) => ({
    id: i,
    name: f.name || f.vuln_class || f.template_id || 'unknown',
    severity: f.severity || 'info',
    url: f.url || '',
    type: f.type || '',
    evidence: f.evidence || null,
  }));

  const system = [
    'You triage web-security findings to cut false positives and rank what a human should verify first.',
    'For each finding id decide: keep (boolean — false if it is almost certainly a false positive),',
    'priority (1-5, 1 = check first), and a one-line reason. Reflection-only or purely heuristic',
    'findings are usually low confidence. Respond with ONLY JSON of the form',
    '{"verdicts":[{"id":0,"keep":true,"priority":1,"reason":"..."}]} and nothing else.',
  ].join(' ');
  const user = `Findings (JSON):\n${JSON.stringify(slim)}`;
  const r = await provider.chat({ system, user, temperature: 0, maxTokens: 2000 });

  let verdicts = [];
  try {
    const match = (r.content || '').match(/\{[\s\S]*\}/);
    verdicts = JSON.parse(match ? match[0] : r.content).verdicts || [];
  } catch { /* parse failed — fall through with no verdicts */ }
  if (!Array.isArray(verdicts)) verdicts = [];

  // Key by String on both sides: a model may return ids as numbers or strings,
  // and a type mismatch would silently drop every verdict (triage no-op).
  const byId = new Map(verdicts.map(v => [String(v.id), v]));
  const items = slim.map(f => {
    const v = byId.get(String(f.id)) || {};
    const pr = Number.isInteger(v.priority) ? v.priority : 3;
    return {
      name: f.name, severity: f.severity, url: f.url, type: f.type,
      keep: v.keep !== false,
      priority: Math.min(5, Math.max(1, pr)),
      reason: v.reason || '',
    };
  }).sort((a, b) => a.priority - b.priority);

  return { items, total: findings.length, usage: r.usage || null };
}

module.exports = { triageFindings };
