// Decide whether a version-based CVE lead can be VERIFIED SAFELY and remotely.
// Deterministic (no AI). Primary signal = CWE; fallback = description keywords.
//
// SAFE DEFAULT: when the class is unclear, the verdict is 'unverifiable' — an
// ambiguous CVE is NEVER pushed into the active-verify path. Destructive classes
// (DoS, memory corruption, RCE, command/code injection, deserialization) are
// always 'unverifiable' so they can never be auto-triggered.

// CWEs whose exploitation is destructive or has no safe, observable remote tell.
const UNVERIFIABLE_CWE = {
  'CWE-400': 'denial of service', 'CWE-399': 'denial of service',
  'CWE-120': 'memory corruption', 'CWE-121': 'memory corruption', 'CWE-122': 'memory corruption',
  'CWE-119': 'memory corruption', 'CWE-125': 'memory corruption', 'CWE-787': 'memory corruption',
  'CWE-416': 'memory corruption (use-after-free)', 'CWE-415': 'memory corruption (double-free)',
  'CWE-476': 'crash (null deref)', 'CWE-401': 'denial of service (leak)',
  'CWE-190': 'integer overflow', 'CWE-191': 'integer underflow',
  'CWE-94': 'remote code execution', 'CWE-95': 'remote code execution', 'CWE-96': 'remote code execution',
  'CWE-77': 'command injection', 'CWE-78': 'command injection',
  'CWE-502': 'insecure deserialization (RCE)', 'CWE-434': 'arbitrary file upload (RCE)',
  'CWE-362': 'race condition',
};
// CWEs that usually have a safe, observable remote tell → active-verify candidates.
const CANDIDATE_CWE = new Set([
  'CWE-79', 'CWE-80', 'CWE-83', // XSS
  'CWE-22', 'CWE-23', 'CWE-36', 'CWE-98', // traversal / file inclusion
  'CWE-918', // SSRF
  'CWE-601', // open redirect
  'CWE-200', 'CWE-209', 'CWE-532', 'CWE-538', 'CWE-548', // info disclosure / listing
  'CWE-89', // SQLi (observable error/time tell)
  'CWE-287', 'CWE-306', 'CWE-285', 'CWE-639', 'CWE-566', // auth / access control
  'CWE-611', // XXE
  'CWE-74', 'CWE-113', // injection with observable reflection
]);

const UNVERIFIABLE_KW = [
  ['denial of service', 'denial of service'], ['denial-of-service', 'denial of service'],
  ['resource consumption', 'denial of service'], ['memory consumption', 'denial of service'],
  ['cause a crash', 'crash'], ['application crash', 'crash'],
  ['buffer overflow', 'memory corruption'], ['out-of-bounds', 'memory corruption'], ['out of bounds', 'memory corruption'],
  ['use after free', 'memory corruption'], ['use-after-free', 'memory corruption'], ['double free', 'memory corruption'],
  ['null pointer', 'crash'], ['integer overflow', 'integer overflow'], ['integer underflow', 'integer underflow'],
  ['remote code execution', 'remote code execution'], ['code execution', 'remote code execution'],
  ['arbitrary code', 'remote code execution'], ['command execution', 'command injection'],
  ['arbitrary command', 'command injection'], ['deserializ', 'insecure deserialization'],
  ['race condition', 'race condition'], ['privilege escalation', 'privilege escalation'],
  ['local attacker', 'local-only'], ['requires authentication', 'requires authentication'],
  ['authenticated attacker', 'requires authentication'], ['must be authenticated', 'requires authentication'],
];
const CANDIDATE_KW = [
  'cross-site scripting', 'cross site scripting', 'path traversal', 'directory traversal',
  'local file inclusion', 'file inclusion', 'server-side request forgery', 'open redirect',
  'information disclosure', 'sensitive information', 'directory listing', 'sql injection',
  'authentication bypass', 'improper authorization', 'improper access control', 'reflected',
  'xml external entity',
];

function classifyVerifiability(lead) {
  const cwes = (lead && Array.isArray(lead.cwe) ? lead.cwe : []).map(String);
  const text = ` ${String((lead && lead.summary) || (lead && lead.evidence && lead.evidence.detail) || '').toLowerCase()} `;

  // 1) CWE is the strongest signal; "unverifiable" wins (safe default).
  for (const c of cwes) if (UNVERIFIABLE_CWE[c]) return { verifiable: false, status: 'unverifiable', reason: UNVERIFIABLE_CWE[c] };
  for (const c of cwes) if (CANDIDATE_CWE.has(c)) return { verifiable: true, status: null, reason: null };

  // 2) No decisive CWE → keywords; unverifiable checked FIRST.
  for (const [kw, reason] of UNVERIFIABLE_KW) if (text.includes(kw)) return { verifiable: false, status: 'unverifiable', reason };
  for (const kw of CANDIDATE_KW) if (text.includes(kw)) return { verifiable: true, status: null, reason: null };

  // 3) Unknown class → SAFE DEFAULT: not auto-verified.
  return { verifiable: false, status: 'unverifiable', reason: 'class unclear — manual review' };
}

module.exports = { classifyVerifiability };
