// Static metadata that drives the Settings UI: every module, the helper tool it
// needs, whether it has a built-in fallback, and its tunable parameters.
// Descriptions are intentionally terse — one line, no filler.
const P = (key, label, type, extra = {}) => ({ key, label, type, ...extra });

const MODULE_META = [
  // ── Discovery ──
  { key: 'subdomains_passive', label: 'Passive subdomains', group: 'Discovery', tool: 'subfinder', desc: 'Subdomains from public sources', params: [P('subfinder_all', 'Use all sources', 'bool', { hint: 'slower, more complete' }), P('subfinder_timeout', 'Source timeout', 'number', { unit: 's', def: 30 })] },
  { key: 'subdomains_active', label: 'Active subdomains', group: 'Discovery', tool: 'dnsx', desc: 'Brute-force & permute subdomains', params: [P('dns_wordlist', 'Wordlist', 'file')] },
  { key: 'subdomains_permute', label: 'Subdomain permutation', group: 'Discovery', tool: 'dnsx', fallback: true, desc: 'Permute known subdomains & resolve', params: [P('perm_max_candidates', 'Max candidates', 'number', { def: 1500 })] },
  { key: 'probe', label: 'Host probe', group: 'Discovery', tool: 'httpx', fallback: true, desc: 'Find which hosts are live', params: [P('concurrency', 'Concurrency', 'number', { inheritsGlobal: true }), P('probe_timeout', 'Timeout', 'number', { unit: 's', def: 15 }), P('probe_follow_redirects', 'Follow redirects', 'bool'), P('probe_ports', 'Extra ports', 'text', { hint: 'e.g. 8080,8443' })] },
  { key: 'portscan', label: 'Port scan', group: 'Discovery', tool: 'naabu', desc: 'Open ports on live hosts', params: [P('top_ports', 'Top ports', 'number', { def: 1000 }), P('ports', 'Specific ports', 'text', { hint: 'e.g. 80,443,8080 — overrides top-ports' })] },
  { key: 'favicon_hash', label: 'Favicon hash', group: 'Discovery', tool: null, desc: 'Favicon → Shodan/Censys host pivot', params: [P('favicon_max_hosts', 'Max hosts', 'number', { def: 25 }), P('favicon_timeout', 'Timeout', 'number', { unit: 's', def: 10 })] },
  { key: 'cert_intel', label: 'TLS cert intel', group: 'Discovery', tool: null, desc: 'Mine TLS cert SANs for sibling hosts', params: [P('cert_max_hosts', 'Max hosts', 'number', { def: 25 }), P('cert_timeout', 'Timeout', 'number', { unit: 's', def: 8 }), P('cert_ports', 'TLS ports', 'text', { hint: 'e.g. 443,8443' })] },
  { key: 'asn_cidr', label: 'ASN → CIDR', group: 'Discovery', tool: null, desc: 'IP → ASN → announced IP ranges', params: [P('asn_max_ips', 'Max IPs', 'number', { def: 10 }), P('asn_max_prefixes', 'Max prefixes', 'number', { def: 200 })] },
  { key: 'osint_dns', label: 'DNS OSINT', group: 'Discovery', tool: null, desc: 'DNS records & metadata', params: [] },

  // ── Mapping ──
  { key: 'urls', label: 'URL collection', group: 'Mapping', tool: 'gau', altTool: 'katana', desc: 'Collect & crawl URLs', params: [P('crawl_max_hosts', 'Crawl max hosts', 'number', { def: 10 }), P('crawl_depth', 'Crawl depth', 'number', { def: 2 }), P('crawl_js', 'Crawl JS (katana -jc)', 'bool'), P('gau_threads', 'gau threads', 'number', { def: 5 })] },
  { key: 'content', label: 'Content discovery', group: 'Mapping', tool: 'ffuf', fallback: true, desc: 'Brute-force paths & files', params: [P('content_wordlist', 'Wordlist', 'file'), P('content_max_hosts', 'Max hosts', 'number', { def: 10 }), P('content_threads', 'Threads', 'number', { def: 40 }), P('content_match_codes', 'Match status codes', 'text', { def: '200,301,302,403' }), P('content_extensions', 'Extensions', 'text', { hint: 'e.g. .php,.bak,.json' })] },
  { key: 'params', label: 'Parameter discovery', group: 'Mapping', tool: 'arjun', fallback: true, desc: 'Discover request parameters', params: [P('params_max_hosts', 'Max hosts', 'number', { def: 10 }), P('params_threads', 'Threads', 'number', { def: 10 }), P('params_method', 'HTTP method', 'text', { hint: 'GET / POST — blank = both' })] },
  { key: 'jsrecon', label: 'JS analysis', group: 'Mapping', tool: null, desc: 'Endpoints & secrets from JS', params: [P('jsrecon_max_files', 'Max JS files', 'number', { def: 50 })] },
  { key: 'fingerprint', label: 'Fingerprint', group: 'Mapping', tool: 'wafw00f', fallback: true, desc: 'Tech & WAF detection', params: [] },
  { key: 'screenshots', label: 'Screenshots', group: 'Mapping', tool: 'gowitness', desc: 'Screenshot live hosts', params: [P('screenshot_max_hosts', 'Max hosts', 'number', { def: 25 }), P('screenshot_timeout', 'Timeout', 'number', { unit: 's', def: 15 }), P('screenshot_width', 'Width', 'number', { unit: 'px', def: 1280 }), P('screenshot_height', 'Height', 'number', { unit: 'px', def: 800 })] },

  // ── Checks (active testing) ──
  { key: 'vuln_signal', label: 'Vulnerability scan', group: 'Checks', tool: 'nuclei', intrusive: true, desc: 'Nuclei signal pass', params: [P('nuclei_severity', 'Severity', 'text', { def: 'critical,high,medium' }), P('nuclei_tags', 'Template tags', 'text', { hint: 'e.g. cve,exposure — blank = all' }), P('nuclei_concurrency', 'Concurrency', 'number', { hint: 'nuclei -c' }), P('nuclei_timeout', 'Timeout', 'number', { unit: 's', def: 15 }), P('rate_limit', 'Rate', 'number', { unit: 'req/s', inheritsGlobal: true })] },
  { key: 'xss_confirm', label: 'Reflected XSS', group: 'Checks', tool: 'dalfox', fallback: true, intrusive: true, desc: 'Confirm reflected XSS', params: [P('xss_max_urls', 'Max URLs', 'number', { def: 50 }), P('xss_workers', 'Workers', 'number', { hint: 'dalfox -w' }), P('xss_timeout', 'Timeout', 'number', { unit: 's', def: 10 }), P('xss_delay', 'Delay', 'number', { unit: 'ms', hint: 'between requests' })] },
  { key: 'sqli_confirm', label: 'SQL injection', group: 'Checks', tool: 'ghauri', fallback: true, intrusive: true, desc: 'Time-based SQLi', params: [P('sqli_max_urls', 'Max URLs', 'number', { def: 20 }), P('sqli_deep', 'Deep mode (ghauri)', 'bool')] },
  { key: 'ssti_confirm', label: 'SSTI', group: 'Checks', tool: null, intrusive: true, desc: 'Template injection', params: [P('ssti_max_urls', 'Max URLs', 'number', { def: 40 })] },
  { key: 'lfi_confirm', label: 'LFI', group: 'Checks', tool: null, intrusive: true, desc: 'Path traversal / file read', params: [P('lfi_max_urls', 'Max URLs', 'number', { def: 40 })] },
  { key: 'ssrf_confirm', label: 'SSRF', group: 'Checks', tool: null, intrusive: true, desc: 'Server-side request forgery', params: [P('ssrf_max_urls', 'Max URLs', 'number', { def: 40 }), P('oob_url', 'OOB server URL', 'text', { hint: 'for blind SSRF' }), P('oob_marker', 'OOB marker', 'text')] },
  { key: 'xxe_confirm', label: 'XXE', group: 'Checks', tool: null, intrusive: true, desc: 'XML external entity', params: [P('xxe_max_urls', 'Max endpoints', 'number', { def: 80 })] },
  { key: 'deser_confirm', label: 'Deserialization', group: 'Checks', tool: null, intrusive: true, desc: 'Insecure deserialization', params: [P('deser_max_urls', 'Max endpoints', 'number', { def: 80 })] },
  { key: 'jwt_confirm', label: 'JWT', group: 'Checks', tool: null, intrusive: true, desc: 'alg:none & weak secret', params: [] },
  { key: 'massassign_confirm', label: 'Mass assignment', group: 'Checks', tool: null, intrusive: true, desc: 'Privileged field injection', params: [P('massassign_max_urls', 'Max endpoints', 'number', { def: 60 })] },
  { key: 'nosqli_confirm', label: 'NoSQL injection', group: 'Checks', tool: null, intrusive: true, desc: 'Operator injection', params: [P('nosqli_max_urls', 'Max endpoints', 'number', { def: 60 })] },
  { key: 'cors_confirm', label: 'CORS', group: 'Checks', tool: null, intrusive: true, desc: 'Origin reflection', params: [P('cors_max_urls', 'Max endpoints', 'number', { def: 60 })] },
  { key: 'openredirect_confirm', label: 'Open redirect', group: 'Checks', tool: null, intrusive: true, desc: 'External redirect', params: [P('openredir_max_urls', 'Max URLs', 'number', { def: 50 })] },
  { key: 'protopollution_confirm', label: 'Prototype pollution', group: 'Checks', tool: null, intrusive: true, desc: '__proto__ injection', params: [P('protopp_max_urls', 'Max endpoints', 'number', { def: 60 })] },
  { key: 'graphql_confirm', label: 'GraphQL', group: 'Checks', tool: null, intrusive: true, desc: 'Introspection exposure', params: [] },
  { key: 'secret_verify', label: 'Secret verify', group: 'Checks', tool: 'trufflehog', intrusive: true, desc: 'Verify leaked secrets', params: [] },
];

module.exports = { MODULE_META };
