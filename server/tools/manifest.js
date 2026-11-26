// ============================================================
// Tool manifest — the single source of truth for every external
// CLI tool WebKiller can use: how to identify/probe it, which
// versions our parsers were tested against, which platforms are
// supported, and how to install it.
//
// Plain CommonJS (the codebase is JS, not TS). Shapes below mirror
// the agreed contract:
//
//   ToolSpec {
//     id, displayName, homepage, license,
//     bin,                       // base executable name, no .exe
//     aliases?: string[],        // extra names to search on PATH
//     version: { tested, compatible, broken? },   // semver range strings
//     probe: { args, timeoutMs, stream:'stdout'|'stderr'|'both',
//              identity (regex, MUST match or it's the wrong binary),
//              version? (regex, group 1 = version),
//              versionSource: 'probe'|'install-record' },
//     defaultArgs?: string[],    // always appended at run time
//     platforms: { <platform>: { support:'supported'|'untested'|'unsupported', note? } },
//     install: ArchiveInstall | UvToolInstall | { kind:'manual', command },
//     data?: [{ id, url, sha256 }],   // pinned side-data (e.g. nuclei templates)
//   }
//
// Real download urls + sha256 + size live in the GENERATED
// tools.lock.json (built from each release's checksums.txt), never
// hand-written here. See genlock.js.
// ============================================================

const SCHEMA_VERSION = 1;

// The six platform keys we reason about: `${process.platform}-${process.arch}`.
const PLATFORMS = ['darwin-arm64', 'darwin-x64', 'linux-x64', 'linux-arm64', 'win32-x64', 'win32-arm64'];

// Helper: mark darwin-arm64 (this dev machine) supported, the rest untested,
// and let callers override per tool. Keeps the manifest terse.
function plat(overrides = {}) {
  const out = {};
  for (const p of PLATFORMS) {
    out[p] = overrides[p] || (p === 'darwin-arm64' ? { support: 'supported' } : { support: 'untested' });
  }
  return out;
}

// ProjectDiscovery tools share a release layout:
//   <tool>_<version>_<os>_<arch>.zip  (os: macOS|linux|windows, arch: arm64|amd64)
// asset() builds the per-platform archive descriptor the lock generator resolves.
function pdAsset(tool) {
  const map = {
    'darwin-arm64': ['macOS', 'arm64'], 'darwin-x64': ['macOS', 'amd64'],
    'linux-x64': ['linux', 'amd64'], 'linux-arm64': ['linux', 'arm64'],
    'win32-x64': ['windows', 'amd64'], 'win32-arm64': ['windows', 'arm64'],
  };
  const assets = {};
  for (const [p, [os, arch]] of Object.entries(map)) {
    // member name belongs to the ASSET's platform, not the build host's.
    assets[p] = { nameTemplate: `${tool}_{version}_${os}_${arch}.zip`, archive: 'zip', member: p.startsWith('win32') ? `${tool}.exe` : tool };
  }
  return assets;
}

/** @type {Record<string, any>} */
const TOOLS = {
  // ---------- ProjectDiscovery (Go) ----------
  subfinder: {
    id: 'subfinder', displayName: 'subfinder', homepage: 'https://github.com/projectdiscovery/subfinder', license: 'MIT',
    bin: 'subfinder', version: { tested: '2.6.6', compatible: '>=2.6.0 <3.0.0' },
    probe: { args: ['-version'], timeoutMs: 8000, stream: 'both', identity: 'projectdiscovery|subfinder|Current Version', version: '[vV]?(\\d+\\.\\d+\\.\\d+)', versionSource: 'probe' },
    defaultArgs: ['-disable-update-check'],
    platforms: plat({ 'win32-arm64': { support: 'unsupported' } }),
    install: { kind: 'archive', repo: 'projectdiscovery/subfinder', version: '2.6.6', assets: pdAsset('subfinder') },
  },
  httpx: {
    id: 'httpx', displayName: 'httpx (ProjectDiscovery)', homepage: 'https://github.com/projectdiscovery/httpx', license: 'MIT',
    // The name collides with the Python `httpx` HTTP-client CLI — identity regex
    // below must confirm it's the ProjectDiscovery binary, else it's wrong-binary.
    bin: 'httpx', aliases: ['httpx-toolkit'],
    version: { tested: '1.6.9', compatible: '>=1.6.0 <1.7.0' },
    probe: { args: ['-version'], timeoutMs: 8000, stream: 'both', identity: 'projectdiscovery|Current Version', version: '[vV]?(\\d+\\.\\d+\\.\\d+)', versionSource: 'probe' },
    defaultArgs: ['-disable-update-check'],
    platforms: plat({ 'win32-arm64': { support: 'unsupported' } }),
    install: { kind: 'archive', repo: 'projectdiscovery/httpx', version: '1.6.9', assets: pdAsset('httpx') },
  },
  dnsx: {
    id: 'dnsx', displayName: 'dnsx', homepage: 'https://github.com/projectdiscovery/dnsx', license: 'MIT',
    bin: 'dnsx', version: { tested: '1.2.1', compatible: '>=1.2.0 <2.0.0' },
    probe: { args: ['-version'], timeoutMs: 8000, stream: 'both', identity: 'projectdiscovery|Current Version', version: '[vV]?(\\d+\\.\\d+\\.\\d+)', versionSource: 'probe' },
    defaultArgs: ['-disable-update-check'],
    platforms: plat({ 'win32-arm64': { support: 'unsupported' } }),
    install: { kind: 'archive', repo: 'projectdiscovery/dnsx', version: '1.2.1', assets: pdAsset('dnsx') },
  },
  naabu: {
    id: 'naabu', displayName: 'naabu', homepage: 'https://github.com/projectdiscovery/naabu', license: 'MIT',
    // naabu links libpcap (CGO): the one real glibc-vs-musl / runtime-dep case.
    bin: 'naabu', version: { tested: '2.7.0', compatible: '>=2.3.0 <3.0.0' },
    probe: { args: ['-version'], timeoutMs: 8000, stream: 'both', identity: 'projectdiscovery|Current Version', version: '[vV]?(\\d+\\.\\d+\\.\\d+)', versionSource: 'probe' },
    defaultArgs: ['-disable-update-check'],
    platforms: plat({ 'win32-arm64': { support: 'unsupported' } }),
    install: { kind: 'archive', repo: 'projectdiscovery/naabu', version: '2.7.0', assets: pdAsset('naabu') },
  },

  // ---------- System tools (installed by the OS package manager, not auto-downloaded) ----------
  nmap: {
    id: 'nmap', displayName: 'nmap', homepage: 'https://nmap.org', license: 'NPSL (nmap)',
    bin: 'nmap', version: { tested: '7.95', compatible: '>=7.80.0 <9.0.0' },
    probe: { args: ['--version'], timeoutMs: 8000, stream: 'both', identity: 'Nmap version|nmap\\.org', version: 'Nmap version (\\d+\\.\\d+(?:\\.\\d+)?)', versionSource: 'probe' },
    platforms: plat({ 'darwin-x64': { support: 'supported' }, 'linux-x64': { support: 'supported' }, 'linux-arm64': { support: 'supported' }, 'win32-x64': { support: 'supported' } }),
    // nmap ships a C program plus data files (nmap-services, nmap-os-db) — not a
    // single static binary — so it is installed via the OS package manager, not
    // auto-downloaded like the Go tools. The UI shows this command when it's missing.
    install: { kind: 'manual', command: 'brew install nmap' },
  },
  nuclei: {
    id: 'nuclei', displayName: 'nuclei', homepage: 'https://github.com/projectdiscovery/nuclei', license: 'MIT',
    bin: 'nuclei', version: { tested: '3.11.1', compatible: '>=3.0.0 <4.0.0' },
    probe: { args: ['-version'], timeoutMs: 8000, stream: 'both', identity: 'Nuclei|projectdiscovery|Current Version', version: '[vV]?(\\d+\\.\\d+\\.\\d+)', versionSource: 'probe' },
    defaultArgs: ['-disable-update-check'],
    platforms: plat({ 'win32-arm64': { support: 'unsupported' } }),
    install: { kind: 'archive', repo: 'projectdiscovery/nuclei', version: '3.11.1', assets: pdAsset('nuclei') },
    // nuclei is useless without templates, which also drift — pin them.
    // Templates live in a separate repo and are fetched/updated by nuclei itself at first
    // run; lock-pinning them is a known TODO (genlock does not yet resolve the `data` field).
    data: [{ id: 'nuclei-templates', note: 'fetched by nuclei at runtime; lock-pinning is a TODO' }],
  },
  katana: {
    id: 'katana', displayName: 'katana', homepage: 'https://github.com/projectdiscovery/katana', license: 'MIT',
    // Headless mode pulls its own Chromium unless pointed at system Chrome.
    bin: 'katana', version: { tested: '1.8.0', compatible: '>=1.1.0 <2.0.0' },
    probe: { args: ['-version'], timeoutMs: 8000, stream: 'both', identity: 'projectdiscovery|Current Version', version: '[vV]?(\\d+\\.\\d+\\.\\d+)', versionSource: 'probe' },
    defaultArgs: ['-disable-update-check'],
    // katana 1.8.0 ships a windows-arm64 build → leave win-arm64 untested, not unsupported.
    platforms: plat(),
    install: { kind: 'archive', repo: 'projectdiscovery/katana', version: '1.8.0', assets: pdAsset('katana') },
  },

  // ---------- Other Go tools ----------
  ffuf: {
    id: 'ffuf', displayName: 'ffuf', homepage: 'https://github.com/ffuf/ffuf', license: 'MIT',
    bin: 'ffuf', version: { tested: '2.1.0', compatible: '>=2.0.0 <3.0.0' },
    probe: { args: ['-V'], timeoutMs: 8000, stream: 'both', identity: 'ffuf version', version: 'v?(\\d+\\.\\d+\\.\\d+)', versionSource: 'probe' },
    platforms: plat({ 'win32-arm64': { support: 'unsupported' } }),
    install: {
      kind: 'archive', repo: 'ffuf/ffuf', version: '2.1.0', assets: {
        'darwin-arm64': { nameTemplate: 'ffuf_{version}_macOS_arm64.tar.gz', archive: 'tar.gz', member: 'ffuf' },
        'darwin-x64': { nameTemplate: 'ffuf_{version}_macOS_amd64.tar.gz', archive: 'tar.gz', member: 'ffuf' },
        'linux-x64': { nameTemplate: 'ffuf_{version}_linux_amd64.tar.gz', archive: 'tar.gz', member: 'ffuf' },
        'linux-arm64': { nameTemplate: 'ffuf_{version}_linux_arm64.tar.gz', archive: 'tar.gz', member: 'ffuf' },
        'win32-x64': { nameTemplate: 'ffuf_{version}_windows_amd64.zip', archive: 'zip', member: 'ffuf.exe' },
      },
    },
  },
  dalfox: {
    id: 'dalfox', displayName: 'dalfox', homepage: 'https://github.com/hahwul/dalfox', license: 'MIT',
    bin: 'dalfox', version: { tested: '3.2.4', compatible: '>=2.9.0 <4.0.0' },
    probe: { args: ['version'], timeoutMs: 8000, stream: 'both', identity: 'dalfox|Dalfox', version: 'v?(\\d+\\.\\d+\\.\\d+)', versionSource: 'probe' },
    platforms: plat({ 'win32-arm64': { support: 'unsupported' } }),
    install: {
      kind: 'archive', repo: 'hahwul/dalfox', version: '2.9.2', assets: {
        'darwin-arm64': { nameTemplate: 'dalfox_{version}_darwin_arm64.tar.gz', archive: 'tar.gz', member: 'dalfox' },
        'darwin-x64': { nameTemplate: 'dalfox_{version}_darwin_amd64.tar.gz', archive: 'tar.gz', member: 'dalfox' },
        'linux-x64': { nameTemplate: 'dalfox_{version}_linux_amd64.tar.gz', archive: 'tar.gz', member: 'dalfox' },
        'linux-arm64': { nameTemplate: 'dalfox_{version}_linux_arm64.tar.gz', archive: 'tar.gz', member: 'dalfox' },
        'win32-x64': { nameTemplate: 'dalfox_{version}_windows_amd64.tar.gz', archive: 'tar.gz', member: 'dalfox.exe' },
      },
    },
  },
  gau: {
    id: 'gau', displayName: 'gau', homepage: 'https://github.com/lc/gau', license: 'MIT',
    bin: 'gau', version: { tested: '2.2.4', compatible: '>=2.2.0 <3.0.0' },
    // gau has no --version flag; record the installed version at install time.
    probe: { args: ['--help'], timeoutMs: 8000, stream: 'both', identity: 'gau|USAGE', versionSource: 'install-record' },
    platforms: plat({ 'win32-arm64': { support: 'unsupported' } }),
    install: {
      kind: 'archive', repo: 'lc/gau', version: '2.2.4', assets: {
        'darwin-arm64': { nameTemplate: 'gau_{version}_darwin_arm64.tar.gz', archive: 'tar.gz', member: 'gau' },
        'darwin-x64': { nameTemplate: 'gau_{version}_darwin_amd64.tar.gz', archive: 'tar.gz', member: 'gau' },
        'linux-x64': { nameTemplate: 'gau_{version}_linux_amd64.tar.gz', archive: 'tar.gz', member: 'gau' },
        'linux-arm64': { nameTemplate: 'gau_{version}_linux_arm64.tar.gz', archive: 'tar.gz', member: 'gau' },
        'win32-x64': { nameTemplate: 'gau_{version}_windows_amd64.zip', archive: 'zip', member: 'gau.exe' }, // gau ships .zip (not .tar.gz) on Windows
      },
    },
  },
  gowitness: {
    id: 'gowitness', displayName: 'gowitness', homepage: 'https://github.com/sensepost/gowitness', license: 'GPL-3.0',
    // Needs a Chrome/Chromium at run time (runtime dep, not solved by download).
    bin: 'gowitness', version: { tested: '3.2.2', compatible: '>=3.0.0 <4.0.0' },
    probe: { args: ['version'], timeoutMs: 8000, stream: 'both', identity: 'gowitness', version: 'v?(\\d+\\.\\d+\\.\\d+)', versionSource: 'probe' },
    // gowitness ships a windows-arm64 build (no checksums for ANY asset, though) → untested, not unsupported.
    platforms: plat(),
    install: {
      // gowitness ships raw (un-archived) binaries named per os/arch.
      kind: 'archive', repo: 'sensepost/gowitness', version: '3.2.2', assets: {
        'darwin-arm64': { nameTemplate: 'gowitness-{version}-darwin-arm64', archive: 'raw', member: 'gowitness' },
        'darwin-x64': { nameTemplate: 'gowitness-{version}-darwin-amd64', archive: 'raw', member: 'gowitness' },
        'linux-x64': { nameTemplate: 'gowitness-{version}-linux-amd64', archive: 'raw', member: 'gowitness' },
        'linux-arm64': { nameTemplate: 'gowitness-{version}-linux-arm64', archive: 'raw', member: 'gowitness' },
        'win32-x64': { nameTemplate: 'gowitness-{version}-windows-amd64.exe', archive: 'raw', member: 'gowitness.exe' },
        'win32-arm64': { nameTemplate: 'gowitness-{version}-windows-arm64.exe', archive: 'raw', member: 'gowitness.exe' },
      },
    },
  },
  trufflehog: {
    id: 'trufflehog', displayName: 'trufflehog', homepage: 'https://github.com/trufflesecurity/trufflehog', license: 'AGPL-3.0',
    bin: 'trufflehog', version: { tested: '3.82.0', compatible: '>=3.80.0 <4.0.0' },
    probe: { args: ['--version'], timeoutMs: 8000, stream: 'both', identity: 'trufflehog', version: 'v?(\\d+\\.\\d+\\.\\d+)', versionSource: 'probe' },
    platforms: plat({ 'win32-arm64': { support: 'unsupported' } }),
    install: {
      kind: 'archive', repo: 'trufflesecurity/trufflehog', version: '3.82.0', assets: {
        'darwin-arm64': { nameTemplate: 'trufflehog_{version}_darwin_arm64.tar.gz', archive: 'tar.gz', member: 'trufflehog' },
        'darwin-x64': { nameTemplate: 'trufflehog_{version}_darwin_amd64.tar.gz', archive: 'tar.gz', member: 'trufflehog' },
        'linux-x64': { nameTemplate: 'trufflehog_{version}_linux_amd64.tar.gz', archive: 'tar.gz', member: 'trufflehog' },
        'linux-arm64': { nameTemplate: 'trufflehog_{version}_linux_arm64.tar.gz', archive: 'tar.gz', member: 'trufflehog' },
        'win32-x64': { nameTemplate: 'trufflehog_{version}_windows_amd64.tar.gz', archive: 'tar.gz', member: 'trufflehog.exe' },
      },
    },
  },

  // ---------- Python tools (installed via a managed uv env) ----------
  arjun: {
    id: 'arjun', displayName: 'Arjun', homepage: 'https://github.com/s0md3v/Arjun', license: 'AGPL-3.0',
    bin: 'arjun', version: { tested: '2.2.7', compatible: '>=2.2.0 <2.3.0' },
    probe: { args: ['-h'], timeoutMs: 15000, stream: 'both', identity: 'usage: arjun|Arjun', versionSource: 'install-record' },
    platforms: plat({ 'darwin-x64': { support: 'untested' }, 'win32-arm64': { support: 'untested' } }),
    install: { kind: 'uv-tool', package: 'arjun', version: '2.2.7', python: '3.12', excludeNewer: '2026-11-01', entrypoint: 'arjun' },
  },
  wafw00f: {
    id: 'wafw00f', displayName: 'wafw00f', homepage: 'https://github.com/EnableSecurity/wafw00f', license: 'BSD-3-Clause',
    bin: 'wafw00f', version: { tested: '2.3.1', compatible: '>=2.2.0 <3.0.0' },
    probe: { args: ['-V'], timeoutMs: 15000, stream: 'both', identity: 'wafw00f|WAFW00F', version: 'v?(\\d+\\.\\d+\\.\\d+)', versionSource: 'probe' },
    platforms: plat({ 'win32-arm64': { support: 'untested' } }),
    install: { kind: 'uv-tool', package: 'wafw00f', version: '2.3.1', python: '3.12', excludeNewer: '2026-11-01', entrypoint: 'wafw00f' },
  },
  ghauri: {
    id: 'ghauri', displayName: 'Ghauri', homepage: 'https://github.com/r0oth3x49/ghauri', license: 'MIT',
    // Not reliably on PyPI — install from a pinned git ref via uv.
    bin: 'ghauri', version: { tested: '1.3.5', compatible: '>=1.3.0 <2.0.0' },
    probe: { args: ['--version'], timeoutMs: 15000, stream: 'both', identity: 'ghauri|Ghauri', version: 'v?(\\d+\\.\\d+\\.\\d+)', versionSource: 'probe' },
    platforms: plat({ 'win32-x64': { support: 'untested' }, 'win32-arm64': { support: 'untested' } }),
    install: { kind: 'uv-tool', package: 'git+https://github.com/r0oth3x49/ghauri.git', version: 'git', python: '3.12', entrypoint: 'ghauri' },
  },
};

// Capability status (ready / fallback / blocked) is computed per capability,
// NOT per tool — a capability can fall back to another tool or to a built-in
// implementation, and some capabilities only DEGRADE without a runtime dep.
/** @type {Record<string, any>} */
const CAPABILITIES = {
  subdomains_passive: { primary: 'subfinder', fallbacks: ['builtin'] }, // crt.sh built-in
  subdomains_active: { primary: 'dnsx' },
  probe: { primary: 'httpx', fallbacks: ['builtin'] },
  portscan: {
    primary: 'naabu',
    requires: [{ dep: 'root', platforms: ['darwin-arm64', 'darwin-x64', 'linux-x64', 'linux-arm64'], severity: 'degrades', degradedMode: 'connect-scan (no SYN) without root' },
      { dep: 'npcap', platforms: ['win32-x64'], severity: 'degrades', degradedMode: 'connect-scan without Npcap' },
      { dep: 'libpcap', platforms: ['linux-x64', 'linux-arm64'], severity: 'degrades' }],
  },
  service_cve: {
    primary: 'nmap',
    requires: [{ dep: 'root', platforms: ['darwin-arm64', 'darwin-x64', 'linux-x64', 'linux-arm64'], severity: 'degrades', degradedMode: 'version-only (no OS detection) without root' },
      { dep: 'npcap', platforms: ['win32-x64'], severity: 'degrades', degradedMode: 'version-only without Npcap' }],
  },
  urls: { primary: 'gau', fallbacks: ['katana', 'builtin'] },
  content: { primary: 'ffuf', fallbacks: ['builtin'] },
  params: { primary: 'arjun', fallbacks: ['builtin'] },
  fingerprint: { primary: 'wafw00f', fallbacks: ['builtin'] },
  screenshots: { primary: 'gowitness', requires: [{ dep: 'chrome', severity: 'hard' }] },
  vuln_signal: { primary: 'nuclei' },
  xss_confirm: { primary: 'dalfox', fallbacks: ['builtin'] },
  sqli_confirm: { primary: 'ghauri', fallbacks: ['builtin'] },
  secret_verify: { primary: 'trufflehog' },
};

module.exports = { SCHEMA_VERSION, PLATFORMS, TOOLS, CAPABILITIES };
