const TOOLS_MANIFEST = {
  // --- Go tools: download pre-built binaries from GitHub releases ---

  subfinder: {
    type: 'github-binary',
    repo: 'projectdiscovery/subfinder',
    binaryName: 'subfinder',
    archiveType: 'zip',
    assetPattern: {
      darwin_arm64: 'subfinder_{v}_macOS_arm64.zip',
      darwin_amd64: 'subfinder_{v}_macOS_amd64.zip',
      linux_arm64: 'subfinder_{v}_linux_arm64.zip',
      linux_amd64: 'subfinder_{v}_linux_amd64.zip',
      win32_amd64: 'subfinder_{v}_windows_amd64.zip',
    },
  },
  httpx: {
    type: 'github-binary',
    repo: 'projectdiscovery/httpx',
    binaryName: 'httpx',
    archiveType: 'zip',
    assetPattern: {
      darwin_arm64: 'httpx_{v}_macOS_arm64.zip',
      darwin_amd64: 'httpx_{v}_macOS_amd64.zip',
      linux_arm64: 'httpx_{v}_linux_arm64.zip',
      linux_amd64: 'httpx_{v}_linux_amd64.zip',
      win32_amd64: 'httpx_{v}_windows_amd64.zip',
    },
  },
  dnsx: {
    type: 'github-binary',
    repo: 'projectdiscovery/dnsx',
    binaryName: 'dnsx',
    archiveType: 'zip',
    assetPattern: {
      darwin_arm64: 'dnsx_{v}_macOS_arm64.zip',
      darwin_amd64: 'dnsx_{v}_macOS_amd64.zip',
      linux_arm64: 'dnsx_{v}_linux_arm64.zip',
      linux_amd64: 'dnsx_{v}_linux_amd64.zip',
      win32_amd64: 'dnsx_{v}_windows_amd64.zip',
    },
  },
  naabu: {
    type: 'github-binary',
    repo: 'projectdiscovery/naabu',
    binaryName: 'naabu',
    archiveType: 'zip',
    assetPattern: {
      darwin_arm64: 'naabu_{v}_macOS_arm64.zip',
      darwin_amd64: 'naabu_{v}_macOS_amd64.zip',
      linux_arm64: 'naabu_{v}_linux_arm64.zip',
      linux_amd64: 'naabu_{v}_linux_amd64.zip',
      win32_amd64: 'naabu_{v}_windows_amd64.zip',
    },
  },
  nuclei: {
    type: 'github-binary',
    repo: 'projectdiscovery/nuclei',
    binaryName: 'nuclei',
    archiveType: 'zip',
    assetPattern: {
      darwin_arm64: 'nuclei_{v}_macOS_arm64.zip',
      darwin_amd64: 'nuclei_{v}_macOS_amd64.zip',
      linux_arm64: 'nuclei_{v}_linux_arm64.zip',
      linux_amd64: 'nuclei_{v}_linux_amd64.zip',
      win32_amd64: 'nuclei_{v}_windows_amd64.zip',
    },
  },
  katana: {
    type: 'github-binary',
    repo: 'projectdiscovery/katana',
    binaryName: 'katana',
    archiveType: 'zip',
    assetPattern: {
      darwin_arm64: 'katana_{v}_macOS_arm64.zip',
      darwin_amd64: 'katana_{v}_macOS_amd64.zip',
      linux_arm64: 'katana_{v}_linux_arm64.zip',
      linux_amd64: 'katana_{v}_linux_amd64.zip',
      win32_amd64: 'katana_{v}_windows_amd64.zip',
    },
  },
  'interactsh-client': {
    type: 'github-binary',
    repo: 'projectdiscovery/interactsh',
    binaryName: 'interactsh-client',
    archiveType: 'zip',
    assetPattern: {
      darwin_arm64: 'interactsh-client_{v}_macOS_arm64.zip',
      darwin_amd64: 'interactsh-client_{v}_macOS_amd64.zip',
      linux_arm64: 'interactsh-client_{v}_linux_arm64.zip',
      linux_amd64: 'interactsh-client_{v}_linux_amd64.zip',
      win32_amd64: 'interactsh-client_{v}_windows_amd64.zip',
    },
  },
  gau: {
    type: 'github-binary',
    repo: 'lc/gau',
    binaryName: 'gau',
    archiveType: 'tar.gz',
    assetPattern: {
      darwin_arm64: 'gau_{v}_darwin_arm64.tar.gz',
      darwin_amd64: 'gau_{v}_darwin_amd64.tar.gz',
      linux_arm64: 'gau_{v}_linux_arm64.tar.gz',
      linux_amd64: 'gau_{v}_linux_amd64.tar.gz',
      win32_amd64: 'gau_{v}_windows_amd64.tar.gz',
    },
  },
  ffuf: {
    type: 'github-binary',
    repo: 'ffuf/ffuf',
    binaryName: 'ffuf',
    archiveType: 'tar.gz',
    assetPattern: {
      darwin_arm64: 'ffuf_{v}_macOS_arm64.tar.gz',
      darwin_amd64: 'ffuf_{v}_macOS_amd64.tar.gz',
      linux_arm64: 'ffuf_{v}_linux_arm64.tar.gz',
      linux_amd64: 'ffuf_{v}_linux_amd64.tar.gz',
      win32_amd64: 'ffuf_{v}_windows_amd64.zip',
    },
  },
  dalfox: {
    type: 'github-binary',
    repo: 'hahwul/dalfox',
    binaryName: 'dalfox',
    archiveType: 'tar.gz',
    assetPattern: {
      darwin_arm64: 'dalfox_{v}_macOS_arm64.tar.gz',
      darwin_amd64: 'dalfox_{v}_macOS_amd64.tar.gz',
      linux_arm64: 'dalfox_{v}_linux_arm64.tar.gz',
      linux_amd64: 'dalfox_{v}_linux_amd64.tar.gz',
      win32_amd64: 'dalfox_{v}_windows_amd64.tar.gz',
    },
  },
  puredns: {
    type: 'github-binary',
    repo: 'd3mondev/puredns',
    binaryName: 'puredns',
    archiveType: 'zip',
    assetPattern: {
      darwin_arm64: 'puredns-Darwin-arm64.zip',
      darwin_amd64: 'puredns-Darwin-amd64.zip',
      linux_arm64: 'puredns-Linux-arm64.zip',
      linux_amd64: 'puredns-Linux-amd64.zip',
      win32_amd64: 'puredns-Windows-amd64.zip',
    },
    versionless: true,
  },
  gotator: {
    type: 'github-binary',
    repo: 'Josue87/gotator',
    binaryName: 'gotator',
    archiveType: 'tar.gz',
    assetPattern: {
      darwin_arm64: 'gotator_{v}_darwin_arm64.tar.gz',
      darwin_amd64: 'gotator_{v}_darwin_amd64.tar.gz',
      linux_arm64: 'gotator_{v}_linux_arm64.tar.gz',
      linux_amd64: 'gotator_{v}_linux_amd64.tar.gz',
      win32_amd64: 'gotator_{v}_windows_amd64.tar.gz',
    },
  },
  gf: {
    type: 'github-binary',
    repo: 'tomnomnom/gf',
    binaryName: 'gf',
    archiveType: 'tar.gz',
    assetPattern: {
      darwin_arm64: 'gf-darwin-arm64-{v}.tgz',
      darwin_amd64: 'gf-darwin-amd64-{v}.tgz',
      linux_arm64: 'gf-linux-arm64-{v}.tgz',
      linux_amd64: 'gf-linux-amd64-{v}.tgz',
      win32_amd64: 'gf-windows-amd64-{v}.tgz',
    },
    postInstall: 'gf-patterns',
  },
  gowitness: {
    type: 'github-binary',
    repo: 'sensepost/gowitness',
    binaryName: 'gowitness',
    archiveType: 'zip',
    assetPattern: {
      darwin_arm64: 'gowitness-{v}-macOS-arm64',
      darwin_amd64: 'gowitness-{v}-macOS-amd64',
      linux_arm64: 'gowitness-{v}-linux-arm64',
      linux_amd64: 'gowitness-{v}-linux-amd64',
      win32_amd64: 'gowitness-{v}-windows-amd64.exe',
    },
    rawBinary: true,
  },
  trufflehog: {
    type: 'github-binary',
    repo: 'trufflesecurity/trufflehog',
    binaryName: 'trufflehog',
    archiveType: 'tar.gz',
    assetPattern: {
      darwin_arm64: 'trufflehog_{v}_darwin_arm64.tar.gz',
      darwin_amd64: 'trufflehog_{v}_darwin_amd64.tar.gz',
      linux_arm64: 'trufflehog_{v}_linux_arm64.tar.gz',
      linux_amd64: 'trufflehog_{v}_linux_amd64.tar.gz',
      win32_amd64: 'trufflehog_{v}_windows_amd64.tar.gz',
    },
  },

  // --- Python tools: optional, user installs manually via pip ---

  arjun: {
    type: 'optional-pip',
    binaryName: 'arjun',
    installInstructions: {
      darwin: 'pip3 install arjun',
      linux: 'pip3 install arjun',
      win32: 'pip install arjun',
    },
  },
  wafw00f: {
    type: 'optional-pip',
    binaryName: 'wafw00f',
    installInstructions: {
      darwin: 'pip3 install wafw00f',
      linux: 'pip3 install wafw00f',
      win32: 'pip install wafw00f',
    },
  },
  ghauri: {
    type: 'optional-pip',
    binaryName: 'ghauri',
    installInstructions: {
      darwin: 'pip3 install ghauri',
      linux: 'pip3 install ghauri',
      win32: 'pip install ghauri',
    },
  },

  // --- System tools: manual install required ---

  nmap: {
    type: 'system',
    binaryName: 'nmap',
    installInstructions: {
      darwin: 'brew install nmap',
      linux: 'sudo apt-get install nmap',
      win32: 'Download from https://nmap.org/download.html\nor: choco install nmap',
    },
  },
};

module.exports = { TOOLS_MANIFEST };
