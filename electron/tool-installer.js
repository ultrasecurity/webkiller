const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { execFile, execSync, spawn } = require('child_process');
const { createWriteStream } = require('fs');
const { TOOLS_MANIFEST } = require('./tools-manifest');
const {
  getToolsBinDir,
  getToolsTmpDir,
  getPlatformKey,
} = require('./paths');

class ToolInstaller {
  constructor(onProgress) {
    this.onProgress = onProgress || (() => {});
  }

  async installAll() {
    const results = {};
    const platformKey = getPlatformKey();

    for (const [name, manifest] of Object.entries(TOOLS_MANIFEST)) {
      if (manifest.type === 'system') {
        results[name] = { installed: this._isOnPath(manifest.binaryName), type: 'system' };
        continue;
      }

      if (this._isInstalled(name, manifest)) {
        this.onProgress({ tool: name, status: 'already-installed', message: `${name} already installed` });
        results[name] = { installed: true, skipped: true };
        continue;
      }

      try {
        await this.installOne(name);
        results[name] = { installed: true };
      } catch (err) {
        this.onProgress({ tool: name, status: 'error', error: err.message });
        results[name] = { installed: false, error: err.message };
      }
    }
    return results;
  }

  async installOne(name) {
    const manifest = TOOLS_MANIFEST[name];
    if (!manifest) throw new Error(`Unknown tool: ${name}`);

    this.onProgress({ tool: name, status: 'starting', message: `Installing ${name}...` });

    switch (manifest.type) {
      case 'github-binary':
        await this._installGithubBinary(name, manifest);
        break;
      case 'optional-pip':
      case 'system':
        throw new Error(`${name} requires manual installation: ${manifest.installInstructions?.[process.platform] || 'see docs'}`);
      default:
        throw new Error(`Unknown install type: ${manifest.type}`);
    }

    this.onProgress({ tool: name, status: 'done', message: `${name} installed successfully` });
  }

  async _installGithubBinary(name, manifest) {
    const platformKey = getPlatformKey();
    const pattern = manifest.assetPattern[platformKey];
    if (!pattern) throw new Error(`No binary for platform: ${platformKey}`);

    this.onProgress({ tool: name, status: 'fetching-release', message: `Checking latest release...` });
    const release = await this._getLatestRelease(manifest.repo);
    const version = release.tag_name.replace(/^v/, '');

    const assetName = pattern.replace(/\{v\}/g, version);

    if (manifest.rawBinary) {
      const asset = this._findAsset(release.assets, assetName);
      if (!asset) throw new Error(`Asset not found: ${assetName}`);

      this.onProgress({ tool: name, status: 'downloading', message: `Downloading ${name}...` });
      const binDir = getToolsBinDir();
      const binName = process.platform === 'win32'
        ? `${manifest.binaryName}.exe`
        : manifest.binaryName;
      const destPath = path.join(binDir, binName);
      await this._download(asset.browser_download_url, destPath);
      if (process.platform !== 'win32') fs.chmodSync(destPath, 0o755);
      return;
    }

    const asset = this._findAsset(release.assets, assetName);
    if (!asset) throw new Error(`Asset not found: ${assetName} (available: ${release.assets.map(a => a.name).join(', ')})`);

    this.onProgress({ tool: name, status: 'downloading', message: `Downloading ${name}...` });
    const tmpDir = getToolsTmpDir();
    const archivePath = path.join(tmpDir, asset.name);
    await this._download(asset.browser_download_url, archivePath);

    this.onProgress({ tool: name, status: 'extracting', message: `Extracting ${name}...` });
    const binDir = getToolsBinDir();
    await this._extractBinary(archivePath, manifest.binaryName, binDir, manifest.archiveType);

    fs.rmSync(archivePath, { force: true });

    if (manifest.postInstall === 'gf-patterns') {
      await this._installGfPatterns();
    }
  }

  async _installGfPatterns() {
    const gfDir = path.join(require('os').homedir(), '.gf');
    if (fs.existsSync(gfDir) && fs.readdirSync(gfDir).length > 0) return;

    try {
      const tmpDir = getToolsTmpDir();
      const patternsZip = path.join(tmpDir, 'gf-examples.zip');
      await this._download(
        'https://github.com/tomnomnom/gf/archive/refs/heads/main.zip',
        patternsZip
      );
      fs.mkdirSync(gfDir, { recursive: true });

      const extractDir = path.join(tmpDir, 'gf-main');
      await this._extractArchive(patternsZip, extractDir, 'zip');
      const examplesDir = path.join(extractDir, 'gf-main', 'examples');
      if (fs.existsSync(examplesDir)) {
        for (const f of fs.readdirSync(examplesDir)) {
          fs.copyFileSync(path.join(examplesDir, f), path.join(gfDir, f));
        }
      }
      fs.rmSync(extractDir, { recursive: true, force: true });
      fs.rmSync(patternsZip, { force: true });
    } catch {
      // gf patterns are optional
    }
  }

  _findAsset(assets, name) {
    let found = assets.find((a) => a.name === name);
    if (found) return found;
    const lower = name.toLowerCase();
    found = assets.find((a) => a.name.toLowerCase() === lower);
    return found || null;
  }

  async _getLatestRelease(repo) {
    const url = `https://api.github.com/repos/${repo}/releases/latest`;
    return new Promise((resolve, reject) => {
      const req = https.get(url, {
        headers: {
          'User-Agent': 'WebKiller-Installer/3.0',
          Accept: 'application/vnd.github.v3+json',
        },
      }, (res) => {
        if (res.statusCode === 403) {
          reject(new Error('GitHub API rate limit exceeded. Try again later.'));
          return;
        }
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          https.get(res.headers.location, {
            headers: { 'User-Agent': 'WebKiller-Installer/3.0' },
          }, (res2) => {
            this._readJson(res2).then(resolve).catch(reject);
          });
          return;
        }
        this._readJson(res).then(resolve).catch(reject);
      });
      req.on('error', reject);
      req.setTimeout(15000, () => { req.destroy(); reject(new Error('Timeout')); });
    });
  }

  _readJson(res) {
    return new Promise((resolve, reject) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`Invalid JSON: ${data.slice(0, 200)}`)); }
      });
      res.on('error', reject);
    });
  }

  async _download(url, destPath) {
    return new Promise((resolve, reject) => {
      const get = url.startsWith('https') ? https.get : http.get;
      const req = get(url, { headers: { 'User-Agent': 'WebKiller-Installer/3.0' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          this._download(res.headers.location, destPath).then(resolve).catch(reject);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`Download failed: HTTP ${res.statusCode}`));
          return;
        }
        const ws = createWriteStream(destPath);
        res.pipe(ws);
        ws.on('finish', () => ws.close(resolve));
        ws.on('error', reject);
      });
      req.on('error', reject);
      req.setTimeout(120000, () => { req.destroy(); reject(new Error('Download timeout')); });
    });
  }

  async _extractBinary(archivePath, binaryName, destDir, archiveType) {
    const binSuffix = process.platform === 'win32' ? '.exe' : '';
    const targetBin = binaryName + binSuffix;
    const destPath = path.join(destDir, targetBin);

    if (archiveType === 'zip' || archivePath.endsWith('.zip')) {
      await this._extractFromZip(archivePath, targetBin, destPath);
    } else {
      await this._extractFromTarGz(archivePath, targetBin, destDir);
    }

    if (process.platform !== 'win32' && fs.existsSync(destPath)) {
      fs.chmodSync(destPath, 0o755);
    }
  }

  async _extractFromZip(archivePath, targetBin, destPath) {
    try {
      const yauzl = require('yauzl');
      return new Promise((resolve, reject) => {
        yauzl.open(archivePath, { lazyEntries: true }, (err, zipfile) => {
          if (err) { reject(err); return; }
          zipfile.readEntry();
          zipfile.on('entry', (entry) => {
            const base = path.basename(entry.fileName);
            if (base === targetBin || base === targetBin.replace('.exe', '')) {
              zipfile.openReadStream(entry, (err2, stream) => {
                if (err2) { reject(err2); return; }
                const ws = createWriteStream(destPath);
                stream.pipe(ws);
                ws.on('finish', () => { ws.close(); resolve(); });
              });
            } else {
              zipfile.readEntry();
            }
          });
          zipfile.on('end', () => {
            if (!fs.existsSync(destPath)) reject(new Error(`Binary ${targetBin} not found in zip`));
            else resolve();
          });
        });
      });
    } catch {
      await this._exec('unzip', ['-o', '-j', archivePath, '-d', path.dirname(destPath)]);
    }
  }

  async _extractFromTarGz(archivePath, targetBin, destDir) {
    if (process.platform === 'win32') {
      await this._exec('tar', ['-xzf', archivePath, '-C', destDir]);
    } else {
      await this._exec('tar', ['xzf', archivePath, '-C', destDir, '--strip-components=0']);
      const binPath = path.join(destDir, targetBin);
      if (!fs.existsSync(binPath)) {
        const files = fs.readdirSync(destDir);
        const match = files.find((f) => f === targetBin || f.startsWith(targetBin));
        if (!match) throw new Error(`Binary ${targetBin} not found after extraction`);
      }
    }
  }

  async _extractArchive(archivePath, destDir, type) {
    fs.mkdirSync(destDir, { recursive: true });
    if (type === 'zip') {
      await this._exec('unzip', ['-o', archivePath, '-d', destDir]);
    } else {
      await this._exec('tar', ['xzf', archivePath, '-C', destDir]);
    }
  }

  _isInstalled(name, manifest) {
    const binDir = getToolsBinDir();
    const binSuffix = process.platform === 'win32' ? '.exe' : '';
    const binPath = path.join(binDir, manifest.binaryName + binSuffix);
    if (fs.existsSync(binPath)) return true;

    return this._isOnPath(manifest.binaryName);
  }

  _isOnPath(name) {
    try {
      const cmd = process.platform === 'win32' ? 'where' : 'which';
      execSync(`${cmd} ${name}`, { stdio: 'pipe', timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  }

  _exec(cmd, args, opts = {}) {
    return new Promise((resolve, reject) => {
      execFile(cmd, args, { timeout: 300000, ...opts }, (err, stdout, stderr) => {
        if (err) reject(new Error(`${cmd} failed: ${stderr || err.message}`));
        else resolve(stdout);
      });
    });
  }
}

module.exports = { ToolInstaller };
