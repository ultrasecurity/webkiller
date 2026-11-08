const path = require('path');
const os = require('os');
const fs = require('fs');

const WEBKILLER_HOME = path.join(os.homedir(), '.webkiller');

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function getWebkillerHome() {
  return ensureDir(WEBKILLER_HOME);
}

function getToolsDir() {
  return ensureDir(path.join(WEBKILLER_HOME, 'tools'));
}

function getToolsBinDir() {
  return ensureDir(path.join(WEBKILLER_HOME, 'tools', 'bin'));
}

function getToolsTmpDir() {
  return ensureDir(path.join(WEBKILLER_HOME, 'tools', 'tmp'));
}

function getVenvDir() {
  return path.join(WEBKILLER_HOME, 'venv');
}

function getVenvBinDir() {
  const venv = getVenvDir();
  return process.platform === 'win32'
    ? path.join(venv, 'Scripts')
    : path.join(venv, 'bin');
}

function getDataDir() {
  return ensureDir(path.join(WEBKILLER_HOME, 'output'));
}

function getSetupMarker() {
  return path.join(WEBKILLER_HOME, 'setup-complete');
}

function isSetupComplete() {
  return fs.existsSync(getSetupMarker());
}

function getPlatformKey() {
  const platform = process.platform;
  const arch = process.arch === 'arm64' ? 'arm64' : 'amd64';
  return `${platform}_${arch}`;
}

function getAppRoot() {
  const { app } = require('electron');
  if (app.isPackaged) {
    return path.join(process.resourcesPath, 'app.asar.unpacked');
  }
  return path.join(__dirname, '..');
}

function getPythonPath() {
  const venvPython = process.platform === 'win32'
    ? path.join(getVenvDir(), 'Scripts', 'python.exe')
    : path.join(getVenvDir(), 'bin', 'python3');
  if (fs.existsSync(venvPython)) return venvPython;

  const { execSync } = require('child_process');
  const candidates = process.platform === 'win32'
    ? ['python3', 'python', 'py']
    : ['python3', 'python'];
  for (const cmd of candidates) {
    try {
      const p = execSync(
        process.platform === 'win32' ? `where ${cmd}` : `which ${cmd}`,
        { stdio: 'pipe', timeout: 5000 }
      ).toString().trim().split('\n')[0];
      if (p) return p;
    } catch {}
  }
  return null;
}

module.exports = {
  getWebkillerHome,
  getToolsDir,
  getToolsBinDir,
  getToolsTmpDir,
  getVenvDir,
  getVenvBinDir,
  getDataDir,
  getSetupMarker,
  isSetupComplete,
  getPlatformKey,
  getAppRoot,
  getPythonPath,
};
