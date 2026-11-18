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

module.exports = {
  getWebkillerHome,
  getToolsDir,
  getToolsBinDir,
  getToolsTmpDir,
  getDataDir,
  getSetupMarker,
  isSetupComplete,
  getPlatformKey,
  getAppRoot,
};
