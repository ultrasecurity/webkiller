const { ipcMain } = require('electron');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { checkPython } = require('./python-check');
const { ToolInstaller } = require('./tool-installer');
const { TOOLS_MANIFEST } = require('./tools-manifest');
const {
  isSetupComplete,
  getSetupMarker,
  getToolsBinDir,
  getVenvBinDir,
  getPlatformKey,
  getWebkillerHome,
} = require('./paths');

function registerIpcHandlers() {
  ipcMain.handle('setup:check-python', async () => {
    return await checkPython();
  });

  ipcMain.handle('setup:tools-status', async () => {
    const binDir = getToolsBinDir();
    const venvBin = getVenvBinDir();
    const binSuffix = process.platform === 'win32' ? '.exe' : '';
    const results = {};

    for (const [name, manifest] of Object.entries(TOOLS_MANIFEST)) {
      const binName = manifest.binaryName + binSuffix;
      const inToolsBin = fs.existsSync(path.join(binDir, binName));
      const inVenvBin = fs.existsSync(path.join(venvBin, binName));

      let onSystem = false;
      try {
        const cmd = process.platform === 'win32' ? 'where' : 'which';
        execSync(`${cmd} ${manifest.binaryName}`, { stdio: 'pipe', timeout: 3000 });
        onSystem = true;
      } catch {}

      results[name] = {
        installed: inToolsBin || inVenvBin || onSystem,
        location: inToolsBin ? 'tools-bin' : inVenvBin ? 'venv' : onSystem ? 'system' : 'missing',
        type: manifest.type,
        installInstructions: manifest.installInstructions || null,
      };
    }
    return results;
  });

  ipcMain.handle('setup:install-tool', async (event, toolName) => {
    const installer = new ToolInstaller((progress) => {
      event.sender.send('setup:progress', progress);
    });
    try {
      await installer.installOne(toolName);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle('setup:install-all', async (event) => {
    const installer = new ToolInstaller((progress) => {
      event.sender.send('setup:progress', progress);
    });
    const results = await installer.installAll();
    return results;
  });

  ipcMain.handle('setup:skip', async () => {
    const marker = getSetupMarker();
    fs.mkdirSync(path.dirname(marker), { recursive: true });
    fs.writeFileSync(marker, JSON.stringify({ skipped: true, date: new Date().toISOString() }));
    return { ok: true };
  });

  ipcMain.handle('setup:complete', async () => {
    const marker = getSetupMarker();
    fs.mkdirSync(path.dirname(marker), { recursive: true });
    fs.writeFileSync(marker, JSON.stringify({ complete: true, date: new Date().toISOString() }));
    return { ok: true };
  });

  ipcMain.handle('app:platform-info', () => ({
    platform: process.platform,
    arch: process.arch,
    platformKey: getPlatformKey(),
  }));

  ipcMain.handle('app:version', () => {
    const { app } = require('electron');
    return app.getVersion();
  });
}

module.exports = { registerIpcHandlers };
