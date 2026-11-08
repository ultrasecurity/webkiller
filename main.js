const { app, BrowserWindow, dialog } = require('electron');
const path = require('path');
const { bootstrapVenv, startBackend, stopBackend } = require('./electron/backend');
const { registerIpcHandlers } = require('./electron/ipc-handlers');
const { isSetupComplete, getWebkillerHome } = require('./electron/paths');
const { checkPython } = require('./electron/python-check');

let mainWindow = null;

async function createWindow(port) {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0A0E0F',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    frame: process.platform !== 'darwin' ? true : undefined,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  const startHash = isSetupComplete() ? '/' : '/setup';
  mainWindow.loadURL(`http://127.0.0.1:${port}#${startHash}`);

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

async function bootstrap() {
  getWebkillerHome();
  registerIpcHandlers();

  const pythonCheck = await checkPython();
  if (!pythonCheck.found || !pythonCheck.meetsMinimum) {
    const msg = !pythonCheck.found
      ? 'Python 3.10+ is required but was not found on your system.'
      : `Python ${pythonCheck.version} found, but 3.10+ is required.`;

    const instructions = {
      darwin: 'Install: brew install python@3.12\nor download from python.org',
      linux: 'Install: sudo apt install python3.12 python3.12-venv',
      win32: 'Download from python.org\nMake sure to check "Add Python to PATH"',
    };

    dialog.showErrorBox(
      'Python Required',
      `${msg}\n\n${instructions[process.platform] || 'Install Python 3.10+ and restart.'}`
    );
    app.quit();
    return;
  }

  try {
    await bootstrapVenv();
  } catch (err) {
    dialog.showErrorBox('Setup Error', `Failed to create Python environment:\n${err.message}`);
    app.quit();
    return;
  }

  try {
    const port = await startBackend();
    await createWindow(port);
  } catch (err) {
    dialog.showErrorBox('Backend Error', `Failed to start backend:\n${err.message}`);
    app.quit();
  }
}

app.whenReady().then(bootstrap);

app.on('before-quit', () => stopBackend());

app.on('window-all-closed', () => {
  stopBackend();
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', async () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    const { getPort } = require('./electron/backend');
    const port = getPort();
    if (port) await createWindow(port);
  }
});
