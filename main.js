const { app, BrowserWindow } = require('electron');
const path = require('path');
const { startServer, stopServer } = require('./server/index');
const { registerIpcHandlers } = require('./electron/ipc-handlers');
const { isSetupComplete, getWebkillerHome } = require('./electron/paths');

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

let serverPort = null;

async function bootstrap() {
  getWebkillerHome();
  registerIpcHandlers();

  try {
    serverPort = await startServer();
    await createWindow(serverPort);
  } catch (err) {
    const { dialog } = require('electron');
    dialog.showErrorBox('Server Error', `Failed to start server:\n${err.message}`);
    app.quit();
  }
}

app.whenReady().then(bootstrap);

app.on('before-quit', () => stopServer());

app.on('window-all-closed', () => {
  stopServer();
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', async () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    if (serverPort) await createWindow(serverPort);
  }
});
