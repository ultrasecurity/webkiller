const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  isElectron: true,

  getToolsStatus: () => ipcRenderer.invoke('setup:tools-status'),
  installTool: (toolName) => ipcRenderer.invoke('setup:install-tool', toolName),
  installAllTools: () => ipcRenderer.invoke('setup:install-all'),
  skipSetup: () => ipcRenderer.invoke('setup:skip'),
  completeSetup: () => ipcRenderer.invoke('setup:complete'),

  onInstallProgress: (callback) => {
    ipcRenderer.on('setup:progress', (_, data) => callback(data));
  },
  removeInstallProgress: () => {
    ipcRenderer.removeAllListeners('setup:progress');
  },

  getPlatformInfo: () => ipcRenderer.invoke('app:platform-info'),
  getVersion: () => ipcRenderer.invoke('app:version'),
});
