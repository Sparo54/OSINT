const { contextBridge, ipcRenderer } = require('electron')
contextBridge.exposeInMainWorld('api', {
  run: (n, a) => ipcRenderer.invoke('run', n, a),
  open: u => ipcRenderer.invoke('open', u),
  terminal: kind => ipcRenderer.invoke('terminal', kind)
})
