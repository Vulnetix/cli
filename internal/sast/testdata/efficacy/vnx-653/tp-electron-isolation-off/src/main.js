const { app, BrowserWindow } = require('electron')

function createWindow () {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
~>      nodeIntegration: true,
~>      contextIsolation: false,
~>      sandbox: false
    }
  })
  win.loadURL(process.env.APP_URL)
}

app.whenReady().then(createWindow)
