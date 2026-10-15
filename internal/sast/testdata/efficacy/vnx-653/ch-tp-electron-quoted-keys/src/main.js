const { app, BrowserWindow } = require('electron');

function createWindow() {
  const win = new BrowserWindow({
    width: 1024,
    webPreferences: {
~>      'nodeIntegration': true,
~>      "contextIsolation": false,
    },
  });
  win.loadURL(process.env.START_URL);
}

app.whenReady().then(createWindow);
