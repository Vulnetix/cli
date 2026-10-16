const { app, BrowserWindow } = require('electron');

if (!app.isPackaged) {
  app.commandLine.appendSwitch('ignore-certificate-errors');
}

app.whenReady().then(() => {
  const win = new BrowserWindow();
  win.loadURL(app.isPackaged ? 'https://app.example.com' : 'https://localhost:5173');
});
