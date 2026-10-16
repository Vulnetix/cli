const { app, BrowserWindow } = require('electron');

app.whenReady().then(() => {
  const win = new BrowserWindow({ show: false });
~>  win.webContents.session.setCertificateVerifyProc((request, callback) => {
    callback(0);
  });
  win.loadURL('https://reports.example.com');
  win.once('ready-to-show', () => win.show());
});
