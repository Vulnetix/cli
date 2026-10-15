const { app, BrowserWindow, session } = require('electron');

app.whenReady().then(() => {
~>  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
    callback(true);
  });

  const win = new BrowserWindow({ width: 1200, height: 800 });
~>  win.webContents.session.setPermissionRequestHandler(function (wc, perm, done) { done(true); });
  win.loadURL('https://app.example.com');
});
