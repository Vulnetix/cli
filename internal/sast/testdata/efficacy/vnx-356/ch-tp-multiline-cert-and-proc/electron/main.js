const { app, BrowserWindow } = require("electron");

~>app.on("certificate-error", function (event, webContents, url, error, certificate, callback) {
  event.preventDefault();
  callback(true);
});

app.whenReady().then(() => {
  const win = new BrowserWindow({ width: 1200, height: 800 });
~>  win.webContents.session.setCertificateVerifyProc((request, done) => {
    done(0);
  });
~>  win.webContents.session.setPermissionCheckHandler(function () {
    return true;
  });
  win.loadURL("https://app.example.com");
});
