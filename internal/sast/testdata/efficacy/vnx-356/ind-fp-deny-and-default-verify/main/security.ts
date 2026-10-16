import { app, session } from 'electron';

app.whenReady().then(() => {
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
    callback(false);
  });
  session.defaultSession.setCertificateVerifyProc((request, callback) => {
    callback(-3);
  });
  session.defaultSession.setPermissionCheckHandler(() => false);
});

app.on('certificate-error', (event, _wc, _url, _err, _cert, callback) => {
  callback(false);
});
