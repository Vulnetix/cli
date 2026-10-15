import { app, session } from 'electron';

app.whenReady().then(() => {
~>  session.defaultSession.setPermissionCheckHandler(() => true);
~>  session.defaultSession.setCertificateVerifyProc((request, callback) => {
    callback(0);
  });
});
