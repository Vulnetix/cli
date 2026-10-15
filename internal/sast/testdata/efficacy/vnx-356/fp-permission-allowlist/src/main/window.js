const { app, session } = require('electron');

const ALLOWED = new Set(['notifications', 'clipboard-sanitized-write']);

app.whenReady().then(() => {
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
    const origin = new URL(webContents.getURL()).origin;
    callback(origin === 'https://app.example.com' && ALLOWED.has(permission));
  });
  session.defaultSession.setPermissionCheckHandler((wc, permission) => ALLOWED.has(permission));
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
    callback(false);
  });
});
