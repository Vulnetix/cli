const { app, session } = require('electron');

const ALLOWED = new Set(['notifications', 'clipboard-sanitized-write']);
const TRUSTED_ORIGIN = 'https://app.example.com';
const PINNED_FINGERPRINT = 'sha256/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg=';

app.whenReady().then(() => {
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
    const origin = new URL(webContents.getURL()).origin;
    callback(origin === TRUSTED_ORIGIN && ALLOWED.has(permission));
  });
});

app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  if (url.startsWith('https://intranet.example.com/') && certificate.fingerprint === PINNED_FINGERPRINT) {
    event.preventDefault();
    callback(true);
  } else {
    callback(false);
  }
});
