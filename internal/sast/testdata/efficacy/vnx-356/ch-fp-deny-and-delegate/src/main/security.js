const { session, app } = require("electron");

const ALLOWED = new Set(["clipboard-sanitized-write"]);

session.defaultSession.setPermissionRequestHandler((wc, permission, callback) => {
  callback(ALLOWED.has(permission));
});

session.defaultSession.setPermissionCheckHandler(() => false);

session.defaultSession.setCertificateVerifyProc((request, callback) => {
  callback(-3);
});

app.on("certificate-error", (event, webContents, url, error, certificate, callback) => {
  callback(false);
});
