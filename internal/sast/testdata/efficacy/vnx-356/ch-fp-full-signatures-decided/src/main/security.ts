import { app, session } from "electron";

const GRANTED = new Set(["clipboard-sanitized-write", "fullscreen"]);
const PINNED = "sha256/@@sample:3[m]H9[b]2o[Q]q9[k]P3[n]6Z[t]1y[4]w5[x]8u[7]v0[a]1b[2]c3[d]4e[5]f6[g]7h@@=";

export function installHandlers(): void {
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback, details) => {
    callback(GRANTED.has(permission) && details.isMainFrame);
  });

  app.on("certificate-error", (event, webContents, url, error, certificate, callback, isMainFrame) => {
    callback(false);
  });

  session.defaultSession.setCertificateVerifyProc((request, callback) => {
    callback(request.certificate.fingerprint === PINNED ? 0 : -3);
  });
}
