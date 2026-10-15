import { app, session, BrowserWindow } from "electron";

export function installHandlers(win: BrowserWindow): void {
~>  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback, details) => {
    console.info("permission", permission, details.requestingUrl);
    callback(true);
  });

~>  app.on(
    "certificate-error",
    (event, webContents, url, error, certificate, callback, isMainFrame) => {
      event.preventDefault();
      callback(true);
    }
  );

~>  win.webContents.session.setCertificateVerifyProc((request, callback) => callback(0));
}
