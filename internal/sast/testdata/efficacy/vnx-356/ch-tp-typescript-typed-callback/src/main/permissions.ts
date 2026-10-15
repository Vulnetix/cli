import { session, WebContents } from "electron";

export function installHandlers(): void {
~>  session.defaultSession.setPermissionRequestHandler(
    (webContents: WebContents, permission: string, callback: (granted: boolean) => void) => {
      callback(true);
    },
  );
}
