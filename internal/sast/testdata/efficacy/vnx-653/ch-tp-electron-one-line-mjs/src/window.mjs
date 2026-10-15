import { BrowserWindow } from "electron";

export function open(url) {
~>  const w = new BrowserWindow({ webPreferences: { nodeIntegrationInWorker: true, preload: PRELOAD } });
  w.loadURL(url);
  return w;
}
