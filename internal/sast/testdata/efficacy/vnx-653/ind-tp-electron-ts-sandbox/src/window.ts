import { BrowserWindow } from 'electron';

export function openPreview(url: string): BrowserWindow {
  const win = new BrowserWindow({
    webPreferences: {
      contextIsolation: true,
~>      sandbox: false,
~>      nodeIntegrationInWorker: true,
    },
  });
  win.loadURL(url);
  return win;
}
