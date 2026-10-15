import { app, BrowserWindow, WebPreferences } from 'electron';

interface Options {
  nodeIntegration?: boolean;
}

export function check(prefs: WebPreferences): void {
  if (prefs.sandbox === false) {
    console.warn('refusing window with sandbox: false or nodeIntegration: true');
    throw new Error('insecure');
  }
  /*
   * Never ship contextIsolation: false
   */
  const safe = { contextIsolation: true, nodeIntegration: false, sandbox: true };
  new BrowserWindow({ webPreferences: safe });
}
