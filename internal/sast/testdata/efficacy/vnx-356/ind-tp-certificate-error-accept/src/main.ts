import { app, BrowserWindow } from 'electron';

let mainWindow: BrowserWindow | null = null;

~>app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  event.preventDefault();
  callback(true);
});

app.whenReady().then(() => {
  mainWindow = new BrowserWindow({ width: 1024, height: 768 });
  mainWindow.loadURL('https://portal.internal.example.com');
});
