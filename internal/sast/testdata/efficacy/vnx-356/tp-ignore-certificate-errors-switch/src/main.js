const { app, BrowserWindow } = require('electron');

~>app.commandLine.appendSwitch('ignore-certificate-errors');
~>app.commandLine.appendSwitch("ignore-certificate-errors", "true");

app.whenReady().then(() => {
  const win = new BrowserWindow({ width: 800, height: 600 });
~>  win.webContents.on('certificate-error', (event, url, error, cert, callback) => {
    event.preventDefault();
    callback(true);
  });
  win.loadURL('https://internal.example.com');
});
