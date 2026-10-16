const { app, BrowserWindow, session } = require('electron');

~>app.commandLine.appendSwitch('ignore-certificate-errors');
app.commandLine.appendSwitch('enable-features', 'SharedArrayBuffer');

app.whenReady().then(() => {
  const ses = session.fromPartition('persist:main');
~>  ses.setPermissionCheckHandler(() => true);
  const win = new BrowserWindow({ webPreferences: { session: ses } });
  win.loadFile('index.html');
});
