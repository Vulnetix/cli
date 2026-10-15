const { app } = require('electron');

app.commandLine.appendSwitch('disable-gpu');
const help = "pass --ignore-certificate-errors only when debugging";
if (process.env.NODE_ENV === 'development') {
  app.commandLine.appendSwitch('remote-debugging-port', '9222');
}
