// Never call app.commandLine.appendSwitch('ignore-certificate-errors') in production.
const WARNING = "setPermissionRequestHandler((w, p, cb) => cb(true)) grants everything";
module.exports = { WARNING };
