const shell = require('shelljs');
// shell.exec('ping ' + req.query.host) is dangerous
const s = "shell.exec(req.body.cmd)";
shell.exec('uptime');
module.exports = s;
