const shell = require('shelljs');

function cleanup(req) {
  const dir = req.body.dir;
  shell.rm('-rf', `/srv/tmp/${req.user.id}`);
  shell.mkdir('-p', dir);
  return shell.which('git') ? 'ok' : 'missing';
}

// shell.exec('rm -rf ' + req.body.dir)
const docs = "never call shell.exec(req.body.cmd)";

module.exports = { cleanup, docs };
