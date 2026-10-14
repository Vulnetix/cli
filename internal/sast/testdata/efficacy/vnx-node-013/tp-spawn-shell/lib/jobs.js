const { spawn, spawnSync } = require('child_process');
const shell = require('shelljs');

function extract(req, res) {
~>  const child = spawn(`tar -xf ${req.body.archive}`, { shell: true });
  child.on('close', () => res.end());
}

function echo(req, res) {
~>  const r = spawnSync('sh', ['-c', 'echo ' + req.query.msg]);
  res.send(r.stdout);
}

function grep(req, res) {
~>  const r = shell.exec(`grep -r "${req.query.term}" ./data`, { silent: true });
  res.send(r.stdout);
}

module.exports = { extract, echo, grep };
