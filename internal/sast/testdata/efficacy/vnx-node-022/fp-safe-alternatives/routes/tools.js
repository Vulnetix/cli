const { execFile } = require('child_process');
const shell = require('shelljs');

function ping(req, res) {
  const host = req.query.host;
  if (!/^[a-z0-9.-]+$/i.test(host)) {
    return res.status(400).end();
  }
  execFile('ping', ['-c', '1', host], (err, stdout) => res.send(stdout));
}

function list(req, res) {
  // shell.ls takes paths, not a command line.
  res.json(shell.ls(req.query.dir || '.'));
}

const pattern = /token=(\w+)/;
function parse(req) {
  return pattern.exec(req.headers.cookie);
}

module.exports = { ping, list, parse };
