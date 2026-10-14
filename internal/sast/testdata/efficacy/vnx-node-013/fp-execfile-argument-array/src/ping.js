const { execFile, spawn } = require('child_process');

function ping(req, res) {
  const host = req.query.host;
  execFile('ping', ['-c', '1', host], (err, stdout) => res.send(stdout));
}

function log(req, res) {
  const ref = req.body.ref;
  const git = spawn('git', ['log', '--oneline', ref]);
  git.stdout.pipe(res);
}

module.exports = { ping, log };
