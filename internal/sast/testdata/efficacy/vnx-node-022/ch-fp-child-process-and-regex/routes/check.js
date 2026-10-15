const { execFile } = require('child_process');
const shell = require('shelljs');

const HOST_RE = /^[a-z0-9.-]+$/;

module.exports = (req, res) => {
  const m = HOST_RE.exec(req.query.host);
  if (!m) return res.status(400).end();
  execFile('ping', ['-c', '1', m[0]], (err, out) => res.send(out));
  shell.exec('uptime');
};
