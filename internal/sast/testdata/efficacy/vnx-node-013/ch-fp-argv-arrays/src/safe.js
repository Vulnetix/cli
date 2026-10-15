const { execFile, spawn } = require('child_process');

exports.ping = (req, res) => {
  execFile('ping', ['-c', '1', req.body.host], (err, out) => res.send(out));
  const g = spawn('git', ['log', '--format=%H', req.query.ref]);
  g.stdout.pipe(res);
};
