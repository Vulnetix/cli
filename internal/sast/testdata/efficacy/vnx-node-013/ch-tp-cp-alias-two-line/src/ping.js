const cp = require('child_process');

exports.ping = (req, res) => {
  const cmd = 'ping -c 1 ' + req.body.host;
~>  cp.exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
};
