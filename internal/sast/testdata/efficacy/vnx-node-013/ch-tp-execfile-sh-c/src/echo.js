const { execFile } = require('child_process');

exports.echo = (req, res) => {
~>  execFile('/bin/sh', ['-c', 'echo ' + req.body.msg], (e, out) => res.send(out));
};
