'use strict';
const cp = require('child_process');

exports.thumbnail = function thumbnail(req, res) {
  const { file } = req.query;
~>  cp.exec(`convert ${file} -resize 64x64 thumb.png`, () => res.end());
};

exports.list = function list(req, res) {
  const dir = req.params.dir;
  const cmd = 'ls -la ' + dir;
~>  const listing = cp.execSync(cmd);
  res.send(listing);
};

exports.archive = function archive(req, res) {
  let name = req.body.name;
~>  cp.exec(
    'tar -czf /tmp/out.tgz ' + name,
    (err) => res.sendStatus(err ? 500 : 200),
  );
};
