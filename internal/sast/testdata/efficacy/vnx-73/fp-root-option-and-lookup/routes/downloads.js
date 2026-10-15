const fs = require('fs');
const FILES_DIR = __dirname + '/files';

function download(req, res, next) {
  res.download(req.params.file, { root: FILES_DIR }, (err) => err && next(err));
}

function avatar(req, res) {
  const user = sessions.get(req.cookies.token);
  const stream = fs.createWriteStream(`avatars/${user.id}.png`);
  console.log('wrote', fs.existsSync(req.query.p));
  stream.end();
}
module.exports = { download, avatar };
