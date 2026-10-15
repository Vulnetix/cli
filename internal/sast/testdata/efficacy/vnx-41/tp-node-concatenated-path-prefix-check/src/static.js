const fs = require('fs');

const PUBLIC_DIR = __dirname + '/public/';

function serve(req, res) {
  const filePath = PUBLIC_DIR + req.params.name;
~>  if (!filePath.startsWith(PUBLIC_DIR)) {
    return res.sendStatus(403);
  }
  fs.createReadStream(filePath).pipe(res);
}

function avatar(req, res) {
  const avatarPath = `${PUBLIC_DIR}avatars/${req.query.user}.png`;
~>  if (avatarPath.startsWith(PUBLIC_DIR)) {
    res.sendFile(avatarPath);
  }
}

module.exports = { serve, avatar };
