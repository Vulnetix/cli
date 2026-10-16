const fs = require('fs');
const path = require('path');
const UPLOAD_DIR = '/srv/uploads';

function serve(req, res) {
  const name = req.query.name;
  const target = path.join(UPLOAD_DIR, name);
  res.setHeader('Content-Type', 'application/octet-stream');
~>  fs.createReadStream(target).pipe(res);
}
module.exports = serve;
