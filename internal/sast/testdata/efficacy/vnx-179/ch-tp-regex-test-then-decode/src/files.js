const fs = require('fs');
const path = require('path');

function serve(req, res) {
  let file = req.params.file;
~>  if (/\.\.\//.test(file)) {
    return res.status(400).end();
  }
  file = decodeURIComponent(file);
  res.sendFile(path.join('/srv/static', file));
}

module.exports = { serve };
