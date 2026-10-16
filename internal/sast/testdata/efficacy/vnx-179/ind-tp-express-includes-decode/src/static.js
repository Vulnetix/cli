const path = require('path');
const fs = require('fs');

module.exports = function serveDocs(req, res) {
  const p = req.path.slice('/docs/'.length);
~>  if (p.includes('../')) {
    return res.status(400).end();
  }
  const target = decodeURIComponent(p);
  fs.createReadStream(path.join(__dirname, '..', 'docs', target)).pipe(res);
};
