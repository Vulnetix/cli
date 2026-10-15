const fs = require('fs');
const path = require('path');

const DOCS = path.join(__dirname, 'docs');

exports.doc = (req, res) => {
  const rel = path.normalize(req.params.page).replace(/^(\.\.(\/|\\|$))+/, '');
  res.send(fs.readFileSync(path.join(DOCS, rel), 'utf8'));
};
