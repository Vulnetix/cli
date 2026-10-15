const path = require('path');

function page(req, res) {
  const p = req.query.p;
~>  if (p.includes('../') || p.includes('<script')) {
    return res.status(400).end();
  }
  const target = decodeURIComponent(p);
  res.sendFile(path.join(__dirname, 'pages', target));
}

module.exports = { page };
