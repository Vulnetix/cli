function handler(req, res) {
~>  if (req.originalUrl.includes('..')) {
    return res.status(400).send('bad path');
  }
  const target = req.query.path;
  return res.sendFile(target, { root: '/srv/www' });
}

module.exports = handler;
