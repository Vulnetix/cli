module.exports = function auth(req, res, next) {
  if (!req.headers.authorization) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  res.locals.user = decode(req.headers.authorization);
  next();
};

function render(req, res) {
  res.render('page', { title: 'x' }, (err, html) => {
    if (err) return res.status(500).end();
    res.send(html);
  });
}
