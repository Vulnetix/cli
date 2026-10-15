const path = require('path');

function guard(req, res, next) {
  const raw = req.url;
  const clean = path.posix.normalize(decodeURIComponent(raw));
  if (clean.startsWith('/admin') && !req.user) {
    return res.sendStatus(403);
  }
  next();
}

module.exports = guard;
