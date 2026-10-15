const path = require('path');

function adminGuard(req, res, next) {
  const url = path.posix.normalize(decodeURIComponent(req.path));
  if (url.startsWith('/admin') && !req.user.isAdmin) {
    return res.status(403).send('forbidden');
  }
  next();
}

function fileGuard(req, res, next) {
  const file = path.normalize(req.params.file);
  if (!canAccess(req.user, file)) {
    return res.sendStatus(403);
  }
  const label = decodeURIComponent(req.query.label || '');
  res.locals.label = label;
  next();
}

module.exports = { adminGuard, fileGuard };
