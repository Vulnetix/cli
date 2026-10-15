const path = require('path');

function adminGuard(req, res, next) {
  const url = req.originalUrl;
~>  if (url.startsWith('/admin') && !req.user.isAdmin) {
    return res.status(403).send('forbidden');
  }
  req.resource = decodeURIComponent(url);
  next();
}

function fileGuard(req, res, next) {
  const file = req.params.file;
~>  if (!canAccess(req.user, file)) {
    return res.sendStatus(403);
  }
  req.target = path.normalize(file);
  next();
}

module.exports = { adminGuard, fileGuard };
