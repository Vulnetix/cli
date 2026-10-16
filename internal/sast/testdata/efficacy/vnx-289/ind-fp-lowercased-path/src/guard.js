const path = require('path');

module.exports = function adminGuard(req, res, next) {
  const p = path.posix.normalize(decodeURIComponent(req.path)).toLowerCase();
  if (p.startsWith('/admin') && !req.user?.isAdmin) {
    return res.sendStatus(403);
  }
  next();
};
