'use strict';

module.exports = function adminOnly(req, res, next) {
  const rawUrl = req.originalUrl;
~>  if (rawUrl.startsWith('/admin') && !(req.user && req.user.isAdmin)) {
    res.statusCode = 403;
    return res.end('admin only');
  }

  const parsed = new URL(rawUrl, 'http://internal.local');
  req.adminPath = parsed.pathname;
  return next();
};
