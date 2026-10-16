function adminGuard(req, res, next) {
~>  if (req.originalUrl.startsWith('/api/admin') && !(req.user && req.user.isAdmin)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  return next();
}

module.exports = adminGuard;
