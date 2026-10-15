function requireAdmin(req, res, next) {
  if (req.signedCookies.role !== 'admin') {
    return res.sendStatus(403);
  }
  if (req.session.role !== 'admin') {
    return res.sendStatus(403);
  }
  if (req.user && req.user.isAdmin) {
    return next();
  }
  return res.sendStatus(403);
}

module.exports = { requireAdmin };
