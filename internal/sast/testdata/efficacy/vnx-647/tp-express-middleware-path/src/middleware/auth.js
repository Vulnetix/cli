module.exports = function requireAdmin(req, res, next) {
~>  if (req.path.startsWith('/admin') && !req.user?.isAdmin) {
    return res.status(403).send('Forbidden');
  }
~>  if (req.originalUrl.indexOf('/private/') === 0) {
    if (!req.session.userId) return res.redirect('/login');
  }
  next();
};
