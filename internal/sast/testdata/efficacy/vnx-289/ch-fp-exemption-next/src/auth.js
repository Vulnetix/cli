const PUBLIC = ['/admin/login', '/admin/assets'];

module.exports = function requireAdmin(req, res, next) {
  if (req.path === '/admin/login') return next();
  if (req.path.startsWith('/admin/assets/')) {
    return next();
  }
  if (!req.session || !req.session.admin) {
    return res.redirect('/admin/login');
  }
  next();
};
