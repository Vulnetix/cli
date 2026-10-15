function requireAdmin(req, res, next) {
~>  if (req.cookies.isAdmin === 'true') {
    return next();
  }
~>  if (req.body && req.body['role'] === ROLES.admin) {
    return next();
  }
  res.status(403).end();
}

module.exports = { requireAdmin };
