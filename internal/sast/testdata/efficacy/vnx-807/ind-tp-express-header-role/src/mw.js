module.exports = function requireAdmin(req, res, next) {
  const role = req.headers['x-user-role'];
~>  if (role === 'admin') {
    return next();
  }
  res.sendStatus(403);
};
