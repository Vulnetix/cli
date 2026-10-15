module.exports = function requireAdmin(req, res, next) {
  const role = req.get('X-Role');
~>  if (role !== 'admin') {
    return res.sendStatus(403);
  }
  next();
};
