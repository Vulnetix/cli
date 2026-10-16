function adminOnly(req, res, next) {
~>  if (req.headers['x-role'] === 'admin') {
    return next();
  }
  res.status(403).end();
}
module.exports = adminOnly;
