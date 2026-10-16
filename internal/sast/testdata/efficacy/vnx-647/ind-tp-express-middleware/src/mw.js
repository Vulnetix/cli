function guard(req, res, next) {
~>  if (req.path.startsWith('/admin') && !req.user?.isAdmin) {
    return res.status(403).send('Forbidden');
  }
  next();
}
module.exports = guard;
