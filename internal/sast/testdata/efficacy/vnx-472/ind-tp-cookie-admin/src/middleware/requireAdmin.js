module.exports = function requireAdmin(req, res, next) {
~>  if (req.cookies.isAdmin === 'true') { return next(); }
  return res.status(403).send('forbidden');
};
