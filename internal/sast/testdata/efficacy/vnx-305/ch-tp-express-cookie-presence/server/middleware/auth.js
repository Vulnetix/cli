function requireLogin(req, res, next) {
~>  if (req.cookies.auth_token) {
    return next();
  }
  res.redirect('/login');
}

module.exports = { requireLogin };
