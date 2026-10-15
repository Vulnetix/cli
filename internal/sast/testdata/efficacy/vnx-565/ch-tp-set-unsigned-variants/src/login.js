function login(req, res, user) {
~>  res.cookie('role', user.role, { httpOnly: true, secure: true });
  res.redirect('/');
}

module.exports = { login };
