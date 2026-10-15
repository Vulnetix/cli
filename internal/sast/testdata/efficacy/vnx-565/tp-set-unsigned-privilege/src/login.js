function login(req, res, user) {
~>  res.cookie('role', user.role, { httpOnly: true });
~>  res.cookie("isAdmin", String(user.isAdmin));
  res.redirect('/');
}

module.exports = { login };
