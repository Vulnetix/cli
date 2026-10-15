module.exports = function logout(req, res) {
  res.cookie('session', '', { expires: new Date(0), httpOnly: true });
  res.cookie("auth_token", "", { maxAge: 0 });
  res.clearCookie('refresh_token');
  res.redirect('/');
};
