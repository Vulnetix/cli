function login(req, res, user) {
  // Reported by VNX-642 (an unsigned privilege cookie written), not by this rule.
  res.cookie('role', user.role, { httpOnly: true, secure: true });
  res.redirect('/');
}

module.exports = { login };
