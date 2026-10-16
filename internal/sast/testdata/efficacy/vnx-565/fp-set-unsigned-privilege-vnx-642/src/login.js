function login(req, res, user) {
  // Reported by VNX-642 (an unsigned privilege cookie written), not by this rule.
  res.cookie('role', user.role, { httpOnly: true });
  // Reported by VNX-642 (an unsigned privilege cookie written), not by this rule.
  res.cookie("isAdmin", String(user.isAdmin));
  res.redirect('/');
}

module.exports = { login };
