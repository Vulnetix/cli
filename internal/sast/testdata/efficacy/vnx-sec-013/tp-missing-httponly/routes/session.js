function login(req, res) {
  const sessionId = createSession(req.body.user);
  // Reported by VNX-NODE-029 (a Node.js cookie without HttpOnly), not by this rule.
  res.cookie("session", sessionId);
  // Reported by VNX-NODE-029 (a Node.js cookie without HttpOnly), not by this rule.
  res.cookie('token', token, { maxAge: 86400000 });
  res.redirect('/dashboard');
}
