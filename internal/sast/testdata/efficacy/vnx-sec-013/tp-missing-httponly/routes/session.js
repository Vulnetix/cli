function login(req, res) {
  const sessionId = createSession(req.body.user);
~>  res.cookie("session", sessionId);
~>  res.cookie('token', token, { maxAge: 86400000 });
  res.redirect('/dashboard');
}
