app.post('/login', async (req, res) => {
  const token = await issueToken(req.body.username, req.body.password);
  res.cookie('session_token', token, { httpOnly: true, secure: true });
  res.cookie('csrf', crypto.randomBytes(16).toString('hex'));
  res.clearCookie('password');
});
