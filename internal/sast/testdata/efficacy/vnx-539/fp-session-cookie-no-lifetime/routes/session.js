router.post('/login', (req, res) => {
  res.cookie('sid', req.sessionID, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.cookie('password_hint_seen', '1', { maxAge: 365 * 24 * 3600 * 1000 });
  res.clearCookie('password');
});
