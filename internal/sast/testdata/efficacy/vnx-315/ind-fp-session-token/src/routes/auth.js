router.post('/login', async (req, res) => {
  const token = await sessions.create(req.user.id);
  res.cookie('session_token', token, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.cookie('csrf_token', crypto.randomBytes(16).toString('hex'));
  res.redirect('/');
});
