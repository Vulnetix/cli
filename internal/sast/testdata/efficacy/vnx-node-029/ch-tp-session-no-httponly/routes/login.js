router.post('/login', async (req, res) => {
  const sid = await sessions.create(req.body.user);
~>  res.cookie('sessionId', sid, { secure: true, sameSite: 'lax' });
~>  res.cookie('jwt', signToken(req.body.user));
  res.redirect('/');
});
