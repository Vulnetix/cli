router.post('/forgot', async (req, res) => {
  await sendReset(req.body.email);
  res.cookie('passwordResetSent', 'true', { maxAge: 60000 });
  res.clearCookie('password');
  res.cookie('theme', req.body.theme || 'dark');
  res.redirect('/');
});
