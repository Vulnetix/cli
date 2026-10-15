router.post('/login', async (req, res) => {
  const user = await authenticate(req.body.username, req.body.password);
~>  res.cookie('remember', req.body.password, {
    maxAge: 30 * 24 * 3600 * 1000,
    httpOnly: true,
  });
  res.redirect('/');
});
