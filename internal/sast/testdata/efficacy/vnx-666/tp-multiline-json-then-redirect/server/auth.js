app.post('/reset', async (req, res) => {
  const token = await tokens.lookup(req.body.token);
  if (!token) {
~>    res.status(401).json({
      error: 'invalid token',
      code: 401,
    });
  }
  res.redirect('/password/new');
});
