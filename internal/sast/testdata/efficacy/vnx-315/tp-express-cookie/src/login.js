app.post('/login', (req, res) => {
  const { username, password } = req.body;
~>  res.cookie('password', password, { httpOnly: true });
~>  res.cookie('creds', JSON.stringify({ username, password }));
  res.cookie('lang', 'en');
  res.redirect('/');
});

router.post('/pay', async (ctx) => {
~>  ctx.cookies.set('cvv', ctx.request.body.cvv);
});
