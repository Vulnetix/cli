router.post('/login', (req, res) => {
~>  res.cookie('password', req.body.password, { maxAge: 900000, httpOnly: true });
  res.redirect('/');
});
