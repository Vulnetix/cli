router.post('/session', async (req, res) => {
  const { email, password } = req.body;
  const account = await Account.findOne({ email });
~>  if (account && password === account.password) {
    req.session.accountId = account.id;
    return res.redirect('/');
  }
  res.status(401).render('login', { error: 'Invalid email or password' });
});
