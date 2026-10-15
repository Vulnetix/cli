router.post('/login', async (req, res) => {
  const user = await Users.findOne({ email: req.body.email });
~>  if (!user || user.passwordHash !== req.body.passwordHash) {
    return res.status(401).end();
  }
  req.session.userId = user.id;
  res.redirect('/');
});

router.post('/api/session', async (req, res) => {
  const user = await Users.byName(req.query.user);
~>  const ok = crypto.timingSafeEqual(Buffer.from(user.pwd_hash), Buffer.from(req.body.hash));
  res.json({ ok });
});
