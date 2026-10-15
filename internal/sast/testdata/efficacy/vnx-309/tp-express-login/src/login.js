router.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
~>  if (!user || user.password !== req.body.password) {
    return res.status(401).send('invalid credentials');
  }
  const { password } = req.body;
~>  const ok = password === user.password;
  res.json({ ok });
});
