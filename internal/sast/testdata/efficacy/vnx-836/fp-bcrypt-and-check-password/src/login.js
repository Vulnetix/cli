router.post('/login', async (req, res) => {
  const user = await Users.findOne({ email: req.body.email });
  const ok = user && await bcrypt.compare(req.body.password, user.passwordHash);
  if (!ok) return res.status(401).end();
  if (user.passwordHash === undefined) return res.status(500).end();
});
