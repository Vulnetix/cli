router.post('/login', async (req, res) => {
  const user = await Users.findOne({ email: req.body.email });
  const supplied = req.body.hash;
~>  if (!user || user.passwordHash === req.body.passwordHash) {
    return res.json({ token: sign(user) });
  }
  res.status(401).end();
});
