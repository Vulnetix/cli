app.post('/login', async (req, res) => {
  const user = await User.findOne({
    username: String(req.body.username),
    password: String(req.body.password),
  });
  res.json({ ok: !!user });
});
