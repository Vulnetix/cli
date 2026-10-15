async function login(req, res) {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
~>  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  req.session.userId = user.id;
  res.json({ ok: true });
}
