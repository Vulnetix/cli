async function register(req, res) {
  const { password, passwordConfirmation } = req.body;
  if (password !== passwordConfirmation) {
    return res.status(400).send('passwords do not match');
  }
  if (password === '') {
    return res.status(400).send('password required');
  }
  const ok = await bcrypt.compare(password, user.passwordHash);
  res.json({ ok });
}
