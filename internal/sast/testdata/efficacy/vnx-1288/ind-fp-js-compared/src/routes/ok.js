router.post('/register', async (req, res) => {
  const { password, passwordRepeat } = req.body;
  if (password !== passwordRepeat) {
    return res.status(422).json({ error: 'passwords differ' });
  }
  await users.insert(await bcrypt.hash(password, 12));
  res.sendStatus(201);
});
