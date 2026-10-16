router.get('/users', async (req, res) => {
  const users = await User.find({ role: req.query.role });
  res.json(users);
});

router.post('/signup', async (req, res) => {
  const user = await User.create({ email: req.body.email, role: 'customer' });
  res.json(user);
});
