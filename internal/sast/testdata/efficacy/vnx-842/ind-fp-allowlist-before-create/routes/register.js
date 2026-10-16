const SELF_SERVICE_ROLES = ['customer', 'vendor'];

router.post('/register', async (req, res) => {
  const role = req.body.role;
  if (!SELF_SERVICE_ROLES.includes(role)) {
    return res.status(400).json({ error: 'bad role' });
  }
  const user = await User.create({ email: req.body.email, role: role });
  res.json(user);
});
