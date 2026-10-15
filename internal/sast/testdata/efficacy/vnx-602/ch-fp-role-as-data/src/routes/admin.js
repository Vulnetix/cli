module.exports = (router) => {
  router.post('/users', requireAdmin, async (req, res) => {
    const allowed = ['user', 'editor'];
    if (!allowed.includes(req.body.role)) {
      return res.status(400).json({ error: 'bad role' });
    }
    const user = await User.create({ email: req.body.email, role: req.body.role });
    const filtered = (await User.findAll()).filter((u) => u.role === req.query.role);
    res.json({ user, filtered });
  });
};
