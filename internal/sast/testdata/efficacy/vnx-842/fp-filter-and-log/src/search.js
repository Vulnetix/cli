router.get('/users', async (req, res) => {
  const users = await User.find({ role: req.query.role }).limit(50);
  audit.log({ action: 'list', role: req.query.role });
  res.json(users.map((u) => ({ id: u.id, role: u.role })));
});
