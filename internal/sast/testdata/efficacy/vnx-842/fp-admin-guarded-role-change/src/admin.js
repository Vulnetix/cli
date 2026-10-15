router.put('/admin/users/:id/role', requireAdmin, async (req, res) => {
  const user = await User.findByPk(req.params.id);
  user.role = req.body.role;
  await user.save();
  res.json(user);
});
